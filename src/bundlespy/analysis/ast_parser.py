"""
Tree-sitter AST parser for JavaScript/TypeScript.

Sits upstream of the regex-based extractors. Does one structural walk over the
AST and produces two outputs:

1. An *augmented* DataFlowEnv with variable bindings the single-pass regex
   engine can't resolve (multi-hop chains, destructuring, ternary branches,
   function-local constants).

2. A list of Endpoint objects from call sites the regex layer structurally
   cannot reach (computed member access, ternary-selected URLs, destructured
   variables used directly in fetch/axios).

The regex layer (ast_endpoints.py) still runs after this pass -- it covers
minified bundles where tree-sitter produces flat, unstructured trees, and it
catches patterns this pass doesn't model. The two lists are merged by the
caller (deduplicated by path key).

Design constraints
------------------
- Never makes network calls.
- Fails silently: any parse or walk error returns (env, []) so callers are
  unaffected.
- Hard time limit: AST_MAX_SECONDS (default 5s). Files that exceed it return
  whatever was collected up to that point.
- Skips files larger than AST_MAX_MB (default 3 MB) -- tree-sitter is fast
  but minified 10 MB bundles are not worth a full AST parse.
- The augmented env is passed to the existing build_env() result via
  DataFlowEnv.merge(), which is defined here.
"""

import logging
import time
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("bundlespy.analysis.ast_parser")

# ── Constants ─────────────────────────────────────────────────────────────────

AST_MAX_SECONDS = 5.0
AST_MAX_MB      = 3

# HTTP methods that appear as axios/jQuery method-call names
_HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "head", "options", "request"})

# fetch() is usually GET; sendBeacon is always POST
_FETCH_METHOD  = "GET"
_BEACON_METHOD = "POST"

# Callee names we care about for URL extraction
_FETCH_NAMES   = frozenset({"fetch"})
_BEACON_NAMES  = frozenset({"sendBeacon"})   # navigator.sendBeacon
_XHR_NAMES     = frozenset({"open"})         # xhr.open("POST", url)
_AXIOS_OBJ     = "axios"
_JQUERY_OBJ    = frozenset({"$", "jQuery"})
_HTTP_CLIENTS  = frozenset({"request", "superagent", "got", "ky", "http", "https"})
_EVENTSOURCE   = "EventSource"
_WEBSOCKET     = "WebSocket"
_APP_ROUTER    = frozenset({"app", "router", "express"})


# ── Lazy-loaded tree-sitter ───────────────────────────────────────────────────

_parser = None
_language = None

def _get_parser():
    """Return a cached tree-sitter Parser, or None if unavailable."""
    global _parser, _language
    if _parser is not None:
        return _parser
    try:
        import tree_sitter_javascript as tsjs
        from tree_sitter import Language, Parser
        _language = Language(tsjs.language())
        _parser = Parser(_language)
        logger.debug("tree-sitter JS parser initialised")
    except Exception as exc:
        logger.debug("tree-sitter unavailable (%s) - AST pass disabled", exc)
        _parser = None
    return _parser


# ── Public API ────────────────────────────────────────────────────────────────

def augment_env_and_extract(
    content: str,
    file_url: str,
    base_origin: str = "",
) -> Tuple["DataFlowEnvAugmented", List]:
    """
    Parse *content* with tree-sitter and return:
      (augmented_env, ast_endpoints)

    augmented_env  -- a DataFlowEnvAugmented; merge into the regex-layer env
                      via env.update(augmented_env.vars) before calling
                      extract_all_endpoints().
    ast_endpoints  -- List[Endpoint] found by the AST walk that the regex layer
                      would likely miss.

    Both outputs are empty/no-op on any error.
    """
    parser = _get_parser()
    if parser is None:
        return DataFlowEnvAugmented(), []

    content_bytes = content.encode("utf-8", errors="replace")
    if len(content_bytes) > AST_MAX_MB * 1_048_576:
        logger.debug("AST pass skipped: file too large (%d bytes)", len(content_bytes))
        return DataFlowEnvAugmented(), []

    try:
        tree = parser.parse(content_bytes)
    except Exception as exc:
        logger.debug("tree-sitter parse failed for %s: %s", file_url, exc)
        return DataFlowEnvAugmented(), []

    walker = _ASTWalker(content_bytes, file_url, base_origin)
    try:
        walker.walk(tree.root_node)
    except Exception as exc:
        logger.debug("AST walk error for %s: %s", file_url, exc)

    return walker.env, walker.endpoints


# ── Augmented environment ─────────────────────────────────────────────────────

class DataFlowEnvAugmented:
    """
    Richer variable bindings produced by the AST walk.

    The existing DataFlowEnv (dataflow.py) stores vars as {name: value}.
    This class produces the same dict so callers can do:

        env.vars.update(ast_env.vars)

    Extra bindings we resolve that the regex scan misses:
    - multi-hop:      const a = x; const b = a + "/foo"; -> b resolved
    - destructuring:  const {apiUrl} = config; -> tracks apiUrl as "config.apiUrl"
    - ternary:        url = flag ? "/a" : "/b" -> both branches stored
    - function consts inside arrow fns and regular fns
    - object spread / property shorthand
    """

    def __init__(self):
        self.vars: Dict[str, str]   = {}   # name  -> value
        self.multi: Dict[str, List[str]] = {}  # name -> [branch1, branch2] (ternary)
        self._count = 0
        self._MAX   = 2000

    def store(self, name: str, value: str) -> None:
        if self._count >= self._MAX or not name or not value:
            return
        if len(value) > 500:
            return
        self.vars[name] = value
        self._count += 1

    def store_branch(self, name: str, value: str) -> None:
        """Store one branch of a ternary; both branches are kept."""
        if not name or not value:
            return
        self.multi.setdefault(name, []).append(value)
        # Also put first branch in vars for single-value resolution
        if name not in self.vars:
            self.vars[name] = value
        self._count += 1

    def resolve(self, name: str) -> Optional[str]:
        return self.vars.get(name)

    def resolve_all(self, name: str) -> List[str]:
        """Return all known values for a name (ternary branches)."""
        branches = self.multi.get(name, [])
        single   = self.vars.get(name)
        if branches:
            return branches
        return [single] if single else []


# ── AST walker ────────────────────────────────────────────────────────────────

class _ASTWalker:
    """
    Walks a tree-sitter JS AST.

    Pass 1 - variable collection: walks ALL nodes to build the env.
    Pass 2 - call extraction: walks call_expression / new_expression nodes
             using the populated env to resolve arguments.
    """

    def __init__(self, content_bytes: bytes, file_url: str, base_origin: str):
        self._src      = content_bytes
        self.file_url  = file_url
        self.base_origin = base_origin
        self.env       = DataFlowEnvAugmented()
        self.endpoints: List = []
        self._seen: Set[str] = set()
        self._t_start  = time.monotonic()

    def _elapsed(self) -> float:
        return time.monotonic() - self._t_start

    def _text(self, node) -> str:
        """Decoded text of a node."""
        try:
            return self._src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _line(self, node) -> int:
        return node.start_point[0] + 1

    def walk(self, root) -> None:
        """Two-pass walk: collect vars, then extract endpoints."""
        # Pass 1 - variable bindings
        self._collect_vars(root)
        # Pass 2 - call sites
        self._extract_calls(root)

    # ── Pass 1: variable collection ───────────────────────────────────────────

    def _collect_vars(self, node) -> None:
        """Recursively collect variable bindings from the AST."""
        if self._elapsed() > AST_MAX_SECONDS:
            return

        t = node.type

        # const/let/var x = ...
        if t == "variable_declarator":
            self._handle_declarator(node)

        # x = ... (bare assignment)
        elif t == "assignment_expression":
            self._handle_assignment(node)

        for child in node.named_children:
            self._collect_vars(child)

    def _handle_declarator(self, node) -> None:
        """Handle: const name = value  or  const {a, b} = obj"""
        children = node.named_children
        if len(children) < 2:
            return
        lhs = children[0]
        rhs = children[1]

        if lhs.type == "identifier":
            name  = self._text(lhs)
            value = self._resolve_rhs(rhs)
            if value:
                self.env.store(name, value)
            # Ternary: both branches
            if rhs.type == "ternary_expression":
                branches = self._ternary_strings(rhs)
                for b in branches:
                    self.env.store_branch(name, b)

        elif lhs.type == "object_pattern":
            # const { apiUrl, baseUrl } = config
            rhs_name = self._text(rhs) if rhs.type == "identifier" else None
            for prop in lhs.named_children:
                prop_name = self._text(prop)
                if rhs_name:
                    # Track as "config.apiUrl" so template resolution works
                    self.env.store(prop_name, f"__destructured_from_{rhs_name}")
                    # Also register as alias in case rhs is in env
                    obj_key = f"{rhs_name}.{prop_name}"
                    resolved = self.env.resolve(obj_key)
                    if resolved:
                        self.env.store(prop_name, resolved)

        elif lhs.type == "array_pattern":
            # const [first, second] = arr - not common for URLs, skip
            pass

    def _handle_assignment(self, node) -> None:
        """Handle: x = value  or  obj.key = value"""
        children = node.named_children
        if len(children) < 2:
            return
        lhs = children[0]
        rhs = children[1]

        if lhs.type == "identifier":
            name  = self._text(lhs)
            value = self._resolve_rhs(rhs)
            if value:
                self.env.store(name, value)

        elif lhs.type == "member_expression":
            # obj.key = "/api/..." -> store as "obj.key"
            obj_node  = lhs.child_by_field_name("object")
            prop_node = lhs.child_by_field_name("property")
            if obj_node and prop_node:
                key   = f"{self._text(obj_node)}.{self._text(prop_node)}"
                value = self._resolve_rhs(rhs)
                if value:
                    self.env.store(key, value)

    def _resolve_rhs(self, node) -> Optional[str]:
        """
        Try to resolve a RHS node to a string value.

        Handles: string, template, binary (+), identifier, member_expression.
        """
        t = node.type

        if t == "string":
            return self._string_value(node)

        if t == "template_string":
            return self._template_value(node)

        if t == "binary_expression":
            return self._concat_value(node)

        if t == "identifier":
            name = self._text(node)
            return self.env.resolve(name)

        if t == "member_expression":
            key = self._text(node)   # e.g. "config.apiBase"
            return self.env.resolve(key)

        if t == "ternary_expression":
            # Return the first resolvable branch
            branches = self._ternary_strings(node)
            return branches[0] if branches else None

        if t == "parenthesized_expression" and node.named_children:
            return self._resolve_rhs(node.named_children[0])

        return None

    def _string_value(self, node) -> Optional[str]:
        """Extract the inner text of a string node (strips quotes)."""
        for child in node.named_children:
            if child.type in ("string_fragment", "string_content"):
                return self._text(child)
        # Fallback: strip outer quotes from raw text
        raw = self._text(node)
        if len(raw) >= 2 and raw[0] in ('"', "'", "`"):
            return raw[1:-1]
        return None

    def _template_value(self, node) -> Optional[str]:
        """
        Resolve a template literal. Substitutes ${var} where the variable
        is known in env; marks unknowns as {dynamic}.
        """
        parts = []
        for child in node.children:
            ct = child.type
            if ct in ("template_chars",):
                parts.append(self._text(child))
            elif ct == "template_substitution":
                # ${expr}
                inner = child.named_children[0] if child.named_children else None
                if inner:
                    val = self._resolve_rhs(inner)
                    if val:
                        parts.append(val)
                    else:
                        parts.append("{dynamic}")
                else:
                    parts.append("{dynamic}")
        result = "".join(parts)
        return result if result else None

    def _concat_value(self, node) -> Optional[str]:
        """Resolve a binary + expression (string concatenation)."""
        children = node.named_children
        if len(children) < 2:
            return None
        op_text = self._text(node)
        if "+" not in op_text:
            return None
        left  = self._resolve_rhs(children[0])
        right = self._resolve_rhs(children[1])
        if left is None and right is None:
            return None
        left  = left  or "{dynamic}"
        right = right or "{dynamic}"
        combined = left + right
        # Return None if result is entirely dynamic (no static prefix)
        if combined == "{dynamic}{dynamic}":
            return None
        return combined

    def _ternary_strings(self, node) -> List[str]:
        """Return both branch values from a ternary expression, filtering non-URLs."""
        results = []
        # ternary_expression: condition ? consequent : alternate
        named = node.named_children
        if len(named) >= 3:
            for branch_node in (named[1], named[2]):
                val = self._resolve_rhs(branch_node)
                if val and self._is_url_like(val):
                    results.append(val)
        return results

    # ── Pass 2: call site extraction ──────────────────────────────────────────

    def _extract_calls(self, node) -> None:
        """Recursively walk looking for call/new expressions."""
        if self._elapsed() > AST_MAX_SECONDS:
            return

        t = node.type

        if t == "call_expression":
            self._handle_call(node)

        elif t == "new_expression":
            self._handle_new(node)

        for child in node.named_children:
            self._extract_calls(child)

    def _handle_call(self, node) -> None:
        """
        Extract endpoint from a call_expression.
        Covers: fetch, axios.method, $.ajax, xhr.open, router.get, sendBeacon,
                http/got/superagent/ky.method, EventSource.
        """
        callee = node.child_by_field_name("function") or (
            node.named_children[0] if node.named_children else None
        )
        args_node = node.child_by_field_name("arguments")
        if not callee or not args_node:
            return

        callee_type = callee.type
        callee_text = self._text(callee)
        args = args_node.named_children

        # fetch(url, options?)
        if callee_type == "identifier" and callee_text in _FETCH_NAMES:
            if args:
                urls = self._resolve_url_arg(args[0])
                for url in urls:
                    self._add(url, _FETCH_METHOD, node, confidence=0.90)
            return

        # navigator.sendBeacon(url, data?)
        if callee_type == "member_expression":
            obj  = callee.child_by_field_name("object")
            prop = callee.child_by_field_name("property")
            if obj is None or prop is None:
                return
            obj_text  = self._text(obj)
            prop_text = self._text(prop)

            # navigator.sendBeacon
            if prop_text == "sendBeacon":
                if args:
                    for url in self._resolve_url_arg(args[0]):
                        self._add(url, _BEACON_METHOD, node, confidence=0.90)
                return

            # axios.get/post/...
            if obj_text == _AXIOS_OBJ and prop_text.lower() in _HTTP_METHODS:
                method = prop_text.upper()
                if args:
                    for url in self._resolve_url_arg(args[0]):
                        self._add(url, method, node, confidence=0.92)
                return

            # axios({ url: "...", method: "POST" })
            if obj_text == _AXIOS_OBJ and prop_text == "request":
                if args and args[0].type == "object":
                    url, method = self._axios_config_obj(args[0])
                    if url:
                        self._add(url, method or "UNKNOWN", node, confidence=0.88)
                return

            # $.ajax / $.get / $.post
            if obj_text in _JQUERY_OBJ and prop_text.lower() in _HTTP_METHODS | {"ajax"}:
                method = "GET" if prop_text.lower() == "get" else (
                         "POST" if prop_text.lower() == "post" else "UNKNOWN")
                if args:
                    first = args[0]
                    if first.type == "object":
                        url, m = self._jquery_config_obj(first)
                        if url:
                            self._add(url, m or method, node, confidence=0.85)
                    else:
                        for url in self._resolve_url_arg(first):
                            self._add(url, method, node, confidence=0.85)
                return

            # xhr.open("POST", url)
            if prop_text == "open" and len(args) >= 2:
                method = self._string_from_node(args[0]) or "UNKNOWN"
                for url in self._resolve_url_arg(args[1]):
                    self._add(url, method.upper(), node, confidence=0.90)
                return

            # superagent/got/ky/http.get(url)
            if obj_text in _HTTP_CLIENTS and prop_text.lower() in _HTTP_METHODS:
                if args:
                    for url in self._resolve_url_arg(args[0]):
                        self._add(url, prop_text.upper(), node, confidence=0.82)
                return

            # app.get("/route", handler)  /  router.post("/route", ...)
            if obj_text in _APP_ROUTER and prop_text.lower() in _HTTP_METHODS:
                if args:
                    for url in self._resolve_url_arg(args[0]):
                        self._add(url, prop_text.upper(), node, confidence=0.88)
                return

            # EventSource constructor (treated as call for this check)
            # handled in _handle_new, but some transpilers produce calls

        # axios({ url: "...", method: "POST" }) - bare call
        if callee_type == "identifier" and callee_text == _AXIOS_OBJ:
            if args and args[0].type == "object":
                url, method = self._axios_config_obj(args[0])
                if url:
                    self._add(url, method or "UNKNOWN", node, confidence=0.88)

    def _handle_new(self, node) -> None:
        """Handle new WebSocket(url) / new EventSource(url)."""
        constructor = node.child_by_field_name("constructor") or (
            node.named_children[0] if node.named_children else None
        )
        args_node = node.child_by_field_name("arguments")
        if not constructor or not args_node:
            return

        ctor_text = self._text(constructor)
        args = args_node.named_children

        if ctor_text == _WEBSOCKET and args:
            for url in self._resolve_url_arg(args[0]):
                self._add(url, "WS", node, confidence=0.94)

        elif ctor_text == _EVENTSOURCE and args:
            for url in self._resolve_url_arg(args[0]):
                self._add(url, "GET", node, confidence=0.90)

    # ── Resolution helpers ────────────────────────────────────────────────────

    def _resolve_url_arg(self, node) -> List[str]:
        """
        Resolve a call argument node to a list of URL strings.
        Returns multiple values for ternary branches.
        """
        t = node.type

        if t == "string":
            val = self._string_value(node)
            return [val] if val and self._is_url_like(val) else []

        if t == "template_string":
            val = self._template_value(node)
            return [val] if val and self._is_url_like(val) else []

        if t == "binary_expression":
            val = self._concat_value(node)
            return [val] if val and self._is_url_like(val) else []

        if t == "identifier":
            name = self._text(node)
            vals = self.env.resolve_all(name)
            return [v for v in vals if self._is_url_like(v)]

        if t == "member_expression":
            key  = self._text(node)
            val  = self.env.resolve(key)
            return [val] if val and self._is_url_like(val) else []

        if t == "ternary_expression":
            return self._ternary_strings(node)

        if t == "parenthesized_expression" and node.named_children:
            return self._resolve_url_arg(node.named_children[0])

        return []

    def _string_from_node(self, node) -> Optional[str]:
        """Return the string value of a string literal node, or None."""
        if node.type == "string":
            return self._string_value(node)
        return None

    def _axios_config_obj(self, obj_node) -> Tuple[Optional[str], Optional[str]]:
        """Extract url and method from axios({ url: "...", method: "POST" })."""
        url    = None
        method = None
        for pair in obj_node.named_children:
            if pair.type != "pair":
                continue
            key_node = pair.child_by_field_name("key")
            val_node = pair.child_by_field_name("value")
            if not key_node or not val_node:
                continue
            key = self._text(key_node).strip("'\"` ")
            if key == "url":
                resolved = self._resolve_url_arg(val_node)
                if resolved:
                    url = resolved[0]
            elif key == "method":
                method = (self._string_from_node(val_node) or "").upper() or None
        return url, method

    def _jquery_config_obj(self, obj_node) -> Tuple[Optional[str], Optional[str]]:
        """Extract url and type from $.ajax({ url: "...", type: "POST" })."""
        url    = None
        method = None
        for pair in obj_node.named_children:
            if pair.type != "pair":
                continue
            key_node = pair.child_by_field_name("key")
            val_node = pair.child_by_field_name("value")
            if not key_node or not val_node:
                continue
            key = self._text(key_node).strip("'\"` ")
            if key == "url":
                resolved = self._resolve_url_arg(val_node)
                if resolved:
                    url = resolved[0]
            elif key in ("type", "method"):
                method = (self._string_from_node(val_node) or "").upper() or None
        return url, method

    # ── URL validation / endpoint creation ───────────────────────────────────

    def _is_url_like(self, value: str) -> bool:
        if not value or len(value) < 2:
            return False
        v = value.strip()
        return (
            v.startswith("/")
            or v.startswith("http://")
            or v.startswith("https://")
            or v.startswith("ws://")
            or v.startswith("wss://")
        )

    def _is_skip(self, path: str) -> bool:
        lower = path.lower()
        # Static assets
        skip_exts = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
                     ".css", ".woff", ".woff2", ".ttf", ".eot", ".pdf",
                     ".zip", ".mp4", ".mp3", ".map")
        if any(lower.endswith(ext) for ext in skip_exts):
            return True
        if lower in ("/", "/*", "//"):
            return True
        # Doc / CDN domains
        skip_domains = ("reactjs.org", "w3.org", "github.com", "mdn.io",
                        "developer.mozilla", "nodejs.org", "example.com",
                        "twitter.com", "facebook.com", "fonts.googleapis.com",
                        "googletagmanager.com", "linkedin.com")
        if any(d in lower for d in skip_domains):
            return True
        # Full HTTP URLs that look like documentation rather than API
        if path.startswith("http") and not path.startswith("ws"):
            api_signals = ("/api/", "/auth", "/admin", "/graphql",
                           "/upload", "/download", "/v1/", "/v2/", "/v3/",
                           "/rest/", "/gql", "/socket", "/functions/", ".netlify")
            if not any(k in lower for k in api_signals):
                return True
        return False

    def _categorize(self, path: str, method: str) -> str:
        lower = path.lower()
        if any(k in lower for k in ("/login", "/logout", "/auth", "/oauth",
                                     "/token", "/session", "/signin", "/signup",
                                     "/register", "/refresh", "/password", "/sso")):
            return "AUTH"
        if any(k in lower for k in ("/admin", "/internal", "/manage",
                                     "/management", "/panel", "/staff",
                                     "/superuser", "/backoffice")):
            return "ADMIN"
        if "/graphql" in lower or "/gql" in lower:
            return "GRAPHQL"
        if any(p in lower for p in ("/.netlify/", "/functions/", "/.vercel/")):
            return "SERVERLESS"
        if lower.startswith("ws://") or lower.startswith("wss://") or "/ws/" in lower:
            return "WEBSOCKET"
        if method == "WS":
            return "WEBSOCKET"
        if any(k in lower for k in ("/api/", "/v1/", "/v2/", "/v3/", "/rest/")):
            return "API"
        return "UNKNOWN"

    def _add(self, path: str, method: str, node, confidence: float = 0.80) -> None:
        """Add an endpoint if it passes filters and is not a duplicate."""
        if not path or not self._is_url_like(path) or self._is_skip(path):
            return
        if path == "{dynamic}":
            return

        # Normalize
        import re
        path = re.sub(r'\$\{[^}]+\}', '{dynamic}', path)
        path = path.rstrip("/") or "/"

        dedup_key = re.sub(r'\{[^}]+\}', '*', path.lower().split("?")[0])
        if dedup_key in self._seen:
            return
        self._seen.add(dedup_key)

        from ..storage.models import Endpoint
        category = self._categorize(path, method)
        line_no  = node.start_point[0] + 1

        # Build a short evidence snippet
        start  = max(0, node.start_byte - 10)
        end    = min(len(self._src), node.end_byte + 20)
        ev     = self._src[start:end].decode("utf-8", errors="replace").replace("\n", " ").strip()[:200]

        ep = Endpoint(
            url         = path,
            path        = path,
            method      = method,
            category    = category,
            source_file = self.file_url,
            line_number = line_no,
            confidence  = confidence,
            evidence    = ev,
        )
        try:
            ep.source_type = "static"
        except Exception:
            pass
        self.endpoints.append(ep)
        logger.debug("AST endpoint: %s %s (line %d, conf=%.2f)",
                     method, path, line_no, confidence)
