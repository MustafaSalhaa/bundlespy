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

3. A list of ASTSecretHit objects from key/value object property pairs where
   the key name is a known secret indicator. This is separate from the regex
   scanner — it runs on the parsed tree so it only matches actual string
   literals assigned to sensitive keys, never comments or random strings.

The regex layer (ast_endpoints.py) still runs after this pass -- it covers
minified bundles where tree-sitter produces flat, unstructured trees, and it
catches patterns this pass doesn't model. The two lists are merged by the
caller (deduplicated by path key).

Design constraints
------------------
- Never makes network calls.
- Fails silently: any parse or walk error returns (env, [], []) so callers are
  unaffected.
- Hard time limit: AST_MAX_SECONDS (default 5s). Files that exceed it return
  whatever was collected up to that point.
- Skips files larger than AST_MAX_MB (default 3 MB) -- tree-sitter is fast
  but minified 10 MB bundles are not worth a full AST parse.
- The augmented env is passed to the existing build_env() result via
  DataFlowEnv.merge(), which is defined here.
"""

import logging
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

# - matches <script>...</script> blocks; used to strip HTML before AST parsing
_SCRIPT_TAG_RE = re.compile(
    r'<script(?:\s[^>]*)?>(.+?)</script>',
    re.DOTALL | re.IGNORECASE,
)


def _extract_inline_js(source: str) -> str:
    """
    If source looks like HTML, return only the concatenated script tag bodies.
    Otherwise return source unchanged. Keeps the AST pass clean on HTML responses.
    """
    stripped = source.lstrip()
    if not stripped.startswith('<'):
        return source
    chunks = _SCRIPT_TAG_RE.findall(source)
    if not chunks:
        return source
    return '\n'.join(chunks)

logger = logging.getLogger("bundlespy.analysis.ast_parser")

# ── Constants ─────────────────────────────────────────────────────────────────

AST_MAX_SECONDS = 5.0
AST_MAX_MB      = 3

# ── AST secret hit dataclass ──────────────────────────────────────────────────

@dataclass
class ASTSecretHit:
    """
    A key/value pair from the AST where the key name looks like a secret.
    Produced by the pair-walking pass; consumed by SecretScanner.scan_with_env()
    to create boosted-confidence findings.
    """
    key_name:   str   # e.g. "apiKey", "password", "STRIPE_SECRET"
    value:      str   # the literal string value
    line:       int   # 1-indexed line in the source file
    context:    str   # ~120 char surrounding snippet
    severity:   str   # pre-computed severity hint: HIGH / MEDIUM / LOW
    confidence: float # base confidence before entropy filtering

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

# ── Secret key-name tables ────────────────────────────────────────────────────
# Key names that strongly indicate a secret assignment. Matched case-insensitively
# against the property name in object literals and variable assignments.

# HIGH severity — these are almost certainly credentials or keys
_SECRET_KEY_HIGH = frozenset({
    "password", "passwd", "pass", "secret", "private_key", "privatekey",
    "private_key_id", "privatekeyid", "client_secret", "clientsecret",
    "access_secret", "accesssecret", "api_secret", "apisecret",
    "auth_secret", "authsecret", "db_password", "dbpassword",
    "database_password", "databasepassword", "master_key", "masterkey",
    "encryption_key", "encryptionkey", "signing_key", "signingkey",
    "jwt_secret", "jwtsecret", "cookie_secret", "cookiesecret",
    "session_secret", "sessionsecret", "webhook_secret", "webhooksecret",
    "stripe_secret", "stripesecret", "stripe_secret_key", "stripesecretkey",
    "stripe_api_key", "stripeapikey",
})

# MEDIUM severity — likely credentials, could be public identifiers
_SECRET_KEY_MEDIUM = frozenset({
    "api_key", "apikey", "access_key", "accesskey", "auth_key", "authkey",
    "token", "auth_token", "authtoken", "access_token", "accesstoken",
    "api_token", "apitoken", "bearer_token", "bearertoken",
    "refresh_token", "refreshtoken", "id_token", "idtoken",
    "aws_secret_key", "awssecretkey", "aws_access_key", "awsaccesskey",
    "gcp_api_key", "gcpapikey", "firebase_api_key", "firebaseapikey",
    "google_api_key", "googleapikey", "azure_key", "azurekey",
    "github_token", "githubtoken", "gitlab_token", "gitlabtoken",
    "slack_token", "slacktoken", "slack_bot_token", "slackbottoken",
    "sendgrid_key", "sendgridkey", "mailgun_key", "mailgunkey",
    "twilio_auth", "twilioauth", "openai_key", "openaiapikey",
    "anthropic_key", "anthropicapikey", "huggingface_token",
    "mapbox_token", "mapboxtoken", "algolia_key", "algoliakey",
    "cloudinary_key", "cloudinarykey", "pusher_key", "pusherkey",
    "recaptcha_secret", "recaptchasecret", "recaptcha_key", "recaptchakey",
    "oauth_secret", "oauthsecret", "consumer_secret", "consumersecret",
    "app_secret", "appsecret", "client_key", "clientkey",
    "credentials", "credential",
})

# LOW severity — could be public-facing identifiers, still worth flagging
_SECRET_KEY_LOW = frozenset({
    "api_id", "apiid", "app_id", "appid", "client_id", "clientid",
    "consumer_key", "consumerkey", "publishable_key", "publishablekey",
    "public_key", "publickey", "account_id", "accountid",
    "project_id", "projectid", "tenant_id", "tenantid",
    "subscription_id", "subscriptionid", "workspace_id", "workspaceid",
    "measurement_id", "measurementid", "tracking_id", "trackingid",
    "gtm_id", "gtmid", "fb_pixel", "fbpixel",
})

# Keys that produce low-confidence downgrade regardless of value
_BENIGN_KEY_FRAGMENTS = frozenset({
    "version", "build", "label", "name", "title", "description",
    "url", "endpoint", "host", "port", "path", "prefix", "suffix",
    "timeout", "retry", "limit", "max", "min", "count", "size",
    "color", "theme", "font", "icon", "image", "logo",
    "locale", "language", "lang", "region", "country", "timezone",
    "debug", "verbose", "log", "level", "mode", "env",
})


def _classify_key(key: str) -> Tuple[Optional[str], float]:
    """
    Return (severity, base_confidence) for a property key name,
    or (None, 0.0) if the key is not a secret indicator.
    """
    normalized = key.lower().replace("-", "_").replace(".", "_")

    # Downgrade benign keys immediately
    if normalized in _BENIGN_KEY_FRAGMENTS:
        return None, 0.0
    for frag in _BENIGN_KEY_FRAGMENTS:
        if normalized == frag:
            return None, 0.0

    if normalized in _SECRET_KEY_HIGH:
        return "HIGH", 0.90
    if normalized in _SECRET_KEY_MEDIUM:
        return "MEDIUM", 0.82
    if normalized in _SECRET_KEY_LOW:
        return "LOW", 0.70

    # Partial match: key contains a HIGH indicator as a substring
    for k in _SECRET_KEY_HIGH:
        if k in normalized and len(k) >= 6:
            return "HIGH", 0.85

    # Partial match: key contains a MEDIUM indicator
    for k in _SECRET_KEY_MEDIUM:
        if k in normalized and len(k) >= 5:
            return "MEDIUM", 0.75

    return None, 0.0


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
) -> Tuple["DataFlowEnvAugmented", List, List["ASTSecretHit"]]:
    """
    Parse *content* with tree-sitter and return:
      (augmented_env, ast_endpoints, ast_secret_hits)

    augmented_env    -- a DataFlowEnvAugmented; merge into the regex-layer env
                        via env.update(augmented_env.vars) before calling
                        extract_all_endpoints().
    ast_endpoints    -- List[Endpoint] found by the AST walk that the regex
                        layer would likely miss.
    ast_secret_hits  -- List[ASTSecretHit] from key/value pairs where the key
                        name is a known secret indicator. Pass these to
                        SecretScanner.scan_with_env() for boosted findings.

    All outputs are empty/no-op on any error.
    """
    parser = _get_parser()
    if parser is None:
        return DataFlowEnvAugmented(), [], []

    # strip HTML wrapper if the response came back as a page instead of pure JS
    content = _extract_inline_js(content)

    content_bytes = content.encode("utf-8", errors="replace")
    if len(content_bytes) > AST_MAX_MB * 1_048_576:
        logger.debug("AST pass skipped: file too large (%d bytes)", len(content_bytes))
        return DataFlowEnvAugmented(), [], []

    try:
        tree = parser.parse(content_bytes)
    except Exception as exc:
        logger.debug("tree-sitter parse failed for %s: %s", file_url, exc)
        return DataFlowEnvAugmented(), [], []

    walker = _ASTWalker(content_bytes, file_url, base_origin)
    try:
        walker.walk(tree.root_node)
    except Exception as exc:
        logger.debug("AST walk error for %s: %s", file_url, exc)

    # dedup secret hits by (key_name, value) - keep highest severity
    _sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    _seen_hits: Dict[Tuple[str, str], "ASTSecretHit"] = {}
    for hit in walker.secret_hits:
        k = (hit.key_name, hit.value)
        existing = _seen_hits.get(k)
        if existing is None or _sev_rank.get(hit.severity, 0) > _sev_rank.get(existing.severity, 0):
            _seen_hits[k] = hit
    deduped_hits = list(_seen_hits.values())

    return walker.env, walker.endpoints, deduped_hits


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
        self._src        = content_bytes
        self.file_url    = file_url
        self.base_origin = base_origin
        self.env         = DataFlowEnvAugmented()
        self.endpoints:    List = []
        self.secret_hits:  List["ASTSecretHit"] = []
        self._seen:        Set[str] = set()
        self._seen_secret: Set[str] = set()  # dedup key/value pairs
        self._t_start    = time.monotonic()

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
        """Three-pass walk using iterative DFS: collect vars, extract endpoints, find secret pairs."""
        self._collect_vars_iter(root)
        self._extract_calls_iter(root)
        self._extract_secret_pairs_iter(root)

    # ── Pass 1: variable collection ───────────────────────────────────────────

    def _collect_vars_iter(self, root) -> None:
        """Iterative DFS variable binding collection - avoids Python recursion limit."""
        stack = [root]
        while stack:
            if self._elapsed() > AST_MAX_SECONDS:
                return
            node = stack.pop()
            t = node.type
            if t == "variable_declarator":
                self._handle_declarator(node)
            elif t == "assignment_expression":
                self._handle_assignment(node)
            # push children in reverse so left-to-right order is preserved
            stack.extend(reversed(node.named_children))

    def _collect_vars(self, node) -> None:
        """Recursive fallback - kept for any internal callers."""
        if self._elapsed() > AST_MAX_SECONDS:
            return
        t = node.type
        if t == "variable_declarator":
            self._handle_declarator(node)
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

    def _extract_calls_iter(self, root) -> None:
        """Iterative DFS call/new expression extraction."""
        stack = [root]
        while stack:
            if self._elapsed() > AST_MAX_SECONDS:
                return
            node = stack.pop()
            t = node.type
            if t == "call_expression":
                self._handle_call(node)
            elif t == "new_expression":
                self._handle_new(node)
            stack.extend(reversed(node.named_children))

    def _extract_calls(self, node) -> None:
        """Recursive fallback - kept for any internal callers."""
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
                _jq_method = "GET" if prop_text.lower() == "get" else (
                             "POST" if prop_text.lower() == "post" else "UNKNOWN")
                if args:
                    first = args[0]

                    # settings-object-only: $.ajax({ url: "...", method: "POST", ... })
                    if first.type == "object":
                        url, m, params, hdrs = self._jquery_config_obj(first)
                        if url:
                            ev_extra = self._jquery_evidence(params, hdrs)
                            self._add_with_evidence(
                                url, m or _jq_method, node,
                                confidence=0.85, extra=ev_extra,
                            )

                    # url-first: $.ajax("/api/x", { ... }) or $.get("/api/x", data, cb)
                    else:
                        resolved_urls = self._resolve_url_arg(first)
                        # find a trailing object arg - may be settings (ajax) or raw data (get/post)
                        second_obj = next(
                            (a for a in args[1:] if a.type == "object"), None
                        )
                        params: List[str] = []
                        hdrs: List[str] = []
                        if second_obj is not None:
                            if prop_text.lower() == "ajax":
                                # second arg is a full settings object
                                _, _, params, hdrs = self._jquery_config_obj(second_obj)
                            else:
                                # $.get/.post: second arg is the data payload directly
                                params = self._extract_object_keys(second_obj)
                        ev_extra = self._jquery_evidence(params, hdrs)
                        for url in resolved_urls:
                            self._add_with_evidence(
                                url, _jq_method, node,
                                confidence=0.85, extra=ev_extra,
                            )
                return

            # xhr.open("POST", url) - with scope-aware setRequestHeader extraction
            if prop_text == "open" and len(args) >= 2:
                method = self._string_from_node(args[0]) or "UNKNOWN"
                if method.upper() not in {"GET", "HEAD", "OPTIONS", "POST",
                                          "PUT", "PATCH", "DELETE"}:
                    return
                resolved = list(self._resolve_url_arg(args[1]))
                if not resolved:
                    return
                # scan the enclosing function/global scope for setRequestHeader calls
                xhr_headers = self._xhr_headers(node, obj_text)
                ev_extra = ""
                if xhr_headers:
                    ev_extra = "headers: " + ",".join(xhr_headers.keys())
                for url in resolved:
                    self._add_with_evidence(
                        url, method.upper(), node,
                        confidence=0.90, extra=ev_extra,
                    )
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

    # ── Pass 3: secret key/value pair extraction ─────────────────────────────

    def _extract_secret_pairs_iter(self, root) -> None:
        """
        Iterative DFS secret pair extraction. Walks every `pair` node in the AST
        and every variable declarator / assignment where the name looks like a
        secret key. Also detects multi-key Firebase-style config objects via
        _materialize_object().
        """
        stack = [root]
        while stack:
            if self._elapsed() > AST_MAX_SECONDS:
                return
            node = stack.pop()
            t = node.type
            if t == "pair":
                self._handle_secret_pair(node)
            elif t in ("variable_declarator", "assignment_expression"):
                self._handle_secret_assignment(node)
            elif t == "object":
                # check if this object is a multi-key config block (Firebase etc.)
                self._handle_config_object(node)
            stack.extend(reversed(node.named_children))

    def _extract_secret_pairs(self, node) -> None:
        """Recursive fallback - kept for any internal callers."""
        if self._elapsed() > AST_MAX_SECONDS:
            return
        t = node.type
        if t == "pair":
            self._handle_secret_pair(node)
        elif t in ("variable_declarator", "assignment_expression"):
            self._handle_secret_assignment(node)
        for child in node.named_children:
            self._extract_secret_pairs(child)

    def _handle_secret_pair(self, node) -> None:
        """Handle a `pair` node: { key: "value" }."""
        key_node = node.child_by_field_name("key")
        val_node = node.child_by_field_name("value")
        if not key_node or not val_node:
            return

        key_raw = self._text(key_node).strip("'\"` \t\n")
        if not key_raw:
            return

        severity, confidence = _classify_key(key_raw)
        if severity is None:
            return

        # Only flag string literal values - skip variables, function calls etc.
        value = self._extract_string_value(val_node)
        if not value:
            # Try env resolution if it's a variable name
            if val_node.type == "identifier":
                resolved = self.env.resolve(self._text(val_node))
                if resolved and len(resolved) >= 8:
                    value = resolved
                    confidence = max(0.60, confidence - 0.15)  # lower conf for resolved
            if not value:
                return

        if len(value) < 8:
            return

        dedup = f"{key_raw.lower()}:{value}"
        if dedup in self._seen_secret:
            return
        self._seen_secret.add(dedup)

        line = key_node.start_point[0] + 1
        start = max(0, node.start_byte - 40)
        end   = min(len(self._src), node.end_byte + 40)
        ctx   = self._src[start:end].decode("utf-8", errors="replace").replace("\n", " ").strip()[:200]

        self.secret_hits.append(ASTSecretHit(
            key_name   = key_raw,
            value      = value,
            line       = line,
            context    = ctx,
            severity   = severity,
            confidence = confidence,
        ))
        logger.debug("AST secret pair: key=%r severity=%s line=%d", key_raw, severity, line)

    def _handle_secret_assignment(self, node) -> None:
        """
        Handle variable declarators and bare assignments where the variable
        name itself looks like a secret key.

        Covers:
          const apiKey = "..."
          this.apiKey = "..."
          config.apiKey = "..."
        """
        children = node.named_children
        if len(children) < 2:
            return

        lhs = children[0]
        rhs = children[1]

        # Pull the rightmost identifier from the LHS (the property name)
        if lhs.type == "identifier":
            key_raw = self._text(lhs)
        elif lhs.type == "member_expression":
            prop = lhs.child_by_field_name("property")
            key_raw = self._text(prop) if prop else ""
        else:
            return

        key_raw = key_raw.strip()
        if not key_raw:
            return

        severity, confidence = _classify_key(key_raw)
        if severity is None:
            return

        value = self._extract_string_value(rhs)
        if not value:
            if rhs.type == "identifier":
                resolved = self.env.resolve(self._text(rhs))
                if resolved and len(resolved) >= 8:
                    value = resolved
                    confidence = max(0.60, confidence - 0.15)
            if not value:
                return

        if len(value) < 8:
            return

        dedup = f"{key_raw.lower()}:{value}"
        if dedup in self._seen_secret:
            return
        self._seen_secret.add(dedup)

        line = lhs.start_point[0] + 1
        start = max(0, node.start_byte - 40)
        end   = min(len(self._src), node.end_byte + 40)
        ctx   = self._src[start:end].decode("utf-8", errors="replace").replace("\n", " ").strip()[:200]

        self.secret_hits.append(ASTSecretHit(
            key_name   = key_raw,
            value      = value,
            line       = line,
            context    = ctx,
            severity   = severity,
            confidence = confidence,
        ))
        logger.debug("AST secret assignment: key=%r severity=%s line=%d", key_raw, severity, line)

    def _materialize_object(self, node) -> Dict[str, str]:
        """
        Turn an `object` AST node into a {key: value} dict of string pairs.
        Non-string values and unresolvable identifiers are skipped.
        Used by _handle_config_object() to detect multi-key secret blocks.
        """
        result: Dict[str, str] = {}
        for child in node.named_children:
            if child.type != "pair":
                continue
            key_node = child.child_by_field_name("key")
            val_node = child.child_by_field_name("value")
            if not key_node or not val_node:
                continue
            key = self._text(key_node).strip("'\"` \t\n")
            if not key:
                continue
            val = self._extract_string_value(val_node)
            if not val and val_node.type == "identifier":
                val = self.env.resolve(self._text(val_node))
            if val:
                result[key] = val
        return result

    def _handle_config_object(self, node) -> None:
        """
        Check an object node for Firebase-style multi-key config blocks.
        If 2+ keys in the same object are secret indicators, treat them
        together - this catches blocks that individually might look low-severity
        but together are clearly credential objects.

        E.g.:  const firebaseConfig = {
                   apiKey: "AIzaSy...",
                   authDomain: "proj.firebaseapp.com",
                   projectId: "proj",
                   ...
               }
        """
        obj = self._materialize_object(node)
        if len(obj) < 2:
            return

        # count how many keys are secret indicators
        hits = []
        for key, value in obj.items():
            severity, confidence = _classify_key(key)
            if severity and len(value) >= 8:
                hits.append((key, value, severity, confidence))

        # only treat as a config block if 2+ secret keys present
        if len(hits) < 2:
            return

        # upgrade severity: if any key is HIGH, whole block is HIGH
        block_severity = "HIGH" if any(s == "HIGH" for _, _, s, _ in hits) else "MEDIUM"
        # confidence boost for multi-key blocks
        block_confidence = min(0.95, max(c for _, _, _, c in hits) + 0.05)

        for key, value, _, _ in hits:
            dedup = f"{key.lower()}:{value}"
            if dedup in self._seen_secret:
                continue
            self._seen_secret.add(dedup)

            line = node.start_point[0] + 1
            start = max(0, node.start_byte - 20)
            end   = min(len(self._src), node.end_byte + 20)
            ctx   = self._src[start:end].decode("utf-8", errors="replace").replace("\n", " ").strip()[:200]

            self.secret_hits.append(ASTSecretHit(
                key_name   = key,
                value      = value,
                line       = line,
                context    = ctx,
                severity   = block_severity,
                confidence = block_confidence,
            ))
            logger.debug("AST config block: key=%r severity=%s line=%d", key, block_severity, line)

    def _extract_string_value(self, node) -> Optional[str]:
        """
        Return the decoded string value from a string/template/concat node.
        Uses _collapsed_string() for binary expressions so partial values like
        "sk-EXPR" are captured instead of dropped entirely.
        """
        if node.type == "string":
            return self._string_value(node)
        if node.type == "template_string":
            val = self._template_value(node)
            return val if val and "{dynamic}" not in val else None
        if node.type == "binary_expression":
            return self._collapsed_string(node)
        return None

    def _collapsed_string(self, node) -> Optional[str]:
        """
        Flatten a binary + expression into a readable string.
        Known string parts are kept verbatim; unresolvable expressions
        become the placeholder EXPR. Returns None if entirely dynamic
        (no static fragment at all), or if the result is too short to matter.

        E.g.:  "sk-" + someVar  ->  "sk-EXPR"
               prefix + apiKey  ->  "EXPRapiKey"  (if apiKey is literal)
        """
        if node.type != "binary_expression":
            return None

        # only handle string concatenation, not arithmetic
        op = None
        for child in node.children:
            if child.type == "+" or (child.type not in ("binary_expression", "string",
                                                          "identifier", "member_expression",
                                                          "template_string", "call_expression",
                                                          "number") and len(self._text(child)) == 1):
                op = self._text(child)
                break
        # fall back: check raw text for + operator
        raw = self._text(node)
        if "+" not in raw:
            return None

        left_node  = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")
        if not left_node or not right_node:
            return None

        left  = self._collapse_part(left_node)
        right = self._collapse_part(right_node)

        combined = left + right
        # must have at least one static fragment to be useful
        if combined == "EXPREXPR":
            return None
        # must be long enough to matter as a secret value
        static_len = len(combined.replace("EXPR", ""))
        if static_len < 3:
            return None
        return combined

    def _collapse_part(self, node) -> str:
        """
        Resolve one side of a binary expression to a string fragment.
        Falls back to EXPR placeholder for anything unresolvable.
        """
        t = node.type
        if t == "string":
            return self._string_value(node) or "EXPR"
        if t == "template_string":
            val = self._template_value(node)
            return val if val else "EXPR"
        if t == "identifier":
            resolved = self.env.resolve(self._text(node))
            return resolved if resolved else "EXPR"
        if t == "member_expression":
            resolved = self.env.resolve(self._text(node))
            return resolved if resolved else "EXPR"
        if t == "binary_expression":
            inner = self._collapsed_string(node)
            return inner if inner else "EXPR"
        if t == "parenthesized_expression" and node.named_children:
            return self._collapse_part(node.named_children[0])
        return "EXPR"

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

    def _jquery_config_obj(
        self, obj_node
    ) -> Tuple[Optional[str], Optional[str], List[str], List[str]]:
        """Parse a jQuery settings object - returns (url, method, params, headers).

        Handles all three surface areas:
          - url / type / method keys
          - data: { key: val } -> body/query param names
          - headers: { Authorization: "..." } -> header names (flags hardcoded auth)
        """
        url: Optional[str] = None
        method: Optional[str] = None
        params: List[str] = []
        headers: List[str] = []

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

            elif key == "data" and val_node.type == "object":
                # collect param names from data object
                for p in val_node.named_children:
                    if p.type != "pair":
                        continue
                    pk = p.child_by_field_name("key")
                    if pk:
                        pname = self._text(pk).strip("'\"` ")
                        if pname:
                            params.append(pname)

            elif key == "headers" and val_node.type == "object":
                # collect header names; note any hardcoded auth values
                _auth_headers = {"authorization", "x-api-key", "x-auth-token",
                                 "x-access-token", "token", "api-key", "apikey"}
                for h in val_node.named_children:
                    if h.type != "pair":
                        continue
                    hk = h.child_by_field_name("key")
                    hv = h.child_by_field_name("value")
                    if not hk:
                        continue
                    hname = self._text(hk).strip("'\"` ")
                    if not hname:
                        continue
                    headers.append(hname)
                    # if a sensitive header has a hardcoded string value, emit a secret hit
                    if hname.lower() in _auth_headers and hv is not None:
                        hval = self._string_from_node(hv)
                        if hval and len(hval) >= 8:
                            # skip if already recorded by the pair-level scan
                            already = any(
                                s.key_name == hname and s.value == hval
                                for s in self.secret_hits
                            )
                            if not already:
                                hit = ASTSecretHit(
                                    key_name   = hname,
                                    value      = hval,
                                    line       = h.start_point[0] + 1,
                                    context    = f"jQuery header: {hname}",
                                    severity   = "HIGH",
                                    confidence = 0.88,
                                )
                                self.secret_hits.append(hit)

        return url, method, params, headers

    def _extract_object_keys(self, obj_node) -> List[str]:
        """Return all top-level key names from an object literal node."""
        keys: List[str] = []
        for pair in obj_node.named_children:
            if pair.type != "pair":
                continue
            kn = pair.child_by_field_name("key")
            if kn:
                k = self._text(kn).strip("'\"` ")
                if k:
                    keys.append(k)
        return keys

    def _jquery_evidence(self, params: List[str], headers: List[str]) -> str:
        """Build an evidence suffix string for jQuery param/header info."""
        parts: List[str] = []
        if params:
            parts.append("params: " + ",".join(params))
        if headers:
            parts.append("headers: " + ",".join(headers))
        return " | ".join(parts)

    def _xhr_headers(self, open_node, xhr_obj_name: str) -> Dict[str, str]:
        """
        Walk up to the enclosing function/global scope and find
        xhr_obj_name.setRequestHeader(name, value) calls.
        Returns {header_name: value_or_empty}.
        Flags hardcoded auth headers as HIGH secret hits.
        """
        _auth_headers = {"authorization", "x-api-key", "x-auth-token",
                         "x-access-token", "token", "api-key", "apikey"}

        # ascend to function or global scope
        scope = open_node.parent
        if scope is None:
            return {}
        while True:
            parent = scope.parent
            if parent is None:
                break
            scope = parent
            t = scope.type
            if t in ("function_declaration", "function", "arrow_function"):
                break

        # scan all call_expressions in scope for xhr.setRequestHeader(...)
        headers: Dict[str, str] = {}
        stack = list(reversed(scope.children))
        while stack:
            n = stack.pop()
            if n.type == "call_expression":
                fn = n.child_by_field_name("function")
                if fn is not None:
                    fn_text = self._text(fn)
                    if (fn_text.endswith(".setRequestHeader")
                            and fn_text.startswith(xhr_obj_name)):
                        args_node = n.child_by_field_name("arguments")
                        if args_node is not None:
                            named = args_node.named_children
                            if named and named[0].type == "string":
                                hname = self._text(named[0]).strip("'\"` ")
                                if hname and hname not in headers:
                                    hval = ""
                                    if len(named) > 1 and named[1].type == "string":
                                        hval = self._text(named[1]).strip("'\"` ")
                                    headers[hname] = hval
                                    # flag hardcoded sensitive header values
                                    if hname.lower() in _auth_headers and len(hval) >= 8:
                                        already = any(
                                            s.key_name == hname and s.value == hval
                                            for s in self.secret_hits
                                        )
                                        if not already:
                                            self.secret_hits.append(ASTSecretHit(
                                                key_name   = hname,
                                                value      = hval,
                                                line       = n.start_point[0] + 1,
                                                context    = f"XHR setRequestHeader: {hname}",
                                                severity   = "HIGH",
                                                confidence = 0.88,
                                            ))
            # descend into children (skip function boundaries to stay in scope)
            if n.type not in ("function_declaration", "function", "arrow_function"):
                stack.extend(reversed(n.children))

        return headers

    def _add_with_evidence(
        self,
        path: str,
        method: str,
        node,
        confidence: float = 0.80,
        extra: str = "",
    ) -> None:
        """Wrapper around _add that appends extra context to the evidence field."""
        if not path or not self._is_url_like(path) or self._is_skip(path):
            return
        if path == "{dynamic}":
            return

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

        start = max(0, node.start_byte - 10)
        end   = min(len(self._src), node.end_byte + 20)
        ev    = self._src[start:end].decode("utf-8", errors="replace").replace("\n", " ").strip()[:180]
        if extra:
            ev = (ev + " | " + extra)[:200]

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
