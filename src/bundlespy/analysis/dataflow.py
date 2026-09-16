"""
Lightweight bounded constant propagation / data-flow analysis.

Purpose: resolve simple variable references in JavaScript so extractors
can find endpoints that are built from variables rather than literal strings.

Design constraints:
- Single-pass, O(n) scan — never quadratic
- Hard limits on substitution depth to prevent infinite loops
- Never invents values — unresolved expressions marked as dynamic
- Never performs network I/O or full AST parsing
- Safe on minified bundles

Resolves:
  const base = "/api";
  const url = base + "/users";
  fetch(url);                    → GET /api/users

  const ENDPOINT = `/api/v2/${resource}`;
                                 → /api/v2/{resource}

  const config = { apiBase: "/api/v2", ws: "wss://host/ws" };
                                 → config.apiBase = /api/v2
                                   config.ws      = wss://host/ws
"""

import re
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("bundlespy.analysis.dataflow")

# ── Limits ────────────────────────────────────────────────────────────────────

MAX_VARS        = 500   # max variables to track
MAX_DEPTH       = 5     # max substitution depth
MAX_CONTENT_MB  = 4     # skip files larger than this
DYNAMIC_MARKER  = "{dynamic}"

# ── Patterns ──────────────────────────────────────────────────────────────────

# const/let/var name = "value"  or  name = 'value'  or  name = `value`
RE_STR_ASSIGN = re.compile(
    r'\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,60})\s*=\s*'
    r'(["\x27`])((?:[^\2\\]|\\.)*?)\2',
    re.MULTILINE,
)

# const name = "prefix" + "suffix" (both literals — same or different quotes)
RE_CONCAT_BOTH_LITERALS = re.compile(
    r'\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,60})\s*=\s*'
    r'["\x27`]([^"\x27`\n]{0,200})["\x27`]\s*\+\s*'
    r'["\x27`]([^"\x27`\n]{0,200})["\x27`]',
    re.MULTILINE,
)

# const name = other + "/suffix"  or  name = other + name2
RE_CONCAT_ASSIGN = re.compile(
    r'\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,60})\s*=\s*'
    r'([A-Za-z_$][A-Za-z0-9_$]{0,60})\s*\+\s*'
    r'(["\x27`])([^"\x27`]{0,200})\3',
    re.MULTILINE,
)

# const name = "prefix" + other
RE_CONCAT_ASSIGN_REV = re.compile(
    r'\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,60})\s*=\s*'
    r'(["\x27`])([^"\x27`]{0,200})\2\s*\+\s*'
    r'([A-Za-z_$][A-Za-z0-9_$]{0,60})',
    re.MULTILINE,
)

# Template literal: const name = `prefix/${var}/suffix`
RE_TEMPLATE_ASSIGN = re.compile(
    r'\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,60})\s*=\s*'
    r'`([^`]{0,300})`',
    re.MULTILINE,
)

# Object property: { apiBase: "/api/v2" } — match one property at a time
RE_OBJ_PROP_STR = re.compile(
    r'["\x27]?([A-Za-z_$][A-Za-z0-9_$]{0,60})["\x27]?\s*:\s*'
    r'(["\x27`])((?:[^\2\\,\n]|\\.){0,300}?)\2'
    r'(?=\s*[,}\n])',
    re.MULTILINE,
)

# Interesting config key names (API URLs, endpoints, bases)
_API_KEY_PATTERNS = re.compile(
    r'(?:api|base|url|endpoint|host|origin|backend|graphql|ws|socket|'
    r'cdn|assets|static|server|gateway|proxy)',
    re.IGNORECASE,
)

# Template var substitution: ${varName}
RE_TEMPLATE_VAR = re.compile(r'\$\{([A-Za-z_$][A-Za-z0-9_$.]{0,60})\}')

# Express-style :param
RE_PATH_PARAM = re.compile(r':([A-Za-z_][A-Za-z0-9_]{0,30})')


def _is_url_like(value: str) -> bool:
    """Return True if the value looks like a URL path or full URL."""
    if not value or len(value) < 2:
        return False
    v = value.strip()
    return (
        v.startswith("/")
        or v.startswith("http://")
        or v.startswith("https://")
        or v.startswith("ws://")
        or v.startswith("wss://")
        or v.startswith("./")
        or v.startswith("../")
    )


def _normalize_template(tmpl: str, env: Dict[str, str], depth: int = 0) -> str:
    """
    Substitute ${var} references in a template literal string.
    Falls back to {var} (param marker) for unresolved references.
    """
    if depth > MAX_DEPTH:
        return tmpl

    def _sub(m: re.Match) -> str:
        name = m.group(1).split(".")[0]  # handle config.key → config
        if name in env:
            val = env[name]
            if _is_url_like(val) or "/" in val:
                return val
        # Check dotted access: config.apiBase
        full = m.group(1)
        if "." in full:
            obj, attr = full.split(".", 1)
            obj_key = f"{obj}.{attr}"
            if obj_key in env:
                return env[obj_key]
        return f"{{{m.group(1)}}}"  # param marker

    result = RE_TEMPLATE_VAR.sub(_sub, tmpl)
    # Normalize Express :param style
    result = RE_PATH_PARAM.sub(lambda m2: f"{{{m2.group(1)}}}", result)
    return result


def _is_placeholder(value: str) -> bool:
    """Return True if value is obviously a placeholder, not a real URL."""
    lower = value.lower().strip()
    bad = {
        "", "undefined", "null", "true", "false", "none",
        "object object", "[object object]", "nan", "infinity",
        "your-api-key", "your_api_key", "api_key", "api-key",
        "example.com", "localhost", "127.0.0.1", "0.0.0.0",
    }
    if lower in bad:
        return True
    # Pure variable name with no slashes
    if re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', value) and "/" not in value:
        return True
    return False


class DataFlowEnv:
    """
    Bounded variable environment for constant propagation.
    Collects string assignments and config object properties.
    """

    def __init__(self):
        self.vars: Dict[str, str] = {}         # name → resolved string value
        self.config: Dict[str, str] = {}        # obj.key → value  (config intel)
        self._count = 0

    def _store(self, name: str, value: str) -> None:
        if self._count >= MAX_VARS:
            return
        if not value or _is_placeholder(value):
            return
        self.vars[name] = value
        self._count += 1

    def _store_config(self, key: str, value: str) -> None:
        """Store a config property if it looks API-related."""
        if _API_KEY_PATTERNS.search(key) and _is_url_like(value):
            self.config[key] = value

    def scan(self, content: str) -> None:
        """Single-pass scan to collect variable bindings."""
        if len(content) > MAX_CONTENT_MB * 1024 * 1024:
            logger.debug("Content too large for dataflow, skipping")
            return

        # 1. Simple string assignments
        for m in RE_STR_ASSIGN.finditer(content):
            name  = m.group(1)
            value = m.group(3)
            self._store(name, value)

        # 2. Template literal assignments
        for m in RE_TEMPLATE_ASSIGN.finditer(content):
            name  = m.group(1)
            tmpl  = m.group(2)
            resolved = _normalize_template(tmpl, self.vars)
            self._store(name, resolved)

        # 0b. Literal + literal concatenation (run after simple assignments
        #     so we can overwrite the partial match that RE_STR_ASSIGN grabbed)
        for m in RE_CONCAT_BOTH_LITERALS.finditer(content):
            name   = m.group(1)
            prefix = m.group(2)
            suffix = m.group(3)
            combined = prefix + suffix
            # Always overwrite with the full concatenation
            if combined and not _is_placeholder(combined):
                self.vars[name] = combined

        # 3. Concatenation: other + "/suffix"
        for m in RE_CONCAT_ASSIGN.finditer(content):
            name   = m.group(1)
            lhs    = m.group(2)
            suffix = m.group(4)
            lhs_val = self.vars.get(lhs, "")
            if lhs_val and not _is_placeholder(lhs_val):
                combined = lhs_val + suffix
                self._store(name, combined)

        # 4. Concatenation: "prefix" + other
        for m in RE_CONCAT_ASSIGN_REV.finditer(content):
            name   = m.group(1)
            prefix = m.group(3)
            rhs    = m.group(4)
            rhs_val = self.vars.get(rhs, "")
            if rhs_val and not _is_placeholder(rhs_val):
                combined = prefix + rhs_val
                self._store(name, combined)
            elif prefix:
                # Store prefix alone so later resolvers can use it
                self._store(name, prefix + DYNAMIC_MARKER)

        # 5. Config/object properties
        for m in RE_OBJ_PROP_STR.finditer(content):
            key   = m.group(1)
            value = m.group(3)
            self._store_config(key, value)
            # Also track in vars for template resolution
            if _is_url_like(value):
                self._store(key, value)

    def resolve(self, name: str, depth: int = 0) -> Optional[str]:
        """Resolve a variable name to its string value, if known."""
        if depth > MAX_DEPTH:
            return None
        return self.vars.get(name)

    def resolve_template(self, tmpl: str) -> str:
        """Resolve template literal using known variable bindings."""
        return _normalize_template(tmpl, self.vars)

    def get_api_config(self) -> Dict[str, str]:
        """Return config properties that look like API endpoints."""
        return dict(self.config)


def build_env(content: str) -> DataFlowEnv:
    """
    Build and return a populated DataFlowEnv for the given JS content.
    This is the main entry point for the analysis layer.
    """
    env = DataFlowEnv()
    env.scan(content)
    return env


def resolve_url_arg(arg: str, env: DataFlowEnv) -> Optional[str]:
    """
    Given a raw argument from a fetch/axios/etc call (which may be a variable
    name, a template literal, or a concatenation result), try to resolve it
    to a concrete URL using the data-flow environment.

    Returns None if the argument cannot be resolved to a URL-like string.
    Returns DYNAMIC_MARKER if partially resolved but contains unknowns.
    """
    if not arg:
        return None

    arg = arg.strip()

    # Already a string literal (was extracted by regex with quotes stripped)
    if _is_url_like(arg) and not _is_placeholder(arg):
        return arg

    # Variable reference
    if re.match(r'^[A-Za-z_$][A-Za-z0-9_$.]*$', arg):
        # Try dotted: config.apiBase
        if "." in arg:
            val = env.config.get(arg)
            if val and _is_url_like(val):
                return val
        val = env.resolve(arg)
        if val and _is_url_like(val) and not _is_placeholder(val):
            return val
        return None

    # Template literal body (backticks already stripped)
    if "${" in arg:
        resolved = env.resolve_template(arg)
        if _is_url_like(resolved.split("{")[0]):  # prefix is URL-like
            return resolved
        return None

    return None
