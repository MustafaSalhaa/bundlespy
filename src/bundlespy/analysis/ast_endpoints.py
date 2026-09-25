"""
Advanced Endpoint Extractor.

Integrates with the lightweight data-flow engine (dataflow.py) to resolve
variable references before pattern matching. Builds on the existing regex
foundation — does not replace it.

New capabilities vs previous version:
- Bounded constant propagation via DataFlowEnv
- Variable reference resolution in fetch/axios/XHR/etc arguments
- Dynamic import / module discovery
- Worker / ServiceWorker / SharedWorker detection
- navigator.sendBeacon detection
- EventSource detection
- GraphQL operation name extraction
- Config object API URL extraction
- Evidence snippets and accurate source locations on every finding
- Netlify / Vercel / serverless function patterns
- All unresolved expressions marked dynamic, never invented
"""

import re
import logging
import time
from typing import List, Set, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..storage.models import Endpoint
from .dataflow import build_env, resolve_url_arg, DYNAMIC_MARKER, _is_url_like, _is_placeholder

logger = logging.getLogger("bundlespy.analysis.ast_endpoints")

# ── Performance guard ─────────────────────────────────────────────────────────

MAX_ANALYSIS_SECONDS = 8.0  # hard wall-clock limit per file


# ── HTTP client patterns ──────────────────────────────────────────────────────

RE_FETCH = re.compile(
    r'\bfetch\s*\(\s*(["\x27`])(/[A-Za-z0-9/_\-.:?=&%#{}]+)\1',
    re.IGNORECASE,
)

RE_FETCH_VAR = re.compile(
    r'\bfetch\s*\(\s*([A-Za-z_$][A-Za-z0-9_$.]{0,60})',
    re.IGNORECASE,
)

RE_FETCH_TEMPLATE = re.compile(
    r'\bfetch\s*\(\s*`([^`]{0,300})`',
    re.IGNORECASE,
)

RE_AXIOS = re.compile(
    r'\baxios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*["\x27`]'
    r'(/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

RE_AXIOS_VAR = re.compile(
    r'\baxios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*'
    r'([A-Za-z_$][A-Za-z0-9_$.]{0,60})',
    re.IGNORECASE,
)

RE_AXIOS_TEMPLATE = re.compile(
    r'\baxios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*`(/[^`]{0,200})`',
    re.IGNORECASE,
)

RE_AXIOS_CONFIG = re.compile(
    r'\baxios\s*\(\s*\{[^}]{0,200}url\s*:\s*["\x27`](/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE | re.DOTALL,
)

RE_JQUERY_AJAX = re.compile(
    r'\$\s*\.\s*(?:ajax|get|post|put|delete)\s*\(\s*["\x27`]'
    r'(/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

RE_XHR = re.compile(
    r'\.open\s*\(\s*["\x27`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["\x27`]\s*,\s*'
    r'["\x27`](/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

RE_XHR_VAR = re.compile(
    r'\.open\s*\(\s*["\x27`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["\x27`]\s*,\s*'
    r'([A-Za-z_$][A-Za-z0-9_$.]{0,60})',
    re.IGNORECASE,
)

RE_HTTP_CLIENTS = re.compile(
    r'\b(?:request|superagent|got|ky|agent|http)\s*\.\s*'
    r'(?:get|post|put|delete|patch)\s*\(\s*["\x27`]'
    r'(/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

# navigator.sendBeacon(url, data)
RE_BEACON = re.compile(
    r'\bnavigator\s*\.\s*sendBeacon\s*\(\s*["\x27`]'
    r'(/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

RE_BEACON_VAR = re.compile(
    r'\bnavigator\s*\.\s*sendBeacon\s*\(\s*([A-Za-z_$][A-Za-z0-9_$.]{0,60})',
    re.IGNORECASE,
)

# EventSource
RE_EVENTSOURCE = re.compile(
    r'\bnew\s+EventSource\s*\(\s*["\x27`](/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

# ── String patterns ───────────────────────────────────────────────────────────

RE_CONCAT = re.compile(
    r'["\x27`](/[A-Za-z0-9/_\-]{1,50})["\x27`]\s*\+\s*["\x27`]([A-Za-z0-9/_\-]{1,50})["\x27`]',
    re.IGNORECASE,
)

RE_TEMPLATE = re.compile(
    r'`(/[A-Za-z0-9/_\-.:?=&%#{}$]+(?:\$\{[^}]+\}[A-Za-z0-9/_\-.:?=&%#{}]*)*)`',
    re.IGNORECASE,
)

# ── Route definitions ─────────────────────────────────────────────────────────

RE_ROUTE_PATH = re.compile(
    r'\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}*][A-Za-z0-9/_\-.:?=&%#{}*]*)["\x27`]',
    re.IGNORECASE,
)

RE_ROUTE_MAP_VALUE = re.compile(
    r':\s*["\x27`](/api/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

RE_EXPRESS_ROUTE = re.compile(
    r'\b(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|use)\s*\(\s*["\x27`]'
    r'(/[A-Za-z0-9/_\-.:?=&%#{}:*]+)["\x27`]',
    re.IGNORECASE,
)

# ── GraphQL ───────────────────────────────────────────────────────────────────

RE_GRAPHQL_PATH = re.compile(
    r'["\x27`](/graphql[A-Za-z0-9/_\-.:?=&%#]*)["\x27`]',
    re.IGNORECASE,
)

# GraphQL operation: query MyOp { ... } / mutation UpdateX { ... }
RE_GQL_OPERATION = re.compile(
    r'\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]{0,80})\s*'
    r'(?:\([^)]{0,200}\))?\s*\{',
    re.IGNORECASE,
)

# ── WebSocket ─────────────────────────────────────────────────────────────────

RE_WEBSOCKET = re.compile(
    r'\bnew\s+WebSocket\s*\(\s*["\x27`](wss?://[^\s"\x27`]+)["\x27`]',
    re.IGNORECASE,
)

RE_WEBSOCKET_VAR = re.compile(
    r'\bnew\s+WebSocket\s*\(\s*([A-Za-z_$][A-Za-z0-9_$.]{0,60})',
    re.IGNORECASE,
)

RE_WEBSOCKET_TEMPLATE = re.compile(
    r'\bnew\s+WebSocket\s*\(\s*`(wss?://[^`]+)`',
    re.IGNORECASE,
)

# ── Dynamic imports ───────────────────────────────────────────────────────────

RE_DYNAMIC_IMPORT = re.compile(
    r'\bimport\s*\(\s*["\x27`](\./[A-Za-z0-9/_\-.:?=&%#.]+)["\x27`]\s*\)',
    re.IGNORECASE,
)

RE_DYNAMIC_IMPORT_TEMPLATE = re.compile(
    r'\bimport\s*\(\s*`(\./[^`]+)`\s*\)',
    re.IGNORECASE,
)

RE_REQUIRE = re.compile(
    r'\brequire\s*\(\s*["\x27`](\./[A-Za-z0-9/_\-.:?=&%#.]+)["\x27`]\s*\)',
    re.IGNORECASE,
)

RE_NEW_URL_IMPORT = re.compile(
    r'\bnew\s+URL\s*\(\s*["\x27`](\./[^"\x27`]+)["\x27`]\s*,\s*import\.meta\.url\s*\)',
    re.IGNORECASE,
)

# ── Workers ───────────────────────────────────────────────────────────────────

RE_WORKER = re.compile(
    r'\bnew\s+(?:Worker|SharedWorker)\s*\(\s*["\x27`]([^"\x27`]+)["\x27`]',
    re.IGNORECASE,
)

RE_WORKER_NEW_URL = re.compile(
    r'\bnew\s+(?:Worker|SharedWorker)\s*\(\s*new\s+URL\s*\(\s*["\x27`]([^"\x27`]+)["\x27`]',
    re.IGNORECASE,
)

RE_SW_REGISTER = re.compile(
    r'serviceWorker\s*\.\s*register\s*\(\s*["\x27`]([^"\x27`]+)["\x27`]',
    re.IGNORECASE,
)

RE_IMPORT_SCRIPTS = re.compile(
    r'\bimportScripts\s*\(\s*["\x27`]([^"\x27`]+)["\x27`]',
    re.IGNORECASE,
)

# ── Admin / Auth / Upload paths ───────────────────────────────────────────────

RE_ADMIN_PATH = re.compile(
    r'["\x27`](/(?:admin|internal|manage|management|dashboard|panel|staff|superuser)'
    r'[A-Za-z0-9/_\-.:?=&%#]*)["\x27`]',
    re.IGNORECASE,
)

RE_AUTH_PATH = re.compile(
    r'["\x27`](/(?:auth|login|logout|signin|signup|register|oauth|token|refresh|session)'
    r'[A-Za-z0-9/_\-.:?=&%#]*)["\x27`]',
    re.IGNORECASE,
)

RE_UPLOAD_PATH = re.compile(
    r'["\x27`](/(?:upload|download|import|export|file|files|attachment|media)'
    r'[A-Za-z0-9/_\-.:?=&%#]*)["\x27`]',
    re.IGNORECASE,
)

RE_API_ASSIGN = re.compile(
    r'["\x27`](/api/[A-Za-z0-9/_\-.:?=&%#{}/]+)["\x27`]',
    re.IGNORECASE,
)

# Serverless function patterns
RE_SERVERLESS_PATH = re.compile(
    r'["\x27`]((?:/\.netlify/functions/|/functions/|/\.vercel/|/serverless/)'
    r'[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

# Redirect/navigation
RE_REDIRECT = re.compile(
    r'(?:window\.location|router\.push|navigate|redirect)\s*[\(=]\s*["\x27`]'
    r'(/[A-Za-z0-9/_\-.:?=&%#]+)["\x27`]',
    re.IGNORECASE,
)


# ── Categorization ────────────────────────────────────────────────────────────

def _categorize(path: str, method: str = "UNKNOWN") -> str:
    lower = path.lower()
    if any(k in lower for k in ["/login", "/logout", "/auth", "/oauth",
                                  "/token", "/session", "/signin", "/signup",
                                  "/register", "/refresh", "/password", "/2fa", "/mfa", "/sso"]):
        return "AUTH"
    if any(k in lower for k in ["/admin", "/internal", "/manage",
                                  "/management", "/panel", "/staff",
                                  "/superuser", "/dashboard/admin", "/backoffice"]):
        return "ADMIN"
    if "/graphql" in lower or "/gql" in lower:
        return "GRAPHQL"
    if any(lower.startswith(p) or p in lower for p in [
        "/.netlify/functions/", "/.netlify/", "/functions/",
        "/serverless/", "/lambdas/", "/fn/", "/.vercel/",
    ]):
        return "SERVERLESS"
    if any(k in lower for k in ["/upload", "/import", "/ingest", "/attach"]):
        return "UPLOAD"
    if any(k in lower for k in ["/download", "/export", "/file"]):
        return "DOWNLOAD"
    if lower.startswith("ws://") or lower.startswith("wss://") or "/socket" in lower or "/ws/" in lower:
        return "WEBSOCKET"
    if any(k in lower for k in ["/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/v5/", "/rest/"]):
        return "API"
    return "UNKNOWN"


def _get_line(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _get_col(content: str, pos: int) -> int:
    last_nl = content.rfind("\n", 0, pos)
    return pos - last_nl if last_nl >= 0 else pos


def _clean_path(path: str) -> str:
    """Normalize template vars and Express params to {param} markers."""
    path = re.sub(r'\$\{[^}]+\}', '{dynamic}', path)
    path = re.sub(r':[A-Za-z_][A-Za-z0-9_]*', '{param}', path)
    path = re.sub(r'\[[^\]]+\]', '{param}', path)  # Next.js [param]
    path = path.rstrip("/") or "/"
    return path


def _is_valid_path(path: str) -> bool:
    """Filter out obvious non-endpoint values."""
    if not path or len(path) < 2:
        return False
    lower = path.lower()

    if lower.startswith("ws://") or lower.startswith("wss://"):
        return True

    skip_exts = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".css", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
        ".mp4", ".mp3", ".avi", ".mov", ".map",
    )
    if any(lower.endswith(ext) for ext in skip_exts):
        return False

    if lower in ("/", "/*", "//"):
        return False

    # Reject paths that start with an unresolved template placeholder
    if path.startswith("{") or re.match(r'^\{[^}]+\}', path):
        return False

    # Single-word route segments without leading slash are valid (Angular/React routes)
    # e.g. path: 'admin', path: 'users' — but not template placeholders
    if re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{1,50}$', path) and len(path) >= 2:
        return True

    skip_domains = [
        "reactjs.org", "w3.org", "github.com", "mdn.io",
        "developer.mozilla", "nodejs.org", "example.com",
        "twitter.com", "facebook.com", "linkedin.com",
        "googletagmanager.com", "fonts.googleapis.com",
    ]
    if any(d in lower for d in skip_domains):
        return False

    if _is_placeholder(path):
        return False

    # Full HTTP URLs only if API-like
    if path.startswith("http") and not path.startswith("ws"):
        if not any(k in lower for k in [
            "/api/", "/auth", "/admin", "/graphql",
            "/upload", "/download", "/v1/", "/v2/", "/v3/",
            "/rest/", "/gql", "/socket", "/functions/", ".netlify",
        ]):
            return False

    return True


def _evidence(content: str, pos: int, length: int = 120) -> str:
    """Return a short evidence snippet around a match position."""
    start = max(0, pos - 10)
    end   = min(len(content), pos + length)
    snippet = content[start:end].replace("\n", " ").strip()
    return snippet[:200]


# ── Dynamic import / worker result types ─────────────────────────────────────

class DynamicImport:
    """Represents a discovered dynamic import or module dependency."""
    __slots__ = ("url", "source_file", "line", "col", "dynamic", "kind", "evidence")

    def __init__(self, url: str, source_file: str, line: int, col: int,
                 dynamic: bool = False, kind: str = "import", evidence: str = ""):
        self.url         = url
        self.source_file = source_file
        self.line        = line
        self.col         = col
        self.dynamic     = dynamic
        self.kind        = kind   # import | require | worker | service-worker | import-scripts
        self.evidence    = evidence


class GraphQLOperation:
    """Represents a GraphQL operation found in JS."""
    __slots__ = ("op_type", "name", "source_file", "line", "evidence")

    def __init__(self, op_type: str, name: str, source_file: str,
                 line: int, evidence: str = ""):
        self.op_type     = op_type   # query | mutation | subscription
        self.name        = name
        self.source_file = source_file
        self.line        = line
        self.evidence    = evidence


class ConfigEntry:
    """A configuration property that looks like an API URL."""
    __slots__ = ("key", "value", "source_file", "line", "evidence")

    def __init__(self, key: str, value: str, source_file: str,
                 line: int, evidence: str = ""):
        self.key         = key
        self.value       = value
        self.source_file = source_file
        self.line        = line
        self.evidence    = evidence


# ── Main extractor ────────────────────────────────────────────────────────────

def extract_all_endpoints(
    content: str,
    file_url: str,
    base_origin: str = "",
) -> List[Endpoint]:
    """
    Extract all endpoints from JS content.

    Uses data-flow analysis to resolve variable references before
    applying regex patterns. Every finding includes:
    - accurate line/column
    - evidence snippet
    - confidence score
    - source_type = "static"
    """
    if not content:
        return []

    _t_start = time.monotonic()

    endpoints: List[Endpoint] = []
    seen: Set[str]            = set()

    # ── Build data-flow environment ───────────────────────────────────────────
    env = build_env(content)

    def _elapsed() -> float:
        return time.monotonic() - _t_start

    def _check_time() -> bool:
        """Return True if we're over the time limit."""
        if _elapsed() > MAX_ANALYSIS_SECONDS:
            logger.warning("Analysis time limit reached for %s", file_url)
            return True
        return False

    def add(path: str, method: str = "UNKNOWN", line_no: int = 0,
            col: int = 0, confidence: float = 0.75,
            evidence: str = "", source_type: str = "static") -> None:
        if not path:
            return

        # Never report dynamic-only placeholders as endpoints
        if path == DYNAMIC_MARKER or path.strip() == "{dynamic}":
            return

        path = _clean_path(path)

        if not _is_valid_path(path):
            return

        key = path.lower().rstrip("/").split("?")[0]
        # Strip {dynamic} from key for dedup
        key = re.sub(r'\{[^}]+\}', '*', key)
        if key in seen:
            return
        seen.add(key)

        category = _categorize(path, method)
        ep = Endpoint(
            url         = path,
            path        = path,
            method      = method,
            category    = category,
            source_file = file_url,
            line_number = line_no,
            confidence  = confidence,
            evidence    = evidence,
        )
        try:
            ep.source_type = source_type
        except Exception:
            pass
        endpoints.append(ep)

    # ── fetch() ───────────────────────────────────────────────────────────────
    for m in RE_FETCH.finditer(content):
        add(m.group(2), "GET", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.88, _evidence(content, m.start()))

    # fetch(variable)
    for m in RE_FETCH_VAR.finditer(content):
        resolved = resolve_url_arg(m.group(1), env)
        if resolved and resolved != DYNAMIC_MARKER:
            add(resolved, "GET", _get_line(content, m.start()),
                _get_col(content, m.start()), 0.78, _evidence(content, m.start()))

    # fetch(`template`)
    for m in RE_FETCH_TEMPLATE.finditer(content):
        resolved = env.resolve_template(m.group(1))
        add(resolved, "GET", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.82, _evidence(content, m.start()))

    if _check_time():
        return endpoints

    # ── axios ─────────────────────────────────────────────────────────────────
    for m in RE_AXIOS.finditer(content):
        add(m.group(2), m.group(1).upper(), _get_line(content, m.start()),
            _get_col(content, m.start()), 0.90, _evidence(content, m.start()))

    for m in RE_AXIOS_VAR.finditer(content):
        resolved = resolve_url_arg(m.group(2), env)
        if resolved and resolved != DYNAMIC_MARKER:
            add(resolved, m.group(1).upper(), _get_line(content, m.start()),
                _get_col(content, m.start()), 0.80, _evidence(content, m.start()))

    for m in RE_AXIOS_TEMPLATE.finditer(content):
        resolved = env.resolve_template(m.group(2))
        add(resolved, m.group(1).upper(), _get_line(content, m.start()),
            _get_col(content, m.start()), 0.84, _evidence(content, m.start()))

    for m in RE_AXIOS_CONFIG.finditer(content):
        add(m.group(1), "UNKNOWN", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.85, _evidence(content, m.start()))

    # ── jQuery ────────────────────────────────────────────────────────────────
    for m in RE_JQUERY_AJAX.finditer(content):
        add(m.group(1), "UNKNOWN", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.82, _evidence(content, m.start()))

    # ── XHR ───────────────────────────────────────────────────────────────────
    for m in RE_XHR.finditer(content):
        add(m.group(2), m.group(1).upper(), _get_line(content, m.start()),
            _get_col(content, m.start()), 0.88, _evidence(content, m.start()))

    for m in RE_XHR_VAR.finditer(content):
        resolved = resolve_url_arg(m.group(2), env)
        if resolved and resolved != DYNAMIC_MARKER:
            add(resolved, m.group(1).upper(), _get_line(content, m.start()),
                _get_col(content, m.start()), 0.78, _evidence(content, m.start()))

    if _check_time():
        return endpoints

    # ── Other HTTP clients ────────────────────────────────────────────────────
    for m in RE_HTTP_CLIENTS.finditer(content):
        add(m.group(1), "UNKNOWN", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.80, _evidence(content, m.start()))

    # ── navigator.sendBeacon ──────────────────────────────────────────────────
    for m in RE_BEACON.finditer(content):
        add(m.group(1), "POST", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.88, _evidence(content, m.start()))

    for m in RE_BEACON_VAR.finditer(content):
        resolved = resolve_url_arg(m.group(1), env)
        if resolved and resolved != DYNAMIC_MARKER:
            add(resolved, "POST", _get_line(content, m.start()),
                _get_col(content, m.start()), 0.78, _evidence(content, m.start()))

    # ── EventSource ───────────────────────────────────────────────────────────
    for m in RE_EVENTSOURCE.finditer(content):
        add(m.group(1), "GET", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.88, _evidence(content, m.start()))

    # ── WebSocket ─────────────────────────────────────────────────────────────
    for m in RE_WEBSOCKET.finditer(content):
        add(m.group(1), "WS", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.92, _evidence(content, m.start()))

    for m in RE_WEBSOCKET_VAR.finditer(content):
        resolved = resolve_url_arg(m.group(1), env)
        if resolved and resolved != DYNAMIC_MARKER and resolved.startswith("ws"):
            add(resolved, "WS", _get_line(content, m.start()),
                _get_col(content, m.start()), 0.80, _evidence(content, m.start()))

    for m in RE_WEBSOCKET_TEMPLATE.finditer(content):
        resolved = env.resolve_template(m.group(1))
        if resolved.startswith("ws"):
            add(resolved, "WS", _get_line(content, m.start()),
                _get_col(content, m.start()), 0.84, _evidence(content, m.start()))

    if _check_time():
        return endpoints

    # ── String concatenation ──────────────────────────────────────────────────
    for m in RE_CONCAT.finditer(content):
        combined = m.group(1) + m.group(2)
        add(combined, "UNKNOWN", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.78, _evidence(content, m.start()))

    # ── Template literals ─────────────────────────────────────────────────────
    for m in RE_TEMPLATE.finditer(content):
        path = m.group(1)
        resolved = env.resolve_template(path)
        if resolved.startswith("/api") or resolved.startswith("/v"):
            add(resolved, "UNKNOWN", _get_line(content, m.start()),
                _get_col(content, m.start()), 0.80, _evidence(content, m.start()))

    # ── Route definitions ─────────────────────────────────────────────────────
    for m in RE_ROUTE_PATH.finditer(content):
        add(m.group(1), "GET", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.85, _evidence(content, m.start()))

    for m in RE_ROUTE_MAP_VALUE.finditer(content):
        add(m.group(1), "UNKNOWN", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.82, _evidence(content, m.start()))

    for m in RE_EXPRESS_ROUTE.finditer(content):
        add(m.group(1), "UNKNOWN", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.80, _evidence(content, m.start()))

    # ── GraphQL ───────────────────────────────────────────────────────────────
    for m in RE_GRAPHQL_PATH.finditer(content):
        add(m.group(1), "POST", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.90, _evidence(content, m.start()))

    # ── Serverless / Netlify functions ────────────────────────────────────────
    for m in RE_SERVERLESS_PATH.finditer(content):
        add(m.group(1), "UNKNOWN", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.88, _evidence(content, m.start()))

    # ── Redirect / navigation ─────────────────────────────────────────────────
    for m in RE_REDIRECT.finditer(content):
        add(m.group(1), "GET", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.75, _evidence(content, m.start()))

    # ── API assign / admin / auth / upload ────────────────────────────────────
    for m in RE_API_ASSIGN.finditer(content):
        add(m.group(1), "UNKNOWN", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.78, _evidence(content, m.start()))

    for m in RE_ADMIN_PATH.finditer(content):
        add(m.group(1), "GET", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.82, _evidence(content, m.start()))

    for m in RE_AUTH_PATH.finditer(content):
        add(m.group(1), "POST", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.82, _evidence(content, m.start()))

    for m in RE_UPLOAD_PATH.finditer(content):
        add(m.group(1), "POST", _get_line(content, m.start()),
            _get_col(content, m.start()), 0.78, _evidence(content, m.start()))

    if endpoints:
        logger.debug(
            "Extracted %d endpoints from %s in %.2fs",
            len(endpoints), file_url, _elapsed(),
        )

    return endpoints


def extract_dynamic_imports(content: str, file_url: str) -> List[DynamicImport]:
    """
    Extract dynamic imports, require() calls, and new URL() worker patterns.
    Returns a list of DynamicImport objects.
    """
    results: List[DynamicImport] = []
    seen: Set[str] = set()

    def _add(url: str, kind: str, line: int, col: int, dynamic: bool, ev: str) -> None:
        if url in seen:
            return
        seen.add(url)
        results.append(DynamicImport(url, file_url, line, col, dynamic, kind, ev))

    for m in RE_DYNAMIC_IMPORT.finditer(content):
        _add(m.group(1), "import", _get_line(content, m.start()),
             _get_col(content, m.start()), False, _evidence(content, m.start()))

    for m in RE_DYNAMIC_IMPORT_TEMPLATE.finditer(content):
        _add(m.group(1), "import", _get_line(content, m.start()),
             _get_col(content, m.start()), True, _evidence(content, m.start()))

    for m in RE_REQUIRE.finditer(content):
        _add(m.group(1), "require", _get_line(content, m.start()),
             _get_col(content, m.start()), False, _evidence(content, m.start()))

    for m in RE_NEW_URL_IMPORT.finditer(content):
        _add(m.group(1), "import", _get_line(content, m.start()),
             _get_col(content, m.start()), False, _evidence(content, m.start()))

    return results


def extract_workers(content: str, file_url: str) -> List[DynamicImport]:
    """
    Extract Worker, SharedWorker, ServiceWorker, and importScripts references.
    Returns DynamicImport objects with kind=worker/service-worker/import-scripts.
    """
    results: List[DynamicImport] = []
    seen: Set[str] = set()

    def _add(url: str, kind: str, line: int, col: int, ev: str) -> None:
        if url in seen or not url:
            return
        seen.add(url)
        results.append(DynamicImport(url, file_url, line, col, False, kind, ev))

    for m in RE_WORKER.finditer(content):
        _add(m.group(1), "worker", _get_line(content, m.start()),
             _get_col(content, m.start()), _evidence(content, m.start()))

    for m in RE_WORKER_NEW_URL.finditer(content):
        _add(m.group(1), "worker", _get_line(content, m.start()),
             _get_col(content, m.start()), _evidence(content, m.start()))

    for m in RE_SW_REGISTER.finditer(content):
        _add(m.group(1), "service-worker", _get_line(content, m.start()),
             _get_col(content, m.start()), _evidence(content, m.start()))

    for m in RE_IMPORT_SCRIPTS.finditer(content):
        _add(m.group(1), "import-scripts", _get_line(content, m.start()),
             _get_col(content, m.start()), _evidence(content, m.start()))

    return results


def extract_graphql_operations(content: str, file_url: str) -> List[GraphQLOperation]:
    """
    Extract GraphQL operation names (query/mutation/subscription) from JS content.
    """
    results: List[GraphQLOperation] = []
    seen: Set[str] = set()

    for m in RE_GQL_OPERATION.finditer(content):
        op_type = m.group(1).lower()
        name    = m.group(2)
        key     = f"{op_type}:{name}"
        if key in seen:
            continue
        seen.add(key)
        results.append(GraphQLOperation(
            op_type     = op_type,
            name        = name,
            source_file = file_url,
            line        = _get_line(content, m.start()),
            evidence    = _evidence(content, m.start(), 80),
        ))

    return results


def extract_config_entries(content: str, file_url: str) -> List[ConfigEntry]:
    """
    Extract API-related configuration values from JS config objects.
    Returns ConfigEntry objects for keys that look like API URLs.
    """
    env     = build_env(content)
    results: List[ConfigEntry] = []
    seen: Set[str] = set()

    for key, value in env.get_api_config().items():
        if key in seen or not _is_url_like(value):
            continue
        seen.add(key)
        # Find approximate line number
        line = 1
        m = re.search(re.escape(key), content)
        if m:
            line = _get_line(content, m.start())
            ev   = _evidence(content, m.start())
        else:
            ev = f"{key}: {value}"
        results.append(ConfigEntry(key, value, file_url, line, ev))

    return results
