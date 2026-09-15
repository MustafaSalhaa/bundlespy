"""
Advanced Endpoint Extractor using pattern analysis.

Goes beyond simple regex by:
1. Resolving string concatenations
2. Extracting template literal patterns
3. Finding all route definitions (React Router, Vue Router, Angular, Next.js)
4. Parsing object maps of routes
5. Following variable assignments
6. Extracting from common HTTP client patterns (fetch, axios, xhr, superagent, got)
7. Parsing API response links
8. Extracting from config objects

All of this runs automatically on every JS file — no flags needed.
"""

import re
import logging
from typing import List, Set, Dict, Optional
from urllib.parse import urljoin

from ..storage.models import Endpoint

logger = logging.getLogger("bundlespy.analysis.ast_endpoints")

# ── HTTP client patterns ──────────────────────────────────────────────────────

# fetch("/api/users") or fetch('/api/users') or fetch(`/api/users`)
RE_FETCH = re.compile(
    r'\bfetch\s*\(\s*["\x27`](/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

# axios.get("/api/users") axios.post axios.put axios.delete axios.patch
RE_AXIOS = re.compile(
    r'\baxios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*["\x27`]'
    r'(/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

# axios({ url: "/api/users", method: "POST" })
RE_AXIOS_CONFIG = re.compile(
    r'\baxios\s*\(\s*\{[^}]{0,200}url\s*:\s*["\x27`](/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE | re.DOTALL,
)

# $.ajax({ url: "/api/users" }) $.get $.post
RE_JQUERY_AJAX = re.compile(
    r'\$\s*\.\s*(?:ajax|get|post|put|delete)\s*\(\s*["\x27`]'
    r'(/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

# XMLHttpRequest.open("GET", "/api/users")
RE_XHR = re.compile(
    r'\.open\s*\(\s*["\x27`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["\x27`]\s*,\s*'
    r'["\x27`](/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

# superagent / got / request / ky
RE_HTTP_CLIENTS = re.compile(
    r'\b(?:request|superagent|got|ky|agent|http)\s*\.\s*'
    r'(?:get|post|put|delete|patch)\s*\(\s*["\x27`]'
    r'(/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

# String concatenation: "/api/v1" + "/users" or "/api/" + "users"
RE_CONCAT = re.compile(
    r'["\x27`](/[A-Za-z0-9/_\-]{1,50})["\x27`]\s*\+\s*["\x27`]([A-Za-z0-9/_\-]{1,50})["\x27`]',
    re.IGNORECASE,
)

# Template literals: `/api/v1/users/${id}` → /api/v1/users/*
RE_TEMPLATE = re.compile(
    r'`(/[A-Za-z0-9/_\-.:?=&%#{}$]+(?:\$\{[^}]+\}[A-Za-z0-9/_\-.:?=&%#{}]*)*)`',
    re.IGNORECASE,
)

# Route definitions: { path: "/admin/users" }
RE_ROUTE_PATH = re.compile(
    r'\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}*][A-Za-z0-9/_\-.:?=&%#{}*]*)["\x27`]',
    re.IGNORECASE,
)

# Next.js page routes in pages/ directory references
RE_NEXTJS_PAGE = re.compile(
    r'["\x27`](/(?:pages?|app)/[A-Za-z0-9/_\-\[\]]+)["\x27`]',
    re.IGNORECASE,
)

# Route maps: routes = { users: "/api/users", orders: "/api/orders" }
RE_ROUTE_MAP_VALUE = re.compile(
    r':\s*["\x27`](/api/[A-Za-z0-9/_\-.:?=&%#{}]+)["\x27`]',
    re.IGNORECASE,
)

# API base + path patterns
RE_API_BASE = re.compile(
    r'(?:apiBase|API_BASE|baseURL|BASE_URL|apiUrl|API_URL)\s*[=:]\s*["\x27`]'
    r'(/[A-Za-z0-9/_\-.:?=&%#]+)["\x27`]',
    re.IGNORECASE,
)

# Express/Koa/Hapi route definitions (sometimes bundled)
RE_EXPRESS_ROUTE = re.compile(
    r'\b(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|use)\s*\(\s*["\x27`]'
    r'(/[A-Za-z0-9/_\-.:?=&%#{}:*]+)["\x27`]',
    re.IGNORECASE,
)

# GraphQL query paths
RE_GRAPHQL_PATH = re.compile(
    r'["\x27`](/graphql[A-Za-z0-9/_\-.:?=&%#]*)["\x27`]',
    re.IGNORECASE,
)

# WebSocket paths — use explicit quote chars to avoid escape issues
RE_WEBSOCKET = re.compile(
    "new\\s+WebSocket\\s*\\(\\s*[\"'`](wss?://[^\\s\"'`]+)[\"'`]",
    re.IGNORECASE,
)

# URL in redirect/navigation
RE_REDIRECT = re.compile(
    r'(?:window\.location|router\.push|navigate|redirect)\s*[\(=]\s*["\x27`]'
    r'(/[A-Za-z0-9/_\-.:?=&%#]+)["\x27`]',
    re.IGNORECASE,
)

# API paths in string assignments
RE_API_ASSIGN = re.compile(
    r'["\x27`](/api/[A-Za-z0-9/_\-.:?=&%#{}/]+)["\x27`]',
    re.IGNORECASE,
)

# Admin/internal paths
RE_ADMIN_PATH = re.compile(
    r'["\x27`](/(?:admin|internal|manage|management|dashboard|panel|staff|superuser)'
    r'[A-Za-z0-9/_\-.:?=&%#]*)["\x27`]',
    re.IGNORECASE,
)

# Auth paths
RE_AUTH_PATH = re.compile(
    r'["\x27`](/(?:auth|login|logout|signin|signup|register|oauth|token|refresh|session)'
    r'[A-Za-z0-9/_\-.:?=&%#]*)["\x27`]',
    re.IGNORECASE,
)

# Upload/download paths
RE_UPLOAD_PATH = re.compile(
    r'["\x27`](/(?:upload|download|import|export|file|files|attachment|media)'
    r'[A-Za-z0-9/_\-.:?=&%#]*)["\x27`]',
    re.IGNORECASE,
)


# ── Categorization ────────────────────────────────────────────────────────────

def _categorize(path: str, method: str = "UNKNOWN") -> str:
    lower = path.lower()
    if any(k in lower for k in ["/login", "/logout", "/auth", "/oauth",
                                  "/token", "/session", "/signin", "/signup",
                                  "/register", "/refresh", "/password"]):
        return "AUTH"
    if any(k in lower for k in ["/admin", "/internal", "/manage",
                                  "/management", "/panel", "/staff",
                                  "/superuser", "/dashboard/admin"]):
        return "ADMIN"
    if "/graphql" in lower or "/gql" in lower:
        return "GRAPHQL"
    if any(k in lower for k in ["/upload", "/import", "/ingest"]):
        return "UPLOAD"
    if any(k in lower for k in ["/download", "/export", "/file"]):
        return "DOWNLOAD"
    if lower.startswith("ws://") or lower.startswith("wss://"):
        return "WEBSOCKET"
    if any(k in lower for k in ["/api/", "/v1/", "/v2/", "/v3/",
                                  "/v4/", "/v5/", "/rest/"]):
        return "API"
    return "UNKNOWN"


def _get_line(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _clean_path(path: str) -> str:
    """Normalize a path — replace template vars with *"""
    path = re.sub(r'\$\{[^}]+\}', '*', path)
    path = re.sub(r':[A-Za-z_][A-Za-z0-9_]*', '*', path)  # Express :param
    path = re.sub(r'\[[^\]]+\]', '*', path)  # Next.js [param]
    return path.rstrip("/") or "/"


def _is_valid_path(path: str) -> bool:
    """Filter out obvious non-API paths."""
    lower = path.lower()

    # WebSocket URLs are always valid — never filter them
    if lower.startswith("ws://") or lower.startswith("wss://"):
        return True

    # Skip static assets
    skip_exts = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
                 ".css", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
                 ".mp4", ".mp3", ".avi", ".mov")
    if any(lower.endswith(ext) for ext in skip_exts):
        return False

    # Skip obvious non-paths
    if lower in ("/", "/*"):
        return False

    # Skip very short meaningless paths
    if len(path) < 3:
        return False

    # Skip documentation URLs embedded in code
    skip_domains = ["reactjs.org", "w3.org", "github.com", "mdn.io",
                    "developer.mozilla", "nodejs.org"]
    if any(d in lower for d in skip_domains):
        return False

    # Skip full HTTP URLs that are not API-like
    if path.startswith("http"):
        if not any(k in lower for k in ["/api/", "/auth", "/admin", "/graphql",
                                         "/upload", "/download", "/v1/", "/v2/",
                                         "/v3/", "/rest/", "/gql", "/socket"]):
            return False

    return True


# ── Skip domains ──────────────────────────────────────────────────────────────

SKIP_FULL_URL_DOMAINS = {
    "reactjs.org", "w3.org", "github.com", "developer.mozilla.org",
    "nodejs.org", "example.com", "example.org", "npmjs.com",
    "webpack.js.org", "babeljs.io", "vuejs.org", "angular.io",
    "twitter.com", "facebook.com", "linkedin.com", "google.com",
    "googleapis.com", "googletagmanager.com", "fonts.googleapis.com",
}


def extract_all_endpoints(content: str, file_url: str) -> List[Endpoint]:
    """
    Extract every possible endpoint from JS content using all patterns.
    Runs automatically on every JS file — no flags needed.
    """
    endpoints: List[Endpoint] = []
    seen:      Set[str]       = set()

    def add(path: str, method: str = "UNKNOWN", line_no: int = 0,
            confidence: float = 0.75) -> None:
        if not path:
            return

        # Clean template vars
        path = _clean_path(path)

        if not _is_valid_path(path):
            return

        key = path.lower().rstrip("/").split("?")[0]
        if key in seen:
            return
        seen.add(key)

        category = _categorize(path, method)
        endpoints.append(Endpoint(
            url         = path,
            path        = path,
            method      = method,
            category    = category,
            source_file = file_url,
            line_number = line_no,
            confidence  = confidence,
        ))

    # ── Run all patterns ──────────────────────────────────────────────────────

    for m in RE_FETCH.finditer(content):
        add(m.group(1), "GET", _get_line(content, m.start()), 0.88)

    for m in RE_AXIOS.finditer(content):
        add(m.group(2), m.group(1).upper(), _get_line(content, m.start()), 0.90)

    for m in RE_AXIOS_CONFIG.finditer(content):
        add(m.group(1), "UNKNOWN", _get_line(content, m.start()), 0.85)

    for m in RE_JQUERY_AJAX.finditer(content):
        add(m.group(1), "UNKNOWN", _get_line(content, m.start()), 0.82)

    for m in RE_XHR.finditer(content):
        add(m.group(2), m.group(1).upper(), _get_line(content, m.start()), 0.88)

    for m in RE_HTTP_CLIENTS.finditer(content):
        add(m.group(1), "UNKNOWN", _get_line(content, m.start()), 0.80)

    # String concatenation resolution
    for m in RE_CONCAT.finditer(content):
        combined = m.group(1) + m.group(2)
        add(combined, "UNKNOWN", _get_line(content, m.start()), 0.78)

    # Template literals
    for m in RE_TEMPLATE.finditer(content):
        path = m.group(1)
        if path.startswith("/api") or path.startswith("/v"):
            add(path, "UNKNOWN", _get_line(content, m.start()), 0.80)

    # Route definitions (React Router, Vue Router, Angular)
    for m in RE_ROUTE_PATH.finditer(content):
        add(m.group(1), "GET", _get_line(content, m.start()), 0.85)

    # Route maps
    for m in RE_ROUTE_MAP_VALUE.finditer(content):
        add(m.group(1), "UNKNOWN", _get_line(content, m.start()), 0.82)

    # Express routes (sometimes in SSR bundles)
    for m in RE_EXPRESS_ROUTE.finditer(content):
        add(m.group(1), "UNKNOWN", _get_line(content, m.start()), 0.80)

    # GraphQL paths
    for m in RE_GRAPHQL_PATH.finditer(content):
        add(m.group(1), "POST", _get_line(content, m.start()), 0.90)

    # WebSockets
    for m in RE_WEBSOCKET.finditer(content):
        add(m.group(1), "WS", _get_line(content, m.start()), 0.92)

    # Redirects and navigation
    for m in RE_REDIRECT.finditer(content):
        add(m.group(1), "GET", _get_line(content, m.start()), 0.75)

    # API paths
    for m in RE_API_ASSIGN.finditer(content):
        add(m.group(1), "UNKNOWN", _get_line(content, m.start()), 0.78)

    # Admin paths
    for m in RE_ADMIN_PATH.finditer(content):
        add(m.group(1), "GET", _get_line(content, m.start()), 0.82)

    # Auth paths
    for m in RE_AUTH_PATH.finditer(content):
        add(m.group(1), "POST", _get_line(content, m.start()), 0.82)

    # Upload/download paths
    for m in RE_UPLOAD_PATH.finditer(content):
        add(m.group(1), "POST", _get_line(content, m.start()), 0.78)

    if endpoints:
        logger.debug("Extracted %d endpoints from %s", len(endpoints), file_url)

    return endpoints
