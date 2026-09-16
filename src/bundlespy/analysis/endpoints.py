"""
Endpoint and URL extractor.
Finds API paths, routes, GraphQL endpoints, WebSocket URLs,
and other interesting references from JavaScript content.

Intelligence improvements:
- Structured _categorize_path with ordered, precise rules
- source_type field: static | runtime | correlated
- Static↔runtime correlation via canonical key
- Dead-code unreachable path removed from _is_skip_url
"""

import re
import logging
from typing import List, Dict, Optional
from urllib.parse import urlparse

from ..storage.models import Endpoint
from ..safety.network import classify_url

logger = logging.getLogger("bundlespy.analysis.endpoints")

# ── Regex patterns ─────────────────────────────────────────────────────────────

RE_API_PATH = re.compile(
    r'["\x27`]'
    r'((?:/api/|/v\d+/|/graphql|/rest/|/ws/|/socket/|/admin|/auth|/oauth|/login|/logout|/upload|/download)'
    r'[a-zA-Z0-9/_\-{}:?=&%#.]*)'
    r'["\x27`]',
    re.IGNORECASE,
)

RE_FULL_URL = re.compile(
    r'["\x27`]((?:https?|wss?|ws)://[^\s"\x27`<>{}]{10,})["\x27`]',
    re.IGNORECASE,
)

RE_GRAPHQL  = re.compile(r'["\x27`](/graphql[^\s"\x27`<>]*)["\x27`]', re.IGNORECASE)
RE_WEBSOCKET = re.compile(r'["\x27`](wss?://[^\s"\x27`<>]+)["\x27`]', re.IGNORECASE)

# ── Category classification ────────────────────────────────────────────────────
#
# Rules are checked in order — first match wins.
# Keep more-specific patterns before more-general ones.

_AUTH_KEYWORDS = frozenset([
    "/login", "/logout", "/auth", "/oauth", "/token", "/session",
    "/signin", "/signup", "/register", "/password", "/reset-password",
    "/forgot-password", "/verify", "/2fa", "/mfa", "/sso",
])
_ADMIN_KEYWORDS = frozenset([
    "/admin", "/management", "/dashboard/admin", "/superuser",
    "/backoffice", "/back-office", "/control-panel", "/cp/",
])
_UPLOAD_KEYWORDS = frozenset(["/upload", "/import", "/ingest", "/attach"])
_DOWNLOAD_KEYWORDS = frozenset(["/download", "/export", "/file", "/attachment"])
_SERVERLESS_PREFIXES = (
    "/.netlify/functions/", "/.netlify/",
    "/functions/", "/serverless/", "/lambdas/", "/fn/",
    "/.vercel/", "/api/functions/",
)
_API_KEYWORDS = frozenset(["/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/rest/"])
_WS_KEYWORDS = frozenset(["/ws/", "/socket", "wss://", "ws://", "/websocket", "/realtime"])

# Verb-segment heuristic: last path segment starts or ends with these → API
_API_VERBS = frozenset([
    "create", "update", "delete", "remove", "toggle", "fetch", "get", "set",
    "submit", "send", "process", "generate", "search", "list", "query",
    "check", "validate", "confirm", "cancel", "approve", "reject",
    "enable", "disable", "sync", "refresh", "revoke", "grant",
])


def _categorize_path(path: str) -> str:
    """
    Classify an endpoint path into a category.
    Ordered from most-specific to most-general.
    """
    lower = path.lower()

    if any(k in lower for k in _AUTH_KEYWORDS):
        return "AUTH"
    if any(k in lower for k in _ADMIN_KEYWORDS):
        return "ADMIN"
    if "/graphql" in lower:
        return "GRAPHQL"
    if any(lower.startswith(p) or p in lower for p in _SERVERLESS_PREFIXES):
        return "SERVERLESS"
    if any(k in lower for k in _WS_KEYWORDS):
        return "WEBSOCKET"
    if any(k in lower for k in _UPLOAD_KEYWORDS):
        return "UPLOAD"
    if any(k in lower for k in _DOWNLOAD_KEYWORDS):
        return "DOWNLOAD"
    if any(k in lower for k in _API_KEYWORDS):
        return "API"

    # Heuristic: last path segment looks like an API action verb
    seg = lower.strip("/").split("/")[-1].split("?")[0].split("-")
    if any(part in _API_VERBS for part in seg):
        return "API"

    return "UNKNOWN"


def _get_line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


# ── Skip-list ──────────────────────────────────────────────────────────────────

SKIP_DOMAINS = frozenset([
    "reactjs.org", "www.reactjs.org",
    "w3.org", "www.w3.org",
    "github.com", "www.github.com",
    "developer.mozilla.org", "mdn.io",
    "tc39.es", "ecma-international.org",
    "nodejs.org", "npmjs.com",
    "webpack.js.org", "babeljs.io",
    "vuejs.org", "angular.io",
    "schema.org", "json-ld.org",
    "ogp.me", "opengraph.io",
    "example.com", "example.org",
    "twitter.com", "www.twitter.com", "x.com",
    "linkedin.com", "www.linkedin.com",
    "facebook.com", "www.facebook.com",
    "instagram.com", "www.instagram.com",
    "youtube.com", "www.youtube.com",
    "t.me", "telegram.org",
    "wa.me", "whatsapp.com",
    "google.com", "www.google.com", "googleapis.com",
    "googletagmanager.com", "google-analytics.com",
    "cloudflare.com", "cdnjs.cloudflare.com",
    "unpkg.com", "jsdelivr.net",
    "fonts.googleapis.com", "fonts.gstatic.com",
])

SKIP_EXTENSIONS = frozenset([
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".zip", ".mp4", ".mp3", ".avi",
])

SKIP_PATH_PATTERNS = frozenset([
    "/storage/", "/uploads/", "/images/", "/img/",
    "/assets/images/", "/static/images/", "/media/",
    "/fonts/", "/icons/",
])


def _is_skip_url(url: str) -> bool:
    """Return True if URL should be skipped as a non-endpoint."""
    try:
        parsed = urlparse(url)
        host   = (parsed.hostname or "").lower()
        path   = parsed.path.lower()

        if host in SKIP_DOMAINS:
            return True
        if host.endswith(".w3.org") or host.endswith(".reactjs.org"):
            return True
        if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
            return True
        if any(p in path for p in SKIP_PATH_PATTERNS) and "/api/" not in path:
            return True

        return False
    except Exception:
        return False


# ── Canonical key for static↔runtime correlation ───────────────────────────────

def _canonical_key(url: str) -> str:
    """
    Normalize a URL or path to a canonical key for deduplication
    and static↔runtime correlation.
    Strips trailing slashes, lowercases, removes query string.
    """
    try:
        parsed = urlparse(url)
        # Path-only endpoints: normalize path
        if not parsed.scheme:
            return url.split("?")[0].rstrip("/").lower() or "/"
        # Full URLs: include host + path, drop query/fragment
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/").lower() or url.lower()
    except Exception:
        return url.lower()


def correlate_endpoints(
    static_eps: List[Endpoint],
    runtime_eps: List[Endpoint],
) -> List[Endpoint]:
    """
    Merge static and runtime endpoint lists.
    Same canonical URL → one entity with source_type="correlated" and
    evidence from both sources combined.
    Runtime observations take precedence for method/category when they differ.
    """
    merged: Dict[str, Endpoint] = {}

    for ep in static_eps:
        k = _canonical_key(ep.url)
        ep.source_type = "static"  # type: ignore[attr-defined]
        merged[k] = ep

    for ep in runtime_eps:
        k = _canonical_key(ep.url)
        ep.source_type = "runtime"  # type: ignore[attr-defined]
        if k in merged:
            existing = merged[k]
            # Upgrade to correlated
            existing.source_type = "correlated"  # type: ignore[attr-defined]
            # Runtime method is more reliable than static regex
            if ep.method not in ("UNKNOWN", "") and existing.method in ("UNKNOWN", ""):
                existing.method = ep.method
            # Runtime category wins if static was UNKNOWN
            if existing.category == "UNKNOWN" and ep.category != "UNKNOWN":
                existing.category = ep.category
            # Boost confidence
            existing.confidence = min(1.0, max(existing.confidence, ep.confidence) + 0.05)
            # Merge evidence strings
            existing.evidence = (
                f"static: {existing.evidence} | runtime: {ep.evidence}"
                if existing.evidence else f"runtime: {ep.evidence}"
            )
        else:
            merged[k] = ep

    return list(merged.values())


def extract_endpoints(content: str, file_url: str) -> List[Endpoint]:
    """Extract all endpoints and interesting URLs from JS content."""
    endpoints: List[Endpoint] = []
    seen: set = set()

    def add(path: str, method: str, line_no: int) -> None:
        if _is_skip_url(path):
            return
        key = _canonical_key(path)
        if key in seen:
            return
        seen.add(key)
        category = _categorize_path(path)
        ep = Endpoint(
            url         = path,
            path        = path,
            method      = method,
            category    = category,
            source_file = file_url,
            line_number = line_no,
            confidence  = 0.75,
        )
        # Tag as static — runtime endpoints come from headless interceptor
        try:
            ep.source_type = "static"  # type: ignore[attr-defined]
        except Exception:
            pass
        endpoints.append(ep)

    for match in RE_API_PATH.finditer(content):
        add(match.group(1), "UNKNOWN", _get_line_number(content, match.start()))

    for match in RE_FULL_URL.finditer(content):
        add(match.group(1), "UNKNOWN", _get_line_number(content, match.start()))

    for match in RE_GRAPHQL.finditer(content):
        add(match.group(1), "POST", _get_line_number(content, match.start()))

    for match in RE_WEBSOCKET.finditer(content):
        add(match.group(1), "WS", _get_line_number(content, match.start()))

    return endpoints
