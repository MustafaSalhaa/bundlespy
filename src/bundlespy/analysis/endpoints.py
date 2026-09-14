"""
Endpoint and URL extractor.
Finds API paths, routes, GraphQL endpoints, WebSocket URLs,
and other interesting references from JavaScript content.
"""

import re
import logging
from typing import List
from urllib.parse import urlparse

from ..storage.models import Endpoint
from ..safety.network import classify_url

logger = logging.getLogger("bundlespy.analysis.endpoints")

# API path patterns
RE_API_PATH = re.compile(
    r'["\x27`]'
    r'((?:/api/|/v\d+/|/graphql|/rest/|/ws/|/socket/|/admin|/auth|/oauth|/login|/logout|/upload|/download)'
    r'[a-zA-Z0-9/_\-{}:?=&%#.]*)'
    r'["\x27`]',
    re.IGNORECASE,
)

# Full URL patterns (http/https/ws/wss)
RE_FULL_URL = re.compile(
    r'["\x27`]((?:https?|wss?|ws)://[^\s"\'`<>{}]{10,})["\x27`]',
    re.IGNORECASE,
)

# GraphQL specific
RE_GRAPHQL  = re.compile(r'["\x27`](/graphql[^\s"\'`<>]*)["\x27`]', re.IGNORECASE)

# WebSocket
RE_WEBSOCKET = re.compile(r'["\x27`](wss?://[^\s"\'`<>]+)["\x27`]', re.IGNORECASE)


def _categorize_path(path: str) -> str:
    lower = path.lower()
    if any(k in lower for k in ["/login", "/logout", "/auth", "/oauth", "/token", "/session", "/signin", "/signup"]):
        return "AUTH"
    if any(k in lower for k in ["/admin", "/management", "/dashboard/admin", "/superuser"]):
        return "ADMIN"
    if any(k in lower for k in ["/upload", "/import", "/ingest"]):
        return "UPLOAD"
    if any(k in lower for k in ["/download", "/export", "/file"]):
        return "DOWNLOAD"
    if "/graphql" in lower:
        return "GRAPHQL"
    if any(k in lower for k in ["/ws/", "/socket", "wss://", "ws://"]):
        return "WEBSOCKET"
    if any(k in lower for k in ["/api/", "/v1/", "/v2/", "/v3/", "/rest/"]):
        return "API"
    return "UNKNOWN"


def _get_line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


# Domains to skip — documentation, CDNs, framework URLs
SKIP_DOMAINS = {
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
}

def _is_doc_url(url: str) -> bool:
    """Return True if URL is a documentation or framework reference."""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        return host in SKIP_DOMAINS or host.endswith(".w3.org") or host.endswith(".reactjs.org")
    except Exception:
        return False


def extract_endpoints(content: str, file_url: str) -> List[Endpoint]:
    """Extract all endpoints and interesting URLs from JS content."""
    endpoints: List[Endpoint] = []
    seen = set()

    def add(path: str, method: str, line_no: int) -> None:
        if _is_doc_url(path):
            return
        key = f"{path}:{method}"
        if key in seen:
            return
        seen.add(key)
        category = _categorize_path(path)
        endpoints.append(Endpoint(
            url         = path,
            path        = path,
            method      = method,
            category    = category,
            source_file = file_url,
            line_number = line_no,
            confidence  = 0.75,
        ))

    for match in RE_API_PATH.finditer(content):
        path   = match.group(1)
        line_no = _get_line_number(content, match.start())
        add(path, "UNKNOWN", line_no)

    for match in RE_FULL_URL.finditer(content):
        url    = match.group(1)
        line_no = _get_line_number(content, match.start())
        add(url, "UNKNOWN", line_no)

    for match in RE_GRAPHQL.finditer(content):
        path   = match.group(1)
        line_no = _get_line_number(content, match.start())
        add(path, "POST", line_no)

    for match in RE_WEBSOCKET.finditer(content):
        url    = match.group(1)
        line_no = _get_line_number(content, match.start())
        add(url, "WS", line_no)

    return endpoints
