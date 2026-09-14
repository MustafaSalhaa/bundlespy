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


# Domains to skip — docs, social, CDNs, framework URLs
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
    # Social media — not API endpoints
    "twitter.com", "www.twitter.com", "x.com",
    "linkedin.com", "www.linkedin.com",
    "facebook.com", "www.facebook.com",
    "instagram.com", "www.instagram.com",
    "youtube.com", "www.youtube.com",
    "t.me", "telegram.org",
    "wa.me", "whatsapp.com",
    # Analytics/CDN
    "google.com", "www.google.com", "googleapis.com",
    "googletagmanager.com", "google-analytics.com",
    "cloudflare.com", "cdnjs.cloudflare.com",
    "unpkg.com", "jsdelivr.net",
    "fonts.googleapis.com", "fonts.gstatic.com",
}

# URL patterns that are not API endpoints
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".zip", ".mp4", ".mp3", ".avi",
}

SKIP_PATH_PATTERNS = {
    "/storage/", "/uploads/", "/images/", "/img/",
    "/assets/images/", "/static/images/", "/media/",
    "/fonts/", "/icons/",
}


def _is_skip_url(url: str) -> bool:
    """Return True if URL should be skipped as a non-endpoint."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host   = parsed.hostname or ""
        path   = parsed.path.lower()

        if host in SKIP_DOMAINS:
            return True
        if host.endswith(".w3.org") or host.endswith(".reactjs.org"):
            return True

        skip_ext = {".png",".jpg",".jpeg",".gif",".svg",".ico",".webp",
                    ".css",".woff",".woff2",".ttf",".eot",".pdf",".zip"}
        if any(path.endswith(ext) for ext in skip_ext):
            return True

        skip_path = {"/storage/", "/uploads/", "/images/", "/img/", "/media/", "/fonts/"}
        if any(p in path for p in skip_path) and "/api/" not in path:
            return True

        return False
    except Exception:
        return False

        # Skip known non-API domains
        if host in SKIP_DOMAINS:
            return True
        if host.endswith(".w3.org") or host.endswith(".reactjs.org"):
            return True

        # Skip static asset extensions
        if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
            return True

        # Skip storage/media paths that look like UUIDs (not API routes)
        if any(pat in path for pat in SKIP_PATH_PATTERNS):
            # Allow if it also has /api/ in the path
            if "/api/" not in path:
                return True

        return False
    except Exception:
        return False


def extract_endpoints(content: str, file_url: str) -> List[Endpoint]:
    """Extract all endpoints and interesting URLs from JS content."""
    endpoints: List[Endpoint] = []
    seen = set()

    def add(path: str, method: str, line_no: int) -> None:
        if _is_skip_url(path):
            return
        # Deduplicate by URL only — same endpoint from multiple inline scripts counts once
        key = path.rstrip("/").lower()
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
