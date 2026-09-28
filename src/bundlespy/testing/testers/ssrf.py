"""
SsrfMapper - SSRF attack surface identification.
Pure static analysis of already-collected endpoint data. Zero HTTP requests.
"""
from typing import List
from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint

# Param names with high SSRF signal - clearly expect a URL or callback
_HIGH_SSRF_PARAMS = {
    "url", "uri", "callback", "webhook", "endpoint",
    "image_url", "avatar_url", "icon_url", "logo_url",
    "photo_url", "thumbnail_url", "cover_url",
    "feed_url", "rss_url", "api_endpoint", "api_url",
    "return_url", "redirect_url",  # can SSRF even when intended for redirect
}

# Param names with medium SSRF signal - context-dependent
_MEDIUM_SSRF_PARAMS = {
    "redirect", "target", "src", "source", "dest", "destination",
    "remote", "proxy", "forward",
    "import", "export", "upload_url", "download_url",
    "attachment_url", "media_url", "resource",
}

# Param names with lower SSRF signal - need supporting context
_LOW_SSRF_PARAMS = {
    "link", "fetch", "load", "pull", "path", "file", "host", "domain",
    "origin", "location", "address", "server", "base_url",
}

_ALL_SSRF_PARAMS = _HIGH_SSRF_PARAMS | _MEDIUM_SSRF_PARAMS | _LOW_SSRF_PARAMS

# Path patterns that suggest import/webhook/integration functionality
_SSRF_PATH_SIGNALS = {
    "/import", "/export", "/webhook", "/callback", "/notify",
    "/fetch", "/proxy", "/forward", "/mirror", "/preview",
    "/screenshot", "/render", "/pdf", "/convert",
    "/integration", "/connect", "/sync",
}

# JS patterns suggesting user-controlled URL in fetch/axios/XHR
_JS_SSRF_PATTERNS = [
    "fetch(", "axios.get(", "axios.post(", "axios(",
    "XMLHttpRequest", "$.ajax(", "$.get(", "$.post(",
    "http.get(", "https.get(",
    "request(", "got(",
]

# JS source patterns that indicate the URL comes from user input
_JS_URL_SOURCE_PATTERNS = [
    "location.search", "URLSearchParams", "searchParams.get(",
    "getParameter(", "location.hash", "document.referrer",
    "req.query", "req.body", "req.params",
    "params.url", "params.uri", "body.url", "body.uri",
    "query.url", "query.uri",
]

_BURP_NOTES = (
    "Test with Burp Collaborator URL as value. "
    "Try: http://169.254.169.254/latest/meta-data/ (AWS metadata). "
    "Try: http://metadata.google.internal/ (GCP). "
    "Try internal hostnames and 127.0.0.1. "
    "Test bypass: http://[::1]/, http://0.0.0.0/, http://localtest.me/"
)

_BURP_NOTES_IMAGE = (
    "Image/media URL parameter - common SSRF via server-side fetch. "
    "Server likely fetches and processes the URL server-side. "
    "Test with Burp Collaborator. Try cloud metadata: http://169.254.169.254/"
)

_BURP_NOTES_PATH = (
    "Path/endpoint suggests server-side HTTP fetching. "
    "Test any URL parameters with Burp Collaborator. "
    "Try internal services, cloud metadata endpoints."
)

_BURP_NOTES_JS = (
    "JS makes HTTP requests that may include user-controlled URLs. "
    "Trace data flow in browser DevTools - Network tab. "
    "Check if request originates server-side or client-side."
)


def _ssrf_confidence(name: str) -> str:
    name = name.lower()
    if name in _HIGH_SSRF_PARAMS:
        return ConfidenceLevel.HIGH
    if name in _MEDIUM_SSRF_PARAMS:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def _ssrf_burp(name: str) -> str:
    if any(kw in name for kw in ("image", "avatar", "icon", "logo", "photo", "thumbnail", "cover", "media")):
        return _BURP_NOTES_IMAGE
    return _BURP_NOTES


class SsrfMapper(BaseSurfaceMapper):
    category = AttackCategory.SSRF

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        # JS SSRF pattern scan - look for fetch/XHR with URL source patterns
        for js in result.js_files:
            if not js.content:
                continue
            content = js.content

            has_fetch  = any(p in content for p in _JS_SSRF_PATTERNS)
            has_source = any(p in content for p in _JS_URL_SOURCE_PATTERNS)

            if has_fetch and has_source:
                fetch_hits  = [p for p in _JS_SSRF_PATTERNS if p in content]
                source_hits = [p for p in _JS_URL_SOURCE_PATTERNS if p in content]

                from ...storage.models import Endpoint as _Endpoint
                js_url = js.url or getattr(js, "source_page", "") or ""
                if js_url:
                    synthetic_ep = _Endpoint(
                        url=js_url,
                        path=js_url,
                        method="GET",
                        category="",
                        source_file=js.url or "",
                        line_number=0,
                        confidence=0.5,
                        query_params=[],
                        path_params=[],
                        body_fields=[],
                        request_headers={},
                        auth_context="",
                        source_type="static",
                    )
                    self._candidate(
                        endpoint     = synthetic_ep,
                        surface_type = "SSRF via JS Fetch",
                        parameters   = [],
                        confidence   = ConfidenceLevel.MEDIUM,
                        evidence     = [
                            f"HTTP client calls in JS: {', '.join(fetch_hits[:3])}",
                            f"User-controlled URL sources: {', '.join(source_hits[:3])}",
                            "Verify if request is server-side or client-side",
                        ],
                        burp_notes   = _BURP_NOTES_JS,
                    )

        for ep in result.endpoints:
            method = (ep.method or "GET").upper()
            path   = (ep.path or ep.url or "").lower()

            # Path-based SSRF signal (import, webhook, proxy endpoints)
            if any(sig in path for sig in _SSRF_PATH_SIGNALS):
                self._candidate(
                    endpoint     = ep,
                    surface_type = "SSRF",
                    parameters   = ["path:ssrf_endpoint"],
                    confidence   = ConfidenceLevel.MEDIUM,
                    evidence     = [
                        f"Endpoint path suggests server-side HTTP fetching: {ep.url}",
                        "Import/webhook/proxy paths commonly make outbound requests",
                    ],
                    burp_notes   = _BURP_NOTES_PATH,
                )

            # Check query params
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name not in _ALL_SSRF_PARAMS:
                    continue
                self._candidate(
                    endpoint     = ep,
                    surface_type = "SSRF",
                    parameters   = [f"query:{name}"],
                    confidence   = _ssrf_confidence(name),
                    evidence     = [
                        f"SSRF-signal query param '{name}' on {ep.url}",
                    ],
                    burp_notes   = _ssrf_burp(name),
                )

            # Check body fields
            for bf in (ep.body_fields or []):
                name = (bf.get("name") or "").lower()
                if name not in _ALL_SSRF_PARAMS:
                    continue
                self._candidate(
                    endpoint     = ep,
                    surface_type = "SSRF",
                    parameters   = [f"body:{name}"],
                    confidence   = _ssrf_confidence(name),
                    evidence     = [
                        f"SSRF-signal body field '{name}' on {method} {ep.url}",
                    ],
                    burp_notes   = _ssrf_burp(name),
                )

        return self._results
