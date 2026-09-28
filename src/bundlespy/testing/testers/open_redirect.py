"""
OpenRedirectMapper - open redirect attack surface identification.
Pure static analysis of already-collected endpoint data. Zero HTTP requests.
"""
from typing import List
from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint

_HIGH_REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "next", "return_url",
    "returnUrl", "returnTo", "next_url", "after_login", "post_login_redirect",
}

_MEDIUM_REDIRECT_PARAMS = {
    "return", "destination", "dest", "goto", "continue",
    "successUrl", "cancelUrl", "back", "forward",
    "after", "then", "follow", "navigate",
}

# "to" and "url" are noisy - only flag if on auth path or with supporting context
_LOW_REDIRECT_PARAMS = {
    "to", "url", "ref", "referrer", "href",
}

_ALL_REDIRECT_PARAMS = _HIGH_REDIRECT_PARAMS | _MEDIUM_REDIRECT_PARAMS | _LOW_REDIRECT_PARAMS

# Path fragments that increase confidence for open redirect
_AUTH_PATH_SIGNALS = {
    "/login", "/logout", "/auth", "/oauth", "/callback",
    "/signin", "/signout", "/sso", "/authorize", "/token",
}

# JS patterns that suggest window.location is set from a param value
_JS_REDIRECT_SINKS = [
    "window.location =", "window.location.href =",
    "window.location.assign(", "window.location.replace(",
    "document.location =", "document.location.href =",
    "location.href =", "location.replace(", "location.assign(",
]

# JS patterns that suggest the value comes from user-controlled input
_JS_REDIRECT_SOURCES = [
    "location.search", "URLSearchParams", "searchParams.get(",
    "getParameter(", "location.hash",
    "params.", "query.", "req.query", "req.body",
]

_BURP_NOTES = (
    "Test with https://evil.com as value. "
    "Check if Location header follows. "
    "Test URL encoding bypass: https:%2F%2Fevil.com, //evil.com. "
    "Try double encoding: %252F%252Fevil.com. "
    "Test protocol-relative: //evil.com"
)

_BURP_NOTES_AUTH = (
    "HIGH PRIORITY: redirect param on auth endpoint. "
    "Classic OAuth/login redirect abuse. "
    "Test: ?redirect_uri=https://evil.com, ?next=//evil.com. "
    "Check if domain validation is bypassable: ?next=https://legit.com.evil.com"
)

_BURP_NOTES_JS = (
    "JS sets window.location from a user-controlled source. "
    "Test in browser: modify location.hash or search params, check if page redirects. "
    "Can be used for DOM-based open redirect even without server round-trip."
)


def _redirect_confidence(name: str, path: str, is_body: bool = False) -> str:
    name_l    = name.lower()
    path_l    = path.lower()
    is_auth   = any(sig in path_l for sig in _AUTH_PATH_SIGNALS)
    is_noisy  = name_l in _LOW_REDIRECT_PARAMS

    if name_l in _HIGH_REDIRECT_PARAMS and is_auth:
        return ConfidenceLevel.HIGH
    if name_l in _HIGH_REDIRECT_PARAMS:
        return ConfidenceLevel.MEDIUM
    if name_l in _MEDIUM_REDIRECT_PARAMS and is_auth:
        return ConfidenceLevel.HIGH
    if name_l in _MEDIUM_REDIRECT_PARAMS:
        return ConfidenceLevel.MEDIUM
    # Low-signal params only flag on auth paths
    if is_noisy and is_auth:
        return ConfidenceLevel.MEDIUM
    if is_noisy:
        return ConfidenceLevel.LOW
    return ConfidenceLevel.LOW


class OpenRedirectMapper(BaseSurfaceMapper):
    category = AttackCategory.OPEN_REDIRECT

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        # JS-based DOM redirect scanning
        for js in result.js_files:
            if not js.content:
                continue
            content = js.content

            has_sink   = any(p in content for p in _JS_REDIRECT_SINKS)
            has_source = any(p in content for p in _JS_REDIRECT_SOURCES)

            if has_sink and has_source:
                sink_hits   = [p for p in _JS_REDIRECT_SINKS if p in content]
                source_hits = [p for p in _JS_REDIRECT_SOURCES if p in content]

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
                        surface_type = "DOM Open Redirect",
                        parameters   = [],
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = [
                            f"JS redirect sinks: {', '.join(sink_hits[:3])}",
                            f"User-controlled sources: {', '.join(source_hits[:3])}",
                            "Source-to-sink flow indicates DOM-based redirect risk",
                        ],
                        burp_notes   = _BURP_NOTES_JS,
                    )

        for ep in result.endpoints:
            method = (ep.method or "GET").upper()
            path   = ep.path or ep.url or ""
            path_l = path.lower()
            is_auth = any(sig in path_l for sig in _AUTH_PATH_SIGNALS)
            burp    = _BURP_NOTES_AUTH if is_auth else _BURP_NOTES

            # Query params
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name not in _ALL_REDIRECT_PARAMS:
                    continue

                # Skip noisy low-signal params on non-auth paths
                if name in _LOW_REDIRECT_PARAMS and not is_auth:
                    continue

                confidence = _redirect_confidence(name, path)
                evidence   = [f"Redirect-signal query param '{name}' on {ep.url}"]
                if is_auth:
                    evidence.append("Auth/OAuth endpoint - redirect param here is high-risk")

                self._candidate(
                    endpoint     = ep,
                    surface_type = "Open Redirect",
                    parameters   = [f"query:{name}"],
                    confidence   = confidence,
                    evidence     = evidence,
                    burp_notes   = burp,
                )

            # Body fields - POST-based redirects (login forms, etc.)
            if method in ("POST", "PUT", "PATCH"):
                for bf in (ep.body_fields or []):
                    name = (bf.get("name") or "").lower()
                    if name not in (_HIGH_REDIRECT_PARAMS | _MEDIUM_REDIRECT_PARAMS):
                        continue

                    confidence = _redirect_confidence(name, path, is_body=True)
                    evidence   = [
                        f"Redirect-signal POST body field '{name}' on {ep.url}",
                        "POST-based redirect params often bypass client-side validation",
                    ]
                    if is_auth:
                        evidence.append("Auth endpoint - POST redirect is classic login flow abuse")
                        confidence = ConfidenceLevel.HIGH

                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Open Redirect",
                        parameters   = [f"body:{name}"],
                        confidence   = confidence,
                        evidence     = evidence,
                        burp_notes   = burp,
                    )

        return self._results
