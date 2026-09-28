"""
CsrfMapper - CSRF attack surface identification.
Pure static analysis of already-collected endpoint data. Zero HTTP requests.
"""
from typing import List
from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint

# Header names that indicate CSRF protection
_CSRF_HEADER_SIGNALS = {
    "x-csrf-token", "x-xsrf-token", "x-requested-with",
    "x-csrftoken",
}

# Body field names that indicate CSRF token presence
_CSRF_BODY_SIGNALS = {
    "csrf", "_token", "authenticity_token", "csrfmiddlewaretoken",
    "xsrf_token", "csrf_token", "_csrf", "token",
}

# JS patterns that indicate CSRF token management
_CSRF_JS_SIGNALS = [
    "csrf", "xsrf", "_token", "authenticity",
    "csrfmiddlewaretoken", "X-CSRF-Token",
]

_BURP_NOTES = (
    "Test by removing CSRF token from request in Burp. "
    "Try cross-origin request from attacker domain. "
    "Check SameSite cookie attribute."
)


def _has_csrf_signal(ep: Endpoint, js_contents: List[str]) -> bool:
    """Returns True if any CSRF protection signal is found."""
    # Check request headers
    for k in (ep.request_headers or {}):
        if k.lower() in _CSRF_HEADER_SIGNALS:
            return True

    # Check body fields
    for bf in (ep.body_fields or []):
        name = (bf.get("name") or "").lower()
        if name in _CSRF_BODY_SIGNALS:
            return True

    # Check JS content for CSRF token patterns
    for content in js_contents:
        for sig in _CSRF_JS_SIGNALS:
            if sig in content:
                return True

    return False


class CsrfMapper(BaseSurfaceMapper):
    category = AttackCategory.CSRF

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        # Collect all JS contents for CSRF signal scan
        js_contents = [js.content for js in result.js_files if js.content]

        for ep in result.endpoints:
            method = (ep.method or "GET").upper()

            # Only flag state-changing methods
            if method not in ("POST", "PUT", "PATCH"):
                continue

            has_csrf = _has_csrf_signal(ep, js_contents)

            if has_csrf:
                # CSRF protection found - lower confidence but still worth noting
                evidence = [
                    f"State-changing {method} endpoint: {ep.url}",
                    "CSRF token signals found - verify token validation is enforced",
                ]
                confidence = ConfidenceLevel.LOW
            else:
                # No CSRF signals - this is the main finding
                evidence = [
                    f"State-changing {method} endpoint with no CSRF token signals: {ep.url}",
                ]
                confidence = ConfidenceLevel.HIGH

            auth_ctx = ep.auth_context or ""
            if auth_ctx and auth_ctx.lower() not in ("", "none"):
                evidence.append(f"Auth context: {auth_ctx}")

            self._candidate(
                endpoint     = ep,
                surface_type = "CSRF",
                parameters   = [],
                confidence   = confidence,
                evidence     = evidence,
                burp_notes   = _BURP_NOTES,
                auth_context = auth_ctx,
            )

        return self._results
