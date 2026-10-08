"""
CsrfMapper - CSRF attack surface identification.
Pure static analysis of already-collected endpoint data. Zero HTTP requests.
"""
from typing import List, Set
from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ..evidence import Evidence, EvidenceType
from ...storage.models import ScanResult, Endpoint

# Header names that indicate CSRF protection
_CSRF_HEADER_SIGNALS = {
    "x-csrf-token", "x-xsrf-token", "x-requested-with",
    "x-csrftoken",
}

# Body field names that indicate CSRF token presence.
# "token" is intentionally excluded - it's too generic and suppresses valid
# CSRF findings on endpoints with unrelated token fields (auth tokens, API keys,
# payment tokens, etc.). Only match names that are clearly CSRF-specific.
_CSRF_BODY_SIGNALS = {
    "csrf", "_token", "authenticity_token", "csrfmiddlewaretoken",
    "xsrf_token", "csrf_token", "_csrf",
}

# JS patterns that indicate CSRF token management
_CSRF_JS_SIGNALS = [
    "csrf", "xsrf", "_token", "authenticity",
    "csrfmiddlewaretoken", "X-CSRF-Token",
]

# State-changing methods that need CSRF protection
_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_BURP_NOTES = (
    "Test by removing CSRF token from request in Burp. "
    "Try cross-origin request from attacker domain. "
    "Check SameSite cookie attribute. "
    "For JSON endpoints: test if Content-Type can be changed to text/plain."
)

_BURP_NOTES_JSON = (
    "JSON endpoint - test CSRF by changing Content-Type to text/plain or application/x-www-form-urlencoded. "
    "Some frameworks only validate CSRF for non-JSON content types. "
    "Try simple_body_hack={} or enctype workaround."
)


def _source_js_contents(ep: Endpoint, js_map: dict) -> List[str]:
    """Get JS content from files directly associated with this endpoint's source."""
    results = []
    source = ep.source_file or ""
    if source and source in js_map:
        results.append(js_map[source])
    # Also check the source page URL
    source_page = getattr(ep, "source_page", "") or ""
    if source_page and source_page in js_map:
        content = js_map[source_page]
        if content not in results:
            results.append(content)
    return results


def _has_csrf_signal(ep: Endpoint, source_js: List[str]) -> bool:
    """Returns True if CSRF protection signal is found on this specific endpoint."""
    # Check request headers captured for this endpoint
    for k in (ep.request_headers or {}):
        if k.lower() in _CSRF_HEADER_SIGNALS:
            return True

    # Check body fields for CSRF token
    for bf in (ep.body_fields or []):
        name = (bf.get("name") or "").lower()
        if name in _CSRF_BODY_SIGNALS:
            return True

    # Check JS content ONLY from source files linked to this endpoint
    for content in source_js:
        for sig in _CSRF_JS_SIGNALS:
            if sig in content:
                return True

    return False


def _is_json_endpoint(ep: Endpoint) -> bool:
    """Heuristic: does this endpoint accept/return JSON?"""
    content_type = (ep.request_headers or {}).get("content-type", "").lower()
    if "json" in content_type:
        return True
    # Body fields with camelCase names strongly suggest JSON API
    body_names = [(bf.get("name") or "") for bf in (ep.body_fields or [])]
    camel_count = sum(1 for n in body_names if n and any(c.isupper() for c in n[1:]))
    if body_names and camel_count / len(body_names) > 0.5:
        return True
    return False


class CsrfMapper(BaseSurfaceMapper):
    category = AttackCategory.CSRF

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        # Build a map of JS url -> content for per-endpoint source JS lookup
        js_map: dict = {}
        for js in result.js_files:
            if js.content:
                if js.url:
                    js_map[js.url] = js.content
                if getattr(js, "source_page", None):
                    # Don't overwrite a real JS url entry with a page url
                    if js.source_page not in js_map:
                        js_map[js.source_page] = js.content

        for ep in result.endpoints:
            method = (ep.method or "GET").upper()

            # Only flag state-changing methods
            if method not in _STATE_CHANGING_METHODS:
                continue

            # Get JS content scoped to this endpoint's source files only
            source_js = _source_js_contents(ep, js_map)

            has_csrf   = _has_csrf_signal(ep, source_js)
            is_json    = _is_json_endpoint(ep)
            auth_ctx   = ep.auth_context or ""
            is_authed  = auth_ctx and auth_ctx.lower() not in ("", "none")

            if has_csrf:
                # CSRF protection found - still surface it, token validation may be incomplete
                evidence = [
                    f"State-changing {method} endpoint: {ep.url}",
                    "CSRF token signals found - verify token validation is enforced server-side",
                ]
                confidence = ConfidenceLevel.LOW
                burp_notes = _BURP_NOTES
            else:
                # No CSRF signals - this is the primary surface
                evidence = [
                    f"State-changing {method} endpoint with no observed CSRF token: {ep.url}",
                ]
                confidence = ConfidenceLevel.HIGH if is_authed else ConfidenceLevel.MEDIUM
                burp_notes = _BURP_NOTES_JSON if is_json else _BURP_NOTES

                if is_json:
                    evidence.append("JSON endpoint - test Content-Type CSRF bypass")
                if method == "DELETE":
                    evidence.append("DELETE method - often overlooked in CSRF protections")

            if is_authed:
                evidence.append(f"Auth context: {auth_ctx} (auth-gated = higher impact)")

            self._candidate(
                endpoint     = ep,
                surface_type = "CSRF",
                parameters   = [],
                confidence   = confidence,
                evidence     = evidence,
                burp_notes   = burp_notes,
                auth_context = auth_ctx,
            )

            # emit structured evidence alongside the legacy candidate
            csrf_ev = []
            if has_csrf:
                # CSRF token signal found - PARAMETER_SEMANTIC for the token name
                csrf_ev.append(Evidence(
                    evidence_type = EvidenceType.PARAMETER_SEMANTIC,
                    source        = "static",
                    asset         = ep.url or "",
                    context       = f"CSRF token signal on {method} {ep.url}",
                    details       = "Header or body field indicates CSRF protection; verify server-side enforcement",
                ))
            else:
                # No CSRF signal found - missing protection is the signal
                csrf_ev.append(Evidence(
                    evidence_type = EvidenceType.PARAMETER_SEMANTIC,
                    source        = "static",
                    asset         = ep.url or "",
                    context       = f"No CSRF token on state-changing {method} {ep.url}",
                    details       = "No CSRF header or body token observed on this endpoint",
                ))
            if is_authed and auth_ctx:
                csrf_ev.append(Evidence(
                    evidence_type = EvidenceType.METADATA,
                    source        = "static",
                    asset         = ep.url or "",
                    context       = f"Auth-gated endpoint: {auth_ctx}",
                    details       = "Authenticated endpoint - CSRF impact is higher",
                ))
            self._emit_evidence(
                evidence     = csrf_ev,
                surface_type = "CSRF",
                endpoint     = ep.url or "",
                method       = method,
                parameter    = "",
                notes        = burp_notes,
            )

        return self._results
