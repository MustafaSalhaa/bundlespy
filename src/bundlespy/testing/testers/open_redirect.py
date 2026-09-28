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
    "returnUrl", "returnTo",
}

_MEDIUM_REDIRECT_PARAMS = {
    "return", "destination", "dest", "to", "goto", "continue",
    "successUrl", "cancelUrl", "back",
}

_LOW_REDIRECT_PARAMS = {
    "url", "ref", "referrer",
}

_ALL_REDIRECT_PARAMS = _HIGH_REDIRECT_PARAMS | _MEDIUM_REDIRECT_PARAMS | _LOW_REDIRECT_PARAMS

# Path fragments that increase confidence for open redirect
_AUTH_PATH_SIGNALS = {
    "/login", "/logout", "/auth", "/oauth", "/callback",
    "/signin", "/signout", "/sso",
}

_BURP_NOTES = (
    "Test with https://evil.com as value. "
    "Check if Location header follows. "
    "Test URL encoding bypass."
)


def _redirect_confidence(name: str, path: str) -> str:
    name  = name.lower()
    path  = path.lower()
    is_auth_path = any(sig in path for sig in _AUTH_PATH_SIGNALS)

    if name in _HIGH_REDIRECT_PARAMS and is_auth_path:
        return ConfidenceLevel.HIGH
    if name in _HIGH_REDIRECT_PARAMS:
        return ConfidenceLevel.MEDIUM
    if name in _MEDIUM_REDIRECT_PARAMS:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


class OpenRedirectMapper(BaseSurfaceMapper):
    category = AttackCategory.OPEN_REDIRECT

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        for ep in result.endpoints:
            path = ep.path or ep.url or ""

            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name not in _ALL_REDIRECT_PARAMS:
                    continue

                confidence = _redirect_confidence(name, path)
                evidence   = [f"Redirect-signal param '{name}' on {ep.url}"]

                is_auth = any(sig in path.lower() for sig in _AUTH_PATH_SIGNALS)
                if is_auth:
                    evidence.append(f"Auth/OAuth endpoint increases SSRF/redirect risk")

                self._candidate(
                    endpoint     = ep,
                    surface_type = "Open Redirect",
                    parameters   = [f"query:{name}"],
                    confidence   = confidence,
                    evidence     = evidence,
                    burp_notes   = _BURP_NOTES,
                )

        return self._results
