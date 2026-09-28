"""
SsrfMapper - SSRF attack surface identification.
Pure static analysis of already-collected endpoint data. Zero HTTP requests.
"""
from typing import List
from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint

# Param names with high SSRF signal
_HIGH_SSRF_PARAMS = {
    "url", "uri", "callback", "webhook", "endpoint",
}

# Param names with medium SSRF signal
_MEDIUM_SSRF_PARAMS = {
    "redirect", "target", "src", "source", "dest", "destination",
    "remote", "proxy", "forward",
}

# Param names with lower but non-zero SSRF signal
_LOW_SSRF_PARAMS = {
    "link", "fetch", "load", "pull", "path", "file", "host", "domain",
}

_ALL_SSRF_PARAMS = _HIGH_SSRF_PARAMS | _MEDIUM_SSRF_PARAMS | _LOW_SSRF_PARAMS

_BURP_NOTES = (
    "Test with Burp Collaborator. "
    "Try http://169.254.169.254/latest/meta-data/ for cloud SSRF. "
    "Try internal hostnames."
)


def _ssrf_confidence(name: str) -> str:
    name = name.lower()
    if name in _HIGH_SSRF_PARAMS:
        return ConfidenceLevel.HIGH
    if name in _MEDIUM_SSRF_PARAMS:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


class SsrfMapper(BaseSurfaceMapper):
    category = AttackCategory.SSRF

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        for ep in result.endpoints:
            method = (ep.method or "GET").upper()

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
                    burp_notes   = _BURP_NOTES,
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
                    burp_notes   = _BURP_NOTES,
                )

        return self._results
