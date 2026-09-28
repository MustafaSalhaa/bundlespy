"""
XssMapper - XSS attack surface identification.
Pure static analysis of endpoints and JS content. Zero HTTP requests.
"""
from typing import List
from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint, JSFile

# JS sinks that indicate DOM XSS risk
_DOM_SINKS = [
    "innerHTML", "outerHTML", "document.write", "insertAdjacentHTML",
    "eval(", "setTimeout(", "location.href =", "location.assign(",
]

# Param names associated with search/reflection functionality
_SEARCH_PARAMS = {
    "search", "query", "q", "filter", "keyword", "term", "s",
    "find", "text", "input", "value", "name", "message", "comment",
}

_BURP_NOTES = (
    "Test for reflected XSS. Check if input appears in response unsanitized. "
    "Try DOM-based vectors via browser console."
)


def _find_js_sinks(content: str) -> List[str]:
    return [sink for sink in _DOM_SINKS if sink in content]


class XssMapper(BaseSurfaceMapper):
    category = AttackCategory.XSS

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        # Build a map of JS file URL -> sinks found for cross-referencing
        js_sinks: dict = {}
        for js in result.js_files:
            if js.content:
                sinks = _find_js_sinks(js.content)
                if sinks:
                    js_sinks[js.url] = sinks

        for ep in result.endpoints:
            method = (ep.method or "GET").upper()

            # 1. Search/query params - these are classic XSS reflection targets
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if not name:
                    continue

                is_search_param = name in _SEARCH_PARAMS
                evidence   = []
                confidence = ConfidenceLevel.LOW

                if is_search_param:
                    evidence.append(f"Search-type param '{name}' - high likelihood of value reflection")
                    confidence = ConfidenceLevel.MEDIUM

                # Check if any JS sink is associated with this endpoint's source
                source_sinks = js_sinks.get(ep.source_file or "", [])
                if source_sinks and is_search_param:
                    evidence.append(f"JS sinks in source file: {', '.join(source_sinks[:3])}")
                    confidence = ConfidenceLevel.HIGH
                elif source_sinks:
                    evidence.append(f"JS sinks in source file: {', '.join(source_sinks[:3])}")
                    confidence = ConfidenceLevel.MEDIUM

                if not evidence:
                    evidence.append(f"Query parameter '{name}' is a potential reflection point")
                    confidence = ConfidenceLevel.LOW

                ep_proxy = type('EP', (), {
                    'url': ep.url,
                    'method': method,
                    'auth_context': ep.auth_context or '',
                    'source_type': getattr(ep, 'source_type', 'static') or 'static',
                    'path_params': [],
                    'query_params': [],
                    'body_fields': [],
                    'request_headers': {},
                })()

                self._candidate(
                    endpoint     = ep,
                    surface_type = "Reflected XSS",
                    parameters   = [f"query:{name}"],
                    confidence   = confidence,
                    evidence     = evidence,
                    burp_notes   = _BURP_NOTES,
                )

            # 2. Body fields on POST endpoints
            if method in ("POST", "PUT", "PATCH"):
                for bf in (ep.body_fields or []):
                    name = (bf.get("name") or "").lower()
                    if not name:
                        continue
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Stored/Reflected XSS",
                        parameters   = [f"body:{name}"],
                        confidence   = ConfidenceLevel.LOW,
                        evidence     = [f"POST body field '{name}' may be stored/reflected"],
                        burp_notes   = _BURP_NOTES,
                    )

        # 3. JS sink candidates from all JS files
        for js in result.js_files:
            if not js.content:
                continue
            sinks = _find_js_sinks(js.content)
            if not sinks:
                continue

            # Create a synthetic endpoint pointing to the JS file
            ep_url = js.url or js.source_page or ""
            if not ep_url:
                continue

            from ...storage.models import Endpoint as _Endpoint
            synthetic_ep = _Endpoint(
                url=ep_url,
                path=ep_url,
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
                source_type=getattr(js, "source_type", "static") or "static",
            )

            self._candidate(
                endpoint     = synthetic_ep,
                surface_type = "DOM XSS",
                parameters   = [],
                confidence   = ConfidenceLevel.MEDIUM,
                evidence     = [f"DOM sinks in JS: {', '.join(sinks[:4])}"],
                burp_notes   = (
                    "Test DOM-based XSS via browser console. "
                    "Trace data flow from user-controlled sources to these sinks."
                ),
            )

        return self._results
