"""
XssMapper - XSS attack surface identification.
Pure static analysis of endpoints and JS content. Zero HTTP requests.
"""
from typing import List
from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint, JSFile

# JS sinks - dangerous if fed attacker-controlled data
_DOM_SINKS = [
    "innerHTML", "outerHTML", "document.write", "insertAdjacentHTML",
    "eval(", "location.href =", "location.assign(",
]

# These sinks only matter paired with a user-controlled source.
# setTimeout(fn, 1000) is harmless. Only flag when a source flows into it.
_WEAK_SINKS = ["setTimeout(", "setInterval("]

# User-controlled DOM sources - these are actual attacker-controlled inputs
_DOM_SOURCES = [
    "location.search", "location.hash", "location.href",
    "document.referrer", "document.URL", "document.documentURI",
    "window.name", "postMessage", "URLSearchParams",
    "location.pathname", "decodeURIComponent(location",
    "getParameter(", "searchParams.get(",
]

# Param names associated with search/reflection functionality
_SEARCH_PARAMS = {
    "search", "query", "q", "filter", "keyword", "term", "s",
    "find", "text", "input", "value", "name", "message", "comment",
}

_BURP_NOTES_REFLECTED = (
    "Test for reflected XSS. Check if input appears in response unsanitized. "
    "Try: <script>alert(1)</script>, \"><img src=x onerror=alert(1)>."
)

_BURP_NOTES_DOM_SURFACE = (
    "DOM source feeds a dangerous sink. Load in browser, set a breakpoint on the sink, "
    "trace the data flow. Try: location.hash payloads first - no server round-trip needed."
)

_BURP_NOTES_DOM_SINK = (
    "DOM sink observed. Verify manually whether any user-controlled source (location.hash, "
    "location.search, postMessage) reaches this sink before treating as XSS."
)


def _find_js_sinks(content: str) -> List[str]:
    return [sink for sink in _DOM_SINKS if sink in content]


def _find_js_sources(content: str) -> List[str]:
    return [src for src in _DOM_SOURCES if src in content]


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
                    burp_notes   = _BURP_NOTES_REFLECTED,
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
                        burp_notes   = _BURP_NOTES_REFLECTED,
                    )

        # 3. JS sink/source analysis per JS file
        for js in result.js_files:
            if not js.content:
                continue
            sinks   = _find_js_sinks(js.content)
            sources = _find_js_sources(js.content)

            if not sinks:
                continue

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

            if sources:
                # Source + sink co-present = plausible data flow - real surface
                evidence = [
                    f"DOM sinks: {', '.join(sinks[:4])}",
                    f"User-controlled sources: {', '.join(sources[:3])}",
                    "Source-to-sink path requires manual trace to confirm",
                ]
                self._candidate(
                    endpoint     = synthetic_ep,
                    surface_type = "DOM XSS Surface",
                    parameters   = [],
                    confidence   = ConfidenceLevel.HIGH,
                    evidence     = evidence,
                    burp_notes   = _BURP_NOTES_DOM_SURFACE,
                )
            else:
                # Sink only - no confirmed user-controlled source feeding it
                # Could still be XSS but needs manual verification first
                self._candidate(
                    endpoint     = synthetic_ep,
                    surface_type = "DOM Sink",
                    parameters   = [],
                    confidence   = ConfidenceLevel.LOW,
                    evidence     = [f"DOM sinks observed: {', '.join(sinks[:4])} - no user-controlled source detected in same file"],
                    burp_notes   = _BURP_NOTES_DOM_SINK,
                )

        return self._results
