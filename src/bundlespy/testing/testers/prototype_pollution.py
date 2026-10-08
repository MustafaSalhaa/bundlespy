"""
PrototypePollutionMapper - prototype pollution attack surface identification.
Pure static analysis of JS file content + endpoint parameter names. Zero HTTP requests.
"""
import logging
import re
from typing import List, Set

from .base import BaseSurfaceMapper

_log = logging.getLogger("bundlespy.testing.prototype_pollution")
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ..evidence import Evidence, EvidenceType
from ...storage.models import ScanResult, Endpoint

_DEEP_MERGE_SINKS = [
    "_.merge(", "_.mergeWith(", "_.defaultsDeep(", "_.extend(",
    "$.extend(true,", "$.extend( true,",
    "Object.assign(", "Object.defineProperty(",
    "merge(", "deepmerge(", "deepExtend(", "deepAssign(",
    "mergeDeep(", "mergeWith(", "assignDeep(",
    "hoek.merge(", "hoek.applyToDefaults(",
    "clone(", "cloneDeep(", "defaults(", "defaultsDeep(",
    "qs.parse(", "querystring.parse(",
    "JSON.parse(",
]

_POLLUTION_SOURCES = [
    "location.search", "location.hash", "URLSearchParams",
    "searchParams.get(", "searchParams.getAll(",
    "addEventListener('message'", 'addEventListener("message"',
    "window.onmessage", "e.data", "event.data",
    "JSON.parse(req.", "JSON.parse(body", "JSON.parse(data",
    "JSON.parse(event.data", "JSON.parse(e.data",
    "req.body", "req.query", "req.params",
    "ctx.request.body", "ctx.query",
    "params.", "$route.query", "router.query",
    "$page.url", "document.location",
]

_EXPLICIT_POLLUTION_RE = re.compile(
    r'(?:__proto__|constructor\s*\[|prototype\s*\[|\[.{0,20}__proto__.{0,20}\])',
    re.I,
)

_GADGET_PATTERNS = [
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "document.write(", "document.writeln(",
    "child_process", "exec(", "spawn(",
    "eval(", "Function(", "setTimeout(", "setInterval(",
    "template(", "render(", "compile(",
]

_POLLUTION_PARAM_NAMES = {
    "__proto__", "constructor", "prototype",
    "%5f%5fproto%5f%5f", "%5f%5fproto__",
}

_BURP_NOTES_JS_SINK = (
    "Prototype pollution sink detected. "
    "Test in browser console: Object.prototype.polluted = 'yes'; check if ({}).polluted === 'yes'. "
    "For lodash _.merge / $.extend(true): send JSON body {\"__proto__\":{\"isAdmin\":true}}. "
    "Use Burp DOM Invader for automated client-side PP scanning. "
    "Server-side: send {\"__proto__\":{\"outputFunctionName\":\"x;process.mainModule.require('child_process').exec('id')//\"}} against pug/jade."
)

_BURP_NOTES_TAINTED = (
    "Prototype pollution: user-controlled source flows into deep merge sink. "
    "PoC: add ?__proto__[polluted]=yes to URL, run Object.prototype.polluted in console. "
    "postMessage: window.postMessage(JSON.stringify({__proto__:{isAdmin:true}}), '*'). "
    "If gadget (innerHTML, eval, template render) reads polluted key, chains to XSS/RCE. "
    "Burp DOM Invader: enable prototype pollution canary."
)

_BURP_NOTES_EXPLICIT = (
    "Explicit __proto__ / constructor / prototype access in JS. "
    "Trace the value source: if user-controlled, it's direct prototype pollution. "
    "Test: inject {\"__proto__\":{\"isAdmin\":true}} in any JSON endpoint and check app behaviour."
)

_BURP_NOTES_PARAM = (
    "API endpoint accepts __proto__, constructor, or prototype parameter. "
    "Direct server-side prototype pollution. "
    "Test: POST {\"__proto__\":{\"isAdmin\":true}} or GET ?__proto__[isAdmin]=true. "
    "Node.js RCE via pug: {\"__proto__\":{\"outputFunctionName\":\"_tmp1;global.process.mainModule.require('child_process').execSync('id')//\"}}. "
    "Also try: {\"constructor\":{\"prototype\":{\"isAdmin\":true}}}."
)

_BURP_NOTES_GADGET = (
    "Prototype pollution sink + DOM/execution gadget in same file — complete chain candidate. "
    "1) Confirm pollution: Object.prototype check in console. "
    "2) Find which key the gadget reads (e.g. innerHTML reads __proto__.innerHTML). "
    "3) Inject via URL or postMessage: ?__proto__[innerHTML]=<img src=x onerror=alert(1)>. "
    "4) Verify DOM update triggers gadget. Report as prototype pollution → XSS chain."
)


def _has_sink(content: str) -> List[str]:
    return [s for s in _DEEP_MERGE_SINKS if s in content]

def _has_source(content: str) -> List[str]:
    return [s for s in _POLLUTION_SOURCES if s in content]

def _has_gadget(content: str) -> List[str]:
    return [g for g in _GADGET_PATTERNS if g in content]

def _synthetic_endpoint(url: str) -> "Endpoint":
    from ...storage.models import Endpoint as _Endpoint
    return _Endpoint(
        url=url, path="", method="GET", category="",
        source_file=url, line_number=0, confidence=0.5,
        query_params=[], path_params=[], body_fields=[],
        request_headers={}, auth_context="", source_type="static",
    )


class PrototypePollutionMapper(BaseSurfaceMapper):
    category = AttackCategory.PROTOTYPE_POLLUTION

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        seen: Set[str] = set()

        # Build set of known library file URLs - findings in library code
        # (React, Angular, jQuery, lodash, etc.) are not exploitable attack surface.
        _lib_urls: Set[str] = {
            lf.source_file
            for lf in getattr(result, "library_findings", [])
            if lf.source_file
        }

        for js in (result.js_files or []):
            content = js.content or ""
            if not content:
                continue

            # Skip library files - their internal sinks are not reachable from app code
            if js.url and js.url in _lib_urls:
                _log.debug("Skipping library file for prototype pollution analysis: %s", js.url)
                continue

            js_url   = js.url or "unknown"
            sinks    = _has_sink(content)
            sources  = _has_source(content)
            gadgets  = _has_gadget(content)
            explicit = bool(_EXPLICIT_POLLUTION_RE.search(content))

            if explicit:
                key = f"pp_explicit:{js_url}"
                if key not in seen:
                    seen.add(key)
                    self._candidate(
                        endpoint     = _synthetic_endpoint(js_url),
                        surface_type = "Prototype Pollution: Explicit __proto__ Access",
                        parameters   = ["__proto__", "constructor.prototype"],
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = [
                            f"Explicit __proto__ or constructor[prototype] access in {js_url}",
                            "Direct prototype manipulation — check if user input controls the value.",
                        ],
                        burp_notes   = _BURP_NOTES_EXPLICIT,
                        auth_context = "",
                    )
                    self._emit_evidence(
                        evidence=[
                            Evidence(
                                evidence_type = EvidenceType.AST,
                                source        = "static",
                                asset         = js_url,
                                context       = "Explicit __proto__ or constructor[prototype] access",
                                details       = "__proto__ / constructor.prototype direct manipulation",
                            ),
                        ],
                        surface_type = "Prototype Pollution: Explicit __proto__ Access",
                        endpoint     = js_url,
                        method       = "GET",
                        parameter    = "__proto__",
                        notes        = _BURP_NOTES_EXPLICIT,
                    )

            if sinks and sources:
                key = f"pp_tainted:{js_url}"
                if key not in seen:
                    seen.add(key)
                    has_chain = bool(gadgets)
                    conf      = ConfidenceLevel.HIGH if has_chain else ConfidenceLevel.MEDIUM
                    evidence  = [
                        f"Deep merge/assign sink(s) in {js_url}: {', '.join(sinks[:4])}",
                        f"User-controlled source(s): {', '.join(sources[:4])}",
                        "User input flows into pollutable merge function without key sanitisation.",
                    ]
                    if has_chain:
                        evidence.append(
                            f"Gadget(s) present: {', '.join(gadgets[:3])} — "
                            "complete pollution-to-execution chain candidate"
                        )
                    surface_type = (
                        "Prototype Pollution: Source-to-Sink Chain (+ Gadget)"
                        if has_chain else
                        "Prototype Pollution: Source-to-Sink Taint"
                    )
                    self._candidate(
                        endpoint     = _synthetic_endpoint(js_url),
                        surface_type = surface_type,
                        parameters   = sinks[:4],
                        confidence   = conf,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_GADGET if has_chain else _BURP_NOTES_TAINTED,
                        auth_context = "",
                    )
                    # build evidence list - source + sink always present, gadget optional
                    ev_list = [
                        Evidence(
                            evidence_type = EvidenceType.STATIC_JS,
                            source        = "static",
                            asset         = js_url,
                            context       = "Deep merge/assign sink",
                            details       = ", ".join(sinks[:4]),
                        ),
                        Evidence(
                            evidence_type = EvidenceType.DOM,
                            source        = "static",
                            asset         = js_url,
                            context       = "User-controlled source",
                            details       = ", ".join(sources[:4]),
                        ),
                    ]
                    if has_chain:
                        ev_list.append(Evidence(
                            evidence_type = EvidenceType.AST,
                            source        = "static",
                            asset         = js_url,
                            context       = "DOM/execution gadget - complete chain candidate",
                            details       = ", ".join(gadgets[:3]),
                        ))
                    self._emit_evidence(
                        evidence     = ev_list,
                        surface_type = surface_type,
                        subtype      = "+ Gadget" if has_chain else "",
                        endpoint     = js_url,
                        method       = "GET",
                        parameter    = sinks[0] if sinks else "",
                        notes        = _BURP_NOTES_GADGET if has_chain else _BURP_NOTES_TAINTED,
                    )

            elif sinks and not sources and not explicit:
                key = f"pp_sink:{js_url}"
                if key not in seen:
                    seen.add(key)
                    self._candidate(
                        endpoint     = _synthetic_endpoint(js_url),
                        surface_type = "Prototype Pollution: Deep Merge Sink",
                        parameters   = sinks[:4],
                        confidence   = ConfidenceLevel.LOW,
                        evidence     = [
                            f"Deep merge/assign sink(s) in {js_url}: {', '.join(sinks[:4])}",
                            "No confirmed user-controlled source in this file — "
                            "may still be reachable if input arrives from another module.",
                        ],
                        burp_notes   = _BURP_NOTES_JS_SINK,
                        auth_context = "",
                    )
                    self._emit_evidence(
                        evidence=[
                            Evidence(
                                evidence_type = EvidenceType.STATIC_JS,
                                source        = "static",
                                asset         = js_url,
                                context       = "Deep merge/assign sink - no source confirmed in this file",
                                details       = ", ".join(sinks[:4]),
                            ),
                        ],
                        surface_type = "Prototype Pollution: Deep Merge Sink",
                        endpoint     = js_url,
                        method       = "GET",
                        parameter    = sinks[0] if sinks else "",
                        notes        = _BURP_NOTES_JS_SINK,
                    )

        for ep in result.endpoints:
            method   = (ep.method or "GET").upper()
            url      = ep.url or ""
            auth_ctx = ep.auth_context or ""
            hits     = []

            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name in _POLLUTION_PARAM_NAMES:
                    hits.append(f"query:{name}")

            for bf in (ep.body_fields or []):
                name = (bf.get("name") or "").lower()
                if name in _POLLUTION_PARAM_NAMES:
                    hits.append(f"body:{name}")

            for pp in (ep.path_params or []):
                name = (pp.get("name") or "").lower()
                if name in _POLLUTION_PARAM_NAMES:
                    hits.append(f"path:{name}")

            if hits:
                key = f"pp_param:{method}:{url}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"Endpoint {method} {url} accepts prototype-polluting param(s): {', '.join(hits)}",
                        "Attacker can send {\"__proto__\":{\"key\":\"val\"}} to pollute Object.prototype server-side.",
                    ]
                    if auth_ctx and auth_ctx.lower() not in ("", "none"):
                        evidence.append(f"Auth context: {auth_ctx}")
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Prototype Pollution: Direct API Parameter",
                        parameters   = hits,
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_PARAM,
                        auth_context = auth_ctx,
                    )
                    ev_list = [
                        Evidence(
                            evidence_type = EvidenceType.ROUTE_DECLARATION,
                            source        = "static",
                            endpoint      = url,
                            method        = method,
                            context       = "API endpoint accepts prototype-polluting parameter",
                            details       = ", ".join(hits),
                        ),
                    ]
                    if auth_ctx and auth_ctx.lower() not in ("", "none"):
                        ev_list.append(Evidence(
                            evidence_type = EvidenceType.METADATA,
                            source        = "static",
                            endpoint      = url,
                            method        = method,
                            context       = f"Auth context: {auth_ctx}",
                        ))
                    self._emit_evidence(
                        evidence     = ev_list,
                        surface_type = "Prototype Pollution: Direct API Parameter",
                        endpoint     = url,
                        method       = method,
                        parameter    = hits[0] if hits else "__proto__",
                        notes        = _BURP_NOTES_PARAM,
                    )

        return self._results
