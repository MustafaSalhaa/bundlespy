"""
PrototypePollutionMapper - prototype pollution attack surface identification.
Pure static analysis of JS file content + endpoint parameter names. Zero HTTP requests.

Prototype pollution lets an attacker set properties on Object.prototype so that
every plain object in the application inherits them, enabling:
  - Client-side: XSS via __proto__.innerHTML, DOM clobbering, logic bypass
  - Server-side: RCE in some Node.js frameworks (lodash.merge, hoek, etc.)
  - Auth bypass: __proto__.isAdmin = true on deserialized JSON

Detection strategy (three independent signals):
  1. JS sink analysis - dangerous merge/assign/extend functions that accept
     user-controlled objects without key sanitisation
  2. JS source-to-sink taint - user input (URL params, postMessage, JSON.parse)
     flows into a pollutable sink in the same file
  3. Endpoint parameter names - JSON body params named __proto__, constructor,
     prototype (direct pollution via API endpoint)
"""
import re
from typing import List, Set, Dict

from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint

# ── Dangerous sink patterns ────────────────────────────────────────────────────
_DEEP_MERGE_SINKS = [
    # lodash / underscore
    "_.merge(", "_.mergeWith(", "_.defaultsDeep(", "_.extend(",
    # jQuery
    "$.extend(true,", "$.extend( true,",
    # node standard / userland
    "Object.assign(", "Object.defineProperty(",
    "merge(", "deepmerge(", "deepExtend(", "deepAssign(",
    "mergeDeep(", "mergeWith(", "assignDeep(",
    # hoek / joi (historic Node.js RCE)
    "hoek.merge(", "hoek.applyToDefaults(",
    # recursive clone / defaults
    "clone(", "cloneDeep(", "defaults(", "defaultsDeep(",
    # qs / querystring parse with prototype keys
    "qs.parse(", "querystring.parse(",
    # JSON.parse into an object that gets merged
    "JSON.parse(",
]

_POLLUTION_SOURCES = [
    # URL / query
    "location.search", "location.hash", "URLSearchParams",
    "searchParams.get(", "searchParams.getAll(",
    # postMessage (classic client-side pollution vector)
    "addEventListener('message'", 'addEventListener("message"',
    "window.onmessage", "e.data", "event.data",
    # JSON deserialization of untrusted input
    "JSON.parse(req.", "JSON.parse(body", "JSON.parse(data",
    "JSON.parse(event.data", "JSON.parse(e.data",
    # Express / Koa / Hapi body
    "req.body", "req.query", "req.params",
    "ctx.request.body", "ctx.query",
    # Generic user-controlled
    "params.", "$route.query", "router.query",
    "$page.url", "document.location",
]

_EXPLICIT_POLLUTION_RE = re.compile(
    r'(?:__proto__|constructor\s*\[|prototype\s*\[|\[.{0,20}__proto__.{0,20}\])',
    re.I,
)

_GADGET_PATTERNS = [
    # DOM gadgets
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "document.write(", "document.writeln(",
    # Node.js spawn gadgets
    "child_process", "exec(", "spawn(",
    # eval gadgets
    "eval(", "Function(", "setTimeout(", "setInterval(",
    # template rendering gadgets
    "template(", "render(", "compile(",
]

_POLLUTION_PARAM_NAMES = {
    "__proto__", "constructor", "prototype",
    "%5f%5fproto%5f%5f", "%5f%5fproto__",
}

# ── Burp notes ─────────────────────────────────────────────────────────────────

_BURP_NOTES_JS_SINK = (
    "Prototype pollution sink detected. "
    "Test in browser console: Object.prototype.polluted = 'yes'; then check if ({}).polluted === 'yes'. "
    "For lodash _.merge / $.extend(true): send a JSON body with {\"__proto__\":{\"isAdmin\":true}} "
    "and check if subsequent objects inherit isAdmin. "
    "Use Burp Suite DOM Invader (Augmented Labs) for automated client-side PP scanning. "
    "For server-side: send POST body {\"__proto__\":{\"outputFunctionName\":\"x;process.mainModule.require('child_process').exec('id')//\"}} "
    "against pug/jade template engines."
)

_BURP_NOTES_TAINTED = (
    "Prototype pollution: user-controlled source flows into deep merge sink. "
    "Client-side PoC: add ?__proto__[polluted]=yes to the URL, then run Object.prototype.polluted in console. "
    "postMessage vector: window.postMessage(JSON.stringify({__proto__:{isAdmin:true}}), '*') "
    "If a gadget (innerHTML, eval, template render) reads the polluted key, this chains to XSS/RCE. "
    "Use Burp DOM Invader: enable prototype pollution canary, browse the app, check for hits."
)

_BURP_NOTES_EXPLICIT = (
    "Explicit __proto__ / constructor / prototype access in JS. "
    "This is either a known-bad pattern or a deliberate prototype manipulation. "
    "Trace the value source: if user-controlled, it's direct prototype pollution. "
    "Test: inject {\"__proto__\":{\"isAdmin\":true}} in any JSON endpoint and check app behaviour."
)

_BURP_NOTES_PARAM = (
    "API endpoint accepts a parameter named __proto__, constructor, or prototype. "
    "This is direct server-side prototype pollution. "
    "Test: POST {\"__proto__\":{\"isAdmin\":true}} or GET ?__proto__[isAdmin]=true. "
    "On Node.js backends: try {\"__proto__\":{\"outputFunctionName\":\"_tmp1;global.process.mainModule.require('child_process').execSync('id')//\"}} "
    "against any pug/jade template render path. "
    "Also try {\"constructor\":{\"prototype\":{\"isAdmin\":true}}}."
)

_BURP_NOTES_GADGET = (
    "Prototype pollution sink + DOM/execution gadget in same file. "
    "This is a complete pollution-to-XSS/RCE chain candidate. "
    "Steps: 1) Confirm pollution via Object.prototype check in console. "
    "2) Find which key the gadget reads (e.g. innerHTML reads __proto__.innerHTML). "
    "3) Inject that key via URL param or postMessage: ?__proto__[innerHTML]=<img src=x onerror=alert(1)>. "
    "4) Verify DOM update triggers the gadget. Report as prototype pollution -> XSS chain."
)


# ── Helpers ───────────────────────────────────────────────────────────────────

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


# ── Mapper ────────────────────────────────────────────────────────────────────

class PrototypePollutionMapper(BaseSurfaceMapper):
    category = AttackCategory.PROTOTYPE_POLLUTION

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        seen: Set[str] = set()

        # ── Phase 1: JS file analysis ─────────────────────────────────────────
        for js in (result.js_files or []):
            content = js.content or ""
            if not content:
                continue

            js_url   = js.url or "unknown"
            sinks    = _has_sink(content)
            sources  = _has_source(content)
            gadgets  = _has_gadget(content)
            explicit = bool(_EXPLICIT_POLLUTION_RE.search(content))

            # Signal 1: Explicit __proto__ / constructor[prototype] usage
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
                            "Direct prototype manipulation detected — check if user input controls the value.",
                        ],
                        burp_notes   = _BURP_NOTES_EXPLICIT,
                        auth_context = "",
                    )

            # Signal 2: Sink + source in same file (tainted merge)
            if sinks and sources:
                key = f"pp_tainted:{js_url}"
                if key not in seen:
                    seen.add(key)
                    has_chain = bool(gadgets)
                    conf = ConfidenceLevel.HIGH if has_chain else ConfidenceLevel.MEDIUM
                    evidence = [
                        f"Deep merge/assign sink(s) in {js_url}: {', '.join(sinks[:4])}",
                        f"User-controlled source(s): {', '.join(sources[:4])}",
                        "User input flows into a pollutable merge function without key sanitisation.",
                    ]
                    if has_chain:
                        evidence.append(
                            f"Gadget(s) present in same file: {', '.join(gadgets[:3])} — "
                            "complete pollution-to-execution chain candidate"
                        )
                    self._candidate(
                        endpoint     = _synthetic_endpoint(js_url),
                        surface_type = (
                            "Prototype Pollution: Source-to-Sink Chain (+ Gadget)"
                            if has_chain else
                            "Prototype Pollution: Source-to-Sink Taint"
                        ),
                        parameters   = sinks[:4],
                        confidence   = conf,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_GADGET if has_chain else _BURP_NOTES_TAINTED,
                        auth_context = "",
                    )

            # Signal 3: Sink only (no confirmed source, but still dangerous)
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

        # ── Phase 2: endpoint parameter analysis ──────────────────────────────
        for ep in result.endpoints:
            method   = (ep.method or "GET").upper()
            url      = ep.url or ""
            auth_ctx = ep.auth_context or ""

            hits = []

            # Query params
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name in _POLLUTION_PARAM_NAMES:
                    hits.append(f"query:{name}")

            # Body fields
            for bf in (ep.body_fields or []):
                name = (bf.get("name") or "").lower()
                if name in _POLLUTION_PARAM_NAMES:
                    hits.append(f"body:{name}")

            # Path params
            for pp in (ep.path_params or []):
                name = (pp.get("name") or "").lower()
                if name in _POLLUTION_PARAM_NAMES:
                    hits.append(f"path:{name}")

            if hits:
                key = f"pp_param:{method}:{url}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"Endpoint {method} {url} accepts prototype-polluting parameter(s): {', '.join(hits)}",
                        "Server-side prototype pollution: attacker can send {\"__proto__\":{\"key\":\"val\"}} "
                        "and pollute Object.prototype on the Node.js server.",
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

        return self._results
