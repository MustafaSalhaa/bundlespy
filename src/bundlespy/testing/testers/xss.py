"""
XssMapper - XSS attack surface identification (reflected, stored, DOM-based).
Pure static analysis of endpoints and JS content. Zero HTTP requests.
"""
from typing import List, Dict, Set
from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint, JSFile

# ─── DOM SINKS ───────────────────────────────────────────────────────────────

# Strong sinks - directly write HTML/JS, any user input = XSS
_STRONG_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write(",
    "document.writeln(",
    "insertAdjacentHTML(",
    "eval(",
    "Function(",
    "setTimeout(",       # only dangerous when first arg is a string, not a fn
    "setInterval(",      # same
    ".html(",            # jQuery .html() - matches $(...).html( in minified code
    ".append(",          # jQuery .append() - can inject HTML nodes
    ".prepend(",
    ".after(",
    ".before(",
    "dangerouslySetInnerHTML",   # React
    "v-html",                    # Vue
    "[innerHTML]",               # Angular template binding
    "__html",                    # React shorthand for dangerouslySetInnerHTML
]

# Navigation sinks - can be exploited with javascript: URIs
_NAVIGATION_SINKS = [
    "location.href =",
    "location.assign(",
    "location.replace(",
    "window.open(",
    "document.location =",
    "location =",
]

# Weak sinks - only dangerous when string-typed user input flows in
_WEAK_SINKS = [
    "postMessage(",      # can be a source OR a sink depending on context
    "document.domain =",
    "document.cookie",   # exfil context, not XSS trigger
]

_ALL_SINKS = _STRONG_SINKS + _NAVIGATION_SINKS + _WEAK_SINKS

# ─── DOM SOURCES ─────────────────────────────────────────────────────────────

# Direct attacker-controlled sources
_DOM_SOURCES = [
    "location.search",
    "location.hash",
    "location.href",
    "location.pathname",
    "document.referrer",
    "document.URL",
    "document.documentURI",
    "document.baseURI",
    "window.name",
    "postMessage",
    "URLSearchParams",
    "decodeURIComponent(location",
    "getParameter(",
    "searchParams.get(",
    "new URL(",
    "location.search.slice(",
    "location.search.substring(",
    "location.search.replace(",
    "params.get(",
    "qs.parse(",         # common query string lib
]

# ─── REFLECTED XSS PARAMS ────────────────────────────────────────────────────

# High-signal: these param names are almost always reflected in the response
_REFLECTED_HIGH_PARAMS = {
    "search", "query", "q", "keyword", "term", "s", "find",
    "error", "msg", "message", "notice", "alert", "warn",    # error/notice reflection
    "callback", "jsonp", "cb",                                # JSONP callbacks
    "next", "redirect", "return_url",                         # value often echoed in page
}

# Medium-signal: commonly reflected but less certain
_REFLECTED_MEDIUM_PARAMS = {
    "text", "input", "value", "name", "username", "email",
    "title", "label", "description", "comment",
    "ref", "referrer", "source", "from",
    "page", "tab", "view", "section", "lang", "locale",
    "format", "type", "mode", "action",
    "filter", "sort", "order", "category",
}

# Low-signal: any query param can reflect - catch everything else
# These won't be flagged individually but we sweep all params with context

_ALL_REFLECTED_PARAMS = _REFLECTED_HIGH_PARAMS | _REFLECTED_MEDIUM_PARAMS

# ─── STORED XSS FIELDS ───────────────────────────────────────────────────────

# Body field names that imply content gets stored and displayed to other users
_STORED_HIGH_FIELDS = {
    "comment", "message", "content", "body", "text", "note",
    "description", "bio", "about", "summary", "review", "feedback",
    "title", "subject", "caption", "post", "reply", "response",
    "announcement", "update", "news",
}

# Field names that may be stored and displayed but with less certainty
_STORED_MEDIUM_FIELDS = {
    "name", "username", "display_name", "first_name", "last_name",
    "address", "location", "website", "url", "link",
    "label", "tag", "category", "reason", "notes",
}

# ─── POSTMESSAGE PATTERNS ────────────────────────────────────────────────────

# Patterns that indicate a postMessage listener is registered
_POSTMESSAGE_LISTENER_PATTERNS = [
    "addEventListener(\"message\"",
    "addEventListener('message'",
    ".onmessage =",
    ".onmessage=",
]

# Patterns that indicate the handler performs an origin check
_ORIGIN_CHECK_PATTERNS = [
    "event.origin",
    "e.origin",
    "message.origin",
    "ev.origin",
    "msg.origin",
    "data.origin",
]

# ─── BURP NOTES ──────────────────────────────────────────────────────────────

_BURP_NOTES_REFLECTED = (
    "Reflected XSS surface. Check if the param value appears in the HTML response unsanitized. "
    "Payloads: <script>alert(1)</script>, \"><img src=x onerror=alert(1)>, "
    "javascript:alert(1) (for href/src contexts). "
    "Use Burp's active scan or manually fuzz with a unique string first to confirm reflection."
)

_BURP_NOTES_REFLECTED_JSONP = (
    "JSONP callback parameter - classic XSS vector. "
    "Test: ?callback=<script>alert(1)</script> and ?callback=alert. "
    "If the response wraps your value in a function call without sanitization, it's exploitable. "
    "Content-Type should be application/json but often isn't for JSONP."
)

_BURP_NOTES_STORED = (
    "Stored XSS surface. Input may be persisted and rendered for other users. "
    "Submit <img src=x onerror=alert(document.domain)> and browse to where the content displays. "
    "Check admin panels, dashboards, user profiles - anywhere the data could be rendered. "
    "Use a Burp Collaborator payload to detect blind stored XSS."
)

_BURP_NOTES_DOM_SURFACE = (
    "DOM source flows into a dangerous sink - plausible XSS data flow. "
    "Open in browser, DevTools -> Sources, set breakpoint on the sink. "
    "Test location.hash payloads first (no server round-trip): #<img src=x onerror=alert(1)>. "
    "Then test location.search params. Trace the full data flow before claiming exploitable."
)

_BURP_NOTES_DOM_SINK = (
    "DOM sink observed with no confirmed user-controlled source in the same file. "
    "Verify manually: trace all inputs into this sink. "
    "The source may arrive via postMessage, an AJAX response, or a variable set elsewhere. "
    "Not exploitable until a user-controlled path to this sink is confirmed."
)

_BURP_NOTES_REACT = (
    "dangerouslySetInnerHTML detected - React's explicit XSS escape hatch. "
    "Trace what value feeds __html. If it includes any user-controlled data without DOMPurify or similar, it's XSS. "
    "Search the codebase for dangerouslySetInnerHTML and review each usage."
)

_BURP_NOTES_VUE = (
    "v-html directive detected - Vue's equivalent of innerHTML, bypasses Vue's XSS protections. "
    "Trace the bound variable back to its source. If any part is user-controlled, test XSS. "
    "Payload: <img src=x onerror=alert(1)>"
)

_BURP_NOTES_JQUERY = (
    "jQuery HTML-injection sink detected (.html(), .append(), etc.). "
    "Very common XSS vector in older apps. Trace what value is passed in. "
    "If any user input reaches this, test: $.html('<img src=x onerror=alert(1)>')"
)

_BURP_NOTES_NAV_SINK = (
    "Navigation sink (location.href, window.open, etc.) with user-controlled source. "
    "Primary risk is open redirect, but javascript: URI injection enables XSS. "
    "Test: ?next=javascript:alert(1), then confirm if href is set without validation."
)

_BURP_NOTES_POSTMESSAGE = (
    "postMessage XSS - no origin check. Open target in browser, open DevTools console, run: "
    "window.postMessage('<img src=x onerror=alert(document.domain)>', '*') and watch for XSS. "
    "Also test: window.postMessage({type:'update', data:'<script>alert(1)<\\/script>'}, '*'). "
    "Check what the handler does with event.data before claiming exploitable."
)


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def _find_strong_sinks(content: str) -> List[str]:
    return [s for s in _STRONG_SINKS if s in content]

def _find_nav_sinks(content: str) -> List[str]:
    return [s for s in _NAVIGATION_SINKS if s in content]

def _find_sources(content: str) -> List[str]:
    return [s for s in _DOM_SOURCES if s in content]

def _is_framework_sink(content: str) -> Dict[str, bool]:
    return {
        "react":  "dangerouslySetInnerHTML" in content or "__html" in content,
        "vue":    "v-html" in content,
        "jquery": any(s in content for s in [".html(", ".append(", ".prepend(", ".after(", ".before("]),
    }

def _sink_burp_notes(sinks: List[str], frameworks: Dict[str, bool]) -> str:
    if frameworks.get("react"):
        return _BURP_NOTES_REACT
    if frameworks.get("vue"):
        return _BURP_NOTES_VUE
    if frameworks.get("jquery"):
        return _BURP_NOTES_JQUERY
    return _BURP_NOTES_DOM_SURFACE

def _has_postmessage_listener(content: str) -> bool:
    return any(p in content for p in _POSTMESSAGE_LISTENER_PATTERNS)

def _has_origin_check(content: str) -> bool:
    return any(p in content for p in _ORIGIN_CHECK_PATTERNS)

# Patterns that indicate event.data is only used in strict equality comparisons
# (e.g. Vue Router / Inertia.js token resolver: `i === G && s === n`)
# In this pattern event.data is deserialized into typed tokens compared by ===,
# not fed into any DOM sink - it's a callback resolver, not an XSS vector.
_POSTMESSAGE_EQUALITY_ONLY_PATTERNS = [
    "event.data ===",
    "event.data!==",
    "e.data ===",
    "e.data!==",
    "data.type ===",
    "data.type!==",
]

_POSTMESSAGE_DOM_ADJACENCY = [
    "innerHTML", "outerHTML", "document.write", "eval(",
    "Function(", "insertAdjacentHTML", ".html(",
    "dangerouslySetInnerHTML", "v-html",
]

def _is_postmessage_equality_resolver(content: str) -> bool:
    """
    Returns True when event.data only appears inside === comparisons with no
    adjacent DOM sink. This is the Vue Router / Inertia.js token-gated callback
    resolver pattern - not an XSS vector.
    """
    has_equality = any(p in content for p in _POSTMESSAGE_EQUALITY_ONLY_PATTERNS)
    has_dom_sink = any(p in content for p in _POSTMESSAGE_DOM_ADJACENCY)
    return has_equality and not has_dom_sink


# ─── MAPPER ──────────────────────────────────────────────────────────────────

class XssMapper(BaseSurfaceMapper):
    category = AttackCategory.XSS

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        # Pre-build JS sink/source index keyed by JS URL for endpoint cross-ref
        js_sink_index: Dict[str, List[str]] = {}
        for js in result.js_files:
            if js.content:
                sinks = _find_strong_sinks(js.content)
                if sinks and js.url:
                    js_sink_index[js.url] = sinks

        # ── 1. REFLECTED XSS - query params ──────────────────────────────────
        for ep in result.endpoints:
            method = (ep.method or "GET").upper()
            path   = (ep.path or ep.url or "").lower()

            for qp in (ep.query_params or []):
                name   = (qp.get("name") or "").lower()
                if not name:
                    continue

                is_high   = name in _REFLECTED_HIGH_PARAMS
                is_medium = name in _REFLECTED_MEDIUM_PARAMS
                is_jsonp  = name in ("callback", "jsonp", "cb")

                evidence   = []
                confidence = ConfidenceLevel.LOW

                if is_jsonp:
                    evidence.append(f"JSONP callback param '{name}' - value echoed as function wrapper")
                    confidence  = ConfidenceLevel.HIGH
                    burp_notes  = _BURP_NOTES_REFLECTED_JSONP
                elif is_high:
                    evidence.append(f"High-signal reflection param '{name}' - commonly echoed in HTML response")
                    confidence  = ConfidenceLevel.MEDIUM
                    burp_notes  = _BURP_NOTES_REFLECTED
                elif is_medium:
                    evidence.append(f"Param '{name}' may appear in rendered response")
                    confidence  = ConfidenceLevel.LOW
                    burp_notes  = _BURP_NOTES_REFLECTED
                else:
                    # Any other query param - flag at LOW, sink in source JS bumps it
                    evidence.append(f"Query param '{name}' is a potential reflection point")
                    confidence  = ConfidenceLevel.LOW
                    burp_notes  = _BURP_NOTES_REFLECTED

                # Cross-reference with JS sinks from the same source file
                source_sinks = js_sink_index.get(ep.source_file or "", [])
                if source_sinks:
                    evidence.append(f"JS sinks in source file: {', '.join(source_sinks[:3])}")
                    if confidence == ConfidenceLevel.LOW:
                        confidence = ConfidenceLevel.MEDIUM
                    elif confidence == ConfidenceLevel.MEDIUM:
                        confidence = ConfidenceLevel.HIGH

                self._candidate(
                    endpoint     = ep,
                    surface_type = "Reflected XSS",
                    parameters   = [f"query:{name}"],
                    confidence   = confidence,
                    evidence     = evidence,
                    burp_notes   = burp_notes,
                )

            # ── 2. STORED XSS - POST/PUT/PATCH body fields ───────────────────
            if method in ("POST", "PUT", "PATCH"):
                for bf in (ep.body_fields or []):
                    name = (bf.get("name") or "").lower()
                    if not name:
                        continue

                    is_stored_high   = name in _STORED_HIGH_FIELDS
                    is_stored_medium = name in _STORED_MEDIUM_FIELDS

                    if not (is_stored_high or is_stored_medium):
                        continue  # skip fields that clearly aren't display-facing

                    confidence = ConfidenceLevel.HIGH if is_stored_high else ConfidenceLevel.MEDIUM
                    evidence   = [
                        f"Body field '{name}' on {method} {ep.url}",
                        "Field name implies content is stored and rendered for other users" if is_stored_high
                        else "Field name may be stored and displayed",
                    ]

                    auth_ctx = ep.auth_context or ""
                    if auth_ctx and auth_ctx.lower() not in ("", "none"):
                        evidence.append(f"Auth-gated submission increases stored XSS impact")

                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Stored XSS",
                        parameters   = [f"body:{name}"],
                        confidence   = confidence,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_STORED,
                    )

        # ── 3. DOM XSS - per JS file sink/source analysis ────────────────────
        for js in result.js_files:
            if not js.content:
                continue
            content = js.content

            strong_sinks = _find_strong_sinks(content)
            nav_sinks    = _find_nav_sinks(content)
            sources      = _find_sources(content)
            frameworks   = _is_framework_sink(content)

            all_sinks    = strong_sinks + nav_sinks

            ep_url = js.url or getattr(js, "source_page", "") or ""
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

            # ── postMessage XSS - runs on every JS file, independent of sinks ─
            if _has_postmessage_listener(content) and not _has_origin_check(content):
                pm_evidence = [
                    "postMessage listener found: addEventListener(\"message\") or .onmessage handler",
                    "No origin check detected (event.origin not present) - any origin can send messages",
                ]

                # Downgrade to LOW when this looks like a framework token resolver
                # (Vue Router / Inertia.js pattern: event.data only in === comparisons,
                # no DOM sinks adjacent - it's a callback dispatcher, not an XSS sink)
                if _is_postmessage_equality_resolver(content):
                    pm_evidence.append(
                        "event.data only appears in strict equality checks (=== comparisons) "
                        "with no adjacent DOM sink - pattern matches Vue Router / Inertia.js "
                        "token resolver, not a real XSS data flow"
                    )
                    pm_confidence = ConfidenceLevel.LOW
                elif strong_sinks:
                    pm_evidence.append(f"Strong DOM sinks in same file: {', '.join(strong_sinks[:4])}")
                    pm_evidence.append("Attacker can send arbitrary messages from evil.com to this handler")
                    pm_confidence = ConfidenceLevel.HIGH
                else:
                    pm_evidence.append("Attacker can send arbitrary messages from evil.com to this handler")
                    pm_confidence = ConfidenceLevel.MEDIUM

                self._candidate(
                    endpoint     = synthetic_ep,
                    surface_type = "DOM XSS via postMessage",
                    parameters   = [],
                    confidence   = pm_confidence,
                    evidence     = pm_evidence,
                    burp_notes   = _BURP_NOTES_POSTMESSAGE,
                )

            # Skip sink/source analysis if no sinks present
            if not all_sinks:
                continue

            if sources and strong_sinks:
                # Strong sink + user-controlled source = real DOM XSS surface
                evidence = [
                    f"DOM sinks: {', '.join(strong_sinks[:4])}",
                    f"User-controlled sources: {', '.join(sources[:3])}",
                    "Source-to-sink path present - manual trace required to confirm exploitability",
                ]
                fw_hits = [k for k, v in frameworks.items() if v]
                if fw_hits:
                    evidence.append(f"Framework-specific sinks: {', '.join(fw_hits)}")

                self._candidate(
                    endpoint     = synthetic_ep,
                    surface_type = "DOM XSS Surface",
                    parameters   = [],
                    confidence   = ConfidenceLevel.HIGH,
                    evidence     = evidence,
                    burp_notes   = _sink_burp_notes(strong_sinks, frameworks),
                )

            elif sources and nav_sinks:
                # Navigation sink + source = DOM open redirect / javascript: XSS
                evidence = [
                    f"Navigation sinks: {', '.join(nav_sinks[:3])}",
                    f"User-controlled sources: {', '.join(sources[:3])}",
                    "javascript: URI injection may be possible if href/src is set from user input",
                ]
                self._candidate(
                    endpoint     = synthetic_ep,
                    surface_type = "DOM XSS via Navigation Sink",
                    parameters   = [],
                    confidence   = ConfidenceLevel.MEDIUM,
                    evidence     = evidence,
                    burp_notes   = _BURP_NOTES_NAV_SINK,
                )

            elif strong_sinks:
                # Sink only - no confirmed user-controlled source in this file
                fw_hits = [k for k, v in frameworks.items() if v]
                evidence_lines = [
                    f"DOM sinks: {', '.join(strong_sinks[:4])} - no user-controlled source detected in same file",
                ]
                if fw_hits:
                    evidence_lines.append(f"Framework sinks detected: {', '.join(fw_hits)} - review usage carefully")

                self._candidate(
                    endpoint     = synthetic_ep,
                    surface_type = "DOM Sink",
                    parameters   = [],
                    confidence   = ConfidenceLevel.LOW,
                    evidence     = evidence_lines,
                    burp_notes   = _BURP_NOTES_DOM_SINK,
                )

        return self._results
