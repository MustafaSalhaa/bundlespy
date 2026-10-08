"""
OpenRedirectMapper - dedicated open redirect attack surface identification.
Pure static analysis of already-collected endpoint data + JS file content.
Zero HTTP requests.

Open redirect lets an attacker craft a URL that the application trusts,
then redirects the user to an attacker-controlled destination. Classic impacts:
  - Phishing: legit domain in the address bar, victim lands on evil.com
  - OAuth abuse: redirect_uri manipulation to steal authorization codes
  - SSRF stepping stone: server-side open redirect + SSRF chain
  - XSS bridge: javascript: URI in redirect param (if unsanitised)

Detection strategy (five independent signals):
  1. Query / path / body param names that conventionally carry redirect targets
     (redirect_uri, next, return_to, etc.) — tiered HIGH / MEDIUM / LOW
  2. Auth-path amplifier — any redirect param on /login, /oauth, /callback etc.
     jumps confidence one tier regardless of param name
  3. Response header signals — Location: header that echoes a request param,
     or Refresh: / X-Redirect-To: headers present on endpoints
  4. JS DOM-based redirect — window.location sink fed by user-controlled source
     (location.search, postMessage, router query, etc.)
  5. Framework-specific router calls — React Router <Redirect to={...}>,
     Vue $router.push(param), Next.js router.push(query.*), etc.
"""
from typing import List, Set

from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ..evidence import Evidence, EvidenceType
from ...storage.models import ScanResult, Endpoint

# ── Param name tiers ──────────────────────────────────────────────────────────

_HIGH_REDIRECT_PARAMS: Set[str] = {
    "redirect", "redirect_uri", "redirect_url", "redirecturi", "redirecturl",
    "next", "next_url", "nexturl",
    "return_url", "returnurl", "return_to", "returnto",
    "after_login", "afterlogin", "post_login_redirect",
    "callback_url", "callbackurl",
    "target_url", "targeturl",
    "login_redirect", "loginredirect",
    "success_url", "successurl",
    "checkout_url", "checkouturl",
}

_MEDIUM_REDIRECT_PARAMS: Set[str] = {
    "return", "destination", "dest",
    "goto", "go",
    "continue", "cont",
    "back", "backurl", "back_url",
    "forward", "fwd",
    "after", "then",
    "follow",
    "navigate", "nav",
    "cancel_url", "cancelurl",
    "exit_url", "exiturl",
    "checkout_redirect",
    "oauth_redirect",
    "landing",
    "rurl", "redir",
}

# Low-signal / noisy — only flag on auth paths
_LOW_REDIRECT_PARAMS: Set[str] = {
    "to", "url", "uri",
    "ref", "referrer",
    "href", "link",
    "location", "loc",
    "page",
}

_ALL_REDIRECT_PARAMS = (
    _HIGH_REDIRECT_PARAMS | _MEDIUM_REDIRECT_PARAMS | _LOW_REDIRECT_PARAMS
)

# ── Auth-path amplifier ───────────────────────────────────────────────────────

_AUTH_PATH_SIGNALS = {
    "/login", "/logout", "/auth", "/oauth",
    "/callback", "/signin", "/signout",
    "/sso", "/authorize", "/token",
    "/verify", "/confirm", "/saml",
    "/connect", "/openid",
}

# ── Response header signals ───────────────────────────────────────────────────

_REDIRECT_RESPONSE_HEADERS = {
    "location",
    "refresh",
    "x-redirect-to",
    "x-redirect",
    "x-forwarded-to",
}

# ── JS DOM-based redirect ─────────────────────────────────────────────────────

_JS_REDIRECT_SINKS = [
    "window.location =", "window.location.href =",
    "window.location.assign(", "window.location.replace(",
    "document.location =", "document.location.href =",
    "location.href =", "location.replace(", "location.assign(",
    "location =",
]

_JS_REDIRECT_SOURCES = [
    "location.search", "location.hash",
    "URLSearchParams", "searchParams.get(",
    "getParameter(", "getQueryParam(",
    "params.", "query.", "router.query",
    "$route.query", "$page.url",
    "req.query", "req.body",
    "e.data", "event.data",
    "document.location",
]

_FRAMEWORK_ROUTER_SINKS = [
    # React Router
    "<Redirect to={", "history.push(", "history.replace(",
    # Vue Router
    "this.$router.push(", "this.$router.replace(", "router.push(", "router.replace(",
    # Next.js
    "Router.push(",
    # Angular
    "this.router.navigate(", "this.router.navigateByUrl(",
    # Nuxt
    "navigateTo(", "useRouter().push(",
    # SvelteKit
    "goto(", "redirect(",
]

# ── Burp notes ────────────────────────────────────────────────────────────────

_BURP_NOTES_HIGH = (
    "Open redirect candidate — high signal param. "
    "Payloads to try (escalating): "
    "1) https://evil.com  2) //evil.com  3) /\\evil.com  "
    "4) https://legit.com.evil.com  5) https:%2F%2Fevil.com  "
    "6) https:%252F%252Fevil.com (double-encoded)  7) javascript:alert(1). "
    "Check response for Location header, meta refresh, or JS redirect. "
    "Burp: right-click → Engagement tools → Find references."
)

_BURP_NOTES_AUTH = (
    "CRITICAL: open redirect param on auth / OAuth endpoint. "
    "Classic authorization-code-theft vector. "
    "• OAuth code theft: /oauth/authorize?redirect_uri=https://evil.com — victim authorizes, code to attacker. "
    "• Login phishing: /login?next=https://phish.evil.com. "
    "• Token exfiltration: access_token appended to redirect URL. "
    "Payloads: //evil.com, https://legit.com.evil.com, /\\evil.com. "
    "Burp: intercept auth flow, replace redirect_uri / next with attacker URL."
)

_BURP_NOTES_HEADER = (
    "Response header indicates server-side redirect logic. "
    "If Location / Refresh / X-Redirect-To value mirrors a request param, endpoint is open redirect. "
    "Test: add ?redirect=https://evil.com, ?url=https://evil.com — check response header. "
    "Also try POST body redirect param and Referer header reflection."
)

_BURP_NOTES_JS = (
    "DOM-based open redirect: JS sets window.location from user-controlled source. "
    "No server round-trip — exploit is entirely client-side. "
    "Test in DevTools: location.hash = '#https://evil.com' or ?next=https://evil.com. "
    "postMessage vector: window.postMessage('https://evil.com', '*'). "
    "Burp DOM Invader: enable open redirect tracking canary."
)

_BURP_NOTES_FRAMEWORK = (
    "Framework router redirect with user-controlled input. "
    "React Router / Vue Router / Next.js / Angular / Nuxt / SvelteKit router called with query/route data. "
    "Test: manipulate URL query params, check if SPA navigates to supplied URL. "
    "Try: ?next=https://evil.com — observe window.location after route change. "
    "javascript: URIs accepted here chain to DOM XSS."
)

_BURP_NOTES_PATH = (
    "Open redirect in path parameter — path params carrying URLs often skip validation. "
    "Test: replace path segment with https%3A%2F%2Fevil.com (URL-encoded). "
    "Try: /redirect/https%3A%2F%2Fevil.com, /to/https%3A%2F%2Fevil.com. "
    "Check server response for Location header or JS redirect."
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_auth_path(path: str) -> bool:
    p = path.lower()
    return any(sig in p for sig in _AUTH_PATH_SIGNALS)


def _param_confidence(name: str, path: str, is_body: bool = False) -> str:
    nl      = name.lower()
    is_auth = _is_auth_path(path)

    if nl in _HIGH_REDIRECT_PARAMS:
        return ConfidenceLevel.HIGH if is_auth else ConfidenceLevel.MEDIUM
    if nl in _MEDIUM_REDIRECT_PARAMS:
        return ConfidenceLevel.HIGH if is_auth else ConfidenceLevel.MEDIUM
    if nl in _LOW_REDIRECT_PARAMS:
        return ConfidenceLevel.MEDIUM if is_auth else ConfidenceLevel.LOW
    return ConfidenceLevel.LOW


def _response_header_keys(ep: Endpoint) -> List[str]:
    headers = (
        getattr(ep, "response_headers", None)
        or getattr(ep, "headers", None)
        or {}
    )
    if isinstance(headers, dict):
        return [k.lower() for k in headers]
    return []


def _synthetic_endpoint(url: str) -> Endpoint:
    from ...storage.models import Endpoint as _Ep
    return _Ep(
        url=url, path=url, method="GET", category="",
        source_file=url, line_number=0, confidence=0.5,
        query_params=[], path_params=[], body_fields=[],
        request_headers={}, auth_context="", source_type="static",
    )


# ── Mapper ────────────────────────────────────────────────────────────────────

class OpenRedirectMapper(BaseSurfaceMapper):
    category = AttackCategory.OPEN_REDIRECT

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        seen: Set[str] = set()

        # ── Phase 1: Endpoint parameter analysis ──────────────────────────────
        for ep in result.endpoints:
            method   = (ep.method or "GET").upper()
            path     = ep.path or ep.url or ""
            url      = ep.url or ""
            is_auth  = _is_auth_path(path)
            auth_ctx = ep.auth_context or ""

            # Query params
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name not in _ALL_REDIRECT_PARAMS:
                    continue
                if name in _LOW_REDIRECT_PARAMS and not is_auth:
                    continue

                key = f"or_query:{method}:{url}:{name}"
                if key in seen:
                    continue
                seen.add(key)

                conf  = _param_confidence(name, path)
                notes = _BURP_NOTES_AUTH if is_auth else _BURP_NOTES_HIGH
                ev    = [f"Redirect-signal query param '{name}' on {url}"]
                if is_auth:
                    ev.append(
                        "Auth / OAuth path — redirect param here is a critical attack surface. "
                        "Classic vector for authorization-code theft and login phishing."
                    )
                if auth_ctx and auth_ctx.lower() not in ("", "none"):
                    ev.append(f"Auth context: {auth_ctx}")

                self._candidate(
                    endpoint     = ep,
                    surface_type = "Open Redirect (Query Param)",
                    parameters   = [f"query:{name}"],
                    confidence   = conf,
                    evidence     = ev,
                    burp_notes   = notes,
                    auth_context = auth_ctx,
                )

                or_ev = [
                    Evidence(
                        evidence_type = EvidenceType.PARAMETER_SEMANTIC,
                        source        = "static",
                        asset         = url,
                        context       = f"Redirect-signal query param '{name}'",
                        details       = f"Param name '{name}' commonly carries a redirect destination",
                    ),
                ]
                if is_auth:
                    or_ev.append(Evidence(
                        evidence_type = EvidenceType.METADATA,
                        source        = "static",
                        asset         = url,
                        context       = "Redirect param on auth/OAuth path",
                        details       = "Auth path amplifier - classic authorization-code theft vector",
                    ))
                if auth_ctx and auth_ctx.lower() not in ("", "none"):
                    or_ev.append(Evidence(
                        evidence_type = EvidenceType.METADATA,
                        source        = "static",
                        asset         = url,
                        context       = f"Auth context: {auth_ctx}",
                        details       = auth_ctx,
                    ))
                self._emit_evidence(
                    evidence     = or_ev,
                    surface_type = "Open Redirect (Query Param)",
                    endpoint     = url,
                    method       = method,
                    parameter    = f"query:{name}",
                    notes        = notes,
                )

            # Body fields (POST/PUT/PATCH)
            if method in ("POST", "PUT", "PATCH"):
                for bf in (ep.body_fields or []):
                    name = (bf.get("name") or "").lower()
                    if name not in (_HIGH_REDIRECT_PARAMS | _MEDIUM_REDIRECT_PARAMS):
                        continue

                    key = f"or_body:{method}:{url}:{name}"
                    if key in seen:
                        continue
                    seen.add(key)

                    conf  = ConfidenceLevel.HIGH if is_auth else _param_confidence(name, path, is_body=True)
                    notes = _BURP_NOTES_AUTH if is_auth else _BURP_NOTES_HIGH
                    ev    = [
                        f"Redirect-signal POST body field '{name}' on {url}",
                        "POST-based redirect params often bypass client-side validation "
                        "and URL-allowlist checks that only inspect the query string.",
                    ]
                    if is_auth:
                        ev.append("Auth endpoint — POST redirect is the classic login-flow abuse vector.")
                    if auth_ctx and auth_ctx.lower() not in ("", "none"):
                        ev.append(f"Auth context: {auth_ctx}")

                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Open Redirect (Body Param)",
                        parameters   = [f"body:{name}"],
                        confidence   = conf,
                        evidence     = ev,
                        burp_notes   = notes,
                        auth_context = auth_ctx,
                    )

                    or_body_ev = [
                        Evidence(
                            evidence_type = EvidenceType.PARAMETER_SEMANTIC,
                            source        = "static",
                            asset         = url,
                            context       = f"Redirect-signal POST body field '{name}'",
                            details       = f"Body param '{name}' commonly carries a redirect destination",
                        ),
                    ]
                    if is_auth:
                        or_body_ev.append(Evidence(
                            evidence_type = EvidenceType.METADATA,
                            source        = "static",
                            asset         = url,
                            context       = "Redirect body param on auth/OAuth path",
                            details       = "Auth path amplifier - POST redirect is the classic login-flow abuse vector",
                        ))
                    if auth_ctx and auth_ctx.lower() not in ("", "none"):
                        or_body_ev.append(Evidence(
                            evidence_type = EvidenceType.METADATA,
                            source        = "static",
                            asset         = url,
                            context       = f"Auth context: {auth_ctx}",
                            details       = auth_ctx,
                        ))
                    self._emit_evidence(
                        evidence     = or_body_ev,
                        surface_type = "Open Redirect (Body Param)",
                        endpoint     = url,
                        method       = method,
                        parameter    = f"body:{name}",
                        notes        = notes,
                    )

            # Path params
            for pp in (ep.path_params or []):
                name = (pp.get("name") or "").lower()
                if name not in _ALL_REDIRECT_PARAMS:
                    continue

                key = f"or_path_param:{method}:{url}:{name}"
                if key in seen:
                    continue
                seen.add(key)

                conf = ConfidenceLevel.HIGH if is_auth else ConfidenceLevel.MEDIUM
                ev   = [
                    f"Redirect-signal path param '{{{name}}}' in {url}",
                    "Path params carrying redirect destinations often skip the "
                    "validation applied to query params.",
                ]
                if is_auth:
                    ev.append("Auth path — elevated risk.")

                self._candidate(
                    endpoint     = ep,
                    surface_type = "Open Redirect (Path Param)",
                    parameters   = [f"path:{name}"],
                    confidence   = conf,
                    evidence     = ev,
                    burp_notes   = _BURP_NOTES_PATH,
                    auth_context = auth_ctx,
                )

                or_path_ev = [
                    Evidence(
                        evidence_type = EvidenceType.PARAMETER_SEMANTIC,
                        source        = "static",
                        asset         = url,
                        context       = f"Redirect-signal path param '{{{name}}}'",
                        details       = f"Path param '{name}' commonly carries a redirect destination",
                    ),
                ]
                if is_auth:
                    or_path_ev.append(Evidence(
                        evidence_type = EvidenceType.METADATA,
                        source        = "static",
                        asset         = url,
                        context       = "Redirect path param on auth path - elevated risk",
                        details       = "Auth path amplifier applied",
                    ))
                self._emit_evidence(
                    evidence     = or_path_ev,
                    surface_type = "Open Redirect (Path Param)",
                    endpoint     = url,
                    method       = method,
                    parameter    = f"path:{name}",
                    notes        = _BURP_NOTES_PATH,
                )

            # Response header signals
            resp_hdrs     = _response_header_keys(ep)
            redirect_hdrs = [h for h in resp_hdrs if h in _REDIRECT_RESPONSE_HEADERS]
            if redirect_hdrs:
                key = f"or_hdr:{method}:{url}"
                if key not in seen:
                    seen.add(key)
                    conf = ConfidenceLevel.HIGH if is_auth else ConfidenceLevel.MEDIUM
                    ev   = [
                        f"Redirect response header(s) present on {url}: {', '.join(redirect_hdrs)}",
                        "If the header value mirrors a request param this is a server-side open redirect.",
                    ]
                    if is_auth:
                        ev.append("Auth endpoint — redirect header here is critical.")

                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Open Redirect (Response Header)",
                        parameters   = redirect_hdrs,
                        confidence   = conf,
                        evidence     = ev,
                        burp_notes   = _BURP_NOTES_HEADER,
                        auth_context = auth_ctx,
                    )

                    or_hdr_ev = [
                        Evidence(
                            evidence_type = EvidenceType.METADATA,
                            source        = "static",
                            asset         = url,
                            context       = f"Redirect response header(s): {', '.join(redirect_hdrs)}",
                            details       = "Location/Refresh/X-Redirect-To header signals server-side redirect logic",
                        ),
                    ]
                    if is_auth:
                        or_hdr_ev.append(Evidence(
                            evidence_type = EvidenceType.METADATA,
                            source        = "static",
                            asset         = url,
                            context       = "Redirect header on auth endpoint - critical",
                            details       = "Auth path amplifier applied",
                        ))
                    self._emit_evidence(
                        evidence     = or_hdr_ev,
                        surface_type = "Open Redirect (Response Header)",
                        endpoint     = url,
                        method       = method,
                        parameter    = redirect_hdrs[0] if redirect_hdrs else "",
                        notes        = _BURP_NOTES_HEADER,
                    )

        # ── Phase 2: JS DOM-based redirect analysis ───────────────────────────
        for js in (result.js_files or []):
            content = js.content or ""
            if not content:
                continue

            js_url      = js.url or getattr(js, "source_page", "") or ""
            sink_hits   = [s for s in _JS_REDIRECT_SINKS    if s in content]
            source_hits = [s for s in _JS_REDIRECT_SOURCES   if s in content]
            fw_hits     = [f for f in _FRAMEWORK_ROUTER_SINKS if f in content]

            # window.location sink + user-controlled source
            if sink_hits and source_hits and js_url:
                key = f"or_dom:{js_url}"
                if key not in seen:
                    seen.add(key)
                    self._candidate(
                        endpoint     = _synthetic_endpoint(js_url),
                        surface_type = "Open Redirect (DOM-Based)",
                        parameters   = sink_hits[:3],
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = [
                            f"JS redirect sink(s) in {js_url}: {', '.join(sink_hits[:3])}",
                            f"User-controlled source(s): {', '.join(source_hits[:3])}",
                            "Source-to-sink flow — user input reaches a location setter "
                            "without evident sanitisation.",
                        ],
                        burp_notes   = _BURP_NOTES_JS,
                        auth_context = "",
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type = EvidenceType.STATIC_JS,
                                source        = "static",
                                asset         = js_url,
                                context       = "JS redirect sink(s)",
                                details       = ", ".join(sink_hits[:3]),
                            ),
                            Evidence(
                                evidence_type = EvidenceType.DOM,
                                source        = "static",
                                asset         = js_url,
                                context       = "User-controlled source feeding redirect sink",
                                details       = ", ".join(source_hits[:3]),
                            ),
                        ],
                        surface_type = "Open Redirect (DOM-Based)",
                        endpoint     = js_url,
                        method       = "GET",
                        parameter    = sink_hits[0] if sink_hits else "",
                        notes        = _BURP_NOTES_JS,
                    )

            # Framework router + user-controlled input
            if fw_hits and source_hits and js_url:
                key = f"or_fw:{js_url}"
                if key not in seen:
                    seen.add(key)
                    self._candidate(
                        endpoint     = _synthetic_endpoint(js_url),
                        surface_type = "Open Redirect (Framework Router)",
                        parameters   = fw_hits[:3],
                        confidence   = ConfidenceLevel.MEDIUM,
                        evidence     = [
                            f"Framework router redirect call(s) in {js_url}: {', '.join(fw_hits[:3])}",
                            f"User-controlled source(s) co-present: {', '.join(source_hits[:3])}",
                            "SPA router called with query/route data — "
                            "may navigate to attacker-supplied URL.",
                        ],
                        burp_notes   = _BURP_NOTES_FRAMEWORK,
                        auth_context = "",
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type = EvidenceType.STATIC_JS,
                                source        = "static",
                                asset         = js_url,
                                context       = "Framework router redirect call(s)",
                                details       = ", ".join(fw_hits[:3]),
                            ),
                            Evidence(
                                evidence_type = EvidenceType.DOM,
                                source        = "static",
                                asset         = js_url,
                                context       = "User-controlled source co-present with router call",
                                details       = ", ".join(source_hits[:3]),
                            ),
                        ],
                        surface_type = "Open Redirect (Framework Router)",
                        endpoint     = js_url,
                        method       = "GET",
                        parameter    = fw_hits[0] if fw_hits else "",
                        notes        = _BURP_NOTES_FRAMEWORK,
                    )

        return self._results
