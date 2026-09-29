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
import re
from typing import List, Set

from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint

# ── Param name tiers ─────────────────────────────────────────────────────────

# Direct, unambiguous redirect destinations — nearly always exploitable
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

# Secondary signals — commonly used for redirect, sometimes for other purposes
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

# Low-signal / noisy — only flag on auth paths or with supporting context
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

# Headers whose presence on an endpoint suggests redirect logic
_REDIRECT_RESPONSE_HEADERS = {
    "location",          # classic redirect — if it echoes input, exploitable
    "refresh",           # Refresh: 0; url=... — browser redirect
    "x-redirect-to",     # common custom header
    "x-redirect",
    "x-forwarded-to",    # sometimes used to carry redirect dest
}

# ── JS DOM-based redirect ─────────────────────────────────────────────────────

# Sinks that perform a client-side navigation
_JS_REDIRECT_SINKS = [
    "window.location =", "window.location.href =",
    "window.location.assign(", "window.location.replace(",
    "document.location =", "document.location.href =",
    "location.href =", "location.replace(", "location.assign(",
    "location =",
]

# Sources that indicate user-controlled input reaching the sink
_JS_REDIRECT_SOURCES = [
    "location.search", "location.hash",
    "URLSearchParams", "searchParams.get(",
    "getParameter(", "getQueryParam(",
    "params.", "query.", "router.query",
    "$route.query", "$page.url",
    "req.query", "req.body",
    "e.data", "event.data",          # postMessage
    "document.location",
]

# Framework-specific router redirect patterns (with user-input sources nearby)
_FRAMEWORK_ROUTER_SINKS = [
    # React Router
    "<Redirect to={", "history.push(", "history.replace(",
    # Vue Router
    "this.$router.push(", "this.$router.replace(", "router.push(", "router.replace(",
    # Next.js
    "Router.push(", "router.replace(",
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
    "Payloads to try (in order of escalation): "
    "1) https://evil.com — plain absolute URL. "
    "2) //evil.com — protocol-relative (bypasses scheme checks). "
    "3) /\\evil.com — backslash trick (IIS / some parsers). "
    "4) https://legit.com.evil.com — subdomain confusion. "
    "5) https:%2F%2Fevil.com — URL-encoded slash. "
    "6) https:%252F%252Fevil.com — double URL-encoded. "
    "7) javascript:alert(1) — may chain to XSS if unsanitised. "
    "Check response: Location header, meta refresh, or JS redirect. "
    "Burp: right-click → Engagement tools → Find references to confirm param usage."
)

_BURP_NOTES_AUTH = (
    "CRITICAL: open redirect param on auth / OAuth endpoint. "
    "This is the classic authorization-code-theft vector. "
    "Attack chains: "
    "• OAuth code theft: craft /oauth/authorize?redirect_uri=https://evil.com, "
    "  share the URL, victim authorizes, code delivered to attacker. "
    "• Login phishing: /login?next=https://phish.evil.com — appears legit. "
    "• Token exfiltration: if access_token is appended to redirect URL. "
    "Payloads: //evil.com, https://legit.com.evil.com, /\\evil.com. "
    "Check OAuth RFC compliance: redirect_uri must be exact match or pre-registered. "
    "Burp: Intercept the auth flow, replace redirect_uri / next with attacker URL."
)

_BURP_NOTES_HEADER = (
    "Response header indicates server-side redirect logic. "
    "If the Location / Refresh / X-Redirect-To value mirrors a request param, "
    "the endpoint is an open redirect. "
    "Test: add ?redirect=https://evil.com, ?url=https://evil.com and check the response header. "
    "Also try: POST body with redirect param, Referer header reflection. "
    "If Refresh header: check 'Refresh: 0; url=<value>' — same exploitation as Location."
)

_BURP_NOTES_JS = (
    "DOM-based open redirect: JS sets window.location from user-controlled source. "
    "No server round-trip required — exploit happens entirely in the browser. "
    "Test in browser DevTools console: "
    "  location.hash = '#https://evil.com'; (if sink reads location.hash) "
    "  Or: ?next=https://evil.com  then observe navigation. "
    "For postMessage vector: window.postMessage('https://evil.com', '*') "
    "Check that the sink value reaches window.location without sanitisation. "
    "Burp DOM Invader: enable open redirect tracking canary and browse the app."
)

_BURP_NOTES_FRAMEWORK = (
    "Framework router redirect with user-controlled input. "
    "React Router / Vue Router / Next.js / Angular Router redirect functions "
    "called with query params or route data — potential client-side open redirect. "
    "Test: manipulate URL query params and observe if the SPA navigates to the supplied URL. "
    "For SPA redirects the browser URL changes without a server request — "
    "test with: ?next=https://evil.com, then check window.location after route change. "
    "If javascript: URIs are accepted: can chain to DOM XSS."
)

_BURP_NOTES_PATH = (
    "Open redirect candidate in path parameter. "
    "Path params carrying URLs are rare but often lack validation. "
    "Test: replace path segment with https://evil.com (URL-encoded: https%3A%2F%2Fevil.com). "
    "Try: /redirect/https%3A%2F%2Fevil.com, /to/https%3A%2F%2Fevil.com. "
    "Check if server follows with Location header or JS redirect."
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_auth_path(path: str) -> bool:
    p = path.lower()
    return any(sig in p for sig in _AUTH_PATH_SIGNALS)


def _param_confidence(name: str, path: str, is_body: bool = False) -> str:
    nl = name.lower()
    is_auth = _is_auth_path(path)

    if nl in _HIGH_REDIRECT_PARAMS:
        return ConfidenceLevel.HIGH if is_auth else ConfidenceLevel.MEDIUM
    if nl in _MEDIUM_REDIRECT_PARAMS:
        return ConfidenceLevel.HIGH if is_auth else ConfidenceLevel.MEDIUM
    if nl in _LOW_REDIRECT_PARAMS:
        return ConfidenceLevel.MEDIUM if is_auth else ConfidenceLevel.LOW
    return ConfidenceLevel.LOW


def _response_header_keys(ep: Endpoint) -> List[str]:
    """Return lower-cased response header names for this endpoint."""
    headers = (
        getattr(ep, "response_headers", None)
        or getattr(ep, "headers", None)
        or {}
    )
    if isinstance(headers, dict):
        return [k.lower() for k in headers]
    return []


def _synthetic_endpoint(url: str, path: str = "") -> Endpoint:
    from ...storage.models import Endpoint as _Ep
    return _Ep(
        url=url, path=path or url, method="GET", category="",
        source_file=url, line_number=0, confidence=0.5,
        query_params=[], path_params=[], body_fields=[],
        request_headers={}, auth_context="", source_type="static",
    )


# ── Mapper ────────────────────────────────────────────────────────────────────

class OpenRedirectMapper(BaseSurfaceMapper):
    category = AttackCategory.OPEN_REDIRECT

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        seen: Set[str] = set()

        # ── Phase 1: Endpoint parameter analysis ─────────────────────────────
        for ep in result.endpoints:
            method   = (ep.method or "GET").upper()
            path     = ep.path or ep.url or ""
            url      = ep.url or ""
            is_auth  = _is_auth_path(path)
            auth_ctx = ep.auth_context or ""

            # ── Query params ─────────────────────────────────────────────────
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name not in _ALL_REDIRECT_PARAMS:
                    continue
                # Suppress pure low-signal on non-auth endpoints
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

            # ── Body fields ──────────────────────────────────────────────────
            if method in ("POST", "PUT", "PATCH"):
                for bf in (ep.body_fields or []):
                    name = (bf.get("name") or "").lower()
                    if name not in (_HIGH_REDIRECT_PARAMS | _MEDIUM_REDIRECT_PARAMS):
                        continue

                    key = f"or_body:{method}:{url}:{name}"
                    if key in seen:
                        continue
                    seen.add(key)

                    # POST body redirect params on auth paths = HIGH
                    conf  = ConfidenceLevel.HIGH if is_auth else _param_confidence(name, path, is_body=True)
                    notes = _BURP_NOTES_AUTH if is_auth else _BURP_NOTES_HIGH
                    ev    = [
                        f"Redirect-signal POST body field '{name}' on {url}",
                        "POST-based redirect params often bypass client-side validation "
                        "and URL-allowlist checks that only inspect the query string.",
                    ]
                    if is_auth:
                        ev.append(
                            "Auth endpoint — POST redirect is the classic login-flow abuse vector."
                        )
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

            # ── Path params ──────────────────────────────────────────────────
            for pp in (ep.path_params or []):
                name = (pp.get("name") or "").lower()
                if name not in _ALL_REDIRECT_PARAMS:
                    continue

                key = f"or_path:{method}:{url}:{name}"
                if key in seen:
                    continue
                seen.add(key)

                conf = ConfidenceLevel.HIGH if is_auth else ConfidenceLevel.MEDIUM
                ev   = [
                    f"Redirect-signal path param '{{{name}}}' in {url}",
                    "Path params carrying redirect destinations are unusual and often "
                    "skip the validation applied to query params.",
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

            # ── Response header signals ──────────────────────────────────────
            resp_hdrs = _response_header_keys(ep)
            redirect_hdrs = [h for h in resp_hdrs if h in _REDIRECT_RESPONSE_HEADERS]
            if redirect_hdrs:
                key = f"or_hdr:{method}:{url}"
                if key not in seen:
                    seen.add(key)
                    conf = ConfidenceLevel.HIGH if is_auth else ConfidenceLevel.MEDIUM
                    ev   = [
                        f"Redirect response header(s) on {url}: {', '.join(redirect_hdrs)}",
                        "The endpoint emits redirect-type headers. "
                        "If the header value is influenced by a request param, "
                        "this is a server-side open redirect.",
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

        # ── Phase 2: JS DOM-based redirect analysis ───────────────────────────
        for js in (result.js_files or []):
            content = js.content or ""
            if not content:
                continue

            js_url = js.url or getattr(js, "source_page", "") or ""

            sink_hits   = [s for s in _JS_REDIRECT_SINKS    if s in content]
            source_hits = [s for s in _JS_REDIRECT_SOURCES   if s in content]
            fw_hits     = [f for f in _FRAMEWORK_ROUTER_SINKS if f in content]

            # Signal 1: window.location sink + user-controlled source
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
                            "Source-to-sink data flow — user input reaches a location setter "
                            "without evident sanitisation.",
                        ],
                        burp_notes   = _BURP_NOTES_JS,
                        auth_context = "",
                    )

            # Signal 2: Framework router redirect with user-controlled input
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
                            "SPA router redirects called with query/route data — "
                            "may navigate to attacker-supplied URL.",
                        ],
                        burp_notes   = _BURP_NOTES_FRAMEWORK,
                        auth_context = "",
                    )

        return self._results
