"""
CorsMapper - CORS misconfiguration surface candidate identification.
Pure static analysis of already-collected endpoint data. Zero HTTP requests.

Detection cases (all real-world, all exploitable):
  1. Wildcard ACAO + credentials: Access-Control-Allow-Origin: * with
     Access-Control-Allow-Credentials: true  — browsers block it but many
     frameworks or proxies produce this by accident (critical signal).
  2. Origin reflection: server echoes the client's Origin header value back
     in ACAO — any origin can read the response.
  3. Null origin trust: Access-Control-Allow-Origin: null — exploitable from
     sandboxed iframes on any domain.
  4. Subdomain wildcard: *.example.com pattern in ACAO — XSS on any subdomain
     escalates to cross-origin read on this endpoint.
  5. Missing Vary: Origin on a reflective endpoint — CDN/proxy cache may
     serve a permissive ACAO response to a victim who sent a different origin.
  6. JS fetch/XHR with credentials: 'include' + user-controlled URL — enables
     SSRF-CORS chain or forces credentialed cross-origin request.
  7. Pre-flight misconfig: Access-Control-Allow-Methods includes unsafe verbs
     (PUT/DELETE/PATCH) with permissive origin policy.
"""
import re
from typing import List, Dict, Set

from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint

# --- Response header name constants (lowercased for comparison) ---

_HDR_ACAO  = "access-control-allow-origin"
_HDR_ACAC  = "access-control-allow-credentials"
_HDR_ACAM  = "access-control-allow-methods"
_HDR_ACAH  = "access-control-allow-headers"
_HDR_VARY  = "vary"

# CORS-unsafe HTTP methods - a permissive policy + these verbs = write CORS
_UNSAFE_METHODS = {"PUT", "DELETE", "PATCH"}

# Signals in JS content that a fetch/XHR carries credentials
_CREDENTIALS_INCLUDE_RE = re.compile(
    r"credentials\s*[:=]\s*['\"]include['\"]",
    re.I,
)
_XHR_CREDS_RE = re.compile(
    r"\.withCredentials\s*=\s*true",
    re.I,
)

# Patterns that suggest a URL is user-controlled (tainted CORS + credentials)
_USER_CONTROLLED_URL_SOURCES = [
    "location.href", "location.search", "location.hash",
    "searchParams.get(", "URLSearchParams",
    "window.name",
    "document.referrer",
    "postMessage",
    "params.",             # path/route params in React Router / Next / SvelteKit
    "$route.query",        # Vue Router
    "$page.url",           # SvelteKit
    "router.query",        # Next.js
    "req.query",           # Express server-side - still counts if in SSR bundle
    "req.params",
]

# --- Burp notes ---

_BURP_NOTES_WILDCARD_CREDS = (
    "CRITICAL: Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. "
    "Modern browsers block this combination (spec violation), but verify the server behaviour: "
    "1) Send a cross-origin preflight with a specific Origin header and check what ACAO comes back. "
    "2) If the server reflects the origin instead of returning *, a real credentialed CORS bypass exists. "
    "In Burp: Repeater -> add 'Origin: https://evil.com' -> check ACAO in response."
)

_BURP_NOTES_REFLECTION = (
    "Origin reflection detected: server echoes back whatever Origin header the client sends. "
    "This allows any website to read the authenticated response. "
    "To confirm: 1) In Burp Repeater, add 'Origin: https://evil.com'. "
    "2) If ACAO: https://evil.com comes back alongside ACAC: true, it's exploitable. "
    "3) Build a PoC page that fetches this endpoint with credentials and reads the body. "
    "Check Vary: Origin header - if missing, this response may be cached and served to others."
)

_BURP_NOTES_NULL_ORIGIN = (
    "Null origin trust: Access-Control-Allow-Origin: null is exploitable from sandboxed iframes. "
    "PoC: create an iframe with sandbox attribute (no allow-same-origin), "
    "fetch the target endpoint from inside it with credentials, read the response. "
    "Any origin - not just same-domain - can do this."
)

_BURP_NOTES_SUBDOMAIN = (
    "Subdomain wildcard in ACAO (e.g. https://*.example.com). "
    "If XSS exists on ANY subdomain of example.com, it can make credentialed cross-origin "
    "requests to this endpoint and read the response. "
    "Enumerate subdomains and look for XSS / open redirects that expand this scope."
)

_BURP_NOTES_VARY = (
    "Origin reflection without Vary: Origin header. "
    "A CDN or caching proxy may store a response with a permissive ACAO and serve it to other users. "
    "Test: send two requests with different Origin values and check if responses are cached together. "
    "Impact: victim's browser may receive an ACAO response allowing attacker's origin."
)

_BURP_NOTES_UNSAFE_METHODS = (
    "Permissive CORS + unsafe HTTP methods (PUT/DELETE/PATCH) allowed in ACAM. "
    "An attacker can make a credentialed cross-origin PUT/DELETE/PATCH request "
    "if they can control the origin and the ACAO is reflective or null. "
    "Combine with IDOR: substitute another user's resource ID in the path."
)

_BURP_NOTES_JS_CREDS = (
    "JS fetch/XHR with credentials:include (or withCredentials=true) found near user-controlled URL source. "
    "If the fetch URL can be influenced by an attacker (via postMessage, URL params, window.name), "
    "this becomes a credentialed cross-origin SSRF: the browser sends the victim's cookies "
    "to an attacker-chosen endpoint. "
    "Trace the URL source to confirm taint. Test by injecting a URL to a collaborator server."
)

_BURP_NOTES_CREDS_INCLUDE = (
    "JS fetch/XHR sends credentialed cross-origin request. "
    "Verify: 1) Does the target server have permissive CORS? "
    "2) If yes, a malicious page can read the response including auth cookies. "
    "Check the request's ACAO response header in Burp."
)

# --- Heuristics ---

def _acao_value(headers: Dict) -> str:
    """Return the Access-Control-Allow-Origin header value, or ''."""
    if not headers:
        return ""
    for k, v in headers.items():
        if k.lower() == _HDR_ACAO:
            return (v or "").strip()
    return ""


def _acac_true(headers: Dict) -> bool:
    """Return True if Access-Control-Allow-Credentials: true is set."""
    if not headers:
        return False
    for k, v in headers.items():
        if k.lower() == _HDR_ACAC:
            return (v or "").strip().lower() == "true"
    return False


def _vary_origin(headers: Dict) -> bool:
    """Return True if 'Vary: Origin' (or 'Vary: *') is present."""
    if not headers:
        return False
    for k, v in headers.items():
        if k.lower() == _HDR_VARY:
            parts = [p.strip().lower() for p in (v or "").split(",")]
            return "origin" in parts or "*" in parts
    return False


def _acam_unsafe(headers: Dict) -> List[str]:
    """Return list of unsafe methods declared in Access-Control-Allow-Methods."""
    if not headers:
        return []
    for k, v in headers.items():
        if k.lower() == _HDR_ACAM:
            methods = [m.strip().upper() for m in (v or "").split(",")]
            return [m for m in methods if m in _UNSAFE_METHODS]
    return []


def _is_subdomain_wildcard(acao: str) -> bool:
    """Return True if ACAO looks like *.domain.tld (subdomain wildcard)."""
    return acao.startswith("*.")


def _is_reflective_marker(acao: str) -> bool:
    """
    Return True when the ACAO value is clearly a verbatim reflection of an
    origin (http(s)://something). We can't confirm it's truly reflective
    without sending a request, but seeing a specific origin value in a
    response header with ACAC: true is a HIGH signal.
    """
    return bool(re.match(r'^https?://', acao, re.I)) and acao != "*"


def _has_user_controlled_url(content: str) -> bool:
    return any(src in content for src in _USER_CONTROLLED_URL_SOURCES)


# --- Mapper ---

class CorsMapper(BaseSurfaceMapper):
    category = AttackCategory.CORS

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        # Phase 1: endpoint-level header analysis
        seen: Set[str] = set()

        for ep in result.endpoints:
            resp_headers: Dict = getattr(ep, "response_headers", None) or {}
            req_headers:  Dict = ep.request_headers or {}

            # Merge response headers from any source: try both attribute names
            # (different collectors store them differently)
            if not resp_headers:
                resp_headers = getattr(ep, "headers", None) or {}

            acao = _acao_value(resp_headers)
            if not acao:
                has_origin_req = any(k.lower() == "origin" for k in req_headers)
                if not has_origin_req:
                    continue
                continue

            acac    = _acac_true(resp_headers)
            vary_ok = _vary_origin(resp_headers)
            unsafe  = _acam_unsafe(resp_headers)
            url     = ep.url
            method  = (ep.method or "GET").upper()
            auth_ctx = ep.auth_context or ""

            dedup_base = f"{method}:{url}"

            # Case 1: Wildcard + credentials (spec violation / framework bug)
            if acao == "*" and acac:
                key = f"cors_wildcard_creds:{dedup_base}"
                if key not in seen:
                    seen.add(key)
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "CORS: Wildcard + Credentials",
                        parameters   = ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"],
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = [
                            f"Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true at {url}",
                            "Browsers block this combination per spec, but the server misconfiguration "
                            "often means the server will also reflect any explicit Origin - verify manually.",
                            "If server reflects the requesting Origin, ANY site can read credentialed responses.",
                        ] + ([f"Auth context: {auth_ctx}"] if auth_ctx else []),
                        burp_notes   = _BURP_NOTES_WILDCARD_CREDS,
                        auth_context = auth_ctx,
                    )

            # Case 2: Origin reflection (specific origin in ACAO + credentials)
            elif _is_reflective_marker(acao) and acac:
                key = f"cors_reflection:{dedup_base}"
                if key not in seen:
                    seen.add(key)
                    reflective_evidence = [
                        f"Access-Control-Allow-Origin: {acao} (specific origin) with "
                        f"Access-Control-Allow-Credentials: true at {url}",
                        "A specific origin in ACAO often means the server reflects the "
                        "Origin request header - high probability of origin reflection.",
                    ]
                    if not vary_ok:
                        reflective_evidence.append(
                            "Vary: Origin header is MISSING - responses may be cached "
                            "with this permissive ACAO and served to other users (cache poisoning risk)"
                        )
                    if auth_ctx:
                        reflective_evidence.append(f"Auth context: {auth_ctx} (auth-gated resource)")
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "CORS: Origin Reflection",
                        parameters   = ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"],
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = reflective_evidence,
                        burp_notes   = _BURP_NOTES_REFLECTION,
                        auth_context = auth_ctx,
                    )

            # Case 3: Null origin trust
            elif acao.lower() == "null":
                key = f"cors_null:{dedup_base}"
                if key not in seen:
                    seen.add(key)
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "CORS: Null Origin Trust",
                        parameters   = ["Access-Control-Allow-Origin"],
                        confidence   = ConfidenceLevel.HIGH if acac else ConfidenceLevel.MEDIUM,
                        evidence     = [
                            f"Access-Control-Allow-Origin: null at {url}",
                            "Exploitable from sandboxed iframes - any attacker-controlled page "
                            "can send a credentialed request with Origin: null.",
                            "ACAC: true" if acac else "No ACAC header - check if cookies/auth are still sent.",
                        ] + ([f"Auth context: {auth_ctx}"] if auth_ctx else []),
                        burp_notes   = _BURP_NOTES_NULL_ORIGIN,
                        auth_context = auth_ctx,
                    )

            # Case 4: Subdomain wildcard (*.example.com)
            elif _is_subdomain_wildcard(acao):
                key = f"cors_subdomain:{dedup_base}:{acao}"
                if key not in seen:
                    seen.add(key)
                    subdomain_conf = ConfidenceLevel.HIGH if acac else ConfidenceLevel.MEDIUM
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "CORS: Subdomain Wildcard",
                        parameters   = ["Access-Control-Allow-Origin"],
                        confidence   = subdomain_conf,
                        evidence     = [
                            f"Access-Control-Allow-Origin: {acao} (subdomain wildcard) at {url}",
                            "XSS on any subdomain of the allowed domain can make credentialed "
                            "cross-origin requests to this endpoint.",
                            "ACAC: true - credentialed requests allowed" if acac else
                            "No ACAC: true - check if unauthenticated data is still sensitive.",
                        ] + ([f"Auth context: {auth_ctx}"] if auth_ctx else []),
                        burp_notes   = _BURP_NOTES_SUBDOMAIN,
                        auth_context = auth_ctx,
                    )

            # Case 5: Reflective ACAO without credentials but missing Vary
            elif _is_reflective_marker(acao) and not acac and not vary_ok:
                key = f"cors_vary:{dedup_base}"
                if key not in seen:
                    seen.add(key)
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "CORS: Missing Vary Header",
                        parameters   = ["Access-Control-Allow-Origin", "Vary"],
                        confidence   = ConfidenceLevel.LOW,
                        evidence     = [
                            f"Access-Control-Allow-Origin: {acao} without Vary: Origin at {url}",
                            "CDN/proxy may cache this permissive CORS response and serve "
                            "it to users with different origins.",
                        ],
                        burp_notes   = _BURP_NOTES_VARY,
                        auth_context = auth_ctx,
                    )

            # Case 6: Unsafe methods in ACAM with permissive ACAO
            if unsafe and acao in ("*", "null") or (unsafe and _is_reflective_marker(acao) and acac):
                key = f"cors_methods:{dedup_base}:{','.join(sorted(unsafe))}"
                if key not in seen:
                    seen.add(key)
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "CORS: Unsafe Methods Allowed",
                        parameters   = ["Access-Control-Allow-Methods"] + (
                            ["Access-Control-Allow-Credentials"] if acac else []
                        ),
                        confidence   = ConfidenceLevel.HIGH if acac else ConfidenceLevel.MEDIUM,
                        evidence     = [
                            f"Access-Control-Allow-Methods includes {', '.join(unsafe)} at {url}",
                            f"Combined with Access-Control-Allow-Origin: {acao}",
                            "Cross-origin write operations (state mutation) may be possible from any origin.",
                        ] + ([f"Auth context: {auth_ctx}"] if auth_ctx else []),
                        burp_notes   = _BURP_NOTES_UNSAFE_METHODS,
                        auth_context = auth_ctx,
                    )

        # Phase 2: JS file analysis for credentialed fetch patterns
        seen_js: Set[str] = set()

        for js in (result.js_files or []):
            content = js.content or ""
            if not content:
                continue

            has_creds_include = bool(_CREDENTIALS_INCLUDE_RE.search(content))
            has_xhr_creds     = bool(_XHR_CREDS_RE.search(content))
            if not (has_creds_include or has_xhr_creds):
                continue

            has_user_url = _has_user_controlled_url(content)
            js_url       = js.url or "unknown"

            key = f"js_creds:{js_url}"
            if key in seen_js:
                continue
            seen_js.add(key)

            creds_signal = (
                "credentials: 'include'" if has_creds_include else "withCredentials = true"
            )

            if has_user_url:
                from ...storage.models import Endpoint as _Endpoint
                synthetic_ep = _Endpoint(
                    url=js_url,
                    path="",
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
                    source_type="static",
                )
                self._candidate(
                    endpoint     = synthetic_ep,
                    surface_type = "CORS: Credentialed Fetch + User-Controlled URL",
                    parameters   = [creds_signal],
                    confidence   = ConfidenceLevel.HIGH,
                    evidence     = [
                        f"JS file {js_url} makes a credentialed cross-origin request ({creds_signal}) "
                        "and has a user-controlled URL source nearby.",
                        "If the fetch URL can be influenced by an attacker (via URL params, postMessage, etc.), "
                        "the victim's cookies will be sent to an attacker-chosen endpoint (CORS-SSRF chain).",
                        "Taint sources found: " + ", ".join(
                            s for s in _USER_CONTROLLED_URL_SOURCES if s in content
                        ),
                    ],
                    burp_notes   = _BURP_NOTES_JS_CREDS,
                    auth_context = "",
                )
            else:
                from ...storage.models import Endpoint as _Endpoint
                synthetic_ep = _Endpoint(
                    url=js_url,
                    path="",
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
                    source_type="static",
                )
                self._candidate(
                    endpoint     = synthetic_ep,
                    surface_type = "CORS: Credentialed Cross-Origin Fetch",
                    parameters   = [creds_signal],
                    confidence   = ConfidenceLevel.LOW,
                    evidence     = [
                        f"JS file {js_url} sends a credentialed cross-origin request ({creds_signal}).",
                        "Verify that the target server has a restrictive CORS policy. "
                        "If permissive ACAO is set on the target, any site can read the response.",
                    ],
                    burp_notes   = _BURP_NOTES_CREDS_INCLUDE,
                    auth_context = "",
                )

        return self._results
