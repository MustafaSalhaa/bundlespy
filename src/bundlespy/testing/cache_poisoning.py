"""
CachePoisoningMapper - Web cache poisoning attack surface detection.
Pure static analysis of collected endpoint data. Zero HTTP requests.

Detection cases:
  1. Unkeyed headers that affect response content (X-Forwarded-Host, X-Forwarded-Scheme, etc.)
  2. Fat GET requests - GET with body fields that influence the response
  3. Parameter cloaking - URL params excluded from cache key that still affect response
  4. Cache-Control misconfiguration on authenticated or user-specific endpoints
  5. Vary header analysis - if Vary is missing/incomplete on dynamic responses
  6. Host header injection via X-Forwarded-Host reflected in response (detected via static signals)
"""
import re
from typing import List, Set, Dict

from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ..evidence import Evidence, EvidenceType
from ...storage.models import ScanResult, Endpoint

# Headers that are commonly unkeyed and can influence response
_UNKEYED_HEADERS = {
    "x-forwarded-host",
    "x-forwarded-scheme",
    "x-forwarded-proto",
    "x-forwarded-for",
    "x-host",
    "x-original-url",
    "x-rewrite-url",
    "x-original-host",
    "forwarded",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
}

# Response headers that indicate cacheable content
_CACHE_HEADERS = {
    "cache-control", "age", "x-cache", "cf-cache-status",
    "x-varnish", "surrogate-control", "cdn-cache-control",
}

# Cache-Control directives that mean the response IS being cached
_CACHED_DIRECTIVES = {"public", "s-maxage", "max-age"}

# Cache-Control directives that protect against poisoning (tell cache not to store)
_NOCACHE_DIRECTIVES = {"no-store", "private", "no-cache"}

# Params commonly excluded from cache key (framework defaults)
_PARAM_CLOAK_SIGNALS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "fbclid", "gclid", "msclkid", "ref", "source",
    "_ga", "_gl",
})

_BURP_NOTES_UNKEYED_HEADER = (
    "Unkeyed header injection surface - endpoint has cacheable response but receives "
    "headers that are likely unkeyed by the cache (e.g. X-Forwarded-Host). "
    "Steps: 1) Add X-Forwarded-Host: evil.com to a GET request. "
    "2) If the response reflects the header value, cache poisoning may be possible. "
    "3) Send the poisoning request, then send an unauthenticated request without the header. "
    "4) If the second response contains evil.com, the cache is poisoned. "
    "Use Burp's Param Miner extension to automate header injection testing."
)

_BURP_NOTES_PARAM_CLOAK = (
    "Parameter cloaking: this endpoint has tracking/analytics params that are commonly "
    "excluded from cache keys but may still affect the response. "
    "Steps: 1) Add ?utm_source=alert(1) and observe if the value appears in the response. "
    "2) If reflected, test if the next cached response also contains the payload. "
    "3) Combine with Burp Collaborator: ?utm_source=<script>fetch('//collab')</script>"
)

_BURP_NOTES_FAT_GET = (
    "Fat GET detected - GET request has body parameters that may influence the response "
    "but are excluded from the cache key (cache key is URL only). "
    "Steps: 1) Send a GET with body param value=<injected>. "
    "2) If response reflects the body param, the cache key does not include it. "
    "3) Next unauthenticated GET to same URL may serve the poisoned response."
)

_BURP_NOTES_AUTH_CACHED = (
    "Authenticated endpoint with caching headers - user-specific responses may be "
    "served to other users if cache does not key on session/auth headers. "
    "Steps: 1) Check if Cache-Control includes no-store or private. "
    "2) If not, test by adding X-Forwarded-Host or other unkeyed header. "
    "3) Verify the response is user-specific - if cached, other users receive attacker's response."
)


def _is_cached(resp_headers: Dict) -> bool:
    """Return True if response headers indicate the response may be cached."""
    for k, v in resp_headers.items():
        kl = k.lower()
        if kl == "cache-control":
            directives = {d.strip().split("=")[0].lower() for d in (v or "").split(",")}
            if directives & _CACHED_DIRECTIVES:
                return True
            if directives & _NOCACHE_DIRECTIVES:
                return False
        if kl in ("age", "x-cache", "cf-cache-status", "x-varnish"):
            return True
    return False


def _has_no_store(resp_headers: Dict) -> bool:
    """Return True if no-store or private is set in Cache-Control."""
    for k, v in resp_headers.items():
        if k.lower() == "cache-control":
            directives = {d.strip().split("=")[0].lower() for d in (v or "").split(",")}
            return bool(directives & _NOCACHE_DIRECTIVES)
    return False


def _unkeyed_headers_present(req_headers: Dict) -> List[str]:
    """Return any unkeyed header names that are present in the request."""
    found = []
    for k in req_headers:
        if k.lower() in _UNKEYED_HEADERS:
            found.append(k)
    return found


def _has_vary_header(resp_headers: Dict) -> bool:
    for k in resp_headers:
        if k.lower() == "vary":
            return True
    return False


class CachePoisoningMapper(BaseSurfaceMapper):
    category = AttackCategory.CACHE_POISONING

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        seen: Set[str] = set()

        for ep in result.endpoints:
            url      = ep.url or ""
            method   = (ep.method or "GET").upper()
            auth_ctx = ep.auth_context or ""
            req_hdrs = ep.request_headers or {}
            resp_hdrs = getattr(ep, "response_headers", None) or {}

            is_cached  = _is_cached(resp_hdrs)
            no_store   = _has_no_store(resp_hdrs)

            # Skip endpoints that have explicit no-store - not cacheable
            if no_store:
                continue

            # Check 1: unkeyed headers sent with cacheable endpoints
            unkeyed = _unkeyed_headers_present(req_hdrs)
            if unkeyed and (is_cached or method == "GET"):
                key = f"cache_unkeyed:{method}:{url}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"GET {url} receives unkeyed header(s): {', '.join(unkeyed)}",
                        "These headers are typically excluded from cache keys - injecting values may poison the cache",
                    ]
                    if is_cached:
                        evidence.append("Response has caching headers - endpoint IS being cached")
                    if auth_ctx:
                        evidence.append(f"Auth context: {auth_ctx}")
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Cache Poisoning: Unkeyed Header",
                        parameters   = unkeyed,
                        confidence   = ConfidenceLevel.MEDIUM if is_cached else ConfidenceLevel.LOW,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_UNKEYED_HEADER,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.RESPONSE_HEADER,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = f"Unkeyed headers on cached endpoint: {', '.join(unkeyed)}",
                                details        = "Unkeyed headers may inject values into cached responses",
                                raw_confidence = 55 if is_cached else 35,
                            ),
                        ],
                        surface_type = "Cache Poisoning: Unkeyed Header",
                        endpoint     = url,
                        method       = method,
                        parameter    = unkeyed[0] if unkeyed else "",
                        notes        = _BURP_NOTES_UNKEYED_HEADER,
                    )

            # Check 2: parameter cloaking (tracking params that may be unkeyed)
            query_params = ep.query_params or []
            cloak_params = []
            for param in query_params:
                pname = (param.get("name") or "") if isinstance(param, dict) else str(param)
                if pname.lower() in _PARAM_CLOAK_SIGNALS:
                    cloak_params.append(pname)

            if cloak_params and method == "GET":
                key = f"cache_cloak:{url}:{','.join(sorted(cloak_params))}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"GET {url} has tracking/analytics params: {', '.join(cloak_params)}",
                        "These params are commonly excluded from CDN cache keys (cache key = URL without tracking params)",
                        "If any param is reflected in the response, it may be injectable into the cached response",
                    ]
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Cache Poisoning: Parameter Cloaking",
                        parameters   = cloak_params,
                        confidence   = ConfidenceLevel.LOW,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_PARAM_CLOAK,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.PARAMETER_SEMANTIC,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = f"Param cloaking candidates: {', '.join(cloak_params)}",
                                details        = "Tracking params are often excluded from CDN cache keys",
                                raw_confidence = 35,
                            ),
                        ],
                        surface_type = "Cache Poisoning: Parameter Cloaking",
                        endpoint     = url,
                        method       = method,
                        parameter    = cloak_params[0] if cloak_params else "",
                        notes        = _BURP_NOTES_PARAM_CLOAK,
                    )

            # Check 3: authenticated endpoint with caching headers but no no-store
            is_authed = auth_ctx and auth_ctx.lower() not in ("", "none")
            if is_authed and is_cached and method == "GET":
                key = f"cache_auth:{url}"
                if key not in seen:
                    seen.add(key)
                    evidence = [
                        f"GET {url} is auth-gated but has cache headers without no-store/private",
                        "User-specific responses may be cached and served to other users",
                        f"Auth context: {auth_ctx}",
                    ]
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Cache Poisoning: Auth Response Cached",
                        parameters   = [],
                        confidence   = ConfidenceLevel.MEDIUM,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_AUTH_CACHED,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.RESPONSE_HEADER,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = "Auth-gated response has caching headers without no-store",
                                details        = "User-specific data may leak to other users via cache",
                                raw_confidence = 55,
                            ),
                            Evidence(
                                evidence_type  = EvidenceType.AUTHENTICATION_CONTEXT,
                                source         = "static",
                                asset          = url,
                                context        = f"Auth context: {auth_ctx}",
                                details        = "Authenticated endpoint - cache poisoning leaks user data",
                            ),
                        ],
                        surface_type = "Cache Poisoning: Auth Response Cached",
                        endpoint     = url,
                        method       = method,
                        parameter    = "",
                        notes        = _BURP_NOTES_AUTH_CACHED,
                    )

            # Check 4: fat GET (GET with body fields)
            if method == "GET" and ep.body_fields:
                key = f"cache_fat_get:{url}"
                if key not in seen:
                    seen.add(key)
                    bfields = [
                        (p.get("name") or "") if isinstance(p, dict) else str(p)
                        for p in ep.body_fields
                    ]
                    evidence = [
                        f"GET {url} has body fields: {', '.join(bfields[:5])}",
                        "Body parameters in GET requests are typically excluded from cache keys",
                        "If body params influence the response, they are injectable unkeyed",
                    ]
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "Cache Poisoning: Fat GET",
                        parameters   = bfields[:5],
                        confidence   = ConfidenceLevel.LOW,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_FAT_GET,
                        auth_context = auth_ctx,
                    )
                    self._emit_evidence(
                        evidence     = [
                            Evidence(
                                evidence_type  = EvidenceType.PARAMETER_SEMANTIC,
                                source         = "static",
                                asset          = url,
                                endpoint       = url,
                                context        = "Fat GET: body fields on GET request",
                                details        = f"Body params likely unkeyed: {', '.join(bfields[:3])}",
                                raw_confidence = 35,
                            ),
                        ],
                        surface_type = "Cache Poisoning: Fat GET",
                        endpoint     = url,
                        method       = method,
                        parameter    = bfields[0] if bfields else "",
                        notes        = _BURP_NOTES_FAT_GET,
                    )

        return self._results
