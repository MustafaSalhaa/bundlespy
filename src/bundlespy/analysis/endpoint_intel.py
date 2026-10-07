"""
Endpoint Intelligence Extractor.

Goes beyond raw URL extraction - pulls out for each endpoint:
- HTTP method (from the actual call context)
- Query parameters
- Path parameters
- Request body fields
- Relevant headers
- Authentication context (Bearer / Cookie / ApiKey)
- Category (AUTH / ADMIN / API / GRAPHQL / etc)

Recognizes: fetch, axios, XMLHttpRequest, Angular HttpClient, jQuery ajax,
superagent, ky, React Query / TanStack Query (useQuery / useMutation /
useInfiniteQuery), and url/endpoint constants assigned in the same file.

Only assigns a method when there is real evidence - otherwise UNKNOWN.
"""

import re
import json
import logging
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

from ..storage.models import Endpoint

logger = logging.getLogger("bundlespy.analysis.endpoint_intel")


# ── Call-site patterns that carry METHOD evidence ─────────────────────────────

# fetch("/url", { method: "POST", body: JSON.stringify({...}) })
RE_FETCH_FULL = re.compile(
    r'fetch\s*\(\s*[`"\']((?:/|https?://)[^`"\']+)[`"\']\s*,\s*(\{[^;]{0,400}?\})\s*\)',
    re.IGNORECASE | re.DOTALL,
)

# fetch("/url") — no options, defaults to GET
RE_FETCH_SIMPLE = re.compile(
    r'fetch\s*\(\s*[`"\']((?:/|https?://)[^`"\']+)[`"\']\s*\)',
    re.IGNORECASE,
)

# axios.post("/url", {body}) / axios.get / axios.put etc
RE_AXIOS_METHOD = re.compile(
    r'axios\s*\.\s*(get|post|put|delete|patch|head)\s*\(\s*[`"\']'
    r'((?:/|https?://)[^`"\']+)[`"\']'
    r'(?:\s*,\s*(\{[^;]{0,400}?\}))?',
    re.IGNORECASE | re.DOTALL,
)

# axios({ url: "/url", method: "post", data: {...} })
RE_AXIOS_CONFIG = re.compile(
    r'axios\s*\(\s*(\{[^;]{0,500}?\})\s*\)',
    re.IGNORECASE | re.DOTALL,
)

# XMLHttpRequest.open("POST", "/url")
RE_XHR = re.compile(
    r'\.open\s*\(\s*[`"\'](GET|POST|PUT|DELETE|PATCH|HEAD)[`"\']\s*,\s*'
    r'[`"\']((?:/|https?://)[^`"\']+)[`"\']',
    re.IGNORECASE,
)

# Angular HttpClient: this.http.post("/url", body) / .get / .put / .delete
RE_ANGULAR_HTTP = re.compile(
    r'\.\s*(get|post|put|delete|patch)\s*(?:<[^>]+>)?\s*\(\s*'
    r'(?:`([^`]+)`|["\']((?:/|https?://|\./)[^"\']+)["\'])'
    r'(?:\s*,\s*([^;)]{0,300}))?',
    re.IGNORECASE,
)

# jQuery: $.ajax({ url:"/url", type:"POST", data:{...} })
RE_JQUERY_AJAX = re.compile(
    r'\$\s*\.\s*ajax\s*\(\s*(\{[^;]{0,500}?\})\s*\)',
    re.IGNORECASE | re.DOTALL,
)

# jQuery shortcuts: $.get("/url") $.post("/url", {data})
RE_JQUERY_SHORT = re.compile(
    r'\$\s*\.\s*(get|post)\s*\(\s*["\']((?:/|https?://)[^"\']+)["\']'
    r'(?:\s*,\s*(\{[^;]{0,300}?\}))?',
    re.IGNORECASE | re.DOTALL,
)

# superagent: request.get("/url") / request.post("/url").send({...})
RE_SUPERAGENT = re.compile(
    r'(?:request|superagent)\s*\.\s*(get|post|put|delete|patch)\s*\(\s*'
    r'[`"\']((?:/|https?://)[^`"\']+)[`"\']',
    re.IGNORECASE,
)

# ky: ky.get("/url") / ky.post("/url", { json: {...} })
RE_KY = re.compile(
    r'\bky\s*\.\s*(get|post|put|delete|patch)\s*\(\s*'
    r'[`"\']((?:/|https?://)[^`"\']+)[`"\']'
    r'(?:\s*,\s*(\{[^;]{0,400}?\}))?',
    re.IGNORECASE | re.DOTALL,
)

# React Query / TanStack: useQuery({ queryKey: [...], queryFn: () => fetch("/url") })
# Captures the key string plus any nested fetch/axios URL
RE_USE_QUERY = re.compile(
    r'(?:useQuery|useInfiniteQuery)\s*\(\s*\{([^;]{0,600}?)\}\s*\)',
    re.IGNORECASE | re.DOTALL,
)

# useMutation({ mutationFn: (data) => api.post("/url", data) })
RE_USE_MUTATION = re.compile(
    r'useMutation\s*\(\s*\{([^;]{0,600}?)\}\s*\)',
    re.IGNORECASE | re.DOTALL,
)

# React Query v5 array-key form: useQuery(["key", id], () => fetch("/url"))
RE_USE_QUERY_V4 = re.compile(
    r'(?:useQuery|useInfiniteQuery)\s*\(\s*\[([^\]]{0,200})\]\s*,\s*(?:\([^)]*\)\s*=>\s*)?'
    r'(?:fetch|axios\s*\.(?:get|post)|api\s*\.(?:get|post))\s*\(\s*'
    r'[`"\']((?:/|https?://)[^`"\']+)[`"\']',
    re.IGNORECASE | re.DOTALL,
)

# $http (AngularJS legacy): $http.get("/url") / $http({ method: "POST", url: "/url" })
RE_ANGULARJS_HTTP_SHORT = re.compile(
    r'\$http\s*\.\s*(get|post|put|delete|patch)\s*\(\s*'
    r'[`"\']((?:/|https?://)[^`"\']+)[`"\']'
    r'(?:\s*,\s*(\{[^;]{0,400}?\}))?',
    re.IGNORECASE | re.DOTALL,
)
RE_ANGULARJS_HTTP_CONFIG = re.compile(
    r'\$http\s*\(\s*(\{[^;]{0,500}?\})\s*\)',
    re.IGNORECASE | re.DOTALL,
)

# WebSocket: new WebSocket("wss://host/path")
RE_WEBSOCKET = re.compile(
    r'new\s+WebSocket\s*\(\s*[`"\'](wss?://[^`"\']+)[`"\']',
    re.IGNORECASE,
)

# GraphQL: client.query({ query: gql`...`, variables: {...} })
# Also apollo client: useLazyQuery / useSubscription
RE_GQL_OPERATION = re.compile(
    r'(?:client\.(?:query|mutate|subscribe)|useLazyQuery|useSubscription)\s*\(\s*\{([^;]{0,600}?)\}\s*\)',
    re.IGNORECASE | re.DOTALL,
)


# ── Constant / variable resolution ────────────────────────────────────────────
# Scan for const/let/var assignments of URL-like strings and build a substitution
# table. Used to resolve fetch(ENDPOINT_CONST) where the literal is assigned nearby.

RE_CONST_URL = re.compile(
    r'(?:const|let|var)\s+([A-Z_][A-Z0-9_]{1,50})\s*=\s*[`"\']((?:/|https?://)[^`"\']+)[`"\']',
    re.IGNORECASE,
)

# Also capture: const ENDPOINT = BASE_URL + "/path" (static suffix after +)
RE_CONST_CONCAT = re.compile(
    r'(?:const|let|var)\s+([A-Z_][A-Z0-9_]{1,50})\s*=\s*[A-Z_][A-Z0-9_]*\s*\+\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# fetch with a variable as URL: fetch(SOME_CONST, opts)
RE_FETCH_VAR = re.compile(
    r'fetch\s*\(\s*([A-Z_][A-Z0-9_]{1,50})\s*(?:,\s*(\{[^;]{0,400}?\}))?\s*\)',
    re.IGNORECASE | re.DOTALL,
)

# axios.get(SOME_CONST) / axios.post(SOME_CONST, body)
RE_AXIOS_VAR = re.compile(
    r'axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*([A-Z_][A-Z0-9_]{1,50})\s*'
    r'(?:,\s*(\{[^;]{0,400}?\}))?\s*\)',
    re.IGNORECASE | re.DOTALL,
)


# ── Template literal static prefix extraction ─────────────────────────────────
# `${BASE}/users/${userId}` → treat "/users/*" as the structural endpoint
RE_TEMPLATE_LITERAL_API = re.compile(
    r'fetch\s*\(\s*`([^`]+)`',
    re.IGNORECASE,
)


def _build_constant_map(content: str) -> Dict[str, str]:
    """
    One-pass constant resolution. Scans file for URL-valued const/let/var
    declarations and returns {VAR_NAME: url_string}.
    Concat form produces only the path suffix as a relative path.
    """
    constants: Dict[str, str] = {}
    for m in RE_CONST_URL.finditer(content):
        name, url = m.group(1), m.group(2)
        constants[name] = url
    for m in RE_CONST_CONCAT.finditer(content):
        name, suffix = m.group(1), m.group(2)
        if suffix.startswith("/"):
            constants[name] = suffix
    return constants


def _resolve_template_literal(tmpl: str) -> Optional[str]:
    """
    Extract the static prefix from a template literal URL.
    `${BASE}/users/${id}/orders` -> /users/*/orders
    Returns None if there is no useful static prefix.
    """
    # Replace ${...} with a wildcard placeholder
    normalized = re.sub(r'\$\{[^}]+\}', '*', tmpl)
    # Must start with / or http to be a real path
    if not (normalized.startswith("/") or normalized.startswith("http")):
        return None
    # If it is nothing but wildcards and slashes, not useful
    stripped = normalized.replace("*", "").replace("/", "").strip()
    if not stripped:
        return None
    return normalized


# ── Field extractors ──────────────────────────────────────────────────────────

def _extract_method_from_options(options: str) -> Optional[str]:
    """Extract method from a fetch/axios options object."""
    if not options:
        return None
    m = re.search(r'method\s*:\s*["\']?(get|post|put|delete|patch|head)["\']?',
                  options, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    return None


def _extract_body_fields(options: str) -> List[Dict]:
    """
    Extract body field names from JSON.stringify({...}) or data: {...}.
    Returns [{"name": "email"}, {"name": "password"}]
    """
    fields = []
    seen   = set()

    # JSON.stringify({ email: ..., password: ... })
    stringify = re.search(r'JSON\.stringify\s*\(\s*\{([^}]{0,400})\}',
                          options, re.IGNORECASE)
    body_block = ""
    if stringify:
        body_block = stringify.group(1)
    else:
        # body: {...} or data: {...} or json: {...} (ky uses json:)
        m = re.search(r'(?:body|data|json)\s*:\s*\{([^}]{0,400})\}',
                      options, re.IGNORECASE)
        if m:
            body_block = m.group(1)

    # If no stringify/body/data block found, treat the whole thing as a body object
    if not body_block and options.strip().startswith("{"):
        body_block = options.strip()[1:-1] if options.strip().endswith("}") else options.strip()[1:]

    if body_block:
        for km in re.finditer(r'["\']?([A-Za-z_][A-Za-z0-9_]{1,40})["\']?\s*:',
                              body_block):
            key = km.group(1)
            if key.lower() not in ("method", "headers", "body", "data",
                                    "json", "url", "type", "params",
                                    "content-type", "authorization",
                                    "queryfn", "mutationfn", "querykey",
                                    "enabled", "staletime", "cachetime") and key not in seen:
                seen.add(key)
                fields.append({"name": key})

    return fields


def _extract_headers(options: str) -> Dict[str, str]:
    """Extract headers from options object."""
    headers = {}
    hblock = re.search(r'headers\s*:\s*\{([^}]{0,300})\}', options, re.IGNORECASE)
    if hblock:
        block = hblock.group(1)
        for hm in re.finditer(r'["\']?([A-Za-z\-]+)["\']?\s*:\s*[`"\']([^`"\']{0,100})[`"\']',
                              block):
            headers[hm.group(1)] = hm.group(2)
    return headers


def _detect_auth_context(options: str, headers: Dict[str, str]) -> str:
    """Determine authentication mechanism from headers and options."""
    combined = options.lower()
    for hval in headers.values():
        combined += " " + hval.lower()
    for hkey in headers.keys():
        combined += " " + hkey.lower()

    if "bearer" in combined or "authorization" in combined:
        return "Bearer"
    if "x-api-key" in combined or "apikey" in combined or "api-key" in combined:
        return "ApiKey"
    if "cookie" in combined or "credentials" in combined:
        return "Cookie"
    if "x-auth-token" in combined or "x-access-token" in combined:
        return "Token"
    return ""


def _extract_query_params(url: str) -> List[Dict]:
    """Extract query parameter names from the URL."""
    params = []
    if "?" in url:
        query = url.split("?", 1)[1]
        for pair in query.split("&"):
            name = pair.split("=")[0]
            if name and re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name):
                params.append({"name": name})
    return params


def _extract_path_params(path: str) -> List[Dict]:
    """
    Detect path parameters - :id, {id}, ${var}, [id], *.
    Returns positions in the path.
    """
    params  = []
    segments = path.split("/")
    for i, seg in enumerate(segments):
        if not seg:
            continue
        if (seg.startswith(":") or
            (seg.startswith("{") and seg.endswith("}")) or
            (seg.startswith("[") and seg.endswith("]")) or
            "${" in seg or seg == "*"):
            name = seg.strip(":{}[]$*") or f"param{i}"
            params.append({"name": name, "position": i})
    return params


def _categorize(path: str, method: str = "") -> str:
    lower = path.lower()
    if any(k in lower for k in ["/login", "/logout", "/auth", "/oauth",
                                  "/token", "/session", "/signin", "/signup",
                                  "/register", "/password"]):
        return "AUTH"
    if any(k in lower for k in ["/admin", "/administration", "/manage",
                                  "/management", "/panel", "/staff"]):
        return "ADMIN"
    if "/graphql" in lower or "/gql" in lower:
        return "GRAPHQL"
    if lower.startswith("ws://") or lower.startswith("wss://"):
        return "WEBSOCKET"
    if any(k in lower for k in ["/api/", "/rest/", "/v1/", "/v2/", "/v3/"]):
        return "API"
    return "UNKNOWN"


def _get_line(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _make_endpoint(url: str, method: str, source_file: str,
                   line: int, body_fields=None, headers=None,
                   auth="", evidence="", confidence=0.90) -> Endpoint:
    parsed = urlparse(url if url.startswith("http") else "http://x" + url)
    path   = parsed.path or url.split("?")[0]
    host   = parsed.netloc if url.startswith("http") else ""

    kind = "api"
    if url.startswith("ws"):
        kind = "websocket"
    elif "/graphql" in url.lower():
        kind = "graphql"
    elif url.startswith("http") and host:
        kind = "external"

    return Endpoint(
        url             = url,
        path            = path,
        method          = method or "UNKNOWN",
        category        = _categorize(path, method),
        source_file     = source_file,
        line_number     = line,
        confidence      = confidence,
        host            = host,
        query_params    = _extract_query_params(url),
        path_params     = _extract_path_params(path),
        body_fields     = body_fields or [],
        request_headers = headers or {},
        content_type    = (headers or {}).get("Content-Type", "") or (headers or {}).get("content-type", ""),
        auth_context    = auth,
        evidence        = evidence[:200] if evidence else "",
        kind            = kind,
    )


def extract_endpoint_intelligence(content: str, file_url: str) -> List[Endpoint]:
    """
    Extract endpoints WITH full intelligence - method, params, body, auth.
    Includes constant resolution and React Query pattern detection.
    """
    endpoints: List[Endpoint] = []
    seen: Dict[str, Endpoint] = {}

    def _key(url: str, method: str) -> str:
        return f"{method}:{url.rstrip('/').lower().split('?')[0]}"

    def _add(ep: Endpoint) -> None:
        k = _key(ep.url, ep.method)
        if k in seen:
            # Merge - prefer the one with more intelligence
            existing = seen[k]
            if ep.body_fields and not existing.body_fields:
                existing.body_fields = ep.body_fields
            if ep.auth_context and not existing.auth_context:
                existing.auth_context = ep.auth_context
            if ep.method != "UNKNOWN" and existing.method == "UNKNOWN":
                existing.method = ep.method
            return
        seen[k] = ep
        endpoints.append(ep)

    # Build constant map for this file - resolves fetch(CONST) patterns
    constant_map = _build_constant_map(content)

    # ── fetch with options ────────────────────────────────────────────────────
    for m in RE_FETCH_FULL.finditer(content):
        url     = m.group(1)
        options = m.group(2) or ""
        method  = _extract_method_from_options(options) or "GET"
        body    = _extract_body_fields(options)
        headers = _extract_headers(options)
        auth    = _detect_auth_context(options, headers)
        _add(_make_endpoint(url, method, file_url, _get_line(content, m.start()),
                            body, headers, auth, m.group(0), 0.92))

    # ── fetch simple ──────────────────────────────────────────────────────────
    for m in RE_FETCH_SIMPLE.finditer(content):
        url = m.group(1)
        _add(_make_endpoint(url, "GET", file_url, _get_line(content, m.start()),
                            evidence=m.group(0), confidence=0.85))

    # ── fetch with variable URL ───────────────────────────────────────────────
    for m in RE_FETCH_VAR.finditer(content):
        var_name = m.group(1)
        options  = m.group(2) or ""
        resolved = constant_map.get(var_name)
        if not resolved:
            continue
        method  = _extract_method_from_options(options) or "GET"
        body    = _extract_body_fields(options)
        headers = _extract_headers(options)
        auth    = _detect_auth_context(options, headers)
        _add(_make_endpoint(resolved, method, file_url, _get_line(content, m.start()),
                            body, headers, auth, m.group(0), 0.88))

    # ── template literal fetch ─────────────────────────────────────────────
    for m in RE_TEMPLATE_LITERAL_API.finditer(content):
        tmpl = m.group(1)
        resolved = _resolve_template_literal(tmpl)
        if resolved and (resolved.startswith("/") or resolved.startswith("http")):
            _add(_make_endpoint(resolved, "GET", file_url, _get_line(content, m.start()),
                                evidence=m.group(0), confidence=0.80))

    # ── axios.method ──────────────────────────────────────────────────────────
    for m in RE_AXIOS_METHOD.finditer(content):
        method  = m.group(1).upper()
        url     = m.group(2)
        options = m.group(3) or ""
        body    = _extract_body_fields(options)
        headers = _extract_headers(options)
        auth    = _detect_auth_context(options, headers)
        _add(_make_endpoint(url, method, file_url, _get_line(content, m.start()),
                            body, headers, auth, m.group(0), 0.92))

    # ── axios.method with variable URL ────────────────────────────────────────
    for m in RE_AXIOS_VAR.finditer(content):
        method   = m.group(1).upper()
        var_name = m.group(2)
        options  = m.group(3) or ""
        resolved = constant_map.get(var_name)
        if not resolved:
            continue
        body    = _extract_body_fields(options)
        headers = _extract_headers(options)
        auth    = _detect_auth_context(options, headers)
        _add(_make_endpoint(resolved, method, file_url, _get_line(content, m.start()),
                            body, headers, auth, m.group(0), 0.88))

    # ── axios config object ───────────────────────────────────────────────────
    for m in RE_AXIOS_CONFIG.finditer(content):
        block = m.group(1)
        url_m = re.search(r'url\s*:\s*[`"\']((?:/|https?://)[^`"\']+)[`"\']', block, re.IGNORECASE)
        if not url_m:
            continue
        url    = url_m.group(1)
        method = _extract_method_from_options(block) or "GET"
        body   = _extract_body_fields(block)
        headers = _extract_headers(block)
        auth   = _detect_auth_context(block, headers)
        _add(_make_endpoint(url, method, file_url, _get_line(content, m.start()),
                            body, headers, auth, m.group(0), 0.90))

    # ── XHR ───────────────────────────────────────────────────────────────────
    for m in RE_XHR.finditer(content):
        method = m.group(1).upper()
        url    = m.group(2)
        _add(_make_endpoint(url, method, file_url, _get_line(content, m.start()),
                            evidence=m.group(0), confidence=0.90))

    # ── Angular HttpClient ────────────────────────────────────────────────────
    for m in RE_ANGULAR_HTTP.finditer(content):
        method = m.group(1).upper()
        url    = m.group(2) or m.group(3) or ""
        args   = m.group(4) or ""
        if not url or not (url.startswith("/") or url.startswith("http") or url.startswith("./")):
            continue
        url = url.replace("./", "/")
        url = re.sub(r'\$\{[^}]+\}', '*', url)
        if len(url) < 2:
            continue
        body = _extract_body_fields(args)
        auth = _detect_auth_context(args, {})
        _add(_make_endpoint(url, method, file_url, _get_line(content, m.start()),
                            body, {}, auth, m.group(0), 0.88))

    # ── AngularJS $http ───────────────────────────────────────────────────────
    for m in RE_ANGULARJS_HTTP_SHORT.finditer(content):
        method  = m.group(1).upper()
        url     = m.group(2)
        options = m.group(3) or ""
        body    = _extract_body_fields(options)
        headers = _extract_headers(options)
        auth    = _detect_auth_context(options, headers)
        _add(_make_endpoint(url, method, file_url, _get_line(content, m.start()),
                            body, headers, auth, m.group(0), 0.88))

    for m in RE_ANGULARJS_HTTP_CONFIG.finditer(content):
        block = m.group(1)
        url_m = re.search(r'url\s*:\s*["\']((?:/|https?://)[^"\']+)["\']', block, re.IGNORECASE)
        if not url_m:
            continue
        url    = url_m.group(1)
        method = _extract_method_from_options(block) or "GET"
        body   = _extract_body_fields(block)
        headers = _extract_headers(block)
        auth   = _detect_auth_context(block, headers)
        _add(_make_endpoint(url, method, file_url, _get_line(content, m.start()),
                            body, headers, auth, m.group(0), 0.88))

    # ── jQuery ajax ───────────────────────────────────────────────────────────
    for m in RE_JQUERY_AJAX.finditer(content):
        block = m.group(1)
        url_m = re.search(r'url\s*:\s*["\']((?:/|https?://)[^"\']+)["\']', block, re.IGNORECASE)
        if not url_m:
            continue
        url    = url_m.group(1)
        tm     = re.search(r'type\s*:\s*["\'](get|post|put|delete)["\']', block, re.IGNORECASE)
        method = tm.group(1).upper() if tm else "GET"
        body   = _extract_body_fields(block)
        headers = _extract_headers(block)
        auth   = _detect_auth_context(block, headers)
        _add(_make_endpoint(url, method, file_url, _get_line(content, m.start()),
                            body, headers, auth, m.group(0), 0.88))

    # ── jQuery shortcuts ──────────────────────────────────────────────────────
    for m in RE_JQUERY_SHORT.finditer(content):
        method  = m.group(1).upper()
        url     = m.group(2)
        options = m.group(3) or ""
        body    = _extract_body_fields(options)
        _add(_make_endpoint(url, method, file_url, _get_line(content, m.start()),
                            body, evidence=m.group(0), confidence=0.85))

    # ── superagent ────────────────────────────────────────────────────────────
    for m in RE_SUPERAGENT.finditer(content):
        method = m.group(1).upper()
        url    = m.group(2)
        _add(_make_endpoint(url, method, file_url, _get_line(content, m.start()),
                            evidence=m.group(0), confidence=0.88))

    # ── ky ────────────────────────────────────────────────────────────────────
    for m in RE_KY.finditer(content):
        method  = m.group(1).upper()
        url     = m.group(2)
        options = m.group(3) or ""
        body    = _extract_body_fields(options)
        headers = _extract_headers(options)
        auth    = _detect_auth_context(options, headers)
        _add(_make_endpoint(url, method, file_url, _get_line(content, m.start()),
                            body, headers, auth, m.group(0), 0.90))

    # ── React Query v5 / TanStack: useQuery({ queryKey, queryFn }) ────────────
    for m in RE_USE_QUERY.finditer(content):
        block = m.group(1)
        # queryFn may contain a fetch/axios call - extract any URL inside it
        inner_urls = re.findall(
            r'[`"\']((?:/|https?://)[^`"\']{2,100})[`"\']',
            block,
        )
        for url in inner_urls:
            if any(url.endswith(ext) for ext in (".js", ".css", ".png", ".jpg")):
                continue
            _add(_make_endpoint(url, "GET", file_url, _get_line(content, m.start()),
                                evidence=m.group(0)[:200], confidence=0.82))

    # ── React Query v4 array-key form ─────────────────────────────────────────
    for m in RE_USE_QUERY_V4.finditer(content):
        url = m.group(2)
        _add(_make_endpoint(url, "GET", file_url, _get_line(content, m.start()),
                            evidence=m.group(0)[:200], confidence=0.85))

    # ── useMutation ───────────────────────────────────────────────────────────
    for m in RE_USE_MUTATION.finditer(content):
        block = m.group(1)
        # Look for method + URL inside mutationFn
        inner_matches = re.finditer(
            r'(?:axios|fetch|api|request|ky)\s*[.(]\s*(?:(post|put|delete|patch)\s*[.(]\s*)?'
            r'[`"\']((?:/|https?://)[^`"\']{2,100})[`"\']',
            block, re.IGNORECASE,
        )
        for im in inner_matches:
            method = (im.group(1) or "POST").upper()
            url    = im.group(2)
            if any(url.endswith(ext) for ext in (".js", ".css", ".png")):
                continue
            _add(_make_endpoint(url, method, file_url, _get_line(content, m.start()),
                                evidence=m.group(0)[:200], confidence=0.83))

    # ── WebSocket ─────────────────────────────────────────────────────────────
    for m in RE_WEBSOCKET.finditer(content):
        url = m.group(1)
        _add(_make_endpoint(url, "WS", file_url, _get_line(content, m.start()),
                            evidence=m.group(0), confidence=0.92))

    return endpoints
