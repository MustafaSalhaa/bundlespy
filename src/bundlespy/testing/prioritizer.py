"""
Scores endpoints and parameters to determine test priority.
High-value targets get tested first; static marketing pages last.
"""
from typing import List, Tuple
from ..storage.models import Endpoint

_ADMIN_SIGNALS    = ["/admin", "/management", "/dashboard", "/panel", "/console"]
_AUTH_SIGNALS     = ["/login", "/logout", "/auth", "/register", "/signin", "/token", "/oauth"]
_FILE_SIGNALS     = ["/download", "/upload", "/file", "/document", "/export", "/import", "/attachment"]
_FETCH_SIGNALS    = ["/proxy", "/fetch", "/webhook", "/callback", "/redirect", "/image"]
_DB_PARAM_SIGNALS = ["id", "user_id", "order_id", "item_id", "product_id", "report_id", "doc_id", "account_id"]
_SEARCH_SIGNALS   = ["q", "query", "search", "filter", "sort", "order", "limit", "offset", "page"]
_REDIRECT_SIGNALS = ["redirect", "return", "next", "url", "continue", "destination", "callback", "goto"]
_SSRF_SIGNALS     = ["url", "uri", "callback", "webhook", "image", "fetch", "proxy", "target", "destination", "resource"]

def score_endpoint(ep: Endpoint) -> float:
    """
    Returns a priority score 0.0 - 1.0 for an endpoint.
    Higher = test earlier.
    """
    score = 0.0
    path = (ep.path or ep.url or "").lower()
    method = (ep.method or "GET").upper()

    # Runtime-observed endpoints are more valuable
    if ep.source_type == "runtime":
        score += 0.3

    # Category boosts
    if ep.category == "ADMIN":
        score += 0.4
    elif ep.category == "AUTH":
        score += 0.35
    elif ep.category == "API":
        score += 0.25
    elif ep.category == "GRAPHQL":
        score += 0.3
    elif ep.category == "WEBSOCKET":
        score += 0.2

    # Method boosts
    if method in ("POST", "PUT", "PATCH"):
        score += 0.2
    elif method == "GET":
        score += 0.05

    # Path signal boosts
    if any(s in path for s in _ADMIN_SIGNALS):
        score += 0.25
    if any(s in path for s in _FILE_SIGNALS):
        score += 0.2
    if any(s in path for s in _FETCH_SIGNALS):
        score += 0.15
    if any(s in path for s in _AUTH_SIGNALS):
        score += 0.15

    # Has parameters (path or query) = higher value
    path_params  = ep.path_params  or []
    query_params = ep.query_params or []
    body_fields  = ep.body_fields  or []
    total_params = len(path_params) + len(query_params) + len(body_fields)
    if total_params > 0:
        score += min(0.2, total_params * 0.05)

    # Numeric or UUID path params (IDOR candidates)
    for pp in path_params:
        name = (pp.get("name") or "").lower()
        if any(s in name for s in _DB_PARAM_SIGNALS):
            score += 0.15

    # Auth context suggests protected resource
    if ep.auth_context and ep.auth_context.lower() not in ("", "none", "unknown"):
        score += 0.1

    return min(1.0, score)

def score_param_for_attack(param_name: str, attack_type: str) -> float:
    """
    Returns 0.0 - 1.0 likelihood that param_name is relevant for attack_type.
    """
    name = param_name.lower()
    if attack_type == "SSRF":
        return 0.9 if any(s in name for s in _SSRF_SIGNALS) else 0.1
    if attack_type == "OPEN_REDIRECT":
        return 0.9 if any(s in name for s in _REDIRECT_SIGNALS) else 0.1
    if attack_type == "SQLI":
        return 0.8 if any(s in name for s in _DB_PARAM_SIGNALS + _SEARCH_SIGNALS) else 0.2
    if attack_type == "IDOR":
        return 0.9 if any(s in name for s in _DB_PARAM_SIGNALS) else 0.2
    if attack_type == "PATH_TRAVERSAL":
        file_signals = ["file", "path", "filename", "template", "document", "download", "resource", "include", "page", "view"]
        return 0.9 if any(s in name for s in file_signals) else 0.1
    return 0.3  # default moderate relevance

def prioritize(endpoints: List[Endpoint]) -> List[Tuple[float, Endpoint]]:
    """Returns list of (score, endpoint) sorted highest first."""
    scored = [(score_endpoint(ep), ep) for ep in endpoints]
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored
