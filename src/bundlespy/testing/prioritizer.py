"""
Surface result prioritizer.
Sorts candidates by confidence (HIGH > MEDIUM > LOW) then by category priority.
Category priority: IDOR > Injection > XSS > SSRF > Redirect > CSRF > PathTraversal > Config
"""
from typing import List
from ..storage.models import Endpoint
from .models import SurfaceResult, ConfidenceLevel, AttackCategory
from .evidence import SurfaceFinding, RiskLevel

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
    Higher = higher priority for manual follow-up.
    """
    score = 0.0
    path   = (ep.path or ep.url or "").lower()
    method = (ep.method or "GET").upper()

    if ep.source_type == "runtime":
        score += 0.3

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

    if method in ("POST", "PUT", "PATCH"):
        score += 0.2
    elif method == "GET":
        score += 0.05

    if any(s in path for s in _ADMIN_SIGNALS):
        score += 0.25
    if any(s in path for s in _FILE_SIGNALS):
        score += 0.2
    if any(s in path for s in _FETCH_SIGNALS):
        score += 0.15
    if any(s in path for s in _AUTH_SIGNALS):
        score += 0.15

    path_params  = ep.path_params  or []
    query_params = ep.query_params or []
    body_fields  = ep.body_fields  or []
    total_params = len(path_params) + len(query_params) + len(body_fields)
    if total_params > 0:
        score += min(0.2, total_params * 0.05)

    for pp in path_params:
        name = (pp.get("name") or "").lower()
        if any(s in name for s in _DB_PARAM_SIGNALS):
            score += 0.15

    if ep.auth_context and ep.auth_context.lower() not in ("", "none", "unknown"):
        score += 0.1

    return min(1.0, score)


def prioritize_surfaces(results: List[SurfaceResult]) -> List[SurfaceResult]:
    """
    Sort SurfaceResult list by:
    1. Confidence: HIGH > MEDIUM > LOW
    2. Category priority: IDOR > Injection > XSS > SSRF > Redirect > CSRF > PathTraversal > Config
    """
    def sort_key(r: SurfaceResult):
        return (
            ConfidenceLevel.order(r.confidence),
            AttackCategory.priority(r.category),
        )

    return sorted(results, key=sort_key)


def prioritize_findings(findings: List[SurfaceFinding]) -> List[SurfaceFinding]:
    """
    Sort SurfaceFinding list by:
    1. Confidence score descending (higher int = higher priority)
    2. Risk level: CRITICAL > HIGH > MEDIUM > LOW > INFO
    """
    return sorted(findings, key=lambda f: (-f.confidence, RiskLevel.order(f.risk)))
