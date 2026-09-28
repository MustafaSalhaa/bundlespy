"""
InjectionMapper - SQL/NoSQL/GraphQL injection surface identification.
Pure static analysis of already-collected endpoint data. Zero HTTP requests.
"""
from typing import List
from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint

# Param names with high injection relevance
_HIGH_SIGNAL_PARAMS = {
    "id", "user", "user_id", "name", "email", "search", "username",
}

_MEDIUM_SIGNAL_PARAMS = {
    "filter", "category", "sort", "order", "page", "limit",
    "where", "query", "select", "table", "column", "field",
    "key", "value", "type", "status",
}

_ALL_INJECTION_PARAMS = _HIGH_SIGNAL_PARAMS | _MEDIUM_SIGNAL_PARAMS

_GRAPHQL_PATH_SIGNALS = {"/graphql", "/graphiql", "/playground", "/gql"}

_BURP_NOTES = (
    "Test SQLi with sqlmap or manual boolean/time-based. "
    "For GraphQL: use graphql-cop. "
    "For NoSQL: test with {$gt:''} operators."
)


class InjectionMapper(BaseSurfaceMapper):
    category = AttackCategory.INJECTION

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        for ep in result.endpoints:
            method = (ep.method or "GET").upper()
            path   = (ep.path or ep.url or "").lower()

            # GraphQL endpoints - flag for introspection and injection
            if ep.category == "GRAPHQL" or any(sig in path for sig in _GRAPHQL_PATH_SIGNALS):
                self._candidate(
                    endpoint     = ep,
                    surface_type = "GraphQL Injection",
                    parameters   = ["graphql:query"],
                    confidence   = ConfidenceLevel.HIGH,
                    evidence     = [f"GraphQL endpoint: {ep.url}"],
                    burp_notes   = (
                        "Run GraphQL introspection. Test for injection via graphql-cop. "
                        "Check for batching attacks, IDOR via query, and sensitive schema exposure."
                    ),
                )
                continue

            # Query params
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name not in _ALL_INJECTION_PARAMS:
                    continue

                confidence = ConfidenceLevel.HIGH if name in _HIGH_SIGNAL_PARAMS and method in ("POST", "PUT") else \
                             ConfidenceLevel.HIGH if name in _HIGH_SIGNAL_PARAMS else \
                             ConfidenceLevel.MEDIUM

                self._candidate(
                    endpoint     = ep,
                    surface_type = "SQL/NoSQL Injection",
                    parameters   = [f"query:{name}"],
                    confidence   = confidence,
                    evidence     = [
                        f"Injection-relevant query param '{name}' on {method} {ep.url}",
                    ],
                    burp_notes   = _BURP_NOTES,
                )

            # Body fields on state-changing methods
            if method in ("POST", "PUT", "PATCH"):
                for bf in (ep.body_fields or []):
                    name = (bf.get("name") or "").lower()
                    if name not in _ALL_INJECTION_PARAMS:
                        continue
                    confidence = ConfidenceLevel.HIGH if name in _HIGH_SIGNAL_PARAMS else ConfidenceLevel.MEDIUM
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "SQL/NoSQL Injection",
                        parameters   = [f"body:{name}"],
                        confidence   = confidence,
                        evidence     = [
                            f"Injection-relevant body field '{name}' on {method} {ep.url}",
                        ],
                        burp_notes   = _BURP_NOTES,
                    )

        return self._results
