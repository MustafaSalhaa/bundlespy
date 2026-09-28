"""
InjectionMapper - SQL/NoSQL/Command/SSTI injection surface identification.
Pure static analysis of already-collected endpoint data. Zero HTTP requests.
"""
from typing import List
from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ...storage.models import ScanResult, Endpoint

# Classic SQL/NoSQL injection - direct DB access signals
_HIGH_SIGNAL_PARAMS = {
    "id", "user", "user_id", "name", "email", "search", "username",
    "password", "login", "uid", "pid",
}

_MEDIUM_SIGNAL_PARAMS = {
    "filter", "category", "sort", "order", "page", "limit",
    "where", "query", "select", "table", "column", "field",
    "key", "value", "type", "status", "role", "group",
}

# Multi-tenant / org context params - high value for injection + IDOR
_TENANT_PARAMS = {
    "group_id", "org_id", "organization_id", "tenant_id",
    "customer_id", "client_id", "team_id", "workspace_id",
    "company_id", "account_id", "site_id", "store_id",
}

# Command injection signals - these almost certainly talk to a shell
_COMMAND_INJECTION_PARAMS = {
    "cmd", "exec", "command", "run", "shell", "execute",
    "ping", "query", "subprocess", "process", "script",
    "eval", "code", "input",
}

# SSTI signals - template rendering with user input
_SSTI_PARAMS = {
    "template", "render", "view", "format", "layout",
    "theme", "style", "page", "content", "text",
}

_ALL_INJECTION_PARAMS = (
    _HIGH_SIGNAL_PARAMS | _MEDIUM_SIGNAL_PARAMS |
    _TENANT_PARAMS | _COMMAND_INJECTION_PARAMS | _SSTI_PARAMS
)

_GRAPHQL_PATH_SIGNALS = {"/graphql", "/graphiql", "/playground", "/gql"}

# Path patterns that suggest shell/OS interaction
_COMMAND_PATH_SIGNALS = {
    "/exec", "/run", "/cmd", "/shell", "/execute", "/process",
    "/ping", "/traceroute", "/nslookup", "/whois",
    "/convert", "/compress", "/resize", "/generate",
}

_BURP_NOTES_SQLI = (
    "Test SQLi with sqlmap or manual boolean/time-based. "
    "For NoSQL: test with {$gt:''} operators. "
    "Try: ' OR 1=1--, 1' AND SLEEP(5)--"
)

_BURP_NOTES_CMDI = (
    "HIGH-VALUE: command injection signal. "
    "Test: ;id, |id, &&id, `id`, $(id). "
    "Try URL-encoded: %3Bid, %7Cid. "
    "Use Burp Collaborator to detect blind command injection."
)

_BURP_NOTES_SSTI = (
    "Test SSTI: {{7*7}} (Jinja2/Twig), #{7*7} (Ruby/Freemarker), "
    "${7*7} (Java/Velocity), <%= 7*7 %> (ERB). "
    "Blind SSTI: use timing or DNS callbacks via Collaborator."
)

_BURP_NOTES_GRAPHQL = (
    "Run GraphQL introspection to map schema. "
    "Use graphql-cop for injection and auth bypass tests. "
    "Check for batching attacks, IDOR via query, sensitive schema exposure. "
    "Try: query{__schema{types{name}}}"
)

_BURP_NOTES_TENANT = (
    "Multi-tenant param - test for cross-tenant data access (horizontal privilege escalation). "
    "Try substituting another organization/tenant ID. "
    "Also test for SQLi: the value likely goes into a WHERE clause."
)


def _injection_type(name: str) -> str:
    if name in _COMMAND_INJECTION_PARAMS:
        return "Command Injection"
    if name in _SSTI_PARAMS:
        return "SSTI"
    if name in _TENANT_PARAMS:
        return "SQL/NoSQL Injection + Tenant IDOR"
    return "SQL/NoSQL Injection"


def _injection_burp(name: str, path: str) -> str:
    if name in _COMMAND_INJECTION_PARAMS:
        return _BURP_NOTES_CMDI
    if name in _SSTI_PARAMS:
        return _BURP_NOTES_SSTI
    if name in _TENANT_PARAMS:
        return _BURP_NOTES_TENANT
    return _BURP_NOTES_SQLI


def _injection_confidence(name: str, method: str) -> str:
    if name in _COMMAND_INJECTION_PARAMS:
        return ConfidenceLevel.HIGH  # Command injection params are almost always injectable
    if name in _TENANT_PARAMS:
        return ConfidenceLevel.HIGH  # Cross-tenant is always interesting
    if name in _HIGH_SIGNAL_PARAMS and method in ("POST", "PUT", "PATCH"):
        return ConfidenceLevel.HIGH
    if name in _HIGH_SIGNAL_PARAMS:
        return ConfidenceLevel.HIGH
    if name in _SSTI_PARAMS:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.MEDIUM


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
                    burp_notes   = _BURP_NOTES_GRAPHQL,
                )
                continue

            # Path-based command injection signal (e.g. /api/ping, /exec)
            if any(sig in path for sig in _COMMAND_PATH_SIGNALS):
                self._candidate(
                    endpoint     = ep,
                    surface_type = "Command Injection",
                    parameters   = ["path:command_path"],
                    confidence   = ConfidenceLevel.HIGH,
                    evidence     = [
                        f"Path pattern suggests OS command execution: {ep.url}",
                        "Endpoint name implies shell/system interaction",
                    ],
                    burp_notes   = _BURP_NOTES_CMDI,
                )

            # Query params
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name not in _ALL_INJECTION_PARAMS:
                    continue

                surface_type = _injection_type(name)
                confidence   = _injection_confidence(name, method)
                burp_notes   = _injection_burp(name, path)

                self._candidate(
                    endpoint     = ep,
                    surface_type = surface_type,
                    parameters   = [f"query:{name}"],
                    confidence   = confidence,
                    evidence     = [
                        f"Injection-relevant query param '{name}' on {method} {ep.url}",
                    ],
                    burp_notes   = burp_notes,
                )

            # Body fields on state-changing methods
            if method in ("POST", "PUT", "PATCH"):
                for bf in (ep.body_fields or []):
                    name = (bf.get("name") or "").lower()
                    if name not in _ALL_INJECTION_PARAMS:
                        continue

                    surface_type = _injection_type(name)
                    confidence   = _injection_confidence(name, method)
                    burp_notes   = _injection_burp(name, path)

                    self._candidate(
                        endpoint     = ep,
                        surface_type = surface_type,
                        parameters   = [f"body:{name}"],
                        confidence   = confidence,
                        evidence     = [
                            f"Injection-relevant body field '{name}' on {method} {ep.url}",
                        ],
                        burp_notes   = burp_notes,
                    )

        return self._results
