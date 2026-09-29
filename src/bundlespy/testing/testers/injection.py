"""
InjectionMapper - SQL/NoSQL/Command/SSTI/XXE/LDAP injection surface identification.
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

# XXE - body field names that commonly carry XML payloads
_XXE_BODY_FIELDS = {
    "xml", "data", "payload", "content", "body", "document",
    "input", "request", "soap", "envelope",
}

# XXE - content-type values that indicate XML parsing
_XXE_CONTENT_TYPES = {
    "application/xml", "text/xml", "application/soap+xml", "application/xhtml+xml",
}

# LDAP - param names that commonly map to directory attributes
_LDAP_PARAMS = {
    "username", "user", "cn", "dn", "ldap", "login", "uid",
    "samaccountname", "userprincipalname", "email", "mail",
}

# LDAP - always LDAP-specific regardless of path context
_LDAP_SPECIFIC_PARAMS = {"cn", "dn", "ldap", "samaccountname", "userprincipalname"}

# LDAP - path patterns that suggest directory/auth backends
_LDAP_PATH_SIGNALS = {
    "/ldap", "/directory", "/search", "/lookup", "/ad",
    "/auth", "/login", "/signin",
}

# Path patterns with injection-relevant semantics (search/filter endpoints)
_PATH_SIGNALS = {"/search", "/query", "/filter", "/find", "/lookup"}

# Search/filter body fields that commonly go straight into WHERE clauses
_SEARCH_BODY_FIELDS = {"search", "query", "q", "filter"}

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

_BURP_NOTES_XXE = (
    "Test XXE: <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>. "
    "Try blind XXE with Burp Collaborator OOB: <!ENTITY % xxe SYSTEM \"http://collaborator/\">. "
    "Check SOAP endpoints for SSRF via XXE."
)

_BURP_NOTES_LDAP = (
    "Test LDAP injection: *)(objectClass=*))(|(objectClass=* and )(|(password=*). "
    "Use blind LDAP with timing or error-based. "
    "Tool: ldap-brute, or manual with Burp."
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


def _has_xml_content_type(ep: Endpoint) -> bool:
    """Check if the endpoint declares an XML-based content-type header."""
    headers = ep.request_headers or {}
    ct = headers.get("content-type") or headers.get("Content-Type") or ""
    ct = ct.lower()
    return any(xml_ct in ct for xml_ct in _XXE_CONTENT_TYPES)


class InjectionMapper(BaseSurfaceMapper):
    category = AttackCategory.INJECTION

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        for ep in result.endpoints:
            method = (ep.method or "GET").upper()
            path   = (ep.path or ep.url or "").lower()

            # GraphQL endpoints - flag for introspection and injection
            # NOTE: do NOT continue here - GraphQL endpoints can also have XXE/LDAP
            # backends and should fall through to all subsequent checks.
            if ep.category == "GRAPHQL" or any(sig in path for sig in _GRAPHQL_PATH_SIGNALS):
                self._candidate(
                    endpoint     = ep,
                    surface_type = "GraphQL Injection",
                    parameters   = ["graphql:query"],
                    confidence   = ConfidenceLevel.HIGH,
                    evidence     = [f"GraphQL endpoint: {ep.url}"],
                    burp_notes   = _BURP_NOTES_GRAPHQL,
                )

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

            # --- XXE Detection ---
            # Three trigger conditions:
            # 1. XML content-type header confirmed on the endpoint
            # 2. Body field name matches known XML-carrying field names (POST/PUT/PATCH)
            # 3. Path contains /xml, /soap, /wsdl, or /api with xml body field
            xml_ct_confirmed = _has_xml_content_type(ep)
            xml_path_signal = any(seg in path for seg in ("/xml", "/soap", "/wsdl"))
            api_path = "/api" in path

            if xml_ct_confirmed:
                self._candidate(
                    endpoint     = ep,
                    surface_type = "XXE",
                    parameters   = ["header:content-type"],
                    confidence   = ConfidenceLevel.HIGH,
                    evidence     = [
                        f"XML content-type confirmed on {method} {ep.url}",
                        "Parser likely accepts external entity declarations",
                    ],
                    burp_notes   = _BURP_NOTES_XXE,
                )
            elif method in ("POST", "PUT", "PATCH"):
                xxe_body_fields = [
                    bf for bf in (ep.body_fields or [])
                    if (bf.get("name") or "").lower() in _XXE_BODY_FIELDS
                ]
                for bf in xxe_body_fields:
                    name = (bf.get("name") or "").lower()
                    # MEDIUM for field name match alone; HIGH if path also signals XML
                    if xml_path_signal or (api_path and name in ("xml", "soap", "envelope")):
                        confidence = ConfidenceLevel.HIGH
                        evidence = [
                            f"XML body field '{name}' on {method} {ep.url}",
                            f"Path also signals XML processing: {ep.url}",
                        ]
                    else:
                        confidence = ConfidenceLevel.MEDIUM
                        evidence = [
                            f"Body field '{name}' commonly carries XML payloads on {method} {ep.url}",
                        ]
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "XXE",
                        parameters   = [f"body:{name}"],
                        confidence   = confidence,
                        evidence     = evidence,
                        burp_notes   = _BURP_NOTES_XXE,
                    )

            # --- LDAP Injection Detection ---
            # Trigger conditions:
            # 1. Param name is always LDAP-specific (cn, dn, ldap, samaccountname, userprincipalname) - HIGH
            # 2. Param in _LDAP_PARAMS AND path contains a _LDAP_PATH_SIGNAL - MEDIUM
            path_is_ldap = any(sig in path for sig in _LDAP_PATH_SIGNALS)

            all_params = list(ep.query_params or [])
            if method in ("POST", "PUT", "PATCH"):
                all_params += list(ep.body_fields or [])

            for param in all_params:
                pname = (param.get("name") or "").lower()
                param_source = "query" if param in (ep.query_params or []) else "body"

                if pname in _LDAP_SPECIFIC_PARAMS:
                    # Always LDAP-specific - flag regardless of path
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "LDAP Injection",
                        parameters   = [f"{param_source}:{pname}"],
                        confidence   = ConfidenceLevel.HIGH,
                        evidence     = [
                            f"LDAP-specific param '{pname}' on {method} {ep.url}",
                            "This param name is native to LDAP directory attributes",
                        ],
                        burp_notes   = _BURP_NOTES_LDAP,
                    )
                elif pname in _LDAP_PARAMS and path_is_ldap:
                    # Generic auth param but path confirms directory/auth context
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "LDAP Injection",
                        parameters   = [f"{param_source}:{pname}"],
                        confidence   = ConfidenceLevel.MEDIUM,
                        evidence     = [
                            f"Param '{pname}' on auth/directory path {ep.url}",
                            "Combination of param name and path suggests LDAP backend",
                        ],
                        burp_notes   = _BURP_NOTES_LDAP,
                    )

            # --- Search param on POST body (missing coverage) ---
            # search/query/q/filter body fields on state-changing methods
            # often go directly into WHERE clauses or document search pipelines
            if method in ("POST", "PUT", "PATCH"):
                for bf in (ep.body_fields or []):
                    name = (bf.get("name") or "").lower()
                    if name in _SEARCH_BODY_FIELDS:
                        self._candidate(
                            endpoint     = ep,
                            surface_type = "SQL/NoSQL Injection",
                            parameters   = [f"body:{name}"],
                            confidence   = ConfidenceLevel.MEDIUM,
                            evidence     = [
                                f"Search/filter body field '{name}' on {method} {ep.url}",
                                "These fields commonly feed directly into WHERE clauses or document search",
                            ],
                            burp_notes   = _BURP_NOTES_SQLI,
                        )

            # --- Injection-relevant path signal + body field ---
            # Endpoints under /search, /query, /filter, /find, /lookup
            # with any body field are worth flagging at MEDIUM
            if method in ("POST", "PUT", "PATCH") and any(sig in path for sig in _PATH_SIGNALS):
                body_fields = ep.body_fields or []
                if body_fields:
                    field_names = [
                        (bf.get("name") or "unknown") for bf in body_fields
                    ]
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "SQL/NoSQL Injection",
                        parameters   = [f"body:{n}" for n in field_names[:5]],
                        confidence   = ConfidenceLevel.MEDIUM,
                        evidence     = [
                            f"Injection-relevant path pattern on {method} {ep.url}",
                            f"Body fields present: {', '.join(field_names[:5])}",
                            "Search/filter/lookup endpoints commonly pass input into DB queries",
                        ],
                        burp_notes   = _BURP_NOTES_SQLI,
                    )

        return self._results
