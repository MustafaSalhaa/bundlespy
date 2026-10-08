"""
AccessControlMapper - IDOR/BOLA and Privilege Escalation surface candidate identification.
Pure static analysis of already-collected endpoint data. Zero HTTP requests.
"""
import re
from typing import List
from urllib.parse import urlparse

from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
from ..evidence import Evidence, EvidenceType
from ...storage.models import ScanResult, Endpoint

# Regex patterns that indicate an object identifier in the path
_NUMERIC_ID_RE  = re.compile(r'/(\d{1,12})(?=/|$|\?)')
_UUID_RE        = re.compile(
    r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)',
    re.I,
)
# Short hash IDs - must contain BOTH letters and digits (not pure words or pure numbers)
# e.g. /share/abc123f, /post/7Hk3pQ, /invite/xK9mP2q  - NOT /functions/stock, /api/users
_HASH_ID_RE = re.compile(r'/([a-z0-9]{6,32})(?=/|$|\?)', re.I)

# Request headers that carry user/account identity - IDOR via header manipulation
_IDOR_HEADER_NAMES = {
    "x-user-id", "x-account-id", "x-tenant-id", "x-customer-id",
    "x-org-id", "x-organization-id", "x-team-id", "x-workspace-id",
    "x-actor-id", "x-resource-id", "x-client-id", "x-subscriber-id",
    "x-forwarded-user", "x-authenticated-user",
}

# Query/body param names that suggest object identifiers
_IDOR_PARAM_NAMES = {
    "id", "user_id", "account_id", "order_id", "item_id",
    "product_id", "report_id", "doc_id", "document_id",
    "file_id", "message_id", "record_id", "object_id",
    "uid", "user", "account", "record",
    # Object reference params often seen in APIs
    "ref", "resource_id", "entity_id", "invoice_id",
    "ticket_id", "post_id", "comment_id", "transaction_id",
    "payment_id", "subscription_id", "member_id",
}

# Body field names that suggest object references in PUT/PATCH
_IDOR_BODY_REFS = {
    "owner_id", "created_by", "assigned_to", "author_id",
    "parent_id", "target_id", "subject_id", "resource_id",
    "referenced_id", "linked_id",
}

# Param/field names that suggest privilege or role manipulation
_PRIVESC_PARAMS = {
    "role", "is_admin", "admin", "privilege", "privileges",
    "permission", "permissions", "group", "access_level",
    "user_type", "account_type", "plan", "tier", "scope",
    "authority", "can_admin", "superuser", "is_superuser",
    "is_staff", "is_moderator", "elevation",
}

_BURP_NOTES = (
    "Test adjacent IDs (id-1, id+1, id+100). "
    "Try unauthenticated. "
    "Try other user session with same ID. "
    "Check if response content differs between sessions. "
    "For DELETE: use another user's resource ID and confirm deletion succeeds."
)

_BURP_NOTES_GET_IDOR = (
    "GET endpoint with ID param - classic IDOR. "
    "Capture a resource ID from User A's session, then request it with User B's session. "
    "If User B gets User A's data, it's IDOR. "
    "Also test unauthenticated and with an incremented/decremented ID. "
    "Use Burp Intruder to enumerate IDs at scale."
)

_BURP_NOTES_HEADER = (
    "Identity header in request - test IDOR by modifying its value. "
    "Try: another user's ID, admin ID (1, 0), empty value. "
    "Some APIs use these headers for authorization instead of session - "
    "if so, any value works."
)

_BURP_NOTES_HASH = (
    "Short hash/token ID in path. "
    "Test with other known hash IDs from the application. "
    "Check if IDs are guessable (low entropy) or sequential. "
    "Try IDOR with IDs from other user sessions."
)

_BURP_NOTES_PRIVESC = (
    "Privilege escalation signal. "
    "Test by submitting role=admin, is_admin=true, privilege=superuser alongside the normal request. "
    "On PUT/PATCH, include this field with an elevated value and check if accepted. "
    "Try both integer (1, 0) and string (admin, true, superuser) values."
)

# Paths where a short hash is unlikely to be a real ID (static assets, etc.)
_HASH_EXCLUSION_RE = re.compile(
    r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|min)$', re.I
)

_ASSET_PATH_RE = re.compile(r'/(assets|static|dist|build|vendor|public|functions|api)/', re.I)

# Common API/route words that look alphanumeric but are NOT object IDs
_KNOWN_ROUTE_WORDS = {
    "admin", "login", "logout", "signup", "register", "profile", "account",
    "settings", "config", "dashboard", "search", "index", "health", "status",
    "metrics", "robots", "sitemap", "favicon", "manifest", "stock", "products",
    "orders", "users", "items", "posts", "comments", "reviews", "categories",
    "upload", "download", "export", "import", "report", "reports", "billing",
    "payment", "checkout", "cart", "wishlist", "notifications", "messages",
    "invite", "token", "verify", "confirm", "reset", "forgot", "password",
    "callback", "webhook", "events", "stream", "feed", "rss", "preview",
    "assets", "static", "public", "private", "secure", "internal",
    "v1", "v2", "v3", "v4", "graphql", "rest", "soap",
}


def _path_pattern(path: str) -> str:
    """Normalize a path to its structural pattern, stripping actual ID values."""
    p = re.sub(r'/(\d{1,12})(?=/|$|\?)', r'/{numeric_id}', path)
    p = re.sub(
        r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)',
        r'/{uuid}', p, flags=re.I,
    )
    p = re.sub(r'/([a-z0-9]{6,32})(?=/|$|\?)', r'/{hash_id}', p, flags=re.I)
    return p


def _is_likely_hash_id(path: str, match_value: str) -> bool:
    """Heuristic: is this short hash token an object ID or just a route/function name?

    Real hash IDs: abc123f, 7Hk3pQ, xK9mP2q  (mixed letters + digits)
    Route words:   stock, users, products, functions  (pure alpha, in a known set)
    """
    if _HASH_EXCLUSION_RE.search(path):
        return False
    if _ASSET_PATH_RE.search(path):
        return False

    val = match_value.lower()

    # Must contain at least one digit - pure-alpha segments are almost always route names
    if not any(c.isdigit() for c in val):
        return False

    # Must contain at least one letter - pure numbers already caught by _NUMERIC_ID_RE
    if not any(c.isalpha() for c in val):
        return False

    # Skip known route words even if they happen to have a digit (v2, h5, etc.)
    if val in _KNOWN_ROUTE_WORDS:
        return False

    return True


class AccessControlMapper(BaseSurfaceMapper):
    category = AttackCategory.ACCESS_CONTROL

    def map(self, result: ScanResult) -> List[SurfaceResult]:
        # Dedup by path pattern so /user/1 and /user/2 produce one candidate
        seen_patterns: set = set()

        for ep in result.endpoints:
            path   = ep.path or urlparse(ep.url).path or ""
            method = (ep.method or "GET").upper()

            params_found = []
            confidence   = ConfidenceLevel.LOW
            evidence     = []

            # 1. Numeric IDs in path
            if _NUMERIC_ID_RE.search(path):
                params_found.append("path:numeric_id")
                evidence.append(
                    f"Numeric ID in path: {path} - "
                    "Type: Horizontal privilege escalation (accessing another user's resource)"
                )
                confidence = ConfidenceLevel.HIGH if ep.auth_context and ep.auth_context.lower() not in ("", "none") else ConfidenceLevel.MEDIUM

            # 2. UUID in path
            if _UUID_RE.search(path):
                params_found.append("path:uuid")
                evidence.append(
                    f"UUID in path: {path} - "
                    "Type: Horizontal privilege escalation (accessing another user's resource)"
                )
                confidence = ConfidenceLevel.HIGH if ep.auth_context and ep.auth_context.lower() not in ("", "none") else ConfidenceLevel.MEDIUM

            # 3. Short hash ID in path (e.g. /share/abc123f, /post/7Hk3pQ)
            hash_match = _HASH_ID_RE.search(path)
            if hash_match and "path:numeric_id" not in params_found and "path:uuid" not in params_found:
                hash_val = hash_match.group(1)
                if _is_likely_hash_id(path, hash_val):
                    params_found.append("path:hash_id")
                    evidence.append(
                        f"Short hash/token ID in path: {path} - "
                        "Type: Horizontal privilege escalation (accessing another user's resource)"
                    )
                    # Hash IDs suggest opaque references - lower initial confidence
                    if confidence == ConfidenceLevel.LOW:
                        confidence = ConfidenceLevel.LOW  # keep LOW unless auth context boosts

            # 4. Path params named like IDs
            for pp in (ep.path_params or []):
                name = (pp.get("name") or "").lower()
                if name in _IDOR_PARAM_NAMES:
                    params_found.append(f"path_param:{name}")
                    path_param_evidence = (
                        f"Path parameter '{name}' matches object ID naming on {method} {ep.url} - "
                        "Type: Horizontal privilege escalation (accessing another user's resource)"
                    )
                    if method == "GET":
                        path_param_evidence += (
                            " | GET + path ID = classic BOLA: "
                            "swap the ID for another user's resource and check if data leaks"
                        )
                    elif method == "DELETE":
                        path_param_evidence += (
                            " | DELETE + path ID = resource deletion IDOR: "
                            "use another user's resource ID and confirm deletion is accepted"
                        )
                    elif method in ("PUT", "PATCH"):
                        path_param_evidence += (
                            " | PUT/PATCH + path ID = write IDOR: "
                            "modify another user's resource by substituting their ID"
                        )
                    evidence.append(path_param_evidence)
                    if ep.auth_context and ep.auth_context.lower() not in ("", "none"):
                        confidence = ConfidenceLevel.HIGH

            # 5. Query params named like IDs
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name in _IDOR_PARAM_NAMES:
                    params_found.append(f"query:{name}")
                    evidence.append(
                        f"Query parameter '{name}' matches object ID naming - "
                        "Type: Horizontal privilege escalation (accessing another user's resource)"
                    )
                    if confidence != ConfidenceLevel.HIGH:
                        confidence = ConfidenceLevel.MEDIUM

            # 6. Body fields that look like object references on PUT/PATCH
            if method in ("PUT", "PATCH"):
                for bf in (ep.body_fields or []):
                    name = (bf.get("name") or "").lower()
                    if name in _IDOR_BODY_REFS:
                        params_found.append(f"body:{name}")
                        evidence.append(
                            f"Body field '{name}' on {method} - may allow reassigning object ownership - "
                            "Type: Horizontal privilege escalation (accessing another user's resource)"
                        )
                        if confidence != ConfidenceLevel.HIGH:
                            confidence = ConfidenceLevel.MEDIUM

            # 7. IDOR-enabling request headers
            header_hits = []
            for h in (ep.request_headers or {}):
                if h.lower() in _IDOR_HEADER_NAMES:
                    header_hits.append(h)

            if header_hits:
                # Headers are standalone - emit a separate candidate
                header_evidence = [
                    f"Identity headers in request: {', '.join(header_hits)} - "
                    "Type: Horizontal via identity header manipulation",
                    "These headers may control which user/resource the request targets",
                ]
                auth_ctx = ep.auth_context or ""
                if auth_ctx and auth_ctx.lower() not in ("", "none"):
                    header_evidence.append(f"Auth context: {auth_ctx}")
                    header_conf = ConfidenceLevel.HIGH
                else:
                    header_conf = ConfidenceLevel.MEDIUM

                pat = _path_pattern(path)
                hdr_dedup = f"{method}:{pat}:headers:{','.join(sorted(header_hits))}"
                if hdr_dedup not in seen_patterns:
                    seen_patterns.add(hdr_dedup)
                    self._candidate(
                        endpoint     = ep,
                        surface_type = "IDOR via Request Header",
                        parameters   = [f"header:{h}" for h in header_hits],
                        confidence   = header_conf,
                        evidence     = header_evidence,
                        burp_notes   = _BURP_NOTES_HEADER,
                        auth_context = auth_ctx,
                    )
                    hdr_ev = [
                        Evidence(
                            evidence_type = EvidenceType.ROUTE_DECLARATION,
                            source        = "static",
                            asset         = ep.url or "",
                            context       = f"Identity headers on {method} {ep.url}",
                            details       = f"Headers: {', '.join(header_hits)} - may control which user/resource is accessed",
                        ),
                    ]
                    if auth_ctx and auth_ctx.lower() not in ("", "none"):
                        hdr_ev.append(Evidence(
                            evidence_type = EvidenceType.METADATA,
                            source        = "static",
                            asset         = ep.url or "",
                            context       = f"Auth context: {auth_ctx}",
                            details       = "Auth-gated endpoint - IDOR impact is higher",
                        ))
                    self._emit_evidence(
                        evidence     = hdr_ev,
                        surface_type = "IDOR via Request Header",
                        endpoint     = ep.url or "",
                        method       = method,
                        parameter    = f"header:{header_hits[0]}" if header_hits else "",
                        notes        = _BURP_NOTES_HEADER,
                    )

            if not params_found:
                # Skip to privilege escalation check even if no IDOR params found
                pass
            else:
                # Dedup by structural path pattern
                pat = _path_pattern(path)
                dedup_key = f"{method}:{pat}:{','.join(sorted(params_found))}"
                if dedup_key not in seen_patterns:
                    seen_patterns.add(dedup_key)

                    auth_ctx = ep.auth_context or ""
                    if auth_ctx and auth_ctx.lower() not in ("", "none"):
                        evidence.append(f"Auth context: {auth_ctx} (auth-gated resource)")

                    # Determine burp notes based on what we found
                    if "path:hash_id" in params_found and len(params_found) == 1:
                        burp = _BURP_NOTES_HASH
                    elif method == "GET" and any(
                        p.startswith("path_param:") or p == "path:numeric_id" or p == "path:uuid"
                        for p in params_found
                    ):
                        burp = _BURP_NOTES_GET_IDOR
                    else:
                        burp = _BURP_NOTES

                    self._candidate(
                        endpoint     = ep,
                        surface_type = "IDOR/BOLA",
                        parameters   = params_found,
                        confidence   = confidence,
                        evidence     = evidence,
                        burp_notes   = burp,
                        auth_context = auth_ctx,
                    )
                    bola_ev = []
                    for p in params_found:
                        bola_ev.append(Evidence(
                            evidence_type = EvidenceType.PARAMETER_SEMANTIC,
                            source        = "static",
                            asset         = ep.url or "",
                            context       = f"Object ID signal: {p} on {method} {ep.url}",
                            details       = f"Parameter '{p}' commonly references an owned resource",
                        ))
                    if auth_ctx and auth_ctx.lower() not in ("", "none"):
                        bola_ev.append(Evidence(
                            evidence_type = EvidenceType.METADATA,
                            source        = "static",
                            asset         = ep.url or "",
                            context       = f"Auth context: {auth_ctx}",
                            details       = "Auth-gated endpoint - IDOR impact is higher",
                        ))
                    self._emit_evidence(
                        evidence     = bola_ev,
                        surface_type = "IDOR/BOLA",
                        endpoint     = ep.url or "",
                        method       = method,
                        parameter    = params_found[0] if params_found else "",
                        notes        = burp,
                    )

            # 8. Privilege escalation - check query params, body fields on ALL methods
            privesc_hits = []
            privesc_evidence = []

            # Query params matching privilege escalation param names
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name in _PRIVESC_PARAMS:
                    privesc_hits.append(f"query:{name}")
                    privesc_evidence.append(
                        f"Query parameter '{name}' is a privilege escalation signal - "
                        "Type: Vertical privilege escalation (elevating own permissions)"
                    )

            # Body fields matching privilege escalation param names - ALL methods
            for bf in (ep.body_fields or []):
                name = (bf.get("name") or "").lower()
                if name in _PRIVESC_PARAMS:
                    privesc_hits.append(f"body:{name}")
                    privesc_evidence.append(
                        f"Body field '{name}' on {method} is a privilege escalation signal - "
                        "Type: Vertical privilege escalation (elevating own permissions)"
                    )

            if privesc_hits:
                # Confidence: HIGH for write methods (actively setting a value), MEDIUM for GET
                if method in ("PUT", "PATCH", "POST"):
                    privesc_conf = ConfidenceLevel.HIGH
                else:
                    privesc_conf = ConfidenceLevel.MEDIUM

                auth_ctx = ep.auth_context or ""
                if auth_ctx and auth_ctx.lower() not in ("", "none"):
                    privesc_evidence.append(f"Auth context: {auth_ctx} (auth-gated resource)")

                pat = _path_pattern(path)
                for hit in privesc_hits:
                    # param_name is the last part after the colon (query:role -> role)
                    param_name = hit.split(":", 1)[-1]
                    privesc_dedup = f"privesc:{method}:{pat}:{param_name}"
                    if privesc_dedup not in seen_patterns:
                        seen_patterns.add(privesc_dedup)
                        self._candidate(
                            endpoint     = ep,
                            surface_type = "Privilege Escalation",
                            parameters   = [hit],
                            confidence   = privesc_conf,
                            evidence     = [e for e in privesc_evidence if param_name in e],
                            burp_notes   = _BURP_NOTES_PRIVESC,
                            auth_context = auth_ctx,
                        )
                        privesc_ev = [
                            Evidence(
                                evidence_type = EvidenceType.PARAMETER_SEMANTIC,
                                source        = "static",
                                asset         = ep.url or "",
                                context       = f"Privilege escalation param '{param_name}' on {method} {ep.url}",
                                details       = f"Param '{param_name}' commonly controls role or permission level",
                            ),
                        ]
                        if auth_ctx and auth_ctx.lower() not in ("", "none"):
                            privesc_ev.append(Evidence(
                                evidence_type = EvidenceType.METADATA,
                                source        = "static",
                                asset         = ep.url or "",
                                context       = f"Auth context: {auth_ctx}",
                                details       = "Auth-gated endpoint - privilege escalation impact is higher",
                            ))
                        self._emit_evidence(
                            evidence     = privesc_ev,
                            surface_type = "Privilege Escalation",
                            endpoint     = ep.url or "",
                            method       = method,
                            parameter    = hit,
                            notes        = _BURP_NOTES_PRIVESC,
                        )

        return self._results
