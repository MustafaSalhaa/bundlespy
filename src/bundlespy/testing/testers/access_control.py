"""
AccessControlMapper - IDOR/BOLA surface candidate identification.
Pure static analysis of already-collected endpoint data. Zero HTTP requests.
"""
import re
from typing import List
from urllib.parse import urlparse

from .base import BaseSurfaceMapper
from ..models import SurfaceResult, AttackCategory, ConfidenceLevel
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

_BURP_NOTES = (
    "Test adjacent IDs (id-1, id+1, id+100). "
    "Try unauthenticated. "
    "Try other user session with same ID. "
    "Check if response content differs between sessions."
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
                evidence.append(f"Numeric ID in path: {path}")
                confidence = ConfidenceLevel.HIGH if ep.auth_context and ep.auth_context.lower() not in ("", "none") else ConfidenceLevel.MEDIUM

            # 2. UUID in path
            if _UUID_RE.search(path):
                params_found.append("path:uuid")
                evidence.append(f"UUID in path: {path}")
                confidence = ConfidenceLevel.HIGH if ep.auth_context and ep.auth_context.lower() not in ("", "none") else ConfidenceLevel.MEDIUM

            # 3. Short hash ID in path (e.g. /share/abc123f, /post/7Hk3pQ)
            hash_match = _HASH_ID_RE.search(path)
            if hash_match and "path:numeric_id" not in params_found and "path:uuid" not in params_found:
                hash_val = hash_match.group(1)
                if _is_likely_hash_id(path, hash_val):
                    params_found.append("path:hash_id")
                    evidence.append(f"Short hash/token ID in path: {path}")
                    # Hash IDs suggest opaque references - lower initial confidence
                    if confidence == ConfidenceLevel.LOW:
                        confidence = ConfidenceLevel.LOW  # keep LOW unless auth context boosts

            # 4. Path params named like IDs
            for pp in (ep.path_params or []):
                name = (pp.get("name") or "").lower()
                if name in _IDOR_PARAM_NAMES:
                    params_found.append(f"path_param:{name}")
                    evidence.append(f"Path parameter '{name}' matches object ID naming")
                    if ep.auth_context and ep.auth_context.lower() not in ("", "none"):
                        confidence = ConfidenceLevel.HIGH

            # 5. Query params named like IDs
            for qp in (ep.query_params or []):
                name = (qp.get("name") or "").lower()
                if name in _IDOR_PARAM_NAMES:
                    params_found.append(f"query:{name}")
                    evidence.append(f"Query parameter '{name}' matches object ID naming")
                    if confidence != ConfidenceLevel.HIGH:
                        confidence = ConfidenceLevel.MEDIUM

            # 6. Body fields that look like object references on PUT/PATCH
            if method in ("PUT", "PATCH"):
                for bf in (ep.body_fields or []):
                    name = (bf.get("name") or "").lower()
                    if name in _IDOR_BODY_REFS:
                        params_found.append(f"body:{name}")
                        evidence.append(f"Body field '{name}' on {method} - may allow reassigning object ownership")
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
                    f"Identity headers in request: {', '.join(header_hits)}",
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

            if not params_found:
                continue

            # Dedup by structural path pattern
            pat = _path_pattern(path)
            dedup_key = f"{method}:{pat}:{','.join(sorted(params_found))}"
            if dedup_key in seen_patterns:
                continue
            seen_patterns.add(dedup_key)

            auth_ctx = ep.auth_context or ""
            if auth_ctx and auth_ctx.lower() not in ("", "none"):
                evidence.append(f"Auth context: {auth_ctx} (auth-gated resource)")

            # Determine burp notes based on what we found
            if "path:hash_id" in params_found and len(params_found) == 1:
                burp = _BURP_NOTES_HASH
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

        return self._results
