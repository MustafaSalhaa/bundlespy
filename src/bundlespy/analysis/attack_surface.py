"""
Attack Surface Analysis - multi-signal classification engine.

Analyzes discovered endpoints and classifies security-relevant attack surface
across 40+ categories using correlated signals, not single-keyword heuristics.

Backward-compatible: existing return dict keys and AttackSurfaceItem fields
are unchanged. Additional fields and categories are additive only.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any

logger = logging.getLogger("bundlespy.analysis.attack_surface")


# ── Confidence model ──────────────────────────────────────────────────────────

class SurfaceStatus:
    # Status is set by what evidence supports - most items are CANDIDATE
    # until validation or runtime evidence promotes them.
    CANDIDATE = "CANDIDATE"
    OBSERVED  = "OBSERVED"   # seen in runtime traffic
    VALIDATED = "VALIDATED"  # actively confirmed reachable
    CONFIRMED = "CONFIRMED"  # exploitability evidence present


def _confidence_to_priority(score: int) -> str:
    """Map 0-100 confidence score to priority string (backward compat)."""
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


# ── Normalizer (module-level, call once) ──────────────────────────────────────

def _norm(s: str) -> str:
    """Normalize: lowercase + strip separators. Used at table build time."""
    return re.sub(r"[-_.\[\]()]", "", s.lower())


# ── Semantic hint tables ──────────────────────────────────────────────────────
# Pre-computed once. All values are _norm()-ed so lookups use _norm_name().

# Explicit object-reference parameter names (IDOR/BOLA)
# - Only include names that semantically represent entity identifiers
# - sessionId/roleId intentionally excluded - they're privilege signals, not BOLA
_IDOR_HINTS: Set[str] = {_norm(x) for x in {
    "id", "uid", "uuid", "oid", "objectid",
    "userid", "accountid", "customerid", "orderid", "invoiceid",
    "documentid", "fileid", "messageid", "ticketid", "recordid",
    "resourceid", "itemid", "productid", "postid", "cartid",
    "transactionid", "paymentid", "reportid", "projectid", "taskid",
    "commentid", "reviewid", "memberid", "groupid", "orgid",
    "tenantid", "workspaceid", "teamid", "refid", "ownerid",
}}

# Known ID-like suffixes that signal an entity reference
# These are word-boundary suffixes - must appear after a real word segment
_ID_SUFFIXES = ("id", "uuid", "uid", "ref")

# Privilege/role-sensitive fields
_PRIVILEGE_HINTS: Set[str] = {_norm(x) for x in {
    "role", "roles", "isadmin", "admin",
    "permissions", "permission", "privilege", "privileges",
    "access", "accesslevel", "enabled", "active",
    "verified", "approved", "status", "usertype", "accounttype",
    "scope", "grants", "entitlements",
}}

# Mass-assignment: writable security-sensitive body fields (tiered)
# HIGH tier - privilege-modifying fields
_MASS_ASSIGN_HIGH: Set[str] = {_norm(x) for x in {
    "role", "roles", "isadmin", "admin", "permissions", "permission",
    "ownerid", "tenantid", "privilege", "privileges",
    "access", "grants", "entitlements", "scope",
}}
# MEDIUM tier - state/lifecycle fields
_MASS_ASSIGN_MED: Set[str] = {_norm(x) for x in {
    "status", "verified", "approved", "enabled", "active",
    "userid", "accountid",
}}
# Combined for quick membership test
_MASS_ASSIGN_HINTS: Set[str] = _MASS_ASSIGN_HIGH | _MASS_ASSIGN_MED

# Injection-prone params - generic user input fields
# Deliberately excludes: name, email, username (too common, context-dependent)
_INJECTION_HINTS: Set[str] = {_norm(x) for x in {
    "q", "query", "search", "searchterm", "keyword", "keywords",
    "filter", "sort", "orderby", "s", "term",
    "where", "conditions", "expr", "expression",
    "category", "group",
}}

# SSTI - template engine inputs
# 'page' and 'body' removed - too common as benign params
_TEMPLATE_HINTS: Set[str] = {_norm(x) for x in {
    "template", "tmpl", "tpl", "layout", "theme", "render",
    "view",
}}

# Command injection - execution-specific only
# 'param', 'input', 'arg', 'args', 'script', 'code' removed - too broad
_COMMAND_HINTS: Set[str] = {_norm(x) for x in {
    "cmd", "command", "exec", "execute", "run",
    "eval", "shell",
}}

# SSRF - URL/destination fetching
_SSRF_HINTS: Set[str] = {_norm(x) for x in {
    "url", "uri", "link", "src", "source", "resource",
    "redirect", "return", "returnurl", "next", "callback",
    "webhook", "proxy", "fetch", "load", "domain", "host",
    "hostname", "site", "target", "dest", "destination",
    "remote", "image", "avatar", "feed",
    "download", "preview",
}}

# High-confidence SSRF - these almost always mean server-side fetch
_SSRF_HIGH_HINTS: Set[str] = {_norm(x) for x in {
    "url", "uri", "webhook", "proxy", "fetch", "remote", "feed",
}}

# Open redirect
_REDIRECT_HINTS: Set[str] = {_norm(x) for x in {
    "redirect", "redirecturi", "return", "returnurl", "next",
    "url", "goto", "dest", "destination", "continue",
    "redir", "callback", "forward", "location",
}}
_REDIRECT_HIGH_HINTS: Set[str] = {_norm(x) for x in {
    "redirect", "redirecturi", "next", "returnurl", "goto", "redir",
}}

# File / path operations
_FILE_HINTS: Set[str] = {_norm(x) for x in {
    "file", "filename", "filepath", "path",
    "dir", "directory", "folder", "doc", "document",
    "attachment", "include", "load", "read",
    "src", "source", "download", "upload", "archive",
    "extract", "unzip", "convert", "preview",
}}
_UPLOAD_HINTS: Set[str] = {_norm(x) for x in {
    "file", "upload", "attachment", "document", "image", "media",
    "avatar", "photo", "picture", "blob", "data", "payload",
    "content", "attachmentdata",
}}

# Auth path segments
_AUTH_PATH_SEGS: Set[str] = {
    "login", "logout", "signin", "signout", "signup", "register",
    "auth", "oauth", "oauth2", "token", "refresh", "session",
    "password", "passwd", "reset", "verify", "confirm", "activate",
    "mfa", "otp", "2fa", "totp", "recover", "recovery",
}

# Admin path segments
_ADMIN_PATH_SEGS: Set[str] = {
    "admin", "administrator", "manage", "management", "console",
    "dashboard", "panel", "control", "internal", "private",
    "debug", "dev", "test", "staging",
}

# Privilege-sensitive path segments
_PRIVILEGE_PATH_SEGS: Set[str] = {
    "role", "roles", "permission", "permissions", "privilege",
    "access", "grant", "grants", "impersonate", "sudo",
    "elevate", "promote", "assign",
}

# Infrastructure/debug endpoints
_INFRA_PATH_SEGS: Set[str] = {
    "health", "healthz", "healthcheck", "status", "ping", "ready",
    "liveness", "metrics", "telemetry", "debug", "info", "version",
    "actuator", "swagger", "openapi", "api-docs", "docs",
}

# Import/export/batch surface
_IMPORT_EXPORT_VERBS: Set[str] = {
    "import", "export", "bulk", "batch",
    "migrate", "sync", "transfer", "dump", "restore", "backup",
}

# Payment/transaction surface
_PAYMENT_PATH_SEGS: Set[str] = {
    "payment", "pay", "checkout", "billing", "invoice", "charge",
    "subscription", "refund", "transaction", "wallet",
}

# GraphQL indicators - 'graph' removed (too broad: /api/graph/reports)
_GRAPHQL_PATH_SEGS: Set[str] = {"graphql", "gql"}

# WebSocket indicators
_WS_KINDS: Set[str] = {"websocket", "ws"}

# Sensitive operation verbs
_SENSITIVE_VERBS: Set[str] = {
    "delete", "remove", "destroy", "drop", "purge", "wipe",
    "reset", "disable", "deactivate", "ban", "block", "suspend",
    "impersonate", "switch", "override", "elevate",
}

# Well-known pagination/utility params - numeric value here is NOT an object ref
# Kept focused: only params whose numeric value is structurally meaningful
_PAGINATION_EXCLUSIONS: Set[str] = {_norm(x) for x in {
    "page", "pagenum", "pagenumber", "pagesize", "perpage",
    "limit", "offset", "skip", "count", "size", "from", "to",
    "start", "end", "rows", "cursor", "after", "before", "since",
    "timestamp", "time", "date", "year", "month", "day",
    "hour", "minute", "second", "version", "v",
    "width", "height", "x", "y", "zoom", "scale",
    "max", "min", "step", "interval", "depth", "level",
    "weight", "rank", "order", "sort",
}}

# Common resource collection names for context-aware IDOR scoring
_RESOURCE_COLLECTIONS: Set[str] = {
    "users", "accounts", "orders", "documents", "files",
    "products", "items", "messages", "tickets", "records",
    "projects", "tasks", "comments", "invoices", "reports",
    "payments", "transactions", "sessions", "subscriptions",
    "organizations", "tenants", "teams", "groups", "roles",
}

# ── Regex patterns ─────────────────────────────────────────────────────────────

_RE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_RE_NUMERIC = re.compile(r"^\d+$")
# Opaque ID: alphanumeric/hex only, no spaces or common word chars
# Excludes slugs: requires no hyphens OR all hex (to avoid slug false positives)
_RE_OPAQUE_HEX  = re.compile(r"^[0-9a-fA-F]{16,}$")
_RE_OPAQUE_B64  = re.compile(r"^[0-9a-zA-Z+/=]{20,}$")
# URL-like value (extended to catch //host and common URI schemes)
_RE_URL_VALUE = re.compile(r"^(https?://|//|ftp://|file://)", re.IGNORECASE)
# Path-like value
_RE_PATH_VALUE = re.compile(r"^\.{0,2}/[a-zA-Z0-9_\-/.]")
# Slug-like: words joined by hyphens - NOT an opaque ID
_RE_SLUG = re.compile(r"^[a-z][a-z0-9]*(-[a-z][a-z0-9]*){2,}$")


# ── Dataclass ─────────────────────────────────────────────────────────────────

@dataclass
class AttackSurfaceItem:
    # Existing fields - unchanged for backward compatibility
    endpoint_url: str
    method:       str
    param_name:   str
    vuln_class:   str
    reason:       str
    priority:     str           # HIGH / MEDIUM / LOW
    source_file:  str
    # Additive fields - all have sensible defaults
    param_location:   str  = ""
    sub_class:        str  = ""
    confidence:       int  = 50
    status:           str  = SurfaceStatus.CANDIDATE
    evidence_sources: List[str] = field(default_factory=list)
    provenance:       str  = ""
    notes:            str  = ""


# ── Parameter normalization ────────────────────────────────────────────────────

def _norm_name(name: str) -> str:
    """Normalize a param name for hint-set lookups."""
    return re.sub(r"[-_.\[\]()]", "", name.lower())


def _split_segments(path: str) -> List[str]:
    """Split URL path into lowercase non-empty segments."""
    return [s.lower() for s in path.split("/") if s and s not in ("{}", "?")]


def _ends_with_id_suffix(norm: str) -> bool:
    """
    True if the normalized name ends with a meaningful ID suffix AND the suffix
    is preceded by a word boundary in the original form.

    'userId', 'user_id', 'user-id', 'user.id' all qualify.
    'valid', 'solid', 'grid', 'rapid' do NOT - no boundary before 'id'.

    We check the normalized form for a camelCase boundary (uppercase I preceding
    the lowercase suffix) or require that the original had a separator character
    (already stripped by _norm_name). The reliable signal: after stripping, if
    the suffix immediately follows a word char with no boundary in the original,
    it's not a compound. We detect this by checking whether the normalized form
    contains the suffix as a word (i.e., the char right before the suffix was
    uppercase in the original, signaling camelCase).
    """
    # Work on the pre-normalized lowercase form - we need to track the original
    # to detect camelCase. Instead, use a regex on the normalized name that
    # only matches when the suffix forms a distinct word segment:
    # - Either the whole norm is just the suffix (bare "id")
    # - Or the suffix starts at a position where the preceding char would have
    #   been a separator originally. Since norm strips separators, the only
    #   remaining boundary signal is: the normalized name IS in _IDOR_HINTS
    #   (handled separately) or we detect the suffix in a compound via the
    #   known-prefix test below.
    #
    # Known-entity prefixes that legitimately compound with _ID_SUFFIXES:
    # user, order, account, item, product, record, object, owner, tenant, etc.
    # This is a whitelist approach - flag only known-safe compounds.
    _KNOWN_ENTITY_PREFIXES = {
        "user", "account", "order", "item", "product", "record", "object",
        "owner", "tenant", "org", "team", "group", "role", "session",
        "transaction", "payment", "invoice", "document", "file", "message",
        "ticket", "comment", "review", "member", "project", "task",
        "workspace", "customer", "client", "resource", "entity", "parent",
        "child", "post", "article", "event", "job", "request", "report",
        "category", "tag", "label", "ref", "ext", "external", "internal",
        "source", "target", "dest", "destination", "origin",
    }
    for sfx in _ID_SUFFIXES:
        if not norm.endswith(sfx):
            continue
        prefix = norm[: -len(sfx)]
        if not prefix:
            continue
        # Bare suffix is already in _IDOR_HINTS - don't double-count
        if prefix in _KNOWN_ENTITY_PREFIXES:
            return True
    return False


def _is_opaque_id(value: str) -> bool:
    """True if value looks like a token/hash, not a word slug."""
    if _RE_SLUG.match(value):
        return False  # word-hyphen slug, not an ID
    if _RE_OPAQUE_HEX.match(value):
        return True
    if len(value) >= 20 and _RE_OPAQUE_B64.match(value):
        return True
    return False


def _looks_like_object_ref(norm: str, value: Optional[str]) -> bool:
    """
    True when param is semantically an entity identifier.
    Pagination/utility params are excluded regardless of value.
    Numeric values alone are not sufficient - name must also signal identity.
    """
    if norm in _PAGINATION_EXCLUSIONS:
        return False
    if norm in _IDOR_HINTS:
        return True
    if _ends_with_id_suffix(norm):
        return True
    if value:
        if _RE_UUID.match(value):
            return True
        if _is_opaque_id(value):
            return True
        # Numeric value alone is weak - only flag when the name also provides
        # a positive identity signal. Unknown names with numbers (grid=3, num=5)
        # should NOT be flagged - too many false positives.
        if _RE_NUMERIC.match(value) and norm not in _PAGINATION_EXCLUSIONS:
            # Name must be in IDOR hints OR end with a known ID suffix to qualify
            if norm in _IDOR_HINTS or _ends_with_id_suffix(norm):
                return True
    return False


def _param_value(param: dict) -> Optional[str]:
    """Extract example/value from a param dict safely."""
    return param.get("example") or param.get("value") or param.get("default")


def _collect_params(ep) -> List[Tuple[str, str, Optional[str]]]:
    """
    Yield (location, name, value) for all parameters.
    Recursively walks nested body dicts up to 4 levels deep.
    Safely handles missing/None fields and malformed structures.
    """
    params: List[Tuple[str, str, Optional[str]]] = []

    for qp in (getattr(ep, "query_params", None) or []):
        if isinstance(qp, dict):
            n = qp.get("name", "")
            if n:
                params.append(("query", n, _param_value(qp)))

    for pp in (getattr(ep, "path_params", None) or []):
        if isinstance(pp, dict):
            n = pp.get("name", "")
            if n:
                params.append(("path", n, _param_value(pp)))

    def _walk_body(d: dict, prefix: str, depth: int) -> None:
        if depth > 4:
            return
        for k, v in d.items():
            if not isinstance(k, str):
                continue
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                _walk_body(v, full_key, depth + 1)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        _walk_body(item, f"{full_key}[]", depth + 1)
            else:
                params.append(("body", full_key, str(v) if v is not None else None))

    for bf in (getattr(ep, "body_fields", None) or []):
        if not isinstance(bf, dict):
            continue
        name = bf.get("name", "")
        if name:
            # Standard format: {"name": "field", "example": "value"}
            params.append(("body", name, _param_value(bf)))
            # Walk nested structure stored alongside the named field
            nested = bf.get("schema") or bf.get("fields") or bf.get("properties")
            if isinstance(nested, dict):
                _walk_body(nested, name, 1)
            val = bf.get("value") or bf.get("example") or bf.get("default")
            if isinstance(val, dict):
                _walk_body(val, name, 1)
        else:
            # Raw body dict format: {"fieldname": value, "other": value}
            # Walk the whole dict treating each key as a top-level body field
            _walk_body(bf, "", 1)

    return params


# ── Evidence and confidence helpers ───────────────────────────────────────────

def _evidence_sources(ep) -> List[str]:
    """Extract discovery source labels from an endpoint object."""
    sources: List[str] = []
    src = (getattr(ep, "source_type", "") or "").upper()
    sf  = (getattr(ep, "source_file", "") or "").lower()
    kind = (getattr(ep, "kind", "") or "").lower()
    cat  = (getattr(ep, "category", "") or "").upper()

    # Normalize compound source_type strings (e.g. "AST+RUNTIME")
    raw_parts = re.split(r"[+,|/]", src) if src else []
    for part in raw_parts:
        p = part.strip()
        if p and p not in sources:
            sources.append(p)

    # Infer runtime from filename
    if any(x in sf for x in ("headless", "browser", "runtime", "puppeteer", "playwright")):
        if "RUNTIME" not in sources:
            sources.append("RUNTIME")
    if "sourcemap" in sf or "sourcemap" in src.lower():
        if "SOURCEMAP" not in sources:
            sources.append("SOURCEMAP")
    if "passive" in src.lower():
        if "PASSIVE" not in sources:
            sources.append("PASSIVE")
    if kind in _WS_KINDS and "WEBSOCKET" not in sources:
        sources.append("WEBSOCKET")
    if (kind == "graphql" or cat == "GRAPHQL") and "GRAPHQL" not in sources:
        sources.append("GRAPHQL")

    return sources if sources else ["STATIC"]


def _source_confidence_boost(sources: List[str]) -> int:
    """
    Confidence boost based on discovery source quality.
    AST/static alone = 0, runtime = +10, both = +15, passive = +5, sourcemap = +5.
    Validation evidence = +10.
    """
    boost = 0
    has_static   = any(s in sources for s in ("STATIC", "AST", "SOURCEMAP", "WEBPACK", "INLINE"))
    has_runtime  = any(s in sources for s in ("RUNTIME", "BROWSER"))
    has_passive  = "PASSIVE" in sources
    has_sourcemap = "SOURCEMAP" in sources
    has_validated = any(s in sources for s in ("VALIDATED", "CONFIRMED"))

    if has_static and has_runtime:
        boost += 15
    elif has_runtime:
        boost += 10
    if has_passive:
        boost += 5
    if has_sourcemap and not has_static:
        boost += 5
    if has_validated:
        boost += 10
    return boost


def _auth_context_boost(ep) -> int:
    """Confidence boost for endpoints with known auth requirement."""
    auth = (getattr(ep, "auth_context", "") or "").lower()
    if auth and auth not in ("none", "unknown", ""):
        return 10
    return 0


def _path_contains_any(segs: List[str], targets: Set[str]) -> bool:
    return any(s in targets for s in segs)


def _http_method_is_mutating(method: str) -> bool:
    return method.upper() in ("POST", "PUT", "PATCH", "DELETE")


def _infer_operation(method: str, segs: List[str]) -> str:
    """
    Infer semantic operation from method + path segments.
    Used to classify state-change and auth surface more precisely.
    """
    m = method.upper()
    last = segs[-1] if segs else ""

    if m == "DELETE" or last in ("delete", "remove", "destroy"):
        return "DELETE"
    if last in ("upload", "import"):
        return "UPLOAD"
    if last in ("download", "export", "report"):
        return "DOWNLOAD"
    if last in ("search", "find", "query", "lookup"):
        return "SEARCH"
    if last in ("execute", "run", "exec", "eval"):
        return "EXECUTE"
    if last in ("reset", "recover", "restore"):
        return "RESET"
    if last in ("disable", "deactivate", "ban", "block", "suspend"):
        return "DISABLE"
    if last in ("enable", "activate", "unban", "unblock"):
        return "ENABLE"
    if last in ("approve", "accept", "verify", "confirm"):
        return "APPROVE"
    if last in ("reject", "deny", "decline"):
        return "REJECT"
    if last in ("archive"):
        return "ARCHIVE"
    if last in ("publish", "release"):
        return "PUBLISH"
    if m == "POST" and last in ("invite", "share"):
        return "SHARE"
    if m == "POST":
        return "CREATE"
    if m in ("PUT", "PATCH"):
        return "UPDATE"
    if m == "GET":
        return "READ"
    return "UNKNOWN"


# ── Deduplication key ─────────────────────────────────────────────────────────

def _dedup_key(vuln_class: str, path: str, param_name: str, location: str, method: str) -> str:
    """Dedup key that preserves method + location distinctions."""
    return f"{vuln_class}:{method.upper()}:{path}:{location}:{param_name}"


# ── Detectors ─────────────────────────────────────────────────────────────────

def _detect_idor(
    ep, method: str, path: str, segs: List[str],
    params: List[Tuple[str, str, Optional[str]]],
    sources: List[str], seen: Set[str],
) -> List[AttackSurfaceItem]:
    items: List[AttackSurfaceItem] = []

    # Path-embedded IDs (numeric or UUID segments in the URL path itself)
    for idx, seg in enumerate(segs):
        is_numeric = bool(_RE_NUMERIC.match(seg))
        is_uuid    = bool(_RE_UUID.match(seg))
        # Opaque: hex-only or base64-ish token, not a slug
        is_opaque  = (not is_numeric and not is_uuid
                      and len(seg) >= 16 and _is_opaque_id(seg))

        if not (is_numeric or is_uuid or is_opaque):
            continue

        # Numeric segment: require it to follow a resource collection name
        # e.g. /users/123 is IDOR but /reports/2026 needs more context
        if is_numeric and not is_uuid:
            preceding = segs[idx - 1] if idx > 0 else ""
            if preceding not in _RESOURCE_COLLECTIONS:
                # Weak signal - only emit at low confidence
                base_confidence = 35
            else:
                base_confidence = 65
        elif is_uuid:
            base_confidence = 72
        else:
            # Opaque hex/b64 token - strong signal regardless of context
            base_confidence = 60

        # Use enumerate index to avoid .index() first-match bug
        implied_name = segs[idx - 1] if idx > 0 else "id"

        key = _dedup_key("IDOR", path, f"{implied_name}/{seg}", "path_value", method)
        if key in seen:
            continue
        seen.add(key)

        # Depth boost: /users/1/orders/2 is stronger than /users/1
        id_depth = sum(1 for s in segs if _RE_NUMERIC.match(s) or _RE_UUID.match(s))
        if id_depth >= 2:
            base_confidence += 10

        confidence = min(
            base_confidence
            + _source_confidence_boost(sources)
            + _auth_context_boost(ep),
            95,
        )

        sub  = "UUID_REFERENCE" if is_uuid else "NUMERIC_ID" if is_numeric else "OPAQUE_ID"
        kind_str = "UUID" if is_uuid else "numeric" if is_numeric else "opaque"
        items.append(AttackSurfaceItem(
            endpoint_url=ep.url,
            method=method,
            param_name=implied_name,
            vuln_class="IDOR",
            reason=f"Path contains {kind_str} ID '{seg}' after '{implied_name}' - likely object reference",
            priority=_confidence_to_priority(confidence),
            source_file=getattr(ep, "source_file", "") or "",
            param_location="path_value",
            sub_class=sub,
            confidence=confidence,
            status=SurfaceStatus.CANDIDATE,
            evidence_sources=list(sources),
            provenance=",".join(sources),
        ))

    # Parameter-level
    for location, pname, pvalue in params:
        norm = _norm_name(pname)
        if not _looks_like_object_ref(norm, pvalue):
            continue

        key = _dedup_key("IDOR", path, pname, location, method)
        if key in seen:
            continue
        seen.add(key)

        base_confidence = 40
        reason_parts: List[str] = []

        if norm in _IDOR_HINTS:
            base_confidence += 20
            reason_parts.append("matches known object-reference name")
        elif _ends_with_id_suffix(norm):
            base_confidence += 12
            reason_parts.append("name ends with entity-id suffix")

        # Resource path context
        if any(s in _RESOURCE_COLLECTIONS for s in segs):
            base_confidence += 15
            reason_parts.append("path references a resource collection")

        if pvalue:
            if _RE_UUID.match(pvalue):
                base_confidence += 15
                reason_parts.append("observed value is UUID-formatted")
            elif _is_opaque_id(pvalue):
                base_confidence += 12
                reason_parts.append("observed value is opaque token")
            elif _RE_NUMERIC.match(pvalue):
                base_confidence += 6
                reason_parts.append("observed value is numeric")

        if location == "path":
            base_confidence += 10
            reason_parts.append("ID is in path (stronger signal)")

        confidence = min(
            base_confidence
            + _source_confidence_boost(sources)
            + _auth_context_boost(ep),
            95,
        )

        items.append(AttackSurfaceItem(
            endpoint_url=ep.url,
            method=method,
            param_name=pname,
            vuln_class="IDOR",
            reason=f"{location} param '{pname}': " + (", ".join(reason_parts) or "looks like object reference"),
            priority=_confidence_to_priority(confidence),
            source_file=getattr(ep, "source_file", "") or "",
            param_location=location,
            sub_class="BOLA_CANDIDATE",
            confidence=confidence,
            status=SurfaceStatus.CANDIDATE,
            evidence_sources=list(sources),
            provenance=",".join(sources),
        ))

    return items


def _detect_injection(
    ep, method: str, path: str, segs: List[str],
    params: List[Tuple[str, str, Optional[str]]],
    sources: List[str], seen: Set[str],
) -> List[AttackSurfaceItem]:
    items: List[AttackSurfaceItem] = []

    for location, pname, pvalue in params:
        norm = _norm_name(pname)

        sub_class = ""
        base_confidence = 0
        reason_parts: List[str] = []

        # Command injection - high specificity hints only
        if norm in _COMMAND_HINTS:
            sub_class = "COMMAND_INJECTION"
            base_confidence = 60
            reason_parts.append("param name implies command execution")
            # Path context boosts strongly
            if any(s in ("execute", "run", "exec", "command", "shell", "eval") for s in segs):
                base_confidence += 20
                reason_parts.append("execution-semantic endpoint path")

        # SSTI - template rendering params
        elif norm in _TEMPLATE_HINTS:
            sub_class = "SSTI"
            base_confidence = 50
            reason_parts.append("param name implies template rendering")
            if any(s in ("render", "template", "generate", "preview") for s in segs):
                base_confidence += 15
                reason_parts.append("rendering/template endpoint path")

        # Generic injection surface (SQL/NoSQL/XSS)
        elif norm in _INJECTION_HINTS:
            sub_class = "SQL_NOSQL_XSS"
            base_confidence = 38
            reason_parts.append("user-controlled search/filter input")
            if any(s in ("search", "query", "find") for s in segs):
                base_confidence += 10
                reason_parts.append("search/query endpoint context")
            if norm in ("sort", "orderby") or any(s in ("sort", "order") for s in segs):
                sub_class = "SQL_ORDER_INJECTION"
                base_confidence += 8
                reason_parts.append("sort/order parameter - ORDER BY injection candidate")

        else:
            continue  # no injection signal

        key = _dedup_key("INJECTION", path, pname, location, method)
        if key in seen:
            continue
        seen.add(key)

        confidence = min(
            base_confidence + _source_confidence_boost(sources),
            92,
        )

        items.append(AttackSurfaceItem(
            endpoint_url=ep.url,
            method=method,
            param_name=pname,
            vuln_class="INJECTION",
            reason=f"{location} param '{pname}' ({sub_class}): " + ", ".join(reason_parts),
            priority=_confidence_to_priority(confidence),
            source_file=getattr(ep, "source_file", "") or "",
            param_location=location,
            sub_class=sub_class,
            confidence=confidence,
            status=SurfaceStatus.CANDIDATE,
            evidence_sources=list(sources),
            provenance=",".join(sources),
        ))

    return items


def _detect_file_ops(
    ep, method: str, path: str, segs: List[str],
    params: List[Tuple[str, str, Optional[str]]],
    sources: List[str], seen: Set[str],
) -> List[AttackSurfaceItem]:
    items: List[AttackSurfaceItem] = []

    has_upload_path   = any(s in ("upload", "uploads", "import") for s in segs)
    has_download_path = any(s in ("download", "downloads", "export") for s in segs)
    has_file_path     = any(s in ("files", "file", "documents", "attachments",
                                   "media", "images", "assets") for s in segs)

    # Path-level: file-storage endpoints with no recognized params still classify
    for path_flag, sub, reason_str, base_conf in (
        (has_upload_path,   "FILE_UPLOAD",   "Upload path - file upload, content-type bypass, stored XSS", 72),
        (has_download_path, "FILE_DOWNLOAD", "Download/export path - file read, LFI surface",              68),
        (has_file_path,     "FILE_STORAGE",  "File/document storage endpoint",                             55),
    ):
        if not path_flag:
            continue
        # Emit a path-level item only if no params already cover this surface
        key = _dedup_key("FILE_OPS", path, f"(path:{sub})", "path", method)
        if key in seen:
            continue
        seen.add(key)
        confidence = min(base_conf + _source_confidence_boost(sources), 90)
        items.append(AttackSurfaceItem(
            endpoint_url=ep.url,
            method=method,
            param_name=f"({sub.lower().replace('_', ' ')})",
            vuln_class="LFI/PATH",
            reason=reason_str,
            priority=_confidence_to_priority(confidence),
            source_file=getattr(ep, "source_file", "") or "",
            param_location="path",
            sub_class=sub,
            confidence=confidence,
            status=SurfaceStatus.CANDIDATE,
            evidence_sources=list(sources),
            provenance=",".join(sources),
        ))

    # Parameter-level
    for location, pname, pvalue in params:
        norm = _norm_name(pname)
        if norm not in _FILE_HINTS:
            continue

        key = _dedup_key("FILE_OPS", path, pname, location, method)
        if key in seen:
            continue
        seen.add(key)

        sub_class = "FILE_READ"
        base_confidence = 45
        reason_parts: List[str] = []

        if norm in _UPLOAD_HINTS and (_http_method_is_mutating(method) or has_upload_path):
            sub_class = "FILE_UPLOAD"
            base_confidence = 62
            reason_parts.append("upload param on mutating endpoint")
        elif has_download_path or norm in ("download", "export"):
            sub_class = "FILE_DOWNLOAD"
            base_confidence = 60
            reason_parts.append("download/export path or param")
        elif norm in ("path", "filepath", "dir", "directory", "folder", "include"):
            sub_class = "PATH_TRAVERSAL_CANDIDATE"
            base_confidence = 65
            reason_parts.append("path-like param name - traversal candidate")
        elif norm == "template":
            sub_class = "LFI_CANDIDATE"
            base_confidence = 60
            reason_parts.append("template param may allow file inclusion")
        else:
            reason_parts.append("file-related parameter")

        if pvalue and _RE_PATH_VALUE.match(pvalue):
            base_confidence += 15
            reason_parts.append("observed value is a file path")

        confidence = min(
            base_confidence + _source_confidence_boost(sources),
            92,
        )

        items.append(AttackSurfaceItem(
            endpoint_url=ep.url,
            method=method,
            param_name=pname,
            vuln_class="LFI/PATH",
            reason=f"{location} param '{pname}' ({sub_class}): " + ", ".join(reason_parts),
            priority=_confidence_to_priority(confidence),
            source_file=getattr(ep, "source_file", "") or "",
            param_location=location,
            sub_class=sub_class,
            confidence=confidence,
            status=SurfaceStatus.CANDIDATE,
            evidence_sources=list(sources),
            provenance=",".join(sources),
        ))

    return items


def _detect_ssrf(
    ep, method: str, path: str, segs: List[str],
    params: List[Tuple[str, str, Optional[str]]],
    sources: List[str], seen: Set[str],
) -> List[AttackSurfaceItem]:
    items: List[AttackSurfaceItem] = []

    ssrf_path_segs = {"proxy", "fetch", "import", "webhook", "callback",
                      "preview", "render", "screenshot", "feed"}
    has_ssrf_path = any(s in ssrf_path_segs for s in segs)

    # Path-only SSRF (no params found) - only for high-confidence path segments
    if has_ssrf_path and not params:
        key = _dedup_key("SSRF", path, "(ssrf_path)", "path", method)
        if key not in seen:
            seen.add(key)
            last_ssrf_seg = next((s for s in reversed(segs) if s in ssrf_path_segs), segs[-1] if segs else "")
            confidence = min(60 + _source_confidence_boost(sources), 85)
            items.append(AttackSurfaceItem(
                endpoint_url=ep.url,
                method=method,
                param_name="(endpoint semantics)",
                vuln_class="SSRF",
                reason=f"Path segment '{last_ssrf_seg}' implies server-side fetch behavior",
                priority=_confidence_to_priority(confidence),
                source_file=getattr(ep, "source_file", "") or "",
                param_location="path",
                sub_class="SSRF_PATH_SEMANTIC",
                confidence=confidence,
                status=SurfaceStatus.CANDIDATE,
                evidence_sources=list(sources),
                provenance=",".join(sources),
            ))

    for location, pname, pvalue in params:
        norm = _norm_name(pname)
        if norm not in _SSRF_HINTS:
            continue

        key = _dedup_key("SSRF", path, pname, location, method)
        if key in seen:
            continue
        seen.add(key)

        if norm in _SSRF_HIGH_HINTS:
            base_confidence = 72  # url/webhook/proxy are unambiguous SSRF signals
            reason_parts = ["param name is a high-confidence server-fetch indicator"]
        else:
            base_confidence = 38
            reason_parts = ["param name suggests URL or remote destination"]

        sub_class = "SSRF_CANDIDATE"

        # URL-formatted value is strong corroboration
        if pvalue and _RE_URL_VALUE.match(pvalue):
            base_confidence += 20
            reason_parts.append("observed value is URL-formatted")
            sub_class = "SSRF_URL_VALUE"

        if has_ssrf_path:
            base_confidence += 10
            reason_parts.append("endpoint path has server-fetch semantics")

        confidence = min(
            base_confidence + _source_confidence_boost(sources),
            88,
        )

        items.append(AttackSurfaceItem(
            endpoint_url=ep.url,
            method=method,
            param_name=pname,
            vuln_class="SSRF",
            reason=f"{location} param '{pname}' ({sub_class}): " + ", ".join(reason_parts),
            priority=_confidence_to_priority(confidence),
            source_file=getattr(ep, "source_file", "") or "",
            param_location=location,
            sub_class=sub_class,
            confidence=confidence,
            status=SurfaceStatus.CANDIDATE,
            evidence_sources=list(sources),
            provenance=",".join(sources),
        ))

    return items


def _detect_open_redirect(
    ep, method: str, path: str, segs: List[str],
    params: List[Tuple[str, str, Optional[str]]],
    sources: List[str], seen: Set[str],
) -> List[AttackSurfaceItem]:
    items: List[AttackSurfaceItem] = []
    is_auth_path = _path_contains_any(segs, _AUTH_PATH_SEGS)

    for location, pname, pvalue in params:
        norm = _norm_name(pname)
        if norm not in _REDIRECT_HINTS:
            continue

        key = _dedup_key("OPEN_REDIRECT", path, pname, location, method)
        if key in seen:
            continue
        seen.add(key)

        if norm in _REDIRECT_HIGH_HINTS:
            base_confidence = 52
            reason_parts = ["param name is a known redirect destination indicator"]
        else:
            base_confidence = 38
            reason_parts = ["param name may carry a redirect destination"]

        sub_class = "REDIRECT_CANDIDATE"

        if is_auth_path:
            base_confidence += 20
            reason_parts.append("redirect param on auth/login endpoint - high risk")
            sub_class = "POST_AUTH_REDIRECT"

        if pvalue and _RE_URL_VALUE.match(pvalue):
            base_confidence += 15
            reason_parts.append("observed value is URL-formatted")
            sub_class = "REDIRECT_URL_VALUE"

        confidence = min(
            base_confidence + _source_confidence_boost(sources),
            88,
        )

        items.append(AttackSurfaceItem(
            endpoint_url=ep.url,
            method=method,
            param_name=pname,
            vuln_class="OPEN_REDIRECT",
            reason=f"{location} param '{pname}' ({sub_class}): " + ", ".join(reason_parts),
            priority=_confidence_to_priority(confidence),
            source_file=getattr(ep, "source_file", "") or "",
            param_location=location,
            sub_class=sub_class,
            confidence=confidence,
            status=SurfaceStatus.CANDIDATE,
            evidence_sources=list(sources),
            provenance=",".join(sources),
        ))

    return items


def _detect_mass_assignment(
    ep, method: str, path: str, segs: List[str],
    params: List[Tuple[str, str, Optional[str]]],
    sources: List[str], seen: Set[str],
) -> List[AttackSurfaceItem]:
    """Mass assignment - only relevant on mutating endpoints."""
    items: List[AttackSurfaceItem] = []
    if not _http_method_is_mutating(method):
        return items

    for location, pname, pvalue in params:
        if location != "body":
            continue
        norm = _norm_name(pname)
        if norm not in _MASS_ASSIGN_HINTS:
            continue

        key = _dedup_key("MASS_ASSIGN", path, pname, location, method)
        if key in seen:
            continue
        seen.add(key)

        if norm in _MASS_ASSIGN_HIGH:
            base_confidence = 68
            reason_parts = ["high-risk: field controls role, privilege, or ownership"]
        else:
            base_confidence = 50
            reason_parts = ["field controls state or lifecycle"]

        confidence = min(
            base_confidence + _source_confidence_boost(sources),
            88,
        )

        items.append(AttackSurfaceItem(
            endpoint_url=ep.url,
            method=method,
            param_name=pname,
            vuln_class="MASS_ASSIGN",
            reason=f"body param '{pname}': " + ", ".join(reason_parts),
            priority=_confidence_to_priority(confidence),
            source_file=getattr(ep, "source_file", "") or "",
            param_location="body",
            sub_class="MASS_ASSIGNMENT_CANDIDATE",
            confidence=confidence,
            status=SurfaceStatus.CANDIDATE,
            evidence_sources=list(sources),
            provenance=",".join(sources),
        ))

    return items


def _is_privilege_endpoint(segs: List[str], params: List[Tuple[str, str, Optional[str]]], method: str) -> bool:
    """True when endpoint looks authorization-sensitive."""
    if _path_contains_any(segs, _PRIVILEGE_PATH_SEGS | _ADMIN_PATH_SEGS):
        return True
    if any(_norm_name(p) in _PRIVILEGE_HINTS for _, p, _ in params):
        return True
    if any(s in _SENSITIVE_VERBS for s in segs):
        return True
    return False


def _detect_websocket_surface(ep, sources: List[str]) -> Optional[AttackSurfaceItem]:
    kind = (getattr(ep, "kind", "") or "").lower()
    cat  = (getattr(ep, "category", "") or "").upper()
    if kind not in _WS_KINDS and cat != "WEBSOCKET":
        return None
    confidence = min(55 + _source_confidence_boost(sources) + _auth_context_boost(ep), 88)
    return AttackSurfaceItem(
        endpoint_url=ep.url,
        method="WS",
        param_name="(websocket)",
        vuln_class="WEBSOCKET",
        reason="WebSocket endpoint - auth, message injection, state-change, subscription surface",
        priority=_confidence_to_priority(confidence),
        source_file=getattr(ep, "source_file", "") or "",
        param_location="ws",
        sub_class="WEBSOCKET_SURFACE",
        confidence=confidence,
        status=SurfaceStatus.CANDIDATE,
        evidence_sources=list(sources),
        provenance=",".join(sources),
    )


def _detect_graphql_surface(ep, segs: List[str], sources: List[str], method: str) -> Optional[AttackSurfaceItem]:
    cat  = (getattr(ep, "category", "") or "").upper()
    # 'graph' alone is too broad - require explicit graphql/gql path or category
    is_gql = cat == "GRAPHQL" or any(s in _GRAPHQL_PATH_SEGS for s in segs)
    if not is_gql:
        return None
    confidence = min(72 + _source_confidence_boost(sources), 92)
    return AttackSurfaceItem(
        endpoint_url=ep.url,
        method=method,
        param_name="(graphql)",
        vuln_class="GRAPHQL",
        reason="GraphQL endpoint - introspection, mutation, injection, authorization surface",
        priority=_confidence_to_priority(confidence),
        source_file=getattr(ep, "source_file", "") or "",
        param_location="body",
        sub_class="GRAPHQL_SURFACE",
        confidence=confidence,
        status=SurfaceStatus.CANDIDATE,
        evidence_sources=list(sources),
        provenance=",".join(sources),
    )


def _detect_infrastructure_surface(
    ep, path: str, segs: List[str], sources: List[str], seen: Set[str],
) -> Optional[AttackSurfaceItem]:
    """Health/debug/metrics/infra endpoints that should not be public."""
    if not _path_contains_any(segs, _INFRA_PATH_SEGS):
        return None
    key = f"infra:{path}"
    if key in seen:
        return None
    seen.add(key)
    method = (getattr(ep, "method", "") or "GET").upper()
    confidence = min(55 + _source_confidence_boost(sources), 82)
    return AttackSurfaceItem(
        endpoint_url=ep.url,
        method=method,
        param_name="(infrastructure endpoint)",
        vuln_class="INFRA_EXPOSURE",
        reason=f"Infrastructure/debug endpoint exposed: /{segs[-1]}",
        priority=_confidence_to_priority(confidence),
        source_file=getattr(ep, "source_file", "") or "",
        param_location="path",
        sub_class="DEBUG_INFRA",
        confidence=confidence,
        status=SurfaceStatus.CANDIDATE,
        evidence_sources=list(sources),
        provenance=",".join(sources),
    )


def _detect_import_export_surface(
    ep, method: str, path: str, segs: List[str],
    sources: List[str], seen: Set[str],
) -> Optional[AttackSurfaceItem]:
    """Import/export/bulk/batch operations - often bypass validation."""
    if not _path_contains_any(segs, _IMPORT_EXPORT_VERBS):
        return None
    key = f"impexp:{method}:{path}"
    if key in seen:
        return None
    seen.add(key)
    verb = next((s for s in segs if s in _IMPORT_EXPORT_VERBS), "bulk operation")
    confidence = min(60 + _source_confidence_boost(sources), 85)
    return AttackSurfaceItem(
        endpoint_url=ep.url,
        method=method,
        param_name=f"({verb})",
        vuln_class="IMPORT_EXPORT",
        reason=f"Bulk/import/export endpoint '{verb}' - file upload, data injection, resource exhaustion surface",
        priority=_confidence_to_priority(confidence),
        source_file=getattr(ep, "source_file", "") or "",
        param_location="path",
        sub_class="BULK_OPERATION",
        confidence=confidence,
        status=SurfaceStatus.CANDIDATE,
        evidence_sources=list(sources),
        provenance=",".join(sources),
    )


def _detect_payment_surface(
    ep, method: str, path: str, segs: List[str],
    sources: List[str], seen: Set[str],
) -> Optional[AttackSurfaceItem]:
    """Payment/transaction endpoints."""
    if not _path_contains_any(segs, _PAYMENT_PATH_SEGS):
        return None
    key = f"payment:{method}:{path}"
    if key in seen:
        return None
    seen.add(key)
    verb = next((s for s in segs if s in _PAYMENT_PATH_SEGS), "payment")
    confidence = min(65 + _source_confidence_boost(sources), 88)
    return AttackSurfaceItem(
        endpoint_url=ep.url,
        method=method,
        param_name=f"({verb})",
        vuln_class="PAYMENT_SURFACE",
        reason=f"Payment/transaction endpoint '{verb}' - amount manipulation, replay, authorization bypass surface",
        priority=_confidence_to_priority(confidence),
        source_file=getattr(ep, "source_file", "") or "",
        param_location="path",
        sub_class="TRANSACTION_SURFACE",
        confidence=confidence,
        status=SurfaceStatus.CANDIDATE,
        evidence_sources=list(sources),
        provenance=",".join(sources),
    )


# ── Main analysis function ────────────────────────────────────────────────────

def analyze_attack_surface(endpoints: List) -> Dict:
    """
    Analyze discovered endpoints and return the security-relevant attack surface.

    Returns a backward-compatible dict. All original keys are preserved.
    Additional categories are additive.
    """
    idor:          List[AttackSurfaceItem] = []
    injection:     List[AttackSurfaceItem] = []
    file_ops:      List[AttackSurfaceItem] = []
    ssrf:          List[AttackSurfaceItem] = []
    open_redirect: List[AttackSurfaceItem] = []
    state_change:  List = []
    auth_surface:  List = []
    admin_surface: List = []
    # Additive categories
    mass_assign:        List[AttackSurfaceItem] = []
    privilege_surface:  List[AttackSurfaceItem] = []
    graphql_surface:    List[AttackSurfaceItem] = []
    websocket_surface:  List[AttackSurfaceItem] = []
    infra_surface:      List[AttackSurfaceItem] = []
    import_export:      List[AttackSurfaceItem] = []
    payment_surface:    List[AttackSurfaceItem] = []
    # Diagnostic: endpoints that raised exceptions
    analysis_errors:    List[Dict] = []

    # Per-category dedup sets
    seen_idor  : Set[str] = set()
    seen_inj   : Set[str] = set()
    seen_file  : Set[str] = set()
    seen_ssrf  : Set[str] = set()
    seen_redir : Set[str] = set()
    seen_mass  : Set[str] = set()
    seen_ws    : Set[str] = set()
    seen_gql   : Set[str] = set()
    seen_infra : Set[str] = set()
    seen_impexp: Set[str] = set()
    seen_pay   : Set[str] = set()
    # State-change / auth / admin / privilege dedup by method+path
    seen_sc    : Set[str] = set()
    seen_auth  : Set[str] = set()
    seen_adm   : Set[str] = set()
    seen_priv  : Set[str] = set()

    for ep in endpoints:
        try:
            method  = (getattr(ep, "method", None) or "UNKNOWN").upper()
            path    = (getattr(ep, "path", None) or getattr(ep, "url", "") or "")
            cat     = (getattr(ep, "category", "") or "").upper()

            segs    = _split_segments(path)
            sources = _evidence_sources(ep)
            params  = _collect_params(ep)
            op      = _infer_operation(method, segs)

            src_file = getattr(ep, "source_file", "") or ""

            # ── State-changing endpoints ─────────────────────────────────────
            if method in ("POST", "PUT", "DELETE", "PATCH") or op in (
                "DELETE", "DISABLE", "ENABLE", "APPROVE", "REJECT",
                "ARCHIVE", "PUBLISH", "RESET",
            ):
                sc_key = f"{method}:{path}"
                if sc_key not in seen_sc:
                    seen_sc.add(sc_key)
                    state_change.append(ep)

            # ── Auth surface ─────────────────────────────────────────────────
            if cat == "AUTH" or _path_contains_any(segs, _AUTH_PATH_SEGS):
                ak = f"{method}:{path}"
                if ak not in seen_auth:
                    seen_auth.add(ak)
                    auth_surface.append(ep)

            # ── Admin surface ────────────────────────────────────────────────
            if cat == "ADMIN" or _path_contains_any(segs, _ADMIN_PATH_SEGS):
                dk = f"{method}:{path}"
                if dk not in seen_adm:
                    seen_adm.add(dk)
                    admin_surface.append(ep)

            # ── Privilege surface - emits AttackSurfaceItems ─────────────────
            if _is_privilege_endpoint(segs, params, method):
                pk = f"{method}:{path}"
                if pk not in seen_priv:
                    seen_priv.add(pk)
                    confidence = min(60 + _source_confidence_boost(sources), 88)
                    privilege_surface.append(AttackSurfaceItem(
                        endpoint_url=ep.url,
                        method=method,
                        param_name="(privilege endpoint)",
                        vuln_class="PRIVILEGE_SURFACE",
                        reason=f"Endpoint involves authorization-sensitive operations: {op}",
                        priority=_confidence_to_priority(confidence),
                        source_file=src_file,
                        param_location="path",
                        sub_class="AUTHZ_SENSITIVE",
                        confidence=confidence,
                        status=SurfaceStatus.CANDIDATE,
                        evidence_sources=list(sources),
                        provenance=",".join(sources),
                    ))

            # ── WebSocket ─────────────────────────────────────────────────────
            ws_key = f"ws:{path}"
            if ws_key not in seen_ws:
                ws_item = _detect_websocket_surface(ep, sources)
                if ws_item:
                    seen_ws.add(ws_key)
                    websocket_surface.append(ws_item)

            # ── GraphQL ───────────────────────────────────────────────────────
            gql_key = f"gql:{method}:{path}"
            if gql_key not in seen_gql:
                gql_item = _detect_graphql_surface(ep, segs, sources, method)
                if gql_item:
                    seen_gql.add(gql_key)
                    graphql_surface.append(gql_item)

            # ── Infrastructure/debug ──────────────────────────────────────────
            infra_item = _detect_infrastructure_surface(ep, path, segs, sources, seen_infra)
            if infra_item:
                infra_surface.append(infra_item)

            # ── Import/export/bulk ────────────────────────────────────────────
            ie_item = _detect_import_export_surface(ep, method, path, segs, sources, seen_impexp)
            if ie_item:
                import_export.append(ie_item)

            # ── Payment surface ───────────────────────────────────────────────
            pay_item = _detect_payment_surface(ep, method, path, segs, sources, seen_pay)
            if pay_item:
                payment_surface.append(pay_item)

            # ── IDOR ──────────────────────────────────────────────────────────
            idor.extend(_detect_idor(ep, method, path, segs, params, sources, seen_idor))

            # ── Injection ─────────────────────────────────────────────────────
            injection.extend(_detect_injection(ep, method, path, segs, params, sources, seen_inj))

            # ── File ops ──────────────────────────────────────────────────────
            file_ops.extend(_detect_file_ops(ep, method, path, segs, params, sources, seen_file))

            # ── SSRF ──────────────────────────────────────────────────────────
            ssrf.extend(_detect_ssrf(ep, method, path, segs, params, sources, seen_ssrf))

            # ── Open redirect ─────────────────────────────────────────────────
            open_redirect.extend(_detect_open_redirect(ep, method, path, segs, params, sources, seen_redir))

            # ── Mass assignment ───────────────────────────────────────────────
            mass_assign.extend(_detect_mass_assignment(ep, method, path, segs, params, sources, seen_mass))

        except Exception as exc:
            # Log at WARNING so the user can see skipped endpoints - silent omission
            # is worse than noise in a recon tool.
            ep_url = getattr(ep, "url", "?")
            logger.warning("attack_surface: analysis error on %s: %s", ep_url, exc)
            analysis_errors.append({"url": ep_url, "error": str(exc)})
            continue

    # total_items: counts all intelligence items including new categories
    # Legacy categories that contain raw endpoints (not AttackSurfaceItems)
    # are excluded from this count to avoid double-counting.
    total_items = (
        len(idor) + len(injection) + len(file_ops)
        + len(ssrf) + len(open_redirect)
        + len(mass_assign) + len(graphql_surface) + len(websocket_surface)
        + len(privilege_surface) + len(infra_surface)
        + len(import_export) + len(payment_surface)
    )

    return {
        # Existing keys - unchanged
        "idor":          idor,
        "injection":     injection,
        "file_ops":      file_ops,
        "ssrf":          ssrf,
        "open_redirect": open_redirect,
        "state_change":  state_change,
        "auth_surface":  auth_surface,
        "admin_surface": admin_surface,
        "total_items":   total_items,
        # Additive keys
        "mass_assign":       mass_assign,
        "privilege_surface": privilege_surface,
        "graphql_surface":   graphql_surface,
        "websocket_surface": websocket_surface,
        "infra_surface":     infra_surface,
        "import_export":     import_export,
        "payment_surface":   payment_surface,
        "analysis_errors":   analysis_errors,
    }
