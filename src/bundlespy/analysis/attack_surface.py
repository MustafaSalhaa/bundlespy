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

# Prototype pollution - dangerous keys that modify object prototypes
_PROTO_POLLUTION_KEYS: Set[str] = {_norm(x) for x in {
    "__proto__", "constructor", "prototype",
    "__defineGetter__", "__defineSetter__",
    "__lookupGetter__", "__lookupSetter__",
}}

# XXE - XML/SOAP content types and path markers
_XXE_CONTENT_TYPES: Set[str] = {
    "text/xml", "application/xml", "application/soap+xml",
    "application/xhtml+xml", "application/atom+xml",
}
_XXE_PATH_SEGS: Set[str] = {
    "soap", "wsdl", "xml", "xmlrpc", "xmlapi",
}

# Business logic - price/quantity params on checkout/cart endpoints
_PRICE_PARAM_HINTS: Set[str] = {_norm(x) for x in {
    "price", "amount", "total", "subtotal", "cost",
    "unitprice", "finalprice", "charge",
}}
_QTY_PARAM_HINTS: Set[str] = {_norm(x) for x in {
    "qty", "quantity", "count", "units",
}}
_COUPON_PARAM_HINTS: Set[str] = {_norm(x) for x in {
    "coupon", "couponcode", "promo", "promocode", "voucher",
    "vouchercode", "discount", "discountcode", "referral",
    "giftcard", "redeemcode",
}}
_CHECKOUT_PATH_SEGS: Set[str] = {
    "checkout", "cart", "order", "orders", "purchase",
    "payment", "pay", "billing", "basket",
}

# OAuth - redirect_uri and state patterns
_OAUTH_REDIRECT_HINTS: Set[str] = {_norm(x) for x in {
    "redirect_uri", "redirecturi", "redirect_url", "redirecturl",
    "callback_url", "callbackurl",
}}
_OAUTH_PATH_SEGS: Set[str] = {
    "oauth", "oauth2", "authorize", "auth", "connect",
    "callback", "token",
}

# Session fixation - session IDs in URL query/path params (not cookies)
_SESSION_PARAM_HINTS: Set[str] = {_norm(x) for x in {
    "sessionid", "session_id", "sid", "jsessionid",
    "phpsessid", "aspsessionid", "auth_token", "authtoken",
    "access_token", "accesstoken",
}}

# HTTP method override - header-based method override
_METHOD_OVERRIDE_HEADERS: Set[str] = {
    "x-http-method-override", "x-method-override",
    "x-http-method", "_method",
}

# Exposed sensitive files - backup/git/env path patterns
_BACKUP_EXTENSIONS: Set[str] = {
    ".bak", ".old", ".backup", ".swp", ".orig",
    ".copy", ".tmp", ".save", "~",
}
_GIT_EXPOSE_PATHS: Set[str] = {
    ".git", ".svn", ".hg", ".bzr", "cvs",
}
_ENV_EXPOSE_PATHS: Set[str] = {
    ".env", ".env.local", ".env.production", ".env.development",
    "config.json", "config.yaml", "config.yml",
    "secrets.yaml", "secrets.yml", "secrets.json",
    ".aws/credentials", "database.yml", "settings.py",
    "appsettings.json", "web.config",
}

# Deserialization - content-type patterns and param names
_DESER_CONTENT_TYPES: Set[str] = {
    "application/x-java-serialized-object",
    "application/x-www-form-urlencoded",  # PHP/Java serialize in POST body
}
_DESER_PARAM_HINTS: Set[str] = {_norm(x) for x in {
    "viewstate", "__viewstate", "__viewstategenerator",
    "serialized", "data", "payload", "object",
    "session", "token", "blob", "pickle", "jar",
}}
_DESER_VALUE_PATTERNS = [
    re.compile(r"^rO0[A-Za-z0-9+/=]{4,}"),   # Java serialized (base64 rO0)
    re.compile(r"^a:[0-9]+:\{"),              # PHP serialize array
    re.compile(r"^O:[0-9]+:\""),              # PHP serialize object
    re.compile(r"^gASV"),                     # Python pickle base64
    re.compile(r"^AAEAAAD"),                  # .NET BinaryFormatter base64
]

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
    has_file_path     = any(s in ("files", "file", "documents", "attachments") for s in segs)

    # "media", "images", "assets" alone are too common on CDN/static paths.
    # Only flag them when the method is mutating OR a file-operation param is present.
    has_generic_media_path = any(s in ("media", "images", "assets") for s in segs)
    has_file_param         = any(_norm_name(p) in _FILE_HINTS for _, p, _ in params)
    if has_generic_media_path and (_http_method_is_mutating(method) or has_file_param):
        has_file_path = True

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


# ── New detectors ─────────────────────────────────────────────────────────────

def _detect_prototype_pollution(
    ep, method: str, path: str,
    params: List[Tuple[str, str, Optional[str]]],
    sources: List[str], seen: Set[str],
) -> List[AttackSurfaceItem]:
    """Prototype pollution - __proto__, constructor, prototype in params."""
    items: List[AttackSurfaceItem] = []
    for location, pname, pvalue in params:
        norm = _norm_name(pname)
        if norm not in _PROTO_POLLUTION_KEYS:
            continue
        key = _dedup_key("PROTO_POLLUTION", path, pname, location, method)
        if key in seen:
            continue
        seen.add(key)
        base_confidence = 75  # any of these keys is almost certainly intentional
        confidence = min(base_confidence + _source_confidence_boost(sources), 92)
        items.append(AttackSurfaceItem(
            endpoint_url=ep.url,
            method=method,
            param_name=pname,
            vuln_class="PROTOTYPE_POLLUTION",
            reason=f"{location} param '{pname}': prototype-polluting key in request - object property injection surface",
            priority=_confidence_to_priority(confidence),
            source_file=getattr(ep, "source_file", "") or "",
            param_location=location,
            sub_class="PROTO_KEY_IN_REQUEST",
            confidence=confidence,
            status=SurfaceStatus.CANDIDATE,
            evidence_sources=list(sources),
            provenance=",".join(sources),
        ))
    return items


def _detect_xxe_surface(
    ep, method: str, path: str, segs: List[str],
    sources: List[str], seen: Set[str],
) -> Optional[AttackSurfaceItem]:
    """XXE - XML content-type endpoints and SOAP/XML path markers."""
    content_type = (getattr(ep, "content_type", "") or "").lower().strip()
    # Also check request_headers dict for Content-Type
    req_headers = getattr(ep, "request_headers", None) or {}
    if isinstance(req_headers, dict):
        ct_header = req_headers.get("Content-Type", "") or req_headers.get("content-type", "")
        if ct_header:
            content_type = ct_header.lower().strip()

    has_xml_ct   = any(ct in content_type for ct in _XXE_CONTENT_TYPES)
    # Check exact segment match OR segment contains an XXE keyword (e.g. service.wsdl, xmlrpc.php)
    has_xml_path = _path_contains_any(segs, _XXE_PATH_SEGS) or any(
        any(kw in seg for kw in _XXE_PATH_SEGS) for seg in segs
    )

    if not (has_xml_ct or has_xml_path):
        return None

    key = f"xxe:{method}:{path}"
    if key in seen:
        return None
    seen.add(key)

    base_confidence = 70 if has_xml_ct else 55
    if has_xml_ct and has_xml_path:
        base_confidence = 78
    confidence = min(base_confidence + _source_confidence_boost(sources), 90)

    reason = "XML content-type endpoint" if has_xml_ct else f"SOAP/XML path segment '/{segs[-1]}'"
    return AttackSurfaceItem(
        endpoint_url=ep.url,
        method=method,
        param_name="(xml body)",
        vuln_class="XXE",
        reason=f"{reason} - external entity injection surface",
        priority=_confidence_to_priority(confidence),
        source_file=getattr(ep, "source_file", "") or "",
        param_location="body",
        sub_class="XXE_CANDIDATE",
        confidence=confidence,
        status=SurfaceStatus.CANDIDATE,
        evidence_sources=list(sources),
        provenance=",".join(sources),
    )


def _detect_business_logic(
    ep, method: str, path: str, segs: List[str],
    params: List[Tuple[str, str, Optional[str]]],
    sources: List[str], seen: Set[str],
) -> List[AttackSurfaceItem]:
    """Price/quantity tampering, coupon abuse, negative value surface."""
    items: List[AttackSurfaceItem] = []
    on_checkout_path = _path_contains_any(segs, _CHECKOUT_PATH_SEGS)

    for location, pname, pvalue in params:
        norm = _norm_name(pname)

        sub_class      = ""
        base_confidence = 0
        reason_str     = ""

        if norm in _PRICE_PARAM_HINTS:
            sub_class = "PRICE_TAMPERING"
            base_confidence = 55 if on_checkout_path else 38
            reason_str = f"{location} param '{pname}': price/amount field - tampering and negative-value surface"
            # Negative value signal
            if pvalue and re.match(r"^-\d+", pvalue.strip()):
                base_confidence += 15
                reason_str += " (observed negative value)"
                sub_class = "NEGATIVE_VALUE"
        elif norm in _QTY_PARAM_HINTS and on_checkout_path:
            sub_class = "PRICE_TAMPERING"
            base_confidence = 52
            reason_str = f"{location} param '{pname}': quantity field on checkout - manipulation surface"
            if pvalue and re.match(r"^-\d+", pvalue.strip()):
                base_confidence += 12
                sub_class = "NEGATIVE_VALUE"
        elif norm in _COUPON_PARAM_HINTS:
            sub_class = "COUPON_ABUSE"
            base_confidence = 58 if on_checkout_path else 42
            reason_str = f"{location} param '{pname}': coupon/promo/discount code - abuse and stacking surface"
        else:
            continue

        key = _dedup_key("BUSINESS_LOGIC", path, pname, location, method)
        if key in seen:
            continue
        seen.add(key)

        confidence = min(base_confidence + _source_confidence_boost(sources), 88)
        items.append(AttackSurfaceItem(
            endpoint_url=ep.url,
            method=method,
            param_name=pname,
            vuln_class="BUSINESS_LOGIC",
            reason=reason_str,
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


def _detect_oauth_misconfig(
    ep, method: str, path: str, segs: List[str],
    params: List[Tuple[str, str, Optional[str]]],
    sources: List[str], seen: Set[str],
) -> List[AttackSurfaceItem]:
    """OAuth misconfig - redirect_uri without strict matching, missing state, implicit flow."""
    items: List[AttackSurfaceItem] = []
    on_oauth_path = _path_contains_any(segs, _OAUTH_PATH_SEGS)

    # Check for redirect_uri param
    for location, pname, pvalue in params:
        norm = _norm_name(pname)

        if norm in _OAUTH_REDIRECT_HINTS:
            key = _dedup_key("OAUTH_MISCONFIG", path, pname, location, method)
            if key in seen:
                continue
            seen.add(key)
            base_confidence = 65 if on_oauth_path else 48
            reason_str = f"{location} param '{pname}': OAuth redirect_uri - open redirect and authorization code interception surface"
            if pvalue and _RE_URL_VALUE.match(pvalue):
                base_confidence += 12
            confidence = min(base_confidence + _source_confidence_boost(sources), 88)
            items.append(AttackSurfaceItem(
                endpoint_url=ep.url,
                method=method,
                param_name=pname,
                vuln_class="OAUTH_MISCONFIG",
                reason=reason_str,
                priority=_confidence_to_priority(confidence),
                source_file=getattr(ep, "source_file", "") or "",
                param_location=location,
                sub_class="REDIRECT_URI_PARAM",
                confidence=confidence,
                status=SurfaceStatus.CANDIDATE,
                evidence_sources=list(sources),
                provenance=",".join(sources),
            ))

    # Missing state param on OAuth authorize endpoint - emit endpoint-level signal
    if on_oauth_path and "authorize" in segs:
        param_names_norm = {_norm_name(p) for _, p, _ in params}
        has_state = "state" in param_names_norm
        if not has_state:
            key = f"oauth_nostate:{method}:{path}"
            if key not in seen:
                seen.add(key)
                confidence = min(60 + _source_confidence_boost(sources), 82)
                items.append(AttackSurfaceItem(
                    endpoint_url=ep.url,
                    method=method,
                    param_name="(missing state param)",
                    vuln_class="OAUTH_MISCONFIG",
                    reason="OAuth authorize endpoint missing 'state' parameter - CSRF on authorization flow",
                    priority=_confidence_to_priority(confidence),
                    source_file=getattr(ep, "source_file", "") or "",
                    param_location="query",
                    sub_class="MISSING_STATE_PARAM",
                    confidence=confidence,
                    status=SurfaceStatus.CANDIDATE,
                    evidence_sources=list(sources),
                    provenance=",".join(sources),
                ))

    # Implicit flow (response_type=token)
    for location, pname, pvalue in params:
        if _norm_name(pname) == "responsetype" and pvalue and pvalue.lower() == "token":
            key = f"oauth_implicit:{method}:{path}"
            if key not in seen:
                seen.add(key)
                confidence = min(68 + _source_confidence_boost(sources), 85)
                items.append(AttackSurfaceItem(
                    endpoint_url=ep.url,
                    method=method,
                    param_name=pname,
                    vuln_class="OAUTH_MISCONFIG",
                    reason=f"response_type=token signals implicit OAuth flow - access token in URL fragment, no PKCE",
                    priority=_confidence_to_priority(confidence),
                    source_file=getattr(ep, "source_file", "") or "",
                    param_location=location,
                    sub_class="IMPLICIT_FLOW",
                    confidence=confidence,
                    status=SurfaceStatus.CANDIDATE,
                    evidence_sources=list(sources),
                    provenance=",".join(sources),
                ))
    return items


def _detect_session_fixation(
    ep, method: str, path: str,
    params: List[Tuple[str, str, Optional[str]]],
    sources: List[str], seen: Set[str],
) -> List[AttackSurfaceItem]:
    """Session fixation - session/auth tokens appearing in URL params (not cookies)."""
    items: List[AttackSurfaceItem] = []
    for location, pname, pvalue in params:
        # Only flag when token is in query or path - NOT body (body tokens are expected)
        if location == "body":
            continue
        norm = _norm_name(pname)
        if norm not in _SESSION_PARAM_HINTS:
            continue
        key = _dedup_key("SESSION_FIXATION", path, pname, location, method)
        if key in seen:
            continue
        seen.add(key)
        # URL-based session tokens are HIGH risk - they leak in logs, referrer, etc.
        base_confidence = 70 if location == "query" else 60
        confidence = min(base_confidence + _source_confidence_boost(sources), 88)
        items.append(AttackSurfaceItem(
            endpoint_url=ep.url,
            method=method,
            param_name=pname,
            vuln_class="SESSION_FIXATION",
            reason=f"{location} param '{pname}': session/auth token in URL - fixation, log exposure, referrer leak surface",
            priority=_confidence_to_priority(confidence),
            source_file=getattr(ep, "source_file", "") or "",
            param_location=location,
            sub_class="TOKEN_IN_URL",
            confidence=confidence,
            status=SurfaceStatus.CANDIDATE,
            evidence_sources=list(sources),
            provenance=",".join(sources),
        ))
    return items


def _detect_method_override(
    ep, method: str, path: str, segs: List[str],
    sources: List[str], seen: Set[str],
) -> Optional[AttackSurfaceItem]:
    """HTTP method override - X-HTTP-Method-Override accepted (PUT/DELETE via POST)."""
    req_headers = getattr(ep, "request_headers", None) or {}
    if not isinstance(req_headers, dict):
        return None

    # Check both header names and values for override signals
    header_keys_norm = {k.lower() for k in req_headers.keys()}
    has_override = any(h in header_keys_norm for h in _METHOD_OVERRIDE_HEADERS)

    # Also detect _method query/body param pattern (Rails, etc.)
    # We check params via a secondary pass only if not already seen
    if not has_override:
        # Check for _method in query params via request_headers hint
        # If explicitly listed as an accepted header, flag it
        return None

    key = f"method_override:{method}:{path}"
    if key in seen:
        return None
    seen.add(key)

    confidence = min(65 + _source_confidence_boost(sources), 85)
    return AttackSurfaceItem(
        endpoint_url=ep.url,
        method=method,
        param_name="(X-HTTP-Method-Override)",
        vuln_class="METHOD_OVERRIDE",
        reason="Endpoint accepts X-HTTP-Method-Override header - PUT/DELETE tunneled via POST, filter bypass surface",
        priority=_confidence_to_priority(confidence),
        source_file=getattr(ep, "source_file", "") or "",
        param_location="header",
        sub_class="METHOD_OVERRIDE_HEADER",
        confidence=confidence,
        status=SurfaceStatus.CANDIDATE,
        evidence_sources=list(sources),
        provenance=",".join(sources),
    )


def _detect_exposed_files(
    ep, method: str, path: str,
    sources: List[str], seen: Set[str],
) -> Optional[AttackSurfaceItem]:
    """Backup files, git exposure, environment file exposure via path patterns."""
    path_lower = path.lower()

    # Check for git/SVN/VCS exposure
    for marker in _GIT_EXPOSE_PATHS:
        if f"/{marker}" in path_lower or path_lower.startswith(marker):
            key = f"git_expose:{path}"
            if key in seen:
                return None
            seen.add(key)
            confidence = min(80 + _source_confidence_boost(sources), 95)
            return AttackSurfaceItem(
                endpoint_url=ep.url,
                method=method,
                param_name=f"({marker} exposure)",
                vuln_class="GIT_EXPOSURE",
                reason=f"VCS directory '{marker}' reachable via HTTP - source code and history disclosure",
                priority=_confidence_to_priority(confidence),
                source_file=getattr(ep, "source_file", "") or "",
                param_location="path",
                sub_class="VCS_EXPOSURE",
                confidence=confidence,
                status=SurfaceStatus.CANDIDATE,
                evidence_sources=list(sources),
                provenance=",".join(sources),
            )

    # Check for env/config file exposure
    for marker in _ENV_EXPOSE_PATHS:
        if path_lower.endswith(marker) or f"/{marker}" in path_lower:
            key = f"env_expose:{path}"
            if key in seen:
                return None
            seen.add(key)
            confidence = min(82 + _source_confidence_boost(sources), 95)
            return AttackSurfaceItem(
                endpoint_url=ep.url,
                method=method,
                param_name=f"({marker})",
                vuln_class="ENV_EXPOSURE",
                reason=f"Environment/config file '{marker}' reachable - secrets, credentials, database config disclosure",
                priority=_confidence_to_priority(confidence),
                source_file=getattr(ep, "source_file", "") or "",
                param_location="path",
                sub_class="ENV_FILE_EXPOSURE",
                confidence=confidence,
                status=SurfaceStatus.CANDIDATE,
                evidence_sources=list(sources),
                provenance=",".join(sources),
            )

    # Check for backup file extensions
    for ext in _BACKUP_EXTENSIONS:
        if path_lower.endswith(ext):
            key = f"backup_expose:{path}"
            if key in seen:
                return None
            seen.add(key)
            confidence = min(72 + _source_confidence_boost(sources), 90)
            return AttackSurfaceItem(
                endpoint_url=ep.url,
                method=method,
                param_name=f"(backup file {ext})",
                vuln_class="BACKUP_EXPOSURE",
                reason=f"Backup file with extension '{ext}' reachable - source code or data disclosure",
                priority=_confidence_to_priority(confidence),
                source_file=getattr(ep, "source_file", "") or "",
                param_location="path",
                sub_class="BACKUP_FILE",
                confidence=confidence,
                status=SurfaceStatus.CANDIDATE,
                evidence_sources=list(sources),
                provenance=",".join(sources),
            )

    return None


def _detect_deserialization(
    ep, method: str, path: str,
    params: List[Tuple[str, str, Optional[str]]],
    sources: List[str], seen: Set[str],
) -> Optional[AttackSurfaceItem]:
    """Deserialization - Java serialized objects, pickle, PHP serialize patterns."""
    content_type = (getattr(ep, "content_type", "") or "").lower().strip()
    req_headers = getattr(ep, "request_headers", None) or {}
    if isinstance(req_headers, dict):
        ct_header = req_headers.get("Content-Type", "") or req_headers.get("content-type", "")
        if ct_header:
            content_type = ct_header.lower().strip()

    has_java_ct = "java-serialized" in content_type or "x-java" in content_type

    # Check param values for serialized object patterns
    deser_param = None
    for location, pname, pvalue in params:
        norm = _norm_name(pname)
        if norm not in _DESER_PARAM_HINTS:
            continue
        if pvalue:
            for pat in _DESER_VALUE_PATTERNS:
                if pat.search(pvalue):
                    deser_param = (location, pname, pvalue)
                    break
        # ViewState is always suspicious regardless of value
        if norm in ("viewstate", "__viewstate", "__viewstategenerator"):
            deser_param = (location, pname, pvalue)
            break

    if not has_java_ct and deser_param is None:
        return None

    key = f"deser:{method}:{path}"
    if key in seen:
        return None
    seen.add(key)

    if deser_param:
        location, pname, _ = deser_param
        base_confidence = 72
        reason = f"{location} param '{pname}': serialized object pattern detected - deserialization RCE surface"
    else:
        pname = "(java serialized body)"
        base_confidence = 68
        reason = "Java-serialized content-type - deserialization attack surface"

    confidence = min(base_confidence + _source_confidence_boost(sources), 90)
    return AttackSurfaceItem(
        endpoint_url=ep.url,
        method=method,
        param_name=pname,
        vuln_class="DESERIALIZATION",
        reason=reason,
        priority=_confidence_to_priority(confidence),
        source_file=getattr(ep, "source_file", "") or "",
        param_location="body",
        sub_class="DESER_CANDIDATE",
        confidence=confidence,
        status=SurfaceStatus.CANDIDATE,
        evidence_sources=list(sources),
        provenance=",".join(sources),
    )


# Token storage key names - auth material that should not be in localStorage/sessionStorage
_TOKEN_STORAGE_KEYS: Set[str] = {_norm(x) for x in {
    "token", "access_token", "accesstoken", "refresh_token", "refreshtoken",
    "id_token", "idtoken", "jwt", "auth_token", "authtoken",
    "api_key", "apikey", "api_secret", "apisecret",
    "session", "session_token", "sessiontoken",
    "credentials", "credential", "secret", "private_key",
    "password", "passwd",
}}

# Regex: localStorage.setItem('key', ...) or sessionStorage.setItem('key', ...)
_RE_STORAGE_SETITEM = re.compile(
    r'(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*["\']([^"\']{1,80})["\']',
    re.IGNORECASE,
)
# Regex: localStorage['key'] = ... or sessionStorage["key"] = ...
_RE_STORAGE_BRACKET = re.compile(
    r'(?:localStorage|sessionStorage)\s*\[\s*["\']([^"\']{1,80})["\']\s*\]\s*=',
    re.IGNORECASE,
)


def _detect_token_storage(
    ep, method: str, path: str,
    sources: List[str], seen: Set[str],
) -> List[AttackSurfaceItem]:
    """
    Detect auth tokens written to localStorage or sessionStorage.
    Reads evidence from the endpoint's source_code or evidence field.
    localStorage/sessionStorage tokens are vulnerable to XSS exfiltration.
    """
    items: List[AttackSurfaceItem] = []

    # Pull source evidence - check evidence list, notes, and any attached source snippet
    evidence_text = ""
    for attr in ("evidence", "notes", "source_snippet", "raw_evidence"):
        val = getattr(ep, attr, None)
        if isinstance(val, str):
            evidence_text += val + "\n"
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    evidence_text += item + "\n"
                elif isinstance(item, dict):
                    evidence_text += str(item.get("snippet", "")) + "\n"

    if not evidence_text.strip():
        return items

    found_keys: List[Tuple[str, str]] = []  # (storage_type, key_name)

    for match in _RE_STORAGE_SETITEM.finditer(evidence_text):
        key_name = match.group(1)
        storage  = "localStorage" if "localStorage" in match.group(0) else "sessionStorage"
        norm_key = _norm(key_name)
        if norm_key in _TOKEN_STORAGE_KEYS or any(
            norm_key.startswith(pfx) for pfx in ("token", "auth", "jwt", "secret", "key", "cred")
        ):
            found_keys.append((storage, key_name))

    for match in _RE_STORAGE_BRACKET.finditer(evidence_text):
        key_name = match.group(1)
        storage  = "localStorage" if "localStorage" in match.group(0) else "sessionStorage"
        norm_key = _norm(key_name)
        if norm_key in _TOKEN_STORAGE_KEYS or any(
            norm_key.startswith(pfx) for pfx in ("token", "auth", "jwt", "secret", "key", "cred")
        ):
            found_keys.append((storage, key_name))

    for storage, key_name in found_keys:
        dedup_key = _dedup_key("TOKEN_STORAGE", path, key_name, storage, method)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # sessionStorage is slightly less severe (tab-scoped) but still XSS-exploitable
        base_confidence = 72 if storage == "localStorage" else 65
        confidence = min(base_confidence + _source_confidence_boost(sources), 88)

        items.append(AttackSurfaceItem(
            endpoint_url=ep.url,
            method=method,
            param_name=key_name,
            vuln_class="TOKEN_STORAGE",
            reason=(
                f"Auth material '{key_name}' written to {storage} - "
                "XSS can exfiltrate token; use HttpOnly cookie instead"
            ),
            priority=_confidence_to_priority(confidence),
            source_file=getattr(ep, "source_file", "") or "",
            param_location=storage,
            sub_class="INSECURE_TOKEN_STORAGE",
            confidence=confidence,
            status=SurfaceStatus.CANDIDATE,
            evidence_sources=list(sources),
            provenance=",".join(sources),
        ))

    return items


def _build_endpoint_field_index(endpoints: List) -> Dict[str, Set[str]]:
    """
    Build a map of {field_name -> set of endpoint URLs} from body/query params.
    Used for cross-endpoint IDOR correlation.
    """
    index: Dict[str, Set[str]] = {}
    for ep in endpoints:
        params = _collect_params(ep)
        for _, pname, _ in params:
            norm = _norm_name(pname)
            if norm not in index:
                index[norm] = set()
            index[norm].add(ep.url)
    return index


def _correlate_cross_endpoint_idor(
    endpoints: List,
    idor_items: List[AttackSurfaceItem],
    seen: Set[str],
) -> List[AttackSurfaceItem]:
    """
    Cross-endpoint IDOR correlation.

    Finds resource reference chains: endpoint A returns an ID field in its response
    (e.g. userId, orderId) and endpoint B accepts that same field name as a parameter.
    This pattern is a strong BOLA/IDOR signal - suggests you can enumerate B by
    harvesting IDs from A.

    We detect this statically using param name overlap across endpoints.
    Any param name that is an IDOR hint AND appears in multiple endpoints is flagged.
    """
    correlated: List[AttackSurfaceItem] = []

    # Build per-URL param name sets
    url_params: Dict[str, Set[str]] = {}
    for ep in endpoints:
        url  = getattr(ep, "url", "") or ""
        if not url:
            continue
        params = _collect_params(ep)
        url_params[url] = {_norm_name(p) for _, p, _ in params if _norm_name(p) in _IDOR_HINTS or _ends_with_id_suffix(_norm_name(p))}

    # Group endpoints by shared IDOR param names
    # param_name -> [url1, url2, ...]
    param_to_urls: Dict[str, List[str]] = {}
    for url, param_set in url_params.items():
        for p in param_set:
            if p not in param_to_urls:
                param_to_urls[p] = []
            param_to_urls[p].append(url)

    # Only flag when the same IDOR-hint param appears in 2+ endpoints
    # (single-endpoint IDOR is already covered by _detect_idor)
    ep_by_url = {getattr(ep, "url", ""): ep for ep in endpoints}

    for param_norm, urls in param_to_urls.items():
        if len(urls) < 2:
            continue

        # Sort for consistent key generation
        urls_sorted = sorted(urls)
        chain_key   = f"xidor:{param_norm}:{':'.join(urls_sorted[:3])}"
        if chain_key in seen:
            continue
        seen.add(chain_key)

        # Build confidence from chain length and source quality
        chain_len   = min(len(urls_sorted), 5)
        base_conf   = 45 + (chain_len - 2) * 8  # 45 for 2-endpoint, +8 per extra

        # Collect combined sources from all chained endpoints
        combined_sources: List[str] = []
        for url in urls_sorted[:5]:
            ep = ep_by_url.get(url)
            if ep:
                for s in _evidence_sources(ep):
                    if s not in combined_sources:
                        combined_sources.append(s)

        confidence = min(base_conf + _source_confidence_boost(combined_sources), 85)

        # Use the first endpoint as the anchor for the finding
        anchor_ep = ep_by_url.get(urls_sorted[0])
        if not anchor_ep:
            continue

        anchor_method = (getattr(anchor_ep, "method", None) or "GET").upper()
        src_file      = getattr(anchor_ep, "source_file", "") or ""

        # Unpack the normalized param name back to a readable form
        display_param = param_norm  # already normalized, but descriptive enough

        correlated.append(AttackSurfaceItem(
            endpoint_url=urls_sorted[0],
            method=anchor_method,
            param_name=display_param,
            vuln_class="IDOR_CHAIN",
            reason=(
                f"Param '{display_param}' shared across {chain_len} endpoints - "
                f"cross-endpoint object reference chain; IDs from one endpoint may "
                f"enumerate others: {', '.join(urls_sorted[1:3])}"
            ),
            priority=_confidence_to_priority(confidence),
            source_file=src_file,
            param_location="cross_endpoint",
            sub_class="CROSS_ENDPOINT_BOLA",
            confidence=confidence,
            status=SurfaceStatus.CANDIDATE,
            evidence_sources=combined_sources,
            provenance=",".join(combined_sources),
            notes=f"Chain ({chain_len} endpoints): " + " | ".join(urls_sorted[:5]),
        ))

    return correlated


def _detect_privesc_chain(
    ep, method: str, path: str, segs: List[str],
    params: List[Tuple[str, str, Optional[str]]],
    idor_items: List[AttackSurfaceItem],
    sources: List[str], seen: Set[str],
) -> Optional[AttackSurfaceItem]:
    """
    Privilege escalation chain - IDOR + privilege param on the same endpoint.
    Only fires when the endpoint already has at least one IDOR item AND
    at least one privilege-sensitive param.
    """
    if not idor_items:
        return None

    has_priv_param = any(
        _norm_name(p) in _PRIVILEGE_HINTS
        for _, p, _ in params
    )
    has_priv_path = _path_contains_any(segs, _PRIVILEGE_PATH_SEGS)

    if not (has_priv_param or has_priv_path):
        return None

    key = f"privesc_chain:{method}:{path}"
    if key in seen:
        return None
    seen.add(key)

    # This is a chained signal - inherently high value
    confidence = min(75 + _source_confidence_boost(sources) + _auth_context_boost(ep), 92)
    priv_signal = "privilege-sensitive path segment" if has_priv_path else "privilege param in body"
    idor_param = idor_items[0].param_name

    return AttackSurfaceItem(
        endpoint_url=ep.url,
        method=method,
        param_name=f"{idor_param} + privilege",
        vuln_class="PRIVESC_CHAIN",
        reason=f"IDOR param '{idor_param}' combined with {priv_signal} - chained object-level privilege escalation surface",
        priority=_confidence_to_priority(confidence),
        source_file=getattr(ep, "source_file", "") or "",
        param_location="mixed",
        sub_class="IDOR_PRIV_CHAIN",
        confidence=confidence,
        status=SurfaceStatus.CANDIDATE,
        evidence_sources=list(sources),
        provenance=",".join(sources),
    )


# ── Main analysis function ────────────────────────────────────────────────────

def analyze_attack_surface(
    endpoints: List,
    validation_results: Optional[Dict[str, Any]] = None,
) -> Dict:
    """
    Analyze discovered endpoints and return the security-relevant attack surface.

    Args:
        endpoints:          List of Endpoint objects to analyze.
        validation_results: Optional dict keyed by URL to ValidationResult objects
                            (from endpoint_validator.validation_results_by_url).
                            When provided, CANDIDATE items are promoted to VALIDATED
                            for any endpoint whose HTTP probe confirmed existence,
                            and CORS/cookie/sensitive-field findings are merged in.

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
    # New detectors
    proto_pollution:    List[AttackSurfaceItem] = []
    xxe_surface:        List[AttackSurfaceItem] = []
    business_logic:     List[AttackSurfaceItem] = []
    oauth_surface:      List[AttackSurfaceItem] = []
    session_fixation:   List[AttackSurfaceItem] = []
    method_override:    List[AttackSurfaceItem] = []
    exposed_files:      List[AttackSurfaceItem] = []
    deserialization:    List[AttackSurfaceItem] = []
    privesc_chain:      List[AttackSurfaceItem] = []
    token_storage:      List[AttackSurfaceItem] = []
    idor_chain:         List[AttackSurfaceItem] = []
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
    # New detector dedup sets
    seen_proto : Set[str] = set()
    seen_xxe   : Set[str] = set()
    seen_bizlog: Set[str] = set()
    seen_oauth : Set[str] = set()
    seen_sesfix: Set[str] = set()
    seen_methov: Set[str] = set()
    seen_expfil: Set[str] = set()
    seen_deser : Set[str] = set()
    seen_priesc: Set[str] = set()
    seen_tokst : Set[str] = set()
    seen_xidor : Set[str] = set()
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

            # ── Prototype pollution ───────────────────────────────────────────
            proto_pollution.extend(_detect_prototype_pollution(ep, method, path, params, sources, seen_proto))

            # ── XXE surface ───────────────────────────────────────────────────
            xxe_item = _detect_xxe_surface(ep, method, path, segs, sources, seen_xxe)
            if xxe_item:
                xxe_surface.append(xxe_item)

            # ── Business logic ────────────────────────────────────────────────
            business_logic.extend(_detect_business_logic(ep, method, path, segs, params, sources, seen_bizlog))

            # ── OAuth misconfig ───────────────────────────────────────────────
            oauth_surface.extend(_detect_oauth_misconfig(ep, method, path, segs, params, sources, seen_oauth))

            # ── Session fixation ──────────────────────────────────────────────
            session_fixation.extend(_detect_session_fixation(ep, method, path, params, sources, seen_sesfix))

            # ── Method override ───────────────────────────────────────────────
            mo_item = _detect_method_override(ep, method, path, segs, sources, seen_methov)
            if mo_item:
                method_override.append(mo_item)

            # ── Exposed files ─────────────────────────────────────────────────
            ef_item = _detect_exposed_files(ep, method, path, sources, seen_expfil)
            if ef_item:
                exposed_files.append(ef_item)

            # ── Deserialization ───────────────────────────────────────────────
            deser_item = _detect_deserialization(ep, method, path, params, sources, seen_deser)
            if deser_item:
                deserialization.append(deser_item)

            # ── Token storage (localStorage/sessionStorage with auth keys) ───────
            token_storage.extend(_detect_token_storage(ep, method, path, sources, seen_tokst))

            # ── Privilege escalation chain ────────────────────────────────────
            # Use already-collected IDOR items for this endpoint
            ep_idor_items = [it for it in idor if it.endpoint_url == ep.url]
            privesc_item = _detect_privesc_chain(ep, method, path, segs, params, ep_idor_items, sources, seen_priesc)
            if privesc_item:
                privesc_chain.append(privesc_item)

        except Exception as exc:
            # Log at WARNING so the user can see skipped endpoints - silent omission
            # is worse than noise in a recon tool.
            ep_url = getattr(ep, "url", "?")
            logger.warning("attack_surface: analysis error on %s: %s", ep_url, exc)
            analysis_errors.append({"url": ep_url, "error": str(exc)})
            continue

    # ── Cross-endpoint IDOR correlation (post-loop) ───────────────────────────
    # Run after all per-endpoint IDOR items are collected so the full param
    # index is populated. Only fires when a param name appears in 2+ endpoints.
    idor_chain.extend(_correlate_cross_endpoint_idor(endpoints, idor, seen_xidor))

    # ── Validation status promotion ───────────────────────────────────────────
    # If the caller provided HTTP probe results, promote CANDIDATE items to VALIDATED
    # for any URL that the probe confirmed exists. Also inject CORS/cookie/sensitive
    # field findings as new AttackSurfaceItems.
    if validation_results:
        all_items: List[AttackSurfaceItem] = (
            idor + injection + file_ops + ssrf + open_redirect + mass_assign +
            privilege_surface + graphql_surface + websocket_surface + infra_surface +
            import_export + payment_surface + proto_pollution + xxe_surface +
            business_logic + oauth_surface + session_fixation + method_override +
            exposed_files + deserialization + privesc_chain + token_storage + idor_chain
        )
        cors_items:    List[AttackSurfaceItem] = []
        cookie_items:  List[AttackSurfaceItem] = []
        sensfld_items: List[AttackSurfaceItem] = []
        seen_val_cors  : Set[str] = set()
        seen_val_cookie: Set[str] = set()
        seen_val_sensfld: Set[str] = set()

        for item in all_items:
            vr = validation_results.get(item.endpoint_url)
            if not vr:
                continue

            # Promote to VALIDATED when HTTP probe confirmed endpoint existence
            if getattr(vr, "validation_status", "") == "VALIDATED":
                if item.status == SurfaceStatus.CANDIDATE:
                    item.status = SurfaceStatus.VALIDATED
                    if "VALIDATED" not in item.evidence_sources:
                        item.evidence_sources.append("VALIDATED")
                    # Boost confidence slightly - real HTTP evidence beats static analysis
                    item.confidence = min(item.confidence + 10, 95)
                    item.priority   = _confidence_to_priority(item.confidence)

        # Emit CORS misconfig items from validation data
        for url, vr in validation_results.items():
            cors_issues = getattr(vr, "cors_issues", []) or []
            for issue in cors_issues:
                key = f"cors_validated:{url}:{issue[:40]}"
                if key in seen_val_cors:
                    continue
                seen_val_cors.add(key)
                confidence = 82  # live HTTP evidence makes this high confidence
                cors_items.append(AttackSurfaceItem(
                    endpoint_url=url,
                    method=getattr(vr, "method", "GET"),
                    param_name="(CORS header)",
                    vuln_class="CORS_MISCONFIG",
                    reason=issue,
                    priority=_confidence_to_priority(confidence),
                    source_file="",
                    param_location="header",
                    sub_class="CORS_VALIDATED",
                    confidence=confidence,
                    status=SurfaceStatus.VALIDATED,
                    evidence_sources=["VALIDATED", "HTTP_PROBE"],
                    provenance="HTTP_PROBE",
                ))

            # Emit cookie flag issues from validation data
            cookie_issues = getattr(vr, "cookie_issues", []) or []
            for issue in cookie_issues:
                key = f"cookie_validated:{url}:{issue[:40]}"
                if key in seen_val_cookie:
                    continue
                seen_val_cookie.add(key)
                confidence = 78
                cookie_items.append(AttackSurfaceItem(
                    endpoint_url=url,
                    method=getattr(vr, "method", "GET"),
                    param_name="(Set-Cookie)",
                    vuln_class="COOKIE_FLAGS",
                    reason=issue,
                    priority=_confidence_to_priority(confidence),
                    source_file="",
                    param_location="header",
                    sub_class="COOKIE_FLAGS_VALIDATED",
                    confidence=confidence,
                    status=SurfaceStatus.VALIDATED,
                    evidence_sources=["VALIDATED", "HTTP_PROBE"],
                    provenance="HTTP_PROBE",
                ))

            # Emit sensitive-field-in-response items from validation data
            sensitive_fields = getattr(vr, "sensitive_response_fields", []) or []
            for fld in sensitive_fields:
                key = f"sensfld_validated:{url}:{fld}"
                if key in seen_val_sensfld:
                    continue
                seen_val_sensfld.add(key)
                confidence = 80
                sensfld_items.append(AttackSurfaceItem(
                    endpoint_url=url,
                    method=getattr(vr, "method", "GET"),
                    param_name=fld,
                    vuln_class="SENSITIVE_DATA_EXPOSURE",
                    reason=f"Response body contains sensitive field '{fld}' - data exposure surface",
                    priority=_confidence_to_priority(confidence),
                    source_file="",
                    param_location="response_body",
                    sub_class="SENSITIVE_FIELD_IN_RESPONSE",
                    confidence=confidence,
                    status=SurfaceStatus.VALIDATED,
                    evidence_sources=["VALIDATED", "HTTP_PROBE"],
                    provenance="HTTP_PROBE",
                ))

    else:
        cors_items    = []
        cookie_items  = []
        sensfld_items = []

    # total_items: counts all AttackSurfaceItem-typed categories.
    # Legacy categories that contain raw endpoints (state_change, auth_surface,
    # admin_surface) are excluded to avoid double-counting.
    total_items = (
        len(idor) + len(injection) + len(file_ops)
        + len(ssrf) + len(open_redirect)
        + len(mass_assign) + len(graphql_surface) + len(websocket_surface)
        + len(privilege_surface) + len(infra_surface)
        + len(import_export) + len(payment_surface)
        + len(proto_pollution) + len(xxe_surface)
        + len(business_logic) + len(oauth_surface)
        + len(session_fixation) + len(method_override)
        + len(exposed_files) + len(deserialization)
        + len(privesc_chain) + len(token_storage)
        + len(idor_chain) + len(cors_items)
        + len(cookie_items) + len(sensfld_items)
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
        # Additive keys (first wave)
        "mass_assign":       mass_assign,
        "privilege_surface": privilege_surface,
        "graphql_surface":   graphql_surface,
        "websocket_surface": websocket_surface,
        "infra_surface":     infra_surface,
        "import_export":     import_export,
        "payment_surface":   payment_surface,
        # New detectors
        "proto_pollution":   proto_pollution,
        "xxe_surface":       xxe_surface,
        "business_logic":    business_logic,
        "oauth_surface":     oauth_surface,
        "session_fixation":  session_fixation,
        "method_override":   method_override,
        "exposed_files":     exposed_files,
        "deserialization":   deserialization,
        "privesc_chain":     privesc_chain,
        # New categories
        "token_storage":     token_storage,
        "idor_chain":        idor_chain,
        "cors_misconfig":    cors_items,
        "cookie_flags":      cookie_items,
        "sensitive_exposure": sensfld_items,
        "analysis_errors":   analysis_errors,
    }
