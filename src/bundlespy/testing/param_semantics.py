"""
param_semantics.py - centralized parameter classification for attack surface analysis.

classify_param(name, value) is the single entry point. All mappers should import
from here instead of maintaining their own ad-hoc param name sets.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import FrozenSet, Optional


# -----------------------------------------------------------------
# Param types - what kind of thing does this param reference?
# -----------------------------------------------------------------
class ParamType:
    OBJECT_ID      = "OBJECT_ID"       # resource/entity identifiers - IDOR/BOLA
    FILE_PATH      = "FILE_PATH"       # file or directory references - path traversal / LFI
    URL            = "URL"             # full URL or URI values - SSRF / open redirect
    REDIRECT       = "REDIRECT"        # redirect/return destination - open redirect
    COMMAND        = "COMMAND"         # shell/exec operands - command injection
    TEMPLATE       = "TEMPLATE"        # render/template names - SSTI
    TENANT         = "TENANT"          # multi-tenant scope IDs - tenant isolation / IDOR
    AUTH_TOKEN     = "AUTH_TOKEN"      # CSRF tokens, session state - CSRF
    SEARCH_FILTER  = "SEARCH_FILTER"   # query/filter/search inputs - SQLi, LDAP, NoSQL
    PRIVILEGE      = "PRIVILEGE"       # role/permission controls - privilege escalation
    XML_BODY       = "XML_BODY"        # XML/SOAP body fields - XXE
    LDAP_IDENTITY  = "LDAP_IDENTITY"   # LDAP-specific identity fields
    GRAPHQL        = "GRAPHQL"         # GraphQL operation names and query params
    DESERIALIZE    = "DESERIALIZE"     # deserialization sinks - Java/PHP/Node
    WEBSOCKET      = "WEBSOCKET"       # WebSocket connection or message fields
    UNKNOWN        = "UNKNOWN"


# -----------------------------------------------------------------
# Signal strength - how strongly does the param name predict the type?
# -----------------------------------------------------------------
class ParamTier:
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


# -----------------------------------------------------------------
# Attack category labels - kept as strings to avoid circular imports
# -----------------------------------------------------------------
_CAT_PATH_TRAVERSAL  = "PATH_TRAVERSAL"
_CAT_SSRF            = "SSRF"
_CAT_OPEN_REDIRECT   = "OPEN_REDIRECT"
_CAT_CMD_INJECTION   = "INJECTION"
_CAT_SSTI            = "INJECTION"
_CAT_SQLI            = "INJECTION"
_CAT_LDAP            = "INJECTION"
_CAT_XXE             = "INJECTION"
_CAT_IDOR            = "ACCESS_CONTROL"
_CAT_PRIVESC         = "ACCESS_CONTROL"
_CAT_CSRF            = "CSRF"
_CAT_TENANT          = "ACCESS_CONTROL"
_CAT_GRAPHQL         = "INJECTION"
_CAT_DESERIALIZE     = "INJECTION"
_CAT_WEBSOCKET       = "INJECTION"


@dataclass
class ParamClassification:
    param_type:       str
    tier:             str
    attack_categories: FrozenSet[str]
    raw_confidence:   float  # 0.0-1.0 - base score hint for Evidence enrichment
    matched_name:     str    # the normalized name that triggered the match
    value_boosted:    bool = False  # True if value analysis upgraded the tier


# =================================================================
# Internal name sets - the single source of truth across all mappers
# =================================================================

# -- OBJECT_ID --
_OBJECT_ID_HIGH: FrozenSet[str] = frozenset({
    "id", "user_id", "account_id", "order_id", "item_id",
    "product_id", "report_id", "doc_id", "document_id",
    "file_id", "message_id", "record_id", "object_id",
    "uid", "resource_id", "entity_id", "invoice_id",
    "ticket_id", "post_id", "comment_id", "transaction_id",
    "payment_id", "subscription_id", "member_id",
    # body ref variants
    "owner_id", "created_by", "assigned_to", "author_id",
    "parent_id", "target_id", "subject_id", "referenced_id", "linked_id",
})

_OBJECT_ID_MEDIUM: FrozenSet[str] = frozenset({
    "uid", "user", "account", "record", "ref",
})

# -- FILE_PATH --
_FILE_PATH_HIGH: FrozenSet[str] = frozenset({
    "file", "filename", "path", "filepath", "dir", "directory",
    "folder", "doc", "document",
})

_FILE_PATH_MEDIUM: FrozenSet[str] = frozenset({
    "page", "template", "view", "include", "load", "read",
    "download", "export", "attachment", "resource",
})

_FILE_PATH_LOW: FrozenSet[str] = frozenset({
    "attachment", "upload", "src_file", "input_file", "asset", "image",
})

# Image/media param names - NOT path traversal, but may be SSRF if they accept URLs
# Kept separate to prevent false positive flood from image-heavy apps
_IMAGE_PARAMS: FrozenSet[str] = frozenset({
    "img", "photo", "pdf", "icon", "logo",
    "thumbnail", "avatar", "cover", "banner", "media",
})

# -- URL (SSRF candidates) --
_URL_HIGH: FrozenSet[str] = frozenset({
    "url", "uri", "callback", "webhook", "endpoint",
    "image_url", "avatar_url", "icon_url", "logo_url",
    "photo_url", "thumbnail_url", "cover_url",
    "feed_url", "rss_url", "api_endpoint", "api_url",
    "return_url", "redirect_url",
})

_URL_MEDIUM: FrozenSet[str] = frozenset({
    "redirect", "target", "src", "source", "dest", "destination",
    "remote", "proxy", "forward",
    "import", "export", "upload_url", "download_url",
    "attachment_url", "media_url", "resource",
})

_URL_LOW: FrozenSet[str] = frozenset({
    "link", "fetch", "load", "pull", "path", "host", "domain",
    "origin", "location", "address", "server", "base_url",
    # note: "file" excluded - FILE_PATH is the primary type for that name
})

# -- REDIRECT (open redirect - overlaps URL but intent differs) --
_REDIRECT_HIGH: FrozenSet[str] = frozenset({
    "redirect", "redirect_uri", "redirect_url", "redirecturi", "redirecturl",
    "next", "next_url", "nexturl",
    "return_url", "returnurl", "return_to", "returnto",
    "after_login", "afterlogin", "post_login_redirect",
    "callback_url", "callbackurl",
    "target_url", "targeturl",
    "login_redirect", "loginredirect",
    "success_url", "successurl",
    "checkout_url", "checkouturl",
})

_REDIRECT_MEDIUM: FrozenSet[str] = frozenset({
    "return", "destination", "dest",
    "goto", "go",
    "continue", "cont",
    "back", "backurl", "back_url",
    "forward", "fwd",
    "after", "then",
    "follow",
    "navigate", "nav",
    "cancel_url", "cancelurl",
    "exit_url", "exiturl",
    "checkout_redirect",
    "oauth_redirect",
    "landing",
    "rurl", "redir",
})

_REDIRECT_LOW: FrozenSet[str] = frozenset({
    "to", "url", "uri",
    "ref", "referrer",
    "href", "link",
    "location", "loc",
    "page",
})

# -- COMMAND --
_COMMAND_HIGH: FrozenSet[str] = frozenset({
    "cmd", "exec", "command", "run", "shell", "execute",
    "ping", "subprocess", "process", "script",
    "eval", "code",
    # note: "query" and "input" excluded - too generic; SEARCH_FILTER is the right home
})

# Value patterns that strongly suggest command injection intent in a param value
_COMMAND_VALUE_SIGNALS: tuple = (";", "&&", "||", "|", "`", "$(",  "$(", "%0a", "%0d%0a")

# -- TEMPLATE (SSTI) --
_TEMPLATE_HIGH: FrozenSet[str] = frozenset({
    "template", "render", "layout", "theme",
    "body_template", "email_template", "html_template",
    "subject_template", "message_template", "tpl",
})

_TEMPLATE_MEDIUM: FrozenSet[str] = frozenset({
    "view", "format", "style", "page", "content", "text",
})

# -- GRAPHQL params --
_GRAPHQL_HIGH: FrozenSet[str] = frozenset({
    "operationname",
    "persistedquery", "extensions",
})

_GRAPHQL_MEDIUM: FrozenSet[str] = frozenset({
    "variables", "operation", "mutation",
})

# -- DESERIALIZE (deserialization sinks) --
_DESERIALIZE_HIGH: FrozenSet[str] = frozenset({
    "serialized", "jndi", "rmi_object", "java_object",
    "ois_payload", "serialized_object", "b64_object",
    "viewstate", "__viewstate", "__eventvalidation",
    "ro0", "deserialize", "object_data",
})

_DESERIALIZE_MEDIUM: FrozenSet[str] = frozenset({
    "state", "session_data", "cached_obj", "encoded_obj",
    "pickle", "marshal", "snapshot",
})

# -- WEBSOCKET params --
_WEBSOCKET_HIGH: FrozenSet[str] = frozenset({
    "ws_url", "socket_url", "ws_endpoint", "websocket_url",
    "wss_url", "socket_endpoint",
})

# -- TENANT --
_TENANT_HIGH: FrozenSet[str] = frozenset({
    "group_id", "org_id", "organization_id", "tenant_id",
    "customer_id", "client_id", "team_id", "workspace_id",
    "company_id", "account_id", "site_id", "store_id",
})

# -- AUTH_TOKEN (CSRF signals) --
_AUTH_TOKEN_HIGH: FrozenSet[str] = frozenset({
    "csrf", "_token", "authenticity_token", "csrfmiddlewaretoken",
    "xsrf_token", "csrf_token", "_csrf",
})

# -- SEARCH_FILTER (injection: SQLi, NoSQL) --
_SEARCH_HIGH: FrozenSet[str] = frozenset({
    "id", "user", "user_id", "name", "email", "search", "username",
    "password", "login", "uid", "pid",
})

_SEARCH_MEDIUM: FrozenSet[str] = frozenset({
    "filter", "category", "sort", "order", "page", "limit",
    "where", "query", "select", "table", "column", "field",
    "key", "value", "type", "status", "role", "group",
    # search body fields (also injection vectors)
    "search", "query", "q", "filter",
})

# -- PRIVILEGE --
_PRIVILEGE_HIGH: FrozenSet[str] = frozenset({
    "role", "is_admin", "admin", "privilege", "privileges",
    "permission", "permissions", "group", "access_level",
    "user_type", "account_type", "plan", "tier", "scope",
    "authority", "can_admin", "superuser", "is_superuser",
    "is_staff", "is_moderator", "elevation",
})

# -- XML_BODY (XXE) --
_XML_BODY_HIGH: FrozenSet[str] = frozenset({
    "xml", "data", "payload", "content", "body", "document",
    "input", "request", "soap", "envelope",
})

# -- LDAP_IDENTITY --
_LDAP_HIGH: FrozenSet[str] = frozenset({
    "cn", "dn", "ldap", "samaccountname", "userprincipalname",
})

_LDAP_MEDIUM: FrozenSet[str] = frozenset({
    "username", "user", "login", "uid", "email", "mail",
})


# =================================================================
# Value-based boosters - file extensions in param values
# =================================================================
_HIGH_VALUE_EXTENSIONS: FrozenSet[str] = frozenset({
    ".php", ".asp", ".aspx", ".jsp", ".txt", ".log", ".conf",
    ".ini", ".bak", ".xml", ".yaml", ".yml", ".env",
})

_URL_SCHEMES: tuple = ("http://", "https://", "ftp://", "//")


def _value_has_file_extension(value: str) -> bool:
    v = value.lower().strip()
    for ext in _HIGH_VALUE_EXTENSIONS:
        if v.endswith(ext):
            return True
    return False


def _value_looks_like_url(value: str) -> bool:
    v = value.lower().strip()
    return any(v.startswith(s) for s in _URL_SCHEMES)


# =================================================================
# Classification lookup tables (priority order matters)
# =================================================================

# Each entry: (frozenset_of_names, ParamType, ParamTier, raw_confidence, categories)
_LOOKUP: list = [
    # COMMAND - highest priority, narrow name set, unambiguous intent
    (_COMMAND_HIGH, ParamType.COMMAND, ParamTier.HIGH, 0.90, frozenset({_CAT_CMD_INJECTION})),

    # DESERIALIZE - very high signal, narrow set
    (_DESERIALIZE_HIGH, ParamType.DESERIALIZE, ParamTier.HIGH, 0.90, frozenset({_CAT_DESERIALIZE})),
    (_DESERIALIZE_MEDIUM, ParamType.DESERIALIZE, ParamTier.MEDIUM, 0.55, frozenset({_CAT_DESERIALIZE})),

    # TEMPLATE / SSTI
    (_TEMPLATE_HIGH, ParamType.TEMPLATE, ParamTier.HIGH, 0.80, frozenset({_CAT_SSTI})),
    (_TEMPLATE_MEDIUM, ParamType.TEMPLATE, ParamTier.MEDIUM, 0.45, frozenset({_CAT_SSTI})),

    # LDAP identity - before generic search because cn/dn are unambiguous
    (_LDAP_HIGH, ParamType.LDAP_IDENTITY, ParamTier.HIGH, 0.85, frozenset({_CAT_LDAP})),
    (_LDAP_MEDIUM, ParamType.LDAP_IDENTITY, ParamTier.MEDIUM, 0.50, frozenset({_CAT_LDAP})),

    # AUTH_TOKEN / CSRF
    (_AUTH_TOKEN_HIGH, ParamType.AUTH_TOKEN, ParamTier.HIGH, 0.80, frozenset({_CAT_CSRF})),

    # PRIVILEGE escalation
    (_PRIVILEGE_HIGH, ParamType.PRIVILEGE, ParamTier.HIGH, 0.85, frozenset({_CAT_PRIVESC})),

    # TENANT isolation
    (_TENANT_HIGH, ParamType.TENANT, ParamTier.HIGH, 0.80, frozenset({_CAT_TENANT})),

    # WEBSOCKET endpoint params
    (_WEBSOCKET_HIGH, ParamType.WEBSOCKET, ParamTier.HIGH, 0.80, frozenset({_CAT_WEBSOCKET})),

    # GRAPHQL operation params - check before generic search to avoid false positives
    (_GRAPHQL_HIGH, ParamType.GRAPHQL, ParamTier.HIGH, 0.75, frozenset({_CAT_GRAPHQL})),
    (_GRAPHQL_MEDIUM, ParamType.GRAPHQL, ParamTier.MEDIUM, 0.50, frozenset({_CAT_GRAPHQL})),

    # REDIRECT (check before URL since redirect names are more specific)
    (_REDIRECT_HIGH, ParamType.REDIRECT, ParamTier.HIGH, 0.85, frozenset({_CAT_OPEN_REDIRECT})),
    (_REDIRECT_MEDIUM, ParamType.REDIRECT, ParamTier.MEDIUM, 0.55, frozenset({_CAT_OPEN_REDIRECT})),
    (_REDIRECT_LOW, ParamType.REDIRECT, ParamTier.LOW, 0.25, frozenset({_CAT_OPEN_REDIRECT})),

    # URL - SSRF candidates
    (_URL_HIGH, ParamType.URL, ParamTier.HIGH, 0.85, frozenset({_CAT_SSRF})),
    (_URL_MEDIUM, ParamType.URL, ParamTier.MEDIUM, 0.55, frozenset({_CAT_SSRF})),
    (_URL_LOW, ParamType.URL, ParamTier.LOW, 0.25, frozenset({_CAT_SSRF})),

    # FILE_PATH - path traversal / LFI (image names excluded - use _IMAGE_PARAMS if needed)
    (_FILE_PATH_HIGH, ParamType.FILE_PATH, ParamTier.HIGH, 0.85, frozenset({_CAT_PATH_TRAVERSAL})),
    (_FILE_PATH_MEDIUM, ParamType.FILE_PATH, ParamTier.MEDIUM, 0.55, frozenset({_CAT_PATH_TRAVERSAL})),
    (_FILE_PATH_LOW, ParamType.FILE_PATH, ParamTier.LOW, 0.30, frozenset({_CAT_PATH_TRAVERSAL, _CAT_SSRF})),

    # XML_BODY - XXE
    (_XML_BODY_HIGH, ParamType.XML_BODY, ParamTier.HIGH, 0.70, frozenset({_CAT_XXE})),

    # OBJECT_ID - IDOR/BOLA
    (_OBJECT_ID_HIGH, ParamType.OBJECT_ID, ParamTier.HIGH, 0.80, frozenset({_CAT_IDOR})),
    (_OBJECT_ID_MEDIUM, ParamType.OBJECT_ID, ParamTier.MEDIUM, 0.50, frozenset({_CAT_IDOR})),

    # SEARCH_FILTER - injection (broadest, lowest priority)
    (_SEARCH_HIGH, ParamType.SEARCH_FILTER, ParamTier.HIGH, 0.70, frozenset({_CAT_SQLI})),
    (_SEARCH_MEDIUM, ParamType.SEARCH_FILTER, ParamTier.MEDIUM, 0.40, frozenset({_CAT_SQLI})),
]

_UNKNOWN_CLASSIFICATION = ParamClassification(
    param_type        = ParamType.UNKNOWN,
    tier              = ParamTier.LOW,
    attack_categories = frozenset(),
    raw_confidence    = 0.0,
    matched_name      = "",
)


# =================================================================
# Public API
# =================================================================

def classify_param(name: str, value: str = "") -> ParamClassification:
    """
    Classify a parameter by name and optional example value.

    Returns a ParamClassification with the inferred type, signal tier,
    attack categories, and a raw_confidence hint (0.0-1.0) that callers
    can use to enrich Evidence objects before scoring.

    Name lookup is case-insensitive. Value analysis can boost the tier
    one level when the value contains a file extension or URL scheme.
    """
    norm = name.lower().strip()
    if not norm:
        return _UNKNOWN_CLASSIFICATION

    for names_set, ptype, tier, conf, categories in _LOOKUP:
        if norm in names_set:
            boosted = False
            final_tier = tier
            final_conf = conf

            # Value boost - file extension in value upgrades FILE_PATH tier
            if ptype == ParamType.FILE_PATH and value and _value_has_file_extension(value):
                if tier == ParamTier.MEDIUM:
                    final_tier = ParamTier.HIGH
                    final_conf = min(1.0, conf + 0.20)
                    boosted = True
                elif tier == ParamTier.LOW:
                    final_tier = ParamTier.MEDIUM
                    final_conf = min(1.0, conf + 0.15)
                    boosted = True

            # Value boost - URL scheme in value upgrades URL/REDIRECT tier
            if ptype in (ParamType.URL, ParamType.REDIRECT) and value and _value_looks_like_url(value):
                if tier == ParamTier.MEDIUM:
                    final_tier = ParamTier.HIGH
                    final_conf = min(1.0, conf + 0.15)
                    boosted = True
                elif tier == ParamTier.LOW:
                    final_tier = ParamTier.MEDIUM
                    final_conf = min(1.0, conf + 0.10)
                    boosted = True

            # Value boost - shell metacharacters in COMMAND param value
            if ptype == ParamType.COMMAND and value:
                v = value.lower()
                if any(sig in v for sig in _COMMAND_VALUE_SIGNALS):
                    final_conf = min(1.0, conf + 0.08)
                    boosted = True

            # Value boost - known elevated role strings in PRIVILEGE param value
            if ptype == ParamType.PRIVILEGE and value:
                v = value.lower()
                if v in {"admin", "administrator", "superuser", "root", "true", "1", "staff", "moderator"}:
                    final_conf = min(1.0, conf + 0.10)
                    boosted = True

            return ParamClassification(
                param_type        = ptype,
                tier              = final_tier,
                attack_categories = categories,
                raw_confidence    = final_conf,
                matched_name      = norm,
                value_boosted     = boosted,
            )

    return ParamClassification(
        param_type        = ParamType.UNKNOWN,
        tier              = ParamTier.LOW,
        attack_categories = frozenset(),
        raw_confidence    = 0.0,
        matched_name      = norm,
    )


def is_file_param(name: str, value: str = "") -> bool:
    """Quick check - does this param reference a file/path? Used by PathTraversalMapper."""
    c = classify_param(name, value)
    return c.param_type == ParamType.FILE_PATH


def is_url_param(name: str, value: str = "") -> bool:
    """Quick check - does this param carry a URL? Used by SSRFMapper."""
    c = classify_param(name, value)
    return c.param_type in (ParamType.URL, ParamType.REDIRECT)


def is_id_param(name: str) -> bool:
    """Quick check - does this param reference an object ID? Used by AccessControlMapper."""
    c = classify_param(name)
    return c.param_type in (ParamType.OBJECT_ID, ParamType.TENANT)


def is_deserialize_param(name: str, value: str = "") -> bool:
    """Quick check - does this param carry serialized data? Used by DeserializationMapper."""
    c = classify_param(name, value)
    return c.param_type == ParamType.DESERIALIZE


def is_graphql_param(name: str) -> bool:
    """Quick check - is this a GraphQL operation param? Used by InjectionMapper."""
    c = classify_param(name)
    return c.param_type == ParamType.GRAPHQL


def tier_to_confidence_level(tier: str) -> str:
    """Map a ParamTier to a ConfidenceLevel string (matches constants in models.py)."""
    return {
        ParamTier.HIGH:   "HIGH",
        ParamTier.MEDIUM: "MEDIUM",
        ParamTier.LOW:    "LOW",
    }.get(tier, "LOW")


# Convenience exports - mappers can import these directly instead of redefining
# ALL_FILE_PARAMS excludes image/media names to avoid false positive flood on image-heavy apps
ALL_FILE_PARAMS: FrozenSet[str]    = _FILE_PATH_HIGH | _FILE_PATH_MEDIUM | _FILE_PATH_LOW
ALL_SSRF_PARAMS: FrozenSet[str]    = _URL_HIGH | _URL_MEDIUM | _URL_LOW
ALL_REDIRECT_PARAMS: FrozenSet[str] = _REDIRECT_HIGH | _REDIRECT_MEDIUM | _REDIRECT_LOW
ALL_IDOR_PARAMS: FrozenSet[str]    = _OBJECT_ID_HIGH | _OBJECT_ID_MEDIUM
ALL_PRIVESC_PARAMS: FrozenSet[str] = _PRIVILEGE_HIGH
ALL_TENANT_PARAMS: FrozenSet[str]  = _TENANT_HIGH
ALL_CMD_PARAMS: FrozenSet[str]     = _COMMAND_HIGH
ALL_SSTI_PARAMS: FrozenSet[str]    = _TEMPLATE_HIGH | _TEMPLATE_MEDIUM
ALL_LDAP_PARAMS: FrozenSet[str]    = _LDAP_HIGH | _LDAP_MEDIUM
ALL_XXE_PARAMS: FrozenSet[str]     = _XML_BODY_HIGH
ALL_CSRF_PARAMS: FrozenSet[str]    = _AUTH_TOKEN_HIGH
ALL_SEARCH_PARAMS: FrozenSet[str]  = _SEARCH_HIGH | _SEARCH_MEDIUM
ALL_GRAPHQL_PARAMS: FrozenSet[str] = _GRAPHQL_HIGH | _GRAPHQL_MEDIUM
ALL_DESERIALIZE_PARAMS: FrozenSet[str] = _DESERIALIZE_HIGH | _DESERIALIZE_MEDIUM
ALL_WEBSOCKET_PARAMS: FrozenSet[str] = _WEBSOCKET_HIGH
ALL_IMAGE_PARAMS: FrozenSet[str]   = _IMAGE_PARAMS  # for SSRF on image URL params

HIGH_FILE_PARAMS: FrozenSet[str]   = _FILE_PATH_HIGH
HIGH_SSRF_PARAMS: FrozenSet[str]   = _URL_HIGH
HIGH_REDIRECT_PARAMS: FrozenSet[str] = _REDIRECT_HIGH
HIGH_PATH_PARAM_NAMES: FrozenSet[str] = _FILE_PATH_HIGH  # for path_traversal.py REST detection
