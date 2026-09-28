"""
Data models used throughout BundleSpy.
All findings, JS files, endpoints, and infrastructure items use these.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import hashlib


# ── Trust model vocabulary ────────────────────────────────────────────────────
# 7 orthogonal dimensions. Every object uses these constants.
# Invariant: NO MISSING SEMANTICS rather than NO UNKNOWN VALUES.
# unknown / not_attempted are valid correct defaults when info is unavailable.

class EvidenceSource:
    """
    HOW was this object discovered?

    STATIC   - found by parsing HTML/JS on disk or over HTTP
    RUNTIME  - captured by headless browser network intercept
    PASSIVE  - from archive sources (Wayback, CommonCrawl)
    SUPPLIED - user-provided via --cookie / --header / --login
    """
    STATIC   = "static"
    RUNTIME  = "runtime"
    PASSIVE  = "passive"
    SUPPLIED = "supplied"

    ALL = {STATIC, RUNTIME, PASSIVE, SUPPLIED}


class AssetOrigin:
    """
    WHAT kind of asset is this?

    Orthogonal to EvidenceSource: a chunk can be found statically or at runtime.

    EXTERNAL  - standalone JS file served from a URL
    INLINE    - embedded <script> block with no standalone URL
    CHUNK     - dynamically loaded webpack/rollup/vite chunk
    SOURCEMAP - recovered via source map (.map file)
    WORKER    - Web Worker or Service Worker
    IFRAME    - loaded inside an iframe context
    """
    EXTERNAL  = "external"
    INLINE    = "inline"
    CHUNK     = "chunk"
    SOURCEMAP = "sourcemap"
    WORKER    = "worker"
    IFRAME    = "iframe"

    ALL = {EXTERNAL, INLINE, CHUNK, SOURCEMAP, WORKER, IFRAME}


class ValidationStatus:
    """
    WAS this object validated, and what was the result?

    NOT_ATTEMPTED - no probe was run (no URL, out of scope, not eligible)
    SKIPPED       - probe possible but deliberately bypassed (e.g. severity too low)
    PROBED        - probe ran; intermediate state before confirmed/unreachable resolution
    CONFIRMED     - probe ran; secret still present or endpoint still live
    UNREACHABLE   - probe ran; 4xx/5xx, timeout, or no route
    INVALIDATED   - probe ran; secret rotated or endpoint no longer exists
    """
    NOT_ATTEMPTED = "not_attempted"
    SKIPPED       = "skipped"
    PROBED        = "probed"
    CONFIRMED     = "confirmed"
    UNREACHABLE   = "unreachable"
    INVALIDATED   = "invalidated"

    ALL = {NOT_ATTEMPTED, SKIPPED, PROBED, CONFIRMED, UNREACHABLE, INVALIDATED}


class AccessLevel:
    """
    WHAT access context is required to reach this object?
    Answers: authorization question.

    PUBLIC        - reachable with no credentials
    AUTHENTICATED - requires a valid session / token
    PRIVILEGED    - requires elevated rights (admin, specific role)
    UNKNOWN       - access requirements not yet determined
    """
    PUBLIC        = "public"
    AUTHENTICATED = "authenticated"
    PRIVILEGED    = "privileged"
    UNKNOWN       = "unknown"

    ALL = {PUBLIC, AUTHENTICATED, PRIVILEGED, UNKNOWN}


class ScopeStatus:
    """
    IS this object within the authorized scan scope?
    Answers: scanning policy question (orthogonal to access level).
    """
    IN_SCOPE     = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"

    ALL = {IN_SCOPE, OUT_OF_SCOPE}


# ── Stage 6: Application State Intelligence ───────────────────────────────────

class AccessState:
    """
    Per-endpoint access classification based on observed HTTP behavior.
    Kept for backwards compatibility with state_intelligence.py.
    Prefer AccessLevel for new code; AccessState is the crawler-observed view.

    PUBLIC         - Responded 2xx with no auth challenge
    AUTHENTICATED  - Responded 2xx only after login, or 401/403 observed
    PRIVILEGED     - Responded 2xx only in an elevated session (admin etc.)
    UNKNOWN        - Never reached or status inconclusive
    """
    PUBLIC        = "PUBLIC"
    AUTHENTICATED = "AUTHENTICATED"
    PRIVILEGED    = "PRIVILEGED"
    UNKNOWN       = "UNKNOWN"

    ALL = {PUBLIC, AUTHENTICATED, PRIVILEGED, UNKNOWN}


class RouteState:
    """
    Per-route lifecycle state from crawl to verification.
    Answers: what did the crawler observe? (orthogonal to access level)

    DISCOVERED    - Found in JS/HTML but never visited
    VISITED       - HTTP request was made; response captured
    OBSERVED      - Seen in runtime network traffic (browser intercept)
    AUTH_REQUIRED - Returned 401
    FORBIDDEN     - Returned 403
    REDIRECTED    - Returned 301/302
    UNREACHABLE   - Connection error, timeout, or 4xx/5xx other than 401/403
    """
    DISCOVERED    = "DISCOVERED"
    VISITED       = "VISITED"
    OBSERVED      = "OBSERVED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    FORBIDDEN     = "FORBIDDEN"
    REDIRECTED    = "REDIRECTED"
    UNREACHABLE   = "UNREACHABLE"

    ALL = {DISCOVERED, VISITED, OBSERVED, AUTH_REQUIRED, FORBIDDEN, REDIRECTED, UNREACHABLE}


@dataclass
class StateTransition:
    """
    A single observed HTTP status transition, e.g. /admin → 403 → FORBIDDEN.
    Recorded in order so callers can reconstruct the access chain.
    """
    url:          str
    http_status:  int
    route_state:  str                  # RouteState constant
    access_state: str                  # AccessState constant
    redirected_to: str = ""           # populated if route_state == REDIRECTED
    observed_at:  str  = ""           # ISO timestamp or empty

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url":           self.url,
            "http_status":   self.http_status,
            "route_state":   self.route_state,
            "access_state":  self.access_state,
            "redirected_to": self.redirected_to,
            "observed_at":   self.observed_at,
        }


@dataclass
class PageAccessRecord:
    """
    What BundleSpy learned about a page's access requirements during the crawl.
    One record per visited URL; stored in ScanResult.page_states.
    """
    url:           str
    http_status:   int        = 0
    route_state:   str        = RouteState.DISCOVERED
    access_state:  str        = AccessState.UNKNOWN
    redirected_to: str        = ""
    auth_required: Optional[bool] = None   # None = unknown
    # Chain of transitions if the page was retried (e.g. unauthenticated then authenticated)
    transitions:   List[StateTransition] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url":           self.url,
            "http_status":   self.http_status,
            "route_state":   self.route_state,
            "access_state":  self.access_state,
            "redirected_to": self.redirected_to,
            "auth_required": self.auth_required,
            "transitions":   [t.to_dict() for t in self.transitions],
        }


# ── Provenance Model ──────────────────────────────────────────────────────────

@dataclass
class Provenance:
    """
    Chain of custody for a finding, endpoint, or JS asset.

    Every field answers one question a security engineer would ask:
      - How was this found?         -> evidence_source (EvidenceSource constant)
      - What kind of asset is it?   -> asset_origin (AssetOrigin constant)
      - Where exactly?              -> discovered_in / line_number
      - Was it runtime-observed?    -> observed_at
      - What supports this claim?   -> evidence (human-readable basis string)
      - Was it validated?           -> validation_status (ValidationStatus constant)
      - Why does it have that status? -> validation_reason
      - Auth-gated?                 -> auth_required / access_level
      - In scope?                   -> scope_status (ScopeStatus constant)
      - Why was something skipped?  -> skipped_reason
    """
    # ── Discovery ─────────────────────────────────────────────────────────────
    evidence_source:      str   = EvidenceSource.STATIC   # EvidenceSource constant
    asset_origin:         str   = AssetOrigin.EXTERNAL    # AssetOrigin constant
    discovered_in:        str   = ""     # JS file URL or page URL where found
    line_number:          int   = 0      # Line inside discovered_in (0 = unknown)
    observed_at:          str   = ""     # Page URL where this was observed at runtime
    evidence:             str   = ""     # Human-readable basis: "Matched rule X in app.js:184"

    # ── Validation ────────────────────────────────────────────────────────────
    validation_status:       str = ValidationStatus.NOT_ATTEMPTED  # ValidationStatus constant
    validation_http_status:  int = 0    # HTTP status from passive probe (0 = not probed)
    validation_error:        str = ""   # Error message if probe failed
    validation_reason:       str = ""   # Why validation_status has its value

    # ── Access context ────────────────────────────────────────────────────────
    auth_required:        Optional[bool] = None             # None = unknown, True/False = observed
    access_level:         str   = AccessLevel.UNKNOWN       # AccessLevel constant

    # ── Scope ─────────────────────────────────────────────────────────────────
    scope_status:         str   = ScopeStatus.IN_SCOPE      # ScopeStatus constant

    # ── Skip tracking ─────────────────────────────────────────────────────────
    skipped_reason:       str   = ""    # Why this was not fully analyzed (empty = analyzed)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_source":        self.evidence_source,
            "asset_origin":           self.asset_origin,
            "discovered_in":          self.discovered_in,
            "line_number":            self.line_number,
            "observed_at":            self.observed_at,
            "evidence":               self.evidence,
            "validation_status":      self.validation_status,
            "validation_http_status": self.validation_http_status,
            "validation_error":       self.validation_error,
            "validation_reason":      self.validation_reason,
            "auth_required":          self.auth_required,
            "access_level":           self.access_level,
            "scope_status":           self.scope_status,
            "skipped_reason":         self.skipped_reason,
        }

    @classmethod
    def from_finding(cls, finding: "Finding") -> "Provenance":
        """
        Build a baseline Provenance from a Finding's existing fields.
        Called at report-time - no network I/O.
        """
        raw_source = getattr(finding, "source_type", EvidenceSource.STATIC) or EvidenceSource.STATIC
        # Normalize legacy source_type values to EvidenceSource constants
        evidence_source = _normalize_evidence_source(raw_source)

        # Infer asset_origin from file_url
        asset_origin = _infer_asset_origin(finding.file_url or "")

        evidence = f"Matched rule {finding.rule_id} in {finding.file_url or 'unknown'}:{finding.line_number}"

        return cls(
            evidence_source = evidence_source,
            asset_origin    = asset_origin,
            discovered_in   = finding.file_url,
            line_number     = finding.line_number,
            observed_at     = finding.source_page or "",
            evidence        = evidence,
        )

    @classmethod
    def from_endpoint(cls, endpoint: "Endpoint") -> "Provenance":
        """
        Build a baseline Provenance from an Endpoint's existing fields.
        Called at report-time - no network I/O.
        """
        raw_source = getattr(endpoint, "source_type", EvidenceSource.STATIC) or EvidenceSource.STATIC
        evidence_source = _normalize_evidence_source(raw_source)

        asset_origin = _infer_asset_origin(endpoint.source_file or "")

        evidence = (
            endpoint.evidence
            if getattr(endpoint, "evidence", "")
            else f"Extracted from {endpoint.source_file or 'unknown'}:{endpoint.line_number}"
        )

        auth_required = (
            True if endpoint.auth_context and endpoint.auth_context not in ("", "None") else None
        )
        # Endpoints that were actually visited/crawled are known-public.
        # source_file == "crawler://page" means the crawler fetched it successfully.
        # headless://route means the headless browser navigated to it.
        _src = endpoint.source_file or ""
        _was_visited = _src.startswith(("crawler://", "headless://"))
        access_level = (
            AccessLevel.AUTHENTICATED
            if endpoint.auth_context and endpoint.auth_context not in ("", "None")
            else AccessLevel.PUBLIC
            if _was_visited
            else AccessLevel.UNKNOWN
        )

        return cls(
            evidence_source = evidence_source,
            asset_origin    = asset_origin,
            discovered_in   = endpoint.source_file,
            line_number     = endpoint.line_number,
            observed_at     = "",   # populated by headless layer if available
            evidence        = evidence,
            auth_required   = auth_required,
            access_level    = access_level,
        )

    @classmethod
    def from_js_file(cls, js_file: "JSFile") -> "Provenance":
        """
        Build a baseline Provenance from a JSFile's existing fields.
        Called when JSFile.provenance is first needed.
        """
        raw_source = getattr(js_file, "source_type", "static") or "static"
        evidence_source = _normalize_evidence_source(raw_source)
        asset_origin    = _infer_asset_origin_from_source_type(raw_source, js_file.url or "")

        return cls(
            evidence_source = evidence_source,
            asset_origin    = asset_origin,
            discovered_in   = js_file.source_page or "",
            evidence        = f"Fetched from {js_file.url or 'unknown'} (HTTP {js_file.status_code})",
        )


# ── Normalization helpers ─────────────────────────────────────────────────────

def _normalize_evidence_source(raw: str) -> str:
    """Map legacy source_type strings to EvidenceSource constants."""
    mapping = {
        "static":     EvidenceSource.STATIC,
        "browser":    EvidenceSource.RUNTIME,
        "runtime":    EvidenceSource.RUNTIME,
        "correlated": EvidenceSource.STATIC,   # correlated means static+runtime; keep static as primary
        "passive":    EvidenceSource.PASSIVE,
        "supplied":   EvidenceSource.SUPPLIED,
        # inline/sourcemap/chunk are AssetOrigin values, not sources - default to static
        "inline":     EvidenceSource.STATIC,
        "sourcemap":  EvidenceSource.STATIC,
        "chunk":      EvidenceSource.RUNTIME,  # chunks are typically runtime-loaded
        "worker":     EvidenceSource.RUNTIME,
    }
    return mapping.get(raw.lower(), EvidenceSource.STATIC)


def _infer_asset_origin(url: str) -> str:
    """Infer AssetOrigin from a URL string."""
    if not url:
        return AssetOrigin.EXTERNAL
    low = url.lower()
    if low.startswith("inline:") or low.startswith("html:"):
        return AssetOrigin.INLINE
    if low.startswith("sourcemap://") or ".map" in low:
        return AssetOrigin.SOURCEMAP
    if low.startswith("local://"):
        return AssetOrigin.EXTERNAL
    if "worker" in low:
        return AssetOrigin.WORKER
    if "chunk" in low or low.endswith(".chunk.js"):
        return AssetOrigin.CHUNK
    return AssetOrigin.EXTERNAL


def _infer_asset_origin_from_source_type(source_type: str, url: str) -> str:
    """Infer AssetOrigin from JSFile.source_type and URL."""
    mapping = {
        "inline":    AssetOrigin.INLINE,
        "sourcemap": AssetOrigin.SOURCEMAP,
        "chunk":     AssetOrigin.CHUNK,
        "worker":    AssetOrigin.WORKER,
    }
    if source_type.lower() in mapping:
        return mapping[source_type.lower()]
    return _infer_asset_origin(url)


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class JSFile:
    url: str
    source_page: str
    status_code: int
    content_type: str
    size_bytes: int
    sha256: str
    content: str
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    has_source_map: bool = False
    source_map_url: str = ""
    technology: str = ""
    source_type: str = "static"   # static | browser | inline | sourcemap | chunk | worker
    # Trust model: populated lazily via Provenance.from_js_file()
    provenance: Optional["Provenance"] = field(default=None, repr=False)


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    category: str
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW / INFO
    confidence: float        # 0.0 - 1.0
    file_url: str
    source_page: str
    line_number: int
    column: int
    matched_value: str
    redacted_value: str
    sha256: str
    context: str
    description: str
    impact: str
    remediation: str
    false_positive_notes: str
    # confidence_label: what the detector believes about this finding
    # candidate         - rule matched, below confidence threshold
    # likely_secret     - rule matched, above confidence threshold
    # likely_false_positive - heuristics suggest this is noise
    confidence_label: str = "candidate"
    classification: str = ""  # PUBLIC_IDENTIFIER / SECRET / CREDENTIAL / TOKEN / CONFIG
    first_seen: datetime = field(default_factory=datetime.utcnow)
    occurrences: List[str] = field(default_factory=list)
    # Trust model: populated lazily at report-time or by passive validator
    provenance: Optional["Provenance"] = field(default=None, repr=False)

    @property
    def status(self) -> str:
        """
        Legacy read-only alias for confidence_label.
        Preserved so existing callers that read finding.status don't break.
        Do not assign to this; set confidence_label instead.
        """
        return self.confidence_label

    @staticmethod
    def make_id(rule_id: str, value: str, file_url: str) -> str:
        raw = f"{rule_id}:{value}:{file_url}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def redact(value: str, show_chars: int = 4) -> str:
        if len(value) <= show_chars * 2:
            return "*" * len(value)
        return value[:show_chars] + "*" * (len(value) - show_chars * 2) + value[-show_chars:]


@dataclass
class Endpoint:
    url:             str
    path:            str
    method:          str
    category:        str   # AUTH / ADMIN / API / GRAPHQL / WEBSOCKET / ROUTE / EXTERNAL / UNKNOWN
    source_file:     str
    line_number:     int
    confidence:      float
    # Extended intelligence fields
    host:            str   = ""
    query_params:    list  = None   # [{"name": "q", "example": "test"}]
    path_params:     list  = None   # [{"name": "id", "position": 2}]
    body_fields:     list  = None   # [{"name": "email"}, {"name": "password"}]
    request_headers: dict  = None   # {"Content-Type": "application/json"}
    auth_context:    str   = ""     # "Bearer", "Cookie", "ApiKey", "None"
    evidence:        str   = ""     # Raw JS snippet that revealed this endpoint
    kind:            str   = "api"  # api / route / external / websocket / graphql
    source_type:     str   = "static"  # static | runtime | correlated
    # Trust model: populated lazily at report-time or by passive validator
    provenance: Optional["Provenance"] = field(default=None, repr=False)
    # Stage 6: Application State Intelligence - populated by crawler + state_intelligence
    http_status:   int = 0                        # Last observed HTTP status (0 = not visited)
    access_state:  str = AccessState.UNKNOWN      # AccessState constant (crawler view)
    route_state:   str = RouteState.DISCOVERED    # RouteState constant


@dataclass
class InfrastructureItem:
    value: str
    classification: str     # PUBLIC_IP / PRIVATE_IP / LOOPBACK / LINK_LOCAL / INTERNAL_HOSTNAME / CLOUD / STAGING / DEV
    source_file: str
    line_number: int
    confidence: float
    action: str             # report_only / investigate


@dataclass
class ScanResult:
    target_url: str
    started_at: datetime
    finished_at: Optional[datetime]
    pages_crawled: int
    js_files: List[JSFile]
    findings: List[Finding]
    endpoints: List[Endpoint]
    infrastructure: List[InfrastructureItem]
    errors: List[str]
    # Attack surface graph - populated after scan, None until built
    # Import lazily to avoid circular imports
    graph: Optional[Any] = field(default=None, repr=False)
    # Stage 6: per-URL access records keyed by URL string
    page_states: Dict[str, "PageAccessRecord"] = field(default_factory=dict, repr=False)
