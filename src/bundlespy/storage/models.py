"""
Data models used throughout BundleSpy.
All findings, JS files, endpoints, and infrastructure items use these.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import hashlib


# ── Stage 5: Provenance Model ─────────────────────────────────────────────────

@dataclass
class Provenance:
    """
    Explains exactly how and where a finding or endpoint was discovered.

    Every field answers one question a security engineer would ask:
      - How was this found?     → source
      - Where exactly?          → discovered_in / line_number
      - Was it runtime-observed? → observed_at
      - Cross-corroborated?     → correlation
      - Confirmed still live?   → validation_status / validation_http_status
      - Auth-gated?             → auth_required
      - Why was something skipped? → skipped_reason
    """
    # ── Discovery ─────────────────────────────────────────────────────────────
    source:               str   = "static"        # static | runtime | correlated | passive
    discovered_in:        str   = ""              # JS file URL or page URL where found
    line_number:          int   = 0               # Line inside discovered_in (0 = unknown)
    observed_at:          str   = ""              # Page URL where endpoint/finding was observed at runtime
    correlation:          str   = ""              # "static+runtime" | "static+passive" | "single"

    # ── Validation ────────────────────────────────────────────────────────────
    validation_status:    str   = "NOT_VALIDATED" # NOT_VALIDATED | CONFIRMED | UNREACHABLE | ERROR
    validation_http_status: int = 0               # HTTP status from passive probe (0 = not probed)
    validation_error:     str   = ""              # Error message if probe failed

    # ── Access context ────────────────────────────────────────────────────────
    auth_required:        Optional[bool] = None   # None = unknown, True/False = observed
    access_level:         str   = "UNKNOWN"       # PUBLIC | AUTHENTICATED | UNKNOWN

    # ── Skip tracking ─────────────────────────────────────────────────────────
    skipped_reason:       str   = ""              # Why this was not fully analyzed (empty = analyzed)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source":               self.source,
            "discovered_in":        self.discovered_in,
            "line_number":          self.line_number,
            "observed_at":          self.observed_at,
            "correlation":          self.correlation,
            "validation_status":    self.validation_status,
            "validation_http_status": self.validation_http_status,
            "validation_error":     self.validation_error,
            "auth_required":        self.auth_required,
            "access_level":         self.access_level,
            "skipped_reason":       self.skipped_reason,
        }

    @classmethod
    def from_finding(cls, finding: "Finding") -> "Provenance":
        """
        Build a baseline Provenance from a Finding's existing fields.
        Called at report-time — no network I/O.
        """
        source = "static"
        if getattr(finding, "source_type", "static") == "runtime":
            source = "runtime"

        return cls(
            source        = source,
            discovered_in = finding.file_url,
            line_number   = finding.line_number,
            observed_at   = finding.source_page or "",
            correlation   = "single",
        )

    @classmethod
    def from_endpoint(cls, endpoint: "Endpoint") -> "Provenance":
        """
        Build a baseline Provenance from an Endpoint's existing fields.
        Called at report-time — no network I/O.
        """
        source = getattr(endpoint, "source_type", "static") or "static"

        # Correlated = we have both a static source file AND a runtime observed_at
        correlation = "single"
        if source == "runtime":
            correlation = "single"
        elif source == "correlated":
            correlation = "static+runtime"

        return cls(
            source        = source,
            discovered_in = endpoint.source_file,
            line_number   = endpoint.line_number,
            observed_at   = "",   # populated by headless layer if available
            correlation   = correlation,
            auth_required = (
                True  if endpoint.auth_context and endpoint.auth_context not in ("", "None") else
                None
            ),
            access_level  = (
                "AUTHENTICATED" if endpoint.auth_context and endpoint.auth_context not in ("", "None")
                else "UNKNOWN"
            ),
        )


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
    source_type: str = "static"   # static | browser | inline | sourcemap | chunk


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    category: str
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW / INFO
    confidence: float       # 0.0 - 1.0
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
    status: str             # candidate / likely_secret / likely_false_positive
    classification: str = ""  # PUBLIC_IDENTIFIER / SECRET / CREDENTIAL / TOKEN / CONFIG
    first_seen: datetime = field(default_factory=datetime.utcnow)
    occurrences: List[str] = field(default_factory=list)
    # Stage 5: populated lazily at report-time or by passive validator
    provenance: Optional["Provenance"] = field(default=None, repr=False)

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
    # Stage 5: populated lazily at report-time or by passive validator
    provenance: Optional["Provenance"] = field(default=None, repr=False)


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
    # Attack surface graph — populated after scan, None until built
    # Import lazily to avoid circular imports
    graph: Optional[Any] = field(default=None, repr=False)
