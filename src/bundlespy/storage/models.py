"""
Data models used throughout BundleSpy.
All findings, JS files, endpoints, and infrastructure items use these.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
import hashlib


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
    first_seen: datetime = field(default_factory=datetime.utcnow)
    occurrences: List[str] = field(default_factory=list)

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
