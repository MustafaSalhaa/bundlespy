from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid

# Test lifecycle status vocabulary
class TestStatus:
    NOT_TESTED    = "NOT_TESTED"
    CANDIDATE     = "CANDIDATE"
    OBSERVED      = "OBSERVED"
    INCONCLUSIVE  = "INCONCLUSIVE"
    VALIDATED     = "VALIDATED"
    CONFIRMED     = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SKIPPED       = "SKIPPED"
    OUT_OF_SCOPE  = "OUT_OF_SCOPE"
    UNREACHABLE   = "UNREACHABLE"

class AttackCategory:
    ACCESS_CONTROL    = "Access Control"
    XSS               = "XSS"
    INJECTION         = "Injection"
    SQLI              = "SQL Injection"
    SSRF              = "SSRF"
    CSRF              = "CSRF"
    PATH_TRAVERSAL    = "Path Traversal"
    FILE_UPLOAD       = "File Upload"
    OPEN_REDIRECT     = "Open Redirect"
    PROTOTYPE_POLL    = "Prototype Pollution"
    SSTI              = "Template Injection"
    GRAPHQL           = "GraphQL"
    WEBSOCKET         = "WebSocket"
    AUTHENTICATION    = "Authentication"
    CONFIGURATION     = "Configuration"

@dataclass
class Baseline:
    status_code:    int
    content_type:   str
    content_length: int
    body_hash:      str      # sha256 of normalized body
    headers:        Dict[str, str] = field(default_factory=dict)
    timing_ms:      float    = 0.0
    redirect_chain: List[str] = field(default_factory=list)

@dataclass
class TestObservation:
    status_code:    int
    content_type:   str
    content_length: int
    body_hash:      str
    body_excerpt:   str      # first 500 chars of response
    headers:        Dict[str, str] = field(default_factory=dict)
    timing_ms:      float    = 0.0
    redirect_chain: List[str] = field(default_factory=list)
    error:          str      = ""

@dataclass
class AttackTestResult:
    test_id:              str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    category:             str = ""
    attack_class:         str = ""          # e.g. "IDOR", "Reflected XSS", "SQL Injection"
    target_url:           str = ""
    parameter:            str = ""          # parameter or field that was tested
    method:               str = "GET"
    route:                str = ""
    authentication_context: str = ""
    evidence_source:      str = ""          # EvidenceSource constant
    payload:              str = ""          # test payload used
    baseline:             Optional[Baseline] = None
    observation:          Optional[TestObservation] = None
    status:               str = TestStatus.NOT_TESTED
    confidence:           float = 0.0       # 0.0 - 1.0
    evidence:             List[str] = field(default_factory=list)  # human-readable evidence lines
    why_tested:           str = ""
    what_changed:         str = ""
    what_observed:        str = ""
    what_remains_unverified: str = ""
    requests_made:        int = 0
    skipped_reason:       str = ""
    timestamp:            datetime = field(default_factory=datetime.utcnow)

@dataclass
class AttackTestSummary:
    category:    str
    candidates:  int = 0
    tested:      int = 0
    skipped:     int = 0
    validated:   int = 0
    confirmed:   int = 0
    inconclusive: int = 0
    out_of_scope: int = 0

@dataclass
class AttackEngineReport:
    target_url:       str
    started_at:       datetime
    finished_at:      Optional[datetime] = None
    total_candidates: int = 0
    total_tested:     int = 0
    total_skipped:    int = 0
    total_validated:  int = 0
    total_confirmed:  int = 0
    total_requests:   int = 0
    results:          List[AttackTestResult] = field(default_factory=list)
    summaries:        List[AttackTestSummary] = field(default_factory=list)
    errors:           List[str] = field(default_factory=list)
