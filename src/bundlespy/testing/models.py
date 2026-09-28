"""
Surface mapping vocabulary for BundleSpy's passive attack surface mapping engine.
No payloads. No exploitation. Pure signal-to-surface mapping from collected intelligence.
"""
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


class SurfaceStatus:
    NOT_MAPPED   = "NOT_MAPPED"
    CANDIDATE    = "CANDIDATE"
    MAPPED       = "MAPPED"
    SKIPPED      = "SKIPPED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class ConfidenceLevel:
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"

    # Ordering for sort comparisons
    _ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}

    @classmethod
    def order(cls, level: str) -> int:
        return cls._ORDER.get(level, 99)


class AttackCategory:
    ACCESS_CONTROL  = "Access Control"
    XSS             = "XSS"
    INJECTION       = "Injection"
    SSRF            = "SSRF"
    OPEN_REDIRECT   = "Open Redirect"
    CSRF            = "CSRF"
    PATH_TRAVERSAL  = "Path Traversal"
    CONFIGURATION   = "Configuration"

    # Priority order for sorting (lower index = higher priority)
    _PRIORITY = [
        ACCESS_CONTROL,
        INJECTION,
        XSS,
        SSRF,
        OPEN_REDIRECT,
        CSRF,
        PATH_TRAVERSAL,
        CONFIGURATION,
    ]

    @classmethod
    def priority(cls, cat: str) -> int:
        try:
            return cls._PRIORITY.index(cat)
        except ValueError:
            return 99


@dataclass
class SurfaceResult:
    endpoint_url:     str
    method:           str
    category:         str                    # AttackCategory constant
    surface_type:     str                    # e.g. "IDOR", "Reflected XSS", "SQLi param"
    parameters:       List[str]             # param names involved
    auth_context:     str
    confidence:       str                    # ConfidenceLevel constant
    evidence:         List[str]
    provenance_source: str                   # EvidenceSource or "config_probe"
    burp_notes:       str                    # what to do in Burp Suite
    requests_made:    int   = 0             # always 0 except ConfigurationMapper
    status:           str   = SurfaceStatus.CANDIDATE


@dataclass
class SurfaceSummary:
    category:         str
    total_candidates: int = 0
    mapped:           int = 0
    skipped:          int = 0
    out_of_scope:     int = 0


@dataclass
class SurfaceReport:
    target_url:       str
    started_at:       datetime
    finished_at:      Optional[datetime]
    results:          List[SurfaceResult] = field(default_factory=list)
    summaries:        List[SurfaceSummary] = field(default_factory=list)
    total_candidates: int = 0
    total_mapped:     int = 0
    total_skipped:    int = 0
    errors:           List[str] = field(default_factory=list)
