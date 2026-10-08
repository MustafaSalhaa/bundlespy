"""
Structured evidence model for BundleSpy's attack surface engine.

Every detector emits Evidence objects. The ConfidenceEngine scores them.
SurfaceFinding is the deduplicated, scored output — not the detector's raw signal.

Three independent dimensions per finding:
  confidence  - how certain the surface exists (0-100 int + level label)
  risk        - how security-sensitive the surface is
  status      - what kind of observation backs it (OBSERVED / CORRELATED / INFERRED / UNKNOWN)
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import List, Optional


# ── Evidence types ─────────────────────────────────────────────────────────────

class EvidenceType:
    """What kind of observation produced this evidence."""
    STATIC_JS           = "STATIC_JS"          # raw JS file content match
    AST                 = "AST"                 # AST-level call / assignment match
    HTML                = "HTML"                # HTML attribute / inline script
    DOM                 = "DOM"                 # DOM sink / source in JS
    ROUTE_DECLARATION   = "ROUTE_DECLARATION"   # framework route definition
    NETWORK_REQUEST     = "NETWORK_REQUEST"     # runtime request observed by browser
    NETWORK_RESPONSE    = "NETWORK_RESPONSE"    # runtime response field / header
    RESPONSE_HEADER     = "RESPONSE_HEADER"     # specific HTTP response header observed
    RESPONSE_JSON       = "RESPONSE_JSON"       # JSON field in response body
    SOURCE_MAP          = "SOURCE_MAP"          # recovered via .map file
    WEBPACK_RUNTIME     = "WEBPACK_RUNTIME"     # webpack chunk manifest / runtime
    WORKER              = "WORKER"              # web worker / service worker reference
    IFRAME              = "IFRAME"              # iframe context
    SERVICE_WORKER      = "SERVICE_WORKER"      # service worker registration
    GRAPHQL_OPERATION   = "GRAPHQL_OPERATION"   # observed GraphQL query / mutation
    WEBSOCKET           = "WEBSOCKET"           # WebSocket frame or endpoint
    ARCHIVE             = "ARCHIVE"             # Wayback / CommonCrawl historical
    METADATA            = "METADATA"            # robots.txt / sitemap / header disclosure
    COOKIE              = "COOKIE"              # Set-Cookie attribute analysis
    STORAGE             = "STORAGE"             # localStorage / sessionStorage usage
    PARAMETER_SEMANTIC  = "PARAMETER_SEMANTIC"  # parameter name matches security pattern
    CROSS_ENDPOINT      = "CROSS_ENDPOINT"      # identifier reused across endpoints


# ── Surface status ─────────────────────────────────────────────────────────────

class SurfaceStatus:
    """
    Quality of the observation behind a finding.
    Not a vulnerability state — a confidence-in-existence state.

    OBSERVED    - direct runtime or static observation (strong)
    CORRELATED  - multiple independent signals agree (very strong)
    INFERRED    - one indirect signal (weak, needs manual trace)
    UNKNOWN     - no observation, pattern match only
    """
    OBSERVED    = "OBSERVED"
    CORRELATED  = "CORRELATED"
    INFERRED    = "INFERRED"
    UNKNOWN     = "UNKNOWN"


# ── Risk level ─────────────────────────────────────────────────────────────────

class RiskLevel:
    """
    How security-sensitive is this surface type?
    Independent of confidence. HIGH risk surface with LOW confidence = still HIGH risk if real.
    """
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    _ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

    @classmethod
    def order(cls, level: str) -> int:
        return cls._ORDER.get(level, 99)


# ── Evidence dataclass ─────────────────────────────────────────────────────────

@dataclass
class Evidence:
    """
    One structured observation from a detector.

    Detectors emit Evidence; they do not emit findings.
    Multiple Evidence objects can support one SurfaceFinding.
    parent_evidence links to a prior Evidence that led to discovering this one.
    """
    evidence_type:   str                    # EvidenceType constant
    source:          str                    # how it was collected (EvidenceSource constant)
    asset:           str   = ""            # JS file URL / page URL / endpoint URL
    endpoint:        str   = ""            # normalized endpoint path, e.g. /api/users/{id}
    method:          str   = ""            # HTTP method
    parameter:       str   = ""            # specific parameter or field name
    route:           str   = ""            # framework route pattern if available
    location:        str   = ""            # file:line or URL fragment
    context:         str   = ""            # human-readable label for what was observed
    details:         str   = ""            # raw snippet, matched value, or note
    raw_confidence:  int   = 0            # 0-100 from EvidenceWeight scoring
    parent_evidence: Optional[str] = None  # id of parent Evidence if chained
    id:              str   = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def __repr__(self) -> str:
        return (
            f"Evidence({self.evidence_type}  {self.source}  "
            f"{self.endpoint or self.asset}  {self.context!r})"
        )


# ── SurfaceFinding dataclass ───────────────────────────────────────────────────

@dataclass
class SurfaceFinding:
    """
    A deduplicated, scored attack surface candidate.

    Built by the ConfidenceEngine from one or more Evidence objects.
    fingerprint identifies the structural surface — used for dedup across detectors.

    Important: confidence != risk != status.
      confidence  - how certain we are the surface exists (0-100, + level label HIGH/MEDIUM/LOW)
      risk        - how sensitive the surface is (RiskLevel constant)
      status      - quality of backing observation (SurfaceStatus constant)
      exploitability is never set here — it is always NOT_TESTED / UNKNOWN
    """
    fingerprint:     str                         # SHA256 of (method+endpoint+param+type+subtype)
    surface_type:    str                         # e.g. "Prototype Pollution: Source-to-Sink Chain"
    subtype:         str   = ""                 # e.g. "+ Gadget", "BOLA", "Explicit __proto__"
    endpoint:        str   = ""                 # normalized endpoint URL
    method:          str   = ""                 # HTTP method
    parameter:       str   = ""                 # primary parameter
    risk:            str   = RiskLevel.MEDIUM   # RiskLevel constant
    confidence:      int   = 0                  # 0-100 score
    confidence_level: str  = "LOW"             # HIGH / MEDIUM / LOW label
    status:          str   = SurfaceStatus.UNKNOWN
    evidence:        List[Evidence] = field(default_factory=list)
    relationships:   List[str]     = field(default_factory=list)  # fingerprints of related findings
    provenance:      str   = ""                 # primary source (EvidenceSource constant)
    notes:           str   = ""                 # burp / manual test guidance

    def add_evidence(self, ev: Evidence) -> None:
        """Merge an additional Evidence into this finding."""
        self.evidence.append(ev)

    def evidence_summary(self) -> List[str]:
        """Human-readable evidence lines for the reporter."""
        lines = []
        for ev in self.evidence:
            if ev.context:
                line = ev.context
                if ev.details:
                    line += f" — {ev.details}"
                lines.append(line)
            elif ev.details:
                lines.append(ev.details)
        return lines
