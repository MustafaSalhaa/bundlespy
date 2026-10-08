"""
Central confidence scorer for BundleSpy's evidence model.

All detectors feed evidence here. No detector invents its own scoring.
Output: (score: int 0-100, level: str HIGH/MEDIUM/LOW)

Scoring is additive with a floor of 0 and a ceiling of 100.
Penalty modifiers reduce confidence for weak signal types.
"""
from __future__ import annotations

from typing import List, Sequence

from .evidence import Evidence, EvidenceType, RiskLevel, SurfaceStatus


# ── Evidence weights ───────────────────────────────────────────────────────────

class EvidenceWeight:
    """
    Additive confidence contribution per evidence type.
    Calibrated against real TP/FP observations; tune with fixtures.
    Negative values are penalties applied when a weakness is present.
    """
    # Strong positive signals
    DIRECT_RUNTIME_OBSERVATION  = 30   # browser intercepted a real request/response
    DIRECT_AST_CALL             = 25   # AST confirms actual function call, not just keyword
    FRAMEWORK_ROUTE_DECLARATION = 20   # framework router definitively declares this route
    RESPONSE_BODY_CONFIRMATION  = 15   # response payload confirms field/endpoint exists
    MULTI_SOURCE_CORRELATION    = 20   # same surface found by 2+ independent pipelines
    SOURCE_MAP_EVIDENCE         = 10   # .map file reveals pre-minified source reference
    PARAMETER_SEMANTIC_MATCH    = 10   # parameter name strongly matches attack pattern
    CROSS_ENDPOINT_CORRELATION  = 15   # identifier reused across multiple endpoints
    WEBSOCKET_MESSAGE_OBSERVED  = 12   # WS frame content observed at runtime
    GRAPHQL_OPERATION_OBSERVED  = 12   # GraphQL operation parsed from runtime traffic

    # Weak positive signals
    STATIC_JS_CONTENT_MATCH     = 15   # string/regex match in JS file (base)
    HTML_ATTRIBUTE_MATCH        = 8    # HTML attribute or data-* match
    ARCHIVE_EVIDENCE            = 5    # Wayback / CommonCrawl reference
    METADATA_DISCLOSURE         = 5    # robots.txt / sitemap / headers
    COOKIE_ATTRIBUTE_SIGNAL     = 8    # Set-Cookie flag analysis

    # Penalty modifiers
    GENERIC_KEYWORD_ONLY        = -15  # only keyword match, no structural context
    THIRD_PARTY_ONLY            = -20  # signal only in third-party / CDN asset
    AMBIGUOUS_PARAMETER         = -10  # parameter name could be many things
    UNRESOLVED_TEMPLATE         = -20  # template variable, value not bound
    NO_USER_CONTROLLED_SOURCE   = -10  # sink found but no source path detected


# Evidence type → base weight mapping
_TYPE_WEIGHT: dict = {
    EvidenceType.NETWORK_REQUEST:    EvidenceWeight.DIRECT_RUNTIME_OBSERVATION,
    EvidenceType.NETWORK_RESPONSE:   EvidenceWeight.DIRECT_RUNTIME_OBSERVATION,
    EvidenceType.AST:                EvidenceWeight.DIRECT_AST_CALL,
    EvidenceType.ROUTE_DECLARATION:  EvidenceWeight.FRAMEWORK_ROUTE_DECLARATION,
    EvidenceType.RESPONSE_JSON:      EvidenceWeight.RESPONSE_BODY_CONFIRMATION,
    EvidenceType.RESPONSE_HEADER:    EvidenceWeight.RESPONSE_BODY_CONFIRMATION,
    EvidenceType.SOURCE_MAP:         EvidenceWeight.SOURCE_MAP_EVIDENCE,
    EvidenceType.PARAMETER_SEMANTIC: EvidenceWeight.PARAMETER_SEMANTIC_MATCH,
    EvidenceType.CROSS_ENDPOINT:     EvidenceWeight.CROSS_ENDPOINT_CORRELATION,
    EvidenceType.WEBSOCKET:          EvidenceWeight.WEBSOCKET_MESSAGE_OBSERVED,
    EvidenceType.GRAPHQL_OPERATION:  EvidenceWeight.GRAPHQL_OPERATION_OBSERVED,
    EvidenceType.STATIC_JS:          EvidenceWeight.STATIC_JS_CONTENT_MATCH,
    EvidenceType.DOM:                EvidenceWeight.STATIC_JS_CONTENT_MATCH,
    EvidenceType.HTML:               EvidenceWeight.HTML_ATTRIBUTE_MATCH,
    EvidenceType.IFRAME:             EvidenceWeight.HTML_ATTRIBUTE_MATCH,
    EvidenceType.WORKER:             EvidenceWeight.STATIC_JS_CONTENT_MATCH,
    EvidenceType.SERVICE_WORKER:     EvidenceWeight.STATIC_JS_CONTENT_MATCH,
    EvidenceType.WEBPACK_RUNTIME:    EvidenceWeight.STATIC_JS_CONTENT_MATCH,
    EvidenceType.ARCHIVE:            EvidenceWeight.ARCHIVE_EVIDENCE,
    EvidenceType.METADATA:           EvidenceWeight.METADATA_DISCLOSURE,
    EvidenceType.COOKIE:             EvidenceWeight.COOKIE_ATTRIBUTE_SIGNAL,
    EvidenceType.STORAGE:            EvidenceWeight.STATIC_JS_CONTENT_MATCH,
}

# Thresholds for confidence level labels
_THRESHOLD_HIGH   = 60
_THRESHOLD_MEDIUM = 35


def _status_from_evidence(evidence: Sequence[Evidence]) -> str:
    """
    Derive SurfaceStatus from what kinds of evidence are present.
    Does NOT derive exploitability — only observation quality.
    """
    types = {ev.evidence_type for ev in evidence}

    runtime_types = {
        EvidenceType.NETWORK_REQUEST,
        EvidenceType.NETWORK_RESPONSE,
        EvidenceType.WEBSOCKET,
        EvidenceType.GRAPHQL_OPERATION,
    }

    if types & runtime_types:
        # Multiple independent pipelines agree
        if len(types) >= 3:
            return SurfaceStatus.CORRELATED
        return SurfaceStatus.OBSERVED

    if len(types) >= 2:
        return SurfaceStatus.CORRELATED

    if EvidenceType.STATIC_JS in types or EvidenceType.AST in types:
        return SurfaceStatus.INFERRED

    return SurfaceStatus.UNKNOWN


class ConfidenceEngine:
    """
    Single scorer for all detectors. Call score() with the evidence list.

    Returns (score, level, status) — three independent values.
    score  - 0-100 int
    level  - "HIGH" / "MEDIUM" / "LOW"
    status - SurfaceStatus constant (OBSERVED / CORRELATED / INFERRED / UNKNOWN)
    """

    @staticmethod
    def score(evidence: Sequence[Evidence]) -> tuple:
        """
        Score a list of Evidence objects.
        Returns (score: int, level: str, status: str).
        """
        if not evidence:
            return 0, "LOW", SurfaceStatus.UNKNOWN

        total = 0
        seen_types: set = set()

        for ev in evidence:
            base = _TYPE_WEIGHT.get(ev.evidence_type, 5)

            # Apply per-evidence raw_confidence override if detector set one
            if ev.raw_confidence > 0:
                base = ev.raw_confidence

            # Multi-source bonus: same type seen twice doesn't double-count
            if ev.evidence_type in seen_types:
                base = max(1, base // 3)    # diminishing returns for same signal type
            seen_types.add(ev.evidence_type)

            total += base

        # Multi-source correlation bonus
        if len(seen_types) >= 3:
            total += EvidenceWeight.MULTI_SOURCE_CORRELATION

        # Clamp to 0-100
        score = max(0, min(100, total))

        if score >= _THRESHOLD_HIGH:
            level = "HIGH"
        elif score >= _THRESHOLD_MEDIUM:
            level = "MEDIUM"
        else:
            level = "LOW"

        status = _status_from_evidence(evidence)
        return score, level, status

    @staticmethod
    def risk_from_category(category: str) -> str:
        """
        Map an AttackCategory to a baseline RiskLevel.
        Detectors can override this for specific surface types.
        """
        from .models import AttackCategory
        _map = {
            AttackCategory.ACCESS_CONTROL:      RiskLevel.CRITICAL,
            AttackCategory.PROTOTYPE_POLLUTION: RiskLevel.HIGH,
            AttackCategory.XSS:                 RiskLevel.HIGH,
            AttackCategory.INJECTION:           RiskLevel.CRITICAL,
            AttackCategory.SSRF:                RiskLevel.HIGH,
            AttackCategory.CORS:                RiskLevel.HIGH,
            AttackCategory.OPEN_REDIRECT:       RiskLevel.MEDIUM,
            AttackCategory.CSRF:                RiskLevel.MEDIUM,
            AttackCategory.PATH_TRAVERSAL:      RiskLevel.MEDIUM,
            AttackCategory.CONFIGURATION:       RiskLevel.LOW,
        }
        return _map.get(category, RiskLevel.MEDIUM)
