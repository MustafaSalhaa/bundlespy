"""
Unit tests for the Phase 1 evidence model:
  - Evidence / SurfaceFinding dataclasses
  - ConfidenceEngine scoring
  - fingerprint normalization and dedup
"""
import pytest
from bundlespy.testing.evidence import (
    Evidence, SurfaceFinding, EvidenceType, SurfaceStatus, RiskLevel,
)
from bundlespy.testing.confidence import ConfidenceEngine, EvidenceWeight
from bundlespy.testing.fingerprint import normalize_endpoint, make_fingerprint, deduplicate


# ── Evidence model ─────────────────────────────────────────────────────────────

class TestEvidence:
    def test_defaults(self):
        ev = Evidence(evidence_type=EvidenceType.STATIC_JS, source="static")
        assert ev.evidence_type == EvidenceType.STATIC_JS
        assert ev.source == "static"
        assert ev.id  # auto-generated

    def test_repr(self):
        ev = Evidence(
            evidence_type=EvidenceType.NETWORK_REQUEST,
            source="runtime",
            endpoint="/api/users",
            context="runtime request observed",
        )
        assert "NETWORK_REQUEST" in repr(ev)
        assert "/api/users" in repr(ev)

    def test_unique_ids(self):
        ev1 = Evidence(evidence_type=EvidenceType.STATIC_JS, source="static")
        ev2 = Evidence(evidence_type=EvidenceType.STATIC_JS, source="static")
        assert ev1.id != ev2.id


class TestSurfaceFinding:
    def test_defaults(self):
        f = SurfaceFinding(fingerprint="abc123", surface_type="Test Surface")
        assert f.risk == RiskLevel.MEDIUM
        assert f.confidence == 0
        assert f.confidence_level == "LOW"
        assert f.status == SurfaceStatus.UNKNOWN
        assert f.evidence == []

    def test_add_evidence(self):
        f = SurfaceFinding(fingerprint="abc", surface_type="Test")
        ev = Evidence(evidence_type=EvidenceType.AST, source="static")
        f.add_evidence(ev)
        assert len(f.evidence) == 1

    def test_evidence_summary_context(self):
        f = SurfaceFinding(fingerprint="abc", surface_type="Test")
        f.add_evidence(Evidence(
            evidence_type=EvidenceType.STATIC_JS,
            source="static",
            context="Sink found",
            details="Object.assign(",
        ))
        lines = f.evidence_summary()
        assert "Sink found" in lines[0]
        assert "Object.assign(" in lines[0]

    def test_evidence_summary_details_only(self):
        f = SurfaceFinding(fingerprint="abc", surface_type="Test")
        f.add_evidence(Evidence(
            evidence_type=EvidenceType.STATIC_JS,
            source="static",
            details="Some raw detail",
        ))
        lines = f.evidence_summary()
        assert "Some raw detail" in lines[0]


# ── ConfidenceEngine ───────────────────────────────────────────────────────────

class TestConfidenceEngine:
    def test_empty_evidence(self):
        score, level, status = ConfidenceEngine.score([])
        assert score == 0
        assert level == "LOW"
        assert status == SurfaceStatus.UNKNOWN

    def test_single_static_js(self):
        ev = Evidence(evidence_type=EvidenceType.STATIC_JS, source="static")
        score, level, status = ConfidenceEngine.score([ev])
        assert score == EvidenceWeight.STATIC_JS_CONTENT_MATCH
        assert level == "LOW"           # 15 < 35 threshold
        assert status == SurfaceStatus.INFERRED

    def test_network_request_gives_observed(self):
        ev = Evidence(evidence_type=EvidenceType.NETWORK_REQUEST, source="runtime")
        score, level, status = ConfidenceEngine.score([ev])
        assert score == EvidenceWeight.DIRECT_RUNTIME_OBSERVATION
        assert status == SurfaceStatus.OBSERVED

    def test_multiple_types_gives_correlated(self):
        evs = [
            Evidence(evidence_type=EvidenceType.NETWORK_REQUEST, source="runtime"),
            Evidence(evidence_type=EvidenceType.AST, source="static"),
            Evidence(evidence_type=EvidenceType.STATIC_JS, source="static"),
        ]
        score, level, status = ConfidenceEngine.score(evs)
        assert status == SurfaceStatus.CORRELATED
        # Multi-source bonus applied
        assert score > (
            EvidenceWeight.DIRECT_RUNTIME_OBSERVATION
            + EvidenceWeight.DIRECT_AST_CALL
            + EvidenceWeight.STATIC_JS_CONTENT_MATCH
        )

    def test_high_level_threshold(self):
        # runtime + AST + response confirmation should exceed HIGH threshold (60)
        # NETWORK_REQUEST(30) + AST(25) + RESPONSE_JSON(15) = 70, crosses HIGH at 60
        evs = [
            Evidence(evidence_type=EvidenceType.NETWORK_REQUEST, source="runtime"),
            Evidence(evidence_type=EvidenceType.AST, source="static"),
            Evidence(evidence_type=EvidenceType.RESPONSE_JSON, source="runtime"),
        ]
        score, level, _ = ConfidenceEngine.score(evs)
        assert level == "HIGH"
        assert score >= 60

    def test_same_type_diminishing_returns(self):
        # Two STATIC_JS signals should not double the score
        ev1 = Evidence(evidence_type=EvidenceType.STATIC_JS, source="static")
        ev2 = Evidence(evidence_type=EvidenceType.STATIC_JS, source="static")
        score_two, _, _ = ConfidenceEngine.score([ev1, ev2])
        score_one, _, _ = ConfidenceEngine.score([ev1])
        assert score_two < score_one * 2

    def test_score_clamped_to_100(self):
        # Pile on a lot of evidence — score should not exceed 100
        evs = [
            Evidence(evidence_type=EvidenceType.NETWORK_REQUEST, source="runtime"),
            Evidence(evidence_type=EvidenceType.NETWORK_RESPONSE, source="runtime"),
            Evidence(evidence_type=EvidenceType.AST, source="static"),
            Evidence(evidence_type=EvidenceType.ROUTE_DECLARATION, source="static"),
            Evidence(evidence_type=EvidenceType.RESPONSE_JSON, source="runtime"),
            Evidence(evidence_type=EvidenceType.CROSS_ENDPOINT, source="static"),
        ]
        score, _, _ = ConfidenceEngine.score(evs)
        assert score <= 100

    def test_raw_confidence_override(self):
        ev = Evidence(
            evidence_type=EvidenceType.STATIC_JS,
            source="static",
            raw_confidence=45,  # override
        )
        score, level, _ = ConfidenceEngine.score([ev])
        assert score == 45
        assert level == "MEDIUM"

    def test_confidence_risk_status_independent(self):
        # High confidence does NOT imply CONFIRMED status
        evs = [
            Evidence(evidence_type=EvidenceType.NETWORK_REQUEST, source="runtime"),
            Evidence(evidence_type=EvidenceType.AST, source="static"),
            Evidence(evidence_type=EvidenceType.STATIC_JS, source="static"),
        ]
        score, level, status = ConfidenceEngine.score(evs)
        assert level == "HIGH"
        assert status != "CONFIRMED"  # CONFIRMED must never be produced by scorer
        assert status in (SurfaceStatus.OBSERVED, SurfaceStatus.CORRELATED)

    def test_risk_from_category(self):
        from bundlespy.testing.models import AttackCategory
        assert ConfidenceEngine.risk_from_category(AttackCategory.ACCESS_CONTROL) == RiskLevel.CRITICAL
        assert ConfidenceEngine.risk_from_category(AttackCategory.CONFIGURATION) == RiskLevel.LOW
        assert ConfidenceEngine.risk_from_category("UNKNOWN_CATEGORY") == RiskLevel.MEDIUM


# ── Fingerprint and normalization ──────────────────────────────────────────────

class TestNormalizeEndpoint:
    def test_strips_scheme_and_host(self):
        assert normalize_endpoint("https://example.com/api/users") == "/api/users"

    def test_strips_query_string(self):
        assert normalize_endpoint("/api/users?foo=bar&baz=1") == "/api/users"

    def test_strips_fragment(self):
        assert normalize_endpoint("/api/users#section") == "/api/users"

    def test_numeric_id_replaced(self):
        assert normalize_endpoint("/api/users/123") == "/api/users/{id}"
        assert normalize_endpoint("/api/users/123/orders/456") == "/api/users/{id}/orders/{id}"

    def test_uuid_replaced(self):
        result = normalize_endpoint("/api/orders/3fa85f64-5717-4562-b3fc-2c963f66afa6")
        assert result == "/api/orders/{uuid}"

    def test_static_asset_unchanged(self):
        # Hashed filename in build asset - should not be mangled
        result = normalize_endpoint("/build/assets/app-BmnQm7Ty.js")
        assert result == "/build/assets/app-BmnQm7Ty.js"

    def test_empty(self):
        assert normalize_endpoint("") == ""

    def test_root(self):
        assert normalize_endpoint("https://example.com/") == "/"

    def test_trailing_slash_stripped(self):
        assert normalize_endpoint("/api/users/") == "/api/users"


class TestMakeFingerprint:
    def test_same_inputs_same_fingerprint(self):
        fp1 = make_fingerprint("GET", "/api/users/123", "id", "BOLA", "")
        fp2 = make_fingerprint("GET", "/api/users/456", "id", "BOLA", "")
        assert fp1 == fp2  # numeric IDs normalized

    def test_method_matters(self):
        fp_get   = make_fingerprint("GET",   "/api/users/{id}", "id", "BOLA", "")
        fp_patch = make_fingerprint("PATCH", "/api/users/{id}", "id", "BOLA", "")
        assert fp_get != fp_patch

    def test_subtype_matters(self):
        fp1 = make_fingerprint("GET", "/api/users/{id}", "id", "BOLA", "")
        fp2 = make_fingerprint("GET", "/api/users/{id}", "id", "BOLA", "+ Gadget")
        assert fp1 != fp2

    def test_returns_16_hex_chars(self):
        fp = make_fingerprint("GET", "/api/users", "id", "IDOR", "")
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)

    def test_case_insensitive_method(self):
        fp1 = make_fingerprint("get", "/api/users", "", "test", "")
        fp2 = make_fingerprint("GET", "/api/users", "", "test", "")
        assert fp1 == fp2


class TestDeduplicate:
    def _make_finding(self, fp: str, confidence: int, ev_count: int = 1) -> SurfaceFinding:
        evs = [
            Evidence(evidence_type=EvidenceType.STATIC_JS, source="static")
            for _ in range(ev_count)
        ]
        return SurfaceFinding(
            fingerprint=fp,
            surface_type="Test",
            confidence=confidence,
            evidence=evs,
        )

    def test_empty(self):
        assert deduplicate([]) == []

    def test_no_duplicates_unchanged(self):
        f1 = self._make_finding("fp1", 80)
        f2 = self._make_finding("fp2", 60)
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_same_fingerprint_collapsed(self):
        f1 = self._make_finding("fp_same", 80, ev_count=1)
        f2 = self._make_finding("fp_same", 40, ev_count=1)
        result = deduplicate([f1, f2])
        assert len(result) == 1

    def test_highest_confidence_kept(self):
        f1 = self._make_finding("fp_same", 40)
        f2 = self._make_finding("fp_same", 80)
        result = deduplicate([f1, f2])
        assert result[0].confidence == 80

    def test_evidence_merged(self):
        f1 = self._make_finding("fp_same", 80, ev_count=2)
        f2 = self._make_finding("fp_same", 40, ev_count=3)
        result = deduplicate([f1, f2])
        # All 5 distinct evidence objects should be merged
        assert len(result[0].evidence) == 5

    def test_no_evidence_duplication(self):
        # Same evidence id in both - should not be doubled
        ev = Evidence(evidence_type=EvidenceType.STATIC_JS, source="static")
        f1 = SurfaceFinding(fingerprint="fp_x", surface_type="T", confidence=80, evidence=[ev])
        f2 = SurfaceFinding(fingerprint="fp_x", surface_type="T", confidence=40, evidence=[ev])
        result = deduplicate([f1, f2])
        assert len(result[0].evidence) == 1  # not doubled
