"""
Tests for the attack surface mapping engine (updated for passive mapper API).
Uses mock fetcher and fixture endpoints - no real network.
"""
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

from bundlespy.testing.models import SurfaceStatus, AttackCategory, ConfidenceLevel
from bundlespy.testing.safety import SurfaceSafetyPolicy
from bundlespy.testing.prioritizer import score_endpoint, prioritize_surfaces
from bundlespy.testing.testers.xss import _find_js_sinks
from bundlespy.testing.testers.csrf import _has_csrf_signal
from bundlespy.storage.models import Endpoint, JSFile, ScanResult, Finding


# ─── Fixtures ────────────────────────────────────────────────────────────────

def _make_endpoint(**kwargs) -> Endpoint:
    defaults = dict(
        url="https://example.com/api/users/1",
        path="/api/users/1",
        method="GET",
        category="API",
        source_file="test.js",
        line_number=1,
        confidence=0.9,
        query_params=[],
        path_params=[{"name": "id", "example": "1"}],
        body_fields=[],
        request_headers={},
        auth_context="Bearer",
        source_type="static",
    )
    defaults.update(kwargs)
    return Endpoint(**defaults)

def _make_scan_result(endpoints=None, js_files=None) -> ScanResult:
    return ScanResult(
        target_url="https://example.com",
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        pages_crawled=1,
        js_files=js_files or [],
        findings=[],
        endpoints=endpoints or [],
        infrastructure=[],
        errors=[],
    )

def _make_scope(in_scope=True):
    scope = MagicMock()
    scope.in_scope.return_value = in_scope
    return scope

def _make_fetcher(content="hello world", status=200):
    fetcher = MagicMock()
    fetcher.get.return_value = (content, status, "text/html", "abc123")
    return fetcher

def _make_policy(scope=None):
    return SurfaceSafetyPolicy(
        scope=scope or _make_scope(True),
        rate_per_second=100,
        max_requests=1000,
    )


# ─── Safety policy tests ──────────────────────────────────────────────────────

class TestSafetyPolicy:
    def test_blocks_out_of_scope(self):
        policy = _make_policy(scope=_make_scope(False))
        ok, reason = policy.allow_get("https://other.com/path")
        assert not ok
        assert "out_of_scope" in reason

    def test_allows_in_scope_url(self):
        policy = _make_policy()
        ok, reason = policy.allow_get("https://example.com/api/users")
        assert ok
        assert reason == ""

    def test_deduplication(self):
        policy = _make_policy()
        ok1, _ = policy.allow_get("https://example.com/api")
        ok2, reason2 = policy.allow_get("https://example.com/api")
        assert ok1
        assert not ok2
        assert "duplicate" in reason2

    def test_max_requests_enforced(self):
        policy = SurfaceSafetyPolicy(scope=_make_scope(True), rate_per_second=1000, max_requests=2)
        policy.allow_get("https://example.com/a")
        policy.allow_get("https://example.com/b")
        ok, reason = policy.allow_get("https://example.com/c")
        assert not ok
        assert "max_requests" in reason

    def test_request_counter_increments(self):
        policy = _make_policy()
        assert policy.requests_made == 0
        policy.allow_get("https://example.com/a")
        assert policy.requests_made == 1


# ─── Prioritizer tests ────────────────────────────────────────────────────────

class TestPrioritizer:
    def test_admin_scores_high(self):
        ep = _make_endpoint(url="https://example.com/admin/dashboard", path="/admin/dashboard", category="ADMIN")
        assert score_endpoint(ep) > 0.5

    def test_static_page_scores_low(self):
        ep = _make_endpoint(url="https://example.com/about", path="/about", category="ROUTE",
                            method="GET", path_params=[], query_params=[], auth_context="")
        assert score_endpoint(ep) < 0.3

    def test_runtime_boosts_score(self):
        ep1 = _make_endpoint(source_type="static")
        ep2 = _make_endpoint(source_type="runtime")
        assert score_endpoint(ep2) > score_endpoint(ep1)

    def test_prioritize_surfaces_returns_sorted(self):
        from bundlespy.testing.models import SurfaceResult
        r1 = SurfaceResult(
            endpoint_url="https://example.com/about",
            method="GET",
            category=AttackCategory.CONFIGURATION,
            surface_type="Config",
            parameters=[],
            auth_context="",
            confidence=ConfidenceLevel.LOW,
            evidence=[],
            provenance_source="test",
            burp_notes="",
        )
        r2 = SurfaceResult(
            endpoint_url="https://example.com/api/users/1",
            method="GET",
            category=AttackCategory.ACCESS_CONTROL,
            surface_type="IDOR/BOLA",
            parameters=["path:numeric_id"],
            auth_context="Bearer",
            confidence=ConfidenceLevel.HIGH,
            evidence=[],
            provenance_source="test",
            burp_notes="",
        )
        sorted_results = prioritize_surfaces([r1, r2])
        # HIGH confidence access control should come first
        assert sorted_results[0].confidence == ConfidenceLevel.HIGH
        assert sorted_results[0].category == AttackCategory.ACCESS_CONTROL


# ─── XSS static analysis tests ───────────────────────────────────────────────

class TestXssStaticAnalysis:
    def test_finds_dom_sink_innerhtml(self):
        js = "element.innerHTML = userInput;"
        sinks = _find_js_sinks(js)
        assert "innerHTML" in sinks

    def test_finds_dom_sink_eval(self):
        js = "eval(userInput);"
        sinks = _find_js_sinks(js)
        assert "eval(" in sinks

    def test_finds_dom_sink_document_write(self):
        js = "document.write(userInput);"
        sinks = _find_js_sinks(js)
        assert "document.write" in sinks

    def test_no_false_positive_on_clean_js(self):
        js = "function add(a, b) { return a + b; }"
        assert _find_js_sinks(js) == []


# ─── CSRF signal detection ────────────────────────────────────────────────────

class TestCsrfDetection:
    def test_detects_csrf_token_in_body_fields(self):
        ep = _make_endpoint(
            method="POST",
            body_fields=[{"name": "csrf_token"}],
        )
        assert _has_csrf_signal(ep, [])

    def test_detects_csrf_header(self):
        ep = _make_endpoint(
            method="POST",
            request_headers={"X-CSRF-Token": "abc123"},
        )
        assert _has_csrf_signal(ep, [])

    def test_no_signal_when_absent(self):
        ep = _make_endpoint(method="POST", body_fields=[], request_headers={})
        assert not _has_csrf_signal(ep, [])

    def test_detects_csrf_in_js_content(self):
        ep = _make_endpoint(method="POST", body_fields=[], request_headers={})
        js_with_csrf = ["fetch('/api', { headers: { 'X-CSRF-Token': token } })"]
        assert _has_csrf_signal(ep, js_with_csrf)


# ─── Integration: AccessControlMapper ────────────────────────────────────────

class TestAccessControlMapperIntegration:
    def test_produces_candidate_for_numeric_id_endpoint(self):
        from bundlespy.testing.testers.access_control import AccessControlMapper
        ep = _make_endpoint(
            url="https://example.com/api/users/1",
            path="/api/users/1",
            path_params=[{"name": "id", "example": "1"}],
        )
        result = _make_scan_result(endpoints=[ep])
        mapper = AccessControlMapper(policy=_make_policy())
        results = mapper.map(result)
        assert len(results) > 0
        assert all(r.category == AttackCategory.ACCESS_CONTROL for r in results)

    def test_skips_endpoint_with_no_id(self):
        from bundlespy.testing.testers.access_control import AccessControlMapper
        ep = _make_endpoint(
            url="https://example.com/about",
            path="/about",
            path_params=[],
            query_params=[],
        )
        result = _make_scan_result(endpoints=[ep])
        mapper = AccessControlMapper(policy=_make_policy())
        results = mapper.map(result)
        assert results == []

    def test_deduplicates_same_pattern(self):
        from bundlespy.testing.testers.access_control import AccessControlMapper
        ep1 = _make_endpoint(url="https://example.com/api/users/1", path="/api/users/1")
        ep2 = _make_endpoint(url="https://example.com/api/users/2", path="/api/users/2")
        result = _make_scan_result(endpoints=[ep1, ep2])
        mapper = AccessControlMapper(policy=_make_policy())
        results = mapper.map(result)
        # Same structural pattern - should produce only 1 candidate
        assert len(results) == 1

    def test_zero_http_requests_made(self):
        from bundlespy.testing.testers.access_control import AccessControlMapper
        ep = _make_endpoint(path="/api/users/1")
        result = _make_scan_result(endpoints=[ep])
        mapper = AccessControlMapper(policy=_make_policy())
        results = mapper.map(result)
        assert all(r.requests_made == 0 for r in results)


# ─── Integration: XssMapper ──────────────────────────────────────────────────

class TestXssMapperIntegration:
    def test_dom_sink_detection_from_js(self):
        from bundlespy.testing.testers.xss import XssMapper
        js = JSFile(
            url="https://example.com/app.js",
            source_page="https://example.com/",
            status_code=200,
            content_type="application/javascript",
            size_bytes=100,
            sha256="abc",
            content="element.innerHTML = location.search;",
        )
        result = _make_scan_result(js_files=[js])
        mapper = XssMapper(policy=_make_policy())
        results = mapper.map(result)
        dom_results = [r for r in results if "DOM" in r.surface_type]
        assert len(dom_results) >= 1
        assert all(r.status == SurfaceStatus.CANDIDATE for r in dom_results)

    def test_no_results_on_clean_js(self):
        from bundlespy.testing.testers.xss import XssMapper
        js = JSFile(
            url="https://example.com/app.js",
            source_page="https://example.com/",
            status_code=200,
            content_type="application/javascript",
            size_bytes=100,
            sha256="def",
            content="function add(a, b) { return a + b; }",
        )
        result = _make_scan_result(js_files=[js])
        mapper = XssMapper(policy=_make_policy())
        results = mapper.map(result)
        assert results == []

    def test_search_param_produces_candidate(self):
        from bundlespy.testing.testers.xss import XssMapper
        ep = _make_endpoint(
            url="https://example.com/search",
            path="/search",
            query_params=[{"name": "q"}],
            path_params=[],
        )
        result = _make_scan_result(endpoints=[ep])
        mapper = XssMapper(policy=_make_policy())
        results = mapper.map(result)
        assert len(results) > 0
        assert all(r.requests_made == 0 for r in results)


# ─── Integration: ConfigurationMapper ────────────────────────────────────────

class TestConfigurationMapperIntegration:
    def test_detects_env_file_200(self):
        from bundlespy.testing.testers.configuration import ConfigurationMapper
        fetcher = _make_fetcher(content="APP_KEY=base64:abc\nDB_PASSWORD=secret123", status=200)
        result = _make_scan_result()
        mapper = ConfigurationMapper(fetcher=fetcher, policy=_make_policy())
        results = mapper.map(result)
        env_results = [r for r in results if ".env" in r.endpoint_url]
        assert len(env_results) > 0
        assert env_results[0].confidence == ConfidenceLevel.HIGH

    def test_ignores_404_paths(self):
        from bundlespy.testing.testers.configuration import ConfigurationMapper
        fetcher = _make_fetcher(content="Not found", status=404)
        result = _make_scan_result()
        mapper = ConfigurationMapper(fetcher=fetcher, policy=_make_policy())
        results = mapper.map(result)
        assert len(results) == 0

    def test_403_produces_medium_confidence(self):
        from bundlespy.testing.testers.configuration import ConfigurationMapper
        fetcher = _make_fetcher(content="Forbidden", status=403)
        result = _make_scan_result()
        mapper = ConfigurationMapper(fetcher=fetcher, policy=_make_policy())
        results = mapper.map(result)
        assert all(r.confidence == ConfidenceLevel.MEDIUM for r in results)


# ─── SurfaceStatus checks ─────────────────────────────────────────────────────

class TestSurfaceStatus:
    def test_candidate_is_default(self):
        from bundlespy.testing.models import SurfaceResult
        r = SurfaceResult(
            endpoint_url="https://example.com/api/users/1",
            method="GET",
            category=AttackCategory.ACCESS_CONTROL,
            surface_type="IDOR/BOLA",
            parameters=[],
            auth_context="Bearer",
            confidence=ConfidenceLevel.HIGH,
            evidence=[],
            provenance_source="test",
            burp_notes="",
        )
        assert r.status == SurfaceStatus.CANDIDATE

    def test_confidence_ordering(self):
        assert ConfidenceLevel.order(ConfidenceLevel.HIGH) < ConfidenceLevel.order(ConfidenceLevel.MEDIUM)
        assert ConfidenceLevel.order(ConfidenceLevel.MEDIUM) < ConfidenceLevel.order(ConfidenceLevel.LOW)

    def test_category_priority(self):
        assert AttackCategory.priority(AttackCategory.ACCESS_CONTROL) < AttackCategory.priority(AttackCategory.CONFIGURATION)
        assert AttackCategory.priority(AttackCategory.INJECTION) < AttackCategory.priority(AttackCategory.XSS)
