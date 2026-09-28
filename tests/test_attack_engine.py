"""
Deterministic tests for the attack testing engine.
Uses mock fetcher and fixture endpoints - no real network.
"""
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

from bundlespy.testing.models import TestStatus, AttackCategory
from bundlespy.testing.safety import SafetyPolicy
from bundlespy.testing.prioritizer import score_endpoint, score_param_for_attack, prioritize
from bundlespy.testing.baseline import differential, _body_hash
from bundlespy.testing.models import Baseline, TestObservation
from bundlespy.testing.testers.access_control import AccessControlTester, _extract_id_candidates
from bundlespy.testing.testers.xss import XssTester, _find_dom_sinks, _find_sources
from bundlespy.testing.testers.injection import InjectionTester, _has_db_error
from bundlespy.testing.testers.ssrf import SsrfTester
from bundlespy.testing.testers.open_redirect import OpenRedirectTester
from bundlespy.testing.testers.csrf import CsrfTester, _has_csrf_protection
from bundlespy.testing.testers.path_traversal import PathTraversalTester
from bundlespy.testing.testers.configuration import ConfigurationTester
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

def _make_policy(scope=None, allow_post=True):
    return SafetyPolicy(
        scope=scope or _make_scope(True),
        rate_per_second=100,
        max_requests=1000,
        allow_post=allow_post,
    )


# ─── Safety policy tests ──────────────────────────────────────────────────────

class TestSafetyPolicy:
    def test_blocks_out_of_scope(self):
        policy = _make_policy(scope=_make_scope(False))
        ok, reason = policy.check("https://other.com/path")
        assert not ok
        assert "out_of_scope" in reason

    def test_blocks_delete_method(self):
        policy = _make_policy()
        ok, reason = policy.check("https://example.com/api", method="DELETE")
        assert not ok
        assert "blocked_method" in reason

    def test_blocks_destructive_path(self):
        policy = _make_policy()
        ok, reason = policy.check("https://example.com/delete/user")
        assert not ok
        assert "destructive_path" in reason

    def test_blocks_protected_param(self):
        policy = _make_policy()
        ok, reason = policy.check("https://example.com/api", param="password")
        assert not ok
        assert "protected_param" in reason

    def test_deduplication(self):
        policy = _make_policy()
        ok1, _ = policy.check("https://example.com/api", param="id", test_type="IDOR")
        ok2, reason2 = policy.check("https://example.com/api", param="id", test_type="IDOR")
        assert ok1
        assert not ok2
        assert "duplicate" in reason2

    def test_allows_valid_request(self):
        policy = _make_policy()
        ok, reason = policy.check("https://example.com/api/users", method="GET", param="id", test_type="T1")
        assert ok
        assert reason == ""

    def test_max_requests_enforced(self):
        policy = SafetyPolicy(scope=_make_scope(True), rate_per_second=1000, max_requests=2)
        policy.check("https://example.com/a", param="p1", test_type="T1")
        policy.check("https://example.com/b", param="p2", test_type="T2")
        ok, reason = policy.check("https://example.com/c", param="p3", test_type="T3")
        assert not ok
        assert "max_requests" in reason


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

    def test_ssrf_param_score(self):
        assert score_param_for_attack("url", "SSRF") > 0.8
        assert score_param_for_attack("name", "SSRF") < 0.3

    def test_prioritize_returns_sorted(self):
        eps = [
            _make_endpoint(url="https://example.com/about", path="/about", category="ROUTE",
                           method="GET", path_params=[], query_params=[], auth_context=""),
            _make_endpoint(url="https://example.com/admin", path="/admin", category="ADMIN"),
        ]
        sorted_eps = prioritize(eps)
        assert sorted_eps[0][0] > sorted_eps[1][0]  # admin first


# ─── Differential analysis tests ─────────────────────────────────────────────

class TestDifferential:
    def _make_baseline(self, status=200, length=100, body_hash="abc"):
        return Baseline(status_code=status, content_type="text/html",
                        content_length=length, body_hash=body_hash)

    def _make_obs(self, status=200, length=100, body_hash="abc"):
        return TestObservation(status_code=status, content_type="text/html",
                               content_length=length, body_hash=body_hash, body_excerpt="")

    def test_no_diff_when_same(self):
        b = self._make_baseline()
        o = self._make_obs()
        assert differential(b, o) == {}

    def test_detects_status_change(self):
        b = self._make_baseline(status=200)
        o = self._make_obs(status=403)
        diff = differential(b, o)
        assert "status_code" in diff

    def test_detects_size_change(self):
        b = self._make_baseline(length=100)
        o = self._make_obs(length=500)
        diff = differential(b, o)
        assert "content_length" in diff

    def test_ignores_tiny_size_diff(self):
        b = self._make_baseline(length=100)
        o = self._make_obs(length=110)
        diff = differential(b, o)
        assert "content_length" not in diff


# ─── ID candidate extraction ──────────────────────────────────────────────────

class TestIdCandidates:
    def test_extracts_numeric_path_param(self):
        ep = _make_endpoint(path_params=[{"name": "id", "example": "42"}])
        candidates = _extract_id_candidates(ep)
        assert any("id" in name for name, _ in candidates)

    def test_extracts_uuid_from_path(self):
        ep = _make_endpoint(
            url="https://example.com/docs/550e8400-e29b-41d4-a716-446655440000",
            path="/docs/550e8400-e29b-41d4-a716-446655440000",
            path_params=[],
        )
        candidates = _extract_id_candidates(ep)
        assert len(candidates) > 0

    def test_no_candidates_on_plain_path(self):
        ep = _make_endpoint(
            url="https://example.com/about",
            path="/about",
            path_params=[],
            query_params=[],
        )
        assert _extract_id_candidates(ep) == []


# ─── XSS static analysis tests ───────────────────────────────────────────────

class TestXssStaticAnalysis:
    def test_finds_dom_sinks(self):
        js = "element.innerHTML = userInput;"
        sinks = _find_dom_sinks(js)
        assert "innerHTML" in sinks

    def test_finds_sources(self):
        js = "var q = location.search;"
        sources = _find_sources(js)
        assert "location.search" in sources

    def test_no_false_positive_on_clean_js(self):
        js = "function add(a, b) { return a + b; }"
        assert _find_dom_sinks(js) == []
        assert _find_sources(js) == []


# ─── Injection error detection ────────────────────────────────────────────────

class TestInjectionErrors:
    def test_detects_mysql_error(self):
        body = "You have an error in your SQL syntax near 'WHERE id='"
        found, text = _has_db_error(body)
        assert found
        assert "sql syntax" in text.lower()

    def test_detects_pdo_exception(self):
        body = "PDOException: SQLSTATE[42000]"
        found, _ = _has_db_error(body)
        assert found

    def test_no_false_positive_on_normal_response(self):
        body = "Welcome to the dashboard. Here are your orders."
        found, _ = _has_db_error(body)
        assert not found


# ─── CSRF protection detection ────────────────────────────────────────────────

class TestCsrfDetection:
    def test_detects_csrf_token_in_body_fields(self):
        ep = _make_endpoint(
            method="POST",
            body_fields=[{"name": "_csrf_token"}],
        )
        assert _has_csrf_protection(ep)

    def test_detects_csrf_header(self):
        ep = _make_endpoint(
            method="POST",
            request_headers={"X-CSRF-Token": "abc123"},
        )
        assert _has_csrf_protection(ep)

    def test_no_protection_detected_when_absent(self):
        ep = _make_endpoint(method="POST", body_fields=[], request_headers={})
        assert not _has_csrf_protection(ep)


# ─── Integration: AccessControlTester ────────────────────────────────────────

class TestAccessControlTesterIntegration:
    def test_produces_candidate_for_id_endpoint(self):
        ep = _make_endpoint(
            url="https://example.com/api/users/1",
            path="/api/users/1",
            path_params=[{"name": "id", "example": "1"}],
        )
        result = _make_scan_result(endpoints=[ep])
        fetcher = _make_fetcher(content='{"user":"alice"}', status=200)
        policy  = _make_policy()
        tester  = AccessControlTester(fetcher=fetcher, policy=policy)
        results = tester.run(result)
        assert len(results) > 0
        assert all(r.category == AttackCategory.ACCESS_CONTROL for r in results)

    def test_skips_out_of_scope_endpoint(self):
        ep = _make_endpoint(url="https://other.com/api/users/1")
        result = _make_scan_result(endpoints=[ep])
        fetcher = _make_fetcher()
        policy  = _make_policy(scope=_make_scope(False))
        tester  = AccessControlTester(fetcher=fetcher, policy=policy)
        results = tester.run(result)
        assert all(r.status == TestStatus.SKIPPED for r in results)

    def test_no_false_findings_on_no_id_endpoint(self):
        ep = _make_endpoint(
            url="https://example.com/about",
            path="/about",
            path_params=[],
            query_params=[],
        )
        result = _make_scan_result(endpoints=[ep])
        tester = AccessControlTester(fetcher=_make_fetcher(), policy=_make_policy())
        results = tester.run(result)
        assert results == []


# ─── Integration: XssTester ──────────────────────────────────────────────────

class TestXssTesterIntegration:
    def test_detects_reflection(self):
        ep = _make_endpoint(
            url="https://example.com/search",
            path="/search",
            query_params=[{"name": "q"}],
            path_params=[],
        )
        # Fetcher returns canary in response
        fetcher = _make_fetcher(content="Results for: bspy7x3k", status=200)
        result  = _make_scan_result(endpoints=[ep])
        tester  = XssTester(fetcher=fetcher, policy=_make_policy())
        results = tester.run(result)
        assert any(r.status in (TestStatus.OBSERVED, TestStatus.VALIDATED) for r in results)

    def test_no_reflection_no_finding(self):
        ep = _make_endpoint(
            url="https://example.com/search",
            path="/search",
            query_params=[{"name": "q"}],
            path_params=[],
        )
        fetcher = _make_fetcher(content="No results found", status=200)
        result  = _make_scan_result(endpoints=[ep])
        tester  = XssTester(fetcher=fetcher, policy=_make_policy())
        # Only DOM XSS results from JS files - no reflection results
        xss_results = [r for r in tester.run(result) if r.attack_class == "Reflected XSS"]
        assert len(xss_results) == 0

    def test_dom_sink_detection_from_js(self):
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
        tester = XssTester(fetcher=_make_fetcher(), policy=_make_policy())
        results = tester.run(result)
        dom_results = [r for r in results if "DOM" in r.attack_class]
        assert len(dom_results) == 1
        assert dom_results[0].status == TestStatus.CANDIDATE


# ─── Integration: ConfigurationTester ────────────────────────────────────────

class TestConfigurationTesterIntegration:
    def test_detects_env_file(self):
        fetcher = _make_fetcher(
            content="APP_KEY=base64:abc\nDB_PASSWORD=secret123",
            status=200,
        )
        result = _make_scan_result()
        tester = ConfigurationTester(fetcher=fetcher, policy=_make_policy())
        results = tester.run(result)
        env_results = [r for r in results if ".env" in r.target_url]
        assert len(env_results) > 0
        assert env_results[0].status == TestStatus.CONFIRMED

    def test_ignores_404_paths(self):
        fetcher = _make_fetcher(content="Not found", status=404)
        result  = _make_scan_result()
        tester  = ConfigurationTester(fetcher=fetcher, policy=_make_policy())
        results = tester.run(result)
        assert all(r.status != TestStatus.CONFIRMED for r in results)


# ─── Summary / report tests ───────────────────────────────────────────────────

class TestSummary:
    def test_summary_counts_correctly(self):
        from bundlespy.testing.testers.base import BaseTester
        from bundlespy.testing.models import AttackTestResult

        class _MockTester(BaseTester):
            category = "Test"
            def run(self, result):
                self._results.append(AttackTestResult(status=TestStatus.VALIDATED))
                self._results.append(AttackTestResult(status=TestStatus.SKIPPED))
                self._results.append(AttackTestResult(status=TestStatus.CANDIDATE))
                return self._results

        t = _MockTester(fetcher=_make_fetcher(), policy=_make_policy())
        t.run(_make_scan_result())
        s = t.summary()
        assert s.skipped == 1
        assert s.validated == 1

    def test_zero_confirmed_without_evidence(self):
        from bundlespy.testing.models import AttackTestResult
        r = AttackTestResult(status=TestStatus.CANDIDATE, confidence=0.1)
        assert r.status != TestStatus.CONFIRMED
