"""
Regression tests for BundleSpy core intelligence layer.
Covers:
- Endpoint classification (_categorize_path)
- Static↔runtime endpoint correlation (correlate_endpoints)
- Content-hash dedup in _analyze()
- JS source_type tagging
- Secret classification propagation
- Canonical key normalization
"""

import hashlib
import pytest
from datetime import datetime

from bundlespy.analysis.endpoints import (
    _categorize_path,
    _canonical_key,
    _is_skip_url,
    correlate_endpoints,
    extract_endpoints,
)
from bundlespy.storage.models import JSFile, Endpoint, Finding
from bundlespy.analysis.secrets import SecretScanner, SecretRule


# ── _categorize_path ──────────────────────────────────────────────────────────

class TestCategorizePath:
    def test_auth_login(self):
        assert _categorize_path("/login") == "AUTH"

    def test_auth_oauth(self):
        assert _categorize_path("/oauth/token") == "AUTH"

    def test_auth_signup(self):
        assert _categorize_path("/signup") == "AUTH"

    def test_auth_2fa(self):
        assert _categorize_path("/2fa/verify") == "AUTH"

    def test_admin(self):
        assert _categorize_path("/admin/users") == "ADMIN"

    def test_admin_backoffice(self):
        assert _categorize_path("/backoffice/settings") == "ADMIN"

    def test_graphql(self):
        assert _categorize_path("/graphql") == "GRAPHQL"

    def test_graphql_versioned(self):
        assert _categorize_path("/graphql/v2") == "GRAPHQL"

    def test_serverless_netlify(self):
        assert _categorize_path("/.netlify/functions/stock") == "SERVERLESS"

    def test_serverless_netlify_create(self):
        assert _categorize_path("/.netlify/functions/create-checkout") == "SERVERLESS"

    def test_serverless_functions(self):
        assert _categorize_path("/functions/send-email") == "SERVERLESS"

    def test_serverless_vercel(self):
        assert _categorize_path("/.vercel/api/hello") == "SERVERLESS"

    def test_websocket(self):
        assert _categorize_path("/ws/chat") == "WEBSOCKET"

    def test_upload(self):
        assert _categorize_path("/upload/avatar") == "UPLOAD"

    def test_download(self):
        assert _categorize_path("/download/report") == "DOWNLOAD"

    def test_api_v1(self):
        assert _categorize_path("/api/v1/users") == "API"

    def test_api_v2(self):
        assert _categorize_path("/v2/orders") == "API"

    def test_api_rest(self):
        assert _categorize_path("/rest/products") == "API"

    def test_api_verb_toggle(self):
        assert _categorize_path("/stock-toggle") == "API"

    def test_api_verb_create(self):
        assert _categorize_path("/create-checkout") == "API"

    def test_api_verb_search(self):
        assert _categorize_path("/search") == "API"

    def test_unknown_static_page(self):
        assert _categorize_path("/about") == "UNKNOWN"

    def test_unknown_home(self):
        assert _categorize_path("/home") == "UNKNOWN"

    def test_api_verb_delete(self):
        assert _categorize_path("/user/delete") == "API"

    def test_auth_before_api(self):
        # /auth should win over /api even if both keywords present
        assert _categorize_path("/api/auth/token") == "AUTH"


# ── _canonical_key ────────────────────────────────────────────────────────────

class TestCanonicalKey:
    def test_trailing_slash(self):
        assert _canonical_key("/api/users/") == _canonical_key("/api/users")

    def test_lowercase(self):
        assert _canonical_key("/API/Users") == _canonical_key("/api/users")

    def test_query_stripped(self):
        assert _canonical_key("/api/users?page=1") == _canonical_key("/api/users")

    def test_full_url(self):
        k = _canonical_key("https://example.com/api/users")
        assert "example.com" in k
        assert "/api/users" in k

    def test_full_url_no_trailing_slash(self):
        a = _canonical_key("https://example.com/api/")
        b = _canonical_key("https://example.com/api")
        assert a == b


# ── _is_skip_url ──────────────────────────────────────────────────────────────

class TestIsSkipUrl:
    def test_skip_github(self):
        assert _is_skip_url("https://github.com/something") is True

    def test_skip_image(self):
        assert _is_skip_url("https://example.com/logo.png") is True

    def test_skip_font(self):
        assert _is_skip_url("/fonts/roboto.woff2") is True

    def test_keep_api(self):
        assert _is_skip_url("https://myapp.com/api/users") is False

    def test_keep_relative_path(self):
        assert _is_skip_url("/api/v1/products") is False

    def test_skip_twitter(self):
        assert _is_skip_url("https://twitter.com/share") is True


# ── correlate_endpoints ───────────────────────────────────────────────────────

def _make_ep(url, method="UNKNOWN", category="API", source="static", confidence=0.75):
    ep = Endpoint(
        url=url, path=url, method=method, category=category,
        source_file="test.js", line_number=1, confidence=confidence,
    )
    ep.source_type = source
    return ep


class TestCorrelateEndpoints:
    def test_unique_endpoints_preserved(self):
        static  = [_make_ep("/api/users")]
        runtime = [_make_ep("/api/orders")]
        result  = correlate_endpoints(static, runtime)
        urls = [e.url for e in result]
        assert "/api/users" in urls
        assert "/api/orders" in urls
        assert len(result) == 2

    def test_same_endpoint_merged(self):
        static  = [_make_ep("/api/users", method="UNKNOWN", category="UNKNOWN")]
        runtime = [_make_ep("/api/users", method="GET", category="API", source="runtime")]
        result  = correlate_endpoints(static, runtime)
        assert len(result) == 1
        ep = result[0]
        assert ep.source_type == "correlated"
        assert ep.method == "GET"
        assert ep.category == "API"

    def test_confidence_boosted_on_correlation(self):
        static  = [_make_ep("/api/users", confidence=0.75)]
        runtime = [_make_ep("/api/users", confidence=0.90, source="runtime")]
        result  = correlate_endpoints(static, runtime)
        assert result[0].confidence > 0.90

    def test_trailing_slash_normalized(self):
        static  = [_make_ep("/api/users/")]
        runtime = [_make_ep("/api/users", source="runtime")]
        result  = correlate_endpoints(static, runtime)
        assert len(result) == 1
        assert result[0].source_type == "correlated"

    def test_runtime_category_wins_over_unknown(self):
        static  = [_make_ep("/stock-toggle", category="UNKNOWN")]
        runtime = [_make_ep("/stock-toggle", category="API", source="runtime")]
        result  = correlate_endpoints(static, runtime)
        assert result[0].category == "API"

    def test_static_category_preserved_if_runtime_unknown(self):
        static  = [_make_ep("/graphql", category="GRAPHQL")]
        runtime = [_make_ep("/graphql", category="UNKNOWN", source="runtime")]
        result  = correlate_endpoints(static, runtime)
        assert result[0].category == "GRAPHQL"


# ── Content-hash dedup in _analyze ────────────────────────────────────────────

def _make_js(url, content, sha=None, source_page="https://test.com"):
    h = sha or hashlib.sha256(content.encode()).hexdigest()
    return JSFile(
        url=url, source_page=source_page, status_code=200,
        content_type="text/javascript", size_bytes=len(content),
        sha256=h, content=content,
    )


class TestContentHashDedup:
    """
    Verify _analyze() analyzes identical content only once
    but preserves provenance across all occurrences.
    """

    def _run_analyze(self, js_files):
        from bundlespy.cli import _analyze
        from bundlespy.analysis.secrets import SecretScanner
        scanner = SecretScanner()
        return _analyze(js_files, scanner)

    def test_identical_content_analyzed_once(self):
        content = 'var x = "/api/users";'
        js1 = _make_js("https://cdn.com/app.js", content)
        js2 = _make_js("https://other.com/app.js", content)  # same sha256
        _, endpoints, _ = self._run_analyze([js1, js2])
        # Should find /api/users only once, not twice
        urls = [e.url for e in endpoints]
        assert urls.count("/api/users") <= 1

    def test_different_content_both_analyzed(self):
        js1 = _make_js("a.js", 'var x = "/api/users";')
        js2 = _make_js("b.js", 'var y = "/api/orders";')
        _, endpoints, _ = self._run_analyze([js1, js2])
        urls = [e.url for e in endpoints]
        assert "/api/users" in urls
        assert "/api/orders" in urls

    def test_no_content_skipped(self):
        js = _make_js("a.js", "")
        js.content = ""
        findings, endpoints, _ = self._run_analyze([js])
        assert findings == []
        assert endpoints == []


# ── source_type on JSFile ─────────────────────────────────────────────────────

class TestJSFileSourceType:
    def test_default_source_type(self):
        js = JSFile(
            url="https://cdn.com/app.js", source_page="https://app.com",
            status_code=200, content_type="text/javascript",
            size_bytes=100, sha256="abc", content="",
        )
        assert js.source_type == "static"

    def test_source_type_assignable(self):
        js = JSFile(
            url="https://cdn.com/app.js", source_page="https://app.com",
            status_code=200, content_type="text/javascript",
            size_bytes=100, sha256="abc", content="",
        )
        js.source_type = "browser"
        assert js.source_type == "browser"


# ── Secret classification propagation ─────────────────────────────────────────

class TestSecretClassification:
    def test_finding_has_classification_field(self):
        f = Finding(
            id="x", rule_id="TEST", title="Test", category="API",
            severity="HIGH", confidence=0.9,
            file_url="test.js", source_page="https://test.com",
            line_number=1, column=0, matched_value="secret",
            redacted_value="****", sha256="abc", context="",
            description="", impact="", remediation="",
            false_positive_notes="", status="likely_secret",
            classification="SECRET",
        )
        assert f.classification == "SECRET"

    def test_finding_default_classification_empty(self):
        f = Finding(
            id="x", rule_id="TEST", title="Test", category="API",
            severity="HIGH", confidence=0.9,
            file_url="test.js", source_page="https://test.com",
            line_number=1, column=0, matched_value="secret",
            redacted_value="****", sha256="abc", context="",
            description="", impact="", remediation="",
            false_positive_notes="", status="likely_secret",
        )
        assert f.classification == ""

    def test_public_identifier_not_secret(self):
        f = Finding(
            id="x", rule_id="NETLIFY_SITE_ID", title="Netlify Site ID",
            category="Hosting", severity="INFO", confidence=0.85,
            file_url="html:test.com", source_page="test.com",
            line_number=1, column=0, matched_value="7b008eda-d5de-4df8-8771-4fb8a2479d5b",
            redacted_value="7b00****", sha256="abc", context="",
            description="", impact="", remediation="",
            false_positive_notes="", status="likely_secret",
            classification="PUBLIC_IDENTIFIER",
        )
        assert f.classification == "PUBLIC_IDENTIFIER"
        assert f.rule_id == "NETLIFY_SITE_ID"


# ── Endpoint source_type field ────────────────────────────────────────────────

class TestEndpointSourceType:
    def test_default_source_type(self):
        ep = Endpoint(
            url="/api/users", path="/api/users", method="GET",
            category="API", source_file="app.js", line_number=1, confidence=0.8,
        )
        assert ep.source_type == "static"

    def test_runtime_source_type(self):
        ep = Endpoint(
            url="/api/users", path="/api/users", method="GET",
            category="API", source_file="app.js", line_number=1, confidence=0.8,
            source_type="runtime",
        )
        assert ep.source_type == "runtime"
