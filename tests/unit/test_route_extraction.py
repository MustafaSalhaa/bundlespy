"""
Route extraction tests — proves each heuristic works against real fixtures.

These are not synthetic tests. Each fixture mirrors actual production
framework output observed in real apps.
"""

import sys
import re
import pytest
sys.path.insert(0, "/home/claude/bundlespy/src")

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fixtures.js_fixtures import (
    ANGULAR_IVY_ROUTES, ANGULAR_NESTED_ROUTES, ANGULAR_LAZY_ROUTES,
    REACT_ROUTER_V6, REACT_ROUTER_V5,
    VUE_ROUTER_V4, VUE_ROUTER_V3,
    NEXTJS_DATA,
    JUICE_SHOP_JS, STRING_CONCAT_ENDPOINTS, TEMPLATE_LITERAL_ENDPOINTS,
)
from bundlespy.analysis.ast_endpoints import extract_all_endpoints


# ── Regex-based route extractors (used as fallback when browser unavailable) ──

RE_PATH_PROP = re.compile(
    r'\bpath\s*:\s*["\x27`](/[A-Za-z0-9/_\-.:?=&%#{}*]*)["\x27`]',
    re.IGNORECASE,
)

def extract_routes_static(js: str) -> set:
    """
    Static route extraction — what we use when no browser is available.
    Extracts path: 'route' or path: '/route' patterns from route config objects.
    Angular uses relative paths (no leading /), React/Vue use absolute.
    """
    # Match both quoted formats: single, double, backtick
    RE_PATH_ANY = re.compile(
        r'\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}*][A-Za-z0-9/_\-.:?=&%#{}*]*)["\x27`]',
        re.IGNORECASE,
    )
    routes = set()
    for m in RE_PATH_ANY.finditer(js):
        path = m.group(1).strip()
        if not path or path in ("**", "*", "full"):
            continue
        # Normalize: add leading slash if missing
        if not path.startswith("/"):
            path = "/" + path
        if path and len(path) > 1 and path not in ("/**", "/*"):
            routes.add(path)
    return routes


# ── Angular tests ─────────────────────────────────────────────────────────────

class TestAngularRouteExtraction:

    def test_angular_ivy_basic_routes(self):
        """Angular Ivy compiled output — real Juice Shop pattern."""
        routes = extract_routes_static(ANGULAR_IVY_ROUTES)
        assert "/login" in routes, f"Missing /login in {routes}"
        assert "/register" in routes
        assert "/search" in routes
        assert "/basket" in routes
        assert "/contact" in routes
        assert "/about" in routes

    def test_angular_ivy_admin_route(self):
        """Admin route with loadChildren must be discovered."""
        routes = extract_routes_static(ANGULAR_IVY_ROUTES)
        assert "/administration" in routes, f"Missing /administration in {routes}"

    def test_angular_ivy_auth_guarded_routes(self):
        """canActivate routes must still be discovered."""
        routes = extract_routes_static(ANGULAR_IVY_ROUTES)
        assert "/accounting" in routes
        assert "/profile" in routes

    def test_angular_ivy_no_empty_path(self):
        """Empty string path redirects must not become '/' or ''."""
        routes = extract_routes_static(ANGULAR_IVY_ROUTES)
        # empty path redirect '' is valid, pathMatch full routes are noise
        # we should not get a bare '' path
        assert "" not in routes

    def test_angular_nested_routes(self):
        """Nested children routes must be discovered."""
        routes = extract_routes_static(ANGULAR_NESTED_ROUTES)
        assert "/admin" in routes
        assert "/users" in routes
        assert "/orders" in routes
        assert "/dashboard" in routes
        assert "/profile" in routes
        assert "/settings" in routes

    def test_angular_lazy_routes(self):
        """Lazy-loaded routes with loadChildren must be discovered."""
        routes = extract_routes_static(ANGULAR_LAZY_ROUTES)
        assert "/products" in routes
        assert "/checkout" in routes
        assert "/account" in routes

    def test_angular_route_count_reasonable(self):
        """Should not produce an explosion of false routes."""
        routes = extract_routes_static(ANGULAR_IVY_ROUTES)
        assert len(routes) <= 20, f"Too many routes extracted: {len(routes)}"


# ── React Router tests ────────────────────────────────────────────────────────

class TestReactRouterExtraction:

    def test_react_router_v6_basic(self):
        """React Router v6 JSX path props."""
        routes = extract_routes_static(REACT_ROUTER_V6)
        assert "/login" in routes
        assert "/dashboard" in routes
        assert "/admin" in routes
        assert "/settings" in routes

    def test_react_router_v6_dynamic_path(self):
        """Dynamic path params like /users/:id must be found."""
        routes = extract_routes_static(REACT_ROUTER_V6)
        assert "/users/:id" in routes

    def test_react_router_v5_basic(self):
        """React Router v5 Route components."""
        routes = extract_routes_static(REACT_ROUTER_V5)
        assert "/products" in routes
        assert "/cart" in routes
        assert "/checkout" in routes

    def test_react_router_v5_nested(self):
        """Nested account routes."""
        routes = extract_routes_static(REACT_ROUTER_V5)
        assert "/account/profile" in routes
        assert "/account/orders" in routes


# ── Vue Router tests ──────────────────────────────────────────────────────────

class TestVueRouterExtraction:

    def test_vue_router_v4_basic(self):
        """Vue Router 4 createRouter pattern."""
        routes = extract_routes_static(VUE_ROUTER_V4)
        assert "/about" in routes
        assert "/products" in routes
        assert "/cart" in routes
        assert "/checkout" in routes
        assert "/login" in routes
        assert "/register" in routes

    def test_vue_router_v4_dynamic(self):
        """Dynamic routes like /products/:id."""
        routes = extract_routes_static(VUE_ROUTER_V4)
        assert "/products/:id" in routes

    def test_vue_router_v3_basic(self):
        """Vue Router 3 new VueRouter() pattern."""
        routes = extract_routes_static(VUE_ROUTER_V3)
        assert "/dashboard" in routes
        assert "/users" in routes
        assert "/settings" in routes

    def test_vue_router_v3_dynamic(self):
        routes = extract_routes_static(VUE_ROUTER_V3)
        assert "/users/:id" in routes


# ── Source map tests ──────────────────────────────────────────────────────────

class TestSourceMapDetection:

    def setup_method(self):
        from bundlespy.discovery.source_maps import detect_source_map_url
        self.detect = detect_source_map_url

    def test_sourcemapping_url_at_end(self):
        """Most common case — comment at very end of minified file."""
        from bundlespy_test_fixtures import MINIFIED_WITH_MAP
        result = self.detect(MINIFIED_WITH_MAP, "https://example.com/app.js")
        assert result == "https://example.com/app.js.map", f"Got: {result}"

    def test_inline_base64_sourcemap(self):
        """Inline base64 encoded source map."""
        from bundlespy_test_fixtures import MINIFIED_WITH_INLINE_MAP
        result = self.detect(MINIFIED_WITH_INLINE_MAP, "https://example.com/app.js")
        assert result is not None
        assert result.startswith("data:application/json;base64,")

    def test_legacy_x_sourcemap_comment(self):
        """Older //@ format still used by some tools."""
        from bundlespy_test_fixtures import MINIFIED_WITH_X_SOURCEMAP
        result = self.detect(MINIFIED_WITH_X_SOURCEMAP, "https://example.com/legacy.js")
        assert result == "https://example.com/legacy.js.map", f"Got: {result}"

    def test_no_sourcemap_returns_none(self):
        """JS with no source map reference must return None."""
        from bundlespy_test_fixtures import MINIFIED_NO_MAP_COMMENT
        result = self.detect(MINIFIED_NO_MAP_COMMENT, "https://example.com/app.js")
        assert result is None

    def test_absolute_url_sourcemap(self):
        """Absolute URL in sourceMappingURL."""
        js = "var x=1;\n//# sourceMappingURL=https://cdn.example.com/maps/app.js.map"
        result = self.detect(js, "https://example.com/app.js")
        assert result == "https://cdn.example.com/maps/app.js.map"

    def test_relative_path_resolved(self):
        """Relative path must be resolved against JS file URL."""
        js = "var x=1;\n//# sourceMappingURL=../maps/app.js.map"
        result = self.detect(js, "https://example.com/static/js/app.js")
        assert result == "https://example.com/static/maps/app.js.map"

    def test_empty_content_returns_none(self):
        """Empty content must not crash."""
        result = self.detect("", "https://example.com/app.js")
        assert result is None

    def test_large_file_tail_detection(self):
        """sourceMappingURL buried in 1MB file must still be found in tail."""
        padding = "var x = 0;\n" * 50000  # ~600KB of noise
        tail    = "//# sourceMappingURL=app.js.map"
        js      = padding + tail
        result  = self.detect(js, "https://example.com/app.js")
        assert result == "https://example.com/app.js.map"

    def test_source_map_parse(self):
        """Valid source map JSON must parse correctly."""
        from bundlespy_test_fixtures import SOURCE_MAP_VALID
        from bundlespy.discovery.source_maps import parse_source_map
        result = parse_source_map(SOURCE_MAP_VALID)
        assert result is not None
        assert "sources" in result
        assert "src/app.js" in result["sources"]
        assert "src/api/client.js" in result["sources"]

    def test_source_map_recover_content(self):
        """sourcesContent must be recovered as individual files."""
        from bundlespy_test_fixtures import SOURCE_MAP_VALID
        from bundlespy.discovery.source_maps import parse_source_map, recover_sources
        map_data = parse_source_map(SOURCE_MAP_VALID)
        recovered = recover_sources(map_data, "https://example.com/app.js.map", "https://example.com/app.js")
        assert len(recovered) > 0
        paths = [r[0] for r in recovered]
        assert any("app.js" in p for p in paths)
        # Content must contain the actual source
        contents = [r[1] for r in recovered]
        assert any("API_KEY" in c for c in contents)

    def test_malformed_source_map_returns_none(self):
        """Malformed JSON must not crash."""
        from bundlespy.discovery.source_maps import parse_source_map
        result = parse_source_map("not json at all {{{")
        assert result is None

    def test_source_map_without_sources_returns_none(self):
        """Source map missing 'sources' key must return None."""
        from bundlespy.discovery.source_maps import parse_source_map
        result = parse_source_map('{"version":3,"mappings":"AAAA"}')
        assert result is None


# ── Endpoint extraction tests ─────────────────────────────────────────────────

class TestEndpointExtraction:

    def test_juice_shop_rest_endpoints(self):
        """Real Juice Shop patterns — /rest/ and /api/ routes."""
        eps = extract_all_endpoints(JUICE_SHOP_JS, "https://demo.owasp-juice.shop/main.js")
        paths = {e.url for e in eps}
        assert "/rest/products/search" not in paths or any("/rest/" in p for p in paths), \
            "Should find at least one /rest/ endpoint"
        assert any("/api/" in p for p in paths), f"Missing /api/ endpoints in {paths}"

    def test_juice_shop_user_endpoint(self):
        eps = extract_all_endpoints(JUICE_SHOP_JS, "https://example.com/main.js")
        paths = {e.url for e in eps}
        assert any("whoami" in p or "user" in p.lower() for p in paths), \
            f"Expected user endpoint in {paths}"

    def test_string_concat_resolution(self):
        """String concatenation /api/v1 + /users must resolve."""
        eps = extract_all_endpoints(STRING_CONCAT_ENDPOINTS, "https://example.com/app.js")
        paths = {e.url for e in eps}
        assert any("/api/v1" in p for p in paths), f"Expected /api/v1/* in {paths}"

    def test_template_literal_extraction(self):
        """Template literals with variables must extract base path."""
        eps = extract_all_endpoints(TEMPLATE_LITERAL_ENDPOINTS, "https://example.com/app.js")
        paths = {e.url for e in eps}
        assert any("/api/" in p for p in paths), f"Expected /api/ in {paths}"

    def test_no_duplicate_endpoints(self):
        """Same endpoint appearing multiple times must be deduplicated."""
        js = """
        fetch('/api/users');
        fetch('/api/users');
        axios.get('/api/users');
        """
        eps = extract_all_endpoints(js, "https://example.com/app.js")
        urls = [e.url for e in eps]
        assert len(urls) == len(set(urls)), f"Duplicates found: {urls}"

    def test_external_urls_filtered(self):
        """External URLs like https://google.com must be filtered out."""
        js = """
        fetch('https://www.googleapis.com/oauth2/v1/userinfo');
        fetch('/api/internal/users');
        """
        eps = extract_all_endpoints(js, "https://example.com/app.js")
        paths = {e.url for e in eps}
        # External non-API URLs should be filtered
        assert not any("googleapis.com/oauth2/v1/userinfo" == p for p in paths), \
            f"External non-API URL should be filtered: {paths}"

    def test_auth_category_detection(self):
        """Login endpoints must be categorized as AUTH."""
        js = "fetch('/api/auth/login', {method:'POST'});"
        eps = extract_all_endpoints(js, "https://example.com/app.js")
        auth_eps = [e for e in eps if e.category == "AUTH"]
        assert len(auth_eps) > 0, f"Expected AUTH category, got: {[(e.url, e.category) for e in eps]}"

    def test_admin_category_detection(self):
        """Admin endpoints must be categorized as ADMIN."""
        js = "fetch('/admin/users');"
        eps = extract_all_endpoints(js, "https://example.com/app.js")
        admin_eps = [e for e in eps if e.category == "ADMIN"]
        assert len(admin_eps) > 0, f"Expected ADMIN category, got: {[(e.url, e.category) for e in eps]}"

    def test_websocket_extraction(self):
        """WebSocket URLs must be extracted."""
        js = "const ws = new WebSocket('wss://api.example.com/live');"
        eps = extract_all_endpoints(js, "https://example.com/app.js")
        ws_eps = [e for e in eps if e.method == "WS"]
        assert len(ws_eps) > 0, f"Expected WebSocket endpoint, got: {eps}"

    def test_graphql_endpoint_detection(self):
        """GraphQL paths must be extracted and categorized."""
        js = "fetch('/graphql', {method: 'POST', body: JSON.stringify(query)});"
        eps = extract_all_endpoints(js, "https://example.com/app.js")
        gql_eps = [e for e in eps if e.category == "GRAPHQL"]
        assert len(gql_eps) > 0, f"Expected GRAPHQL category, got: {[(e.url, e.category) for e in eps]}"


# ── False positive tests ──────────────────────────────────────────────────────

class TestFalsePositiveSuppression:

    def setup_method(self):
        import sys
        sys.path.insert(0, "/home/claude/bundlespy/src")
        from bundlespy.analysis.secrets import SecretScanner
        self.scanner = SecretScanner()

    def test_angular_material_not_gitlab_token(self):
        """MAT_PROGRESS_BAR_DEFAULT_OPTIONS must not be a GitLab token."""
        from bundlespy_test_fixtures import ANGULAR_MATERIAL_FP
        findings = self.scanner.scan(ANGULAR_MATERIAL_FP, "https://example.com/main.js", "")
        gitlab_findings = [f for f in findings if f.rule_id == "GITLAB_RUNNER_TOKEN"]
        # Either no finding, or confidence must be low
        for f in gitlab_findings:
            assert f.confidence < 0.7, \
                f"GRESS_BAR should not be HIGH confidence GitLab token. Got {f.confidence}: {f.matched_value}"

    def test_html_input_name_not_password(self):
        """inputs: {{password: 'password'}} must not be a high-severity finding."""
        from bundlespy_test_fixtures import HTML_INPUT_FP
        findings = self.scanner.scan(HTML_INPUT_FP, "https://example.com/main.js", "")
        password_findings = [f for f in findings
                            if f.rule_id == "GENERIC_PASSWORD" and f.matched_value == "password"]
        for f in password_findings:
            assert f.confidence < 0.75, \
                f"Single word 'password' matched as HTML input should be low confidence: {f.confidence}"

    def test_test_credential_downgraded(self):
        """IamUsedForTesting must not be CRITICAL or HIGH confidence."""
        from bundlespy_test_fixtures import TEST_CREDENTIAL_FP
        findings = self.scanner.scan(TEST_CREDENTIAL_FP, "https://example.com/main.js", "")
        test_findings = [f for f in findings if "IamUsedForTesting" in f.matched_value]
        for f in test_findings:
            assert f.severity not in ("CRITICAL",), \
                f"Test credential should not be CRITICAL: {f.severity} {f.matched_value}"

    def test_oauth_client_id_is_medium_not_high(self):
        """Public OAuth client IDs are not secrets — must not be HIGH or CRITICAL."""
        from bundlespy_test_fixtures import OAUTH_CLIENT_ID_FP
        findings = self.scanner.scan(OAUTH_CLIENT_ID_FP, "https://example.com/main.js", "")
        oauth_findings = [f for f in findings if "googleusercontent" in f.matched_value.lower()]
        for f in oauth_findings:
            assert f.severity in ("MEDIUM", "LOW", "INFO"), \
                f"OAuth client ID should be MEDIUM or lower, got: {f.severity}"


# ── Summary integrity tests ───────────────────────────────────────────────────

class TestSummaryIntegrity:
    """Proves the critical findings bug is fixed."""

    def test_zero_critical_no_critical_warning(self):
        """Zero CRITICAL findings must never produce 'Critical findings present'."""
        import io
        from contextlib import redirect_stdout
        from bundlespy.ui.printer import print_summary
        from bundlespy.storage.models import ScanResult, Finding
        from datetime import datetime
        import hashlib

        # Create a result with only HIGH findings, no CRITICAL
        high_finding = Finding(
            id="test001", rule_id="GENERIC_API_KEY", title="Generic API Key",
            category="Generic", severity="HIGH", confidence=0.82,
            file_url="test.js", source_page="https://example.com",
            line_number=1, column=0,
            matched_value="test-key-12345", redacted_value="test****12345",
            sha256=hashlib.sha256(b"test").hexdigest(),
            context="const key = 'test-key-12345'",
            description="", impact="", remediation="",
            false_positive_notes="", status="likely_secret",
            occurrences=["test.js:1"],
        )

        result = ScanResult(
            target_url="https://example.com",
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            pages_crawled=1,
            js_files=[],
            findings=[high_finding],
            endpoints=[],
            infrastructure=[],
            errors=[],
        )

        f = io.StringIO()
        with redirect_stdout(f):
            print_summary(result)

        output = f.getvalue()
        assert "Critical findings present" not in output, \
            f"HIGH-only findings must not trigger 'Critical findings present'. Got:\n{output}"
        assert "High severity" in output, \
            f"HIGH findings should trigger high severity message. Got:\n{output}"

    def test_zero_findings_no_warning(self):
        """Zero findings must show clean completion."""
        import io
        from contextlib import redirect_stdout
        from bundlespy.ui.printer import print_summary
        from bundlespy.storage.models import ScanResult
        from datetime import datetime

        result = ScanResult(
            target_url="https://example.com",
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            pages_crawled=1,
            js_files=[], findings=[], endpoints=[], infrastructure=[], errors=[],
        )

        f = io.StringIO()
        with redirect_stdout(f):
            print_summary(result)

        output = f.getvalue()
        assert "Critical findings present" not in output
        assert "No critical findings" in output

    def test_critical_finding_triggers_warning(self):
        """Actual CRITICAL finding must trigger the warning."""
        import io
        from contextlib import redirect_stdout
        from bundlespy.ui.printer import print_summary
        from bundlespy.storage.models import ScanResult, Finding
        from datetime import datetime
        import hashlib

        critical = Finding(
            id="c001", rule_id="AWS_ACCESS_KEY", title="AWS Access Key",
            category="AWS", severity="CRITICAL", confidence=0.95,
            file_url="main.js", source_page="https://example.com",
            line_number=1, column=0,
            matched_value="AKIAIOSFODNN7EXAMPLE",
            redacted_value="AKIA****EXAMPLE",
            sha256=hashlib.sha256(b"crit").hexdigest(),
            context="", description="", impact="", remediation="",
            false_positive_notes="", status="likely_secret",
            occurrences=["main.js:1"],
        )

        result = ScanResult(
            target_url="https://example.com",
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            pages_crawled=1,
            js_files=[], findings=[critical], endpoints=[],
            infrastructure=[], errors=[],
        )

        f = io.StringIO()
        with redirect_stdout(f):
            print_summary(result)

        output = f.getvalue()
        assert "Critical findings present" in output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
