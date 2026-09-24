"""
Canonical discovery registry regression tests (Stage 2).

Proves the DiscoveryRegistry contract:

    DISCOVERY SOURCES
          |
    CANONICAL REGISTRY
          |- routes          (Endpoint, category=ROUTE)
          |- endpoints       (Endpoint, non-ROUTE)
          |- findings        (Finding)
          |- assets          (JSFile)
          `- runtime_events  (dict)
               |
         CORRELATION / GRAPH
               |
         TERMINAL / HTML / JSON
"""

import hashlib
from datetime import datetime

import pytest

from bundlespy.storage.models import Endpoint, Finding, JSFile, InfrastructureItem
from bundlespy.storage.registry import DiscoveryRegistry


def _route(url: str, source_file: str = "https://app.example.com/app.js",
           confidence: float = 0.90) -> Endpoint:
    return Endpoint(
        url=url, path=url, method="GET", category="ROUTE",
        source_file=source_file, line_number=1, confidence=confidence,
    )


def _api(url: str, method: str = "GET",
         category: str = "API",
         source_file: str = "https://app.example.com/app.js") -> Endpoint:
    return Endpoint(
        url=url, path=url, method=method, category=category,
        source_file=source_file, line_number=1, confidence=0.85,
    )


def _finding(value: str = "AKIA1234SECRET") -> Finding:
    sha = hashlib.sha256(value.encode()).hexdigest()
    fid = Finding.make_id("aws-key", value, "https://app.example.com/app.js")
    return Finding(
        id=fid, rule_id="aws-key", title="AWS Access Key",
        category="SECRET", severity="CRITICAL", confidence=0.98,
        file_url="https://app.example.com/app.js",
        source_page="https://app.example.com/",
        line_number=42, column=0,
        matched_value=value, redacted_value=Finding.redact(value),
        sha256=sha, context="const KEY = 'AKIA1234SECRET';",
        description="AWS key found", impact="Full account access",
        remediation="Rotate key", false_positive_notes="",
        status="likely_secret",
    )


def _js_file(url: str, content: str = "router.push('/home');") -> JSFile:
    sha = hashlib.sha256(content.encode()).hexdigest()
    return JSFile(
        url=url, source_page="https://app.example.com/",
        status_code=200, content_type="application/javascript",
        size_bytes=len(content.encode()), sha256=sha, content=content,
    )


def _infra(value: str = "10.0.0.1") -> InfrastructureItem:
    return InfrastructureItem(
        value=value, classification="PRIVATE_IP",
        source_file="https://app.example.com/app.js",
        line_number=5, confidence=0.95, action="investigate",
    )


class TestLaneRouting:
    def test_route_endpoint_goes_to_routes_lane(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/dashboard"))
        assert len(reg.routes)    == 1
        assert len(reg.endpoints) == 0

    def test_api_endpoint_goes_to_endpoints_lane(self):
        reg = DiscoveryRegistry()
        reg.add(_api("/api/users"))
        assert len(reg.endpoints) == 1
        assert len(reg.routes)    == 0

    def test_finding_goes_to_findings_lane(self):
        reg = DiscoveryRegistry()
        reg.add(_finding())
        assert len(reg.findings)  == 1
        assert len(reg.routes)    == 0
        assert len(reg.endpoints) == 0

    def test_js_file_goes_to_assets_lane(self):
        reg = DiscoveryRegistry()
        reg.add(_js_file("https://app.example.com/app.js"))
        assert len(reg.assets)    == 1
        assert len(reg.findings)  == 0
        assert len(reg.routes)    == 0

    def test_infra_item_goes_to_infrastructure_lane(self):
        reg = DiscoveryRegistry()
        reg.add(_infra("10.0.0.1"))
        assert reg.stats["infrastructure"] == 1

    def test_runtime_event_dict_goes_to_events_lane(self):
        reg = DiscoveryRegistry()
        reg.add_runtime_event("fetch", "/api/data", method="POST")
        assert len(reg.runtime_events) == 1

    def test_all_endpoints_combines_routes_and_endpoints(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/home"))
        reg.add(_api("/api/users"))
        assert len(reg.all_endpoints) == 2
        cats = {ep.category for ep in reg.all_endpoints}
        assert "ROUTE" in cats
        assert "API"   in cats


class TestLaneSeparation:
    def test_route_is_not_api_endpoint(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/admin"))
        assert len(reg.endpoints) == 0
        assert len(reg.routes)    == 1
        assert reg.routes[0].category == "ROUTE"

    def test_api_endpoint_is_not_route(self):
        reg = DiscoveryRegistry()
        reg.add(_api("/api/v1/users"))
        assert len(reg.routes)    == 0
        assert len(reg.endpoints) == 1
        assert reg.endpoints[0].category == "API"

    def test_same_url_as_route_and_api_produces_two_typed_records(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/admin"))
        reg.add(_api("/admin", category="ADMIN"))

        assert len(reg.routes)    == 1
        assert len(reg.endpoints) == 1
        assert reg.routes[0].category    == "ROUTE"
        assert reg.endpoints[0].category == "ADMIN"
        assert len(reg.all_endpoints) == 2

    def test_graphql_endpoint_does_not_become_route(self):
        reg = DiscoveryRegistry()
        reg.add(_api("/graphql", method="POST", category="GRAPHQL"))
        assert len(reg.routes)    == 0
        assert len(reg.endpoints) == 1
        assert reg.endpoints[0].category == "GRAPHQL"

    def test_websocket_endpoint_does_not_become_route(self):
        reg = DiscoveryRegistry()
        reg.add(_api("/ws/live", category="WEBSOCKET"))
        assert len(reg.routes)    == 0
        assert len(reg.endpoints) == 1
        assert reg.endpoints[0].category == "WEBSOCKET"

    def test_worker_endpoint_goes_to_endpoints_not_routes(self):
        ep = _api("/workers/crypto.worker.js", category="UNKNOWN")
        reg = DiscoveryRegistry()
        reg.add(ep)
        assert len(reg.routes)    == 0
        assert len(reg.endpoints) == 1


class TestDeduplication:
    def test_duplicate_routes_produce_one_record(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/settings"))
        reg.add(_route("/settings"))
        assert len(reg.routes) == 1

    def test_duplicate_endpoints_produce_one_record(self):
        reg = DiscoveryRegistry()
        reg.add(_api("/api/users"))
        reg.add(_api("/api/users"))
        assert len(reg.endpoints) == 1

    def test_duplicate_findings_produce_one_record(self):
        reg = DiscoveryRegistry()
        f = _finding("AKIA_SECRET_KEY")
        reg.add(f)
        reg.add(f)
        assert len(reg.findings) == 1

    def test_duplicate_assets_produce_one_record(self):
        reg = DiscoveryRegistry()
        js = _js_file("https://app.example.com/app.js")
        reg.add(js)
        reg.add(js)
        assert len(reg.assets) == 1

    def test_routes_and_endpoints_dedup_independently(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/admin"))
        reg.add(_route("/admin"))
        reg.add(_api("/admin", category="ADMIN"))
        reg.add(_api("/admin", category="ADMIN"))

        assert len(reg.routes)    == 1
        assert len(reg.endpoints) == 1

    def test_trailing_slash_variants_deduplicated_as_same_route(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/settings"))
        reg.add(_route("/settings/"))
        assert len(reg.routes) == 1

    def test_query_string_variants_deduplicated_as_same_route(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/page?tab=1"))
        reg.add(_route("/page"))
        assert len(reg.routes) == 1

    def test_case_insensitive_route_dedup(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/Admin"))
        reg.add(_route("/admin"))
        assert len(reg.routes) == 1

    def test_runtime_event_deduplicated_by_type_and_url(self):
        reg = DiscoveryRegistry()
        reg.add_runtime_event("fetch", "/api/data")
        reg.add_runtime_event("fetch", "/api/data")
        assert len(reg.runtime_events) == 1

    def test_add_returns_true_for_new_false_for_dup(self):
        reg = DiscoveryRegistry()
        ep = _route("/profile")
        assert reg.add(ep) is True
        assert reg.add(ep) is False


class TestProvenance:
    def test_static_source_type_preserved(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/home"), source_type="static")
        assert reg.routes[0].source_type == "static"

    def test_runtime_source_type_preserved(self):
        reg = DiscoveryRegistry()
        ep = _api("/api/orders")
        reg.add(ep, source_type="runtime")
        assert reg.endpoints[0].source_type == "runtime"

    def test_source_file_preserved_on_route(self):
        sf = "https://app.example.com/chunk.abc.js"
        reg = DiscoveryRegistry()
        reg.add(_route("/checkout", source_file=sf))
        assert reg.routes[0].source_file == sf

    def test_source_file_preserved_on_endpoint(self):
        sf = "https://app.example.com/vendor.js"
        reg = DiscoveryRegistry()
        reg.add(_api("/api/v2/products", source_file=sf))
        assert reg.endpoints[0].source_file == sf

    def test_static_and_runtime_correlation_preserved(self):
        reg = DiscoveryRegistry()
        static_ep  = _api("/api/payments")
        runtime_ep = _api("/api/payments")
        reg.add(static_ep,  source_type="static")
        reg.add(runtime_ep, source_type="runtime")

        assert len(reg.endpoints) == 1
        assert reg.endpoints[0].source_type == "static"


class TestCorrelation:
    def test_correlate_finds_route_and_api_for_same_url(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/admin"))
        reg.add(_api("/admin/users"))
        reg.add_runtime_event("fetch", "/admin/users", method="GET")

        result = reg.correlate("/admin")
        assert len(result["routes"])    == 1
        assert len(result["endpoints"]) == 1
        assert "runtime_events" in result

    def test_correlate_returns_empty_lists_for_unknown_url(self):
        reg = DiscoveryRegistry()
        result = reg.correlate("/nonexistent-page")
        assert result["routes"]         == []
        assert result["endpoints"]      == []
        assert result["findings"]       == []
        assert result["assets"]         == []
        assert result["runtime_events"] == []

    def test_correlate_ignores_unrelated_entries(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/admin"))
        reg.add(_api("/api/v1/users"))

        result = reg.correlate("/admin")
        assert len(result["routes"])    == 1
        assert len(result["endpoints"]) == 0


class TestStats:
    def test_stats_reflect_current_counts(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/home"))
        reg.add(_api("/api/users"))
        reg.add(_finding())
        reg.add(_js_file("https://app.example.com/app.js"))

        s = reg.stats
        assert s["routes"]    == 1
        assert s["endpoints"] == 1
        assert s["findings"]  == 1
        assert s["assets"]    == 1

    def test_repr_does_not_raise(self):
        reg = DiscoveryRegistry()
        reg.add(_route("/home"))
        r = repr(reg)
        assert "DiscoveryRegistry" in r
        assert "routes=1" in r

    def test_empty_registry_stats_are_all_zero(self):
        reg = DiscoveryRegistry()
        for v in reg.stats.values():
            assert v == 0

    def test_add_bad_object_does_not_raise(self):
        reg = DiscoveryRegistry()
        reg.add(None)
        reg.add(42)
        reg.add("not-an-endpoint")
        assert reg.stats["routes"] == 0


class TestExplicitHelpers:
    def test_add_route_forces_route_category(self):
        ep = _api("/login")
        reg = DiscoveryRegistry()
        reg.add_route(ep)
        assert len(reg.routes)    == 1
        assert len(reg.endpoints) == 0
        assert reg.routes[0].category == "ROUTE"

    def test_add_endpoint_routes_to_endpoints_lane(self):
        ep = _api("/api/orders")
        reg = DiscoveryRegistry()
        reg.add_endpoint(ep)
        assert len(reg.endpoints) == 1
        assert len(reg.routes)    == 0


class TestRegistryFromAnalyze:
    def test_analyze_output_populates_registry_lanes(self):
        import hashlib
        from bundlespy.storage.models import JSFile
        from bundlespy.analysis.secrets import SecretScanner
        from bundlespy.cli import _analyze

        js_content = """
            const ROUTES = { HOME: '/home', SETTINGS: '/settings' };
            router.push('/reports');
            fetch('/api/v1/data', { method: 'GET' });
        """
        sha = hashlib.sha256(js_content.encode()).hexdigest()
        js = JSFile(
            url="https://app.example.com/app.js",
            source_page="https://app.example.com/",
            status_code=200, content_type="application/javascript",
            size_bytes=len(js_content.encode()), sha256=sha, content=js_content,
        )
        _, endpoints, _, _ = _analyze([js], SecretScanner())

        reg = DiscoveryRegistry()
        for ep in endpoints:
            reg.add(ep)

        route_paths = {ep.url for ep in reg.routes}
        assert "/home"     in route_paths, f"routes: {route_paths}"
        assert "/settings" in route_paths, f"routes: {route_paths}"
        assert "/reports"  in route_paths, f"routes: {route_paths}"

        for ep in reg.endpoints:
            assert ep.category != "ROUTE", (
                f"{ep.url} with category ROUTE leaked into endpoints lane"
            )

    def test_route_extractor_feeds_route_lane(self):
        from bundlespy.analysis.route_extractor import extract_routes

        js = """
            createBrowserRouter([
                { path: '/app', element: '<App />' },
                { path: '/app/dashboard', element: '<Dashboard />' },
            ]);
        """
        eps = extract_routes(js, "https://app.example.com/app.js")
        reg = DiscoveryRegistry()
        for ep in eps:
            reg.add(ep)

        assert len(reg.routes)    > 0
        assert len(reg.endpoints) == 0
        for ep in reg.routes:
            assert ep.category == "ROUTE"
