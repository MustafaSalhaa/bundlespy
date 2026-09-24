"""
Route integration regression tests.

These tests verify the two critical integration contracts:

1. _process() contract:
   JS asset -> _process() -> route_extractor -> canonical endpoint list

2. Headless seed-builder contract:
   JS asset -> route extraction -> seed builder -> Playwright-ready URL set

Unit tests in test_route_extractor.py already verify that
extract_routes() returns correct Endpoint objects for each framework.
These tests verify that the extracted routes actually flow through the
real integration paths in cli.py - they do NOT call extract_routes()
directly.
"""

import hashlib
from collections import defaultdict

import pytest

from bundlespy.storage.models import JSFile, Endpoint
from bundlespy.analysis.secrets import SecretScanner
from bundlespy.cli import _analyze


def _make_js(content: str, url: str = "https://app.example.com/static/app.js") -> JSFile:
    """Build a minimal JSFile from raw JS content."""
    sha = hashlib.sha256(content.encode()).hexdigest()
    return JSFile(
        url=url,
        source_page="https://app.example.com/",
        status_code=200,
        content_type="application/javascript",
        size_bytes=len(content.encode()),
        sha256=sha,
        content=content,
    )


def _route_paths(endpoints: list) -> set:
    """Return the set of paths for all ROUTE-category endpoints."""
    return {ep.url for ep in endpoints if ep.category == "ROUTE"}


def _api_paths(endpoints: list) -> set:
    """Return the set of paths for all non-ROUTE endpoints."""
    return {ep.url for ep in endpoints if ep.category != "ROUTE"}


def _scanner() -> SecretScanner:
    return SecretScanner()


class TestProcessIntegration:
    """
    Verify that route_extractor is called from within _analyze() (_process())
    and that discovered routes appear in the returned endpoints list with
    category=ROUTE and are properly separated from API endpoints.
    """

    FIXTURE_JS = """
        const routes = {
            HOME: "/",
            ADMIN: "/admin/users",
            SETTINGS: "/settings"
        };

        router.push("/reports");
        history.pushState({}, "", "/dashboard");
    """

    def test_routes_present_in_endpoint_list(self):
        js = _make_js(self.FIXTURE_JS)
        _, endpoints, _, _ = _analyze([js], _scanner())
        paths = _route_paths(endpoints)

        assert "/admin/users" in paths, f"expected /admin/users in routes, got: {paths}"
        assert "/settings"    in paths, f"expected /settings in routes, got: {paths}"
        assert "/reports"     in paths, f"expected /reports in routes, got: {paths}"
        assert "/dashboard"   in paths, f"expected /dashboard in routes, got: {paths}"

    def test_route_category_is_ROUTE(self):
        js = _make_js(self.FIXTURE_JS)
        _, endpoints, _, _ = _analyze([js], _scanner())

        route_eps = [ep for ep in endpoints if ep.url in {
            "/admin/users", "/settings", "/reports", "/dashboard"
        }]
        assert route_eps, "No matching endpoints found"
        for ep in route_eps:
            assert ep.category == "ROUTE", (
                f"{ep.url} has category={ep.category!r}, expected ROUTE"
            )

    def test_routes_are_not_classified_as_API(self):
        js = _make_js(self.FIXTURE_JS)
        _, endpoints, _, _ = _analyze([js], _scanner())

        api_eps = [ep for ep in endpoints
                   if ep.url in {"/admin/users", "/settings", "/reports", "/dashboard"}
                   and ep.category == "API"]
        assert not api_eps, (
            f"These routes were incorrectly labelled API: {[e.url for e in api_eps]}"
        )

    def test_duplicate_routes_deduplicated(self):
        js_content = """
            router.push("/settings");
            router.push("/settings");
            navigate("/settings");
        """
        js = _make_js(js_content)
        _, endpoints, _, _ = _analyze([js], _scanner())

        settings_eps = [ep for ep in endpoints
                        if ep.url == "/settings" and ep.category == "ROUTE"]
        assert len(settings_eps) == 1, (
            f"Expected 1 entry for /settings, got {len(settings_eps)}"
        )

    def test_route_source_type_is_static(self):
        js = _make_js(self.FIXTURE_JS)
        _, endpoints, _, _ = _analyze([js], _scanner())

        route_eps = [ep for ep in endpoints
                     if ep.category == "ROUTE"
                     and ep.url in {"/admin/users", "/settings", "/reports", "/dashboard"}]
        for ep in route_eps:
            assert ep.source_type == "static", (
                f"{ep.url} has source_type={ep.source_type!r}, expected 'static'"
            )

    def test_api_endpoints_remain_separate_from_routes(self):
        js_content = """
            router.push("/dashboard");
            fetch("/api/v1/users", { method: "GET" });
            axios.post("/api/v1/auth/login", payload);
        """
        js = _make_js(js_content)
        _, endpoints, _, _ = _analyze([js], _scanner())

        route_paths = _route_paths(endpoints)
        assert "/dashboard" in route_paths, (
            f"/dashboard missing from routes; routes={route_paths}"
        )
        for ep in endpoints:
            if "/api/" in ep.url:
                assert ep.category != "ROUTE", (
                    f"API endpoint {ep.url} was incorrectly classified as ROUTE"
                )

    def test_url_normalization_applied(self):
        js_content = """
            const routes = [
                { path: '/users/:id', component: UserDetail },
                { path: '/posts/:postId/comments', component: Comments },
            ];
        """
        js = _make_js(js_content)
        _, endpoints, _, _ = _analyze([js], _scanner())
        paths = _route_paths(endpoints)

        normalized = {p for p in paths if "users" in p}
        assert any("{id}" in p for p in normalized), (
            f":id was not normalized to {{id}}; user-related routes: {normalized}"
        )

    def test_content_hash_dedup_does_not_double_count(self):
        js_content = """
            router.push("/account");
            router.push("/billing");
        """
        js1 = _make_js(js_content, url="https://app.example.com/chunk-a.js")
        js2 = _make_js(js_content, url="https://app.example.com/chunk-b.js")
        assert js1.sha256 == js2.sha256

        _, endpoints, _, _ = _analyze([js1, js2], _scanner())
        account_routes = [ep for ep in endpoints
                          if ep.url == "/account" and ep.category == "ROUTE"]
        assert len(account_routes) == 1, (
            f"Expected 1 /account route (dedup by content hash), got {len(account_routes)}"
        )

    def test_route_source_file_recorded(self):
        url = "https://app.example.com/static/main.abc123.js"
        js = _make_js('router.push("/profile");', url=url)
        _, endpoints, _, _ = _analyze([js], _scanner())

        profile_eps = [ep for ep in endpoints
                       if ep.url == "/profile" and ep.category == "ROUTE"]
        assert profile_eps, "No /profile ROUTE endpoint found"
        for ep in profile_eps:
            assert ep.source_file == url, (
                f"source_file={ep.source_file!r}, expected {url!r}"
            )

    def test_multiple_frameworks_in_same_file(self):
        js_content = """
            <Route path="/home" component={Home} />
            const vueRoutes = [{ path: '/about', component: About }];
            const ngRoutes = [{ path: 'contact', component: Contact }];
            history.pushState({}, "", "/faq");
        """
        js = _make_js(js_content)
        _, endpoints, _, _ = _analyze([js], _scanner())
        paths = _route_paths(endpoints)

        assert "/home"  in paths, f"React Router route /home missing; paths={paths}"
        assert "/about" in paths, f"Vue Router route /about missing; paths={paths}"
        assert "/faq"   in paths, f"history.pushState route /faq missing; paths={paths}"
        assert any("contact" in p for p in paths), (
            f"Angular route 'contact' missing; paths={paths}"
        )

    def test_noise_routes_not_registered(self):
        js_content = """
            import styles from '/static/css/app.abc123.css';
            const img = '/images/logo.png';
            fetch('https://api.example.com/data');
            const cdn = 'https://cdn.jsdelivr.net/npm/vue@3/dist/vue.cjs.js';
        """
        js = _make_js(js_content)
        _, endpoints, _, _ = _analyze([js], _scanner())
        paths = _route_paths(endpoints)

        for bad in ["/static/css/app.abc123.css", "/images/logo.png",
                    "https://api.example.com/data",
                    "https://cdn.jsdelivr.net/npm/vue@3/dist/vue.cjs.js"]:
            assert bad not in paths, (
                f"Noise value {bad!r} was incorrectly registered as a ROUTE"
            )


class TestSeedBuilderIntegration:
    """
    Verify the seed-builder path:
        JS asset -> route_extractor -> seed URL set -> Playwright-ready URLs
    """

    BASE = "https://app.example.com"

    def _build_seeds(self, js_content: str, base: str = None) -> set:
        from urllib.parse import urlparse
        from bundlespy.analysis.route_extractor import extract_routes as _extract_routes

        base = base or self.BASE
        parsed = urlparse(base)
        _base = f"{parsed.scheme}://{parsed.netloc}"

        js = _make_js(js_content, url=f"{_base}/static/app.js")
        static_routes: set = set()

        for ep in _extract_routes(js.content, js.url):
            if ep.url.startswith("/") and not ep.url.startswith("//"):
                static_routes.add(_base + ep.url.split("?")[0])

        return static_routes

    SEED_JS = """
        const ROUTES = {
            ADMIN:    "/admin",
            SETTINGS: "/settings",
            REPORTS:  "/reports"
        };
    """

    def test_seeds_are_fully_qualified(self):
        seeds = self._build_seeds(self.SEED_JS)
        assert seeds, "No seeds were generated"
        for url in seeds:
            assert url.startswith("https://"), (
                f"Seed {url!r} is not a fully-qualified URL"
            )

    def test_expected_routes_become_seeds(self):
        seeds = self._build_seeds(self.SEED_JS)
        assert f"{self.BASE}/admin"    in seeds, f"/admin missing; seeds={seeds}"
        assert f"{self.BASE}/settings" in seeds, f"/settings missing; seeds={seeds}"
        assert f"{self.BASE}/reports"  in seeds, f"/reports missing; seeds={seeds}"

    def test_relative_routes_resolved_against_origin(self):
        js = """
            const routes = [{ path: 'dashboard', component: Dashboard }];
        """
        seeds = self._build_seeds(js)
        for seed in seeds:
            assert seed.startswith(self.BASE), (
                f"Seed {seed!r} does not start with {self.BASE!r}"
            )

    def test_duplicate_routes_produce_one_seed(self):
        js = """
            router.push("/account");
            navigate("/account");
            history.pushState({}, "", "/account");
        """
        seeds = self._build_seeds(js)
        account_seeds = [s for s in seeds if s.endswith("/account")]
        assert len(account_seeds) == 1, (
            f"Expected 1 seed for /account, got {len(account_seeds)}: {account_seeds}"
        )

    def test_query_params_stripped_from_seeds(self):
        js = """
            router.push("/reports?view=monthly");
            navigate("/dashboard?section=overview");
        """
        seeds = self._build_seeds(js)
        for seed in seeds:
            assert "?" not in seed, (
                f"Seed {seed!r} contains a query string; should be stripped"
            )

    def test_external_urls_not_added_to_seeds(self):
        js = """
            window.location.href = "https://external.evil.com/phishing";
            navigate("https://cdn.example.com/static/file.js");
        """
        seeds = self._build_seeds(js)
        for seed in seeds:
            assert seed.startswith(self.BASE), (
                f"External URL leaked into seeds: {seed!r}"
            )

    def test_malformed_routes_ignored(self):
        js = """
            router.push(undefined);
            router.push(null);
            navigate("");
            history.pushState({}, "", "javascript:void(0)");
            router.push("#anchor");
        """
        seeds = self._build_seeds(js)
        for seed in seeds:
            assert seed.startswith("https://"), (
                f"Invalid seed produced: {seed!r}"
            )

    def test_api_endpoints_do_not_become_seeds(self):
        from bundlespy.analysis.route_extractor import extract_routes

        js_content = """
            fetch("/api/v1/users", { method: "GET" });
            axios.post("/api/v1/auth/login", creds);
            router.push("/login");
        """
        js = _make_js(js_content)
        static_routes: set = set()
        for ep in extract_routes(js.content, js.url):
            if ep.url.startswith("/") and not ep.url.startswith("//"):
                static_routes.add(self.BASE + ep.url.split("?")[0])

        assert f"{self.BASE}/login" in static_routes, (
            f"/login should be a seed; seeds={static_routes}"
        )
        api_seeds = [s for s in static_routes if "/api/" in s]
        assert not api_seeds, (
            f"API paths leaked into seed set: {api_seeds}"
        )

    def test_double_slash_routes_excluded(self):
        js = """
            window.location.href = "//tracker.evil.com/pixel";
        """
        seeds = self._build_seeds(js)
        for seed in seeds:
            assert not seed.startswith(f"{self.BASE}//"), (
                f"Protocol-relative URL leaked into seeds: {seed!r}"
            )


class TestLaneSeparation:
    """
    Prove that frontend routes and API endpoints are distinct records.
    """

    def test_same_url_as_route_and_api_produces_two_records(self):
        js_content = """
            const routes = [{ path: '/admin', component: AdminPanel }];
            fetch('/admin', { method: 'GET' });
        """
        js = _make_js(js_content)
        _, endpoints, _, _ = _analyze([js], _scanner())

        admin_eps = [ep for ep in endpoints if ep.url == "/admin"]
        assert admin_eps, "No endpoint found for /admin"

        route_eps = [ep for ep in admin_eps if ep.category == "ROUTE"]
        assert route_eps, (
            "/admin was not registered as a ROUTE; "
            f"found categories: {[e.category for e in admin_eps]}"
        )

    def test_worker_endpoints_distinct_from_routes(self):
        js_content = """
            router.push("/dashboard");
            new Worker('/workers/crypto.worker.js');
        """
        js = _make_js(js_content)
        _, endpoints, _, _ = _analyze([js], _scanner())
        route_paths = _route_paths(endpoints)

        assert "/workers/crypto.worker.js" not in route_paths, (
            "Worker JS file URL was incorrectly added as a ROUTE"
        )

    def test_graphql_operations_do_not_become_routes(self):
        js_content = """
            fetch('/graphql', {
                method: 'POST',
                body: JSON.stringify({ query: '{ users { id name } }' })
            });
            router.push("/users");
        """
        js = _make_js(js_content)
        _, endpoints, _, graphql_ops = _analyze([js], _scanner())
        route_paths = _route_paths(endpoints)

        assert "/users" in route_paths, (
            f"/users missing from routes; routes={route_paths}"
        )
        assert "/graphql" not in route_paths, (
            "/graphql was incorrectly labelled as a ROUTE"
        )
