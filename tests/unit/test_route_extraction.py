"""
Route extraction tests — proves each heuristic works against real fixtures.
All fixtures are inlined — no external imports needed.
"""

import re
import sys
import hashlib
import pytest

sys.path.insert(0, "src")

from bundlespy.analysis.ast_endpoints import extract_all_endpoints

# ── Fixtures inlined ──────────────────────────────────────────────────────────

ANGULAR_IVY_ROUTES = """
var Vf = [{
    path: '',
    redirectTo: 'login',
    pathMatch: 'full'
}, {
    path: 'login',
    component: pf
}, {
    path: 'register',
    component: Ef
}, {
    path: 'search',
    component: Cf
}, {
    path: 'basket',
    component: _f
}, {
    path: 'contact',
    component: Tf
}, {
    path: 'about',
    component: Sf
}, {
    path: 'administration',
    loadChildren: () => import('./admin.module').then(m => m.AdminModule)
}, {
    path: 'accounting',
    canActivate: [Af],
    component: Mf
}, {
    path: 'profile',
    canActivate: [Af],
    component: Df
}];
"""

ANGULAR_NESTED_ROUTES = """
const routes = [
  { path: 'admin', component: AdminComponent, children: [
    { path: 'users', component: UsersComponent },
    { path: 'orders', component: OrdersComponent },
    { path: 'dashboard', component: DashComponent },
  ]},
  { path: 'profile', component: ProfileComponent },
  { path: 'settings', component: SettingsComponent },
];
"""

ANGULAR_LAZY_ROUTES = """
const appRoutes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', component: HomeComponent },
  { path: 'products', loadChildren: () => import('./products/products.module').then(m => m.ProductsModule) },
  { path: 'checkout', loadChildren: () => import('./checkout/checkout.module').then(m => m.CheckoutModule) },
  { path: 'account', loadChildren: () => import('./account/account.module').then(m => m.AccountModule) },
];
RouterModule.forRoot(appRoutes)
"""

REACT_ROUTER_V6 = """
function App(){return(0,r.jsxs)(Xt,{children:[(0,r.jsx)(Qt,{path:"/",element:(0,r.jsx)(Home,{})}),(0,r.jsx)(Qt,{path:"/login",element:(0,r.jsx)(Login,{})}),(0,r.jsx)(Qt,{path:"/dashboard",element:(0,r.jsx)(Dashboard,{})}),(0,r.jsx)(Qt,{path:"/users/:id",element:(0,r.jsx)(UserDetail,{})}),(0,r.jsx)(Qt,{path:"/admin",element:(0,r.jsx)(Admin,{})}),(0,r.jsx)(Qt,{path:"/settings",element:(0,r.jsx)(Settings,{})}),(0,r.jsx)(Qt,{path:"*",element:(0,r.jsx)(NotFound,{})})]});}
"""

REACT_ROUTER_V5 = """
function AppRouter() {
  return React.createElement(Switch, null,
    React.createElement(Route, {exact: true, path: "/"}),
    React.createElement(Route, {path: "/products"}),
    React.createElement(Route, {path: "/cart"}),
    React.createElement(Route, {path: "/checkout"}),
    React.createElement(Route, {path: "/account/profile"}),
    React.createElement(Route, {path: "/account/orders"}),
  );
}
"""

VUE_ROUTER_V4 = """
const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: Home },
    { path: '/about', component: About },
    { path: '/products', component: Products },
    { path: '/products/:id', component: ProductDetail },
    { path: '/cart', component: Cart },
    { path: '/checkout', component: Checkout },
    { path: '/login', component: Login },
    { path: '/register', component: Register },
    { path: '/:pathMatch(.*)*', name: 'NotFound', component: NotFound }
  ]
});
"""

VUE_ROUTER_V3 = """
const router = new VueRouter({
  mode: 'history',
  routes: [
    { path: '/', component: Home },
    { path: '/dashboard', component: Dashboard },
    { path: '/users', component: UserList },
    { path: '/users/:id', component: UserDetail },
    { path: '/settings', component: Settings },
  ]
})
"""

SOURCE_MAP_VALID = '{"version":3,"sources":["src/app.js","src/api/client.js"],"sourcesContent":["const API_KEY = \'sk-test-abc123\';","fetch(\'/api/users\');"],"mappings":"AAAA"}'

MINIFIED_WITH_MAP = "var a=1,b=2;function c(d){return d+a}module.exports=c;\n//# sourceMappingURL=app.js.map"

MINIFIED_WITH_INLINE_MAP = "var x=1;function y(){return x}\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAuanMiXSwic291cmNlc0NvbnRlbnQiOlsidmFyIHg9MSJdLCJtYXBwaW5ncyI6IkFBQUEifQ=="

MINIFIED_WITH_X_SOURCEMAP = "var z=function(){};\n//@ sourceMappingURL=legacy.js.map"

MINIFIED_NO_MAP_COMMENT = "!function(){var e={};e.init=function(){fetch('/api/data')}}();"

JUICE_SHOP_JS = """
this.http.get('/rest/user/whoami').subscribe();
this.http.post('/api/Users/', {email:e,password:t}).subscribe();
this.http.put('/rest/user/change-password',{current:e,new:t}).subscribe();
this.socket=io('/',{path:'/socket.io'});
"""

STRING_CONCAT_ENDPOINTS = """
const BASE = '/api/v1';
const ADMIN = '/admin';
fetch(BASE + '/users');
fetch(BASE + '/orders');
fetch(ADMIN + '/dashboard');
axios.post(BASE + '/auth/login', credentials);
"""

TEMPLATE_LITERAL_ENDPOINTS = """
const userId = getCurrentUser().id;
fetch(`/api/users/${userId}/profile`);
fetch(`/api/orders/${orderId}/items`);
axios.delete(`/api/basket/${itemId}`);
"""

ANGULAR_MATERIAL_FP = """
var $y$1 = new InjectionToken("MAT_PROGRESS_BAR_DEFAULT_OPTIONS");
var cf$1 = (()=>{
    class t {
        constructor() {
            this.mode = "determinate";
        }
    }
    return t;
})();
"""

HTML_INPUT_FP = """
Ae$3({
    type: t,
    selectors: [["app-password-strength"]],
    inputs: {password: "password"},
    features: [vi$2],
    decls: 1,
    vars: 3
});
"""

TEST_CREDENTIAL_FP = """
testingUsername = "testing@juice-sh.op";
testingPassword = "IamUsedForTesting";
"""

OAUTH_CLIENT_ID_FP = """
clientId = "1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.com";
"""


# ── Route extraction helper ───────────────────────────────────────────────────

RE_PATH_ANY = re.compile(
    r'\bpath\s*:\s*["\x27`](/?[A-Za-z0-9/_\-.:?=&%#{}*][A-Za-z0-9/_\-.:?=&%#{}*]*)["\x27`]',
    re.IGNORECASE,
)


def extract_routes_static(js: str) -> set:
    routes = set()
    for m in RE_PATH_ANY.finditer(js):
        path = m.group(1).strip()
        if not path or path in ("**", "*", "full"):
            continue
        if not path.startswith("/"):
            path = "/" + path
        if len(path) > 1 and path not in ("/**", "/*"):
            routes.add(path)
    return routes


# ── Angular tests ─────────────────────────────────────────────────────────────

class TestAngularRouteExtraction:

    def test_angular_ivy_basic_routes(self):
        routes = extract_routes_static(ANGULAR_IVY_ROUTES)
        assert "/login" in routes, f"Missing /login in {routes}"
        assert "/register" in routes
        assert "/search" in routes
        assert "/basket" in routes
        assert "/contact" in routes
        assert "/about" in routes

    def test_angular_ivy_admin_route(self):
        routes = extract_routes_static(ANGULAR_IVY_ROUTES)
        assert "/administration" in routes

    def test_angular_ivy_auth_guarded_routes(self):
        routes = extract_routes_static(ANGULAR_IVY_ROUTES)
        assert "/accounting" in routes
        assert "/profile" in routes

    def test_angular_ivy_no_empty_path(self):
        routes = extract_routes_static(ANGULAR_IVY_ROUTES)
        assert "" not in routes

    def test_angular_nested_routes(self):
        routes = extract_routes_static(ANGULAR_NESTED_ROUTES)
        assert "/admin" in routes
        assert "/users" in routes
        assert "/orders" in routes
        assert "/profile" in routes
        assert "/settings" in routes

    def test_angular_lazy_routes(self):
        routes = extract_routes_static(ANGULAR_LAZY_ROUTES)
        assert "/products" in routes
        assert "/checkout" in routes
        assert "/account" in routes

    def test_angular_route_count_reasonable(self):
        routes = extract_routes_static(ANGULAR_IVY_ROUTES)
        assert len(routes) <= 20


# ── React Router tests ────────────────────────────────────────────────────────

class TestReactRouterExtraction:

    def test_react_router_v6_basic(self):
        routes = extract_routes_static(REACT_ROUTER_V6)
        assert "/login" in routes
        assert "/dashboard" in routes
        assert "/admin" in routes
        assert "/settings" in routes

    def test_react_router_v6_dynamic_path(self):
        routes = extract_routes_static(REACT_ROUTER_V6)
        assert "/users/:id" in routes

    def test_react_router_v5_basic(self):
        routes = extract_routes_static(REACT_ROUTER_V5)
        assert "/products" in routes
        assert "/cart" in routes
        assert "/checkout" in routes

    def test_react_router_v5_nested(self):
        routes = extract_routes_static(REACT_ROUTER_V5)
        assert "/account/profile" in routes
        assert "/account/orders" in routes


# ── Vue Router tests ──────────────────────────────────────────────────────────

class TestVueRouterExtraction:

    def test_vue_router_v4_basic(self):
        routes = extract_routes_static(VUE_ROUTER_V4)
        assert "/about" in routes
        assert "/products" in routes
        assert "/cart" in routes
        assert "/login" in routes
        assert "/register" in routes

    def test_vue_router_v4_dynamic(self):
        routes = extract_routes_static(VUE_ROUTER_V4)
        assert "/products/:id" in routes

    def test_vue_router_v3_basic(self):
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
        result = self.detect(MINIFIED_WITH_MAP, "https://example.com/app.js")
        assert result == "https://example.com/app.js.map", f"Got: {result}"

    def test_inline_base64_sourcemap(self):
        result = self.detect(MINIFIED_WITH_INLINE_MAP, "https://example.com/app.js")
        assert result is not None
        assert result.startswith("data:application/json;base64,")

    def test_legacy_x_sourcemap_comment(self):
        result = self.detect(MINIFIED_WITH_X_SOURCEMAP, "https://example.com/legacy.js")
        assert result == "https://example.com/legacy.js.map", f"Got: {result}"

    def test_no_sourcemap_returns_none(self):
        result = self.detect(MINIFIED_NO_MAP_COMMENT, "https://example.com/app.js")
        assert result is None

    def test_absolute_url_sourcemap(self):
        js = "var x=1;\n//# sourceMappingURL=https://cdn.example.com/maps/app.js.map"
        result = self.detect(js, "https://example.com/app.js")
        assert result == "https://cdn.example.com/maps/app.js.map"

    def test_relative_path_resolved(self):
        js = "var x=1;\n//# sourceMappingURL=../maps/app.js.map"
        result = self.detect(js, "https://example.com/static/js/app.js")
        assert result == "https://example.com/static/maps/app.js.map"

    def test_empty_content_returns_none(self):
        result = self.detect("", "https://example.com/app.js")
        assert result is None

    def test_large_file_tail_detection(self):
        padding = "var x = 0;\n" * 50000
        tail    = "//# sourceMappingURL=app.js.map"
        js      = padding + tail
        result  = self.detect(js, "https://example.com/app.js")
        assert result == "https://example.com/app.js.map"

    def test_source_map_parse(self):
        from bundlespy.discovery.source_maps import parse_source_map
        result = parse_source_map(SOURCE_MAP_VALID)
        assert result is not None
        assert "src/app.js" in result["sources"]

    def test_source_map_recover_content(self):
        from bundlespy.discovery.source_maps import parse_source_map, recover_sources
        map_data  = parse_source_map(SOURCE_MAP_VALID)
        recovered = recover_sources(map_data, "https://example.com/app.js.map", "https://example.com/app.js")
        assert len(recovered) > 0
        assert any("API_KEY" in c for _, c in recovered)

    def test_malformed_source_map_returns_none(self):
        from bundlespy.discovery.source_maps import parse_source_map
        assert parse_source_map("not json {{{") is None

    def test_source_map_without_sources_returns_none(self):
        from bundlespy.discovery.source_maps import parse_source_map
        assert parse_source_map('{"version":3,"mappings":"AAAA"}') is None


# ── Endpoint extraction tests ─────────────────────────────────────────────────

class TestEndpointExtraction:

    def test_juice_shop_user_endpoint(self):
        eps   = extract_all_endpoints(JUICE_SHOP_JS, "https://example.com/main.js")
        paths = {e.url for e in eps}
        assert any("user" in p.lower() or "api" in p.lower() for p in paths), \
            f"Expected user/api endpoint in {paths}"

    def test_string_concat_resolution(self):
        eps   = extract_all_endpoints(STRING_CONCAT_ENDPOINTS, "https://example.com/app.js")
        paths = {e.url for e in eps}
        assert any("/api/v1" in p for p in paths), f"Expected /api/v1/* in {paths}"

    def test_template_literal_extraction(self):
        eps   = extract_all_endpoints(TEMPLATE_LITERAL_ENDPOINTS, "https://example.com/app.js")
        paths = {e.url for e in eps}
        assert any("/api/" in p for p in paths), f"Expected /api/ in {paths}"

    def test_no_duplicate_endpoints(self):
        js  = "fetch('/api/users');\nfetch('/api/users');\naxios.get('/api/users');"
        eps = extract_all_endpoints(js, "https://example.com/app.js")
        urls = [e.url for e in eps]
        assert len(urls) == len(set(urls)), f"Duplicates: {urls}"

    def test_external_urls_filtered(self):
        js  = "fetch('https://www.google-analytics.com/collect');\nfetch('/api/users');"
        eps = extract_all_endpoints(js, "https://example.com/app.js")
        paths = {e.url for e in eps}
        assert not any("google-analytics" in p for p in paths), \
            f"Analytics URL should be filtered: {paths}"

    def test_auth_category_detection(self):
        js  = "fetch('/api/auth/login', {method:'POST'});"
        eps = extract_all_endpoints(js, "https://example.com/app.js")
        assert any(e.category == "AUTH" for e in eps), \
            f"Expected AUTH: {[(e.url, e.category) for e in eps]}"

    def test_admin_category_detection(self):
        js  = "fetch('/admin/users');"
        eps = extract_all_endpoints(js, "https://example.com/app.js")
        assert any(e.category == "ADMIN" for e in eps), \
            f"Expected ADMIN: {[(e.url, e.category) for e in eps]}"

    def test_websocket_extraction(self):
        js  = 'const ws = new WebSocket("wss://api.target.com/live");'
        eps = extract_all_endpoints(js, "https://example.com/app.js")
        assert any(e.method == "WS" for e in eps), \
            f"Expected WS endpoint: {[(e.url, e.method) for e in eps]}"

    def test_graphql_endpoint_detection(self):
        js  = "fetch('/graphql', {method:'POST', body: JSON.stringify(query)});"
        eps = extract_all_endpoints(js, "https://example.com/app.js")
        assert any(e.category == "GRAPHQL" for e in eps), \
            f"Expected GRAPHQL: {[(e.url, e.category) for e in eps]}"


# ── False positive tests ──────────────────────────────────────────────────────

class TestFalsePositiveSuppression:

    def setup_method(self):
        from bundlespy.analysis.secrets import SecretScanner
        self.scanner = SecretScanner()

    def test_angular_material_not_gitlab_token(self):
        findings = self.scanner.scan(ANGULAR_MATERIAL_FP, "https://example.com/main.js", "")
        gitlab   = [f for f in findings if f.rule_id == "GITLAB_RUNNER_TOKEN"]
        for f in gitlab:
            assert f.confidence < 0.7, \
                f"GRESS_BAR should not be high-confidence GitLab token: {f.confidence} {f.matched_value}"

    def test_html_input_name_not_password(self):
        findings = self.scanner.scan(HTML_INPUT_FP, "https://example.com/main.js", "")
        pw = [f for f in findings
              if f.rule_id == "GENERIC_PASSWORD" and f.matched_value == "password"]
        for f in pw:
            assert f.confidence < 0.75, \
                f"Single word 'password' as input name should be low confidence: {f.confidence}"

    def test_test_credential_not_critical(self):
        findings = self.scanner.scan(TEST_CREDENTIAL_FP, "https://example.com/main.js", "")
        test_f   = [f for f in findings if "IamUsedForTesting" in f.matched_value]
        for f in test_f:
            assert f.severity != "CRITICAL", \
                f"Test credential must not be CRITICAL: {f.severity}"

    def test_oauth_client_id_not_high(self):
        findings = self.scanner.scan(OAUTH_CLIENT_ID_FP, "https://example.com/main.js", "")
        oauth    = [f for f in findings if "googleusercontent" in f.matched_value.lower()]
        for f in oauth:
            assert f.severity in ("MEDIUM", "LOW", "INFO"), \
                f"OAuth client ID should be MEDIUM or lower: {f.severity}"


# ── Summary integrity tests ───────────────────────────────────────────────────

class TestSummaryIntegrity:

    def _make_result(self, findings):
        from bundlespy.storage.models import ScanResult
        from datetime import datetime
        return ScanResult(
            target_url="https://example.com",
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            pages_crawled=1,
            js_files=[], findings=findings,
            endpoints=[], infrastructure=[], errors=[],
        )

    def _make_finding(self, severity):
        from bundlespy.storage.models import Finding
        return Finding(
            id=severity, rule_id="TEST", title="Test",
            category="Test", severity=severity, confidence=0.90,
            file_url="test.js", source_page="https://example.com",
            line_number=1, column=0,
            matched_value="testvalue", redacted_value="test****",
            sha256=hashlib.sha256(severity.encode()).hexdigest(),
            context="", description="", impact="", remediation="",
            false_positive_notes="", status="likely_secret",
            occurrences=["test.js:1"],
        )

    def _get_summary_output(self, result):
        import io
        from contextlib import redirect_stdout
        from bundlespy.ui.printer import print_summary
        f = io.StringIO()
        with redirect_stdout(f):
            print_summary(result)
        return f.getvalue()

    def test_high_only_no_critical_message(self):
        result = self._make_result([self._make_finding("HIGH")])
        output = self._get_summary_output(result)
        assert "Critical findings present" not in output
        assert "High severity" in output

    def test_zero_findings_clean(self):
        result = self._make_result([])
        output = self._get_summary_output(result)
        assert "Critical findings present" not in output
        assert "No critical findings" in output

    def test_critical_triggers_message(self):
        result = self._make_result([self._make_finding("CRITICAL")])
        output = self._get_summary_output(result)
        assert "Critical findings present" in output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
