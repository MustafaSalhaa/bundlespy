"""
Tests for the frontend route extractor.

Covers: React Router, Vue Router, Angular Router, Next.js, SvelteKit,
Nuxt, Tanstack Router, Backbone, route constant objects, and generic
navigation APIs.
"""

import pytest
from bundlespy.analysis.route_extractor import extract_routes, _is_valid_route, _clean_route


# ── Helper ────────────────────────────────────────────────────────────────────

def _paths(js: str) -> set:
    """Return just the set of paths extracted from js content."""
    return {ep.path for ep in extract_routes(js, "https://example.com/app.js")}


def _ep(js: str) -> list:
    """Return Endpoint objects."""
    return extract_routes(js, "https://example.com/app.js")


# ── _is_valid_route ───────────────────────────────────────────────────────────

class TestIsValidRoute:
    def test_valid_absolute(self):
        assert _is_valid_route("/admin/users")

    def test_valid_relative_word(self):
        assert _is_valid_route("dashboard")

    def test_invalid_empty(self):
        assert not _is_valid_route("")

    def test_invalid_root_only(self):
        assert not _is_valid_route("/")

    def test_invalid_js_file(self):
        assert not _is_valid_route("/app.js")

    def test_invalid_css_file(self):
        assert not _is_valid_route("/styles.css")

    def test_invalid_image(self):
        assert not _is_valid_route("/logo.png")

    def test_invalid_absolute_http(self):
        assert not _is_valid_route("https://example.com/page")

    def test_invalid_javascript_protocol(self):
        assert not _is_valid_route("javascript:void(0)")

    def test_invalid_hash(self):
        assert not _is_valid_route("#section")

    def test_invalid_template_only(self):
        assert not _is_valid_route("${variable}")

    def test_valid_with_param(self):
        assert _is_valid_route("/users/:id")

    def test_valid_nextjs_param(self):
        assert _is_valid_route("/users/[id]")

    def test_invalid_wildcard_only(self):
        assert not _is_valid_route("/*")

    def test_invalid_single_char(self):
        assert not _is_valid_route("/a")


# ── _clean_route ──────────────────────────────────────────────────────────────

class TestCleanRoute:
    def test_express_param(self):
        assert _clean_route("/users/:id") == "/users/{id}"

    def test_express_multi_param(self):
        assert _clean_route("/org/:orgId/user/:userId") == "/org/{orgId}/user/{userId}"

    def test_nextjs_param(self):
        assert _clean_route("/users/[id]") == "/users/{id}"

    def test_nextjs_catchall(self):
        result = _clean_route("/blog/[...slug]")
        assert "{" in result

    def test_trailing_slash_stripped(self):
        assert _clean_route("/admin/") == "/admin"

    def test_root_preserved(self):
        assert _clean_route("/") == "/"

    def test_no_change_simple(self):
        assert _clean_route("/admin/users") == "/admin/users"


# ── React Router ──────────────────────────────────────────────────────────────

class TestReactRouter:
    def test_jsx_route_double_quote(self):
        js = '<Route path="/admin/users" component={AdminUsers} />'
        assert "/admin/users" in _paths(js)

    def test_jsx_route_single_quote(self):
        js = "<Route path='/login' component={Login} />"
        assert "/login" in _paths(js)

    def test_jsx_route_nested(self):
        js = """
        <Routes>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/settings/profile" element={<Profile />} />
        </Routes>
        """
        paths = _paths(js)
        assert "/dashboard" in paths
        assert "/settings/profile" in paths

    def test_create_browser_router(self):
        js = """
        const router = createBrowserRouter([
          { path: "/", element: <Home /> },
          { path: "/about", element: <About /> },
          { path: "/admin/users", element: <AdminUsers /> },
        ]);
        """
        paths = _paths(js)
        assert "/about" in paths
        assert "/admin/users" in paths

    def test_link_to(self):
        js = '<Link to="/dashboard">Go to dashboard</Link>'
        assert "/dashboard" in _paths(js)

    def test_link_href(self):
        js = '<Link href="/about">About</Link>'
        assert "/about" in _paths(js)

    def test_redirect_to(self):
        js = '<Redirect to="/login" />'
        assert "/login" in _paths(js)

    def test_navigate_call(self):
        js = 'navigate("/checkout/complete");'
        assert "/checkout/complete" in _paths(js)

    def test_push_call(self):
        js = 'history.push("/profile");'
        assert "/profile" in _paths(js)

    def test_history_replace(self):
        js = 'history.replace("/logout");'
        assert "/logout" in _paths(js)

    def test_express_params_normalized(self):
        js = '<Route path="/users/:id/edit" />'
        paths = _paths(js)
        assert "/users/{id}/edit" in paths

    def test_wildcard_route(self):
        js = '<Route path="/admin/*" element={<Admin />} />'
        assert "/admin/*" in _paths(js)

    def test_route_object_with_children(self):
        js = """
        { path: '/app', children: [
            { path: 'dashboard', element: <Dashboard /> },
            { path: 'settings', element: <Settings /> },
        ]}
        """
        paths = _paths(js)
        assert "/app" in paths or "app" in paths

    def test_confidence_high_for_jsx_route(self):
        js = '<Route path="/admin" />'
        eps = _ep(js)
        assert any(e.path == "/admin" and e.confidence >= 0.85 for e in eps)


# ── Vue Router ────────────────────────────────────────────────────────────────

class TestVueRouter:
    def test_routes_array_path(self):
        js = """
        const routes = [
          { path: '/home', component: Home },
          { path: '/profile', component: Profile },
          { path: '/admin/dashboard', component: AdminDashboard },
        ]
        """
        paths = _paths(js)
        assert "/home" in paths
        assert "/profile" in paths
        assert "/admin/dashboard" in paths

    def test_router_push(self):
        js = "router.push('/settings');"
        assert "/settings" in _paths(js)

    def test_router_push_object_form(self):
        js = "router.push({ path: '/admin/users' });"
        assert "/admin/users" in _paths(js)

    def test_router_replace(self):
        js = "router.replace('/login');"
        assert "/login" in _paths(js)

    def test_add_route(self):
        js = "router.addRoute({ path: '/secret-admin', component: SecretAdmin })"
        assert "/secret-admin" in _paths(js)

    def test_router_link(self):
        js = '<router-link to="/about">About</router-link>'
        assert "/about" in _paths(js)

    def test_nested_routes(self):
        js = """
        routes: [
          {
            path: '/user',
            component: User,
            children: [
              { path: 'profile', component: UserProfile },
              { path: 'posts', component: UserPosts },
            ]
          }
        ]
        """
        paths = _paths(js)
        assert "/user" in paths

    def test_params_in_vue_route(self):
        js = "{ path: '/users/:id', component: UserDetail }"
        paths = _paths(js)
        assert "/users/{id}" in paths


# ── Angular Router ────────────────────────────────────────────────────────────

class TestAngularRouter:
    def test_router_module_routes(self):
        js = """
        const routes: Routes = [
          { path: 'home', component: HomeComponent },
          { path: 'admin', component: AdminComponent },
          { path: 'admin/users', component: UsersComponent },
        ];
        """
        paths = _paths(js)
        assert "home" in paths or "/home" in paths
        assert "admin" in paths or "/admin" in paths

    def test_routerlink_attr(self):
        js = 'routerLink="/dashboard/overview"'
        assert "/dashboard/overview" in _paths(js)

    def test_navigate_array(self):
        js = "this.router.navigate(['/admin/settings']);"
        assert "/admin/settings" in _paths(js)

    def test_navigate_by_url(self):
        js = "this.router.navigateByUrl('/profile/edit');"
        assert "/profile/edit" in _paths(js)

    def test_redirect_to(self):
        js = "{ path: '', redirectTo: '/home', pathMatch: 'full' }"
        assert "/home" in _paths(js)

    def test_lazy_loaded_route(self):
        js = """
        { path: 'admin', loadChildren: () => import('./admin/admin.module')
            .then(m => m.AdminModule) }
        """
        paths = _paths(js)
        assert "admin" in paths or "/admin" in paths


# ── Next.js ───────────────────────────────────────────────────────────────────

class TestNextJs:
    def test_router_push(self):
        js = "router.push('/checkout/payment');"
        assert "/checkout/payment" in _paths(js)

    def test_link_href(self):
        js = '<Link href="/products/list">Products</Link>'
        assert "/products/list" in _paths(js)

    def test_getserversideprops_redirect(self):
        js = """
        return {
          redirect: {
            destination: '/login',
            permanent: false,
          },
        }
        """
        assert "/login" in _paths(js)

    def test_app_router_redirect(self):
        js = "redirect('/not-authorized');"
        assert "/not-authorized" in _paths(js)

    def test_permanent_redirect(self):
        js = "permanentRedirect('/new-location');"
        assert "/new-location" in _paths(js)

    def test_nextjs_rewrite_source(self):
        js = "{ source: '/legacy-page', destination: '/new-page' }"
        paths = _paths(js)
        assert "/legacy-page" in paths
        assert "/new-page" in paths


# ── SvelteKit ─────────────────────────────────────────────────────────────────

class TestSvelteKit:
    def test_goto(self):
        js = "goto('/dashboard');"
        assert "/dashboard" in _paths(js)

    def test_goto_with_options(self):
        js = "goto('/login', { replaceState: true });"
        assert "/login" in _paths(js)


# ── Nuxt ──────────────────────────────────────────────────────────────────────

class TestNuxt:
    def test_navigate_to(self):
        js = "navigateTo('/admin/panel');"
        assert "/admin/panel" in _paths(js)

    def test_use_router_push(self):
        js = "useRouter().push('/settings/account');"
        assert "/settings/account" in _paths(js)


# ── Route constant objects ────────────────────────────────────────────────────

class TestRouteConstants:
    def test_routes_object(self):
        js = """
        const ROUTES = {
          HOME: '/',
          LOGIN: '/login',
          DASHBOARD: '/dashboard',
          ADMIN_USERS: '/admin/users',
          PROFILE: '/profile',
        };
        """
        paths = _paths(js)
        assert "/login" in paths
        assert "/dashboard" in paths
        assert "/admin/users" in paths
        assert "/profile" in paths

    def test_frozen_routes_object(self):
        js = """
        const PATHS = Object.freeze({
          AUTH: '/auth/login',
          RESET: '/auth/reset-password',
          HOME: '/home',
        });
        """
        paths = _paths(js)
        assert "/auth/login" in paths
        assert "/auth/reset-password" in paths

    def test_routes_dot_assignment(self):
        js = "ROUTES.ADMIN = '/admin/dashboard';"
        assert "/admin/dashboard" in _paths(js)

    def test_paths_constant(self):
        js = "PATHS.USER_PROFILE = '/user/profile';"
        assert "/user/profile" in _paths(js)

    def test_nav_constant(self):
        js = "NAV.SETTINGS = '/settings/security';"
        assert "/settings/security" in _paths(js)


# ── Generic navigation ────────────────────────────────────────────────────────

class TestGenericNavigation:
    def test_history_push_state(self):
        js = "history.pushState({}, '', '/new-page');"
        assert "/new-page" in _paths(js)

    def test_history_replace_state(self):
        js = "history.replaceState({}, '', '/updated-page');"
        assert "/updated-page" in _paths(js)

    def test_window_location_href(self):
        js = "window.location.href = '/logout';"
        assert "/logout" in _paths(js)

    def test_location_assign(self):
        js = "location.assign('/new-location');"
        assert "/new-location" in _paths(js)


# ── Backbone Router ───────────────────────────────────────────────────────────

class TestBackboneRouter:
    def test_backbone_routes(self):
        js = """
        var Router = Backbone.Router.extend({
          routes: {
            "": "index",
            "help": "help",
            "search/:query": "search",
            "page/:num": "page",
          },
        });
        """
        paths = _paths(js)
        # Backbone routes get / prepended
        assert "/help" in paths
        assert "/search/{query}" in paths or "/search/:query" in paths

    def test_backbone_complex_routes(self):
        js = """
        routes: {
          "docs/:section": "showDoc",
          "admin/users": "adminUsers",
        }
        """
        paths = _paths(js)
        assert "/admin/users" in paths


# ── Category and source_type ──────────────────────────────────────────────────

class TestEndpointMetadata:
    def test_category_is_route(self):
        js = '<Route path="/admin" />'
        eps = _ep(js)
        assert all(e.category == "ROUTE" for e in eps)

    def test_source_file_set(self):
        js = '<Route path="/test" />'
        eps = _ep(js)
        assert all(e.source_file == "https://example.com/app.js" for e in eps)

    def test_line_number_set(self):
        js = '\n\n<Route path="/test" />'
        eps = _ep(js)
        assert any(e.line_number >= 3 for e in eps)

    def test_evidence_set(self):
        js = '<Route path="/admin" component={Admin} />'
        eps = _ep(js)
        assert any(e.evidence and "Route" in e.evidence for e in eps)


# ── Deduplication ─────────────────────────────────────────────────────────────

class TestDeduplication:
    def test_same_path_deduplicated(self):
        js = """
        <Route path="/admin" />
        router.push('/admin');
        navigate('/admin');
        """
        paths = list(_paths(js))
        # /admin should appear exactly once
        assert paths.count("/admin") == 1

    def test_different_paths_both_kept(self):
        js = """
        <Route path="/admin" />
        <Route path="/users" />
        """
        paths = _paths(js)
        assert "/admin" in paths
        assert "/users" in paths

    def test_case_insensitive_dedup(self):
        js = """
        <Route path="/Admin" />
        <Route path="/admin" />
        """
        paths = _paths(js)
        # Should only have one variant
        admin_paths = [p for p in paths if p.lower() == "/admin"]
        assert len(admin_paths) == 1


# ── Noise filtering ───────────────────────────────────────────────────────────

class TestNoiseFiltering:
    def test_no_js_files(self):
        js = 'import("/static/js/chunk.abc123.js")'
        paths = _paths(js)
        assert not any(p.endswith(".js") for p in paths)

    def test_no_image_files(self):
        js = '<Link href="/images/logo.png" />'
        paths = _paths(js)
        assert not any(p.endswith(".png") for p in paths)

    def test_no_external_urls(self):
        js = '<Link href="https://google.com/maps" />'
        paths = _paths(js)
        assert not any("google" in p for p in paths)

    def test_no_mailto(self):
        js = '<a href="mailto:admin@example.com" />'
        paths = _paths(js)
        assert not any("mailto" in p for p in paths)

    def test_no_cdn_paths(self):
        js = '<script src="//cdn.example.com/lib.js"></script>'
        paths = _paths(js)
        assert not any("cdn." in p for p in paths)

    def test_no_pure_anchor(self):
        js = '<a href="#section-2">Jump</a>'
        paths = _paths(js)
        assert not any(p.startswith("#") for p in paths)


# ── Resilience ────────────────────────────────────────────────────────────────

class TestResilience:
    def test_empty_content(self):
        assert extract_routes("", "https://example.com/app.js") == []

    def test_no_routes_in_content(self):
        js = "var x = 1; console.log(x);"
        assert _paths(js) == set()

    def test_malformed_jsx(self):
        js = "<Route path= />"
        # Should not raise, just return empty or skip
        result = extract_routes(js, "https://example.com/app.js")
        assert isinstance(result, list)

    def test_minified_bundle(self):
        js = 'var r=createBrowserRouter([{path:"/home",element:n},{path:"/admin",element:a}])'
        paths = _paths(js)
        assert "/home" in paths
        assert "/admin" in paths

    def test_large_content(self):
        # Should not blow up on large content
        big = ('<Route path="/page-%d" />\n' % i for i in range(500))
        js = "".join(big)
        result = extract_routes(js, "https://example.com/app.js")
        assert len(result) > 0

    def test_unicode_in_content(self):
        js = '<Route path="/about-über" />'
        # Should not raise
        result = extract_routes(js, "https://example.com/app.js")
        assert isinstance(result, list)


# ── Real-world patterns ───────────────────────────────────────────────────────

class TestRealWorldPatterns:
    def test_react_router_v6_full_app(self):
        js = """
        import { createBrowserRouter, RouterProvider } from 'react-router-dom';

        const router = createBrowserRouter([
          { path: '/', element: <Home /> },
          { path: '/login', element: <Login /> },
          { path: '/register', element: <Register /> },
          {
            path: '/app',
            element: <AuthLayout />,
            children: [
              { path: 'dashboard', element: <Dashboard /> },
                          { path: 'profile', element: <Profile /> },
              { path: 'settings', element: <Settings /> },
              { path: 'admin', element: <Admin /> },
              { path: 'admin/users', element: <AdminUsers /> },
              { path: 'admin/users/:id', element: <UserDetail /> },
            ],
          },
        ]);
        """
        paths = _paths(js)
        assert "/login" in paths
        assert "/register" in paths
        assert "/app" in paths
        assert "/app/dashboard" in paths or "dashboard" in paths
        assert "/admin/users" in paths or "admin/users" in paths

    def test_vue_router_v4_full_config(self):
        js = """
        const router = createRouter({
          history: createWebHistory(),
          routes: [
            { path: '/', component: Home },
            { path: '/login', component: Login },
            { path: '/register', component: Register },
            {
              path: '/admin',
              component: AdminLayout,
              children: [
                { path: '', component: AdminHome },
                { path: 'users', component: UserList },
                { path: 'users/:id', component: UserDetail },
                { path: 'settings', component: AdminSettings },
              ],
            },
          ],
        });
        """
        paths = _paths(js)
        assert "/login" in paths
        assert "/register" in paths
        assert "/admin" in paths
        assert "users" in paths or "/admin/users" in paths

    def test_angular_lazy_routing(self):
        js = """
        const routes: Routes = [
          { path: '', redirectTo: '/home', pathMatch: 'full' },
          { path: 'home', component: HomeComponent },
          { path: 'login', component: LoginComponent },
          { path: 'register', component: RegisterComponent },
          { path: 'dashboard', component: DashboardComponent, canActivate: [AuthGuard] },
          {
            path: 'admin',
            loadChildren: () => import('./admin/admin.module').then(m => m.AdminModule),
            canActivate: [AdminGuard],
          },
          { path: '**', redirectTo: '/home' },
        ];
        """
        paths = _paths(js)
        assert "home" in paths or "/home" in paths
        assert "login" in paths or "/login" in paths
        assert "dashboard" in paths or "/dashboard" in paths
        assert "/home" in paths  # from redirectTo
