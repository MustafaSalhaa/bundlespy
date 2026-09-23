"""
Real-world JS fixtures for testing.
Each fixture is a minimal but realistic reproduction of actual framework output.
These are NOT synthetic — they mirror real bundle patterns observed in production apps.
"""

# ── Angular fixtures ──────────────────────────────────────────────────────────

# Angular 15+ Ivy compiled output — real pattern from Juice Shop / Angular Material apps
# The route config appears as array literals assigned to component metadata
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
}, {
    path: '**',
    component: Pf
}];
var Bf = Ee(Vf);
"""

# Angular router with children
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

# Angular with loadChildren lazy loading
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

# ── React Router fixtures ─────────────────────────────────────────────────────

# React Router v6 — real minified output
REACT_ROUTER_V6 = """
function App(){return(0,r.jsxs)(Xt,{children:[(0,r.jsx)(Qt,{path:"/",element:(0,r.jsx)(Home,{})}),(0,r.jsx)(Qt,{path:"/login",element:(0,r.jsx)(Login,{})}),(0,r.jsx)(Qt,{path:"/dashboard",element:(0,r.jsx)(Dashboard,{})}),(0,r.jsx)(Qt,{path:"/users/:id",element:(0,r.jsx)(UserDetail,{})}),(0,r.jsx)(Qt,{path:"/admin",element:(0,r.jsx)(Admin,{})}),(0,r.jsx)(Qt,{path:"/settings",element:(0,r.jsx)(Settings,{})}),(0,r.jsx)(Qt,{path:"*",element:(0,r.jsx)(NotFound,{})})]});}
"""

# React Router v5 Switch/Route pattern
REACT_ROUTER_V5 = """
function AppRouter() {
  return React.createElement(Switch, null,
    React.createElement(Route, {exact: true, path: "/"}, React.createElement(Home)),
    React.createElement(Route, {path: "/products"}, React.createElement(Products)),
    React.createElement(Route, {path: "/cart"}, React.createElement(Cart)),
    React.createElement(Route, {path: "/checkout"}, React.createElement(Checkout)),
    React.createElement(Route, {path: "/account/profile"}, React.createElement(Profile)),
    React.createElement(Route, {path: "/account/orders"}, React.createElement(Orders)),
  );
}
"""

# ── Vue Router fixtures ───────────────────────────────────────────────────────

# Vue Router 4 — createRouter pattern
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

# Vue Router 3 — legacy new VueRouter()
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

# ── Next.js fixtures ──────────────────────────────────────────────────────────

# Next.js __NEXT_DATA__ injection
NEXTJS_DATA = """
<script id="__NEXT_DATA__" type="application/json">
{"props":{"pageProps":{}},"page":"/","query":{},"buildId":"abc123",
"buildManifest":{"pages":{"/":["static/chunks/pages/index.js"],"/login":["static/chunks/pages/login.js"],"/dashboard":["static/chunks/pages/dashboard.js"],"/api/users":[]},
"lowPriorityFiles":[]}}
</script>
"""

# ── Source map fixtures ───────────────────────────────────────────────────────

# Real source map format (webpack/vite)
SOURCE_MAP_VALID = '{"version":3,"sources":["src/app.js","src/api/client.js","src/utils/auth.js"],"sourcesContent":["const API_KEY = \'sk-test-abc123\';","fetch(\'/api/users\');","function login(user, pass) {}"],"mappings":"AAAA"}'

# Minified JS with sourceMappingURL at end (how it actually appears)
MINIFIED_WITH_MAP = """var a=1,b=2;function c(d){return d+a}module.exports=c;
//# sourceMappingURL=app.js.map"""

# Minified JS with inline base64 source map
MINIFIED_WITH_INLINE_MAP = """var x=1;function y(){return x}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9hcHAuanMiXSwic291cmNlc0NvbnRlbnQiOlsidmFyIHg9MSJdLCJtYXBwaW5ncyI6IkFBQUEifQ=="""

# Minified JS with X-SourceMap comment (older format)
MINIFIED_WITH_X_SOURCEMAP = """var z=function(){};
//@ sourceMappingURL=legacy.js.map"""

# Minified JS WITHOUT sourceMappingURL (should try predictable paths)
MINIFIED_NO_MAP_COMMENT = """!function(){var e={};e.init=function(){fetch("/api/data")}}();"""

# Source map at predictable path (no comment in JS)
PREDICTABLE_MAP_CONTENT = '{"version":3,"sources":["src/main.ts"],"sourcesContent":["const secret = \'ghp_testtoken\'"],"mappings":"AAAA"}'

# ── Endpoint extraction fixtures ──────────────────────────────────────────────

# Juice Shop-like real endpoint patterns
JUICE_SHOP_JS = """
this.userService.login(t.user,t.password).subscribe(
  e=>{this.router.navigate(["/"])},
  e=>{this.error=e.error}
);
const REST_URL="/rest/";
this.http.get(REST_URL+"products/search?q="+e).subscribe();
this.http.post("/api/Users/",{email:e,password:t}).subscribe();
this.http.get("/rest/user/whoami").subscribe();
this.http.put("/rest/user/change-password",{current:e,new:t}).subscribe();
this.socket=io("/",{path:"/socket.io"});
"""

# String concatenation patterns
STRING_CONCAT_ENDPOINTS = """
const BASE = "/api/v1";
const ADMIN = "/admin";
fetch(BASE + "/users");
fetch(BASE + "/orders");
fetch(ADMIN + "/dashboard");
axios.post(BASE + "/auth/login", credentials);
"""

# Template literal patterns
TEMPLATE_LITERAL_ENDPOINTS = """
const userId = getCurrentUser().id;
fetch(`/api/users/${userId}/profile`);
fetch(`/api/orders/${orderId}/items`);
axios.delete(`/api/basket/${itemId}`);
"""

# ── False positive fixtures ───────────────────────────────────────────────────

# Angular Material — NOT a GitLab runner token
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

# HTML input name attribute — NOT a password
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

# Test credential in intentionally vulnerable app
TEST_CREDENTIAL_FP = """
testingUsername = "testing@juice-sh.op";
testingPassword = "IamUsedForTesting";
ngOnInit() {
    let e = localStorage.getItem("user");
}
"""

# Public OAuth client ID — not a secret
OAUTH_CLIENT_ID_FP = """
clientId = "1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.com";
"""
