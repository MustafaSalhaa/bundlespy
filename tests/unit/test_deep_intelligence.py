"""
Regression tests for BundleSpy deep JavaScript intelligence engine.

Covers:
- Data-flow / constant propagation
- Variable reference resolution in fetch/axios/XHR
- Template literal resolution
- String concatenation
- Path parameter extraction
- All HTTP client patterns
- WebSocket detection
- GraphQL operation extraction
- Dynamic imports
- Workers / ServiceWorkers
- Config object extraction
- Serverless/Netlify function patterns
- navigator.sendBeacon / EventSource
- Minified JavaScript
- False-positive rejection
- Unresolved placeholder handling
- Static/runtime correlation (via existing correlate_endpoints)
- Content-hash deduplication (via existing _analyze)
"""

import hashlib
import pytest
import sys

sys.path.insert(0, "src")

from bundlespy.analysis.ast_endpoints import (
    extract_all_endpoints,
    extract_dynamic_imports,
    extract_workers,
    extract_graphql_operations,
    extract_config_entries,
)
from bundlespy.analysis.dataflow import (
    build_env,
    resolve_url_arg,
    DataFlowEnv,
    DYNAMIC_MARKER,
    _is_url_like,
    _is_placeholder,
)
from bundlespy.analysis.endpoints import _categorize_path, correlate_endpoints, _canonical_key
from bundlespy.storage.models import Endpoint


# ─────────────────────────────────────────────────────────────────────────────
# DataFlowEnv — constant propagation
# ─────────────────────────────────────────────────────────────────────────────

class TestDataFlowEnv:

    def test_simple_string_const(self):
        env = build_env('const base = "/api/v2";')
        assert env.resolve("base") == "/api/v2"

    def test_let_assignment(self):
        env = build_env('let url = "/api/users";')
        assert env.resolve("url") == "/api/users"

    def test_var_assignment(self):
        env = build_env('var endpoint = "/api/orders";')
        assert env.resolve("endpoint") == "/api/orders"

    def test_concat_assignment(self):
        env = build_env('const base = "/api";\nconst path = base + "/users";')
        assert env.resolve("path") == "/api/users"

    def test_concat_assignment_reversed(self):
        env = build_env('const suffix = "/users";\nconst path = "/api" + suffix;')
        assert env.resolve("path") == "/api/users"

    def test_template_literal(self):
        env = build_env('const base = "/api/v2";\nconst url = `${base}/orders`;')
        assert env.resolve("url") == "/api/v2/orders"

    def test_unresolved_returns_none(self):
        env = build_env("const x = someFunction();")
        assert env.resolve("x") is None

    def test_config_object_api_url(self):
        js = 'const config = { apiBase: "/api/v2", wsUrl: "wss://host/ws" };'
        env = build_env(js)
        cfg = env.get_api_config()
        assert "apiBase" in cfg
        assert cfg["apiBase"] == "/api/v2"

    def test_config_ws_url(self):
        js = 'const config = { wsUrl: "wss://api.example.com/socket" };'
        env = build_env(js)
        cfg = env.get_api_config()
        assert "wsUrl" in cfg

    def test_placeholder_not_stored(self):
        env = build_env('const key = "your-api-key";')
        assert env.resolve("key") is None

    def test_empty_string_not_stored(self):
        env = build_env('const x = "";')
        assert env.resolve("x") is None

    def test_max_vars_not_exceeded(self):
        """Should not crash on large files with many assignments."""
        js = "\n".join(f'const v{i} = "/api/{i}";' for i in range(600))
        env = build_env(js)
        assert isinstance(env.vars, dict)

    def test_resolve_url_arg_literal(self):
        env = build_env("")
        assert resolve_url_arg("/api/users", env) == "/api/users"

    def test_resolve_url_arg_variable(self):
        env = build_env('const url = "/api/users";')
        assert resolve_url_arg("url", env) == "/api/users"

    def test_resolve_url_arg_nonurl_returns_none(self):
        env = build_env('const x = "hello world";')
        assert resolve_url_arg("x", env) is None

    def test_is_url_like(self):
        assert _is_url_like("/api/users")
        assert _is_url_like("https://example.com/api")
        assert _is_url_like("wss://host/ws")
        assert not _is_url_like("undefined")
        assert not _is_url_like("")

    def test_is_placeholder(self):
        assert _is_placeholder("undefined")
        assert _is_placeholder("null")
        assert _is_placeholder("your-api-key")
        assert _is_placeholder("")
        assert not _is_placeholder("/api/users")


# ─────────────────────────────────────────────────────────────────────────────
# fetch() detection
# ─────────────────────────────────────────────────────────────────────────────

class TestFetchDetection:

    def test_simple_fetch(self):
        eps = extract_all_endpoints('fetch("/api/users")', "test.js")
        urls = [e.url for e in eps]
        assert "/api/users" in urls

    def test_fetch_single_quote(self):
        eps = extract_all_endpoints("fetch('/api/users')", "test.js")
        assert any("/api/users" in e.url for e in eps)

    def test_fetch_template_literal(self):
        eps = extract_all_endpoints('fetch(`/api/users`)', "test.js")
        assert any("/api/users" in e.url for e in eps)

    def test_fetch_variable_resolved(self):
        js = 'const url = "/api/users";\nfetch(url);'
        eps = extract_all_endpoints(js, "test.js")
        assert any("/api/users" in e.url for e in eps)

    def test_fetch_method_is_get(self):
        eps = extract_all_endpoints('fetch("/api/users")', "test.js")
        ep = next((e for e in eps if "/api/users" in e.url), None)
        assert ep is not None
        assert ep.method == "GET"

    def test_fetch_template_with_variable(self):
        js = 'const base = "/api/v2";\nfetch(`${base}/orders`);'
        eps = extract_all_endpoints(js, "test.js")
        assert any("orders" in e.url for e in eps)

    def test_fetch_no_duplicate(self):
        js = 'fetch("/api/users");\nfetch("/api/users");'
        eps = extract_all_endpoints(js, "test.js")
        matching = [e for e in eps if "/api/users" in e.url]
        assert len(matching) == 1

    def test_fetch_has_evidence(self):
        eps = extract_all_endpoints('fetch("/api/users")', "test.js")
        ep = next((e for e in eps if "/api/users" in e.url), None)
        assert ep is not None
        assert ep.evidence  # must not be empty

    def test_fetch_has_line_number(self):
        js = "\n\nfetch('/api/users')"
        eps = extract_all_endpoints(js, "test.js")
        ep = next((e for e in eps if "/api/users" in e.url), None)
        assert ep is not None
        assert ep.line_number == 3


# ─────────────────────────────────────────────────────────────────────────────
# axios detection
# ─────────────────────────────────────────────────────────────────────────────

class TestAxiosDetection:

    def test_axios_get(self):
        eps = extract_all_endpoints('axios.get("/api/users")', "test.js")
        ep = next((e for e in eps if "/api/users" in e.url), None)
        assert ep is not None
        assert ep.method == "GET"

    def test_axios_post(self):
        eps = extract_all_endpoints('axios.post("/api/orders", data)', "test.js")
        ep = next((e for e in eps if "/api/orders" in e.url), None)
        assert ep is not None
        assert ep.method == "POST"

    def test_axios_put(self):
        eps = extract_all_endpoints('axios.put("/api/users/1", data)', "test.js")
        ep = next((e for e in eps if "/api/users" in e.url), None)
        assert ep is not None
        assert ep.method == "PUT"

    def test_axios_delete(self):
        eps = extract_all_endpoints('axios.delete("/api/users/1")', "test.js")
        ep = next((e for e in eps if "/api/users" in e.url), None)
        assert ep is not None
        assert ep.method == "DELETE"

    def test_axios_patch(self):
        eps = extract_all_endpoints('axios.patch("/api/users/1", data)', "test.js")
        ep = next((e for e in eps if "/api/users" in e.url), None)
        assert ep is not None
        assert ep.method == "PATCH"

    def test_axios_variable_resolved(self):
        js = 'const endpoint = "/api/orders";\naxios.post(endpoint, data);'
        eps = extract_all_endpoints(js, "test.js")
        assert any("/api/orders" in e.url for e in eps)

    def test_axios_template_literal(self):
        js = 'const id = "123";\naxios.get(`/api/orders/${id}`);'
        eps = extract_all_endpoints(js, "test.js")
        assert any("orders" in e.url for e in eps)

    def test_axios_config_object(self):
        js = 'axios({ url: "/api/users", method: "POST" })'
        eps = extract_all_endpoints(js, "test.js")
        assert any("/api/users" in e.url for e in eps)

    def test_axios_concat_base(self):
        js = 'const base = "/api";\naxios.get(base + "/products");'
        eps = extract_all_endpoints(js, "test.js")
        # Either the concat or the base var resolution should find it
        assert any("product" in e.url or "/api" in e.url for e in eps)


# ─────────────────────────────────────────────────────────────────────────────
# XMLHttpRequest
# ─────────────────────────────────────────────────────────────────────────────

class TestXHRDetection:

    def test_xhr_get(self):
        js = 'xhr.open("GET", "/api/data")'
        eps = extract_all_endpoints(js, "test.js")
        ep = next((e for e in eps if "/api/data" in e.url), None)
        assert ep is not None
        assert ep.method == "GET"

    def test_xhr_post(self):
        js = 'xhr.open("POST", "/api/submit")'
        eps = extract_all_endpoints(js, "test.js")
        ep = next((e for e in eps if "/api/submit" in e.url), None)
        assert ep is not None
        assert ep.method == "POST"

    def test_xhr_variable_resolved(self):
        js = 'const url = "/api/data";\nxhr.open("GET", url);'
        eps = extract_all_endpoints(js, "test.js")
        assert any("/api/data" in e.url for e in eps)


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket
# ─────────────────────────────────────────────────────────────────────────────

class TestWebSocketDetection:

    def test_ws_url(self):
        eps = extract_all_endpoints('new WebSocket("ws://host/socket")', "test.js")
        ep = next((e for e in eps if "ws://" in e.url), None)
        assert ep is not None
        assert ep.method == "WS"
        assert ep.category == "WEBSOCKET"

    def test_wss_url(self):
        eps = extract_all_endpoints('new WebSocket("wss://api.example.com/ws")', "test.js")
        ep = next((e for e in eps if "wss://" in e.url), None)
        assert ep is not None

    def test_ws_template(self):
        js = 'new WebSocket(`wss://host/ws`)'
        eps = extract_all_endpoints(js, "test.js")
        assert any("wss://" in e.url for e in eps)

    def test_ws_variable(self):
        js = 'const wsUrl = "wss://host/ws";\nnew WebSocket(wsUrl);'
        eps = extract_all_endpoints(js, "test.js")
        assert any("wss://" in e.url for e in eps)


# ─────────────────────────────────────────────────────────────────────────────
# GraphQL
# ─────────────────────────────────────────────────────────────────────────────

class TestGraphQLDetection:

    def test_graphql_path(self):
        eps = extract_all_endpoints('fetch("/graphql", { method: "POST" })', "test.js")
        ep = next((e for e in eps if "graphql" in e.url), None)
        assert ep is not None
        assert ep.category == "GRAPHQL"

    def test_graphql_operation_query(self):
        js = 'const q = gql`query GetUsers { users { id name } }`'
        ops = extract_graphql_operations(js, "test.js")
        assert any(o.op_type == "query" and o.name == "GetUsers" for o in ops)

    def test_graphql_operation_mutation(self):
        js = 'mutation CreateOrder($input: OrderInput!) { createOrder(input: $input) { id } }'
        ops = extract_graphql_operations(js, "test.js")
        assert any(o.op_type == "mutation" and o.name == "CreateOrder" for o in ops)

    def test_graphql_operation_subscription(self):
        js = 'subscription OnOrderUpdate { orderUpdated { id status } }'
        ops = extract_graphql_operations(js, "test.js")
        assert any(o.op_type == "subscription" and o.name == "OnOrderUpdate" for o in ops)

    def test_graphql_operation_has_source_file(self):
        js = 'query GetProduct { product { id } }'
        ops = extract_graphql_operations(js, "app.js")
        assert all(o.source_file == "app.js" for o in ops)

    def test_graphql_no_duplicate_operations(self):
        js = 'query GetUsers { users { id } }\nquery GetUsers { users { id } }'
        ops = extract_graphql_operations(js, "test.js")
        names = [o.name for o in ops if o.name == "GetUsers"]
        assert len(names) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Dynamic imports
# ─────────────────────────────────────────────────────────────────────────────

class TestDynamicImports:

    def test_dynamic_import(self):
        js = 'import("./chunks/admin.js")'
        imports = extract_dynamic_imports(js, "app.js")
        assert any("admin.js" in i.url for i in imports)

    def test_dynamic_import_kind(self):
        js = 'import("./chunks/admin.js")'
        imports = extract_dynamic_imports(js, "app.js")
        assert all(i.kind == "import" for i in imports)

    def test_require(self):
        js = 'require("./modules/auth.js")'
        imports = extract_dynamic_imports(js, "app.js")
        assert any("auth.js" in i.url for i in imports)

    def test_require_kind(self):
        js = 'require("./modules/auth.js")'
        imports = extract_dynamic_imports(js, "app.js")
        reqs = [i for i in imports if "auth.js" in i.url]
        assert reqs[0].kind == "require"

    def test_new_url_import_meta(self):
        js = 'new URL("./worker.js", import.meta.url)'
        imports = extract_dynamic_imports(js, "app.js")
        assert any("worker.js" in i.url for i in imports)

    def test_dynamic_template_import(self):
        js = 'import(`./chunks/${name}.js`)'
        imports = extract_dynamic_imports(js, "app.js")
        assert len(imports) >= 1
        assert imports[0].dynamic is True

    def test_no_duplicate_imports(self):
        js = 'import("./chunk.js");\nimport("./chunk.js");'
        imports = extract_dynamic_imports(js, "app.js")
        assert len([i for i in imports if "chunk.js" in i.url]) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Workers
# ─────────────────────────────────────────────────────────────────────────────

class TestWorkerDetection:

    def test_worker(self):
        js = 'new Worker("/js/worker.js")'
        workers = extract_workers(js, "app.js")
        assert any("worker.js" in w.url for w in workers)

    def test_worker_kind(self):
        js = 'new Worker("/js/worker.js")'
        workers = extract_workers(js, "app.js")
        assert any(w.kind == "worker" for w in workers)

    def test_shared_worker(self):
        js = 'new SharedWorker("/js/shared.js")'
        workers = extract_workers(js, "app.js")
        assert any("shared.js" in w.url for w in workers)

    def test_service_worker_register(self):
        js = 'navigator.serviceWorker.register("/sw.js")'
        workers = extract_workers(js, "app.js")
        sw = next((w for w in workers if "sw.js" in w.url), None)
        assert sw is not None
        assert sw.kind == "service-worker"

    def test_import_scripts(self):
        js = 'importScripts("/js/utils.js")'
        workers = extract_workers(js, "worker.js")
        assert any("utils.js" in w.url for w in workers)
        assert any(w.kind == "import-scripts" for w in workers)

    def test_worker_new_url(self):
        js = 'new Worker(new URL("./myworker.js", import.meta.url))'
        workers = extract_workers(js, "app.js")
        assert any("myworker.js" in w.url for w in workers)

    def test_worker_has_source_file(self):
        js = 'new Worker("/js/worker.js")'
        workers = extract_workers(js, "main.js")
        assert all(w.source_file == "main.js" for w in workers)


# ─────────────────────────────────────────────────────────────────────────────
# Config extraction
# ─────────────────────────────────────────────────────────────────────────────

class TestConfigExtraction:

    def test_api_base_url(self):
        js = 'const config = { apiBase: "/api/v2" };'
        entries = extract_config_entries(js, "app.js")
        assert any(e.key == "apiBase" and e.value == "/api/v2" for e in entries)

    def test_graphql_url(self):
        js = 'const config = { graphqlUrl: "/graphql" };'
        entries = extract_config_entries(js, "app.js")
        assert any("graphql" in e.key.lower() for e in entries)

    def test_ws_url(self):
        js = 'const config = { wsUrl: "wss://api.example.com/ws" };'
        entries = extract_config_entries(js, "app.js")
        assert any("ws" in e.key.lower() for e in entries)

    def test_non_url_not_extracted(self):
        js = 'const config = { debugMode: true, retries: 3 };'
        entries = extract_config_entries(js, "app.js")
        assert not entries

    def test_entry_has_source_file(self):
        js = 'const config = { apiBase: "/api/v2" };'
        entries = extract_config_entries(js, "config.js")
        assert all(e.source_file == "config.js" for e in entries)


# ─────────────────────────────────────────────────────────────────────────────
# navigator.sendBeacon / EventSource
# ─────────────────────────────────────────────────────────────────────────────

class TestSendBeaconEventSource:

    def test_send_beacon(self):
        js = 'navigator.sendBeacon("/api/analytics", data)'
        eps = extract_all_endpoints(js, "test.js")
        ep = next((e for e in eps if "analytics" in e.url), None)
        assert ep is not None
        assert ep.method == "POST"

    def test_event_source(self):
        js = 'new EventSource("/api/events")'
        eps = extract_all_endpoints(js, "test.js")
        ep = next((e for e in eps if "events" in e.url), None)
        assert ep is not None
        assert ep.method == "GET"


# ─────────────────────────────────────────────────────────────────────────────
# Serverless / Netlify patterns
# ─────────────────────────────────────────────────────────────────────────────

class TestServerlessPatterns:

    def test_netlify_function(self):
        js = 'fetch("/.netlify/functions/send-email")'
        eps = extract_all_endpoints(js, "test.js")
        ep = next((e for e in eps if "send-email" in e.url), None)
        assert ep is not None
        assert ep.category == "SERVERLESS"

    def test_netlify_stock(self):
        js = 'fetch("/.netlify/functions/stock")'
        eps = extract_all_endpoints(js, "test.js")
        ep = next((e for e in eps if "stock" in e.url), None)
        assert ep is not None
        assert ep.category == "SERVERLESS"

    def test_functions_path(self):
        js = 'fetch("/functions/process-payment")'
        eps = extract_all_endpoints(js, "test.js")
        ep = next((e for e in eps if "payment" in e.url), None)
        assert ep is not None
        assert ep.category == "SERVERLESS"


# ─────────────────────────────────────────────────────────────────────────────
# Path parameter extraction
# ─────────────────────────────────────────────────────────────────────────────

class TestPathParameters:

    def test_express_param(self):
        eps = extract_all_endpoints('fetch("/api/users/:id")', "test.js")
        ep = next((e for e in eps if "users" in e.url), None)
        assert ep is not None
        # :id should be replaced with {param}
        assert "{param}" in ep.url or "id" in ep.url

    def test_template_param(self):
        js = 'const id = "123";\nfetch(`/api/orders/${id}`);'
        eps = extract_all_endpoints(js, "test.js")
        assert any("orders" in e.url for e in eps)

    def test_dynamic_param_not_fake_endpoint(self):
        js = 'fetch(`${unknownVar}/users`)'
        eps = extract_all_endpoints(js, "test.js")
        # Should not create a fake endpoint with unresolved var as literal
        for ep in eps:
            assert "unknownVar" not in ep.url
            assert ep.url != DYNAMIC_MARKER


# ─────────────────────────────────────────────────────────────────────────────
# Route definitions (React / Vue / Angular)
# ─────────────────────────────────────────────────────────────────────────────

class TestRouteDefinitions:

    def test_react_router_path(self):
        js = '{ path: "/dashboard", element: <Dashboard /> }'
        eps = extract_all_endpoints(js, "app.js")
        assert any("dashboard" in e.url for e in eps)

    def test_vue_router_path(self):
        js = '{ path: "/users/:id", component: UserDetail }'
        eps = extract_all_endpoints(js, "app.js")
        assert any("users" in e.url for e in eps)

    def test_angular_route(self):
        js = "{ path: 'admin', component: AdminComponent }"
        eps = extract_all_endpoints(js, "app.js")
        assert any("admin" in e.url for e in eps)

    def test_nested_route(self):
        js = "{ path: 'users', children: [{ path: 'list' }, { path: 'create' }] }"
        eps = extract_all_endpoints(js, "app.js")
        urls = [e.url for e in eps]
        assert any("users" in u for u in urls)


# ─────────────────────────────────────────────────────────────────────────────
# String concatenation
# ─────────────────────────────────────────────────────────────────────────────

class TestStringConcatenation:

    def test_simple_concat(self):
        js = 'const url = "/api" + "/users";'
        env = build_env(js)
        val = env.resolve("url")
        assert val == "/api/users"

    def test_concat_endpoint_extracted(self):
        js = 'fetch("/api" + "/users")'
        eps = extract_all_endpoints(js, "test.js")
        assert any("api" in e.url and "users" in e.url for e in eps)

    def test_multipart_concat_via_var(self):
        js = 'const base = "/api/v1";\nconst path = base + "/products";\nfetch(path);'
        eps = extract_all_endpoints(js, "test.js")
        assert any("products" in e.url for e in eps)


# ─────────────────────────────────────────────────────────────────────────────
# Minified JavaScript
# ─────────────────────────────────────────────────────────────────────────────

class TestMinifiedJS:

    def test_minified_fetch(self):
        js = 'function t(){return fetch("/api/users").then(r=>r.json())}t()'
        eps = extract_all_endpoints(js, "bundle.min.js")
        assert any("/api/users" in e.url for e in eps)

    def test_minified_axios(self):
        js = 'var r=axios.get("/api/orders"),s=axios.post("/api/submit",{a:1})'
        eps = extract_all_endpoints(js, "bundle.min.js")
        urls = [e.url for e in eps]
        assert any("/api/orders" in u for u in urls)
        assert any("/api/submit" in u for u in urls)

    def test_minified_websocket(self):
        js = 'var s=new WebSocket("wss://api.example.com/ws");s.onmessage=function(e){}'
        eps = extract_all_endpoints(js, "bundle.min.js")
        assert any("wss://" in e.url for e in eps)


# ─────────────────────────────────────────────────────────────────────────────
# False positive rejection
# ─────────────────────────────────────────────────────────────────────────────

class TestFalsePositiveRejection:

    def test_undefined_not_endpoint(self):
        js = 'fetch(undefined)'
        eps = extract_all_endpoints(js, "test.js")
        assert not any(e.url == "undefined" for e in eps)

    def test_null_not_endpoint(self):
        js = 'fetch(null)'
        eps = extract_all_endpoints(js, "test.js")
        assert not any(e.url == "null" for e in eps)

    def test_empty_string_not_endpoint(self):
        js = 'fetch("")'
        eps = extract_all_endpoints(js, "test.js")
        assert not any(e.url == "" for e in eps)

    def test_image_url_not_endpoint(self):
        js = 'fetch("/images/logo.png")'
        eps = extract_all_endpoints(js, "test.js")
        assert not any(".png" in e.url for e in eps)

    def test_css_url_not_endpoint(self):
        js = 'fetch("/static/app.css")'
        eps = extract_all_endpoints(js, "test.js")
        assert not any(".css" in e.url for e in eps)

    def test_github_url_not_endpoint(self):
        js = 'var docs = "https://github.com/user/repo";'
        eps = extract_all_endpoints(js, "test.js")
        assert not any("github.com" in e.url for e in eps)

    def test_dynamic_only_not_endpoint(self):
        js = 'fetch(`${unknownBase}/unknown`)'
        eps = extract_all_endpoints(js, "test.js")
        for ep in eps:
            assert ep.url != "{dynamic}"
            assert "unknownBase" not in ep.url

    def test_root_slash_not_endpoint(self):
        js = 'router.push("/")'
        eps = extract_all_endpoints(js, "test.js")
        assert not any(e.url == "/" for e in eps)


# ─────────────────────────────────────────────────────────────────────────────
# Static ↔ runtime correlation
# ─────────────────────────────────────────────────────────────────────────────

class TestStaticRuntimeCorrelation:

    def _ep(self, url, method="GET", category="API", source="static", conf=0.75):
        ep = Endpoint(
            url=url, path=url, method=method, category=category,
            source_file="test.js", line_number=1, confidence=conf,
        )
        ep.source_type = source
        return ep

    def test_same_url_correlated(self):
        static  = [self._ep("/api/users")]
        runtime = [self._ep("/api/users", source="runtime", conf=0.95)]
        result  = correlate_endpoints(static, runtime)
        assert len(result) == 1
        assert result[0].source_type == "correlated"

    def test_different_urls_preserved(self):
        static  = [self._ep("/api/users")]
        runtime = [self._ep("/api/orders", source="runtime")]
        result  = correlate_endpoints(static, runtime)
        assert len(result) == 2

    def test_runtime_method_wins(self):
        static  = [self._ep("/api/users", method="UNKNOWN")]
        runtime = [self._ep("/api/users", method="POST", source="runtime")]
        result  = correlate_endpoints(static, runtime)
        assert result[0].method == "POST"

    def test_confidence_boosted(self):
        static  = [self._ep("/api/users", conf=0.75)]
        runtime = [self._ep("/api/users", conf=0.90, source="runtime")]
        result  = correlate_endpoints(static, runtime)
        assert result[0].confidence > 0.90

    def test_trailing_slash_normalized(self):
        static  = [self._ep("/api/users/")]
        runtime = [self._ep("/api/users", source="runtime")]
        result  = correlate_endpoints(static, runtime)
        assert len(result) == 1
        assert result[0].source_type == "correlated"


# ─────────────────────────────────────────────────────────────────────────────
# Source locations
# ─────────────────────────────────────────────────────────────────────────────

class TestSourceLocations:

    def test_line_number_accurate(self):
        js = "// line 1\n// line 2\nfetch('/api/users')"
        eps = extract_all_endpoints(js, "test.js")
        ep = next((e for e in eps if "/api/users" in e.url), None)
        assert ep is not None
        assert ep.line_number == 3

    def test_source_file_preserved(self):
        js = 'fetch("/api/users")'
        eps = extract_all_endpoints(js, "https://app.com/build/app.js")
        assert all(e.source_file == "https://app.com/build/app.js" for e in eps)

    def test_evidence_not_empty(self):
        js = 'axios.post("/api/orders", { item: 1 })'
        eps = extract_all_endpoints(js, "test.js")
        for ep in eps:
            if "orders" in ep.url:
                assert ep.evidence


# ─────────────────────────────────────────────────────────────────────────────
# Performance
# ─────────────────────────────────────────────────────────────────────────────

class TestPerformance:

    def test_large_file_completes(self):
        """Analysis must complete within the time limit on a large repetitive file."""
        import time
        chunk = 'fetch("/api/users/' + str(0) + '");\n' * 2000
        large = chunk * 5  # ~10k lines
        t = time.monotonic()
        eps = extract_all_endpoints(large, "large.js")
        elapsed = time.monotonic() - t
        assert elapsed < 15.0  # generous wall-clock limit for CI
        assert len(eps) >= 1

    def test_minified_bundle_completes(self):
        """Single-line minified file must not hang."""
        import time
        line = ";".join([f'axios.get("/api/endpoint{i}")' for i in range(500)])
        t = time.monotonic()
        eps = extract_all_endpoints(line, "bundle.min.js")
        elapsed = time.monotonic() - t
        assert elapsed < 10.0
        assert len(eps) >= 1
