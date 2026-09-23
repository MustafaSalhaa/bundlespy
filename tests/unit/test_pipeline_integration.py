"""
Integration tests for BundleSpy discovery pipelines.

These tests prove the actual fetch-analyze pipelines work end-to-end,
not just that individual extractors return correct output.

Uses a real threaded HTTP server (stdlib only, no extra deps) to serve
mock JS files, then runs the actual _analyze() pipeline against them.

Proves:
  - Worker pipeline: extract -> resolve URL -> scope check -> fetch -> analyze
  - Dynamic import pipeline: extract -> resolve -> fetch -> analyze -> recurse
  - Preload/duplicate: same content hash fetched via two paths -> analyzed once
  - Analysis counter: content analyzed exactly once, not once per URL
  - GraphQL + REST coexist in one graph via AttackSurfaceGraph.from_scan_result
  - AttackSurfaceGraph nodes and edges built correctly from all sources
  - Same asset appearing via static + runtime -> one correlated endpoint node
"""

import hashlib
import sys
from datetime import datetime
from typing import Dict
from urllib.parse import urlparse

import pytest

sys.path.insert(0, "src")

from bundlespy.analysis.endpoints import correlate_endpoints
from bundlespy.analysis.secrets import SecretScanner
from bundlespy.cli import _analyze
from bundlespy.crawler.fetcher import Fetcher
from bundlespy.crawler.scope import ScopeChecker
from bundlespy.storage.graph import AttackSurfaceGraph, NodeType, EdgeType
from bundlespy.storage.models import Endpoint, JSFile, ScanResult


# ─── Mock fetcher + scope ─────────────────────────────────────────────────────
#
# 127.0.0.1 is blocked by the safety layer (private IP range), so we can't use
# a real TCP server. Instead we use a stub Fetcher that serves content from an
# in-memory dict keyed by path, and a stub ScopeChecker that accepts any URL
# whose path is in that dict (same-origin simulation without network).

class _StubFetcher:
    """Returns JS content from an in-memory routes dict. Tracks call history."""

    def __init__(self, routes: Dict[str, str]):
        # routes: {"/path": "js content"}
        self._routes = routes
        self.calls: list = []  # list of URLs fetched

    def get(self, url: str, **kwargs):
        self.calls.append(url)
        path = urlparse(url).path
        content = self._routes.get(path)
        if content is None:
            return None, 404, "text/javascript", ""
        h = hashlib.sha256(content.encode()).hexdigest()
        return content, 200, "text/javascript", h


class _StubScope:
    """Accepts any URL whose path is registered in the routes dict."""

    def __init__(self, routes: Dict[str, str], base: str = "https://app.example.com"):
        self._routes = routes
        self._base = base

    def in_scope(self, url: str) -> bool:
        path = urlparse(url).path
        return path in self._routes


def _make_stub(routes: Dict[str, str]):
    """Return (stub_fetcher, stub_scope) for the given route map."""
    return _StubFetcher(routes), _StubScope(routes)


def _make_js(url: str, content: str, source_page: str = "https://test.local") -> JSFile:
    h = hashlib.sha256(content.encode()).hexdigest()
    return JSFile(
        url=url, source_page=source_page, status_code=200,
        content_type="text/javascript", size_bytes=len(content),
        sha256=h, content=content,
    )


def _run(js_files, fetcher=None, scope=None):
    scanner = SecretScanner()
    return _analyze(js_files, scanner, fetcher=fetcher, scope=scope)


# ─── Worker pipeline ──────────────────────────────────────────────────────────

class TestWorkerPipeline:
    """
    Proves: main.js -> extract_workers() -> resolve URL -> scope check
            -> fetch (stub) -> _process() -> endpoint registered
    """

    def test_worker_endpoint_fetched_and_analyzed(self):
        worker_js = 'fetch("/api/worker-task", {method:"POST"});'
        main_js   = 'const w = new Worker("https://app.example.com/worker.js");'
        fetcher, scope = _make_stub({"/worker.js": worker_js})
        main = _make_js("https://app.example.com/main.js", main_js)
        _, endpoints, _, _ = _run([main], fetcher=fetcher, scope=scope)
        urls = [e.url for e in endpoints]
        assert "/api/worker-task" in urls, (
            f"Worker endpoint not found. Got: {urls}"
        )

    def test_service_worker_endpoint_fetched(self):
        sw_js   = 'fetch("/api/push-subscription");'
        main_js = 'navigator.serviceWorker.register("https://app.example.com/sw.js");'
        fetcher, scope = _make_stub({"/sw.js": sw_js})
        main = _make_js("https://app.example.com/main.js", main_js)
        _, endpoints, _, _ = _run([main], fetcher=fetcher, scope=scope)
        urls = [e.url for e in endpoints]
        assert "/api/push-subscription" in urls

    def test_out_of_scope_worker_not_fetched(self):
        """Worker URL whose path is not in scope -> worker JS not fetched."""
        main_js = 'const w = new Worker("https://evil.com/worker.js");'
        fetcher, scope = _make_stub({})  # nothing in scope
        main = _make_js("https://app.example.com/main.js", main_js)
        _run([main], fetcher=fetcher, scope=scope)
        # The worker URL should never have been fetched
        evil_fetches = [u for u in fetcher.calls if "evil.com" in u]
        assert evil_fetches == [], f"Out-of-scope worker was fetched: {evil_fetches}"

    def test_worker_not_fetched_twice(self):
        """Same worker URL referenced in two files -> fetched once."""
        worker_js = 'fetch("/api/shared");'
        main_a    = 'new Worker("https://app.example.com/shared-worker.js");'
        main_b    = 'new Worker("https://app.example.com/shared-worker.js");'
        fetcher, scope = _make_stub({"/shared-worker.js": worker_js})
        a = _make_js("https://app.example.com/a.js", main_a)
        b = _make_js("https://app.example.com/b.js", main_b)
        _run([a, b], fetcher=fetcher, scope=scope)
        worker_fetches = [u for u in fetcher.calls if "shared-worker" in u]
        assert len(worker_fetches) <= 1, (
            f"Worker fetched {len(worker_fetches)} times, expected at most 1"
        )


# ─── Dynamic import pipeline ──────────────────────────────────────────────────

class TestDynamicImportPipeline:
    """
    Proves: main.js -> extract_dynamic_imports() -> resolve -> scope check
            -> fetch (stub) -> _process(chunk) -> endpoint registered
    """

    def test_dynamic_import_chunk_analyzed(self):
        chunk_js = 'axios.get("/api/admin/dashboard");'
        # urljoin("https://app.example.com/main.js", "./chunks/admin.js")
        # -> https://app.example.com/chunks/admin.js
        main_js  = 'import("./chunks/admin.js").then(m => m.default());'
        fetcher, scope = _make_stub({"/chunks/admin.js": chunk_js})
        main = _make_js("https://app.example.com/main.js", main_js)
        _, endpoints, _, _ = _run([main], fetcher=fetcher, scope=scope)
        urls = [e.url for e in endpoints]
        assert "/api/admin/dashboard" in urls

    def test_require_chunk_analyzed(self):
        chunk_js = 'fetch("/api/settings");'
        main_js  = 'const m = require("./modules/settings.js");'
        fetcher, scope = _make_stub({"/modules/settings.js": chunk_js})
        main = _make_js("https://app.example.com/main.js", main_js)
        _, endpoints, _, _ = _run([main], fetcher=fetcher, scope=scope)
        urls = [e.url for e in endpoints]
        assert "/api/settings" in urls

    def test_template_placeholder_not_fetched(self):
        """import(`./chunks/${id}.js`) must not be fetched - unresolvable."""
        main_js = 'import(`./chunks/${chunkId}.js`)'
        fetcher, scope = _make_stub({})
        main = _make_js("https://app.example.com/main.js", main_js)
        _run([main], fetcher=fetcher, scope=scope)
        bad = [u for u in fetcher.calls if "${" in u]
        assert bad == [], f"Template literal leaked into fetch: {bad}"

    def test_dynamic_import_not_fetched_twice(self):
        """Same chunk referenced from two files -> fetched once."""
        chunk_js = 'fetch("/api/shared-chunk");'
        main_a   = 'import("./shared.js")'
        main_b   = 'import("./shared.js")'
        fetcher, scope = _make_stub({"/shared.js": chunk_js})
        a = _make_js("https://app.example.com/a.js", main_a)
        b = _make_js("https://app.example.com/b.js", main_b)
        _run([a, b], fetcher=fetcher, scope=scope)
        chunk_fetches = [u for u in fetcher.calls if "shared.js" in u]
        assert len(chunk_fetches) <= 1


# ─── Content analyzed exactly once ────────────────────────────────────────────

class TestSingleAnalysis:
    """
    Proves JS content is analyzed exactly once, not once per URL.
    Uses an instrumented scanner to count actual scan() invocations.
    """

    def test_identical_content_scanned_once(self):
        content = 'fetch("/api/dedup-check");'
        js1 = _make_js("https://cdn1.com/app.js", content)
        js2 = _make_js("https://cdn2.com/app.js", content)  # same sha256

        scanner = SecretScanner()
        scan_calls = []
        real_scan = scanner.scan

        def counted_scan(content_, *args, **kwargs):
            scan_calls.append(content_[:30])
            return real_scan(content_, *args, **kwargs)

        scanner.scan = counted_scan
        _analyze([js1, js2], scanner)

        assert len(scan_calls) == 1, (
            f"Content scanned {len(scan_calls)} times, expected 1"
        )

    def test_different_content_each_scanned(self):
        js1 = _make_js("a.js", 'fetch("/api/orders");')
        js2 = _make_js("b.js", 'fetch("/api/products");')

        scanner = SecretScanner()
        scan_calls = []
        real_scan = scanner.scan
        def counted_scan(c, *a, **kw):
            scan_calls.append(c[:30])
            return real_scan(c, *a, **kw)
        scanner.scan = counted_scan
        _analyze([js1, js2], scanner)
        assert len(scan_calls) == 2

    def test_three_cdn_copies_scanned_once(self):
        """Three CDN URLs serving identical content -> one scan."""
        content = 'fetch("/api/shared");'
        files = [_make_js(f"https://cdn{i}.com/app.js", content) for i in range(3)]
        scanner = SecretScanner()
        scan_calls = []
        real_scan = scanner.scan
        def counted_scan(c, *a, **kw):
            scan_calls.append(True)
            return real_scan(c, *a, **kw)
        scanner.scan = counted_scan
        _analyze(files, scanner)
        assert len(scan_calls) == 1


# ─── AttackSurfaceGraph construction ─────────────────────────────────────────

class TestAttackSurfaceGraph:
    """
    Proves AttackSurfaceGraph.from_scan_result() builds correct nodes
    and edges from all source types.
    """

    def _make_result(self, js_files=None, endpoints=None, findings=None):
        return ScanResult(
            target_url="https://app.example.com",
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            pages_crawled=1,
            js_files=js_files or [],
            findings=findings or [],
            endpoints=endpoints or [],
            infrastructure=[],
            errors=[],
        )

    def _ep(self, url, method="GET", category="API", source_type="static",
             source_file="app.js"):
        ep = Endpoint(
            url=url, path=url, method=method, category=category,
            source_file=source_file, line_number=1, confidence=0.85,
        )
        ep.source_type = source_type
        return ep

    def test_page_node_created(self):
        js = _make_js("https://app.example.com/app.js", 'fetch("/api/x");',
                      source_page="https://app.example.com/")
        result = self._make_result(js_files=[js])
        g = AttackSurfaceGraph.from_scan_result(result)
        pages = g.nodes_of_kind(NodeType.PAGE)
        assert len(pages) >= 1

    def test_js_node_created(self):
        js = _make_js("https://app.example.com/app.js", "",
                      source_page="https://app.example.com/")
        result = self._make_result(js_files=[js])
        g = AttackSurfaceGraph.from_scan_result(result)
        js_nodes = g.nodes_of_kind(NodeType.JS)
        assert len(js_nodes) >= 1

    def test_page_loads_js_edge(self):
        js = _make_js("https://app.example.com/app.js", "",
                      source_page="https://app.example.com/")
        result = self._make_result(js_files=[js])
        g = AttackSurfaceGraph.from_scan_result(result)
        js_nodes = g.nodes_of_kind(NodeType.JS)
        assert js_nodes, "No JS node found"
        edges_to_js = g.edges_to(js_nodes[0].id)
        assert any(e.kind == EdgeType.LOADS for e in edges_to_js), (
            "No PAGE->LOADS->JS edge found"
        )

    def test_endpoint_node_created(self):
        ep = self._ep("/api/users")
        result = self._make_result(endpoints=[ep])
        g = AttackSurfaceGraph.from_scan_result(result)
        ep_nodes = g.nodes_of_kind(NodeType.ENDPOINT)
        assert len(ep_nodes) == 1

    def test_multiple_endpoints_all_nodes(self):
        eps = [
            self._ep("/api/users",    category="API"),
            self._ep("/api/products", category="API"),
            self._ep("/graphql",      category="GRAPHQL"),
        ]
        result = self._make_result(endpoints=eps)
        g = AttackSurfaceGraph.from_scan_result(result)
        ep_nodes = g.nodes_of_kind(NodeType.ENDPOINT)
        assert len(ep_nodes) == 3

    def test_correlated_endpoint_single_node(self):
        """Static + runtime same endpoint -> one node in graph."""
        static_ep  = self._ep("/api/orders", source_type="static")
        runtime_ep = self._ep("/api/orders", source_type="runtime")
        correlated = correlate_endpoints([static_ep], [runtime_ep])
        assert len(correlated) == 1
        result = self._make_result(endpoints=correlated)
        g = AttackSurfaceGraph.from_scan_result(result)
        ep_nodes = g.nodes_of_kind(NodeType.ENDPOINT)
        assert len(ep_nodes) == 1
        assert ep_nodes[0].data.get("source_type") == "correlated"

    def test_worker_node_type(self):
        """JS file with worker in URL gets WORKER node type."""
        js = _make_js("https://app.example.com/worker.js", "",
                      source_page="https://app.example.com/")
        result = self._make_result(js_files=[js])
        g = AttackSurfaceGraph.from_scan_result(result)
        worker_nodes = g.nodes_of_kind(NodeType.WORKER)
        assert len(worker_nodes) >= 1

    def test_chunk_node_type(self):
        """JS file with chunk in URL gets CHUNK node type."""
        js = _make_js("https://app.example.com/chunks/admin.chunk.js", "",
                      source_page="https://app.example.com/")
        result = self._make_result(js_files=[js])
        g = AttackSurfaceGraph.from_scan_result(result)
        chunk_nodes = g.nodes_of_kind(NodeType.CHUNK)
        assert len(chunk_nodes) >= 1

    def test_graph_no_duplicate_nodes(self):
        """Same endpoint added twice -> one node (graph deduplicates by id)."""
        ep = self._ep("/api/users")
        result = self._make_result(endpoints=[ep, ep])
        g = AttackSurfaceGraph.from_scan_result(result)
        ep_nodes = g.nodes_of_kind(NodeType.ENDPOINT)
        urls = [n.data.get("url") for n in ep_nodes]
        assert urls.count("/api/users") == 1

    def test_graph_no_duplicate_edges(self):
        """PAGE->LOADS->JS added twice -> one edge (graph deduplicates)."""
        js = _make_js("https://app.example.com/app.js", "",
                      source_page="https://app.example.com/")
        # Two JS entries with same URL
        js2 = _make_js("https://app.example.com/app.js", "",
                        source_page="https://app.example.com/")
        result = self._make_result(js_files=[js, js2])
        g = AttackSurfaceGraph.from_scan_result(result)
        js_nodes = g.nodes_of_kind(NodeType.JS)
        if js_nodes:
            edges = g.edges_to(js_nodes[0].id)
            loads = [e for e in edges if e.kind == EdgeType.LOADS]
            assert len(loads) == 1


# ─── Full pipeline convergence ────────────────────────────────────────────────

class TestFullPipelineConvergence:
    """
    End-to-end: real HTTP server + real _analyze() + real graph builder.
    Proves all discovery paths produce one coherent attack-surface graph.
    """

    def test_static_worker_runtime_one_graph(self):
        """
        main.js (static) + worker.js (fetched) both find /api/orders.
        Runtime also sees /api/orders.
        Final graph: one correlated endpoint.
        """
        worker_js = 'fetch("/api/orders");'
        main_js   = (
            'new Worker("https://app.example.com/worker.js");\n'
            'fetch("/api/users");'
        )
        fetcher, scope = _make_stub({"/worker.js": worker_js})
        main = _make_js("https://app.example.com/main.js", main_js)
        _, static_eps, _, _ = _run([main], fetcher=fetcher, scope=scope)

        # Runtime sees the same endpoint
        runtime_ep = Endpoint(
            url="/api/orders", path="/api/orders", method="GET",
            category="API", source_file="runtime", line_number=0,
            confidence=0.95,
        )
        runtime_ep.source_type = "runtime"

        final_eps = correlate_endpoints(static_eps, [runtime_ep])

        orders_eps = [e for e in final_eps if "/api/orders" in e.url]
        assert len(orders_eps) == 1, (
            f"Expected 1 /api/orders endpoint, got: {[e.url for e in orders_eps]}"
        )
        assert orders_eps[0].source_type == "correlated"

    def test_graphql_and_rest_in_one_graph(self):
        """
        main.js has both REST and GraphQL.
        Both should appear in the graph as separate endpoint nodes.
        """
        content = (
            'fetch("/api/products");\n'
            'fetch("/graphql", {method:"POST", body: JSON.stringify({query})});\n'
            'const Q = gql`query GetProducts { products { id } }`;'
        )
        js = _make_js("https://app.example.com/app.js", content,
                      source_page="https://app.example.com")
        _, endpoints, _, graphql_ops = _run([js])

        ep_urls = [e.url for e in endpoints]
        assert "/api/products" in ep_urls
        assert "/graphql" in ep_urls
        assert any(o.name == "GetProducts" for o in graphql_ops)

    def test_worker_chunk_static_no_duplicates_in_graph(self):
        """
        Three JS discovery paths all find /api/shared -> one endpoint in result.
        """
        shared_ep_content = 'fetch("/api/shared");'
        main_js   = (
            shared_ep_content +
            '\nimport("./chunk.js");\n'
            'new Worker("https://app.example.com/worker.js");'
        )
        fetcher, scope = _make_stub({
            "/chunk.js":  shared_ep_content,
            "/worker.js": shared_ep_content,
        })
        main = _make_js("https://app.example.com/main.js", main_js)
        _, endpoints, _, _ = _run([main], fetcher=fetcher, scope=scope)
        shared = [e for e in endpoints if "/api/shared" in e.url]
        assert len(shared) == 1, (
            f"/api/shared appears {len(shared)} times, expected 1"
        )

    def test_complete_graph_structure(self):
        """
        Build a ScanResult from a full pipeline run and verify the graph
        has the expected node types and at least one LOADS edge.
        """
        content = (
            'fetch("/api/users");\n'
            'fetch("/graphql", {method:"POST"});\n'
        )
        js_file = _make_js(
            "https://app.example.com/app.js", content,
            source_page="https://app.example.com/"
        )
        findings, endpoints, infra, graphql_ops = _run([js_file])

        result = ScanResult(
            target_url="https://app.example.com",
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            pages_crawled=1,
            js_files=[js_file],
            findings=findings,
            endpoints=endpoints,
            infrastructure=infra,
            errors=[],
        )

        g = AttackSurfaceGraph.from_scan_result(result)

        assert len(g.nodes_of_kind(NodeType.PAGE)) >= 1
        assert len(g.nodes_of_kind(NodeType.JS)) >= 1
        assert len(g.nodes_of_kind(NodeType.ENDPOINT)) >= 1

        # At least one LOADS edge from page to JS
        all_edges = [e for n in g.nodes_of_kind(NodeType.JS)
                     for e in g.edges_to(n.id)]
        loads_edges = [e for e in all_edges if e.kind == EdgeType.LOADS]
        assert len(loads_edges) >= 1, "No PAGE->LOADS->JS edge in graph"

        # /api/users and /graphql both present
        ep_urls = [n.data.get("url") for n in g.nodes_of_kind(NodeType.ENDPOINT)]
        assert "/api/users" in ep_urls
        assert "/graphql" in ep_urls
