"""
Regression tests for the BundleSpy Attack Surface Graph (storage/graph.py).

Every public API of AttackSurfaceGraph is covered.
Tests use synthetic ScanResult fixtures — no network, no disk I/O.
"""

import hashlib
import pytest
from datetime import datetime
from typing import List

import sys
sys.path.insert(0, "src")

from bundlespy.storage.models import (
    ScanResult, JSFile, Finding, Endpoint, InfrastructureItem,
)
from bundlespy.storage.graph import (
    AttackSurfaceGraph, Node, Edge,
    NodeType, EdgeType,
    _node_id, _page_label, _js_label, _endpoint_label,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _js(url: str, source_page: str = "https://app.com/",
        size: int = 10000, sha: str = "",
        source_type: str = "static", tech: str = "") -> JSFile:
    return JSFile(
        url=url, source_page=source_page,
        status_code=200, content_type="text/javascript",
        size_bytes=size, sha256=sha or hashlib.sha256(url.encode()).hexdigest(),
        content="", technology=tech, source_type=source_type,
    )


def _ep(url: str, method: str = "GET", category: str = "API",
        source_file: str = "https://app.com/app.js",
        confidence: float = 0.85,
        path_params: list = None,
        query_params: list = None,
        auth_context: str = "") -> Endpoint:
    from urllib.parse import urlparse
    p = urlparse(url)
    return Endpoint(
        url=url, path=p.path or url,
        method=method, category=category,
        source_file=source_file,
        line_number=1, confidence=confidence,
        host=p.netloc if p.scheme else "",
        path_params=path_params or [],
        query_params=query_params or [],
        auth_context=auth_context,
        evidence="", kind="api",
    )


def _finding(rule_id: str, value: str,
             file_url: str = "https://app.com/app.js",
             source_page: str = "https://app.com/",
             severity: str = "HIGH",
             status: str = "likely_secret") -> Finding:
    sha = hashlib.sha256(f"{rule_id}:{value}".encode()).hexdigest()
    return Finding(
        id=sha[:16], rule_id=rule_id, title=f"Test {rule_id}",
        category="Test", severity=severity, confidence=0.90,
        file_url=file_url, source_page=source_page,
        line_number=10, column=0,
        matched_value=value, redacted_value=value[:4] + "****",
        sha256=sha, context="test context",
        description="", impact="", remediation="",
        false_positive_notes="", status=status,
    )


def _infra(value: str, classification: str = "PRIVATE_IP",
           source_file: str = "app.js") -> InfrastructureItem:
    return InfrastructureItem(
        value=value, classification=classification,
        source_file=source_file, line_number=1,
        confidence=0.92, action="report_only",
    )


def _result(**kwargs) -> ScanResult:
    defaults = dict(
        target_url="https://app.com",
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        pages_crawled=3,
        js_files=[],
        findings=[],
        endpoints=[],
        infrastructure=[],
        errors=[],
    )
    defaults.update(kwargs)
    return ScanResult(**defaults)


# ── Node ID helpers ────────────────────────────────────────────────────────────

class TestNodeId:
    def test_deterministic(self):
        assert _node_id("page", "https://app.com/") == _node_id("page", "https://app.com/")

    def test_different_parts_differ(self):
        assert _node_id("page", "https://app.com/a") != _node_id("page", "https://app.com/b")

    def test_length_16(self):
        assert len(_node_id("x", "y")) == 16

    def test_empty_parts_ignored(self):
        assert _node_id("page", "", "x") == _node_id("page", "x")


class TestLabels:
    def test_page_label_path_only(self):
        assert _page_label("https://app.com/dashboard") == "/dashboard"

    def test_page_label_root(self):
        assert _page_label("https://app.com/") == "/"

    def test_page_label_query(self):
        label = _page_label("https://app.com/search?q=test")
        assert "search" in label
        assert "q=test" in label

    def test_js_label_filename(self):
        assert _js_label("https://app.com/build/app.js") == "app.js"

    def test_js_label_inline(self):
        label = _js_label("inline:https://app.com/#script-3-abc123")
        assert "inline script 3" in label

    def test_endpoint_label(self):
        ep = _ep("/api/users", method="GET")
        assert "GET" in _endpoint_label(ep)
        assert "users" in _endpoint_label(ep)

    def test_endpoint_label_unknown_method(self):
        ep = _ep("/api/users", method="UNKNOWN")
        label = _endpoint_label(ep)
        assert "?" in label or "UNKNOWN" not in label


# ── Graph construction ────────────────────────────────────────────────────────

class TestGraphConstruction:

    def test_empty_result(self):
        g = AttackSurfaceGraph.from_scan_result(_result())
        assert isinstance(g, AttackSurfaceGraph)
        assert g.stats()["nodes"] == 0

    def test_js_file_creates_node(self):
        js = _js("https://app.com/app.js")
        g  = AttackSurfaceGraph.from_scan_result(_result(js_files=[js]))
        nodes = g.nodes_of_kind(NodeType.JS)
        assert len(nodes) == 1
        assert "app.js" in nodes[0].label

    def test_js_source_page_creates_page_node(self):
        js = _js("https://app.com/app.js", source_page="https://app.com/dashboard")
        g  = AttackSurfaceGraph.from_scan_result(_result(js_files=[js]))
        pages = g.nodes_of_kind(NodeType.PAGE)
        assert len(pages) == 1
        assert "/dashboard" in pages[0].label

    def test_page_loads_js_edge(self):
        js = _js("https://app.com/app.js", source_page="https://app.com/dashboard")
        g  = AttackSurfaceGraph.from_scan_result(_result(js_files=[js]))
        pages = g.nodes_of_kind(NodeType.PAGE)
        js_nodes = g.nodes_of_kind(NodeType.JS)
        edges = g.edges_from(pages[0].id)
        assert any(e.kind == EdgeType.LOADS and e.target == js_nodes[0].id for e in edges)

    def test_endpoint_creates_node(self):
        ep = _ep("/api/users")
        g  = AttackSurfaceGraph.from_scan_result(_result(endpoints=[ep]))
        eps = g.nodes_of_kind(NodeType.ENDPOINT)
        assert len(eps) == 1
        assert "users" in eps[0].label

    def test_js_calls_endpoint_edge(self):
        js = _js("https://app.com/app.js")
        ep = _ep("/api/users", source_file="https://app.com/app.js")
        g  = AttackSurfaceGraph.from_scan_result(_result(js_files=[js], endpoints=[ep]))
        js_nodes = g.nodes_of_kind(NodeType.JS)
        eps = g.nodes_of_kind(NodeType.ENDPOINT)
        edges = g.edges_from(js_nodes[0].id)
        assert any(e.kind == EdgeType.CALLS and e.target == eps[0].id for e in edges)

    def test_path_param_creates_node(self):
        ep = _ep("/api/users/{id}", path_params=[{"name": "id", "position": 2}])
        g  = AttackSurfaceGraph.from_scan_result(_result(endpoints=[ep]))
        params = g.nodes_of_kind(NodeType.PARAMETER)
        assert any(p.label == "id" for p in params)

    def test_query_param_creates_node(self):
        ep = _ep("/api/search", query_params=[{"name": "q"}])
        g  = AttackSurfaceGraph.from_scan_result(_result(endpoints=[ep]))
        params = g.nodes_of_kind(NodeType.PARAMETER)
        assert any(p.label == "q" for p in params)

    def test_endpoint_accepts_path_param_edge(self):
        ep = _ep("/api/users/{id}", path_params=[{"name": "id", "position": 2}])
        g  = AttackSurfaceGraph.from_scan_result(_result(endpoints=[ep]))
        eps = g.nodes_of_kind(NodeType.ENDPOINT)
        edges = g.edges_from(eps[0].id)
        assert any(e.kind == EdgeType.ACCEPTS for e in edges)

    def test_finding_creates_secret_node(self):
        f = _finding("JWT_TOKEN", "eyJhbG...")
        g = AttackSurfaceGraph.from_scan_result(_result(findings=[f]))
        secrets = g.nodes_of_kind(NodeType.SECRET)
        assert len(secrets) == 1

    def test_false_positive_not_in_graph(self):
        f = _finding("JWT_TOKEN", "eyJhbG...", status="likely_false_positive")
        g = AttackSurfaceGraph.from_scan_result(_result(findings=[f]))
        secrets = g.nodes_of_kind(NodeType.SECRET)
        assert len(secrets) == 0

    def test_js_exposes_secret_edge(self):
        js = _js("https://app.com/app.js")
        f  = _finding("JWT_TOKEN", "eyJhbG...", file_url="https://app.com/app.js")
        g  = AttackSurfaceGraph.from_scan_result(_result(js_files=[js], findings=[f]))
        js_nodes = g.nodes_of_kind(NodeType.JS)
        edges = g.edges_from(js_nodes[0].id)
        assert any(e.kind == EdgeType.EXPOSES for e in edges)

    def test_infrastructure_creates_host_node(self):
        infra = _infra("192.168.1.100")
        g = AttackSurfaceGraph.from_scan_result(_result(infrastructure=[infra]))
        hosts = g.nodes_of_kind(NodeType.HOST)
        assert any(h.label == "192.168.1.100" for h in hosts)

    def test_worker_js_creates_worker_node(self):
        js = _js("https://app.com/worker.js", tech="webworker")
        g  = AttackSurfaceGraph.from_scan_result(_result(js_files=[js]))
        workers = g.nodes_of_kind(NodeType.WORKER)
        assert len(workers) == 1

    def test_chunk_js_creates_chunk_node(self):
        js = _js("https://app.com/chunk.abc123.js", tech="webpack-chunk")
        g  = AttackSurfaceGraph.from_scan_result(_result(js_files=[js]))
        chunks = g.nodes_of_kind(NodeType.CHUNK)
        assert len(chunks) == 1


# ── Graph queries ─────────────────────────────────────────────────────────────

class TestGraphQueries:

    def _build_rich_graph(self) -> AttackSurfaceGraph:
        js  = _js("https://app.com/app.js", source_page="https://app.com/dashboard")
        ep1 = _ep("/api/users", source_file="https://app.com/app.js",
                  path_params=[{"name": "id"}])
        ep2 = _ep("/api/orders", source_file="https://app.com/app.js")
        f   = _finding("JWT_TOKEN", "eyJhbG...", file_url="https://app.com/app.js",
                       source_page="https://app.com/dashboard")
        return AttackSurfaceGraph.from_scan_result(_result(
            js_files=[js], endpoints=[ep1, ep2], findings=[f],
        ))

    def test_nodes_of_kind(self):
        g = self._build_rich_graph()
        assert len(g.nodes_of_kind(NodeType.JS))       == 1
        assert len(g.nodes_of_kind(NodeType.PAGE))     == 1
        assert len(g.nodes_of_kind(NodeType.ENDPOINT)) == 2
        assert len(g.nodes_of_kind(NodeType.SECRET))   == 1

    def test_node_by_id(self):
        g = self._build_rich_graph()
        js_nodes = g.nodes_of_kind(NodeType.JS)
        assert g.node(js_nodes[0].id) is js_nodes[0]

    def test_node_missing_returns_none(self):
        g = self._build_rich_graph()
        assert g.node("nonexistent") is None

    def test_edges_from(self):
        g = self._build_rich_graph()
        page = g.nodes_of_kind(NodeType.PAGE)[0]
        edges = g.edges_from(page.id)
        assert len(edges) >= 1
        assert all(e.source == page.id for e in edges)

    def test_edges_to(self):
        g = self._build_rich_graph()
        js = g.nodes_of_kind(NodeType.JS)[0]
        edges = g.edges_to(js.id)
        assert len(edges) >= 1
        assert all(e.target == js.id for e in edges)

    def test_neighbors_out(self):
        g  = self._build_rich_graph()
        page = g.nodes_of_kind(NodeType.PAGE)[0]
        ns   = g.neighbors(page.id, direction="out")
        kinds = {n.kind for n in ns}
        assert NodeType.JS in kinds

    def test_neighbors_in(self):
        g  = self._build_rich_graph()
        js   = g.nodes_of_kind(NodeType.JS)[0]
        ns   = g.neighbors(js.id, direction="in")
        kinds = {n.kind for n in ns}
        assert NodeType.PAGE in kinds

    def test_neighbors_both(self):
        g  = self._build_rich_graph()
        js   = g.nodes_of_kind(NodeType.JS)[0]
        ns   = g.neighbors(js.id, direction="both")
        kinds = {n.kind for n in ns}
        # PAGE comes in, ENDPOINTs and SECRETs go out
        assert NodeType.PAGE in kinds

    def test_attack_surface_for_page(self):
        g    = self._build_rich_graph()
        page = g.nodes_of_kind(NodeType.PAGE)[0]
        surf = g.attack_surface_for_page(page.id)
        assert len(surf["js_files"])  >= 1
        assert len(surf["endpoints"]) >= 1
        assert len(surf["secrets"])   >= 1

    def test_related_findings(self):
        g       = self._build_rich_graph()
        js_node = g.nodes_of_kind(NodeType.JS)[0]
        secrets = g.related_findings(js_node.id)
        assert len(secrets) >= 1
        assert all(s.kind == NodeType.SECRET for s in secrets)


# ── Deduplication ─────────────────────────────────────────────────────────────

class TestDeduplication:

    def test_same_page_not_duplicated(self):
        js1 = _js("https://app.com/app.js",   source_page="https://app.com/dashboard")
        js2 = _js("https://app.com/chunk.js", source_page="https://app.com/dashboard")
        g   = AttackSurfaceGraph.from_scan_result(_result(js_files=[js1, js2]))
        pages = g.nodes_of_kind(NodeType.PAGE)
        assert len(pages) == 1  # same page, one node

    def test_same_edge_not_duplicated(self):
        js = _js("https://app.com/app.js", source_page="https://app.com/dashboard")
        g  = AttackSurfaceGraph.from_scan_result(_result(js_files=[js]))
        page = g.nodes_of_kind(NodeType.PAGE)[0]
        edges = [e for e in g.edges_from(page.id) if e.kind == EdgeType.LOADS]
        assert len(edges) == 1

    def test_same_finding_not_duplicated(self):
        f1 = _finding("JWT", "eyJhbG...")
        f2 = _finding("JWT", "eyJhbG...")  # same content
        g  = AttackSurfaceGraph.from_scan_result(_result(findings=[f1, f2]))
        secrets = g.nodes_of_kind(NodeType.SECRET)
        assert len(secrets) == 1


# ── Stats ─────────────────────────────────────────────────────────────────────

class TestStats:

    def test_stats_keys(self):
        g = AttackSurfaceGraph.from_scan_result(_result())
        s = g.stats()
        assert "nodes" in s
        assert "edges" in s
        assert "by_type" in s

    def test_stats_counts(self):
        js = _js("https://app.com/app.js", source_page="https://app.com/")
        ep = _ep("/api/users", source_file="https://app.com/app.js")
        g  = AttackSurfaceGraph.from_scan_result(_result(js_files=[js], endpoints=[ep]))
        s  = g.stats()
        assert s["by_type"].get("JS",       0) == 1
        assert s["by_type"].get("PAGE",     0) == 1
        assert s["by_type"].get("ENDPOINT", 0) == 1
        assert s["edges"] >= 2  # PAGE→LOADS→JS, JS→CALLS→ENDPOINT


# ── Serialisation ─────────────────────────────────────────────────────────────

class TestSerialisation:

    def test_to_dict_keys(self):
        g = AttackSurfaceGraph.from_scan_result(_result())
        d = g.to_dict()
        assert "nodes" in d
        assert "edges" in d
        assert "stats" in d

    def test_node_to_dict(self):
        n = Node(id="abc", kind=NodeType.JS, label="app.js", confidence=0.95)
        d = n.to_dict()
        assert d["id"]         == "abc"
        assert d["kind"]       == "JS"
        assert d["label"]      == "app.js"
        assert d["confidence"] == 0.95

    def test_edge_to_dict(self):
        e = Edge(source="a", target="b", kind=EdgeType.CALLS)
        d = e.to_dict()
        assert d["source"] == "a"
        assert d["target"] == "b"
        assert d["kind"]   == "CALLS"

    def test_full_graph_serialisable(self):
        import json
        js = _js("https://app.com/app.js", source_page="https://app.com/")
        ep = _ep("/api/users", source_file="https://app.com/app.js",
                 path_params=[{"name": "id"}])
        f  = _finding("JWT", "eyJhbG...", file_url="https://app.com/app.js")
        g  = AttackSurfaceGraph.from_scan_result(_result(
            js_files=[js], endpoints=[ep], findings=[f],
        ))
        # Must not raise
        serialised = json.dumps(g.to_dict())
        assert len(serialised) > 100

    def test_node_data_is_dict(self):
        js = _js("https://app.com/app.js")
        g  = AttackSurfaceGraph.from_scan_result(_result(js_files=[js]))
        for node in g.nodes_of_kind(NodeType.JS):
            assert isinstance(node.data, dict)


# ── ScanResult integration ────────────────────────────────────────────────────

class TestScanResultIntegration:

    def test_scan_result_graph_field_exists(self):
        r = _result()
        assert hasattr(r, "graph")

    def test_scan_result_graph_defaults_none(self):
        r = _result()
        assert r.graph is None

    def test_scan_result_graph_assignable(self):
        r = _result()
        js = _js("https://app.com/app.js")
        r.js_files = [js]
        r.graph = AttackSurfaceGraph.from_scan_result(r)
        assert r.graph is not None
        assert isinstance(r.graph, AttackSurfaceGraph)

    def test_existing_fields_unchanged(self):
        """Verify none of the existing ScanResult fields were removed."""
        r = _result(
            js_files=[_js("https://app.com/app.js")],
            findings=[_finding("JWT", "x")],
            endpoints=[_ep("/api/users")],
            infrastructure=[_infra("10.0.0.1")],
        )
        assert r.target_url   == "https://app.com"
        assert len(r.js_files)       == 1
        assert len(r.findings)       == 1
        assert len(r.endpoints)      == 1
        assert len(r.infrastructure) == 1
        assert r.errors == []
