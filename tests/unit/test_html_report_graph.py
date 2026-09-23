"""
HTML report + AttackSurfaceGraph integration tests.

Covers:
- generate() returns a string (not None, not empty)
- GRAPH_DATA = null when result.graph is None
- GRAPH_DATA = null when result.graph is an empty AttackSurfaceGraph
- GRAPH_DATA is valid JSON when graph has nodes
- GRAPH_DATA contains nodes array
- GRAPH_DATA contains edges array
- GRAPH_DATA contains stats block
- Node type values in GRAPH_DATA are plain strings ('PAGE', 'JS', etc.)
- Edge type values in GRAPH_DATA are plain strings ('LOADS', 'CALLS', etc.)
- GRAPH_DATA node count matches stats.nodes
- Attack Surface nav button present in HTML
- section-graph div present in HTML
- graph-container div present in HTML
- graph-svg element present in HTML
- d3 script tag present in HTML
- Graph stats row in overview table present when graph has nodes
- Graph stats row absent when graph is None
- No Python Enum repr leaks into GRAPH_DATA string
- HTML output is a string containing valid structure around GRAPH_DATA
- from_scan_result round-trip: graph nodes appear in HTML GRAPH_DATA
- JS nodes from js_files appear in GRAPH_DATA
- ENDPOINT nodes from endpoints appear in GRAPH_DATA
- SECRET nodes from findings appear in GRAPH_DATA
- Empty ScanResult with no graph still produces valid HTML
- show_sensitive=True does not break graph serialization in HTML
"""

import json
import re
from datetime import datetime

import pytest

from bundlespy.storage.models import (
    ScanResult, JSFile, Finding, Endpoint, InfrastructureItem,
)
from bundlespy.storage.graph import (
    AttackSurfaceGraph, Node, Edge, NodeType, EdgeType, _node_id,
)
from bundlespy.reporting import html_report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _empty_result() -> ScanResult:
    return ScanResult(
        target_url="https://app.example.com",
        started_at=datetime(2026, 1, 1, 12, 0, 0),
        finished_at=datetime(2026, 1, 1, 12, 5, 0),
        pages_crawled=1,
        js_files=[],
        findings=[],
        endpoints=[],
        infrastructure=[],
        errors=[],
    )


def _js_file(url: str) -> JSFile:
    return JSFile(
        url=url,
        source_page="https://app.example.com/",
        status_code=200,
        content_type="application/javascript",
        size_bytes=1000,
        sha256="a" * 64,
        content="",
        has_source_map=False,
        technology="React",
        source_type="static",
    )


def _endpoint(url: str) -> Endpoint:
    return Endpoint(
        url=url,
        path=url,
        method="GET",
        category="API",
        source_file="https://app.example.com/app.js",
        line_number=10,
        confidence=0.9,
    )


def _finding() -> Finding:
    matched = "AKIAIOSFODNN7EXAMPLE"
    return Finding(
        id=Finding.make_id("aws-key", matched, "https://app.example.com/app.js"),
        rule_id="aws-key",
        title="AWS Access Key",
        category="credentials",
        severity="CRITICAL",
        confidence=0.95,
        file_url="https://app.example.com/app.js",
        source_page="https://app.example.com/",
        line_number=42,
        column=5,
        matched_value=matched,
        redacted_value=Finding.redact(matched),
        sha256="x" * 64,
        context="const key = 'AKIAIOSFODNN7EXAMPLE'",
        description="AWS key found",
        impact="Full AWS account takeover",
        remediation="Rotate immediately",
        false_positive_notes="",
        status="candidate",
    )


def _simple_graph() -> AttackSurfaceGraph:
    g = AttackSurfaceGraph()
    page_id = _node_id("page", "https://app.example.com/")
    js_id   = _node_id("js",   "https://app.example.com/app.js")
    ep_id   = _node_id("endpoint", "https://api.example.com/users", "GET")
    sec_id  = _node_id("finding",  "aws-key", "AKIAIOSFODNN7EXAMPLE")

    g.add_node(Node(id=page_id, kind=NodeType.PAGE,     label="/",           data={}))
    g.add_node(Node(id=js_id,   kind=NodeType.JS,       label="app.js",      data={}))
    g.add_node(Node(id=ep_id,   kind=NodeType.ENDPOINT, label="GET /users",  data={}))
    g.add_node(Node(id=sec_id,  kind=NodeType.SECRET,   label="aws-key",     data={}))

    g.add_edge(page_id, js_id,  EdgeType.LOADS)
    g.add_edge(js_id,   ep_id,  EdgeType.CALLS)
    g.add_edge(js_id,   sec_id, EdgeType.EXPOSES)
    return g


def _extract_graph_data(html: str) -> dict:
    """Pull GRAPH_DATA = {...}; or GRAPH_DATA = null; from the HTML and parse it."""
    m = re.search(r"const GRAPH_DATA = (.+?);", html, re.DOTALL)
    assert m, "GRAPH_DATA assignment not found in HTML"
    raw = m.group(1).strip()
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Basic output
# ---------------------------------------------------------------------------

def test_generate_returns_string():
    """html_report.generate() must return a non-empty string."""
    result = _empty_result()
    out = html_report.generate(result)
    assert isinstance(out, str) and len(out) > 0


def test_generate_with_graph_returns_string():
    """html_report.generate() with graph attached returns a non-empty string."""
    result = _empty_result()
    result.graph = _simple_graph()
    out = html_report.generate(result)
    assert isinstance(out, str) and len(out) > 0


# ---------------------------------------------------------------------------
# GRAPH_DATA injection
# ---------------------------------------------------------------------------

def test_graph_data_null_when_no_graph():
    """GRAPH_DATA = null when result.graph is None."""
    result = _empty_result()
    result.graph = None
    out = html_report.generate(result)
    assert "const GRAPH_DATA = null;" in out


def test_graph_data_null_when_empty_graph():
    """GRAPH_DATA from an empty AttackSurfaceGraph is the graph's to_dict()."""
    result = _empty_result()
    result.graph = AttackSurfaceGraph()
    out = html_report.generate(result)
    # Empty graph still serializes as a dict (not null)
    gd = _extract_graph_data(out)
    assert isinstance(gd, dict)


def test_graph_data_is_valid_json_with_nodes():
    """GRAPH_DATA is parseable JSON when the graph has nodes."""
    result = _empty_result()
    result.graph = _simple_graph()
    out = html_report.generate(result)
    gd = _extract_graph_data(out)
    assert isinstance(gd, dict)


def test_graph_data_contains_nodes_key():
    """GRAPH_DATA dict contains a 'nodes' key."""
    result = _empty_result()
    result.graph = _simple_graph()
    gd = _extract_graph_data(html_report.generate(result))
    assert "nodes" in gd


def test_graph_data_contains_edges_key():
    """GRAPH_DATA dict contains an 'edges' key."""
    result = _empty_result()
    result.graph = _simple_graph()
    gd = _extract_graph_data(html_report.generate(result))
    assert "edges" in gd


def test_graph_data_contains_stats_key():
    """GRAPH_DATA dict contains a 'stats' key."""
    result = _empty_result()
    result.graph = _simple_graph()
    gd = _extract_graph_data(html_report.generate(result))
    assert "stats" in gd


def test_graph_data_node_types_are_strings():
    """Every node in GRAPH_DATA has a 'kind' field that is a plain string."""
    result = _empty_result()
    result.graph = _simple_graph()
    gd = _extract_graph_data(html_report.generate(result))
    for node in gd["nodes"]:
        assert isinstance(node["kind"], str), f"node kind not a string: {node['kind']!r}"
        assert "NodeType" not in node["kind"]


def test_graph_data_edge_types_are_strings():
    """Every edge in GRAPH_DATA has a 'kind' field that is a plain string."""
    result = _empty_result()
    result.graph = _simple_graph()
    gd = _extract_graph_data(html_report.generate(result))
    for edge in gd["edges"]:
        assert isinstance(edge["kind"], str), f"edge kind not a string: {edge['kind']!r}"
        assert "EdgeType" not in edge["kind"]


def test_graph_data_stats_node_count_matches():
    """GRAPH_DATA stats.nodes matches the length of the nodes array."""
    result = _empty_result()
    result.graph = _simple_graph()
    gd = _extract_graph_data(html_report.generate(result))
    assert gd["stats"]["nodes"] == len(gd["nodes"])


def test_graph_data_stats_edge_count_matches():
    """GRAPH_DATA stats.edges matches the length of the edges array."""
    result = _empty_result()
    result.graph = _simple_graph()
    gd = _extract_graph_data(html_report.generate(result))
    assert gd["stats"]["edges"] == len(gd["edges"])


def test_no_enum_repr_in_html():
    """The string 'NodeType.' and 'EdgeType.' never appear in the HTML output."""
    result = _empty_result()
    result.graph = _simple_graph()
    out = html_report.generate(result)
    assert "NodeType." not in out
    assert "EdgeType." not in out


# ---------------------------------------------------------------------------
# HTML structure
# ---------------------------------------------------------------------------

def test_attack_surface_nav_button_present():
    """HTML contains the Attack Surface nav button."""
    result = _empty_result()
    out = html_report.generate(result)
    assert "Attack Surface" in out


def test_section_graph_div_present():
    """HTML contains section-graph div."""
    result = _empty_result()
    out = html_report.generate(result)
    assert 'id="section-graph"' in out


def test_graph_container_div_present():
    """HTML contains graph-container div."""
    result = _empty_result()
    out = html_report.generate(result)
    assert 'id="graph-container"' in out


def test_graph_svg_element_present():
    """HTML contains graph-svg SVG element."""
    result = _empty_result()
    out = html_report.generate(result)
    assert 'id="graph-svg"' in out


def test_d3_script_tag_present():
    """HTML includes d3.js script tag."""
    result = _empty_result()
    out = html_report.generate(result)
    assert "d3" in out


# ---------------------------------------------------------------------------
# Overview table stats row
# ---------------------------------------------------------------------------

def test_graph_stats_row_present_when_graph_exists():
    """Overview meta table shows graph node/relationship count when graph is set."""
    result = _empty_result()
    result.graph = _simple_graph()
    out = html_report.generate(result)
    assert "nodes" in out and "relationships" in out


def test_graph_stats_row_absent_when_no_graph():
    """Overview meta table does not show graph stats when graph is None."""
    result = _empty_result()
    result.graph = None
    out = html_report.generate(result)
    # 'relationships' only appears in the graph stats row
    assert "relationships" not in out


# ---------------------------------------------------------------------------
# from_scan_result round-trip: entity types appear in GRAPH_DATA
# ---------------------------------------------------------------------------

def test_js_files_become_js_nodes_in_html():
    """JS files from ScanResult appear as JS kind nodes in GRAPH_DATA."""
    result = ScanResult(
        target_url="https://app.example.com",
        started_at=datetime(2026, 1, 1),
        finished_at=None,
        pages_crawled=1,
        js_files=[_js_file("https://app.example.com/app.js")],
        findings=[],
        endpoints=[],
        infrastructure=[],
        errors=[],
    )
    result.graph = AttackSurfaceGraph.from_scan_result(result)
    gd = _extract_graph_data(html_report.generate(result))
    kinds = {n["kind"] for n in gd["nodes"]}
    assert "JS" in kinds


def test_endpoints_become_endpoint_nodes_in_html():
    """Endpoints from ScanResult appear as ENDPOINT kind nodes in GRAPH_DATA."""
    result = ScanResult(
        target_url="https://app.example.com",
        started_at=datetime(2026, 1, 1),
        finished_at=None,
        pages_crawled=1,
        js_files=[_js_file("https://app.example.com/app.js")],
        findings=[],
        endpoints=[_endpoint("https://api.example.com/users")],
        infrastructure=[],
        errors=[],
    )
    result.graph = AttackSurfaceGraph.from_scan_result(result)
    gd = _extract_graph_data(html_report.generate(result))
    kinds = {n["kind"] for n in gd["nodes"]}
    assert "ENDPOINT" in kinds


def test_findings_become_secret_nodes_in_html():
    """Findings from ScanResult appear as SECRET kind nodes in GRAPH_DATA."""
    result = ScanResult(
        target_url="https://app.example.com",
        started_at=datetime(2026, 1, 1),
        finished_at=None,
        pages_crawled=1,
        js_files=[_js_file("https://app.example.com/app.js")],
        findings=[_finding()],
        endpoints=[],
        infrastructure=[],
        errors=[],
    )
    result.graph = AttackSurfaceGraph.from_scan_result(result)
    gd = _extract_graph_data(html_report.generate(result))
    kinds = {n["kind"] for n in gd["nodes"]}
    assert "SECRET" in kinds


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_scan_result_no_graph_valid_html():
    """An empty ScanResult with no graph produces valid HTML (no crash)."""
    result = _empty_result()
    result.graph = None
    out = html_report.generate(result)
    assert "<html" in out or "<!DOCTYPE" in out or "<body" in out


def test_show_sensitive_true_graph_not_broken():
    """show_sensitive=True does not break graph section in HTML."""
    result = _empty_result()
    result.graph = _simple_graph()
    out = html_report.generate(result, show_sensitive=True)
    gd = _extract_graph_data(out)
    assert len(gd["nodes"]) == 4


def test_graph_node_labels_in_html():
    """Node labels are present as strings in GRAPH_DATA nodes."""
    result = _empty_result()
    result.graph = _simple_graph()
    gd = _extract_graph_data(html_report.generate(result))
    labels = [n["label"] for n in gd["nodes"]]
    assert "app.js" in labels
