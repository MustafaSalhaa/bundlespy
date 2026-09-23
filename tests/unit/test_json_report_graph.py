"""
Advanced JSON report + AttackSurfaceGraph serialization tests.

Covers:
- generate() output is valid JSON
- attack_surface_graph key is always present in output (stable schema)
- attack_surface_graph.nodes / .edges / .stats always present even with no graph
- No graph on ScanResult -> nodes:[], edges:[], stats zeroed
- Graph with one JS node -> serialised with correct fields
- Graph node 'type' field is a string (not an Enum object)
- Graph edge 'type' field is a string (not an Enum object)
- Graph stats total_nodes / total_edges counts match actual nodes/edges
- Graph stats nodes_by_type keyed by strings
- Page node serialised as type "PAGE"
- JS node serialised as type "JS" (not "CHUNK" or "WORKER")
- Worker node serialised as type "WORKER"
- Endpoint node serialised as type "ENDPOINT"
- Secret node serialised as type "SECRET"
- LOADS edge serialised correctly
- EXPOSES edge serialised correctly
- CALLS edge serialised correctly
- Edge deduplication: same edge added twice appears once in JSON
- Node deduplication: same node added twice appears once in JSON
- Full from_scan_result() round-trip serialized into JSON report
- show_sensitive=True / False does not break graph serialisation
- Graph node data dict is serialized (no Enum leak)
- Empty ScanResult with graph -> report still valid JSON
- generate() with graph, no findings, no endpoints -> still has attack_surface_graph
- statistics block unaffected by graph presence
- notice field present in output
- ScanResult with graph=None is identical structurally to no graph
"""

import json
from datetime import datetime

import pytest

from bundlespy.storage.models import (
    ScanResult, JSFile, Finding, Endpoint, InfrastructureItem,
)
from bundlespy.storage.graph import (
    AttackSurfaceGraph, Node, Edge, NodeType, EdgeType, _node_id,
)
from bundlespy.reporting.json_report import generate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _empty_result(with_graph: bool = False) -> ScanResult:
    r = ScanResult(
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
    if with_graph:
        r.graph = AttackSurfaceGraph()
    return r


def _js_file(url: str, page: str = "https://app.example.com/") -> JSFile:
    return JSFile(
        url=url,
        source_page=page,
        status_code=200,
        content_type="application/javascript",
        size_bytes=1000,
        sha256="abc" * 21 + "d",
        content="",
        has_source_map=False,
        technology="React",
        source_type="static",
    )


def _endpoint(url: str, source: str = "https://app.example.com/app.js") -> Endpoint:
    return Endpoint(
        url=url,
        path=url,
        method="GET",
        category="API",
        source_file=source,
        line_number=10,
        confidence=0.9,
    )


def _finding(url: str = "https://app.example.com/app.js") -> Finding:
    matched = "AKIAIOSFODNN7EXAMPLE"
    return Finding(
        id=Finding.make_id("aws-key", matched, url),
        rule_id="aws-key",
        title="AWS Access Key",
        category="credentials",
        severity="CRITICAL",
        confidence=0.95,
        file_url=url,
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
    """Graph: PAGE -LOADS-> JS -CALLS-> ENDPOINT -EXPOSES-> SECRET"""
    g = AttackSurfaceGraph()
    page_id = _node_id("page", "https://app.example.com/")
    js_id   = _node_id("js",   "https://app.example.com/app.js")
    ep_id   = _node_id("endpoint", "https://api.example.com/users", "GET")
    sec_id  = _node_id("finding", "aws-key", "AKIAIOSFODNN7EXAMPLE")

    g.add_node(Node(id=page_id, kind=NodeType.PAGE,     label="/",        data={"url": "https://app.example.com/"}))
    g.add_node(Node(id=js_id,   kind=NodeType.JS,       label="app.js",   data={"url": "https://app.example.com/app.js"}))
    g.add_node(Node(id=ep_id,   kind=NodeType.ENDPOINT, label="GET /users", data={"method": "GET"}))
    g.add_node(Node(id=sec_id,  kind=NodeType.SECRET,   label="aws-key",  data={"severity": "CRITICAL"}))

    g.add_edge(page_id, js_id,  EdgeType.LOADS)
    g.add_edge(js_id,   ep_id,  EdgeType.CALLS)
    g.add_edge(js_id,   sec_id, EdgeType.EXPOSES)
    return g


# ---------------------------------------------------------------------------
# Output is valid JSON
# ---------------------------------------------------------------------------

def test_generate_returns_valid_json():
    """generate() must return parseable JSON."""
    result = _empty_result()
    output = generate(result)
    parsed = json.loads(output)
    assert isinstance(parsed, dict)


def test_generate_with_graph_returns_valid_json():
    """generate() with a graph attached must still return valid JSON."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    output = generate(result)
    parsed = json.loads(output)
    assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# Stable schema: attack_surface_graph always present
# ---------------------------------------------------------------------------

def test_attack_surface_graph_key_always_present_no_graph():
    """attack_surface_graph key is present even when result.graph is None."""
    result = _empty_result()
    result.graph = None
    parsed = json.loads(generate(result))
    assert "attack_surface_graph" in parsed


def test_attack_surface_graph_key_always_present_with_graph():
    """attack_surface_graph key is present when result.graph is set."""
    result = _empty_result(with_graph=True)
    parsed = json.loads(generate(result))
    assert "attack_surface_graph" in parsed


def test_attack_surface_graph_has_nodes_edges_stats():
    """attack_surface_graph always has nodes, edges, stats sub-keys."""
    for with_graph in (True, False):
        result = _empty_result(with_graph=with_graph)
        parsed = json.loads(generate(result))
        asg = parsed["attack_surface_graph"]
        assert "nodes" in asg, "nodes key missing"
        assert "edges" in asg, "edges key missing"
        assert "stats" in asg, "stats key missing"


# ---------------------------------------------------------------------------
# No graph -> zeroed structure
# ---------------------------------------------------------------------------

def test_no_graph_nodes_is_empty_list():
    result = _empty_result()
    result.graph = None
    asg = json.loads(generate(result))["attack_surface_graph"]
    assert asg["nodes"] == []


def test_no_graph_edges_is_empty_list():
    result = _empty_result()
    result.graph = None
    asg = json.loads(generate(result))["attack_surface_graph"]
    assert asg["edges"] == []


def test_no_graph_stats_total_nodes_zero():
    result = _empty_result()
    result.graph = None
    stats = json.loads(generate(result))["attack_surface_graph"]["stats"]
    assert stats["total_nodes"] == 0


def test_no_graph_stats_total_edges_zero():
    result = _empty_result()
    result.graph = None
    stats = json.loads(generate(result))["attack_surface_graph"]["stats"]
    assert stats["total_edges"] == 0


# ---------------------------------------------------------------------------
# Node serialization
# ---------------------------------------------------------------------------

def test_node_type_is_string_not_enum():
    """node.type in JSON must be a plain string, not a Python Enum repr."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    asg = json.loads(generate(result))["attack_surface_graph"]
    for node in asg["nodes"]:
        assert isinstance(node["type"], str), f"node type is not string: {node['type']!r}"
        # Must not look like a Python Enum repr: NodeType.PAGE
        assert "NodeType" not in node["type"]


def test_page_node_type_value():
    """A PAGE node is serialized as type 'PAGE'."""
    g = AttackSurfaceGraph()
    nid = _node_id("page", "https://app.example.com/")
    g.add_node(Node(id=nid, kind=NodeType.PAGE, label="/"))
    result = _empty_result(with_graph=True)
    result.graph = g
    asg = json.loads(generate(result))["attack_surface_graph"]
    types = {n["type"] for n in asg["nodes"]}
    assert "PAGE" in types


def test_js_node_type_value():
    """A JS node is serialized as type 'JS'."""
    g = AttackSurfaceGraph()
    nid = _node_id("js", "https://app.example.com/app.js")
    g.add_node(Node(id=nid, kind=NodeType.JS, label="app.js"))
    result = _empty_result(with_graph=True)
    result.graph = g
    asg = json.loads(generate(result))["attack_surface_graph"]
    types = {n["type"] for n in asg["nodes"]}
    assert "JS" in types


def test_worker_node_type_value():
    """A WORKER node is serialized as type 'WORKER'."""
    g = AttackSurfaceGraph()
    nid = _node_id("worker", "https://app.example.com/sw.js")
    g.add_node(Node(id=nid, kind=NodeType.WORKER, label="sw.js"))
    result = _empty_result(with_graph=True)
    result.graph = g
    asg = json.loads(generate(result))["attack_surface_graph"]
    types = {n["type"] for n in asg["nodes"]}
    assert "WORKER" in types


def test_endpoint_node_type_value():
    """An ENDPOINT node is serialized as type 'ENDPOINT'."""
    g = AttackSurfaceGraph()
    nid = _node_id("endpoint", "/api/users", "GET")
    g.add_node(Node(id=nid, kind=NodeType.ENDPOINT, label="GET /api/users"))
    result = _empty_result(with_graph=True)
    result.graph = g
    asg = json.loads(generate(result))["attack_surface_graph"]
    types = {n["type"] for n in asg["nodes"]}
    assert "ENDPOINT" in types


def test_secret_node_type_value():
    """A SECRET node is serialized as type 'SECRET'."""
    g = AttackSurfaceGraph()
    nid = _node_id("finding", "aws-key", "AKIA...")
    g.add_node(Node(id=nid, kind=NodeType.SECRET, label="aws-key"))
    result = _empty_result(with_graph=True)
    result.graph = g
    asg = json.loads(generate(result))["attack_surface_graph"]
    types = {n["type"] for n in asg["nodes"]}
    assert "SECRET" in types


def test_node_has_id_label_type_fields():
    """Each node dict has at minimum id, label, type."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    asg = json.loads(generate(result))["attack_surface_graph"]
    for node in asg["nodes"]:
        assert "id" in node
        assert "label" in node
        assert "type" in node


def test_node_data_dict_serialized():
    """Node data dict is present and is a dict in JSON output."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    asg = json.loads(generate(result))["attack_surface_graph"]
    for node in asg["nodes"]:
        assert "data" in node
        assert isinstance(node["data"], dict)


# ---------------------------------------------------------------------------
# Edge serialization
# ---------------------------------------------------------------------------

def test_edge_type_is_string_not_enum():
    """edge.type in JSON must be a plain string."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    asg = json.loads(generate(result))["attack_surface_graph"]
    for edge in asg["edges"]:
        assert isinstance(edge["type"], str)
        assert "EdgeType" not in edge["type"]


def test_loads_edge_type_value():
    """LOADS edge is serialized as type 'LOADS'."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    asg = json.loads(generate(result))["attack_surface_graph"]
    edge_types = {e["type"] for e in asg["edges"]}
    assert "LOADS" in edge_types


def test_calls_edge_type_value():
    """CALLS edge is serialized as type 'CALLS'."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    asg = json.loads(generate(result))["attack_surface_graph"]
    edge_types = {e["type"] for e in asg["edges"]}
    assert "CALLS" in edge_types


def test_exposes_edge_type_value():
    """EXPOSES edge is serialized as type 'EXPOSES'."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    asg = json.loads(generate(result))["attack_surface_graph"]
    edge_types = {e["type"] for e in asg["edges"]}
    assert "EXPOSES" in edge_types


def test_edge_has_source_target_type():
    """Each edge dict has source, target, type."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    asg = json.loads(generate(result))["attack_surface_graph"]
    for edge in asg["edges"]:
        assert "source" in edge
        assert "target" in edge
        assert "type" in edge


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_node_deduplication_in_json():
    """Adding the same node twice results in one node entry in JSON."""
    g = AttackSurfaceGraph()
    nid = _node_id("page", "https://app.example.com/")
    n = Node(id=nid, kind=NodeType.PAGE, label="/")
    g.add_node(n)
    g.add_node(n)  # duplicate
    result = _empty_result(with_graph=True)
    result.graph = g
    asg = json.loads(generate(result))["attack_surface_graph"]
    ids = [node["id"] for node in asg["nodes"]]
    assert ids.count(nid) == 1


def test_edge_deduplication_in_json():
    """Adding the same edge twice results in one edge entry in JSON."""
    g = AttackSurfaceGraph()
    pid = _node_id("page", "https://app.example.com/")
    jid = _node_id("js",   "https://app.example.com/app.js")
    g.add_node(Node(id=pid, kind=NodeType.PAGE, label="/"))
    g.add_node(Node(id=jid, kind=NodeType.JS,   label="app.js"))
    g.add_edge(pid, jid, EdgeType.LOADS)
    g.add_edge(pid, jid, EdgeType.LOADS)  # duplicate
    result = _empty_result(with_graph=True)
    result.graph = g
    asg = json.loads(generate(result))["attack_surface_graph"]
    loads_edges = [e for e in asg["edges"] if e["type"] == "LOADS"]
    assert len(loads_edges) == 1


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_stats_total_nodes_matches_actual():
    """stats.total_nodes equals the count of nodes in the nodes array."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    asg = json.loads(generate(result))["attack_surface_graph"]
    assert asg["stats"]["total_nodes"] == len(asg["nodes"])


def test_stats_total_edges_matches_actual():
    """stats.total_edges equals the count of edges in the edges array."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    asg = json.loads(generate(result))["attack_surface_graph"]
    assert asg["stats"]["total_edges"] == len(asg["edges"])


def test_stats_nodes_by_type_keys_are_strings():
    """nodes_by_type keys in stats are plain strings."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    stats = json.loads(generate(result))["attack_surface_graph"]["stats"]
    for k in stats["nodes_by_type"]:
        assert isinstance(k, str)
        assert "NodeType" not in k


# ---------------------------------------------------------------------------
# from_scan_result round-trip
# ---------------------------------------------------------------------------

def test_from_scan_result_round_trip_valid_json():
    """Build graph from real ScanResult, serialize to JSON - must be valid."""
    result = ScanResult(
        target_url="https://app.example.com",
        started_at=datetime(2026, 1, 1),
        finished_at=datetime(2026, 1, 1, 0, 5),
        pages_crawled=2,
        js_files=[_js_file("https://app.example.com/app.js")],
        findings=[_finding()],
        endpoints=[_endpoint("https://api.example.com/users")],
        infrastructure=[],
        errors=[],
    )
    result.graph = AttackSurfaceGraph.from_scan_result(result)
    output = generate(result)
    parsed = json.loads(output)
    assert "attack_surface_graph" in parsed
    asg = parsed["attack_surface_graph"]
    assert len(asg["nodes"]) > 0
    assert asg["stats"]["total_nodes"] == len(asg["nodes"])


def test_from_scan_result_endpoints_become_nodes():
    """Endpoints in ScanResult appear as ENDPOINT nodes in the graph."""
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
    asg = json.loads(generate(result))["attack_surface_graph"]
    types = [n["type"] for n in asg["nodes"]]
    assert "ENDPOINT" in types


def test_from_scan_result_findings_become_secret_nodes():
    """Findings in ScanResult appear as SECRET nodes in the graph."""
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
    asg = json.loads(generate(result))["attack_surface_graph"]
    types = [n["type"] for n in asg["nodes"]]
    assert "SECRET" in types


# ---------------------------------------------------------------------------
# show_sensitive flag does not break graph
# ---------------------------------------------------------------------------

def test_show_sensitive_true_graph_still_valid():
    """show_sensitive=True does not break graph serialization."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    output = generate(result, show_sensitive=True)
    parsed = json.loads(output)
    assert "attack_surface_graph" in parsed


def test_show_sensitive_false_graph_still_valid():
    """show_sensitive=False does not break graph serialization."""
    result = _empty_result(with_graph=True)
    result.graph = _simple_graph()
    output = generate(result, show_sensitive=False)
    parsed = json.loads(output)
    assert "attack_surface_graph" in parsed


# ---------------------------------------------------------------------------
# Statistics block unaffected by graph
# ---------------------------------------------------------------------------

def test_statistics_block_unchanged_with_graph():
    """Presence of graph does not alter the statistics block counts."""
    result = ScanResult(
        target_url="https://app.example.com",
        started_at=datetime(2026, 1, 1),
        finished_at=None,
        pages_crawled=3,
        js_files=[_js_file("https://app.example.com/app.js")],
        findings=[_finding()],
        endpoints=[_endpoint("https://api.example.com/users")],
        infrastructure=[],
        errors=[],
    )
    result.graph = _simple_graph()
    parsed = json.loads(generate(result))
    assert parsed["statistics"]["js_files"]  == 1
    assert parsed["statistics"]["findings"]  == 1
    assert parsed["statistics"]["endpoints"] == 1


# ---------------------------------------------------------------------------
# Notice field
# ---------------------------------------------------------------------------

def test_notice_field_present():
    """notice field must always appear in JSON output."""
    result = _empty_result()
    parsed = json.loads(generate(result))
    assert "notice" in parsed
    assert "No credentials were validated" in parsed["notice"]
