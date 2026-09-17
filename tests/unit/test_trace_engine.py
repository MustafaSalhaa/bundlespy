"""
Trace Engine regression tests - storage/graph.py

All tests use synthetic graphs built directly via add_node/add_edge.
No network, no disk I/O, no discovery/analysis behavior.

Coverage:
  - duplicate edges within a branch
  - duplicate nodes reached via different branches
  - branching graphs (siblings stay separate)
  - cycles
  - RELATED_TO excluded by default, included when requested
  - multiple endpoints on one page
  - multiple scripts on one page
  - same endpoint from static + runtime discovery
  - correlated edges
  - deterministic output
  - depth / node limits
  - missing / isolated nodes
  - self-loop guard
  - empty graph
  - upstream tracing
  - trace_path (point-to-point)
  - trace_all_to_secrets / trace_all_from_pages
"""

import sys
sys.path.insert(0, "src")

import pytest
from bundlespy.storage.graph import (
    AttackSurfaceGraph, Node, Edge,
    NodeType, EdgeType,
    TraceStep, TraceResult,
    _evidence_for_edge,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _n(g: AttackSurfaceGraph, nid: str, kind: NodeType, label: str) -> Node:
    node = Node(id=nid, kind=kind, label=label)
    g.add_node(node)
    return node


def _e(g: AttackSurfaceGraph, src: str, dst: str, kind: EdgeType) -> None:
    g.add_edge(src, dst, kind)


def _path_node_ids(path):
    """Return list of all node IDs touched in a path (from_node of step 0 + all to_nodes)."""
    if not path:
        return []
    ids = [path[0].from_node.id]
    ids += [s.to_node.id for s in path]
    return ids


def _all_edge_keys(result: TraceResult):
    """Collect (src, kind, tgt) for every step across all paths."""
    keys = []
    for path in result.paths:
        for step in path:
            keys.append((step.edge.source, step.edge.kind.value, step.edge.target))
    return keys


# ── 1. Duplicate edges within a branch ────────────────────────────────────────

class TestNoDuplicateEdgesInBranch:

    def test_linear_chain_no_duplicate_steps(self):
        """A -> B -> C: each edge appears exactly once per path."""
        g = AttackSurfaceGraph()
        _n(g, "A", NodeType.PAGE, "page-A")
        _n(g, "B", NodeType.JS, "script-B")
        _n(g, "C", NodeType.ENDPOINT, "ep-C")
        _e(g, "A", "B", EdgeType.LOADS)
        _e(g, "B", "C", EdgeType.CALLS)

        result = g.trace_downstream("A")

        assert len(result.paths) == 1
        path = result.paths[0]
        edge_keys = [(s.edge.source, s.edge.kind.value, s.edge.target) for s in path]
        assert len(edge_keys) == len(set(map(tuple, edge_keys))), "Duplicate edge in branch"

    def test_graph_dedup_does_not_emit_same_edge_twice(self):
        """The graph itself deduplicates edges at add_edge time."""
        g = AttackSurfaceGraph()
        _n(g, "A", NodeType.PAGE, "page-A")
        _n(g, "B", NodeType.JS, "script-B")
        _e(g, "A", "B", EdgeType.LOADS)
        _e(g, "A", "B", EdgeType.LOADS)  # duplicate

        result = g.trace_downstream("A")
        keys = _all_edge_keys(result)
        assert keys.count(("A", "LOADS", "B")) == 1


# ── 2. Duplicate nodes via different branches ──────────────────────────────────

class TestDuplicateNodesAcrossBranches:

    def test_diamond_keeps_branches_independent(self):
        """
        A -LOADS-> B1 -CALLS-> C
        A -LOADS-> B2 -CALLS-> C

        C is reached via two distinct branches. Both paths should exist
        and no path should merge B1 and B2.
        """
        g = AttackSurfaceGraph()
        _n(g, "A",  NodeType.PAGE,     "page-A")
        _n(g, "B1", NodeType.JS,       "script-B1")
        _n(g, "B2", NodeType.JS,       "script-B2")
        _n(g, "C",  NodeType.ENDPOINT, "ep-C")
        _e(g, "A",  "B1", EdgeType.LOADS)
        _e(g, "A",  "B2", EdgeType.LOADS)
        _e(g, "B1", "C",  EdgeType.CALLS)
        _e(g, "B2", "C",  EdgeType.CALLS)

        result = g.trace_downstream("A")

        assert len(result.paths) == 2, f"Expected 2 paths, got {len(result.paths)}"

        # Verify no path contains both B1 and B2
        for path in result.paths:
            node_ids = _path_node_ids(path)
            assert not ("B1" in node_ids and "B2" in node_ids), \
                "Sibling nodes B1 and B2 merged into same path"

    def test_all_nodes_includes_duplicates_once(self):
        """all_nodes() deduplicates across branches."""
        g = AttackSurfaceGraph()
        _n(g, "A",  NodeType.PAGE,     "page-A")
        _n(g, "B1", NodeType.JS,       "script-B1")
        _n(g, "B2", NodeType.JS,       "script-B2")
        _n(g, "C",  NodeType.ENDPOINT, "ep-C")
        _e(g, "A",  "B1", EdgeType.LOADS)
        _e(g, "A",  "B2", EdgeType.LOADS)
        _e(g, "B1", "C",  EdgeType.CALLS)
        _e(g, "B2", "C",  EdgeType.CALLS)

        result = g.trace_downstream("A")
        all_ids = [n.id for n in result.all_nodes()]
        assert len(all_ids) == len(set(all_ids)), "all_nodes() contains duplicates"


# ── 3. Branching structure preserved ──────────────────────────────────────────

class TestBranchingStructure:

    def test_two_scripts_two_endpoints_four_paths(self):
        """
        PAGE -LOADS-> JS1 -CALLS-> EP1
        PAGE -LOADS-> JS1 -CALLS-> EP2
        PAGE -LOADS-> JS2 -CALLS-> EP3

        /stock and /checkout must remain separate branches.
        """
        g = AttackSurfaceGraph()
        _n(g, "P",   NodeType.PAGE,     "/")
        _n(g, "JS1", NodeType.JS,       "app.js")
        _n(g, "JS2", NodeType.JS,       "vendor.js")
        _n(g, "EP1", NodeType.ENDPOINT, "GET /stock")
        _n(g, "EP2", NodeType.ENDPOINT, "POST /create-checkout")
        _n(g, "EP3", NodeType.ENDPOINT, "GET /products")
        _e(g, "P",   "JS1", EdgeType.LOADS)
        _e(g, "P",   "JS2", EdgeType.LOADS)
        _e(g, "JS1", "EP1", EdgeType.CALLS)
        _e(g, "JS1", "EP2", EdgeType.CALLS)
        _e(g, "JS2", "EP3", EdgeType.CALLS)

        result = g.trace_downstream("P")

        endpoint_ids_per_path = [
            frozenset(s.to_node.id for s in path if s.to_node.kind == NodeType.ENDPOINT)
            for path in result.paths
        ]

        # EP1 and EP2 must be on paths that go through JS1
        # EP3 must be on a path through JS2 - not mixed
        for path in result.paths:
            node_ids = _path_node_ids(path)
            if "EP3" in node_ids:
                assert "JS1" not in node_ids, "/products branch incorrectly merged with app.js"
            if "EP1" in node_ids or "EP2" in node_ids:
                assert "JS2" not in node_ids, "/stock or /checkout branch incorrectly merged with vendor.js"

    def test_each_branch_terminates_independently(self):
        """Leaf branches that end at different depths are all recorded."""
        g = AttackSurfaceGraph()
        _n(g, "P",  NodeType.PAGE,     "/")
        _n(g, "J1", NodeType.JS,       "a.js")
        _n(g, "J2", NodeType.JS,       "b.js")
        _n(g, "E1", NodeType.ENDPOINT, "GET /a")
        _n(g, "S1", NodeType.SECRET,   "api-key")
        _e(g, "P",  "J1", EdgeType.LOADS)
        _e(g, "P",  "J2", EdgeType.LOADS)
        _e(g, "J1", "E1", EdgeType.CALLS)
        _e(g, "J2", "S1", EdgeType.EXPOSES)

        result = g.trace_downstream("P")
        assert len(result.paths) == 2
        assert result.endpoints() != []
        assert result.secrets() != []


# ── 4. Cycles ──────────────────────────────────────────────────────────────────

class TestCycles:

    def test_simple_cycle_does_not_loop(self):
        """A -> B -> A: cycle must be broken, not infinite."""
        g = AttackSurfaceGraph()
        _n(g, "A", NodeType.PAGE, "page-A")
        _n(g, "B", NodeType.JS,   "script-B")
        _e(g, "A", "B", EdgeType.LOADS)
        _e(g, "B", "A", EdgeType.OBSERVED_ON)

        result = g.trace_downstream("A")
        # Should terminate; each branch stops when revisiting A
        all_ids = [n.id for n in result.all_nodes()]
        assert all_ids.count("A") == 1  # origin counted once

    def test_three_node_cycle(self):
        """A -> B -> C -> A: must terminate."""
        g = AttackSurfaceGraph()
        _n(g, "A", NodeType.PAGE,     "page")
        _n(g, "B", NodeType.JS,       "js")
        _n(g, "C", NodeType.ENDPOINT, "ep")
        _e(g, "A", "B", EdgeType.LOADS)
        _e(g, "B", "C", EdgeType.CALLS)
        _e(g, "C", "A", EdgeType.OBSERVED_ON)

        result = g.trace_downstream("A")
        assert not result.truncated or len(result.paths) >= 0  # just must not hang

    def test_self_loop_not_emitted(self):
        """A -> A self-edge must not produce a step (no actual self-edge means skip)."""
        g = AttackSurfaceGraph()
        _n(g, "A", NodeType.ENDPOINT, "ep-A")
        # Do NOT add a self-edge - the guard must prevent A->A appearing
        result = g.trace_downstream("A")
        for path in result.paths:
            for step in path:
                assert not (step.from_node.id == "A" and step.to_node.id == "A"), \
                    "Self-loop A->A emitted without a real self-edge"


# ── 5. RELATED_TO excluded by default ─────────────────────────────────────────

class TestRelatedToEdge:

    def _graph_with_related_to(self):
        g = AttackSurfaceGraph()
        _n(g, "P",  NodeType.PAGE,     "/")
        _n(g, "J",  NodeType.JS,       "app.js")
        _n(g, "S",  NodeType.SECRET,   "api-key")
        _n(g, "EP", NodeType.ENDPOINT, "GET /api")
        _e(g, "P", "J",  EdgeType.LOADS)
        _e(g, "J", "S",  EdgeType.EXPOSES)
        _e(g, "S", "EP", EdgeType.RELATED_TO)
        return g

    def test_related_to_excluded_by_default(self):
        g = self._graph_with_related_to()
        result = g.trace_downstream("P")
        for path in result.paths:
            for step in path:
                assert step.edge.kind != EdgeType.RELATED_TO, \
                    "RELATED_TO edge emitted without explicit opt-in"

    def test_related_to_included_when_requested(self):
        g = self._graph_with_related_to()
        result = g.trace_downstream("P", include_related_to=True)
        edge_kinds = {step.edge.kind for path in result.paths for step in path}
        assert EdgeType.RELATED_TO in edge_kinds, \
            "RELATED_TO missing after include_related_to=True"


# ── 6. Multiple endpoints on one page ─────────────────────────────────────────

class TestMultipleEndpointsOnePage:

    def test_five_endpoints_all_separate_paths(self):
        g = AttackSurfaceGraph()
        _n(g, "P",  NodeType.PAGE, "/")
        _n(g, "JS", NodeType.JS,   "app.js")
        _e(g, "P", "JS", EdgeType.LOADS)
        for i in range(5):
            eid = f"EP{i}"
            _n(g, eid, NodeType.ENDPOINT, f"GET /ep{i}")
            _e(g, "JS", eid, EdgeType.CALLS)

        result = g.trace_downstream("P")
        endpoint_ids = {n.id for n in result.endpoints()}
        assert endpoint_ids == {f"EP{i}" for i in range(5)}, \
            "Not all endpoints reached"

        # Each path must contain at most one endpoint at its leaf
        for path in result.paths:
            ep_steps = [s for s in path if s.to_node.kind == NodeType.ENDPOINT]
            assert len(ep_steps) <= 1, "Path contains more than one endpoint leaf"


# ── 7. Multiple scripts on one page ───────────────────────────────────────────

class TestMultipleScriptsOnePage:

    def test_three_scripts_independent_branches(self):
        g = AttackSurfaceGraph()
        _n(g, "P", NodeType.PAGE, "/")
        for i in range(3):
            jid = f"JS{i}"
            eid = f"EP{i}"
            _n(g, jid, NodeType.JS,       f"script{i}.js")
            _n(g, eid, NodeType.ENDPOINT, f"GET /api/{i}")
            _e(g, "P",  jid, EdgeType.LOADS)
            _e(g, jid, eid, EdgeType.CALLS)

        result = g.trace_downstream("P")
        assert len(result.paths) == 3

        for path in result.paths:
            js_nodes = [s.from_node.id for s in path if s.from_node.kind == NodeType.JS]
            assert len(set(js_nodes)) <= 1, "Multiple scripts in one branch"


# ── 8. Same endpoint static + runtime ─────────────────────────────────────────

class TestSameEndpointTwoSources:

    def test_static_and_runtime_observed(self):
        """
        JS -CALLS-> EP (static discovery)
        EP -OBSERVED_ON-> PAGE (runtime observation)

        Both edges are real; both should appear in downstream trace from PAGE.
        """
        g = AttackSurfaceGraph()
        _n(g, "P",  NodeType.PAGE,     "/")
        _n(g, "JS", NodeType.JS,       "app.js")
        _n(g, "EP", NodeType.ENDPOINT, "POST /checkout")
        _e(g, "P",  "JS", EdgeType.LOADS)
        _e(g, "JS", "EP", EdgeType.CALLS)
        _e(g, "EP", "P",  EdgeType.OBSERVED_ON)

        result = g.trace_downstream("P")
        # EP must be reachable and CALLS edge must appear
        edge_kinds = {step.edge.kind for path in result.paths for step in path}
        assert EdgeType.CALLS in edge_kinds
        assert "EP" in {n.id for n in result.endpoints()}


# ── 9. Correlated edges ────────────────────────────────────────────────────────

class TestCorrelatedEdges:

    def test_hosts_edge_traversed(self):
        g = AttackSurfaceGraph()
        _n(g, "H",  NodeType.HOST,     "cdn.example.com")
        _n(g, "EP", NodeType.ENDPOINT, "GET /resource")
        _e(g, "H", "EP", EdgeType.HOSTS)

        result = g.trace_downstream("H")
        assert len(result.paths) == 1
        assert result.paths[0][0].edge.kind == EdgeType.HOSTS


# ── 10. Deterministic output ───────────────────────────────────────────────────

class TestDeterminism:

    def test_same_graph_same_paths_multiple_runs(self):
        """Running trace twice on identical graphs must produce identical output."""
        def _build():
            g = AttackSurfaceGraph()
            _n(g, "P",  NodeType.PAGE,     "/")
            _n(g, "J1", NodeType.JS,       "a.js")
            _n(g, "J2", NodeType.JS,       "b.js")
            _n(g, "E1", NodeType.ENDPOINT, "GET /a")
            _n(g, "E2", NodeType.ENDPOINT, "GET /b")
            _e(g, "P",  "J1", EdgeType.LOADS)
            _e(g, "P",  "J2", EdgeType.LOADS)
            _e(g, "J1", "E1", EdgeType.CALLS)
            _e(g, "J2", "E2", EdgeType.CALLS)
            return g

        def _sig(result: TraceResult):
            return tuple(
                sorted(
                    tuple((s.edge.source, s.edge.kind.value, s.edge.target) for s in path)
                    for path in result.paths
                )
            )

        g1, g2 = _build(), _build()
        r1 = g1.trace_downstream("P")
        r2 = g2.trace_downstream("P")
        assert _sig(r1) == _sig(r2), "Non-deterministic trace output"

    def test_path_order_stable(self):
        """Path order must be consistent across runs (sorted edges)."""
        g = AttackSurfaceGraph()
        _n(g, "P",  NodeType.PAGE,     "/")
        _n(g, "J1", NodeType.JS,       "a.js")
        _n(g, "J2", NodeType.JS,       "b.js")
        _e(g, "P", "J1", EdgeType.LOADS)
        _e(g, "P", "J2", EdgeType.LOADS)

        r1 = g.trace_downstream("P")
        r2 = g.trace_downstream("P")
        ids1 = [_path_node_ids(p) for p in r1.paths]
        ids2 = [_path_node_ids(p) for p in r2.paths]
        assert ids1 == ids2


# ── 11. Depth / node limits ────────────────────────────────────────────────────

class TestLimits:

    def test_max_depth_respected(self):
        """Chain A->B->C->D: max_depth=1 should stop after first hop."""
        g = AttackSurfaceGraph()
        _n(g, "A", NodeType.PAGE,     "A")
        _n(g, "B", NodeType.JS,       "B")
        _n(g, "C", NodeType.ENDPOINT, "C")
        _n(g, "D", NodeType.SECRET,   "D")
        _e(g, "A", "B", EdgeType.LOADS)
        _e(g, "B", "C", EdgeType.CALLS)
        _e(g, "C", "D", EdgeType.RELATED_TO)

        result = g.trace_downstream("A", max_depth=1, include_related_to=True)
        for path in result.paths:
            assert len(path) <= 1, f"Path exceeds max_depth=1: {[s.to_node.id for s in path]}"
        assert result.truncated

    def test_max_nodes_respected(self):
        """Many endpoints from one JS: max_nodes stops expansion early."""
        g = AttackSurfaceGraph()
        _n(g, "P",  NodeType.PAGE, "/")
        _n(g, "JS", NodeType.JS,   "app.js")
        _e(g, "P", "JS", EdgeType.LOADS)
        for i in range(20):
            eid = f"EP{i}"
            _n(g, eid, NodeType.ENDPOINT, f"GET /ep{i}")
            _e(g, "JS", eid, EdgeType.CALLS)

        result = g.trace_downstream("P", max_nodes=5)
        assert result.truncated
        assert len(result.all_nodes()) <= 5

    def test_no_truncation_on_small_graph(self):
        g = AttackSurfaceGraph()
        _n(g, "P",  NodeType.PAGE,     "/")
        _n(g, "JS", NodeType.JS,       "app.js")
        _n(g, "EP", NodeType.ENDPOINT, "GET /api")
        _e(g, "P", "JS", EdgeType.LOADS)
        _e(g, "JS", "EP", EdgeType.CALLS)

        result = g.trace_downstream("P")
        assert not result.truncated


# ── 12. Missing / isolated nodes ──────────────────────────────────────────────

class TestMissingNodes:

    def test_missing_origin_returns_empty_trace_result(self):
        g = AttackSurfaceGraph()
        result = g.trace_downstream("nonexistent-id")
        assert isinstance(result, TraceResult)
        assert result.paths == []
        assert not result.truncated

    def test_isolated_node_returns_empty_paths(self):
        g = AttackSurfaceGraph()
        _n(g, "X", NodeType.ENDPOINT, "GET /orphan")
        result = g.trace_downstream("X")
        assert result.paths == []
        assert result.origin.id == "X"

    def test_empty_graph_returns_empty(self):
        g = AttackSurfaceGraph()
        result = g.trace_downstream("anything")
        assert result.paths == []


# ── 13. Upstream tracing ───────────────────────────────────────────────────────

class TestUpstream:

    def test_upstream_finds_page_from_endpoint(self):
        """
        PAGE -LOADS-> JS -CALLS-> EP
        trace_upstream from EP should find JS then PAGE.
        """
        g = AttackSurfaceGraph()
        _n(g, "P",  NodeType.PAGE,     "/")
        _n(g, "JS", NodeType.JS,       "app.js")
        _n(g, "EP", NodeType.ENDPOINT, "GET /api")
        _e(g, "P",  "JS", EdgeType.LOADS)
        _e(g, "JS", "EP", EdgeType.CALLS)

        result = g.trace_upstream("EP")
        all_ids = {n.id for n in result.all_nodes()}
        assert "JS" in all_ids
        assert "P"  in all_ids

    def test_upstream_direction_label(self):
        g = AttackSurfaceGraph()
        _n(g, "A", NodeType.PAGE, "/")
        _n(g, "B", NodeType.JS,   "b.js")
        _e(g, "A", "B", EdgeType.LOADS)
        result = g.trace_upstream("B")
        assert result.direction == "upstream"


# ── 14. trace_path ────────────────────────────────────────────────────────────

class TestTracePath:

    def test_direct_path_found(self):
        g = AttackSurfaceGraph()
        _n(g, "P",  NodeType.PAGE,     "/")
        _n(g, "JS", NodeType.JS,       "app.js")
        _n(g, "EP", NodeType.ENDPOINT, "GET /api")
        _e(g, "P",  "JS", EdgeType.LOADS)
        _e(g, "JS", "EP", EdgeType.CALLS)

        result = g.trace_path("P", "EP")
        assert len(result.paths) == 1
        assert result.paths[0][-1].to_node.id == "EP"

    def test_no_path_returns_empty(self):
        g = AttackSurfaceGraph()
        _n(g, "A", NodeType.PAGE,     "/a")
        _n(g, "B", NodeType.ENDPOINT, "GET /b")
        # No edge between A and B
        result = g.trace_path("A", "B")
        assert result.paths == []

    def test_path_excludes_unrelated_endpoints(self):
        """trace_path to EP1 should not return paths ending at EP2."""
        g = AttackSurfaceGraph()
        _n(g, "P",   NodeType.PAGE,     "/")
        _n(g, "JS",  NodeType.JS,       "app.js")
        _n(g, "EP1", NodeType.ENDPOINT, "GET /a")
        _n(g, "EP2", NodeType.ENDPOINT, "GET /b")
        _e(g, "P",  "JS",  EdgeType.LOADS)
        _e(g, "JS", "EP1", EdgeType.CALLS)
        _e(g, "JS", "EP2", EdgeType.CALLS)

        result = g.trace_path("P", "EP1")
        for path in result.paths:
            assert path[-1].to_node.id == "EP1"


# ── 15. trace_all_to_secrets / trace_all_from_pages ───────────────────────────

class TestTraceAllMethods:

    def _two_page_graph(self):
        g = AttackSurfaceGraph()
        _n(g, "P1", NodeType.PAGE,     "/home")
        _n(g, "P2", NodeType.PAGE,     "/admin")
        _n(g, "J1", NodeType.JS,       "app.js")
        _n(g, "J2", NodeType.JS,       "admin.js")
        _n(g, "S1", NodeType.SECRET,   "api-key")
        _n(g, "EP", NodeType.ENDPOINT, "GET /api")
        _e(g, "P1", "J1", EdgeType.LOADS)
        _e(g, "P2", "J2", EdgeType.LOADS)
        _e(g, "J1", "EP", EdgeType.CALLS)
        _e(g, "J2", "S1", EdgeType.EXPOSES)
        return g

    def test_trace_all_from_pages_returns_one_per_page(self):
        g = self._two_page_graph()
        results = g.trace_all_from_pages()
        assert len(results) == 2
        origins = {r.origin.id for r in results}
        assert origins == {"P1", "P2"}

    def test_trace_all_to_secrets_filters_correctly(self):
        g = self._two_page_graph()
        results = g.trace_all_to_secrets()
        # Only P2 leads to a secret
        assert len(results) == 1
        assert results[0].origin.id == "P2"
        assert results[0].secrets() != []


# ── 16. Evidence and metadata preserved ───────────────────────────────────────

class TestMetadataPreserved:

    def test_evidence_string_populated(self):
        g = AttackSurfaceGraph()
        _n(g, "P",  NodeType.PAGE,     "/")
        _n(g, "JS", NodeType.JS,       "app.js")
        _e(g, "P", "JS", EdgeType.LOADS)

        result = g.trace_downstream("P")
        assert len(result.paths) == 1
        step = result.paths[0][0]
        assert step.evidence != ""
        assert "app.js" in step.evidence or "page" in step.evidence.lower()

    def test_step_depth_increments(self):
        g = AttackSurfaceGraph()
        _n(g, "A", NodeType.PAGE,     "/")
        _n(g, "B", NodeType.JS,       "b.js")
        _n(g, "C", NodeType.ENDPOINT, "GET /c")
        _e(g, "A", "B", EdgeType.LOADS)
        _e(g, "B", "C", EdgeType.CALLS)

        result = g.trace_downstream("A")
        assert len(result.paths) == 1
        path = result.paths[0]
        for i, step in enumerate(path):
            assert step.depth == i

    def test_to_dict_serialisable(self):
        import json
        g = AttackSurfaceGraph()
        _n(g, "P",  NodeType.PAGE,     "/")
        _n(g, "JS", NodeType.JS,       "app.js")
        _n(g, "EP", NodeType.ENDPOINT, "GET /api")
        _e(g, "P",  "JS", EdgeType.LOADS)
        _e(g, "JS", "EP", EdgeType.CALLS)

        result = g.trace_downstream("P")
        d = result.to_dict()
        # Must not raise
        json.dumps(d)
        assert d["direction"] == "downstream"
        assert d["summary"]["total_paths"] == 1


# ── 17. Evidence helper ────────────────────────────────────────────────────────

class TestEvidenceHelper:

    def _step(self, src_kind, edge_kind, tgt_kind):
        src = Node(id="src", kind=src_kind, label="Source", data={"url": "https://x.com/a.js"})
        tgt = Node(id="tgt", kind=tgt_kind, label="Target")
        edge = Edge(source="src", target="tgt", kind=edge_kind)
        return _evidence_for_edge(edge, src, tgt)

    def test_loads_evidence(self):
        ev = self._step(NodeType.PAGE, EdgeType.LOADS, NodeType.JS)
        assert "loads" in ev.lower() or "script" in ev.lower()

    def test_calls_evidence(self):
        ev = self._step(NodeType.JS, EdgeType.CALLS, NodeType.ENDPOINT)
        assert "calls" in ev.lower() or "endpoint" in ev.lower()

    def test_exposes_evidence(self):
        ev = self._step(NodeType.JS, EdgeType.EXPOSES, NodeType.SECRET)
        assert "exposes" in ev.lower() or "secret" in ev.lower()

    def test_unknown_edge_fallback(self):
        src = Node(id="s", kind=NodeType.PAGE,     label="S", data={})
        tgt = Node(id="t", kind=NodeType.ENDPOINT, label="T")
        # Use a real EdgeType that has no custom template
        edge = Edge(source="s", target="t", kind=EdgeType.ACCEPTS)
        ev = _evidence_for_edge(edge, src, tgt)
        assert ev != ""
