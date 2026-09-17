"""
BundleSpy Attack Surface Graph
===============================================================================

The graph is the intelligence layer that sits on top of the flat lists in
ScanResult. It connects every discovered entity - pages, JS files, endpoints,
secrets, workers, parameters - into a traversable relationship model.

Design principles:
  - Zero breaking changes: existing fields on JSFile/Finding/Endpoint/ScanResult
    are untouched. The graph is additive.
  - Built once after the scan completes, in O(n) time.
  - Every node has a stable string ID.
  - Relationships are directional and typed.
  - The graph is serialisable to JSON for the HTML report.

Node types:
  PAGE        - a crawled or discovered HTML page
  JS          - a JavaScript asset (static, browser-captured, inline, chunk)
  ENDPOINT    - an API / WebSocket / GraphQL / route endpoint
  SECRET      - a confirmed finding
  WORKER      - a Web Worker or Service Worker
  PARAMETER   - a path or query parameter on an endpoint
  HOST        - an external hostname or IP
  CHUNK       - a dynamically loaded JS chunk
  SOURCEMAP   - a recovered source map
  CONFIG      - a configuration entry (API base URL, etc.)

Relationship types:
  LOADS           PAGE      -> JS
  IMPORTS         JS        -> JS (chunk / worker)
  CALLS           JS        -> ENDPOINT
  EXPOSES         JS        -> SECRET
  ACCEPTS         ENDPOINT  -> PARAMETER
  OBSERVED_ON     ENDPOINT  -> PAGE
  RELATED_TO      SECRET    -> ENDPOINT
  HOSTS           HOST      -> ENDPOINT
  REFERENCES      PAGE      -> PAGE (navigation / redirect)
  RECOVERS        JS        -> SOURCEMAP

Trace Engine (P1):
  trace_upstream(node_id)    - what leads to this node? (reverse BFS)
  trace_downstream(node_id)  - what does this node lead to? (forward BFS)
  trace_path(src, dst)       - shortest path between two nodes (BFS)

  All trace functions return a TraceResult with structured TraceStep entries.
  Each step includes: from_node, edge, to_node, evidence snippet.
"""

from __future__ import annotations

import hashlib
import re
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse

from .models import JSFile, Finding, Endpoint, InfrastructureItem, ScanResult


# -- Node / Edge types ---------------------------------------------------------

class NodeType(str, Enum):
    PAGE       = "PAGE"
    JS         = "JS"
    ENDPOINT   = "ENDPOINT"
    SECRET     = "SECRET"
    WORKER     = "WORKER"
    PARAMETER  = "PARAMETER"
    HOST       = "HOST"
    CHUNK      = "CHUNK"
    SOURCEMAP  = "SOURCEMAP"
    CONFIG     = "CONFIG"


class EdgeType(str, Enum):
    LOADS       = "LOADS"       # PAGE      -> JS
    IMPORTS     = "IMPORTS"     # JS        -> JS
    CALLS       = "CALLS"       # JS        -> ENDPOINT
    EXPOSES     = "EXPOSES"     # JS        -> SECRET
    ACCEPTS     = "ACCEPTS"     # ENDPOINT  -> PARAMETER
    OBSERVED_ON = "OBSERVED_ON" # ENDPOINT  -> PAGE
    RELATED_TO  = "RELATED_TO"  # SECRET    -> ENDPOINT
    HOSTS       = "HOSTS"       # HOST      -> ENDPOINT
    REFERENCES  = "REFERENCES"  # PAGE      -> PAGE
    RECOVERS    = "RECOVERS"    # JS        -> SOURCEMAP


# -- Core node -----------------------------------------------------------------

@dataclass
class Node:
    """
    A node in the attack surface graph.

    id          - stable hash-based identifier
    kind        - NodeType enum value
    label       - short human-readable name (URL path, file name, etc.)
    data        - arbitrary metadata dict (serialisable to JSON)
    confidence  - 0.0-1.0 where applicable
    """
    id:         str
    kind:       NodeType
    label:      str
    data:       Dict[str, Any] = field(default_factory=dict)
    confidence: float          = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":         self.id,
            "kind":       self.kind.value,
            "label":      self.label,
            "data":       self.data,
            "confidence": round(self.confidence, 3),
        }


# -- Core edge -----------------------------------------------------------------

@dataclass
class Edge:
    """
    A directed relationship between two nodes.

    source      - source node id
    target      - target node id
    kind        - EdgeType enum value
    label       - optional human-readable qualifier
    data        - arbitrary metadata dict
    """
    source: str
    target: str
    kind:   EdgeType
    label:  str           = ""
    data:   Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind":   self.kind.value,
            "label":  self.label,
            "data":   self.data,
        }


# -- Trace Engine types --------------------------------------------------------

@dataclass
class TraceStep:
    """
    A single hop in a trace result.

    from_node  - the node we're coming from (None at the start anchor)
    edge       - the relationship traversed (None at the start anchor)
    to_node    - the node we're arriving at
    evidence   - a human-readable description of why this hop exists
    depth      - how many hops from the trace origin
    """
    from_node: Optional[Node]
    edge:      Optional[Edge]
    to_node:   Node
    evidence:  str = ""
    depth:     int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_node": self.from_node.to_dict() if self.from_node else None,
            "edge":      self.edge.to_dict()      if self.edge      else None,
            "to_node":   self.to_node.to_dict(),
            "evidence":  self.evidence,
            "depth":     self.depth,
        }


@dataclass
class TraceResult:
    """
    The result of a graph trace operation.

    origin      - the node the trace started from
    direction   - 'upstream', 'downstream', or 'path'
    steps       - ordered list of TraceStep entries
    paths       - grouped list-of-lists for multi-path results
    truncated   - True if the result was cut short (graph too large)
    """
    origin:     Node
    direction:  str
    steps:      List[TraceStep]      = field(default_factory=list)
    paths:      List[List[TraceStep]] = field(default_factory=list)
    truncated:  bool                 = False

    # -- Convenience accessors -------------------------------------------------

    def all_nodes(self) -> List[Node]:
        """All unique nodes that appear in the trace (origin + all to_nodes)."""
        seen: Set[str] = set()
        result: List[Node] = [self.origin]
        seen.add(self.origin.id)
        for step in self.steps:
            if step.to_node.id not in seen:
                result.append(step.to_node)
                seen.add(step.to_node.id)
        return result

    def secrets(self) -> List[Node]:
        """All SECRET nodes discovered during this trace."""
        return [n for n in self.all_nodes() if n.kind == NodeType.SECRET]

    def endpoints(self) -> List[Node]:
        """All ENDPOINT nodes discovered during this trace."""
        return [n for n in self.all_nodes() if n.kind == NodeType.ENDPOINT]

    def chain_label(self) -> str:
        """
        Produce a single-line chain description.
        Example: /admin -> admin.js -> GET /api/admin/users -> API_KEY
        """
        parts: List[str] = [self.origin.label]
        for step in self.steps:
            parts.append(step.to_node.label)
        return " -> ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "origin":    self.origin.to_dict(),
            "direction": self.direction,
            "steps":     [s.to_dict() for s in self.steps],
            "paths":     [[s.to_dict() for s in p] for p in self.paths],
            "truncated": self.truncated,
            "chain":     self.chain_label(),
        }


# -- ID helpers ----------------------------------------------------------------

def _node_id(*parts: str) -> str:
    """Deterministic 16-character node ID from one or more string parts."""
    raw = ":".join(p.lower().strip() for p in parts if p)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _page_label(url: str) -> str:
    """Return the path + query of a URL as a short label."""
    try:
        p = urlparse(url)
        label = p.path or "/"
        if p.query:
            label += "?" + p.query[:40]
        return label.rstrip("/") or "/"
    except Exception:
        return url


def _js_label(url: str) -> str:
    """Return the file name portion of a JS URL."""
    if url.startswith("inline:"):
        page = url.replace("inline:", "").split("#")[0]
        fragment = url.split("#")[-1] if "#" in url else ""
        num = re.search(r"script-(\d+)", fragment)
        n = num.group(1) if num else "?"
        return f"inline script {n} @ {_page_label(page)}"
    try:
        path = urlparse(url).path
        return path.split("/")[-1] or path or url
    except Exception:
        return url


def _endpoint_label(ep: Endpoint) -> str:
    """Short label: METHOD /path"""
    method = ep.method if ep.method not in ("UNKNOWN", "") else "?"
    path   = urlparse(ep.url).path if ep.url.startswith("http") else ep.url
    return f"{method} {path}"


def _evidence_for_edge(edge: Edge, from_node: Node, to_node: Node) -> str:
    """
    Generate a human-readable evidence snippet for a graph hop.
    Used in Trace Engine output.
    """
    kind = edge.kind

    if kind == EdgeType.LOADS:
        return f"Page '{from_node.label}' loads JavaScript asset '{to_node.label}'"

    if kind == EdgeType.IMPORTS:
        return f"'{from_node.label}' dynamically imports '{to_node.label}'"

    if kind == EdgeType.CALLS:
        src_file = to_node.data.get("source_file", "")
        line     = to_node.data.get("line_number", "")
        loc      = f" (line {line})" if line else ""
        return f"'{from_node.label}' contains a call to endpoint '{to_node.label}'{loc}"

    if kind == EdgeType.EXPOSES:
        sev = to_node.data.get("severity", "")
        cat = to_node.data.get("category", "")
        return f"'{from_node.label}' exposes {sev} {cat} finding: '{to_node.label}'"

    if kind == EdgeType.ACCEPTS:
        param_kind = edge.label or to_node.data.get("kind", "")
        return f"Endpoint '{from_node.label}' accepts {param_kind} parameter '{to_node.label}'"

    if kind == EdgeType.OBSERVED_ON:
        return f"Endpoint '{from_node.label}' was observed on page '{to_node.label}'"

    if kind == EdgeType.RELATED_TO:
        return f"Finding '{from_node.label}' is co-located with endpoint '{to_node.label}'"

    if kind == EdgeType.HOSTS:
        return f"External host '{from_node.label}' serves endpoint '{to_node.label}'"

    if kind == EdgeType.REFERENCES:
        return f"Page '{from_node.label}' references / navigates to '{to_node.label}'"

    if kind == EdgeType.RECOVERS:
        return f"'{from_node.label}' has a recoverable source map: '{to_node.label}'"

    return f"{from_node.label} -[{kind.value}]-> {to_node.label}"


# -- Attack surface graph ------------------------------------------------------

class AttackSurfaceGraph:
    """
    The complete attack surface graph for one BundleSpy scan.

    Build it with AttackSurfaceGraph.from_scan_result(result).

    Query it with:
        graph.neighbors(node_id)
        graph.edges_from(node_id)
        graph.nodes_of_kind(NodeType.ENDPOINT)
        graph.to_dict()   # for JSON serialisation

    Trace the attack surface with:
        graph.trace_upstream(node_id)
        graph.trace_downstream(node_id)
        graph.trace_path(src_id, dst_id)
    """

    def __init__(self) -> None:
        self._nodes:    Dict[str, Node] = {}
        self._edges:    List[Edge]      = []
        self._edge_set: Set[str]        = set()  # dedup key: source+kind+target

    # -- Construction ----------------------------------------------------------

    def add_node(self, node: Node) -> Node:
        """Add or merge a node. Returns the stored node."""
        if node.id not in self._nodes:
            self._nodes[node.id] = node
        return self._nodes[node.id]

    def add_edge(self, source: str, target: str, kind: EdgeType,
                 label: str = "", data: Optional[Dict] = None) -> None:
        """Add a directed edge. Silently deduplicates."""
        key = f"{source}:{kind.value}:{target}"
        if key in self._edge_set:
            return
        if source not in self._nodes or target not in self._nodes:
            return
        self._edge_set.add(key)
        self._edges.append(Edge(source, target, kind, label, data or {}))

    # -- Query -----------------------------------------------------------------

    def node(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id)

    def nodes_of_kind(self, kind: NodeType) -> List[Node]:
        return [n for n in self._nodes.values() if n.kind == kind]

    def edges_from(self, node_id: str) -> List[Edge]:
        return [e for e in self._edges if e.source == node_id]

    def edges_to(self, node_id: str) -> List[Edge]:
        return [e for e in self._edges if e.target == node_id]

    def neighbors(self, node_id: str, direction: str = "out") -> List[Node]:
        """
        Return connected nodes.
        direction: 'out' (default), 'in', or 'both'
        """
        ids: Set[str] = set()
        if direction in ("out", "both"):
            ids.update(e.target for e in self.edges_from(node_id))
        if direction in ("in", "both"):
            ids.update(e.source for e in self.edges_to(node_id))
        return [self._nodes[i] for i in ids if i in self._nodes]

    def related_findings(self, node_id: str) -> List[Node]:
        """Return all SECRET nodes connected to a given node (any direction)."""
        seen: Set[str] = set()
        result: List[Node] = []

        def _walk(nid: str, depth: int = 0) -> None:
            if depth > 3 or nid in seen:
                return
            seen.add(nid)
            n = self._nodes.get(nid)
            if n and n.kind == NodeType.SECRET and nid != node_id:
                result.append(n)
            for e in self.edges_from(nid) + self.edges_to(nid):
                other = e.target if e.source == nid else e.source
                _walk(other, depth + 1)

        _walk(node_id)
        return result

    def attack_surface_for_page(self, page_id: str) -> Dict[str, List[Node]]:
        """
        Return the full attack surface reachable from a page:
        js_files, endpoints, secrets, workers
        """
        result: Dict[str, List[Node]] = {
            "js_files":  [],
            "endpoints": [],
            "secrets":   [],
            "workers":   [],
        }
        for edge in self.edges_from(page_id):
            if edge.kind == EdgeType.LOADS:
                js = self._nodes.get(edge.target)
                if js:
                    result["js_files"].append(js)
                    for e2 in self.edges_from(js.id):
                        target = self._nodes.get(e2.target)
                        if not target:
                            continue
                        if e2.kind == EdgeType.CALLS:
                            result["endpoints"].append(target)
                        elif e2.kind == EdgeType.EXPOSES:
                            result["secrets"].append(target)
                        elif e2.kind == EdgeType.IMPORTS and target.kind == NodeType.WORKER:
                            result["workers"].append(target)
        return result

    # -- Statistics ------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Return a summary dict suitable for the Overview card."""
        counts: Dict[str, int] = {}
        for n in self._nodes.values():
            counts[n.kind.value] = counts.get(n.kind.value, 0) + 1
        return {
            "nodes":   len(self._nodes),
            "edges":   len(self._edges),
            "by_type": counts,
        }

    # -- Serialisation ---------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the full graph to a JSON-ready dict."""
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
            "stats": self.stats(),
        }

    # -- Trace Engine (P1) -----------------------------------------------------

    def trace_downstream(
        self,
        node_id: str,
        max_depth: int = 6,
        max_nodes: int = 200,
    ) -> TraceResult:
        """
        Trace all paths reachable FROM a node (forward BFS).
        Answers: "What attack surface does this node expose?"

        Example: trace_downstream(page_node_id)
          /admin -> admin.js -> GET /api/admin/users -> API_KEY
        """
        origin = self._nodes.get(node_id)
        if not origin:
            return TraceResult(
                origin=Node(id=node_id, kind=NodeType.PAGE, label="(not found)"),
                direction="downstream",
            )

        result = TraceResult(origin=origin, direction="downstream")
        seen:    Set[str]          = {node_id}
        # queue: (current_node, edge_that_led_here, parent_node, depth)
        queue: deque = deque()
        queue.append((origin, None, None, 0))

        while queue and len(result.steps) < max_nodes:
            current, arriving_edge, parent, depth = queue.popleft()

            if arriving_edge is not None and parent is not None:
                evidence = _evidence_for_edge(arriving_edge, parent, current)
                result.steps.append(TraceStep(
                    from_node = parent,
                    edge      = arriving_edge,
                    to_node   = current,
                    evidence  = evidence,
                    depth     = depth,
                ))

            if depth >= max_depth:
                continue

            for edge in self.edges_from(current.id):
                nid = edge.target
                if nid in seen:
                    continue
                child = self._nodes.get(nid)
                if not child:
                    continue
                seen.add(nid)
                queue.append((child, edge, current, depth + 1))

        result.truncated = len(result.steps) >= max_nodes
        return result

    def trace_upstream(
        self,
        node_id: str,
        max_depth: int = 6,
        max_nodes: int = 200,
    ) -> TraceResult:
        """
        Trace all paths that LEAD TO a node (reverse BFS).
        Answers: "How can an attacker reach this node?"

        Example: trace_upstream(endpoint_node_id)
          GET /api/admin/users <- admin.js <- /admin
        """
        origin = self._nodes.get(node_id)
        if not origin:
            return TraceResult(
                origin=Node(id=node_id, kind=NodeType.PAGE, label="(not found)"),
                direction="upstream",
            )

        result = TraceResult(origin=origin, direction="upstream")
        seen:  Set[str] = {node_id}
        queue: deque    = deque()
        queue.append((origin, None, None, 0))

        while queue and len(result.steps) < max_nodes:
            current, arriving_edge, child_node, depth = queue.popleft()

            if arriving_edge is not None and child_node is not None:
                # Upstream: edge runs current -> child, but we traversed it backwards
                evidence = _evidence_for_edge(arriving_edge, current, child_node)
                result.steps.append(TraceStep(
                    from_node = current,
                    edge      = arriving_edge,
                    to_node   = child_node,
                    evidence  = f"[upstream] {evidence}",
                    depth     = depth,
                ))

            if depth >= max_depth:
                continue

            for edge in self.edges_to(current.id):
                nid = edge.source
                if nid in seen:
                    continue
                parent = self._nodes.get(nid)
                if not parent:
                    continue
                seen.add(nid)
                queue.append((parent, edge, current, depth + 1))

        result.truncated = len(result.steps) >= max_nodes
        return result

    def trace_path(
        self,
        src_id: str,
        dst_id: str,
        max_depth: int = 8,
    ) -> TraceResult:
        """
        Find the shortest path between two nodes using BFS.
        Answers: "How is node A connected to node B?"

        Example: trace_path(page_id, secret_id)
          /admin -> admin.js -> admin.js#L23 -> AWS_ACCESS_KEY
        """
        src = self._nodes.get(src_id)
        dst = self._nodes.get(dst_id)

        if not src:
            return TraceResult(
                origin=Node(id=src_id, kind=NodeType.PAGE, label="(not found)"),
                direction="path",
            )

        result = TraceResult(origin=src, direction="path")

        if not dst:
            return result

        if src_id == dst_id:
            return result

        # BFS tracking: node_id -> (parent_id, edge_that_got_here)
        parent_map: Dict[str, Optional[tuple]] = {src_id: None}
        queue: deque = deque([(src_id, 0)])

        found = False
        while queue:
            current_id, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in self.edges_from(current_id) + self.edges_to(current_id):
                nid = edge.target if edge.source == current_id else edge.source
                if nid in parent_map:
                    continue
                parent_map[nid] = (current_id, edge)
                if nid == dst_id:
                    found = True
                    break
                queue.append((nid, depth + 1))
            if found:
                break

        if not found:
            return result

        # Reconstruct path by walking parent_map backwards
        path_ids: List[str] = []
        cur = dst_id
        while cur is not None:
            path_ids.append(cur)
            entry = parent_map.get(cur)
            cur = entry[0] if entry else None
        path_ids.reverse()

        # Build steps along the path
        for i in range(1, len(path_ids)):
            prev_id  = path_ids[i - 1]
            curr_id  = path_ids[i]
            prev_node = self._nodes[prev_id]
            curr_node = self._nodes[curr_id]

            # Find the edge connecting them
            connecting_edge: Optional[Edge] = None
            for e in self.edges_from(prev_id):
                if e.target == curr_id:
                    connecting_edge = e
                    break
            if not connecting_edge:
                for e in self.edges_to(prev_id):
                    if e.source == curr_id:
                        connecting_edge = e
                        break

            ev = _evidence_for_edge(connecting_edge, prev_node, curr_node) if connecting_edge else ""
            result.steps.append(TraceStep(
                from_node = prev_node,
                edge      = connecting_edge,
                to_node   = curr_node,
                evidence  = ev,
                depth     = i,
            ))

        return result

    def trace_all_to_secrets(self) -> List[TraceResult]:
        """
        For every SECRET node in the graph, trace its upstream path.
        Returns a list of TraceResult, one per secret, sorted by severity.
        """
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        secrets = self.nodes_of_kind(NodeType.SECRET)
        secrets.sort(
            key=lambda n: severity_order.get(n.data.get("severity", "INFO"), 99)
        )
        results: List[TraceResult] = []
        for secret in secrets:
            tr = self.trace_upstream(secret.id, max_depth=5)
            results.append(tr)
        return results

    def trace_all_from_pages(self) -> List[TraceResult]:
        """
        For every PAGE node, trace the full downstream attack surface.
        """
        pages = self.nodes_of_kind(NodeType.PAGE)
        results: List[TraceResult] = []
        for page in pages:
            tr = self.trace_downstream(page.id, max_depth=4)
            if tr.steps:
                results.append(tr)
        return results

    # -- Builder ---------------------------------------------------------------

    @classmethod
    def from_scan_result(cls, result: ScanResult) -> "AttackSurfaceGraph":
        """
        Build the attack surface graph from a completed ScanResult.

        Runs in O(n) - one pass over each entity list.
        No network I/O, no re-analysis.
        """
        g = cls()

        # -- 1. Index pages ----------------------------------------------------
        # Collect pages from: js source_pages, endpoint source pages,
        # finding source pages, and any crawled page URLs.
        page_ids: Dict[str, str] = {}  # url -> node_id

        def _ensure_page(url: str) -> Optional[str]:
            if not url or url.startswith("inline:") or url.startswith("local://"):
                return None
            norm = url.rstrip("/").lower().split("?")[0]
            if norm in page_ids:
                return page_ids[norm]
            nid = _node_id("page", url)
            g.add_node(Node(
                id         = nid,
                kind       = NodeType.PAGE,
                label      = _page_label(url),
                confidence = 1.0,
                data       = {"url": url},
            ))
            page_ids[norm] = nid
            return nid

        # -- 2. JS files -------------------------------------------------------
        js_ids: Dict[str, str] = {}  # url -> node_id

        for js in result.js_files:
            nid = _node_id("js", js.url)
            kind = NodeType.JS

            # Classify subtypes
            if js.technology == "webworker" or "worker" in js.url.lower():
                kind = NodeType.WORKER
            elif js.technology == "webpack-chunk" or "chunk" in js.url.lower():
                kind = NodeType.CHUNK
            elif js.source_type == "sourcemap" or js.url.startswith("sourcemap://"):
                kind = NodeType.SOURCEMAP

            g.add_node(Node(
                id         = nid,
                kind       = kind,
                label      = _js_label(js.url),
                confidence = 1.0,
                data       = {
                    "url":         js.url,
                    "size_bytes":  js.size_bytes,
                    "sha256":      js.sha256[:12] if js.sha256 else "",
                    "source_type": js.source_type,
                    "technology":  js.technology,
                    "has_map":     js.has_source_map,
                },
            ))
            js_ids[js.url] = nid

            # PAGE -> LOADS -> JS
            if js.source_page:
                page_nid = _ensure_page(js.source_page)
                if page_nid:
                    g.add_edge(page_nid, nid, EdgeType.LOADS)

        # -- 3. Endpoints ------------------------------------------------------
        ep_ids: Dict[str, str] = {}  # canonical url -> node_id

        for ep in result.endpoints:
            nid   = _node_id("ep", ep.method, ep.url)
            label = _endpoint_label(ep)

            g.add_node(Node(
                id         = nid,
                kind       = NodeType.ENDPOINT,
                label      = label,
                confidence = ep.confidence,
                data       = {
                    "url":          ep.url,
                    "path":         ep.path,
                    "method":       ep.method,
                    "category":     ep.category,
                    "source_file":  ep.source_file,
                    "source_type":  getattr(ep, "source_type", "static"),
                    "auth_context": ep.auth_context or "",
                    "kind":         ep.kind or "api",
                },
            ))
            ep_ids[ep.url] = nid

            # JS -> CALLS -> ENDPOINT
            js_nid = js_ids.get(ep.source_file)
            if js_nid:
                g.add_edge(js_nid, nid, EdgeType.CALLS)

            # ENDPOINT -> OBSERVED_ON -> PAGE (via source_file's source_page)
            # Find the page that loaded the JS that contains this endpoint
            for js in result.js_files:
                if js.url == ep.source_file and js.source_page:
                    page_nid = _ensure_page(js.source_page)
                    if page_nid:
                        g.add_edge(nid, page_nid, EdgeType.OBSERVED_ON)
                    break

            # ENDPOINT -> ACCEPTS -> PARAMETER
            for param in (ep.path_params or []):
                pname  = param.get("name", "?") if isinstance(param, dict) else str(param)
                pnid   = _node_id("param", ep.url, pname, "path")
                g.add_node(Node(
                    id    = pnid,
                    kind  = NodeType.PARAMETER,
                    label = pname,
                    data  = {"kind": "path", "endpoint": ep.url},
                ))
                g.add_edge(nid, pnid, EdgeType.ACCEPTS, "path")

            for param in (ep.query_params or []):
                pname = param.get("name", "?") if isinstance(param, dict) else str(param)
                pnid  = _node_id("param", ep.url, pname, "query")
                g.add_node(Node(
                    id    = pnid,
                    kind  = NodeType.PARAMETER,
                    label = pname,
                    data  = {"kind": "query", "endpoint": ep.url},
                ))
                g.add_edge(nid, pnid, EdgeType.ACCEPTS, "query")

            # HOST node for external endpoints
            if ep.host or (ep.url.startswith("http") and not ep.url.startswith("http://x")):
                try:
                    host = ep.host or urlparse(ep.url).netloc
                    if host and host != urlparse(result.target_url).netloc:
                        hnid = _node_id("host", host)
                        g.add_node(Node(
                            id    = hnid,
                            kind  = NodeType.HOST,
                            label = host,
                            data  = {"host": host},
                        ))
                        g.add_edge(hnid, nid, EdgeType.HOSTS)
                except Exception:
                    pass

        # -- 4. Findings -------------------------------------------------------
        finding_ids: Dict[str, str] = {}  # finding.id -> node_id

        for finding in result.findings:
            if finding.status == "likely_false_positive":
                continue

            nid = _node_id("secret", finding.rule_id, finding.matched_value)
            g.add_node(Node(
                id         = nid,
                kind       = NodeType.SECRET,
                label      = finding.title,
                confidence = finding.confidence,
                data       = {
                    "rule_id":        finding.rule_id,
                    "severity":       finding.severity,
                    "category":       finding.category,
                    "classification": finding.classification or "",
                    "status":         finding.status,
                    "file_url":       finding.file_url,
                    "source_page":    finding.source_page,
                    "line_number":    finding.line_number,
                    "redacted_value": finding.redacted_value,
                    "occurrences":    finding.occurrences or [],
                },
            ))
            finding_ids[finding.id] = nid

            # JS -> EXPOSES -> SECRET
            # Strip prefixes to find the JS node
            raw_url = finding.file_url
            for pfx in ("html:", "inline:", "sourcemap://", "local://"):
                if raw_url.startswith(pfx):
                    raw_url = raw_url[len(pfx):]
                    break

            # Try direct JS file match first
            matched_js = False
            for js_url, js_nid in js_ids.items():
                # Match by stripping prefixes from both sides
                stripped_js = js_url
                for pfx in ("inline:", "html:", "sourcemap://", "local://"):
                    if stripped_js.startswith(pfx):
                        stripped_js = stripped_js[len(pfx):]
                        break
                if stripped_js.split("#")[0] == raw_url.split("#")[0]:
                    g.add_edge(js_nid, nid, EdgeType.EXPOSES)
                    matched_js = True
                    break

            # If not matched to a JS file, attach to the page
            if not matched_js and finding.source_page:
                page_nid = _ensure_page(finding.source_page)
                if page_nid:
                    g.add_edge(page_nid, nid, EdgeType.EXPOSES)

            # SECRET -> RELATED_TO -> ENDPOINT (same source file or page)
            for ep_url, ep_nid in ep_ids.items():
                ep_node = g.node(ep_nid)
                if not ep_node:
                    continue
                ep_source = ep_node.data.get("source_file", "")
                ep_page   = ""
                # Find page via the JS that contains this endpoint
                for js in result.js_files:
                    if js.url == ep_source:
                        ep_page = js.source_page
                        break
                if (ep_source and (ep_source == finding.file_url or
                    ep_source.split("#")[0] in finding.file_url)):
                    g.add_edge(nid, ep_nid, EdgeType.RELATED_TO)
                elif ep_page and ep_page == finding.source_page:
                    g.add_edge(nid, ep_nid, EdgeType.RELATED_TO)

        # -- 5. Infrastructure as HOST nodes -----------------------------------
        for infra in result.infrastructure:
            nid = _node_id("host", infra.value)
            existing = g.node(nid)
            if not existing:
                g.add_node(Node(
                    id         = nid,
                    kind       = NodeType.HOST,
                    label      = infra.value,
                    confidence = infra.confidence,
                    data       = {
                        "value":          infra.value,
                        "classification": infra.classification,
                        "action":         infra.action,
                        "source_file":    infra.source_file,
                    },
                ))

        return g
