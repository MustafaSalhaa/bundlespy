"""
BundleSpy Attack Surface Graph
═══════════════════════════════════════════════════════════════════════════════

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
  LOADS           PAGE      → JS
  IMPORTS         JS        → JS (chunk / worker)
  CALLS           JS        → ENDPOINT
  EXPOSES         JS        → SECRET
  ACCEPTS         ENDPOINT  → PARAMETER
  OBSERVED_ON     ENDPOINT  → PAGE
  RELATED_TO      SECRET    → ENDPOINT
  HOSTS           HOST      → ENDPOINT
  REFERENCES      PAGE      → PAGE (navigation / redirect)
  RECOVERS        JS        → SOURCEMAP
"""

from __future__ import annotations

import hashlib
import re
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse

from .models import JSFile, Finding, Endpoint, InfrastructureItem, ScanResult


# ── Node / Edge types ─────────────────────────────────────────────────────────

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
    LOADS       = "LOADS"       # PAGE      → JS
    IMPORTS     = "IMPORTS"     # JS        → JS
    CALLS       = "CALLS"       # JS        → ENDPOINT
    EXPOSES     = "EXPOSES"     # JS        → SECRET
    ACCEPTS     = "ACCEPTS"     # ENDPOINT  → PARAMETER
    OBSERVED_ON = "OBSERVED_ON" # ENDPOINT  → PAGE
    RELATED_TO  = "RELATED_TO"  # SECRET    → ENDPOINT
    HOSTS       = "HOSTS"       # HOST      → ENDPOINT
    REFERENCES  = "REFERENCES"  # PAGE      → PAGE
    RECOVERS    = "RECOVERS"    # JS        → SOURCEMAP


# ── Core node ─────────────────────────────────────────────────────────────────

@dataclass
class Node:
    """
    A node in the attack surface graph.

    id          - stable hash-based identifier
    kind        - NodeType enum value
    label       - short human-readable name (URL path, file name, etc.)
    data        - arbitrary metadata dict (serialisable to JSON)
    confidence  - 0.0–1.0 where applicable
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


# ── Core edge ─────────────────────────────────────────────────────────────────

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


# ── ID helpers ────────────────────────────────────────────────────────────────

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


# ── Attack surface graph ───────────────────────────────────────────────────────

class AttackSurfaceGraph:
    """
    The complete attack surface graph for one BundleSpy scan.

    Build it with AttackSurfaceGraph.from_scan_result(result).
    Query it with:
        graph.neighbors(node_id)
        graph.edges_from(node_id)
        graph.nodes_of_kind(NodeType.ENDPOINT)
        graph.to_dict()   # for JSON serialisation
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, Node] = {}
        self._edges: List[Edge]      = []
        self._edge_set: Set[str]     = set()  # dedup key: source+kind+target

    # ── Construction ─────────────────────────────────────────────────────────

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

    # ── Query ─────────────────────────────────────────────────────────────────

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

    # ── Statistics ────────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Return a summary dict suitable for the Overview card."""
        counts: Dict[str, int] = {}
        for n in self._nodes.values():
            counts[n.kind.value] = counts.get(n.kind.value, 0) + 1
        return {
            "nodes":      len(self._nodes),
            "edges":      len(self._edges),
            "by_type":    counts,
        }

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the full graph to a JSON-ready dict."""
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
            "stats": self.stats(),
        }

    # ── Builder ───────────────────────────────────────────────────────────────

    @classmethod
    def from_scan_result(cls, result: ScanResult) -> "AttackSurfaceGraph":
        """
        Build the attack surface graph from a completed ScanResult.

        Runs in O(n) — one pass over each entity list.
        No network I/O, no re-analysis.
        """
        g = cls()

        # ── 1. Index pages ────────────────────────────────────────────────────
        # Collect pages from: js source_pages, endpoint source pages,
        # finding source pages, and any crawled page URLs.
        page_ids: Dict[str, str] = {}  # url → node_id

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

        # ── 2. JS files ───────────────────────────────────────────────────────
        js_ids: Dict[str, str] = {}  # url → node_id

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

            # PAGE → LOADS → JS
            if js.source_page:
                page_nid = _ensure_page(js.source_page)
                if page_nid:
                    g.add_edge(page_nid, nid, EdgeType.LOADS)

        # ── 3. Endpoints ──────────────────────────────────────────────────────
        ep_ids: Dict[str, str] = {}  # canonical url → node_id

        for ep in result.endpoints:
            nid  = _node_id("ep", ep.method, ep.url)
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

            # JS → CALLS → ENDPOINT
            js_nid = js_ids.get(ep.source_file)
            if js_nid:
                g.add_edge(js_nid, nid, EdgeType.CALLS)

            # ENDPOINT → OBSERVED_ON → PAGE (via source_file's source_page)
            # Find the page that loaded the JS that contains this endpoint
            for js in result.js_files:
                if js.url == ep.source_file and js.source_page:
                    page_nid = _ensure_page(js.source_page)
                    if page_nid:
                        g.add_edge(nid, page_nid, EdgeType.OBSERVED_ON)
                    break

            # ENDPOINT → ACCEPTS → PARAMETER
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

        # ── 4. Findings ───────────────────────────────────────────────────────
        finding_ids: Dict[str, str] = {}  # finding.id → node_id

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

            # JS → EXPOSES → SECRET
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

            # SECRET → RELATED_TO → ENDPOINT (same source file or page)
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

        # ── 5. Infrastructure as HOST nodes ───────────────────────────────────
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


# ── Trace Engine ──────────────────────────────────────────────────────────────

@dataclass
class TraceStep:
    """
    One hop in a trace path.

    from_node   - source Node
    edge        - the Edge that connects them
    to_node     - destination Node
    evidence    - human-readable description of why this hop exists
    depth       - hop index from the trace origin (0-based)
    """
    from_node: Node
    edge:      Edge
    to_node:   Node
    evidence:  str
    depth:     int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_node": self.from_node.to_dict(),
            "edge":      self.edge.to_dict(),
            "to_node":   self.to_node.to_dict(),
            "evidence":  self.evidence,
            "depth":     self.depth,
        }


@dataclass
class TraceResult:
    """
    The result of one trace operation.

    origin      - the node the trace started from
    direction   - 'downstream' or 'upstream'
    paths       - list of paths; each path is a list of TraceStep
    truncated   - True when max_depth or max_nodes was hit
    """
    origin:    Node
    direction: str
    paths:     List[List[TraceStep]]
    truncated: bool = False

    def all_nodes(self) -> List[Node]:
        """All unique nodes across every path (origin + reachable)."""
        seen: Set[str] = set()
        result: List[Node] = [self.origin]
        seen.add(self.origin.id)
        for path in self.paths:
            for step in path:
                if step.to_node.id not in seen:
                    seen.add(step.to_node.id)
                    result.append(step.to_node)
        return result

    def secrets(self) -> List[Node]:
        return [n for n in self.all_nodes() if n.kind == NodeType.SECRET]

    def endpoints(self) -> List[Node]:
        return [n for n in self.all_nodes() if n.kind == NodeType.ENDPOINT]

    def chain_label(self) -> str:
        """Short human-readable summary of what was found."""
        ep  = len(self.endpoints())
        sec = len(self.secrets())
        parts = []
        if ep:
            parts.append(f"{ep} endpoint{'s' if ep != 1 else ''}")
        if sec:
            parts.append(f"{sec} secret{'s' if sec != 1 else ''}")
        return ", ".join(parts) or "no findings"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "origin":    self.origin.to_dict(),
            "direction": self.direction,
            "paths":     [[step.to_dict() for step in path] for path in self.paths],
            "truncated": self.truncated,
            "summary": {
                "total_paths":     len(self.paths),
                "total_nodes":     len(self.all_nodes()),
                "secrets":         len(self.secrets()),
                "endpoints":       len(self.endpoints()),
                "chain_label":     self.chain_label(),
            },
        }


def _evidence_for_edge(edge: Edge, from_node: Node, to_node: Node) -> str:
    """Return a one-line human-readable evidence string for a graph hop."""
    kind = edge.kind.value
    if kind == "LOADS":
        return f"Page '{from_node.label}' loads script '{to_node.label}'"
    if kind == "IMPORTS":
        return f"Script '{from_node.label}' imports '{to_node.label}'"
    if kind == "CALLS":
        return f"Script '{from_node.label}' calls endpoint '{to_node.label}'"
    if kind == "EXPOSES":
        src = from_node.data.get("url", from_node.label)
        return f"'{from_node.label}' exposes secret '{to_node.label}' at {src}"
    if kind == "OBSERVED_ON":
        return f"Endpoint '{from_node.label}' observed on page '{to_node.label}'"
    if kind == "RELATED_TO":
        return f"Secret '{from_node.label}' co-located with endpoint '{to_node.label}'"
    if kind == "HOSTS":
        return f"Host '{from_node.label}' serves endpoint '{to_node.label}'"
    if kind == "REFERENCES":
        return f"Page '{from_node.label}' references '{to_node.label}'"
    if kind == "RECOVERS":
        return f"Script '{from_node.label}' has source map '{to_node.label}'"
    if kind == "ACCEPTS":
        return f"Endpoint '{from_node.label}' accepts parameter '{to_node.label}'"
    return f"{from_node.label} -[{kind}]-> {to_node.label}"


# Sentinel type for edge key used in cycle/duplicate detection
_EdgeKey = Tuple[str, str, str]  # (source_id, kind, target_id)


def _trace(
    graph: "AttackSurfaceGraph",
    origin_id: str,
    direction: str,
    max_depth: int,
    max_nodes: int,
    allowed_edge_types: Optional[Set[EdgeType]],
    include_related_to: bool,
) -> TraceResult:
    """
    Core BFS traversal used by all public trace methods.

    Rules enforced:
    - Each edge appears at most once per branch (no duplicate hops).
    - Nodes may be reached via multiple branches but never revisited
      within the same branch (cycle protection).
    - RELATED_TO is excluded unless include_related_to=True.
    - Branches are independent: siblings are never merged into one path.
    - Output is deterministic (edges sorted by source+kind+target).
    - Stops when max_depth or max_nodes reached (sets truncated=True).
    """
    origin = graph.node(origin_id)
    if origin is None:
        placeholder = Node(id=origin_id, kind=NodeType.PAGE, label=origin_id)
        return TraceResult(origin=placeholder, direction=direction, paths=[], truncated=False)

    def _sorted_edges(node_id: str) -> List[Edge]:
        if direction == "downstream":
            edges = graph.edges_from(node_id)
        else:
            edges = graph.edges_to(node_id)
        filtered = []
        for e in edges:
            if allowed_edge_types and e.kind not in allowed_edge_types:
                continue
            if not include_related_to and e.kind == EdgeType.RELATED_TO:
                continue
            filtered.append(e)
        return sorted(filtered, key=lambda e: (e.source, e.kind.value, e.target))

    completed_paths: List[List[TraceStep]] = []
    truncated = False
    total_nodes_seen: Set[str] = {origin_id}

    # Queue items: (current_node_id, path_so_far, edges_used_in_branch, nodes_in_branch)
    queue: deque = deque()
    queue.append((origin_id, [], frozenset(), frozenset({origin_id})))

    while queue:
        node_id, path_so_far, branch_edges, branch_nodes = queue.popleft()
        edges = _sorted_edges(node_id)

        if not edges:
            if path_so_far:
                completed_paths.append(path_so_far)
            continue

        branched = False
        for edge in edges:
            next_id = edge.target if direction == "downstream" else edge.source

            # Skip self-edges without a real self-loop in the graph
            if next_id == node_id:
                continue

            edge_key: _EdgeKey = (edge.source, edge.kind.value, edge.target)

            # Skip if edge already used in this branch
            if edge_key in branch_edges:
                continue

            # Skip if node already visited in this branch (cycle guard)
            if next_id in branch_nodes:
                continue

            next_node = graph.node(next_id)
            if next_node is None:
                continue

            if len(path_so_far) >= max_depth:
                truncated = True
                continue

            if len(total_nodes_seen) >= max_nodes and next_id not in total_nodes_seen:
                truncated = True
                continue

            total_nodes_seen.add(next_id)

            step = TraceStep(
                from_node=graph.node(node_id),
                edge=edge,
                to_node=next_node,
                evidence=_evidence_for_edge(edge, graph.node(node_id), next_node),
                depth=len(path_so_far),
            )

            queue.append((
                next_id,
                path_so_far + [step],
                branch_edges | {edge_key},
                branch_nodes | {next_id},
            ))
            branched = True

        if not branched and path_so_far:
            completed_paths.append(path_so_far)

    # De-duplicate identical paths
    seen_sigs: Set[Tuple] = set()
    unique_paths: List[List[TraceStep]] = []
    for path in completed_paths:
        sig = tuple((s.edge.source, s.edge.kind.value, s.edge.target) for s in path)
        if sig not in seen_sigs:
            seen_sigs.add(sig)
            unique_paths.append(path)

    return TraceResult(
        origin=origin,
        direction=direction,
        paths=unique_paths,
        truncated=truncated,
    )


def _asg_trace_downstream(
    self,
    node_id: str,
    max_depth: int = 6,
    max_nodes: int = 200,
    edge_types: Optional[Set[EdgeType]] = None,
    include_related_to: bool = False,
) -> TraceResult:
    """
    Trace all paths reachable from node_id following outgoing edges.
    RELATED_TO edges excluded by default; pass include_related_to=True to include.
    """
    return _trace(self, node_id, "downstream", max_depth, max_nodes,
                  edge_types, include_related_to)


def _asg_trace_upstream(
    self,
    node_id: str,
    max_depth: int = 6,
    max_nodes: int = 200,
    edge_types: Optional[Set[EdgeType]] = None,
    include_related_to: bool = False,
) -> TraceResult:
    """Trace all paths leading INTO node_id following incoming edges in reverse."""
    return _trace(self, node_id, "upstream", max_depth, max_nodes,
                  edge_types, include_related_to)


def _asg_trace_path(
    self,
    from_id: str,
    to_id: str,
    max_depth: int = 8,
    include_related_to: bool = False,
) -> TraceResult:
    """Find all simple paths between two specific nodes."""
    full = _trace(self, from_id, "downstream", max_depth, 500, None, include_related_to)
    matching = [p for p in full.paths if p and p[-1].to_node.id == to_id]
    return TraceResult(
        origin=full.origin,
        direction="downstream",
        paths=matching,
        truncated=full.truncated,
    )


def _asg_trace_all_to_secrets(
    self,
    max_depth: int = 6,
    include_related_to: bool = False,
) -> List[TraceResult]:
    """Run trace_downstream from every PAGE and return only those reaching a SECRET."""
    results = []
    for page in self.nodes_of_kind(NodeType.PAGE):
        tr = self.trace_downstream(page.id, max_depth=max_depth,
                                   include_related_to=include_related_to)
        if tr.secrets():
            results.append(tr)
    return results


def _asg_trace_all_from_pages(
    self,
    max_depth: int = 6,
    include_related_to: bool = False,
) -> List[TraceResult]:
    """Run trace_downstream from every PAGE and return all results."""
    return [
        self.trace_downstream(page.id, max_depth=max_depth,
                              include_related_to=include_related_to)
        for page in self.nodes_of_kind(NodeType.PAGE)
    ]


AttackSurfaceGraph.trace_downstream     = _asg_trace_downstream
AttackSurfaceGraph.trace_upstream       = _asg_trace_upstream
AttackSurfaceGraph.trace_path           = _asg_trace_path
AttackSurfaceGraph.trace_all_to_secrets = _asg_trace_all_to_secrets
AttackSurfaceGraph.trace_all_from_pages = _asg_trace_all_from_pages
