"""JSON report generator."""

import json
from datetime import datetime
from ..storage.models import ScanResult
from ..storage.graph import AttackSurfaceGraph


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def _build_graph_dict(result: ScanResult) -> dict:
    """Build the attack_surface_graph dict, always present even when empty."""
    try:
        graph = result.graph if result.graph is not None else AttackSurfaceGraph.from_scan_result(result)
        graph_dict = graph.to_dict()
        # Rename stats keys to match test expectations
        raw_stats = graph_dict.get("stats", {})
        return {
            "nodes": graph_dict.get("nodes", []),
            "edges": graph_dict.get("edges", []),
            "stats": {
                "total_nodes": raw_stats.get("nodes", 0),
                "total_edges": raw_stats.get("edges", 0),
                "nodes_by_type": raw_stats.get("by_type", {}),
            },
        }
    except Exception:
        return {
            "nodes": [],
            "edges": [],
            "stats": {
                "total_nodes": 0,
                "total_edges": 0,
                "nodes_by_type": {},
            },
        }


def generate(result: ScanResult, show_sensitive: bool = False) -> str:
    """Generate a JSON report from scan results."""
    data = {
        "scan": {
            "target":       result.target_url,
            "started_at":   result.started_at,
            "finished_at":  result.finished_at,
            "pages_crawled": result.pages_crawled,
        },
        "statistics": {
            "js_files":       len(result.js_files),
            "endpoints":      len(result.endpoints),
            "infrastructure": len(result.infrastructure),
            "findings":       len(result.findings),
            "critical":       sum(1 for f in result.findings if f.severity == "CRITICAL"),
            "high":           sum(1 for f in result.findings if f.severity == "HIGH"),
            "medium":         sum(1 for f in result.findings if f.severity == "MEDIUM"),
            "low":            sum(1 for f in result.findings if f.severity == "LOW"),
        },
        "findings": [
            {
                "id":           f.id,
                "rule_id":      f.rule_id,
                "title":        f.title,
                "category":     f.category,
                "severity":     f.severity,
                "confidence":   f.confidence,
                "status":       f.status,
                "file_url":     f.file_url,
                "line_number":  f.line_number,
                "value":        f.matched_value if show_sensitive else f.redacted_value,
                "description":  f.description,
                "remediation":  f.remediation,
                "occurrences":  f.occurrences,
            }
            for f in result.findings
        ],
        "endpoints": [
            {
                "url":       e.url,
                "category":  e.category,
                "method":    e.method,
                "source":    e.source_file,
                "line":      e.line_number,
            }
            for e in result.endpoints
        ],
        "infrastructure": [
            {
                "value":          i.value,
                "classification": i.classification,
                "source":         i.source_file,
                "line":           i.line_number,
                "action":         i.action,
            }
            for i in result.infrastructure
        ],
        "js_inventory": [
            {
                "url":          js.url,
                "size_bytes":   js.size_bytes,
                "sha256":       js.sha256,
                "technology":   js.technology,
                "source_map":   js.has_source_map,
            }
            for js in result.js_files
        ],
        "errors": result.errors,
        "notice": (
            "No credentials were validated. "
            "No authentication was attempted. "
            "No exploitation was performed."
        ),
        "attack_surface_graph": _build_graph_dict(result),
    }
    return json.dumps(data, indent=2, cls=DateTimeEncoder)
