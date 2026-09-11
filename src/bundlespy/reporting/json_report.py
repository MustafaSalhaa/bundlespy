"""JSON report generator."""

import json
from datetime import datetime
from ..storage.models import ScanResult


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


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
    }
    return json.dumps(data, indent=2, cls=DateTimeEncoder)
