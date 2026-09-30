"""
CSV report generator.

Writes three sections to a single file separated by blank lines + headers:
  1. Secrets / Findings   — one row per finding
  2. Endpoints            — one row per discovered endpoint
  3. Infrastructure       — one row per infrastructure item

Easy to import into Excel, a tracker, or a vuln management platform.
"""

import csv
import io
from ..storage.models import ScanResult


def generate(result: ScanResult, show_sensitive: bool = False) -> str:
    out    = io.StringIO()
    writer = csv.writer(out)

    # ── Section 1: Secrets / Findings ────────────────────────────────────────
    writer.writerow(["## SECRETS / FINDINGS"])
    writer.writerow([
        "Severity", "Title", "Category", "Confidence", "Status",
        "File", "Line", "Value", "Description", "Remediation", "Occurrences",
    ])

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        result.findings,
        key=lambda f: sev_order.get(f.severity, 99),
    )

    for f in sorted_findings:
        value = f.matched_value if show_sensitive else f.redacted_value
        writer.writerow([
            f.severity,
            f.title,
            f.category,
            f"{f.confidence:.0%}",
            f.status,
            f.file_url,
            f.line_number,
            value,
            f.description,
            f.remediation,
            len(f.occurrences or []),
        ])

    # ── Section 2: Endpoints ──────────────────────────────────────────────────
    writer.writerow([])
    writer.writerow(["## ENDPOINTS"])
    writer.writerow([
        "Method", "URL", "Path", "Category", "Kind", "Confidence",
        "Source File", "Auth Context", "Query Params", "Body Fields",
        "Evidence",
    ])

    cat_order = {
        "ADMIN": 0, "AUTH": 1, "API": 2, "GRAPHQL": 3,
        "UPLOAD": 4, "DOWNLOAD": 5, "WEBSOCKET": 6,
        "ROUTE": 7, "EXTERNAL": 8, "UNKNOWN": 9,
    }
    sorted_endpoints = sorted(
        result.endpoints,
        key=lambda ep: cat_order.get(ep.category or "", 99),
    )

    for ep in sorted_endpoints:
        query_params = ", ".join(
            p.get("name", "") for p in (ep.query_params or []) if p.get("name")
        )
        body_fields = ", ".join(
            f.get("name", "") for f in (ep.body_fields or []) if f.get("name")
        )
        writer.writerow([
            ep.method or "UNKNOWN",
            ep.url,
            ep.path or "",
            ep.category or "",
            getattr(ep, "kind", "") or "",
            f"{ep.confidence:.0%}" if ep.confidence is not None else "",
            getattr(ep, "source_file", "") or "",
            getattr(ep, "auth_context", "") or "",
            query_params,
            body_fields,
            getattr(ep, "evidence", "") or "",
        ])

    # ── Section 3: Infrastructure ─────────────────────────────────────────────
    writer.writerow([])
    writer.writerow(["## INFRASTRUCTURE"])
    writer.writerow([
        "Classification", "Value", "Action", "Source File", "Line", "Confidence",
    ])

    infra_class_order = {
        "CDN": 0, "CLOUD": 1, "STORAGE": 2, "DATABASE": 3,
        "AUTH": 4, "API": 5, "THIRD_PARTY": 6, "INTERNAL": 7,
    }
    sorted_infra = sorted(
        result.infrastructure,
        key=lambda i: infra_class_order.get(getattr(i, "classification", "") or "", 99),
    )

    for item in sorted_infra:
        writer.writerow([
            getattr(item, "classification", "") or "",
            getattr(item, "value", "") or "",
            getattr(item, "action", "") or "",
            getattr(item, "source_file", "") or "",
            getattr(item, "line_number", "") or "",
            f"{item.confidence:.0%}" if getattr(item, "confidence", None) is not None else "",
        ])

    return out.getvalue()
