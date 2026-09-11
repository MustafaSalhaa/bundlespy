"""CSV report generator - one row per finding, easy to import into Excel or a tracker."""

import csv
import io
from ..storage.models import ScanResult


def generate(result: ScanResult, show_sensitive: bool = False) -> str:
    out = io.StringIO()
    writer = csv.writer(out)

    writer.writerow([
        "Severity", "Title", "Category", "Confidence", "Status",
        "File", "Line", "Value", "Description", "Remediation", "Occurrences",
    ])

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sorted_findings = sorted(
        result.findings,
        key=lambda f: order.index(f.severity) if f.severity in order else 99,
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
            len(f.occurrences),
        ])

    return out.getvalue()
