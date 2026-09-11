"""
Terminal output reporter.
Prints color-coded findings to stdout with redaction by default.
"""

from typing import List
from ..storage.models import Finding, Endpoint, InfrastructureItem, ScanResult
from ..config import PROJECT_NAME, PROJECT_VERSION


class Colors:
    RED    = "\033[91m"
    ORANGE = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


SEVERITY_COLOR = {
    "CRITICAL": Colors.RED + Colors.BOLD,
    "HIGH":     Colors.ORANGE,
    "MEDIUM":   Colors.CYAN,
    "LOW":      Colors.BLUE,
    "INFO":     Colors.DIM,
}


def _sev_label(severity: str, no_color: bool = False) -> str:
    if no_color:
        return f"[{severity}]"
    color = SEVERITY_COLOR.get(severity, Colors.RESET)
    return f"{color}[{severity}]{Colors.RESET}"


def print_finding(finding: Finding, show_sensitive: bool = False, no_color: bool = False) -> None:
    label = _sev_label(finding.severity, no_color)
    value = finding.matched_value if show_sensitive else finding.redacted_value

    print(f"\n  {label} {finding.title}")
    print(f"  {'─' * 60}")
    print(f"  File       : {finding.file_url}")
    print(f"  Line       : {finding.line_number}")
    print(f"  Category   : {finding.category}")
    print(f"  Confidence : {finding.confidence:.0%}")
    print(f"  Status     : {finding.status}")
    print(f"  Value      : {value}")
    if finding.occurrences and len(finding.occurrences) > 1:
        print(f"  Occurrences: {len(finding.occurrences)}")
    print(f"  Context    : ...{finding.context[:100]}...")
    print(f"  Fix        : {finding.remediation[:120]}")
    if finding.false_positive_notes:
        print(f"  FP Note    : {finding.false_positive_notes}")


def print_summary(result: ScanResult, no_color: bool = False) -> None:
    findings   = result.findings
    critical   = [f for f in findings if f.severity == "CRITICAL"]
    high       = [f for f in findings if f.severity == "HIGH"]
    medium     = [f for f in findings if f.severity == "MEDIUM"]
    low        = [f for f in findings if f.severity == "LOW"]
    likely_fps = [f for f in findings if f.status == "likely_false_positive"]

    c = Colors

    print(f"""
{c.BOLD}{c.CYAN}
+--------------------------------------------------+
|                  SCAN SUMMARY                    |
+--------------------------------------------------+
{c.RESET}
  Target              : {result.target_url}
  Pages crawled       : {result.pages_crawled}
  JavaScript files    : {len(result.js_files)}
  Endpoints found     : {len(result.endpoints)}
  Infrastructure hits : {len(result.infrastructure)}
  Total findings      : {len(findings)}

  {c.RED}{c.BOLD}Critical            : {len(critical)}{c.RESET}
  {c.ORANGE}High                : {len(high)}{c.RESET}
  {c.CYAN}Medium              : {len(medium)}{c.RESET}
  {c.BLUE}Low                 : {len(low)}{c.RESET}
  {c.DIM}Likely false pos.   : {len(likely_fps)}{c.RESET}
""")

    if result.errors:
        print(f"  {c.ORANGE}Scan errors: {len(result.errors)}{c.RESET}")
        for err in result.errors[:5]:
            print(f"    - {err}")

    print(f"""
  {c.DIM}No credentials were validated.
  No authentication was attempted.
  No exploitation was performed.
  Private network targets were not contacted.{c.RESET}
""")


def print_report(
    result: ScanResult,
    show_sensitive: bool = False,
    no_color: bool = False,
    min_severity: str = "INFO",
) -> None:
    """Print a full terminal report."""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    min_idx = order.index(min_severity) if min_severity in order else len(order)

    filtered = [
        f for f in result.findings
        if order.index(f.severity) <= min_idx
        and f.status != "likely_false_positive"
    ]

    if filtered:
        print(f"\n  {'─' * 60}")
        print(f"  FINDINGS ({len(filtered)})")
        print(f"  {'─' * 60}")
        for finding in sorted(filtered, key=lambda f: order.index(f.severity)):
            print_finding(finding, show_sensitive=show_sensitive, no_color=no_color)

    if result.endpoints:
        print(f"\n  {'─' * 60}")
        print(f"  ENDPOINTS ({len(result.endpoints)})")
        print(f"  {'─' * 60}")
        by_cat: dict = {}
        for ep in result.endpoints:
            by_cat.setdefault(ep.category, []).append(ep)
        for cat, eps in sorted(by_cat.items()):
            print(f"\n  [{cat}]")
            for ep in eps[:10]:
                print(f"    {ep.url}  (from {ep.source_file.split('/')[-1]})")

    if result.infrastructure:
        print(f"\n  {'─' * 60}")
        print(f"  INFRASTRUCTURE INTELLIGENCE ({len(result.infrastructure)})")
        print(f"  {'─' * 60}")
        for item in result.infrastructure[:20]:
            print(f"  [{item.classification}] {item.value}  (from line {item.line_number})")

    print_summary(result, no_color=no_color)
