"""
Terminal and structured output for AttackEngineReport.
No emojis. No ASCII boxes. Clean tabular output.
"""
from .models import AttackEngineReport, AttackTestResult, TestStatus

_SEV_ORDER = {
    TestStatus.CONFIRMED:  0,
    TestStatus.VALIDATED:  1,
    TestStatus.OBSERVED:   2,
    TestStatus.CANDIDATE:  3,
    TestStatus.INCONCLUSIVE: 4,
}

def _status_label(status: str) -> str:
    labels = {
        TestStatus.CONFIRMED:    "CONFIRMED",
        TestStatus.VALIDATED:    "VALIDATED",
        TestStatus.OBSERVED:     "OBSERVED",
        TestStatus.CANDIDATE:    "CANDIDATE",
        TestStatus.INCONCLUSIVE: "INCONCLUSIVE",
        TestStatus.SKIPPED:      "SKIPPED",
        TestStatus.OUT_OF_SCOPE: "OUT_OF_SCOPE",
        TestStatus.NOT_TESTED:   "NOT_TESTED",
    }
    return labels.get(status, status)

def print_attack_report(report: AttackEngineReport, no_color: bool = False) -> None:
    print()
    print(f"  ATTACK SURFACE TESTING")
    print(f"  {'─' * 70}")
    print(f"  Candidates   {report.total_candidates:>6}")
    print(f"  Tested       {report.total_tested:>6}")
    print(f"  Skipped      {report.total_skipped:>6}")
    print(f"  Validated    {report.total_validated:>6}")
    print(f"  Requests     {report.total_requests:>6}")
    print()

    # Per-category summary table
    print(f"  {'Category':<22}  {'Tested':>6}  {'Candidates':>10}  {'Validated':>10}")
    print(f"  {'─'*22}  {'─'*6}  {'─'*10}  {'─'*10}")
    for s in report.summaries:
        print(f"  {s.category:<22}  {s.tested:>6}  {s.candidates:>10}  {s.validated:>10}")
    print()

    # High-value findings only (VALIDATED and CONFIRMED)
    high_value = [
        r for r in report.results
        if r.status in (TestStatus.VALIDATED, TestStatus.CONFIRMED, TestStatus.OBSERVED)
    ]
    high_value.sort(key=lambda r: _SEV_ORDER.get(r.status, 9))

    if not high_value:
        print("  No validated or observed issues found.")
        return

    print(f"  FINDINGS  ({len(high_value)})")
    print(f"  {'─' * 70}")
    for r in high_value:
        label = _status_label(r.status)
        print(f"  [{label}]  {r.attack_class}  -  {r.target_url}")
        if r.parameter:
            print(f"    parameter : {r.parameter}")
        print(f"    method    : {r.method}")
        print(f"    confidence: {r.confidence:.0%}")
        for ev in r.evidence:
            print(f"    evidence  : {ev}")
        if r.what_remains_unverified:
            print(f"    unverified: {r.what_remains_unverified}")
        print()

def attack_report_to_dict(report: AttackEngineReport) -> dict:
    """Serialize AttackEngineReport to a JSON-serializable dict."""
    def _result_dict(r: AttackTestResult) -> dict:
        return {
            "test_id":    r.test_id,
            "category":   r.category,
            "attack_class": r.attack_class,
            "target_url": r.target_url,
            "parameter":  r.parameter,
            "method":     r.method,
            "route":      r.route,
            "status":     r.status,
            "confidence": r.confidence,
            "payload":    r.payload,
            "evidence":   r.evidence,
            "why_tested": r.why_tested,
            "what_changed": r.what_changed,
            "what_observed": r.what_observed,
            "what_remains_unverified": r.what_remains_unverified,
            "requests_made": r.requests_made,
            "timestamp":  r.timestamp.isoformat(),
        }
    return {
        "target_url":       report.target_url,
        "started_at":       report.started_at.isoformat(),
        "finished_at":      report.finished_at.isoformat() if report.finished_at else None,
        "total_candidates": report.total_candidates,
        "total_tested":     report.total_tested,
        "total_skipped":    report.total_skipped,
        "total_validated":  report.total_validated,
        "total_requests":   report.total_requests,
        "summaries": [
            {"category": s.category, "candidates": s.candidates, "tested": s.tested,
             "validated": s.validated, "confirmed": s.confirmed, "skipped": s.skipped}
            for s in report.summaries
        ],
        "results": [_result_dict(r) for r in report.results],
        "errors":  report.errors,
    }
