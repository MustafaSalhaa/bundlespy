"""
Terminal and structured output for SurfaceReport.
Groups candidates by attack category. Shows burp_notes for actionable follow-up.
"""
from .models import SurfaceReport, SurfaceResult, SurfaceStatus, ConfidenceLevel, AttackCategory

_CONF_LABEL = {
    ConfidenceLevel.HIGH:   "HIGH  ",
    ConfidenceLevel.MEDIUM: "MEDIUM",
    ConfidenceLevel.LOW:    "LOW   ",
}

_STATUS_LABEL = {
    SurfaceStatus.CANDIDATE:    "CANDIDATE",
    SurfaceStatus.MAPPED:       "MAPPED",
    SurfaceStatus.SKIPPED:      "SKIPPED",
    SurfaceStatus.OUT_OF_SCOPE: "OUT_OF_SCOPE",
    SurfaceStatus.NOT_MAPPED:   "NOT_MAPPED",
}


def print_surface_report(report: SurfaceReport, no_color: bool = False) -> None:
    print()
    print(f"  ATTACK SURFACE MAP")
    print(f"  {'─' * 70}")
    print(f"  Target       {report.target_url}")
    print(f"  Candidates   {report.total_candidates:>6}")
    print(f"  Mapped       {report.total_mapped:>6}")
    print(f"  Skipped      {report.total_skipped:>6}")
    print()

    if not report.results:
        print("  No surface candidates found.")
        return

    # Group by category
    by_category: dict = {}
    for r in report.results:
        by_category.setdefault(r.category, []).append(r)

    # Print in category priority order
    for cat in AttackCategory._PRIORITY:
        candidates = by_category.get(cat, [])
        if not candidates:
            continue

        print(f"  {cat.upper()} ({len(candidates)} candidates)")
        print(f"  {'─' * 70}")

        for r in candidates:
            conf_label = _CONF_LABEL.get(r.confidence, r.confidence)
            print(f"  [{conf_label}] {r.surface_type} - {r.endpoint_url}")
            if r.parameters:
                print(f"    params    : {', '.join(r.parameters)}")
            if r.method:
                print(f"    method    : {r.method}")
            if r.auth_context:
                print(f"    auth      : {r.auth_context}")
            for ev in r.evidence:
                print(f"    evidence  : {ev}")
            if r.burp_notes:
                print(f"    burp      : {r.burp_notes}")
            print()

    # Summary table
    print(f"  SUMMARY")
    print(f"  {'─' * 70}")
    print(f"  {'Category':<22}  {'Candidates':>10}  {'Mapped':>8}  {'Skipped':>8}")
    print(f"  {'─'*22}  {'─'*10}  {'─'*8}  {'─'*8}")
    for s in report.summaries:
        if s.total_candidates > 0:
            print(f"  {s.category:<22}  {s.total_candidates:>10}  {s.mapped:>8}  {s.skipped:>8}")
    print()

    if report.errors:
        print(f"  ERRORS ({len(report.errors)})")
        for e in report.errors:
            print(f"    {e}")
        print()


def surface_report_to_dict(report: SurfaceReport) -> dict:
    """Serialize SurfaceReport to a JSON-serializable dict."""
    def _result_dict(r: SurfaceResult) -> dict:
        return {
            "endpoint_url":     r.endpoint_url,
            "method":           r.method,
            "category":         r.category,
            "surface_type":     r.surface_type,
            "parameters":       r.parameters,
            "auth_context":     r.auth_context,
            "confidence":       r.confidence,
            "evidence":         r.evidence,
            "provenance_source": r.provenance_source,
            "burp_notes":       r.burp_notes,
            "requests_made":    r.requests_made,
            "status":           r.status,
        }

    return {
        "target_url":       report.target_url,
        "started_at":       report.started_at.isoformat(),
        "finished_at":      report.finished_at.isoformat() if report.finished_at else None,
        "total_candidates": report.total_candidates,
        "total_mapped":     report.total_mapped,
        "total_skipped":    report.total_skipped,
        "summaries": [
            {
                "category":         s.category,
                "total_candidates": s.total_candidates,
                "mapped":           s.mapped,
                "skipped":          s.skipped,
                "out_of_scope":     s.out_of_scope,
            }
            for s in report.summaries
        ],
        "results": [_result_dict(r) for r in report.results],
        "errors":  report.errors,
    }


# Keep old name working - cli.py imports print_attack_report for backward compat
# The task says to update cli.py to use print_surface_report, but we keep both
print_attack_report = print_surface_report
