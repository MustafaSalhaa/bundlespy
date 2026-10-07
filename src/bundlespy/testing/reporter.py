"""
Terminal and structured output for SurfaceReport.
Groups candidates by attack category. Shows burp_notes for actionable follow-up.
"""
import shutil
import textwrap
from .models import SurfaceReport, SurfaceResult, SurfaceStatus, ConfidenceLevel, AttackCategory

try:
    from ..ui.theme import A
except ImportError:
    # Fallback when theme not available (e.g. unit tests)
    class _Noop:
        def __getattr__(self, _): return ""
    A = _Noop()


def _w() -> int:
    try:
        return min(shutil.get_terminal_size((80, 24)).columns, 110)
    except Exception:
        return 80


# Category colors - severity-based, not arbitrary
_CAT_COLOR = {
    AttackCategory.ACCESS_CONTROL:      A.RED    + A.BOLD,
    AttackCategory.PROTOTYPE_POLLUTION: A.RED    + A.BOLD,
    AttackCategory.XSS:                 A.ORANGE + A.BOLD,
    AttackCategory.INJECTION:           A.ORANGE + A.BOLD,
    AttackCategory.SSRF:                A.YELLOW + A.BOLD,
    AttackCategory.OPEN_REDIRECT:       A.YELLOW + A.BOLD,
    AttackCategory.CSRF:                A.YELLOW + A.BOLD,
    AttackCategory.PATH_TRAVERSAL:      A.YELLOW,
    AttackCategory.CORS:                A.ORANGE + A.BOLD,
    AttackCategory.CONFIGURATION:       A.BLUE,
}

# Confidence colors
_CONF_COLOR = {
    ConfidenceLevel.HIGH:   A.RED    + A.BOLD,
    ConfidenceLevel.MEDIUM: A.YELLOW,
    ConfidenceLevel.LOW:    A.BLUE,
}


def _cat_header(cat: str, count: int) -> None:
    """Print a colored category header with bookend dashes."""
    color  = _CAT_COLOR.get(cat, A.WHITE + A.BOLD)
    label  = f"  {color}── {cat.upper()}{A.RESET}  {A.GREY}·  {count} candidate{'s' if count != 1 else ''}{A.RESET}"
    # Trailing dashes to terminal width
    # Strip ANSI for length calc
    import re
    _ansi_re = re.compile(r"\033\[[0-9;]*m")
    visible_len = len(_ansi_re.sub("", label))
    trail = max(0, _w() - visible_len - 2)
    print(f"{label}  {A.GREY}{'─' * trail}{A.RESET}")


def _wrap_burp(notes: str, indent: int = 9) -> None:
    """
    Print burp notes with consistent indentation.
    Splits on existing newlines first, then word-wraps each segment.
    """
    if not notes:
        return
    pad    = " " * indent
    width  = max(40, _w() - indent - 2)
    print(f"  {A.WHITE}Burp{A.RESET}")
    for line in notes.splitlines():
        line = line.strip()
        if not line:
            continue
        for wrapped in textwrap.wrap(line, width=width) or [line]:
            print(f"  {A.GREY}{pad}{wrapped}{A.RESET}")


def _print_result(r: SurfaceResult) -> None:
    """Print one finding block."""
    conf_color = _CONF_COLOR.get(r.confidence, A.GREY)
    conf_label = f"{conf_color}{r.confidence:<6}{A.RESET}"

    # Line 1: confidence + surface type
    print(f"  {conf_label}  {A.WHITE}{A.BOLD}{r.surface_type}{A.RESET}")

    # Line 2: URL (indented, dimmed)
    print(f"          {A.GREY}{r.endpoint_url}{A.RESET}")

    # Line 3: method + params on one line
    method_str = r.method or "?"
    if r.parameters:
        params_short = ", ".join(r.parameters[:6])
        print(f"          {A.GREY}{method_str}  ·  params: {params_short}{A.RESET}")
    else:
        print(f"          {A.GREY}{method_str}{A.RESET}")

    if r.auth_context:
        print(f"          {A.YELLOW}auth: {r.auth_context}{A.RESET}")

    # Evidence block - bullet list, no repeated label
    if r.evidence:
        print()
        for ev in r.evidence:
            ev = ev.strip()
            if ev:
                print(f"  {A.GREY}·  {ev}{A.RESET}")

    # Burp notes - wrapped
    if r.burp_notes:
        print()
        _wrap_burp(r.burp_notes)

    print()
    print(f"  {A.GREY}{'─' * min(60, _w() - 4)}{A.RESET}")
    print()


def print_surface_report(report: SurfaceReport, no_color: bool = False) -> None:
    print()
    # Header block
    print(f"  {A.WHITE}{A.BOLD}ATTACK SURFACE MAP{A.RESET}")
    print(f"  {A.GREY}{'─' * min(70, _w() - 4)}{A.RESET}")
    print(f"  {A.GREY}Target      {A.RESET}{A.CYAN}{report.target_url}{A.RESET}")

    cand_c = A.RED + A.BOLD if report.total_candidates >= 10 else A.YELLOW if report.total_candidates > 0 else A.GREY
    map_c  = A.GREEN if report.total_mapped > 0 else A.GREY
    print(f"  {A.GREY}Candidates  {A.RESET}{cand_c}{report.total_candidates}{A.RESET}")
    print(f"  {A.GREY}Mapped      {A.RESET}{map_c}{report.total_mapped}{A.RESET}")
    if report.total_skipped:
        print(f"  {A.GREY}Skipped     {report.total_skipped}{A.RESET}")
    print()

    if not report.results:
        print(f"  {A.GREY}No surface candidates found.{A.RESET}")
        return

    # Group by category
    by_category: dict = {}
    for r in report.results:
        by_category.setdefault(r.category, []).append(r)

    # Print in priority order
    for cat in AttackCategory._PRIORITY:
        candidates = by_category.get(cat, [])
        if not candidates:
            continue

        # Sort HIGH first within each category
        candidates = sorted(candidates, key=lambda x: ConfidenceLevel.order(x.confidence))

        print()
        _cat_header(cat, len(candidates))
        print()

        for r in candidates:
            _print_result(r)

    # Summary table
    print()
    print(f"  {A.WHITE}{A.BOLD}SUMMARY{A.RESET}")
    print(f"  {A.GREY}{'─' * min(70, _w() - 4)}{A.RESET}")
    print(f"  {A.GREY}{'Category':<22}  {'Candidates':>10}  {'Mapped':>8}  {'Skipped':>8}{A.RESET}")
    print(f"  {A.GREY}{'─'*22}  {'─'*10}  {'─'*8}  {'─'*8}{A.RESET}")
    for s in report.summaries:
        if s.total_candidates == 0:
            continue
        cat_c  = _CAT_COLOR.get(s.category, A.WHITE)
        cand_c = A.RED if s.total_candidates >= 5 else A.YELLOW if s.total_candidates > 0 else A.GREY
        map_c  = A.GREEN if s.mapped > 0 else A.GREY
        skip_c = A.GREY
        print(
            f"  {cat_c}{s.category:<22}{A.RESET}"
            f"  {cand_c}{s.total_candidates:>10}{A.RESET}"
            f"  {map_c}{s.mapped:>8}{A.RESET}"
            f"  {skip_c}{s.skipped:>8}{A.RESET}"
        )
    print()

    if report.errors:
        print(f"  {A.YELLOW}ERRORS ({len(report.errors)}){A.RESET}")
        for e in report.errors:
            print(f"  {A.GREY}  · {e}{A.RESET}")
        print()


def surface_report_to_dict(report: SurfaceReport) -> dict:
    """Serialize SurfaceReport to a JSON-serializable dict."""
    def _result_dict(r: SurfaceResult) -> dict:
        return {
            "endpoint_url":      r.endpoint_url,
            "method":            r.method,
            "category":          r.category,
            "surface_type":      r.surface_type,
            "parameters":        r.parameters,
            "auth_context":      r.auth_context,
            "confidence":        r.confidence,
            "evidence":          r.evidence,
            "provenance_source": r.provenance_source,
            "burp_notes":        r.burp_notes,
            "requests_made":     r.requests_made,
            "status":            r.status,
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


# Backward compat alias
print_attack_report = print_surface_report
