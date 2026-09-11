"""
Terminal reporter for BundleSpy.
Beautiful, clear, advanced terminal output for all features.
File output is always optional.
"""

from typing import List, Optional
from ..storage.models import Finding, Endpoint, InfrastructureItem, ScanResult
from ..config import PROJECT_NAME, PROJECT_VERSION


class C:
    RED    = "\033[91m"
    ORANGE = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    PURPLE = "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"
    WHITE  = "\033[97m"


SEVERITY_COLOR = {
    "CRITICAL": C.RED + C.BOLD,
    "HIGH":     C.ORANGE,
    "MEDIUM":   C.CYAN,
    "LOW":      C.BLUE,
    "INFO":     C.DIM,
}

SEVERITY_ICON = {
    "CRITICAL": "💀",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

STATUS_COLOR = {
    "likely_secret":        C.RED,
    "validated":            C.RED + C.BOLD,
    "candidate":            C.ORANGE,
    "likely_false_positive": C.DIM,
}

CATEGORY_ICON = {
    "AUTH":      "🔐",
    "ADMIN":     "⚠️ ",
    "GRAPHQL":   "🔷",
    "WEBSOCKET": "🔌",
    "UPLOAD":    "📤",
    "DOWNLOAD":  "📥",
    "API":       "🔗",
    "UNKNOWN":   "📍",
}

INFRA_ICON = {
    "PRIVATE_IP":       "🏠",
    "PUBLIC_IP":        "🌐",
    "LOOPBACK":         "🔄",
    "LINK_LOCAL":       "⚡",
    "CLOUD_METADATA":   "☁️ ",
    "INTERNAL_HOSTNAME":"🏢",
    "STAGING":          "🧪",
    "DEVELOPMENT":      "🛠️ ",
}


def _divider(char: str = "─", width: int = 72, color: str = C.DIM) -> str:
    return f"{color}{char * width}{C.RESET}"


def _section_header(title: str, count: int = None, color: str = C.CYAN) -> str:
    count_str = f" ({count})" if count is not None else ""
    line = _divider()
    return f"\n{line}\n{color}{C.BOLD}  {title}{count_str}{C.RESET}\n{line}"


def _badge(text: str, color: str) -> str:
    return f"{color}{C.BOLD}[{text}]{C.RESET}"


def print_finding(f: Finding, show_sensitive: bool = True, no_color: bool = False) -> None:
    sc     = SEVERITY_COLOR.get(f.severity, C.RESET) if not no_color else ""
    rst    = C.RESET if not no_color else ""
    icon   = SEVERITY_ICON.get(f.severity, "•") if not no_color else ""
    stc    = STATUS_COLOR.get(f.status, C.DIM) if not no_color else ""
    value  = f.matched_value if show_sensitive else f.redacted_value
    dimclr = C.DIM if not no_color else ""
    grn    = C.GREEN if not no_color else ""
    wht    = C.WHITE if not no_color else ""

    print(f"\n  {sc}{C.BOLD if not no_color else ''}┌─ {icon} {f.severity} ─ {f.title}{rst}")
    print(f"  {dimclr}│{rst}  Rule       {dimclr}:{rst} {f.rule_id}")
    print(f"  {dimclr}│{rst}  Category   {dimclr}:{rst} {f.category}")
    print(f"  {dimclr}│{rst}  Confidence {dimclr}:{rst} {grn}{f.confidence:.0%}{rst}  Status {dimclr}:{rst} {stc}{f.status}{rst}")
    print(f"  {dimclr}│{rst}  File       {dimclr}:{rst} {wht}{f.file_url}{rst}")
    print(f"  {dimclr}│{rst}  Line       {dimclr}:{rst} {f.line_number}")
    print(f"  {dimclr}│{rst}  Value      {dimclr}:{rst} {sc}{value}{rst}")
    if f.occurrences and len(f.occurrences) > 1:
        print(f"  {dimclr}│{rst}  Seen in    {dimclr}:{rst} {len(f.occurrences)} locations")
    print(f"  {dimclr}│{rst}  Context    {dimclr}:{rst} {dimclr}...{f.context[:100]}...{rst}")
    print(f"  {dimclr}│{rst}  Fix        {dimclr}:{rst} {f.remediation[:100]}")
    if f.false_positive_notes and f.status == "likely_false_positive":
        print(f"  {dimclr}│{rst}  FP Note    {dimclr}:{rst} {dimclr}{f.false_positive_notes}{rst}")
    if f.status == "validated":
        print(f"  {dimclr}│{rst}  {C.RED}{C.BOLD}⚡ VALIDATED - Secret confirmed active!{rst}")
    print(f"  {sc}{'└' + '─' * 68}{rst}")


def print_endpoints(endpoints: List[Endpoint], no_color: bool = False) -> None:
    if not endpoints:
        return

    print(_section_header("ENDPOINT INTELLIGENCE", len(endpoints), C.BLUE))

    by_cat: dict = {}
    for ep in endpoints:
        by_cat.setdefault(ep.category, []).append(ep)

    for cat in ["AUTH", "ADMIN", "GRAPHQL", "UPLOAD", "DOWNLOAD", "API", "WEBSOCKET", "UNKNOWN"]:
        eps = by_cat.get(cat, [])
        if not eps:
            continue
        icon = CATEGORY_ICON.get(cat, "•") if not no_color else ""
        clr  = C.ORANGE if cat in ("ADMIN", "GRAPHQL") else (C.RED if cat == "AUTH" else C.BLUE)
        clr  = clr if not no_color else ""
        rst  = C.RESET if not no_color else ""
        dim  = C.DIM if not no_color else ""
        print(f"\n  {clr}{C.BOLD if not no_color else ''}{icon} {cat}{rst}  {dim}({len(eps)} endpoint{'s' if len(eps) != 1 else ''}){rst}")
        for ep in eps[:30]:
            conf = f"{ep.confidence:.0%}"
            print(f"  {dim}  ├─{rst} {ep.url}  {dim}[{conf}]{rst}")
        if len(eps) > 30:
            print(f"  {dim}  └─ ... and {len(eps) - 30} more{rst}")


def print_infrastructure(items: List[InfrastructureItem], no_color: bool = False) -> None:
    if not items:
        return

    print(_section_header("INFRASTRUCTURE INTELLIGENCE", len(items), C.PURPLE))

    by_class: dict = {}
    for item in items:
        by_class.setdefault(item.classification, []).append(item)

    for cls, its in sorted(by_class.items()):
        icon = INFRA_ICON.get(cls, "•") if not no_color else ""
        clr  = C.RED if cls in ("PRIVATE_IP", "CLOUD_METADATA") else (C.ORANGE if cls == "INTERNAL_HOSTNAME" else C.CYAN)
        clr  = clr if not no_color else ""
        rst  = C.RESET if not no_color else ""
        dim  = C.DIM if not no_color else ""
        print(f"\n  {clr}{C.BOLD if not no_color else ''}{icon} {cls}{rst}  {dim}({len(its)}){rst}")
        for item in its[:20]:
            print(f"  {dim}  ├─{rst} {item.value}  {dim}line {item.line_number} in {item.source_file.split('/')[-1]}{rst}")


def print_js_inventory(js_files: list, no_color: bool = False) -> None:
    if not js_files:
        return

    print(_section_header("JAVASCRIPT FILES DISCOVERED", len(js_files), C.CYAN))

    dim  = C.DIM if not no_color else ""
    grn  = C.GREEN if not no_color else ""
    rst  = C.RESET if not no_color else ""
    org  = C.ORANGE if not no_color else ""
    wht  = C.WHITE if not no_color else ""

    for js in js_files[:50]:
        size  = f"{js.size_bytes:,}" if js.size_bytes else "?"
        tech  = f" {grn}[{js.technology}]{rst}" if js.technology else ""
        smap  = f" {org}[source map]{rst}" if js.has_source_map else ""
        url   = js.url
        if url.startswith("sourcemap://"):
            url = f"{grn}[recovered]{rst} {url.replace('sourcemap://', '')}"
        elif url.startswith("local://"):
            url = f"{org}[local]{rst} {url.replace('local://', '')}"
        print(f"  {dim}├─{rst} {wht}{url}{rst}{tech}{smap}  {dim}{size} bytes{rst}")

    if len(js_files) > 50:
        print(f"  {dim}└─ ... and {len(js_files) - 50} more files{rst}")


def print_source_map_results(recovered_count: int, no_color: bool = False) -> None:
    if recovered_count == 0:
        return
    grn = C.GREEN if not no_color else ""
    rst = C.RESET if not no_color else ""
    dim = C.DIM if not no_color else ""
    print(f"\n  {grn}[+]{rst} Source Maps  {dim}→{rst}  Recovered {grn}{recovered_count}{rst} original source files")


def print_chunk_results(chunk_count: int, no_color: bool = False) -> None:
    if chunk_count == 0:
        return
    grn = C.GREEN if not no_color else ""
    rst = C.RESET if not no_color else ""
    dim = C.DIM if not no_color else ""
    print(f"  {grn}[+]{rst} Webpack Chunks  {dim}→{rst}  Discovered {grn}{chunk_count}{rst} additional chunks")


def print_passive_results(url_count: int, no_color: bool = False) -> None:
    if url_count == 0:
        return
    cyn = C.CYAN if not no_color else ""
    rst = C.RESET if not no_color else ""
    dim = C.DIM if not no_color else ""
    print(f"  {cyn}[*]{rst} Passive Mode  {dim}→{rst}  Pulled {cyn}{url_count}{rst} historical JS URLs from archives")


def print_headless_results(file_count: int, no_color: bool = False) -> None:
    if file_count == 0:
        return
    cyn = C.CYAN if not no_color else ""
    rst = C.RESET if not no_color else ""
    dim = C.DIM if not no_color else ""
    print(f"  {cyn}[*]{rst} Headless Browser  {dim}→{rst}  Captured {cyn}{file_count}{rst} dynamically loaded JS files")


def print_validation_results(results: list, no_color: bool = False) -> None:
    if not results:
        return

    interesting = [r for r in results if r.interesting]
    if not interesting:
        return

    print(_section_header("ENDPOINT VALIDATION RESULTS", len(interesting), C.GREEN))

    dim = C.DIM if not no_color else ""
    rst = C.RESET if not no_color else ""
    red = C.RED if not no_color else ""
    grn = C.GREEN if not no_color else ""
    org = C.ORANGE if not no_color else ""
    cyn = C.CYAN if not no_color else ""

    for r in interesting:
        if r.status_code == 200:
            sc = grn
        elif r.status_code in (401, 403):
            sc = org
        elif r.status_code in (301, 302):
            sc = cyn
        else:
            sc = dim

        notes = " | ".join(r.notes) if r.notes else ""
        print(f"\n  {sc}[{r.status_code}]{rst}  {r.endpoint}")
        if notes:
            print(f"  {dim}     └─ {notes}{rst}")
        if r.redirect_url:
            print(f"  {dim}     └─ → {r.redirect_url}{rst}")


def print_graphql_results(schemas: list, no_color: bool = False) -> None:
    if not schemas:
        return

    print(_section_header("GRAPHQL INTROSPECTION", len(schemas), C.PURPLE))

    dim = C.DIM if not no_color else ""
    rst = C.RESET if not no_color else ""
    red = C.RED if not no_color else ""
    cyn = C.CYAN if not no_color else ""
    org = C.ORANGE if not no_color else ""
    bld = C.BOLD if not no_color else ""

    for schema in schemas:
        print(f"\n  {cyn}{bld}Endpoint:{rst} {schema.endpoint}")
        if schema.error:
            print(f"  {dim}  Status: {schema.error}{rst}")
            continue
        print(f"  {dim}  ├─{rst} Query Type   : {schema.query_type or 'N/A'}")
        print(f"  {dim}  ├─{rst} Mutation Type: {schema.mutation_type or 'N/A'}")
        print(f"  {dim}  ├─{rst} Total Types  : {len(schema.types)}")
        if schema.queries:
            print(f"  {dim}  ├─{rst} Queries ({len(schema.queries)}):")
            for q in schema.queries[:10]:
                print(f"  {dim}  │    ├─{rst} {q}")
        if schema.mutations:
            print(f"  {dim}  ├─{rst} {org}Mutations ({len(schema.mutations)}):{rst}")
            for m in schema.mutations[:10]:
                print(f"  {dim}  │    ├─{rst} {org}{m}{rst}")
        if schema.sensitive_fields:
            print(f"  {dim}  └─{rst} {red}{bld}Sensitive Fields ({len(schema.sensitive_fields)}):{rst}")
            for sf in schema.sensitive_fields[:10]:
                print(f"  {dim}       ├─{rst} {red}{sf}{rst}")


def print_subdomains(subdomains: list, no_color: bool = False) -> None:
    if not subdomains:
        return

    print(_section_header("SUBDOMAINS DISCOVERED", len(subdomains), C.GREEN))

    dim = C.DIM if not no_color else ""
    grn = C.GREEN if not no_color else ""
    rst = C.RESET if not no_color else ""

    for sub in subdomains[:50]:
        print(f"  {dim}├─{rst} {grn}{sub}{rst}")
    if len(subdomains) > 50:
        print(f"  {dim}└─ ... and {len(subdomains) - 50} more{rst}")


def print_summary(result: ScanResult, extras: dict = None, no_color: bool = False) -> None:
    findings   = result.findings
    critical   = [f for f in findings if f.severity == "CRITICAL" and f.status != "likely_false_positive"]
    high       = [f for f in findings if f.severity == "HIGH"     and f.status != "likely_false_positive"]
    medium     = [f for f in findings if f.severity == "MEDIUM"   and f.status != "likely_false_positive"]
    low        = [f for f in findings if f.severity == "LOW"      and f.status != "likely_false_positive"]
    validated  = [f for f in findings if f.status == "validated"]
    fps        = [f for f in findings if f.status == "likely_false_positive"]

    extras = extras or {}

    red = C.RED if not no_color else ""
    org = C.ORANGE if not no_color else ""
    grn = C.GREEN if not no_color else ""
    cyn = C.CYAN if not no_color else ""
    dim = C.DIM if not no_color else ""
    bld = C.BOLD if not no_color else ""
    rst = C.RESET if not no_color else ""
    pur = C.PURPLE if not no_color else ""

    duration = ""
    if result.finished_at and result.started_at:
        secs = (result.finished_at - result.started_at).total_seconds()
        duration = f"{secs:.1f}s"

    print(f"\n{_divider('═', 72, cyn)}")
    print(f"{cyn}{bld}  SCAN COMPLETE{rst}  {dim}{duration}{rst}")
    print(f"{_divider('═', 72, cyn)}\n")

    print(f"  {dim}Target{rst}          {result.target_url}")
    print(f"  {dim}Pages crawled{rst}   {result.pages_crawled}")
    print(f"  {dim}JS files{rst}        {len(result.js_files)}")

    if extras.get("recovered_sources"):
        print(f"  {dim}Recovered sources{rst} {grn}{extras['recovered_sources']}{rst}")
    if extras.get("chunks_found"):
        print(f"  {dim}Chunks found{rst}    {grn}{extras['chunks_found']}{rst}")
    if extras.get("passive_urls"):
        print(f"  {dim}Archive URLs{rst}    {cyn}{extras['passive_urls']}{rst}")
    if extras.get("headless_files"):
        print(f"  {dim}Headless JS{rst}     {cyn}{extras['headless_files']}{rst}")

    print(f"  {dim}Endpoints{rst}       {len(result.endpoints)}")

    if extras.get("subdomains"):
        print(f"  {dim}Subdomains{rst}      {grn}{extras['subdomains']}{rst}")

    print(f"  {dim}Infrastructure{rst}  {len(result.infrastructure)}")
    print()

    # Findings breakdown
    print(f"  {dim}{'─' * 40}{rst}")
    print(f"  {dim}FINDINGS BREAKDOWN{rst}")
    print(f"  {dim}{'─' * 40}{rst}")

    if critical:
        print(f"  {red}{bld}💀 Critical     {len(critical):>4}{rst}")
    if high:
        print(f"  {org}🔴 High         {len(high):>4}{rst}")
    if medium:
        print(f"  {cyn}🟡 Medium       {len(medium):>4}{rst}")
    if low:
        print(f"  {C.BLUE if not no_color else ''}🔵 Low          {len(low):>4}{rst}")
    if validated:
        print(f"  {red}{bld}⚡ VALIDATED    {len(validated):>4}  ← CONFIRMED ACTIVE{rst}")
    if fps:
        print(f"  {dim}⚪ False pos.   {len(fps):>4}{rst}")
    if not any([critical, high, medium, low, validated, fps]):
        print(f"  {grn}✓  No findings{rst}")

    print()

    # Critical findings quick list
    if critical:
        print(f"  {red}{bld}[!] CRITICAL FINDINGS:{rst}")
        for f in critical[:5]:
            val = f.matched_value[:40] if len(f.matched_value) > 40 else f.matched_value
            print(f"  {red}    ├─ {f.title}{rst}  {dim}→ {val}{rst}")

    if result.errors:
        print(f"\n  {org}Errors: {len(result.errors)}{rst}")
        for e in result.errors[:3]:
            print(f"  {dim}  ├─ {e[:80]}{rst}")

    print(f"\n  {dim}No credentials validated. No exploitation performed.")
    print(f"  Private networks not contacted. Authorized assessment only.{rst}")
    print(f"\n{_divider('═', 72, cyn)}\n")


def print_report(
    result:          ScanResult,
    show_sensitive:  bool = True,
    no_color:        bool = False,
    min_severity:    str  = "INFO",
    extras:          dict = None,
    validation_results: list = None,
    graphql_schemas:    list = None,
    subdomains:         list = None,
) -> None:
    """Print the full terminal report."""
    extras = extras or {}
    order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    min_idx = order.index(min_severity) if min_severity in order else len(order)

    real_findings = [
        f for f in result.findings
        if order.index(f.severity) <= min_idx
        and f.status != "likely_false_positive"
    ]

    # ── JS Inventory ──────────────────────────────────────────────────────
    print_js_inventory(result.js_files, no_color=no_color)

    # ── Feature result lines ───────────────────────────────────────────────
    if extras.get("recovered_sources"):
        print_source_map_results(extras["recovered_sources"], no_color=no_color)
    if extras.get("chunks_found"):
        print_chunk_results(extras["chunks_found"], no_color=no_color)
    if extras.get("passive_urls"):
        print_passive_results(extras["passive_urls"], no_color=no_color)
    if extras.get("headless_files"):
        print_headless_results(extras["headless_files"], no_color=no_color)

    # ── Findings ───────────────────────────────────────────────────────────
    if real_findings:
        print(_section_header("FINDINGS", len(real_findings), C.RED if not no_color else ""))
        for f in sorted(real_findings, key=lambda x: order.index(x.severity)):
            print_finding(f, show_sensitive=show_sensitive, no_color=no_color)
    else:
        dim = C.DIM if not no_color else ""
        rst = C.RESET if not no_color else ""
        print(f"\n  {dim}No findings detected above the confidence threshold.{rst}")

    # ── Endpoints ──────────────────────────────────────────────────────────
    print_endpoints(result.endpoints, no_color=no_color)

    # ── Endpoint validation ────────────────────────────────────────────────
    if validation_results:
        print_validation_results(validation_results, no_color=no_color)

    # ── GraphQL ────────────────────────────────────────────────────────────
    if graphql_schemas:
        print_graphql_results(graphql_schemas, no_color=no_color)

    # ── Infrastructure ─────────────────────────────────────────────────────
    print_infrastructure(result.infrastructure, no_color=no_color)

    # ── Subdomains ─────────────────────────────────────────────────────────
    if subdomains:
        print_subdomains(subdomains, no_color=no_color)

    # ── Summary ────────────────────────────────────────────────────────────
    print_summary(result, extras=extras, no_color=no_color)
