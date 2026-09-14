"""
Printer — high-level print functions for every feature section.
Every output in BundleSpy goes through here.
"""

import sys
from typing import List, Optional
from datetime import datetime

from .theme import A, SEVERITY_COLOR, STATUS_COLOR
from .renderer import (
    section, kv, truncate_url, severity_badge, redact,
    two_col_table, count_table, severity_table, divider,
    bullet, progress_bar, _w,
)


def _p(text: str = "") -> None:
    print(text)


def _err(text: str) -> None:
    print(f"  {A.RED}Error:{A.RESET} {text}", file=sys.stderr)


# ── Header ────────────────────────────────────────────────────────────────────

def print_header(
    target:   str,
    mode:     str = "Active",
    scope:    str = "Strict",
    version:  str = "1.0.0",
    author:   str = "Mustafa Salha",
) -> None:
    ts = datetime.utcnow().strftime("%H:%M:%S UTC")
    _p()
    _p(f"  {A.BOLD}{A.WHITE}BundleSpy{A.RESET}  {A.GREY}v{version}  -  {author}{A.RESET}")
    _p(f"  {A.GREY}{divider()}{A.RESET}")
    _p(kv("Target",  truncate_url(target, 70), value_color=A.CYAN))
    _p(kv("Mode",    mode,   value_color=A.WHITE))
    _p(kv("Scope",   scope,  value_color=A.WHITE))
    _p(kv("Started", ts,     value_color=A.GREY))
    _p()


# ── Phase announcements ───────────────────────────────────────────────────────

def phase(label: str) -> None:
    _p(f"  {A.GREY}>{A.RESET} {label}")


def phase_done(label: str, detail: str = "") -> None:
    det = f"  {A.GREY}{detail}{A.RESET}" if detail else ""
    _p(f"  {A.GREEN}✓{A.RESET} {label}{det}")


def phase_warn(label: str) -> None:
    _p(f"  {A.YELLOW}!{A.RESET} {label}")


def phase_error(label: str) -> None:
    _p(f"  {A.RED}x{A.RESET} {label}", )


# ── Discovery ─────────────────────────────────────────────────────────────────

def print_discovery(
    pages:       int,
    js_files:    int,
    source_maps: int = 0,
    chunks:      int = 0,
    inline:      int = 0,
    duration:    float = 0.0,
) -> None:
    _p(section("DISCOVERY"))
    rows = [
        ("Pages crawled",    str(pages)),
        ("JavaScript files", str(js_files)),
    ]
    if source_maps:
        rows.append(("Source maps",  str(source_maps)))
    if chunks:
        rows.append(("Chunks",       str(chunks)))
    if inline:
        rows.append(("Inline scripts", str(inline)))
    _p(two_col_table(rows))
    if duration:
        _p(f"\n  {A.GREY}Discovery complete in {duration:.1f}s{A.RESET}")
    _p()


# ── JS Inventory ─────────────────────────────────────────────────────────────

def print_js_inventory(js_files: list, verbose: bool = False) -> None:
    if not js_files:
        return
    _p(section("JAVASCRIPT ASSETS", f"{len(js_files)} collected"))

    show = js_files if verbose else js_files[:20]
    for js in show:
        size = f"{js.size_bytes:,}b" if js.size_bytes else "?"
        tech = f"  {A.GREY}[{js.technology}]{A.RESET}" if js.technology else ""
        smap = f"  {A.YELLOW}[map]{A.RESET}" if js.has_source_map else ""
        url  = truncate_url(js.url, _w() - 20)

        prefix = ""
        if js.url.startswith("sourcemap://"):
            url    = js.url.replace("sourcemap://", "")
            prefix = f"  {A.GREEN}recovered{A.RESET}  "
        elif js.url.startswith("local://"):
            url    = js.url.replace("local://", "")
            prefix = f"  {A.YELLOW}local{A.RESET}     "

        _p(f"  {A.GREY}•{A.RESET} {prefix}{url}{tech}{smap}  {A.GREY}{size}{A.RESET}")

    if not verbose and len(js_files) > 20:
        _p(f"  {A.GREY}... and {len(js_files) - 20} more  (use -v to show all){A.RESET}")
    _p()


# ── Source maps ───────────────────────────────────────────────────────────────

def print_source_maps(
    discovered:  int,
    valid:       int,
    recovered:   int,
    sources:     int,
    details:     list = None,
) -> None:
    _p(section("SOURCE MAPS"))
    _p(two_col_table([
        ("Discovered",  str(discovered)),
        ("Valid",       str(valid)),
        ("Recovered",   str(recovered)),
        ("Sources",     str(sources)),
    ]))
    if details:
        _p()
        for d in details:
            _p(f"  {A.WHITE}{d.get('js','')}{A.RESET}")
            _p(f"  {A.GREY}└─ {d.get('map','')}{A.RESET}")
            if d.get("sources"):
                _p(f"     {A.GREY}├─ {d['sources']} original sources{A.RESET}")
            if d.get("endpoints"):
                _p(f"     {A.GREY}├─ {d['endpoints']} endpoints{A.RESET}")
            if d.get("findings"):
                _p(f"     {A.GREY}└─ {d['findings']} potential secrets{A.RESET}")
    _p()


# ── Webpack ───────────────────────────────────────────────────────────────────

def print_webpack(
    runtime:    bool,
    discovered: int,
    downloaded: int,
    endpoints:  int = 0,
    findings:   int = 0,
) -> None:
    _p(section("WEBPACK"))
    rows = [
        ("Runtime detected", "yes" if runtime else "no"),
        ("Chunks discovered", str(discovered)),
        ("Chunks downloaded", str(downloaded)),
    ]
    if endpoints:
        rows.append(("New endpoints", str(endpoints)))
    if findings:
        rows.append(("New findings",  str(findings)))
    _p(two_col_table(rows))
    _p()


# ── Passive ───────────────────────────────────────────────────────────────────

def print_passive(
    source:   str,
    urls:     int,
    js:       int,
    unique:   int,
    new:      int,
) -> None:
    _p(section("PASSIVE DISCOVERY"))
    _p(two_col_table([
        ("Source",     source),
        ("URLs found", str(urls)),
        ("JS assets",  str(js)),
        ("Unique",     str(unique)),
        ("New assets", str(new)),
    ]))
    _p()


# ── Headless ─────────────────────────────────────────────────────────────────

def print_headless(
    pages:      int,
    js:         int,
    xhr:        int = 0,
    fetch:      int = 0,
    ws:         int = 0,
    chunks:     int = 0,
    endpoints:  int = 0,
    routes:     int = 0,
) -> None:
    _p(section("BROWSER DISCOVERY"))
    rows = [
        ("Engine",      "Chromium (advanced)"),
        ("Pages visited", str(pages)),
        ("JS assets",   str(js)),
    ]
    if xhr or fetch:
        rows.append(("XHR/fetch calls", str(xhr + fetch)))
    if ws:
        rows.append(("WebSockets",    str(ws)))
    if routes:
        rows.append(("Routes found",  str(routes)))
    if endpoints:
        rows.append(("API endpoints", str(endpoints)))
    _p(two_col_table(rows))
    _p()


# ── Endpoints ─────────────────────────────────────────────────────────────────

def print_endpoints(
    endpoints:          list,
    validation_results: list = None,
    verbose:            bool = False,
) -> None:
    if not endpoints:
        return

    # Count by category
    by_cat: dict = {}
    for ep in endpoints:
        by_cat.setdefault(ep.category, []).append(ep)

    auth_count   = len(by_cat.get("AUTH", []))
    admin_count  = len(by_cat.get("ADMIN", []))
    gql_count    = len(by_cat.get("GRAPHQL", []))
    api_count    = len(by_cat.get("API", []))
    ext_count    = sum(1 for ep in endpoints if ep.url.startswith("http") and _is_external(ep.url, endpoints))

    _p(section("ENDPOINTS", f"{len(endpoints)} discovered"))
    rows = [("Total", str(len(endpoints)))]
    if api_count:
        rows.append(("API",        str(api_count)))
    if gql_count:
        rows.append(("GraphQL",    str(gql_count)))
    if auth_count:
        rows.append(("Auth-related", str(auth_count)))
    if admin_count:
        rows.append(("Admin",      str(admin_count)))
    _p(two_col_table(rows))

    # Build validation lookup
    val_map: dict = {}
    if validation_results:
        for r in validation_results:
            val_map[r.endpoint] = r

    # Show endpoints — with or without validation
    _p()
    order = ["AUTH", "ADMIN", "GRAPHQL", "UPLOAD", "DOWNLOAD", "API", "WEBSOCKET", "UNKNOWN"]
    shown = 0
    limit = 9999 if verbose else 60

    for cat in order:
        eps = by_cat.get(cat, [])
        if not eps:
            continue
        cat_color = A.RED if cat in ("AUTH", "ADMIN") else (A.PURPLE if cat == "GRAPHQL" else A.BLUE)
        _p(f"  {cat_color}{A.BOLD}{cat}{A.RESET}")
        for ep in eps:
            if shown >= limit:
                break
            method = (ep.method or "?").ljust(6)
            path   = truncate_url(ep.url, _w() - 30)
            vr     = val_map.get(ep.url)
            if vr:
                sc    = str(vr.status_code).rjust(4)
                sc_c  = A.GREEN if vr.status_code == 200 else (A.YELLOW if vr.status_code in (301,302,307) else A.RED)
                ct    = vr.content_type.split(";")[0][:25] if vr.content_type else ""
                _p(f"  {A.GREY}{method}{A.RESET}  {path}  {sc_c}{sc}{A.RESET}  {A.GREY}{ct}{A.RESET}")
            else:
                _p(f"  {A.GREY}{method}{A.RESET}  {path}")
            shown += 1

    if not verbose and shown >= limit:
        _p(f"\n  {A.GREY}... use -v to show all {len(endpoints)} endpoints{A.RESET}")
    _p()


def _is_external(url: str, endpoints: list) -> bool:
    return False  # placeholder


# ── GraphQL ───────────────────────────────────────────────────────────────────

def print_graphql(schemas: list) -> None:
    if not schemas:
        return

    total_types     = sum(len(s.types)     for s in schemas if not s.error)
    total_queries   = sum(len(s.queries)   for s in schemas if not s.error)
    total_mutations = sum(len(s.mutations) for s in schemas if not s.error)
    enabled         = sum(1 for s in schemas if not s.error)

    _p(section("GRAPHQL"))
    _p(two_col_table([
        ("Endpoints",     str(len(schemas))),
        ("Introspection", "enabled" if enabled else "disabled"),
        ("Types",         str(total_types)),
        ("Queries",       str(total_queries)),
        ("Mutations",     str(total_mutations)),
    ]))

    for schema in schemas:
        _p()
        _p(f"  {A.WHITE}{truncate_url(schema.endpoint)}{A.RESET}")
        if schema.error:
            _p(f"  {A.GREY}  Status: {schema.error}{A.RESET}")
            continue
        if schema.queries:
            _p(f"  {A.GREY}  Queries:   {', '.join(schema.queries[:8])}{A.RESET}")
        if schema.mutations:
            _p(f"  {A.YELLOW}  Mutations: {', '.join(schema.mutations[:8])}{A.RESET}")
        if schema.sensitive_fields:
            _p(f"  {A.RED}  Sensitive: {', '.join(schema.sensitive_fields[:6])}{A.RESET}")
    _p()


# ── Infrastructure ────────────────────────────────────────────────────────────

def print_infrastructure(items: list) -> None:
    if not items:
        return

    by_cls: dict = {}
    for item in items:
        by_cls.setdefault(item.classification, []).append(item)

    _p(section("INFRASTRUCTURE INTELLIGENCE", f"{len(items)} indicators"))

    for cls, its in sorted(by_cls.items()):
        cls_c = A.RED if cls in ("PRIVATE_IP", "CLOUD_METADATA") else (A.YELLOW if "HOSTNAME" in cls else A.GREY)
        _p(f"\n  {cls_c}{cls}{A.RESET}  {A.GREY}({len(its)}){A.RESET}")
        for item in its[:15]:
            fname = item.source_file.split("/")[-1] if "/" in item.source_file else item.source_file
            _p(f"  {A.GREY}  •{A.RESET} {item.value}  {A.GREY}line {item.line_number} in {fname}{A.RESET}")
    _p()


# ── Subdomains ────────────────────────────────────────────────────────────────

def print_subdomains(subdomains: list) -> None:
    if not subdomains:
        return

    _p(section("SUBDOMAINS", f"{len(subdomains)} discovered"))
    for sub in subdomains[:40]:
        _p(f"  {A.GREY}•{A.RESET} {sub}")
    if len(subdomains) > 40:
        _p(f"  {A.GREY}... and {len(subdomains) - 40} more{A.RESET}")
    _p()


# ── Secret analysis ───────────────────────────────────────────────────────────

def print_secret_analysis(findings: list) -> None:
    if not findings:
        return

    total      = len(findings)
    high_conf  = sum(1 for f in findings if f.confidence >= 0.85 and f.status != "likely_false_positive")
    validated  = sum(1 for f in findings if f.status == "validated")
    fps        = sum(1 for f in findings if f.status == "likely_false_positive")

    _p(section("SECRET ANALYSIS"))
    _p(two_col_table([
        ("Detected",        str(total)),
        ("High confidence", str(high_conf)),
        ("Likely FP",       str(fps)),
        ("Validated",       str(validated) if validated else "0"),
    ]))
    _p()


# ── Findings ──────────────────────────────────────────────────────────────────

def print_findings(findings: list, verbose: bool = False) -> None:
    real = [f for f in findings if f.status != "likely_false_positive"]
    fps  = [f for f in findings if f.status == "likely_false_positive"]

    if not real and not fps:
        _p(section("FINDINGS"))
        _p(f"  {A.GREY}No findings detected above the confidence threshold.{A.RESET}")
        _p()
        return

    # Severity counts
    counts: dict = {}
    for f in real:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    _p(section("FINDINGS", f"{len(real)} confirmed  {A.GREY}({len(fps)} likely FP excluded){A.RESET}"))
    _p(severity_table(counts))
    _p()

    # Print each finding
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for f in sorted(real, key=lambda x: order.index(x.severity) if x.severity in order else 99):
        _print_finding(f, verbose=verbose)

    if fps and verbose:
        _p(f"\n  {A.GREY}--- Likely false positives ({len(fps)}) ---{A.RESET}")
        for f in fps:
            _p(f"  {A.GREY}•{A.RESET} {f.title}  {A.GREY}{f.file_url.split('/')[-1]}:{f.line_number}{A.RESET}")
    _p()


def _print_finding(f, verbose: bool = False) -> None:
    badge = severity_badge(f.severity)
    sev_c = SEVERITY_COLOR.get(f.severity, "")
    rst   = A.RESET

    _p(f"{badge}  {sev_c}{f.title}{rst}")
    _p()
    _p(f"  {A.GREY}Location{rst}")
    _p(f"  {A.WHITE}{truncate_url(f.file_url)}:{f.line_number}{rst}")
    _p()
    _p(f"  {A.GREY}Type{rst}")
    _p(f"  {f.category}  {A.GREY}({f.rule_id}){rst}")
    _p()
    _p(f"  {A.GREY}Confidence{rst}")
    _p(f"  {f.confidence:.0%}  {A.GREY}{f.status}{rst}")
    _p()
    _p(f"  {A.GREY}Evidence{rst}")

    # Redact only actual secrets — show infrastructure/endpoint values as-is
    val = f.matched_value
    _p(f"  {sev_c}{val}{rst}")

    if f.context and verbose:
        _p()
        _p(f"  {A.GREY}Context{rst}")
        ctx = f.context[:120].replace("\n", " ").strip()
        _p(f"  {A.GREY}{ctx}{rst}")

    if f.remediation:
        _p()
        _p(f"  {A.GREY}Recommendation{rst}")
        _p(f"  {f.remediation[:120]}")

    if f.status == "validated":
        _p()
        _p(f"  {A.RED}{A.BOLD}VALIDATED — Secret confirmed active{rst}")
        _p(f"  {A.RED}Provider: {f.description.split('VALIDATED:')[-1].strip()[:80] if 'VALIDATED:' in f.description else 'confirmed'}{rst}")

    _p()
    _p(f"  {A.GREY}{'─' * 48}{A.RESET}")
    _p()


# ── Final summary ─────────────────────────────────────────────────────────────

def print_summary(
    result,
    extras:      dict = None,
    report_paths: dict = None,
) -> None:
    extras = extras or {}
    report_paths = report_paths or {}

    findings = result.findings
    real     = [f for f in findings if f.status != "likely_false_positive"]

    counts: dict = {}
    for f in real:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    duration = ""
    if result.finished_at and result.started_at:
        secs     = (result.finished_at - result.started_at).total_seconds()
        duration = f"{secs:.1f}s"

    _p()
    _p(f"  {A.BOLD}{A.WHITE}SCAN COMPLETE{A.RESET}")
    _p(f"  {A.GREY}{divider()}{A.RESET}")
    _p()
    _p(f"  {A.GREY}Target{A.RESET}")
    _p(f"  {A.CYAN}{truncate_url(result.target_url, 70)}{A.RESET}")
    if duration:
        _p()
        _p(f"  {A.GREY}Duration{A.RESET}")
        _p(f"  {duration}")

    # Assets
    _p()
    _p(f"  {A.GREY}Assets{A.RESET}")
    js_count = len([js for js in result.js_files if not js.url.startswith("sourcemap://")])
    _p(f"  {js_count} JavaScript files")
    if extras.get("recovered_sources"):
        _p(f"  {extras['recovered_sources']} recovered source files")
    if extras.get("chunks_found"):
        _p(f"  {extras['chunks_found']} webpack chunks")
    if extras.get("passive_urls"):
        _p(f"  {extras['passive_urls']} archive URLs collected")

    # Intelligence
    _p()
    _p(f"  {A.GREY}Intelligence{A.RESET}")
    _p(f"  {len(result.endpoints)} endpoints")
    if extras.get("subdomains"):
        _p(f"  {extras['subdomains']} subdomains")
    if extras.get("graphql_queries"):
        _p(f"  {extras['graphql_queries']} GraphQL operations")
    if real:
        _p(f"  {len(real)} secrets / potential secrets")
    if result.infrastructure:
        _p(f"  {len(result.infrastructure)} infrastructure indicators")

    # Findings
    _p()
    _p(f"  {A.GREY}Findings{A.RESET}")
    if counts:
        _p(severity_table(counts))
    else:
        _p(f"  {A.GREEN}none{A.RESET}")

    # Reports
    if report_paths:
        _p()
        _p(f"  {A.GREY}Reports{A.RESET}")
        for fmt, path in report_paths.items():
            _p(f"  {fmt.upper().ljust(6)}  {A.GREY}{path}{A.RESET}")

    _p()
    if counts.get("CRITICAL") or counts.get("HIGH"):
        _p(f"  {A.RED}Completed with critical findings. Immediate action required.{A.RESET}")
    else:
        _p(f"  {A.GREEN}Completed successfully.{A.RESET}")
    _p()
