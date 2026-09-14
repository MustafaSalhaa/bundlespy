"""
BundleSpy terminal UI — clean, modern, professional.
Every section is consistent, readable, and information-dense.
No noise. No clutter. Maximum signal.
"""

import os
import sys
import shutil
from typing import List, Optional, Dict
from datetime import datetime

from .theme import A
from .renderer import divider, two_col_table, severity_table, truncate_url, redact, section, _w


def _p(text: str = "") -> None:
    print(text)


def _w() -> int:
    try:
        return min(shutil.get_terminal_size((80, 24)).columns, 110)
    except Exception:
        return 80


def _line(char: str = "─", color: str = "") -> str:
    rst = A.RESET if color else ""
    return f"{color}{char * _w()}{rst}"


def _label(text: str, width: int = 18) -> str:
    return f"{A.GREY}{text.ljust(width)}{A.RESET}"


def _val(text: str, color: str = "") -> str:
    rst = A.RESET if color else ""
    return f"{color}{text}{rst}"


def _badge(severity: str) -> str:
    colors = {
        "CRITICAL": A.RED + A.BOLD,
        "HIGH":     A.ORANGE + A.BOLD,
        "MEDIUM":   A.YELLOW,
        "LOW":      A.BLUE,
        "INFO":     A.GREY,
    }
    c = colors.get(severity, A.GREY)
    return f"{c}{severity:<8}{A.RESET}"


# ── Header ────────────────────────────────────────────────────────────────────

def print_header(
    target:  str,
    mode:    str = "Active",
    scope:   str = "Strict",
    version: str = "1.0.0",
    author:  str = "Mustafa Salha",
) -> None:
    ts = datetime.utcnow().strftime("%Y-%m-%d  %H:%M UTC")
    _p()
    _p(f"  {A.WHITE}{A.BOLD}BundleSpy{A.RESET}  {A.GREY}v{version}{A.RESET}")
    _p(f"  {A.GREY}{_line()}{A.RESET}")
    _p(f"  {_label('Target')}{A.CYAN}{truncate_url(target, _w() - 22)}{A.RESET}")
    _p(f"  {_label('Mode')}{mode}")
    _p(f"  {_label('Scope')}{scope}")
    _p(f"  {_label('Started')}{A.GREY}{ts}{A.RESET}")
    _p()


# ── Phase lines ───────────────────────────────────────────────────────────────

def phase(label: str) -> None:
    _p(f"  {A.GREY}›{A.RESET}  {label}")


def phase_done(label: str, detail: str = "") -> None:
    det = f"  {A.GREY}{detail}{A.RESET}" if detail else ""
    _p(f"  {A.GREEN}✓{A.RESET}  {label}{det}")


def phase_warn(label: str) -> None:
    _p(f"  {A.YELLOW}!{A.RESET}  {label}")


def phase_error(label: str) -> None:
    print(f"  {A.RED}✗{A.RESET}  {label}", file=sys.stderr)


# ── Section header ─────────────────────────────────────────────────────────────

def _section(title: str, count: str = "", color: str = "") -> None:
    c   = color or A.WHITE
    cnt = f"  {A.GREY}({count}){A.RESET}" if count else ""
    _p()
    _p(f"  {c}{A.BOLD}{title}{A.RESET}{cnt}")
    _p(f"  {A.GREY}{_line('─')}{A.RESET}")


# ── JS Inventory ──────────────────────────────────────────────────────────────

def print_js_inventory(js_files: list, verbose: bool = False) -> None:
    if not js_files:
        return

    show = js_files if verbose else js_files[:15]
    _section("JAVASCRIPT ASSETS", str(len(js_files)), A.CYAN)

    for js in show:
        size  = f"{js.size_bytes:,}b" if js.size_bytes else "?"
        tech  = f"  {A.GREY}[{js.technology}]{A.RESET}" if js.technology else ""
        smap  = f"  {A.YELLOW}map{A.RESET}" if js.has_source_map else ""
        url   = js.url

        prefix = ""
        if url.startswith("sourcemap://"):
            url    = url.replace("sourcemap://", "")
            prefix = f"{A.GREEN}recovered  {A.RESET}"
        elif url.startswith("local://"):
            url    = url.replace("local://", "")
            prefix = f"{A.YELLOW}local      {A.RESET}"
        elif url.startswith("inline:"):
            prefix = f"{A.GREY}inline     {A.RESET}"
            url    = url.replace("inline:", "")
        elif url.startswith("html:"):
            prefix = f"{A.BLUE}html       {A.RESET}"
            url    = url.replace("html:", "")

        url = truncate_url(url, _w() - 28)
        _p(f"  {A.GREY}  {prefix}{A.RESET}{url}{tech}{smap}  {A.GREY}{size}{A.RESET}")

    if not verbose and len(js_files) > 15:
        _p(f"  {A.GREY}  ... and {len(js_files) - 15} more  (-v to show all){A.RESET}")
    _p()


# ── Feature summaries ─────────────────────────────────────────────────────────

def print_source_maps(discovered, valid, recovered, sources, details=None):
    if not discovered:
        return
    _section("SOURCE MAPS", "", A.YELLOW)
    rows = [
        ("Discovered", str(discovered)),
        ("Valid",      str(valid)),
        ("Recovered",  str(recovered)),
        ("Sources",    str(sources)),
    ]
    for label, val in rows:
        _p(f"  {_label(label, 14)}{val}")
    if details:
        for d in details:
            _p(f"\n  {A.WHITE}{d.get('js','')}{A.RESET}")
            _p(f"  {A.GREY}  └─ {d.get('map','')}{A.RESET}")
            if d.get("sources"):
                _p(f"  {A.GREY}     ├─ {d['sources']} original sources{A.RESET}")
    _p()


def print_webpack(runtime, discovered, downloaded, endpoints=0, findings=0):
    if not discovered:
        return
    _section("WEBPACK CHUNKS", "", A.YELLOW)
    rows = [
        ("Runtime",    "detected" if runtime else "not found"),
        ("Discovered", str(discovered)),
        ("Downloaded", str(downloaded)),
    ]
    if endpoints:
        rows.append(("New endpoints", str(endpoints)))
    if findings:
        rows.append(("New findings",  str(findings)))
    for label, val in rows:
        _p(f"  {_label(label, 14)}{val}")
    _p()


def print_passive(source, urls, js, unique, new):
    _section("PASSIVE DISCOVERY", "", A.CYAN)
    rows = [
        ("Source",     source),
        ("URLs found", str(urls)),
        ("JS assets",  str(js)),
        ("Unique",     str(unique)),
        ("New",        str(new)),
    ]
    for label, val in rows:
        _p(f"  {_label(label, 14)}{val}")
    _p()


def print_headless(pages, js, xhr=0, fetch=0, ws=0, routes=0, endpoints=0):
    _section("BROWSER DISCOVERY", "", A.CYAN)
    rows = [
        ("Engine",      "Chromium"),
        ("Pages",       str(pages)),
        ("JS captured", str(js)),
    ]
    if xhr or fetch:
        rows.append(("API calls", str(xhr + fetch)))
    if ws:
        rows.append(("WebSockets", str(ws)))
    if routes:
        rows.append(("Routes",    str(routes)))
    if endpoints:
        rows.append(("Endpoints", str(endpoints)))
    for label, val in rows:
        _p(f"  {_label(label, 14)}{val}")
    _p()


def _print_libraries(lib_findings: list) -> None:
    """Print vulnerable library findings — clean, clear, reportable."""
    if not lib_findings:
        return

    sev_colors = {
        "CRITICAL": A.RED + A.BOLD,
        "HIGH":     A.ORANGE + A.BOLD,
        "MEDIUM":   A.YELLOW,
        "LOW":      A.BLUE,
    }

    counts: dict = {}
    for lf in lib_findings:
        counts[lf.severity] = counts.get(lf.severity, 0) + 1

    _section("VULNERABLE LIBRARIES", str(len(lib_findings)), A.RED)

    # Summary counts
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts.get(sev):
            c = sev_colors.get(sev, "")
            _p(f"  {c}{sev:<10}{A.RESET}  {counts[sev]}")
    _p()

    # Individual findings
    shown_libs = set()
    for lf in sorted(lib_findings, key=lambda x: -x.cvss):
        c = sev_colors.get(lf.severity, "")

        lib_key = f"{lf.library}:{lf.version}"
        is_new  = lib_key not in shown_libs
        shown_libs.add(lib_key)

        if is_new:
            _p(f"  {c}{lf.severity:<8}{A.RESET}  {A.WHITE}{A.BOLD}{lf.library} v{lf.version}{A.RESET}")
            fname = lf.source_file.split("/")[-1] if "/" in lf.source_file else lf.source_file
            _p(f"  {_label('File', 14)}{fname}")
        else:
            _p(f"  {A.GREY}{'':8}{A.RESET}  {A.GREY}+ additional CVE{A.RESET}")

        _p(f"  {_label('CVE', 14)}{c}{lf.cve_id}{A.RESET}  {A.GREY}CVSS {lf.cvss}{A.RESET}")
        _p(f"  {_label('Issue', 14)}{lf.description}")
        _p(f"  {_label('Fix', 14)}{lf.remediation}")
        _p(f"  {A.GREY}{'─' * 60}{A.RESET}")
        _p()


def _print_intelligence(intel) -> None:
    has = (intel.sitemap_urls or intel.api_endpoints or
           intel.security_txt or intel.openid_config or intel.api_schema)
    if not has:
        return

    _section("PASSIVE INTELLIGENCE", "", A.PURPLE)

    if intel.sitemap_urls:
        _p(f"  {_label('Sitemap URLs', 16)}{len(intel.sitemap_urls)}")
        for url in intel.sitemap_urls[:8]:
            _p(f"  {A.GREY}  • {truncate_url(url, _w() - 8)}{A.RESET}")
        if len(intel.sitemap_urls) > 8:
            _p(f"  {A.GREY}  ... and {len(intel.sitemap_urls) - 8} more{A.RESET}")

    if intel.api_schema:
        _p(f"\n  {_label('API Schema', 16)}{intel.api_schema.get('type', '?')}  {A.GREY}{intel.api_schema.get('url', '')}{A.RESET}")
        for ep in intel.api_endpoints[:12]:
            _p(f"  {A.GREY}  • {ep}{A.RESET}")

    if intel.security_txt:
        _p(f"\n  {_label('security.txt', 16)}{A.GREEN}found{A.RESET}")
        for line in intel.security_txt.splitlines()[:5]:
            if line.strip() and not line.startswith("#"):
                _p(f"  {A.GREY}  {line.strip()}{A.RESET}")

    if intel.openid_config:
        _p(f"\n  {_label('OpenID Config', 16)}{A.YELLOW}found{A.RESET}")
        if isinstance(intel.openid_config, dict):
            for k in ["issuer", "authorization_endpoint", "token_endpoint"]:
                if k in intel.openid_config:
                    _p(f"  {A.GREY}  {k}: {intel.openid_config[k]}{A.RESET}")
    _p()


# ── Secret analysis ───────────────────────────────────────────────────────────

def print_secret_analysis(findings: list) -> None:
    if not findings:
        return
    total     = len(findings)
    high_conf = sum(1 for f in findings if f.confidence >= 0.85 and f.status != "likely_false_positive")
    validated = sum(1 for f in findings if f.status == "validated")
    fps       = sum(1 for f in findings if f.status == "likely_false_positive")

    _section("SECRET ANALYSIS", "", A.RED)
    for label, val, color in [
        ("Detected",        str(total),      ""),
        ("High confidence", str(high_conf),  A.RED if high_conf else ""),
        ("Likely FP",       str(fps),        A.GREY),
        ("Validated",       str(validated),  A.RED + A.BOLD if validated else ""),
    ]:
        _p(f"  {_label(label, 18)}{_val(val, color)}")
    _p()


# ── Findings ──────────────────────────────────────────────────────────────────

def print_findings(findings: list, verbose: bool = False, show_fp: bool = False) -> None:
    real = [f for f in findings if f.status != "likely_false_positive"]
    fps  = [f for f in findings if f.status == "likely_false_positive"]

    if not real and not fps:
        _section("FINDINGS")
        _p(f"  {A.GREY}No findings detected above the confidence threshold.{A.RESET}")
        _p()
        return

    counts: dict = {}
    for f in real:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_colors = {
        "CRITICAL": A.RED + A.BOLD,
        "HIGH":     A.ORANGE + A.BOLD,
        "MEDIUM":   A.YELLOW,
        "LOW":      A.BLUE,
        "INFO":     A.GREY,
    }

    fp_note = f"  {A.GREY}+{len(fps)} FP excluded{A.RESET}" if fps else ""
    _section("FINDINGS", f"{len(real)} confirmed{fp_note}", A.RED)

    # Severity breakdown
    for sev in order:
        if counts.get(sev):
            c = sev_colors.get(sev, "")
            _p(f"  {c}{sev:<10}{A.RESET}  {counts[sev]}")
    _p()

    # Individual findings
    for f in sorted(real, key=lambda x: order.index(x.severity) if x.severity in order else 99):
        _print_finding(f, verbose=verbose)

    if fps and (verbose or show_fp):
        _p(f"  {A.GREY}{'─' * 40}{A.RESET}")
        _p(f"  {A.GREY}Likely false positives ({len(fps)}){A.RESET}")
        for f in fps[:10]:
            fname = f.file_url.split("/")[-1] if "/" in f.file_url else f.file_url
            _p(f"  {A.GREY}  • {f.title}  {fname}:{f.line_number}  {f.matched_value[:40]}{A.RESET}")
    _p()


def _print_finding(f, verbose: bool = False) -> None:
    sev_colors = {
        "CRITICAL": A.RED + A.BOLD,
        "HIGH":     A.ORANGE + A.BOLD,
        "MEDIUM":   A.YELLOW,
        "LOW":      A.BLUE,
        "INFO":     A.GREY,
    }
    sc  = sev_colors.get(f.severity, "")
    rst = A.RESET

    # Finding header
    _p(f"  {sc}{f.severity:<8}{rst}  {A.WHITE}{A.BOLD}{f.title}{rst}  {A.GREY}({f.rule_id}){rst}")
    _p()

    # Location
    url  = truncate_url(f.file_url, _w() - 6)
    _p(f"  {_label('Location', 14)}{url}  {A.GREY}line {f.line_number}{rst}")

    # Category and confidence
    status_colors = {
        "likely_secret":         A.RED,
        "validated":             A.RED + A.BOLD,
        "candidate":             A.YELLOW,
        "likely_false_positive": A.GREY,
    }
    sc2 = status_colors.get(f.status, "")
    _p(f"  {_label('Type', 14)}{f.category}")
    _p(f"  {_label('Confidence', 14)}{f.confidence:.0%}  {sc2}{f.status}{rst}")

    # Evidence — always show full value
    _p(f"  {_label('Evidence', 14)}{sc}{f.matched_value}{rst}")

    # Context
    if f.context and verbose:
        ctx = f.context[:120].replace("\n", " ").strip()
        _p(f"  {_label('Context', 14)}{A.GREY}{ctx}{rst}")

    # Recommendation
    _p(f"  {_label('Fix', 14)}{f.remediation[:100]}")

    # Validated
    if f.status == "validated":
        _p(f"  {A.RED}{A.BOLD}  ⚡ CONFIRMED ACTIVE — immediate action required{rst}")

    _p(f"  {A.GREY}{'─' * 60}{rst}")
    _p()


# ── Endpoints ─────────────────────────────────────────────────────────────────

def print_endpoints(endpoints: list, validation_results: list = None, verbose: bool = False) -> None:
    if not endpoints:
        return

    by_cat: dict = {}
    for ep in endpoints:
        by_cat.setdefault(ep.category, []).append(ep)

    val_map: dict = {}
    if validation_results:
        for r in validation_results:
            val_map[r.endpoint] = r

    total = len(endpoints)
    _section("ENDPOINTS", str(total), A.BLUE)

    # Summary counts
    for cat in ["AUTH", "ADMIN", "GRAPHQL", "API", "WEBSOCKET", "UPLOAD", "DOWNLOAD", "UNKNOWN"]:
        eps = by_cat.get(cat, [])
        if not eps:
            continue
        cat_colors = {
            "AUTH":      A.RED,
            "ADMIN":     A.ORANGE,
            "GRAPHQL":   A.PURPLE,
            "API":       A.BLUE,
            "WEBSOCKET": A.CYAN,
        }
        c = cat_colors.get(cat, A.GREY)
        _p(f"  {c}{A.BOLD}{cat:<12}{A.RESET}  {len(eps)}")

    _p()

    # Endpoint list
    shown = 0
    limit = 9999 if verbose else 40

    for cat in ["AUTH", "ADMIN", "GRAPHQL", "UPLOAD", "DOWNLOAD", "API", "WEBSOCKET", "UNKNOWN"]:
        eps = by_cat.get(cat, [])
        if not eps:
            continue
        cat_colors = {
            "AUTH":    A.RED,
            "ADMIN":   A.ORANGE,
            "GRAPHQL": A.PURPLE,
            "API":     A.BLUE,
        }
        c = cat_colors.get(cat, A.GREY)

        for ep in eps:
            if shown >= limit:
                break
            method = (ep.method or "?").ljust(5)
            url    = truncate_url(ep.url, _w() - 20)
            vr     = val_map.get(ep.url)

            if vr:
                sc = A.GREEN if vr.status_code == 200 else (A.YELLOW if vr.status_code in (301,302,307) else (A.RED if vr.status_code in (401,403) else A.GREY))
                ct = vr.content_type.split(";")[0][:20] if vr.content_type else ""
                _p(f"  {A.GREY}{method}{A.RESET}  {c}{url}{A.RESET}  {sc}{vr.status_code}{A.RESET}  {A.GREY}{ct}{A.RESET}")
            else:
                _p(f"  {A.GREY}{method}{A.RESET}  {c}{url}{A.RESET}")
            shown += 1

    if shown >= limit and not verbose:
        _p(f"\n  {A.GREY}  ... use -v to show all {total} endpoints{A.RESET}")
    _p()


# ── GraphQL ───────────────────────────────────────────────────────────────────

def print_graphql(schemas: list) -> None:
    if not schemas:
        return

    total_types     = sum(len(s.types)     for s in schemas if not s.error)
    total_queries   = sum(len(s.queries)   for s in schemas if not s.error)
    total_mutations = sum(len(s.mutations) for s in schemas if not s.error)

    _section("GRAPHQL", "", A.PURPLE)
    _p(f"  {_label('Endpoints',     14)}{len(schemas)}")
    _p(f"  {_label('Introspection', 14)}{'enabled' if any(not s.error for s in schemas) else 'disabled'}")
    _p(f"  {_label('Types',         14)}{total_types}")
    _p(f"  {_label('Queries',       14)}{total_queries}")
    _p(f"  {_label('Mutations',     14)}{total_mutations}")

    for schema in schemas:
        _p(f"\n  {A.WHITE}{truncate_url(schema.endpoint)}{A.RESET}")
        if schema.error:
            _p(f"  {A.GREY}  Status: {schema.error}{A.RESET}")
            continue
        if schema.queries:
            _p(f"  {A.GREY}  Queries:{A.RESET}   {', '.join(schema.queries[:8])}")
        if schema.mutations:
            _p(f"  {A.ORANGE}  Mutations:{A.RESET}  {', '.join(schema.mutations[:8])}")
        if schema.sensitive_fields:
            _p(f"  {A.RED}  Sensitive:{A.RESET}  {', '.join(schema.sensitive_fields[:6])}")
    _p()


# ── Infrastructure ────────────────────────────────────────────────────────────

def print_infrastructure(items: list) -> None:
    if not items:
        return

    by_cls: dict = {}
    for item in items:
        by_cls.setdefault(item.classification, []).append(item)

    _section("INFRASTRUCTURE", str(len(items)), A.YELLOW)

    for cls, its in sorted(by_cls.items()):
        cls_c = A.RED if cls in ("PRIVATE_IP", "CLOUD_METADATA") else (A.ORANGE if "HOSTNAME" in cls else A.GREY)
        _p(f"\n  {cls_c}{cls}{A.RESET}  {A.GREY}({len(its)}){A.RESET}")
        for item in its[:10]:
            fname = item.source_file.split("/")[-1] if "/" in item.source_file else item.source_file
            _p(f"  {A.GREY}  • {item.value}  line {item.line_number} in {fname}{A.RESET}")
    _p()


# ── Subdomains ────────────────────────────────────────────────────────────────

def print_subdomains(subdomains: list) -> None:
    if not subdomains:
        return

    _section("SUBDOMAINS", str(len(subdomains)), A.GREEN)
    for sub in subdomains[:30]:
        _p(f"  {A.GREY}  • {sub}{A.RESET}")
    if len(subdomains) > 30:
        _p(f"  {A.GREY}  ... and {len(subdomains) - 30} more{A.RESET}")
    _p()


# ── Endpoint validation ───────────────────────────────────────────────────────

def print_validation_results(results: list) -> None:
    interesting = [r for r in results if r.interesting]
    if not interesting:
        return

    _section("ENDPOINT VALIDATION", f"{len(interesting)} interesting", A.GREEN)

    for r in interesting:
        sc = A.GREEN if r.status_code == 200 else (A.YELLOW if r.status_code in (301,302,307) else (A.RED if r.status_code in (401,403) else A.GREY))
        url = truncate_url(r.endpoint, _w() - 20)
        notes = " | ".join(r.notes[:2]) if r.notes else ""
        _p(f"  {sc}{r.status_code}{A.RESET}  {url}  {A.GREY}{notes}{A.RESET}")
    _p()


# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary(result, extras=None, report_paths=None) -> None:
    extras       = extras or {}
    report_paths = report_paths or {}

    findings = result.findings
    real     = [f for f in findings if f.status != "likely_false_positive"]
    counts: dict = {}
    for f in real:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    validated = [f for f in findings if f.status == "validated"]

    duration = ""
    if result.finished_at and result.started_at:
        secs     = (result.finished_at - result.started_at).total_seconds()
        duration = f"{secs:.1f}s"

    sev_colors = {
        "CRITICAL": A.RED + A.BOLD,
        "HIGH":     A.ORANGE + A.BOLD,
        "MEDIUM":   A.YELLOW,
        "LOW":      A.BLUE,
        "INFO":     A.GREY,
    }

    _p()
    _p(f"  {A.WHITE}{A.BOLD}{'─' * _w()}{A.RESET}")
    _p(f"  {A.WHITE}{A.BOLD}SCAN COMPLETE{A.RESET}  {A.GREY}{duration}{A.RESET}")
    _p(f"  {A.WHITE}{A.BOLD}{'─' * _w()}{A.RESET}")
    _p()

    # Target
    _p(f"  {_label('Target', 18)}{A.CYAN}{truncate_url(result.target_url, 70)}{A.RESET}")
    _p(f"  {_label('Pages crawled', 18)}{result.pages_crawled}")

    # Assets
    js_count = len([js for js in result.js_files if not js.url.startswith("sourcemap://")])
    _p(f"  {_label('JS files', 18)}{js_count}")
    if extras.get("recovered_sources"):
        _p(f"  {_label('Recovered', 18)}{A.GREEN}{extras['recovered_sources']} source files{A.RESET}")
    if extras.get("chunks_found"):
        _p(f"  {_label('Chunks', 18)}{extras['chunks_found']}")

    _p()

    # Intelligence
    _p(f"  {_label('Endpoints', 18)}{len(result.endpoints)}")
    if extras.get("subdomains"):
        _p(f"  {_label('Subdomains', 18)}{extras['subdomains']}")
    if extras.get("graphql_queries"):
        _p(f"  {_label('GraphQL ops', 18)}{extras['graphql_queries']}")
    if result.infrastructure:
        _p(f"  {_label('Infrastructure', 18)}{len(result.infrastructure)}")

    _p()

    # Findings — severity colored in summary
    _p(f"  {_label('Findings', 18)}{len(real)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = counts.get(sev, 0)
        if n:
            c = sev_colors.get(sev, "")
            _p(f"  {c}  {sev:<10}  {n}{A.RESET}")

    if validated:
        _p(f"\n  {A.RED}{A.BOLD}  ⚡ {len(validated)} secrets VALIDATED as active{A.RESET}")

    # Reports
    if report_paths:
        _p()
        _p(f"  {_label('Reports', 18)}")
        for fmt, path in report_paths.items():
            _p(f"  {A.GREY}  {fmt.upper():<8}{A.RESET}  {path}")

    _p()
    if counts.get("CRITICAL") or counts.get("HIGH") or validated:
        _p(f"  {A.RED}{A.BOLD}Critical findings present. Immediate action required.{A.RESET}")
    else:
        _p(f"  {A.GREEN}Scan complete. No critical findings.{A.RESET}")
    _p()


# ── Main report ───────────────────────────────────────────────────────────────

def print_report(
    result,
    show_sensitive:     bool  = True,
    no_color:           bool  = False,
    min_severity:       str   = "INFO",
    extras:             dict  = None,
    validation_results: list  = None,
    graphql_schemas:    list  = None,
    subdomains:         list  = None,
    report_paths:       dict  = None,
    verbose:            bool  = False,
    show_fp:            bool  = False,
    lib_findings:       list  = None,
) -> None:
    extras = extras or {}

    print_js_inventory(result.js_files, verbose=verbose)

    if extras.get("source_map_details"):
        d = extras["source_map_details"]
        print_source_maps(d.get("discovered",0), d.get("valid",0),
                          d.get("recovered",0), d.get("sources",0),
                          d.get("items",[]))

    if extras.get("chunk_stats"):
        c = extras["chunk_stats"]
        print_webpack(c.get("runtime",False), c.get("discovered",0),
                      c.get("downloaded",0), c.get("endpoints",0),
                      c.get("findings",0))

    if extras.get("passive_stats"):
        p = extras["passive_stats"]
        print_passive(p.get("source",""), p.get("urls",0),
                      p.get("js",0), p.get("unique",0), p.get("new",0))

    if extras.get("headless_stats"):
        h = extras["headless_stats"]
        print_headless(h.get("pages",0), h.get("js",0), h.get("xhr",0),
                       h.get("fetch",0), h.get("ws",0), h.get("routes",0),
                       h.get("endpoints",0))

    intel = extras.get("intel")
    if intel:
        _print_intelligence(intel)

    if lib_findings:
        _print_libraries(lib_findings)

    print_secret_analysis(result.findings)
    print_findings(result.findings, verbose=verbose, show_fp=show_fp)
    print_endpoints(result.endpoints, validation_results=validation_results, verbose=verbose)

    if validation_results:
        print_validation_results(validation_results)

    if graphql_schemas:
        print_graphql(graphql_schemas)

    print_infrastructure(result.infrastructure)

    if subdomains:
        print_subdomains(subdomains)

    print_summary(result, extras=extras, report_paths=report_paths)
