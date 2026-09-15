"""
BundleSpy terminal UI — clean, modern, professional.
"""

import os
import sys
import shutil
from typing import List, Optional, Dict
from datetime import datetime

from .theme import A


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


def _label(text: str, width: int = 14) -> str:
    return f"{A.GREY}{text.ljust(width)}{A.RESET}"


def _val(text: str, color: str = "") -> str:
    rst = A.RESET if color else ""
    return f"{color}{text}{rst}"


def _section(title: str, count: str = "", color: str = "") -> None:
    c   = color or A.WHITE
    cnt = f"  {A.GREY}({count}){A.RESET}" if count else ""
    _p()
    _p(f"  {c}{A.BOLD}{title}{A.RESET}{cnt}")
    _p(f"  {A.GREY}{_line()}{A.RESET}")


SEV_COLOR = {
    "CRITICAL": A.RED    + A.BOLD,
    "HIGH":     A.ORANGE + A.BOLD,
    "MEDIUM":   A.YELLOW,
    "LOW":      A.BLUE,
    "INFO":     A.GREY,
}


# ── Header ────────────────────────────────────────────────────────────────────

def print_header(target, mode="Active", scope="Strict", version="1.0.0", author="Mustafa Salha"):
    ts = datetime.utcnow().strftime("%Y-%m-%d  %H:%M UTC")
    _p()
    _p(f"  {A.WHITE}{A.BOLD}BundleSpy{A.RESET}  {A.GREY}v{version}{A.RESET}")
    _p(f"  {A.GREY}{_line()}{A.RESET}")
    _p(f"  {_label('Target')}{A.CYAN}{target[:_w()-22]}{A.RESET}")
    _p(f"  {_label('Mode')}{mode}")
    _p(f"  {_label('Scope')}{scope}")
    _p(f"  {_label('Started')}{A.GREY}{ts}{A.RESET}")
    _p()


# ── Phase lines ───────────────────────────────────────────────────────────────

def phase(label):
    _p(f"  {A.GREY}›{A.RESET}  {label}")


def phase_done(label, detail=""):
    det = f"  {A.GREY}{detail}{A.RESET}" if detail else ""
    _p(f"  {A.GREEN}✓{A.RESET}  {label}{det}")


def phase_warn(label):
    _p(f"  {A.YELLOW}!{A.RESET}  {label}")


def phase_error(label):
    print(f"  {A.RED}✗{A.RESET}  {label}", file=sys.stderr)


# ── JS Inventory ──────────────────────────────────────────────────────────────

def print_js_inventory(js_files, verbose=False):
    if not js_files:
        return

    # Count by source type
    headless_count  = sum(1 for j in js_files if "headless-captured" in j.technology)
    inline_count    = sum(1 for j in js_files if j.url.startswith("inline:"))
    recovered_count = sum(1 for j in js_files if j.url.startswith("sourcemap://"))
    static_count    = len(js_files) - headless_count - inline_count - recovered_count
    total_size      = sum(j.size_bytes for j in js_files if j.size_bytes)

    _section("JAVASCRIPT ASSETS", str(len(js_files)), A.CYAN)

    # Summary line
    summary_parts = []
    if static_count:   summary_parts.append(f"{static_count} static")
    if headless_count: summary_parts.append(f"{headless_count} browser-captured")
    if inline_count:   summary_parts.append(f"{inline_count} inline")
    if recovered_count: summary_parts.append(f"{recovered_count} recovered")
    if summary_parts:
        _p(f"  {A.GREY}{' · '.join(summary_parts)} · {total_size/1024:.0f} KB total{A.RESET}")
    _p()

    show = js_files if verbose else js_files[:15]

    for js in show:
        size  = f"{js.size_bytes/1024:.1f}KB" if js.size_bytes else "?"
        tech  = f" {A.GREY}[{js.technology.replace('headless-captured','')}]{A.RESET}" if js.technology and js.technology != "headless-captured" else ""
        smap  = f" {A.YELLOW}[map]{A.RESET}" if js.has_source_map else ""
        url   = js.url
        tag   = ""

        if url.startswith("sourcemap://"):
            url = url.replace("sourcemap://", "")
            tag = f" {A.GREEN}[recovered]{A.RESET}"
        elif url.startswith("local://"):
            url = url.replace("local://", "")
            tag = f" {A.YELLOW}[local]{A.RESET}"
        elif url.startswith("inline:"):
            url = url.replace("inline:", "")
            tag = f" {A.GREY}[inline]{A.RESET}"
        elif url.startswith("html:"):
            url = url.replace("html:", "")
            tag = f" {A.BLUE}[html]{A.RESET}"
        elif "headless-captured" in js.technology:
            tag = f" {A.CYAN}[browser]{A.RESET}"

        url = url[:_w()-30]
        _p(f"  {A.GREY}•{A.RESET} {url}{tag}{tech}{smap}  {A.GREY}{size}{A.RESET}")

    if not verbose and len(js_files) > 15:
        _p(f"\n  {A.GREY}  ... and {len(js_files)-15} more  (-v to show all){A.RESET}")
    _p()


# ── Feature summaries ─────────────────────────────────────────────────────────

def print_source_maps(discovered, valid, recovered, sources, details=None):
    if not discovered:
        return
    _section("SOURCE MAPS", "", A.YELLOW)
    for label, val in [("Discovered", str(discovered)), ("Valid", str(valid)),
                       ("Recovered", str(recovered)), ("Sources", str(sources))]:
        _p(f"  {_label(label)}{val}")
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
    rows = [("Runtime", "detected" if runtime else "not found"),
            ("Discovered", str(discovered)), ("Downloaded", str(downloaded))]
    if endpoints:
        rows.append(("New endpoints", str(endpoints)))
    if findings:
        rows.append(("New findings", str(findings)))
    for label, val in rows:
        _p(f"  {_label(label)}{val}")
    _p()


def print_passive(source, urls, js, unique, new, errors=None):
    _section("PASSIVE DISCOVERY", "", A.CYAN)
    _p(f"  {_label('Source')}{source}")
    if urls > 0:
        _p(f"  {_label('URLs found')}{urls}")
        _p(f"  {_label('JS assets')}{js}")
        _p(f"  {_label('New')}{new}")
    else:
        _p(f"  {_label('Status')}{A.GREY}No historical assets found{A.RESET}")
    if errors:
        for err in errors:
            _p(f"  {A.YELLOW}  ! {err}{A.RESET}")
    _p()


def print_headless(pages, js, xhr=0, fetch=0, ws=0, routes=0, endpoints=0,
                   workers=0, timings=None):
    _section("BROWSER DISCOVERY", "", A.CYAN)
    rows = [("Engine", "Chromium"), ("Pages", str(pages)), ("JS captured", str(js))]
    if xhr or fetch:
        rows.append(("API calls", str(xhr + fetch)))
    if ws:
        rows.append(("WebSockets", str(ws)))
    if routes:
        rows.append(("Routes", str(routes)))
    if endpoints:
        rows.append(("Endpoints", str(endpoints)))
    if workers:
        rows.append(("Workers", str(workers)))
    for label, val in rows:
        _p(f"  {_label(label)}{val}")

    # Phase timings
    if timings:
        _p()
        _p(f"  {A.GREY}Phase timings:{A.RESET}")
        phase_labels = {
            "browser_start": "Browser start",
            "phase1_root":   "Root page",
            "phase2_routes": "Route crawl",
            "endpoint_build":"Endpoint build",
            "total":         "Total",
        }
        for key, label in phase_labels.items():
            if key in timings:
                secs = timings[key]
                color = A.RED if key == "total" else A.GREY
                _p(f"  {A.GREY}  {label:<16}{color}{secs:.1f}s{A.RESET}")
    _p()


def _print_libraries(lib_findings):
    if not lib_findings:
        return

    # Group CVEs by library+version
    by_lib: dict = {}
    for lf in lib_findings:
        key = f"{lf.library}::{lf.version}"
        by_lib.setdefault(key, []).append(lf)

    unique_libs = len(by_lib)
    total_cves  = len(lib_findings)

    counts: dict = {}
    for lf in lib_findings:
        counts[lf.severity] = counts.get(lf.severity, 0) + 1

    _section("VULNERABLE LIBRARIES",
             f"{total_cves} in {unique_libs}", A.RED)

    # Severity summary bar
    parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts.get(sev):
            c = SEV_COLOR.get(sev, "")
            parts.append(f"{c}{counts[sev]} {sev.lower()}{A.RESET}")
    if parts:
        _p("  " + "   ".join(parts))
    _p()

    # One block per library, showing all its CVEs together
    for lib_key in sorted(by_lib.keys(),
                          key=lambda k: -max(c.cvss for c in by_lib[k])):
        cves    = sorted(by_lib[lib_key], key=lambda x: -x.cvss)
        library = cves[0].library
        version = cves[0].version
        fname   = cves[0].source_file.split("/")[-1] if "/" in cves[0].source_file else cves[0].source_file

        # Highest severity determines header color
        top_sev = cves[0].severity
        hc      = SEV_COLOR.get(top_sev, "")

        # Library header
        _p(f"  {hc}{A.BOLD}{library} {version}{A.RESET}  {A.GREY}·  {fname}{A.RESET}")
        _p(f"  {A.GREY}{'─' * min(_w()-4, 70)}{A.RESET}")

        # Each CVE as a clean row
        for cve in cves:
            c        = SEV_COLOR.get(cve.severity, "")
            sev_tag  = f"{c}{cve.severity:<8}{A.RESET}"
            cvss_tag = f"{A.GREY}CVSS {cve.cvss}{A.RESET}"
            _p(f"  {sev_tag} {A.CYAN}{cve.cve_id}{A.RESET}  {cvss_tag}")
            _p(f"           {cve.description}")
            _p(f"           {A.GREY}Fix: {cve.remediation}{A.RESET}")
            _p()
        _p()


def _print_intelligence(intel):
    has = (intel.sitemap_urls or intel.api_endpoints or
           intel.security_txt or intel.openid_config or intel.api_schema)
    if not has:
        return

    _section("PASSIVE INTELLIGENCE", "", A.PURPLE)

    if intel.sitemap_urls:
        _p(f"  {_label('Sitemap URLs')}{len(intel.sitemap_urls)}")
        for url in intel.sitemap_urls[:8]:
            _p(f"  {A.GREY}  • {url[:_w()-8]}{A.RESET}")
        if len(intel.sitemap_urls) > 8:
            _p(f"  {A.GREY}  ... and {len(intel.sitemap_urls)-8} more{A.RESET}")

    if intel.api_schema:
        _p(f"\n  {_label('API Schema')}{intel.api_schema.get('type','?')}  {A.GREY}{intel.api_schema.get('url','')}{A.RESET}")
        for ep in intel.api_endpoints[:12]:
            _p(f"  {A.GREY}  • {ep}{A.RESET}")

    if intel.security_txt:
        _p(f"\n  {_label('security.txt')}{A.GREEN}found{A.RESET}")
        for line in intel.security_txt.splitlines()[:5]:
            if line.strip() and not line.startswith("#"):
                _p(f"  {A.GREY}  {line.strip()}{A.RESET}")

    if intel.openid_config:
        _p(f"\n  {_label('OpenID Config')}{A.YELLOW}found{A.RESET}")
        if isinstance(intel.openid_config, dict):
            for k in ["issuer", "authorization_endpoint", "token_endpoint"]:
                if k in intel.openid_config:
                    _p(f"  {A.GREY}  {k}: {intel.openid_config[k]}{A.RESET}")
    _p()


# ── Secret analysis ───────────────────────────────────────────────────────────

def print_secret_analysis(findings):
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

def print_findings(findings, verbose=False):
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

    order    = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    fp_note  = f"  {A.GREY}+{len(fps)} FP excluded{A.RESET}" if fps else ""
    _section("FINDINGS", f"{len(real)} confirmed{fp_note}", A.RED)

    for sev in order:
        if counts.get(sev):
            c = SEV_COLOR.get(sev, "")
            _p(f"  {c}{sev:<10}{A.RESET}  {counts[sev]}")
    _p()

    for f in sorted(real, key=lambda x: order.index(x.severity) if x.severity in order else 99):
        _print_finding(f, verbose=verbose)

    if fps and verbose:
        _p(f"  {A.GREY}{'─' * 40}{A.RESET}")
        _p(f"  {A.GREY}Likely false positives ({len(fps)}){A.RESET}")
        for f in fps[:10]:
            fname = f.file_url.split("/")[-1] if "/" in f.file_url else f.file_url
            _p(f"  {A.GREY}  • {f.title}  {fname}:{f.line_number}  {f.matched_value[:40]}{A.RESET}")
    _p()


def _print_finding(f, verbose=False):
    sc  = SEV_COLOR.get(f.severity, "")

    _p(f"  {sc}{f.severity:<8}{A.RESET}  {A.WHITE}{A.BOLD}{f.title}{A.RESET}  {A.GREY}({f.rule_id}){A.RESET}")
    _p()

    url = f.file_url[:_w()-6]
    _p(f"  {_label('Location')}{url}  {A.GREY}line {f.line_number}{A.RESET}")
    _p(f"  {_label('Type')}{f.category}")

    sc2 = {"likely_secret": A.RED, "validated": A.RED+A.BOLD,
           "candidate": A.YELLOW, "likely_false_positive": A.GREY}.get(f.status, "")
    _p(f"  {_label('Confidence')}{f.confidence:.0%}  {sc2}{f.status}{A.RESET}")
    _p(f"  {_label('Evidence')}{sc}{f.matched_value}{A.RESET}")

    if f.context and verbose:
        ctx = f.context[:120].replace("\n", " ").strip()
        _p(f"  {_label('Context')}{A.GREY}{ctx}{A.RESET}")

    _p(f"  {_label('Fix')}{f.remediation[:100]}")

    if f.status == "validated":
        _p(f"  {A.RED}{A.BOLD}  ⚡ CONFIRMED ACTIVE{A.RESET}")

    _p(f"  {A.GREY}{'─' * 60}{A.RESET}")
    _p()


# ── Endpoints ─────────────────────────────────────────────────────────────────

def print_endpoints(endpoints, validation_results=None, verbose=False):
    if not endpoints:
        return

    by_cat: dict = {}
    for ep in endpoints:
        by_cat.setdefault(ep.category, []).append(ep)

    val_map: dict = {}
    if validation_results:
        for r in validation_results:
            val_map[r.endpoint] = r

    _section("ENDPOINTS", str(len(endpoints)), A.BLUE)

    cat_colors = {"AUTH": A.RED, "ADMIN": A.ORANGE, "GRAPHQL": A.PURPLE,
                  "API": A.BLUE, "WEBSOCKET": A.CYAN}

    for cat in ["AUTH", "ADMIN", "GRAPHQL", "UPLOAD", "DOWNLOAD", "API", "WEBSOCKET", "UNKNOWN"]:
        eps = by_cat.get(cat, [])
        if not eps:
            continue
        c = cat_colors.get(cat, A.GREY)
        _p(f"  {c}{A.BOLD}{cat:<12}{A.RESET}  {len(eps)}")

    _p()
    shown = 0
    limit = 9999 if verbose else 40

    for cat in ["AUTH", "ADMIN", "GRAPHQL", "UPLOAD", "DOWNLOAD", "API", "WEBSOCKET", "UNKNOWN"]:
        eps = by_cat.get(cat, [])
        if not eps:
            continue
        c = cat_colors.get(cat, A.GREY)
        for ep in eps:
            if shown >= limit:
                break
            method = (ep.method or "?").ljust(6)
            url    = ep.url[:_w()-20]
            vr     = val_map.get(ep.url)

            # Color method by type
            mc = (A.RED if ep.method in ("DELETE", "PUT") else
                  A.ORANGE if ep.method == "POST" else
                  A.GREY)

            if vr:
                sc = (A.GREEN if vr.status_code == 200 else
                      A.YELLOW if vr.status_code in (301,302,307) else
                      A.RED if vr.status_code in (401,403) else A.GREY)
                ct = vr.content_type.split(";")[0][:20] if vr.content_type else ""
                _p(f"  {mc}{method}{A.RESET}  {c}{url}{A.RESET}  {sc}{vr.status_code}{A.RESET}  {A.GREY}{ct}{A.RESET}")
            else:
                _p(f"  {mc}{method}{A.RESET}  {c}{url}{A.RESET}")

            # Show intelligence in verbose mode
            if verbose:
                intel_parts = []
                bf = getattr(ep, "body_fields", None) or []
                qp = getattr(ep, "query_params", None) or []
                pp = getattr(ep, "path_params", None) or []
                auth = getattr(ep, "auth_context", "") or ""

                if bf:
                    names = ", ".join(f["name"] for f in bf[:6])
                    _p(f"  {A.GREY}         body: {names}{A.RESET}")
                if qp:
                    names = ", ".join(f["name"] for f in qp[:6])
                    _p(f"  {A.GREY}         query: {names}{A.RESET}")
                if pp:
                    names = ", ".join(f["name"] for f in pp[:6])
                    _p(f"  {A.GREY}         path params: {names}{A.RESET}")
                if auth:
                    _p(f"  {A.YELLOW}         auth: {auth}{A.RESET}")

            shown += 1

    if shown >= limit and not verbose:
        _p(f"\n  {A.GREY}  ... use -v to show all {len(endpoints)} endpoints{A.RESET}")
    _p()


# ── GraphQL ───────────────────────────────────────────────────────────────────

def print_graphql(schemas):
    if not schemas:
        return
    _section("GRAPHQL", "", A.PURPLE)
    _p(f"  {_label('Endpoints')}{len(schemas)}")
    _p(f"  {_label('Introspection')}{'enabled' if any(not s.error for s in schemas) else 'disabled'}")
    _p(f"  {_label('Types')}{sum(len(s.types) for s in schemas if not s.error)}")
    _p(f"  {_label('Queries')}{sum(len(s.queries) for s in schemas if not s.error)}")
    _p(f"  {_label('Mutations')}{sum(len(s.mutations) for s in schemas if not s.error)}")
    for schema in schemas:
        _p(f"\n  {A.WHITE}{schema.endpoint[:_w()-4]}{A.RESET}")
        if schema.error:
            _p(f"  {A.GREY}  {schema.error}{A.RESET}")
            continue
        if schema.queries:
            _p(f"  {A.GREY}  Queries:{A.RESET}   {', '.join(schema.queries[:8])}")
        if schema.mutations:
            _p(f"  {A.ORANGE}  Mutations:{A.RESET}  {', '.join(schema.mutations[:8])}")
        if schema.sensitive_fields:
            _p(f"  {A.RED}  Sensitive:{A.RESET}  {', '.join(schema.sensitive_fields[:6])}")
    _p()


# ── Infrastructure ────────────────────────────────────────────────────────────

def print_infrastructure(items):
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

def print_subdomains(subdomains):
    if not subdomains:
        return
    _section("SUBDOMAINS", str(len(subdomains)), A.GREEN)
    for sub in subdomains[:30]:
        _p(f"  {A.GREY}  • {sub}{A.RESET}")
    if len(subdomains) > 30:
        _p(f"  {A.GREY}  ... and {len(subdomains)-30} more{A.RESET}")
    _p()


# ── Endpoint validation ───────────────────────────────────────────────────────

def print_validation_results(results):
    interesting = [r for r in results if r.interesting]
    if not interesting:
        return
    _section("ENDPOINT VALIDATION", f"{len(interesting)} interesting", A.GREEN)
    for r in interesting:
        sc = (A.GREEN if r.status_code == 200 else
              A.YELLOW if r.status_code in (301,302,307) else
              A.RED if r.status_code in (401,403) else A.GREY)
        url   = r.endpoint[:_w()-20]
        notes = " | ".join(r.notes[:2]) if r.notes else ""
        _p(f"  {sc}{r.status_code}{A.RESET}  {url}  {A.GREY}{notes}{A.RESET}")
    _p()


# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary(result, extras=None, report_paths=None):
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

    _p()
    _p(f"  {A.WHITE}{A.BOLD}{_line('─')}{A.RESET}")
    _p(f"  {A.WHITE}{A.BOLD}SCAN COMPLETE{A.RESET}  {A.GREY}{duration}{A.RESET}")
    _p(f"  {A.WHITE}{A.BOLD}{_line('─')}{A.RESET}")
    _p()

    _p(f"  {_label('Target')}{A.CYAN}{result.target_url[:70]}{A.RESET}")
    _p(f"  {_label('Pages crawled')}{result.pages_crawled}")

    js_count = len([js for js in result.js_files if not js.url.startswith("sourcemap://")])
    _p(f"  {_label('JS files')}{js_count}")
    if extras.get("recovered_sources"):
        _p(f"  {_label('Recovered')}{A.GREEN}{extras['recovered_sources']} source files{A.RESET}")
    if extras.get("chunks_found"):
        _p(f"  {_label('Chunks')}{extras['chunks_found']}")

    _p()
    _p(f"  {_label('Endpoints')}{len(result.endpoints)}")
    if extras.get("subdomains"):
        _p(f"  {_label('Subdomains')}{extras['subdomains']}")
    if result.infrastructure:
        _p(f"  {_label('Infrastructure')}{len(result.infrastructure)}")

    lib_f = extras.get("lib_findings", [])
    if lib_f:
        _p(f"  {_label('Vuln libraries')}{A.RED}{len(lib_f)}{A.RESET}")

    _p()
    _p(f"  {_label('Findings')}{len(real)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = counts.get(sev, 0)
        if n:
            c = SEV_COLOR.get(sev, "")
            _p(f"  {c}  {sev:<10}  {n}{A.RESET}")

    if validated:
        _p(f"\n  {A.RED}{A.BOLD}  ⚡ {len(validated)} secrets VALIDATED as active{A.RESET}")

    if report_paths:
        _p()
        _p(f"  {_label('Reports')}")
        for fmt, path in report_paths.items():
            _p(f"  {A.GREY}  {fmt.upper():<8}{A.RESET}  {path}")

    _p()
    if counts.get("CRITICAL") or validated:
        _p(f"  {A.RED}{A.BOLD}Critical findings present. Immediate action required.{A.RESET}")
    elif counts.get("HIGH"):
        _p(f"  {A.ORANGE}{A.BOLD}High severity findings present. Review required.{A.RESET}")
    elif counts.get("MEDIUM"):
        _p(f"  {A.YELLOW}Medium severity findings present.{A.RESET}")
    else:
        _p(f"  {A.GREEN}Scan complete. No critical findings.{A.RESET}")
    _p()


# ── Main report ───────────────────────────────────────────────────────────────

def print_report(
    result,
    show_sensitive:     bool = True,
    no_color:           bool = False,
    min_severity:       str  = "INFO",
    extras:             dict = None,
    validation_results: list = None,
    graphql_schemas:    list = None,
    subdomains:         list = None,
    report_paths:       dict = None,
    verbose:            bool = False,
) -> None:
    extras = extras or {}

    print_js_inventory(result.js_files, verbose=verbose)

    if extras.get("source_map_details"):
        d = extras["source_map_details"]
        print_source_maps(d.get("discovered",0), d.get("valid",0),
                          d.get("recovered",0), d.get("sources",0), d.get("items",[]))

    if extras.get("chunk_stats"):
        c = extras["chunk_stats"]
        print_webpack(c.get("runtime",False), c.get("discovered",0),
                      c.get("downloaded",0), c.get("endpoints",0), c.get("findings",0))

    if extras.get("passive_stats"):
        p = extras["passive_stats"]
        print_passive(p.get("source",""), p.get("urls",0), p.get("js",0),
                      p.get("unique",0), p.get("new",0))

    if extras.get("headless_stats"):
        h = extras["headless_stats"]
        print_headless(h.get("pages",0), h.get("js",0), h.get("xhr",0),
                       h.get("fetch",0), h.get("ws",0), h.get("routes",0),
                       h.get("endpoints",0))

    intel = extras.get("intel")
    if intel:
        _print_intelligence(intel)

    lib_findings = extras.get("lib_findings", [])
    if lib_findings:
        _print_libraries(lib_findings)

    print_secret_analysis(result.findings)
    print_findings(result.findings, verbose=verbose)
    print_endpoints(result.endpoints, validation_results=validation_results, verbose=verbose)

    if validation_results:
        print_validation_results(validation_results)

    if graphql_schemas:
        print_graphql(graphql_schemas)

    print_infrastructure(result.infrastructure)

    if subdomains:
        print_subdomains(subdomains)

    print_summary(result, extras=extras, report_paths=report_paths)
