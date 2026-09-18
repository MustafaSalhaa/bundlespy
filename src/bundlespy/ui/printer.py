"""
BundleSpy terminal UI - clean, modern, professional.

Exports all public functions used by the scanner:
    phase, phase_sub, phase_done, phase_warn, phase_error,
    print_header, print_auth_result, print_js_inventory,
    print_source_maps, print_webpack, print_passive, print_headless,
    print_secret_analysis, print_findings, print_coverage,
    print_attack_surface, print_endpoints, print_graphql,
    print_infrastructure, print_subdomains, print_validation_results,
    print_summary, print_report,
    _p, _w, _line, _label, _val, _section, SEV_COLOR
"""

from __future__ import annotations

import os
import re
import sys
import shutil
import textwrap
from typing import Any
from datetime import datetime

from .theme import (
    A, USE_COLOR, SEVERITY_COLOR, SEVERITY_LABEL,
    SEVERITY_DOT_COLOR, STATUS_COLOR, SECTION_COLOR,
)
from .renderer import (
    _p, _w, _vis_len, _pad,
    term_width, divider, section, kv, truncate, truncate_url,
    severity_badge, redact, bullet, indent_block, two_col_table,
    count_table, severity_table, progress_bar,
    D, S,
    _box_top_d, _box_bot_d, _box_mid_d, _box_row_d,
    _box_top_s, _box_bot_s, _box_mid_s, _box_row_s,
    _hline_d, _hline_s,
)

# ---------------------------------------------------------------------------
# Backward-compat alias used throughout the codebase
# ---------------------------------------------------------------------------

SEV_COLOR: dict[str, str] = SEVERITY_COLOR


# ---------------------------------------------------------------------------
# Internal helpers  (_p, _w, _line, _label, _val, _section)
# Re-exported here so callers can import them directly from this module.
# ---------------------------------------------------------------------------

def _p(text: str = "") -> None:
    """Print a line (single point of output). Re-export from renderer."""
    print(text)


def _w() -> int:
    """Return current terminal width (clamped). Re-export from renderer."""
    return term_width()


def _line(char: str = "-", color: str = "") -> str:
    """Return a full-width line of `char`."""
    rst = A.RESET if color else ""
    return f"{color}{char * _w()}{rst}"


def _label(text: str, width: int = 14) -> str:
    """Return a styled label string (key in a k/v pair)."""
    return A.GREY + text.ljust(width) + A.RESET


def _val(text: str, color: str = "") -> str:
    """Return a styled value string."""
    rst = A.RESET if color else ""
    return f"{color}{text}{rst}"


def _section(title: str, count: str = "", color: str = "") -> None:
    """
    Print an accent-bar section header.

    Renders:
      2sp + bright-cyan vertical bar + space + bold-white TITLE + dim fill + right count

    Signature preserved: _section(title, count="", color="")
    """
    c = color or SECTION_COLOR.get(title.lower(), SECTION_COLOR["default"])
    w = _w()
    bar   = A.B_CYAN + "▌" + A.RESET  # left half block
    label = A.BOLD + A.BRIGHT_WHITE + title + A.RESET
    # visible lengths
    bar_vis   = 1
    label_vis = len(title)
    count_vis = len(count) + 2 if count else 0  # " N"
    # fill: bar(1) + sp(1) + label + sp(1) + fill + count
    fill_len = max(0, w - 2 - bar_vis - 1 - label_vis - 2 - count_vis)
    fill = A.DIM + "  " + "─" * fill_len + A.RESET
    cnt  = ("  " + A.DIM + count + A.RESET) if count else ""
    _p(f"  {bar} {label}{fill}{cnt}")
    _p()


# ---------------------------------------------------------------------------
# Phase / status lines  (original signatures)
# ---------------------------------------------------------------------------

def phase(label: str) -> None:
    """Phase line - shows a running indicator."""
    _p(f"  {A.CYAN}>{A.RESET}  {label}")


def phase_sub(label: str) -> None:
    """Sub-phase line - indented, subordinate to parent phase."""
    _p(f"       {A.DIM}-{A.RESET}  {A.DIM}{label}{A.RESET}")


def phase_done(label: str, detail: str = "") -> None:
    """Done line - shown when a phase completes successfully."""
    det = f"  {A.DIM}{detail}{A.RESET}" if detail else ""
    _p(f"  {A.B_GREEN}+{A.RESET}  {label}{det}")


def phase_warn(label: str) -> None:
    """Warning line."""
    _p(f"  {A.YELLOW}!{A.RESET}  {label}")


def phase_error(label: str) -> None:
    """Error line - written to stderr."""
    print(f"  {A.RED}x{A.RESET}  {label}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Scan header  (original signature restored)
# ---------------------------------------------------------------------------

def print_header(
    target: str,
    mode: str = "Active",
    scope: str = "Strict",
    version: str = "1.0.0",
    author: str = "Mustafa Salha",
) -> None:
    """
    Print the scan header - no box, pure typographic power.
    """
    ts = datetime.utcnow().strftime("%Y-%m-%d  %H:%M UTC")
    w  = _w()
    rc = A.RESET

    _p("")
    # Top accent line - full width dim
    _p(f"  {A.DIM}{'─' * (w - 4)}{rc}")
    _p("")

    # Tool name - large, confident
    _p(f"  {A.B_BRIGHT_WHITE}BUNDLESPY{rc}  {A.DIM}v{version}{rc}")
    _p("")

    # Target - most important info, highlighted
    target_display = target[:w - 12] if len(target) > w - 12 else target
    _p(f"  {A.DIM}TARGET{rc}")
    _p(f"  {A.B_CYAN}{A.BOLD}{target_display}{rc}")
    _p("")

    # Meta row
    _p(f"  {A.DIM}MODE   {rc}{A.BRIGHT_WHITE}{mode}{rc}    {A.DIM}SCOPE  {rc}{A.BRIGHT_WHITE}{scope}{rc}    {A.DIM}STARTED  {rc}{A.BRIGHT_WHITE}{ts}{rc}")
    _p("")

    # Bottom accent line
    _p(f"  {A.DIM}{'─' * (w - 4)}{rc}")
    _p("")


# ---------------------------------------------------------------------------
# Authentication result  (original signature)
# ---------------------------------------------------------------------------

def print_auth_result(auth: dict) -> None:
    """
    Print the authentication verification block.
    Only called when credentials were supplied (cookie/header).
    """
    if not auth:
        return

    _section("AUTHENTICATION")

    verified   = auth.get("authenticated", False)
    supplied   = auth.get("credentials_supplied", False)
    n_cookies  = auth.get("cookies_injected", 0)
    init_url   = auth.get("initial_url", "")
    status     = auth.get("status", 0)
    final_url  = auth.get("final_url", "")
    chain      = auth.get("redirect_chain", [])
    ck_present = auth.get("cookies_present", [])
    reason     = auth.get("reason", "")

    _p(f"  {_label('Credentials')}{'YES' if supplied else 'NO'}")
    _p(f"  {_label('Cookies injected')}{n_cookies}")
    _p(f"  {_label('Initial URL')}{init_url}")

    status_color = A.B_GREEN if status == 200 else A.ORANGE if status in (301, 302) else A.BRIGHT_RED
    _p(f"  {_label('Status')}{status_color}{status}{A.RESET}")
    _p(f"  {_label('Final URL')}{final_url}")

    redirected = init_url.rstrip("/") != final_url.rstrip("/") if init_url and final_url else False
    to_login   = any(k in final_url.lower() for k in ["/login", "/signin", "/sign-in"])

    redir_color = A.BRIGHT_RED if to_login else A.ORANGE if redirected else A.B_GREEN
    redir_label = "YES (to login)" if to_login else "YES" if redirected else "NO"
    _p(f"  {_label('Redirected')}{redir_color}{redir_label}{A.RESET}")

    if chain:
        _p(f"  {_label('Redirect chain')}{A.DIM}{' -> '.join(chain[:5])}{A.RESET}")

    if ck_present:
        _p(f"  {_label('Browser cookies')}{A.DIM}{', '.join(ck_present[:8])}{A.RESET}")

    if verified:
        _p(f"  {_label('Auth state')}{A.B_GREEN}VERIFIED{A.RESET}")
    else:
        _p(f"  {_label('Auth state')}{A.B_BRIGHT_RED}NOT VERIFIED{A.RESET}")
        if reason:
            _p(f"  {_label('Reason')}{A.DIM}{reason}{A.RESET}")
        _p(f"  {A.B_YELLOW}!{A.RESET}  Credentials supplied but authentication not verified.{A.RESET}")
        _p(f"  {A.B_YELLOW}!{A.RESET}  Results reflect the unauthenticated application state.{A.RESET}")

    _p()


# ---------------------------------------------------------------------------
# JS Inventory  (original signature)
# ---------------------------------------------------------------------------

def print_js_inventory(js_files, verbose=False, per_file_stats=None):
    """Print JS asset table with heat bar."""
    if not js_files:
        return

    headless_count  = sum(1 for j in js_files if "headless-captured" in (j.technology or ""))
    inline_count    = sum(1 for j in js_files if j.url.startswith("inline:") or j.url.startswith("html:"))
    recovered_count = sum(1 for j in js_files if j.url.startswith("sourcemap://"))
    static_count    = len(js_files) - headless_count - inline_count - recovered_count
    total_size      = sum(j.size_bytes for j in js_files if j.size_bytes)

    _section("JAVASCRIPT ASSETS", str(len(js_files)), A.B_CYAN)

    summary_parts = []
    if static_count:    summary_parts.append(f"{static_count} static")
    if headless_count:  summary_parts.append(f"{headless_count} browser-captured")
    if inline_count:    summary_parts.append(f"{inline_count} inline")
    if recovered_count: summary_parts.append(f"{recovered_count} recovered")
    if summary_parts:
        _p(f"  {A.DIM}{' · '.join(summary_parts)} · {total_size/1024:.0f} KB total{A.RESET}")
    _p()

    # Per-file analysis table
    stats_map = {}
    if per_file_stats:
        for s in per_file_stats:
            stats_map[s["url"]] = s

    show = js_files if verbose else js_files[:20]

    # Separate JS files from HTML-attribute synthetic entries
    js_files_only = [j for j in show if not j.url.startswith("html:")]
    html_entries  = [s for s in (per_file_stats or []) if s.get("technology") == "html-attrs"]

    w = _w()
    path_w = max(30, w - 52)

    for js in js_files_only:
        size = f"{js.size_bytes/1024:.1f}KB" if js.size_bytes else "?"
        url  = js.url
        tag  = ""
        context = ""

        if url.startswith("sourcemap://"):
            url = url.replace("sourcemap://", "")
            tag = f" {A.B_GREEN}[recovered]{A.RESET}"
            context = "recovered"
        elif url.startswith("inline:") or url.startswith("html:"):
            bare = re.sub(r"^(inline:|html:)", "", url)
            _frag_match = re.search(r"#script-(\d+)-[a-f0-9]+$", bare)
            if _frag_match:
                _script_num = _frag_match.group(1)
                _page_display = bare.split("#")[0]
                _page_display = re.sub(r"^https?://", "", _page_display).rstrip("/") or "/"
                url = f"script {_script_num} @ {_page_display}"
            else:
                url = re.sub(r"^https?://[^/]+", "", bare) or bare
            tag = f" {A.DIM}[inline]{A.RESET}"
            context = "inline"
        elif "headless-captured" in (js.technology or ""):
            tag = f" {A.B_CYAN}[browser]{A.RESET}"
            context = "browser"
        elif "webworker" in (js.technology or ""):
            tag = f" {A.BRIGHT_MAGENTA}[worker]{A.RESET}"
            context = "worker"

        _display = re.sub(r"^https?://[^/]+", "", url) or url
        if not _display or _display == "/":
            _display = url.rstrip("/").split("/")[-1] or url

        st = stats_map.get(js.url)
        n_secrets   = st["secrets"]   if st else 0
        n_endpoints = st["endpoints"] if st else 0

        # Heat bar: 4 chars, filled = hot (secrets/endpoints), empty = cold
        heat_score = min(4, n_secrets * 2 + (1 if n_endpoints > 10 else 0))
        hot  = A.B_BRIGHT_RED + "█" * heat_score + A.RESET
        cold = A.DIM + "░" * (4 - heat_score) + A.RESET
        heat_bar = hot + cold

        fname = _display[:path_w].ljust(path_w + 1)

        if st:
            sec_c = A.B_BRIGHT_RED if n_secrets > 0 else A.DIM
            ep_c  = A.B_CYAN       if n_endpoints > 0 else A.DIM
            stats_str = (
                f"  {sec_c}s:{n_secrets}{A.RESET}"
                f"  {ep_c}ep:{n_endpoints}{A.RESET}"
            )
        else:
            stats_str = f"  {A.DIM}--{A.RESET}"

        smap = f" {A.B_YELLOW}[map]{A.RESET}" if getattr(js, "has_source_map", False) else ""
        size_str = A.DIM + f"{size:>7}" + A.RESET
        _p(f"  {A.DIM}·{A.RESET} {fname}{tag}{smap}  {size_str}  {heat_bar}{stats_str}")

    # Show HTML-attribute findings as page-level entries
    if html_entries:
        _p()
        _p(f"  {A.DIM}HTML attribute findings (not in JS content):{A.RESET}")
        for he in html_entries:
            _page = re.sub(r"^https?://[^/]+", "", he["url"].replace("html:", "")) or he["url"]
            sec_c = A.B_BRIGHT_RED if he["secrets"] > 0 else A.DIM
            _p(f"  {A.DIM}·{A.RESET} {_page[:path_w].ljust(path_w + 1)}  {A.DIM}[page]{A.RESET}  {sec_c}s:{he['secrets']}{A.RESET}")

    if not verbose and len(js_files) > 20:
        _p(f"\n  {A.DIM}  ... and {len(js_files)-20} more  (-v to show all){A.RESET}")
    _p()


# ---------------------------------------------------------------------------
# Feature summaries  (original signatures)
# ---------------------------------------------------------------------------

def print_source_maps(discovered, valid, recovered, sources, details=None):
    """Print source map discovery section."""
    if not discovered:
        return
    _section("SOURCE MAPS", "", A.B_YELLOW)
    for lbl, val in [("Discovered", str(discovered)), ("Valid", str(valid)),
                     ("Recovered", str(recovered)), ("Sources", str(sources))]:
        _p(f"  {_label(lbl)}{val}")
    if details:
        for d in details:
            _p(f"\n  {A.BRIGHT_WHITE}{d.get('js','')}{A.RESET}")
            _p(f"  {A.DIM}  +-- {d.get('map','')}{A.RESET}")
            if d.get("sources"):
                _p(f"  {A.DIM}     +-- {d['sources']} original sources{A.RESET}")
    _p()


def print_webpack(runtime, discovered, downloaded, endpoints=0, findings=0):
    """Print webpack chunk discovery section."""
    if not discovered:
        return
    _section("WEBPACK CHUNKS", "", A.B_YELLOW)
    rows = [("Runtime", "detected" if runtime else "not found"),
            ("Discovered", str(discovered)), ("Downloaded", str(downloaded))]
    if endpoints:
        rows.append(("New endpoints", str(endpoints)))
    if findings:
        rows.append(("New findings", str(findings)))
    for lbl, val in rows:
        _p(f"  {_label(lbl)}{val}")
    _p()


def print_passive(source, urls, js, unique, new, errors=None):
    """Print passive discovery section."""
    _section("PASSIVE DISCOVERY", "", A.B_CYAN)
    _p(f"  {_label('Source')}{source}")
    if urls > 0:
        _p(f"  {_label('URLs found')}{urls}")
        _p(f"  {_label('JS assets')}{js}")
        _p(f"  {_label('New')}{new}")
    else:
        _p(f"  {_label('Status')}{A.DIM}No historical assets found{A.RESET}")
    if errors:
        for err in errors:
            _p(f"  {A.B_YELLOW}  ! {err}{A.RESET}")
    _p()


def print_headless(pages, js, xhr=0, fetch=0, ws=0, routes=0, endpoints=0,
                   workers=0, timings=None):
    """Print browser discovery section."""
    _section("BROWSER DISCOVERY", "", A.B_CYAN)
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
    for lbl, val in rows:
        _p(f"  {_label(lbl)}{val}")

    # Phase timings
    if timings:
        _p()
        _p(f"  {A.DIM}Phase timings:{A.RESET}")
        phase_labels = {
            "browser_start":  "Browser start",
            "phase1_root":    "Root page",
            "phase2_routes":  "Route crawl",
            "endpoint_build": "Endpoint build",
            "total":          "Total",
        }
        for key, lbl in phase_labels.items():
            if key in timings:
                secs  = timings[key]
                color = A.BRIGHT_RED if key == "total" else A.DIM
                _p(f"  {A.DIM}  {lbl:<16}{color}{secs:.1f}s{A.RESET}")
    _p()


# ---------------------------------------------------------------------------
# Internal helpers for libraries and intelligence
# ---------------------------------------------------------------------------

def _print_libraries(lib_findings):
    if not lib_findings:
        return

    by_lib: dict = {}
    for lf in lib_findings:
        key = f"{lf.library}::{lf.version}"
        by_lib.setdefault(key, []).append(lf)

    unique_libs = len(by_lib)
    total_cves  = len(lib_findings)

    counts: dict = {}
    for lf in lib_findings:
        counts[lf.severity] = counts.get(lf.severity, 0) + 1

    _section("VULNERABLE LIBRARIES", f"{total_cves} in {unique_libs}", A.B_BRIGHT_RED)

    parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts.get(sev):
            c = SEV_COLOR.get(sev, "")
            parts.append(f"{c}{counts[sev]} {sev.lower()}{A.RESET}")
    if parts:
        _p("  " + "   ".join(parts))
    _p()

    for lib_key in sorted(by_lib.keys(),
                          key=lambda k: -max(c.cvss for c in by_lib[k])):
        cves    = sorted(by_lib[lib_key], key=lambda x: -x.cvss)
        library = cves[0].library
        version = cves[0].version
        fname   = cves[0].source_file.split("/")[-1] if "/" in cves[0].source_file else cves[0].source_file

        top_sev = cves[0].severity
        hc      = SEV_COLOR.get(top_sev, "")

        w  = _w()
        bc = hc

        # Left-border card style
        title_line = f"{hc}{A.BOLD}{library} {version}{A.RESET}  {A.DIM}{fname}{A.RESET}"
        _p(f"  {hc}┃{A.RESET} {title_line}")

        for cve in cves:
            c        = SEV_COLOR.get(cve.severity, "")
            sev_tag  = f"{c}{cve.severity:<8}{A.RESET}"
            cvss_tag = f"{A.DIM}CVSS {cve.cvss}{A.RESET}"
            _p(f"  {A.DIM}│{A.RESET} {sev_tag} {A.CYAN}{cve.cve_id}{A.RESET}  {cvss_tag}")
            _p(f"  {A.DIM}│{A.RESET}          {cve.description}")
            _p(f"  {A.DIM}│{A.RESET}          {A.DIM}Fix: {cve.remediation}{A.RESET}")

        _p()


def _print_intelligence(intel):
    has = (intel.sitemap_urls or intel.api_endpoints or
           intel.security_txt or intel.openid_config or intel.api_schema)
    if not has:
        return

    _section("PASSIVE INTELLIGENCE", "", A.BRIGHT_MAGENTA)

    if intel.sitemap_urls:
        _p(f"  {_label('Sitemap URLs')}{len(intel.sitemap_urls)}")
        for url in intel.sitemap_urls[:8]:
            _p(f"  {A.DIM}  · {url[:_w()-8]}{A.RESET}")
        if len(intel.sitemap_urls) > 8:
            _p(f"  {A.DIM}  ... and {len(intel.sitemap_urls)-8} more{A.RESET}")

    if intel.api_schema:
        _p(f"\n  {_label('API Schema')}{intel.api_schema.get('type','?')}  {A.DIM}{intel.api_schema.get('url','')}{A.RESET}")
        for ep in intel.api_endpoints[:12]:
            _p(f"  {A.DIM}  · {ep}{A.RESET}")

    if intel.security_txt:
        _p(f"\n  {_label('security.txt')}{A.B_GREEN}found{A.RESET}")
        for line in intel.security_txt.splitlines()[:5]:
            if line.strip() and not line.startswith("#"):
                _p(f"  {A.DIM}  {line.strip()}{A.RESET}")

    if intel.openid_config:
        _p(f"\n  {_label('OpenID Config')}{A.B_YELLOW}found{A.RESET}")
        if isinstance(intel.openid_config, dict):
            for k in ["issuer", "authorization_endpoint", "token_endpoint"]:
                if k in intel.openid_config:
                    _p(f"  {A.DIM}  {k}: {intel.openid_config[k]}{A.RESET}")
    _p()


# ---------------------------------------------------------------------------
# Secret analysis  (original signature)
# ---------------------------------------------------------------------------

def print_secret_analysis(findings):
    """Print the secret analysis summary block - stat pill row style."""
    if not findings:
        return

    def _is_public_id(f):
        return getattr(f, "classification", "") == "PUBLIC_IDENTIFIER" or f.rule_id in (
            "NETLIFY_SITE_ID",
        )

    secrets   = [f for f in findings if not _is_public_id(f)]
    pub_ids   = [f for f in findings if _is_public_id(f)]
    total     = len(secrets)
    high_conf = sum(1 for f in secrets if f.confidence >= 0.85 and f.status != "likely_false_positive")
    validated = sum(1 for f in secrets if f.status == "validated")
    fps       = sum(1 for f in secrets if f.status == "likely_false_positive")

    _section("SECRET ANALYSIS", "", A.B_BRIGHT_RED)

    # Stat pills: [ N label ]
    def _pill(count, label, active_color=""):
        lbr = A.DIM + "[" + A.RESET
        rbr = A.DIM + "]" + A.RESET
        c   = active_color if (active_color and count) else A.DIM
        num = f"{c}{count}{A.RESET}"
        txt = f"{A.DIM} {label}{A.RESET}"
        return f"{lbr} {num}{txt} {rbr}"

    pills = [
        _pill(total,          "detected",         A.BRIGHT_WHITE),
        _pill(high_conf,      "high confidence",  A.B_BRIGHT_RED),
        _pill(validated,      "validated",        A.B_BRIGHT_RED),
        _pill(len(pub_ids),   "public id",        A.DIM),
    ]
    _p("  " + "  ".join(pills))
    _p()


# ---------------------------------------------------------------------------
# Findings  (original signature)
# ---------------------------------------------------------------------------

def print_findings(findings, verbose=False):
    """Print all findings as compact left-border cards."""
    real = [f for f in findings if f.status != "likely_false_positive"]
    fps  = [f for f in findings if f.status == "likely_false_positive"]

    if not real and not fps:
        _section("FINDINGS")
        _p(f"  {A.DIM}No findings detected above the confidence threshold.{A.RESET}")
        _p()
        return

    counts: dict = {}
    for f in real:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    order   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    fp_note = f"  {A.DIM}+{len(fps)} FP excluded{A.RESET}" if fps else ""
    _section("FINDINGS", f"{len(real)} confirmed{fp_note}", A.B_BRIGHT_RED)

    # Severity tally line
    sev_parts = []
    for sev in order:
        if counts.get(sev):
            c = SEV_COLOR.get(sev, "")
            sev_parts.append(f"{c}{sev}{A.RESET}  {A.BRIGHT_WHITE}{counts[sev]}{A.RESET}")
    if sev_parts:
        _p("  " + "   ".join(sev_parts))
        _p()

    for f in sorted(real, key=lambda x: order.index(x.severity) if x.severity in order else 99):
        _print_finding(f, verbose=verbose)

    if fps and verbose:
        _p(f"  {A.DIM}{'-' * 40}{A.RESET}")
        _p(f"  {A.DIM}Likely false positives ({len(fps)}){A.RESET}")
        for f in fps[:10]:
            fname = f.file_url.split("/")[-1] if "/" in f.file_url else f.file_url
            _p(f"  {A.DIM}  · {f.title}  {fname}:{f.line_number}  {f.matched_value[:40]}{A.RESET}")
    _p()


def _print_finding(f, verbose=False):
    """Print a single finding as a compact left-border card."""
    sev    = f.severity.lower()
    dot_c  = SEVERITY_DOT_COLOR.get(sev, A.WHITE)
    lbl_c  = SEV_COLOR.get(f.severity, A.WHITE)
    lbl    = SEVERITY_LABEL.get(sev, f.severity.upper()).strip()
    stat_c = STATUS_COLOR.get(f.status.lower(), A.WHITE) if f.status else A.WHITE

    w = _w()

    # Title line: thick border colored by severity
    sev_badge = lbl_c + A.BOLD + f"{lbl:<6}" + A.RESET
    title_str = A.BRIGHT_WHITE + f.title + A.RESET
    rule_str  = (A.DIM + "rule:" + f.rule_id + A.RESET) if f.rule_id else ""
    # Right-align rule on title line
    title_vis  = len(lbl) + 2 + len(f.title)
    rule_vis   = len("rule:" + f.rule_id) if f.rule_id else 0
    gap_len    = max(1, w - 6 - title_vis - rule_vis)
    gap        = " " * gap_len
    title_line = f"{sev_badge}  {title_str}{gap}{rule_str}"
    _p(f"  {dot_c}┃{A.RESET} {title_line}")

    # Detail lines: thin dim border
    dim_pipe = A.DIM + "│" + A.RESET

    # Location line
    url  = f.file_url[:w - 10]
    occ  = getattr(f, "occurrences", None) or []
    if occ and len(occ) > 1:
        loc = f"{A.DIM}file{A.RESET}  {A.BRIGHT_WHITE}{url}{A.RESET}  {A.DIM}line {f.line_number}{A.RESET}  {A.B_YELLOW}(+{len(occ)-1} more){A.RESET}"
    else:
        loc = f"{A.DIM}file{A.RESET}  {A.BRIGHT_WHITE}{url}{A.RESET}  {A.DIM}line {f.line_number}{A.RESET}"
    _p(f"  {dim_pipe} {loc}")

    # Type / confidence
    conf_pct = f"{f.confidence:.0%}"
    type_line = f"{A.DIM}type{A.RESET}  {A.BRIGHT_WHITE}{f.category}{A.RESET}  {A.DIM}·{A.RESET}  {stat_c}{f.status}{A.RESET}  {A.DIM}{conf_pct}{A.RESET}"
    _p(f"  {dim_pipe} {type_line}")

    # Fix
    max_fix = w - 12
    fix_txt = f.remediation[:100]
    wrapped = textwrap.wrap(fix_txt, max_fix) if len(fix_txt) > max_fix else [fix_txt]
    fix_line = f"{A.DIM}fix   {wrapped[0]}{A.RESET}"
    _p(f"  {dim_pipe} {fix_line}")
    for cont in wrapped[1:]:
        _p(f"  {dim_pipe}       {A.DIM}{cont}{A.RESET}")

    # Evidence (redacted)
    ev_line = f"{A.DIM}{redact(f.matched_value)}{A.RESET}"
    _p(f"  {dim_pipe} {ev_line}")

    if f.context and verbose:
        ctx = f.context[:120].replace("\n", " ").strip()
        _p(f"  {dim_pipe} {A.DIM}ctx   {ctx}{A.RESET}")

    if f.status == "validated":
        _p(f"  {dim_pipe} {A.B_BRIGHT_RED}[!] CONFIRMED ACTIVE{A.RESET}")

    _p()


# ---------------------------------------------------------------------------
# Coverage  (original signature)
# ---------------------------------------------------------------------------

def print_coverage(coverage) -> None:
    """Print observed coverage data and blind spots - compact inline style."""
    if not coverage:
        return

    _section("COVERAGE", "", A.B_CYAN)

    p = coverage.pages
    j = coverage.js
    r = coverage.routes

    # Compact inline stat row
    page_color = A.B_GREEN if p.visited == p.discovered else A.B_YELLOW
    js_color   = A.B_GREEN if j.analyzed == j.discovered else A.B_YELLOW
    rt_color   = A.B_GREEN if r.visited >= r.discovered else A.B_YELLOW

    pages_str = f"{A.DIM}Pages{A.RESET}  {page_color}{p.visited}/{p.discovered}{A.RESET} {A.DIM}visited{A.RESET}"
    js_str    = f"{A.DIM}JS{A.RESET}    {js_color}{j.analyzed}/{j.discovered}{A.RESET} {A.DIM}analyzed{A.RESET}"
    rt_str    = f"{A.DIM}Routes{A.RESET} {rt_color}{r.visited}/{r.discovered}{A.RESET} {A.DIM}visited{A.RESET}"
    _p(f"  {pages_str}    {js_str}    {rt_str}")
    _p()

    # Failure details
    if p.failed:
        _p(f"  {A.B_YELLOW}!{A.RESET}  {A.DIM}{p.failed} page(s) failed to load{A.RESET}")
    if p.auth_required:
        _p(f"  {A.B_YELLOW}!{A.RESET}  {p.auth_required} auth-required page(s) skipped")
        for u in p.auth_urls[:3]:
            _p(f"  {A.DIM}     {u}{A.RESET}")
    if j.failed:
        _p(f"  {A.B_YELLOW}!{A.RESET}  {A.DIM}{j.failed} JS file(s) failed{A.RESET}")
        for u in j.failed_urls[:2]:
            _p(f"  {A.DIM}     {u}{A.RESET}")
    if r.unvisited:
        _p(f"  {A.B_YELLOW}!{A.RESET}  {A.DIM}{r.unvisited} route(s) unvisited{A.RESET}")

    # Runtime stats
    rt = coverage.runtime
    has_runtime = any([rt.api_requests, rt.websockets, rt.workers, rt.iframes])
    if has_runtime:
        parts = []
        if rt.api_requests: parts.append(f"{A.DIM}api:{A.RESET} {A.B_GREEN}{rt.api_requests}{A.RESET}")
        if rt.websockets:   parts.append(f"{A.DIM}ws:{A.RESET}  {A.B_GREEN}{rt.websockets}{A.RESET}")
        if rt.workers:      parts.append(f"{A.DIM}workers:{A.RESET} {A.B_GREEN}{rt.workers}{A.RESET}")
        if rt.iframes:      parts.append(f"{A.DIM}iframes:{A.RESET} {A.B_GREEN}{rt.iframes}{A.RESET}")
        _p(f"\n  {A.DIM}Runtime:{A.RESET}  " + "  ".join(parts))

    # Source maps
    sm = coverage.source_maps
    if sm.discovered > 0:
        sm_color = A.B_GREEN if sm.recovered > 0 else A.B_YELLOW
        _p(f"\n  {A.DIM}Source maps:{A.RESET}  {sm.discovered} found  {sm_color}{sm.recovered} recovered{A.RESET}")
        if sm.unavailable > 0:
            _p(f"  {A.DIM}             {sm.unavailable} unavailable{A.RESET}")

    # Blind spots - clean tag style, no emoji
    if coverage.blind_spots:
        _p()
        for bs in coverage.blind_spots:
            sc    = A.B_BRIGHT_RED if bs.severity == "HIGH" else A.B_YELLOW if bs.severity == "MEDIUM" else A.DIM
            tag   = f"{sc}[{bs.severity}]{A.RESET}"
            miti  = (f"  {A.DIM}-> {bs.mitigation}{A.RESET}") if bs.mitigation else ""
            _p(f"  {tag}  {bs.description}{miti}")

    _p()


# ---------------------------------------------------------------------------
# Attack surface  (original signature)
# ---------------------------------------------------------------------------

def print_attack_surface(surface):
    """Print attack surface analysis section."""
    if not surface:
        return
    has_content = (
        surface.get("total_items", 0) > 0
        or surface.get("state_change")
    )
    if not has_content:
        return

    total = surface.get("total_items", 0)
    _section("ATTACK SURFACE", str(total), A.B_BRIGHT_RED)

    parts = []
    for key, lbl, color in [
        ("idor",          "IDOR",          A.B_BRIGHT_RED),
        ("injection",     "Injection",     A.ORANGE),
        ("file_ops",      "LFI/Path",      A.ORANGE),
        ("ssrf",          "SSRF",          A.B_YELLOW),
        ("open_redirect", "Open Redirect", A.B_YELLOW),
    ]:
        n = len(surface.get(key, []))
        if n:
            parts.append(f"{color}{n} {lbl}{A.RESET}")
    if parts:
        _p("  " + "   ".join(parts))
        _p()

    def _print_group(items, title, color):
        if not items:
            return
        _p(f"  {color}{A.BOLD}{title}{A.RESET}  {A.DIM}({len(items)}){A.RESET}")
        for it in items[:15]:
            path = it.endpoint_url[:_w()-30]
            _p(f"  {A.DIM}  {it.method:<6}{A.RESET} {path}")
            _p(f"  {A.DIM}         param: {A.RESET}{color}{it.param_name}{A.RESET}  {A.DIM}{it.reason}{A.RESET}")
        if len(items) > 15:
            _p(f"  {A.DIM}  ... and {len(items)-15} more{A.RESET}")
        _p()

    _print_group(surface.get("idor", []),          "IDOR CANDIDATES",        A.B_BRIGHT_RED)
    _print_group(surface.get("injection", []),     "INJECTION CANDIDATES",   A.ORANGE)
    _print_group(surface.get("file_ops", []),      "PATH TRAVERSAL / LFI",  A.ORANGE)
    _print_group(surface.get("ssrf", []),          "SSRF CANDIDATES",        A.B_YELLOW)
    _print_group(surface.get("open_redirect", []), "OPEN REDIRECT",          A.B_YELLOW)

    sc = surface.get("state_change", [])
    if sc:
        _p(f"  {A.BRIGHT_MAGENTA}{A.BOLD}STATE-CHANGING ENDPOINTS{A.RESET}  {A.DIM}({len(sc)}){A.RESET}")
        for ep in sc[:15]:
            mc = A.B_BRIGHT_RED if ep.method in ("DELETE", "PUT") else A.ORANGE
            _p(f"  {mc}  {ep.method:<6}{A.RESET} {ep.url[:_w()-14]}")
        if len(sc) > 15:
            _p(f"  {A.DIM}  ... and {len(sc)-15} more{A.RESET}")
        _p()


# ---------------------------------------------------------------------------
# Endpoints  (original signature)
# ---------------------------------------------------------------------------

def print_endpoints(endpoints, validation_results=None, verbose=False):
    """Print endpoints grouped by category with colored chip headers."""
    if not endpoints:
        return

    by_cat: dict = {}
    for ep in endpoints:
        by_cat.setdefault(ep.category, []).append(ep)

    val_map: dict = {}
    if validation_results:
        for r in validation_results:
            val_map[r.endpoint] = r

    cat_colors = {
        "AUTH":       A.B_BRIGHT_RED,
        "ADMIN":      A.ORANGE,
        "GRAPHQL":    A.BRIGHT_MAGENTA,
        "API":        A.B_BLUE,
        "WEBSOCKET":  A.B_CYAN,
        "SERVERLESS": A.B_YELLOW,
        "ROUTE":      A.B_GREEN,
    }

    w  = _w()

    _section("ENDPOINTS", str(len(endpoints)), A.B_BLUE)

    shown = 0
    limit = 9999 if verbose else 40

    cat_order = ["AUTH", "ADMIN", "GRAPHQL", "UPLOAD", "DOWNLOAD", "API",
                 "SERVERLESS", "WEBSOCKET", "ROUTE", "UNKNOWN"]

    for cat in cat_order:
        eps = by_cat.get(cat, [])
        if not eps:
            continue
        c = cat_colors.get(cat, A.DIM)

        # Category chip header
        chip = f"{c}{A.BOLD}{cat}{A.RESET}"
        count_tag = f"  {A.DIM}{len(eps)}{A.RESET}"
        _p(f"  {chip}{count_tag}")

        for ep in eps:
            if shown >= limit:
                break
            method = (ep.method or "?").ljust(6)
            url    = ep.url[:w - 18]
            vr     = val_map.get(ep.url)

            mc = (A.B_BRIGHT_RED if ep.method in ("DELETE", "PUT") else
                  A.ORANGE       if ep.method == "POST"             else
                  A.DIM)

            if vr:
                sc2 = (A.B_GREEN      if vr.status_code == 200             else
                       A.B_YELLOW     if vr.status_code in (301, 302, 307) else
                       A.B_BRIGHT_RED if vr.status_code in (401, 403)      else A.DIM)
                ct  = vr.content_type.split(";")[0][:20] if vr.content_type else ""
                row = (f"    {mc}{method}{A.RESET}  {url}"
                       + f"  {sc2}{vr.status_code}{A.RESET}"
                       + (f"  {A.DIM}{ct}{A.RESET}" if ct else ""))
            else:
                row = f"    {mc}{method}{A.RESET}  {url}"

            _p(row)

            if verbose:
                bf   = getattr(ep, "body_fields",  None) or []
                qp   = getattr(ep, "query_params", None) or []
                pp   = getattr(ep, "path_params",  None) or []
                auth = getattr(ep, "auth_context", "") or ""
                if bf:
                    names = ", ".join(f["name"] for f in bf[:6])
                    _p(f"           {A.DIM}body: {names}{A.RESET}")
                if qp:
                    names = ", ".join(f["name"] for f in qp[:6])
                    _p(f"           {A.DIM}query: {names}{A.RESET}")
                if pp:
                    names = ", ".join(f["name"] for f in pp[:6])
                    _p(f"           {A.DIM}path params: {names}{A.RESET}")
                if auth:
                    _p(f"           {A.B_YELLOW}auth: {auth}{A.RESET}")

            shown += 1

        _p()

    if shown >= limit and not verbose:
        _p(f"  {A.DIM}  ... use -v to show all {len(endpoints)} endpoints{A.RESET}")
    _p()


# ---------------------------------------------------------------------------
# GraphQL  (original signature)
# ---------------------------------------------------------------------------

def print_graphql(schemas):
    """Print GraphQL schema section."""
    if not schemas:
        return
    _section("GRAPHQL", "", A.BRIGHT_MAGENTA)
    _p(f"  {_label('Endpoints')}{len(schemas)}")
    _p(f"  {_label('Introspection')}{'enabled' if any(not s.error for s in schemas) else 'disabled'}")
    _p(f"  {_label('Types')}{sum(len(s.types) for s in schemas if not s.error)}")
    _p(f"  {_label('Queries')}{sum(len(s.queries) for s in schemas if not s.error)}")
    _p(f"  {_label('Mutations')}{sum(len(s.mutations) for s in schemas if not s.error)}")
    for schema in schemas:
        _p(f"\n  {A.BRIGHT_WHITE}{schema.endpoint[:_w()-4]}{A.RESET}")
        if schema.error:
            _p(f"  {A.DIM}  {schema.error}{A.RESET}")
            continue
        if schema.queries:
            _p(f"  {A.DIM}  Queries:{A.RESET}   {', '.join(schema.queries[:8])}")
        if schema.mutations:
            _p(f"  {A.ORANGE}  Mutations:{A.RESET}  {', '.join(schema.mutations[:8])}")
        if schema.sensitive_fields:
            _p(f"  {A.B_BRIGHT_RED}  Sensitive:{A.RESET}  {', '.join(schema.sensitive_fields[:6])}")
    _p()


# ---------------------------------------------------------------------------
# Infrastructure  (original signature)
# ---------------------------------------------------------------------------

def print_infrastructure(items):
    """Print infrastructure findings section."""
    if not items:
        return
    by_cls: dict = {}
    for item in items:
        by_cls.setdefault(item.classification, []).append(item)
    _section("INFRASTRUCTURE", str(len(items)), A.B_YELLOW)
    for cls, its in sorted(by_cls.items()):
        cls_c = (A.B_BRIGHT_RED if cls in ("PRIVATE_IP", "CLOUD_METADATA") else
                 A.ORANGE       if "HOSTNAME" in cls                         else A.DIM)
        _p(f"\n  {cls_c}{cls}{A.RESET}  {A.DIM}({len(its)}){A.RESET}")
        for item in its[:10]:
            fname = item.source_file.split("/")[-1] if "/" in item.source_file else item.source_file
            _p(f"  {A.DIM}  · {item.value}  line {item.line_number} in {fname}{A.RESET}")
    _p()


# ---------------------------------------------------------------------------
# Subdomains  (original signature)
# ---------------------------------------------------------------------------

def print_subdomains(subdomains):
    """Print subdomain list section."""
    if not subdomains:
        return
    _section("SUBDOMAINS", str(len(subdomains)), A.B_GREEN)
    for sub in subdomains[:30]:
        _p(f"  {A.DIM}  · {sub}{A.RESET}")
    if len(subdomains) > 30:
        _p(f"  {A.DIM}  ... and {len(subdomains)-30} more{A.RESET}")
    _p()


# ---------------------------------------------------------------------------
# Endpoint validation  (original signature)
# ---------------------------------------------------------------------------

def print_validation_results(results):
    """Print interesting endpoint validation results."""
    interesting = [r for r in results if r.interesting]
    if not interesting:
        return
    _section("ENDPOINT VALIDATION", f"{len(interesting)} interesting", A.B_GREEN)
    for r in interesting:
        sc = (A.B_GREEN      if r.status_code == 200             else
              A.B_YELLOW     if r.status_code in (301, 302, 307) else
              A.B_BRIGHT_RED if r.status_code in (401, 403)      else A.DIM)
        url   = r.endpoint[:_w()-20]
        notes = " | ".join(r.notes[:2]) if r.notes else ""
        _p(f"  {sc}{r.status_code}{A.RESET}  {url}  {A.DIM}{notes}{A.RESET}")
    _p()


# ---------------------------------------------------------------------------
# Summary  (original signature)
# ---------------------------------------------------------------------------

def print_summary(result, extras=None, report_paths=None):
    """Print the final scan-complete summary - no boxes, no emoji."""
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

    w  = _w()
    rc = A.RESET

    _p("")
    # Accent divider - same style as _section but for the summary block
    _p(f"  {A.DIM}{'─' * (w - 4)}{rc}")
    _p("")

    # SCAN COMPLETE label
    dur_str = f"  {A.DIM}{duration}{rc}" if duration else ""
    _p(f"  {A.B_GREEN}SCAN COMPLETE{rc}{dur_str}")
    _p("")

    # Key stats: compact inline
    js_count = len([js for js in result.js_files if not js.url.startswith("sourcemap://")])
    _p(f"  {A.DIM}target{rc}     {A.BRIGHT_WHITE}{result.target_url[:60]}{rc}")
    _p(f"  {A.DIM}pages{rc}      {A.BRIGHT_WHITE}{result.pages_crawled}{rc}         "
       f"{A.DIM}js files{rc}   {A.BRIGHT_WHITE}{js_count}{rc}         "
       f"{A.DIM}endpoints{rc}  {A.BRIGHT_WHITE}{len(result.endpoints)}{rc}")

    if extras.get("recovered_sources"):
        _p(f"  {A.DIM}recovered{rc}  {A.B_GREEN}{extras['recovered_sources']} source files{rc}")
    if extras.get("chunks_found"):
        _p(f"  {A.DIM}chunks{rc}     {A.BRIGHT_WHITE}{extras['chunks_found']}{rc}")
    if extras.get("subdomains"):
        _p(f"  {A.DIM}subdomains{rc} {A.BRIGHT_WHITE}{extras['subdomains']}{rc}")
    if result.infrastructure:
        _p(f"  {A.DIM}infra{rc}      {A.BRIGHT_WHITE}{len(result.infrastructure)}{rc}")
    lib_f = extras.get("lib_findings", [])
    if lib_f:
        _p(f"  {A.DIM}vuln libs{rc}  {A.B_BRIGHT_RED}{len(lib_f)}{rc}")
    _p("")

    # Severity tiles
    if counts:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        tile_parts = []
        for sev in order:
            n = counts.get(sev, 0)
            if n == 0:
                continue
            sev_c = SEV_COLOR.get(sev, A.DIM)
            dot_c = SEVERITY_DOT_COLOR.get(sev.lower(), A.DIM)
            bar = (dot_c + "██" + rc if sev in ("CRITICAL", "HIGH") else
                   A.DIM + "░░" + rc   if sev == "INFO"               else
                   A.DIM + "▒▒" + rc)
            label = SEVERITY_LABEL.get(sev.lower(), sev).strip()
            tile_parts.append(f"{bar} {sev_c}{label:<8}{rc} {A.BRIGHT_WHITE}{n}{rc}")

        _p("  " + "    ".join(tile_parts))
        _p("")

    # Validated secrets callout
    if validated:
        _p(f"  {A.B_BRIGHT_RED}[!]{rc} {A.B_BRIGHT_RED}{len(validated)} secret{'s' if len(validated) != 1 else ''} VALIDATED as active{rc}")
        _p("")

    # Report paths
    if report_paths:
        for fmt, path in report_paths.items():
            _p(f"  {A.DIM}{fmt.upper():<8}{rc}  {path}")
        _p("")

    # Final verdict - no emoji, clean text
    if counts.get("CRITICAL") or validated:
        _p(f"  {A.B_BRIGHT_RED}Critical findings present. Immediate action required.{rc}")
    elif counts.get("HIGH"):
        _p(f"  {A.ORANGE}High severity findings present. Review required.{rc}")
    elif counts.get("MEDIUM"):
        _p(f"  {A.B_YELLOW}Medium severity findings present.{rc}")
    else:
        _p(f"  {A.B_GREEN}Scan complete. No critical findings.{rc}")
    _p("")


def _fmt_sev_cell(sev: str, count: int) -> str:
    """Format a single severity count cell for the summary grid."""
    dot_c = SEVERITY_DOT_COLOR.get(sev.lower(), A.WHITE)
    lbl_c = SEV_COLOR.get(sev, A.WHITE)
    label = SEVERITY_LABEL.get(sev.lower(), sev.upper()).strip()
    rc    = A.RESET
    return (
        dot_c + "· " + rc
        + lbl_c + f"{label:<8}" + rc
        + "  "
        + A.BRIGHT_WHITE + str(count) + rc
    )


# ---------------------------------------------------------------------------
# Main report  (original signature)
# ---------------------------------------------------------------------------

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
    """
    Orchestrate a full scan report.

    All sections use the new visual design (accent bars, left-border cards,
    stat pills, compact heat bars) while preserving the original function
    signature.
    """
    extras = extras or {}

    if extras.get("auth_result"):
        print_auth_result(extras["auth_result"])

    print_js_inventory(result.js_files, verbose=verbose,
                       per_file_stats=extras.get("per_file_stats"))

    if extras.get("source_map_details"):
        d = extras["source_map_details"]
        print_source_maps(d.get("discovered", 0), d.get("valid", 0),
                          d.get("recovered", 0), d.get("sources", 0), d.get("items", []))

    if extras.get("chunk_stats"):
        c = extras["chunk_stats"]
        print_webpack(c.get("runtime", False), c.get("discovered", 0),
                      c.get("downloaded", 0), c.get("endpoints", 0), c.get("findings", 0))

    if extras.get("passive_stats"):
        p = extras["passive_stats"]
        print_passive(p.get("source", ""), p.get("urls", 0), p.get("js", 0),
                      p.get("unique", 0), p.get("new", 0))

    if extras.get("headless_stats"):
        h = extras["headless_stats"]
        print_headless(h.get("pages", 0), h.get("js", 0), h.get("xhr", 0),
                       h.get("fetch", 0), h.get("ws", 0), h.get("routes", 0),
                       h.get("endpoints", 0))

    intel = extras.get("intel")
    if intel:
        _print_intelligence(intel)

    lib_findings = extras.get("lib_findings", [])
    if lib_findings:
        _print_libraries(lib_findings)

    print_secret_analysis(result.findings)
    print_findings(result.findings, verbose=verbose)
    print_endpoints(result.endpoints, validation_results=validation_results, verbose=verbose)

    surface = extras.get("attack_surface")
    if surface:
        print_attack_surface(surface)

    coverage = extras.get("coverage")
    if coverage:
        print_coverage(coverage)

    if validation_results:
        print_validation_results(validation_results)

    if graphql_schemas:
        print_graphql(graphql_schemas)

    print_infrastructure(result.infrastructure)

    if subdomains:
        print_subdomains(subdomains)

    print_summary(result, extras=extras, report_paths=report_paths)
