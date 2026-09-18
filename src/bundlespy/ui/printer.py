"""
BundleSpy terminal UI - professional security console.

Design: Vercel/Stripe CLI aesthetic - clean whitespace, typography-driven,
restrained color, excellent information hierarchy.

Exports all public functions used by the scanner.
"""

from __future__ import annotations

import os
import re
import sys
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
# Backward-compat alias
# ---------------------------------------------------------------------------

SEV_COLOR: dict[str, str] = SEVERITY_COLOR


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _p(text: str = "") -> None:
    print(text)


def _w() -> int:
    return term_width()


def _line(char: str = "-", color: str = "") -> str:
    rst = A.RESET if color else ""
    return f"{color}{char * _w()}{rst}"


def _label(text: str, width: int = 14) -> str:
    return A.GREY + text.ljust(width) + A.RESET


def _val(text: str, color: str = "") -> str:
    rst = A.RESET if color else ""
    return f"{color}{text}{rst}"


def _rule(color: str = "") -> None:
    """Print a full-width thin horizontal rule."""
    c = color or A.DIM
    _p(f"  {c}{'─' * (_w() - 4)}{A.RESET}")


def _section(title: str, count: str = "", color: str = "") -> None:
    """
    Clean typographic section header - Vercel/Stripe style.
    One blank line above, title left, count right, one blank line below.
    """
    w         = _w()
    label     = A.BOLD + A.BRIGHT_WHITE + title + A.RESET
    count_vis = len(count) if count else 0
    gap_len   = max(1, w - 2 - len(title) - count_vis)
    gap       = " " * gap_len
    cnt       = (A.DIM + count + A.RESET) if count else ""
    _p("")
    _p(f"  {label}{gap}{cnt}")
    _p("")


# ---------------------------------------------------------------------------
# Phase / status lines
# ---------------------------------------------------------------------------

def phase(label: str) -> None:
    _p(f"  {A.CYAN}>{A.RESET}  {label}")


def phase_sub(label: str) -> None:
    _p(f"       {A.DIM}-{A.RESET}  {A.DIM}{label}{A.RESET}")


def phase_done(label: str, detail: str = "") -> None:
    det = f"  {A.DIM}{detail}{A.RESET}" if detail else ""
    _p(f"  {A.B_GREEN}+{A.RESET}  {label}{det}")


def phase_warn(label: str) -> None:
    _p(f"  {A.YELLOW}!{A.RESET}  {label}")


def phase_error(label: str) -> None:
    print(f"  {A.RED}x{A.RESET}  {label}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Scan header
# ---------------------------------------------------------------------------

def print_header(
    target: str,
    mode: str = "Active",
    scope: str = "Strict",
    version: str = "1.0.0",
    author: str = "Mustafa Salha",
) -> None:
    """
    Compact professional header.

    BundleSpy 1.0.0
    JavaScript Attack Surface Intelligence
    ────────────────────────────────────────────

    TARGET
    https://example.com
    Active - Strict - 2026-09-18 08:10 UTC
    """
    ts  = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    w   = _w()
    rc  = A.RESET

    _p("")
    _p(f"  {A.BOLD}{A.BRIGHT_WHITE}BundleSpy {version}{rc}  {A.DIM}JavaScript Attack Surface Intelligence{rc}")
    _p("")
    _rule()
    _p("")
    _p(f"  {A.DIM}TARGET{rc}")
    target_display = target[:w - 4] if len(target) > w - 4 else target
    _p(f"  {A.B_CYAN}{A.BOLD}{target_display}{rc}")
    _p(f"  {A.DIM}{mode} - {scope} - {ts}{rc}")
    _p("")


# ---------------------------------------------------------------------------
# Authentication result
# ---------------------------------------------------------------------------

def print_auth_result(auth: dict) -> None:
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
    _p(f"  {_label('Cookies')}{n_cookies} injected")
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
        _p(f"  {_label('Chain')}{A.DIM}{' -> '.join(chain[:5])}{A.RESET}")
    if ck_present:
        _p(f"  {_label('Browser cookies')}{A.DIM}{', '.join(ck_present[:8])}{A.RESET}")

    if verified:
        _p(f"  {_label('Auth state')}{A.B_GREEN}VERIFIED{A.RESET}")
    else:
        _p(f"  {_label('Auth state')}{A.B_BRIGHT_RED}NOT VERIFIED{A.RESET}")
        if reason:
            _p(f"  {_label('Reason')}{A.DIM}{reason}{A.RESET}")
        _p(f"  {A.B_YELLOW}!{A.RESET}  Credentials supplied but authentication not verified.")
        _p(f"  {A.B_YELLOW}!{A.RESET}  Results reflect the unauthenticated application state.")

    _p("")


# ---------------------------------------------------------------------------
# Scan status (PARTIAL / COMPLETE / FAILED)
# ---------------------------------------------------------------------------

def _print_scan_status(args_flags: dict) -> None:
    """
    Print a SCAN STATUS block near the top showing what was and was not run.
    args_flags: dict with boolean keys: headless, source_maps, passive,
                has_cookie, validate, graphql, chunks, harvest_subs
    """
    stages = [
        ("Target initialization",   True),
        ("Page discovery",           True),
        ("JavaScript inventory",     True),
        ("Static analysis",          True),
        ("Secret analysis",          True),
        ("Endpoint extraction",      True),
        ("Library detection",        True),
        ("Runtime discovery",        args_flags.get("headless", False)),
        ("Source-map recovery",      args_flags.get("source_maps", False)),
        ("Passive discovery",        args_flags.get("passive", False)),
        ("Endpoint validation",      args_flags.get("validate", False)),
        ("GraphQL introspection",    args_flags.get("graphql", False)),
    ]
    done    = sum(1 for _, ran in stages if ran)
    total   = len(stages)

    if done == total:
        status_color = A.B_GREEN
        status_label = "COMPLETE"
    elif done >= total - 3:
        status_color = A.B_YELLOW
        status_label = "PARTIAL"
    else:
        status_color = A.ORANGE
        status_label = "PARTIAL"

    _section("SCAN STATUS")
    _p(f"  {status_color}{status_label}{A.RESET}  {A.DIM}{done}/{total} discovery stages completed{A.RESET}")
    _p("")

    for name, ran in stages:
        if ran:
            _p(f"  {A.B_GREEN}+{A.RESET}  {name}")
        else:
            _p(f"  {A.DIM}-  {name}  SKIPPED{A.RESET}")
    _p("")


# ---------------------------------------------------------------------------
# Overview panel
# ---------------------------------------------------------------------------

def _print_overview(result, extras: dict) -> None:
    """Compact high-level numbers."""
    real_findings = [f for f in result.findings if f.status != "likely_false_positive"]
    counts: dict  = {}
    for f in real_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    js_count   = len([j for j in result.js_files if not j.url.startswith("sourcemap://")])
    ep_count   = len(result.endpoints)
    infra_count = len(result.infrastructure)
    lib_count  = len(extras.get("lib_findings", []))

    _section("OVERVIEW")

    w = _w()
    col = (w - 4) // 5
    row_vals = [
        ("PAGES",     str(result.pages_crawled)),
        ("JS",        str(js_count)),
        ("ENDPOINTS", str(ep_count)),
        ("FINDINGS",  str(len(real_findings))),
        ("INFRA",     str(infra_count)),
    ]
    labels_line = ""
    values_line = ""
    for lbl, val in row_vals:
        labels_line += A.DIM + lbl.ljust(col) + A.RESET
        values_line += A.BRIGHT_WHITE + A.BOLD + val.ljust(col) + A.RESET
    _p(f"  {labels_line}")
    _p(f"  {values_line}")

    if lib_count:
        _p(f"\n  {A.DIM}Vulnerable libraries:{A.RESET}  {A.B_BRIGHT_RED}{lib_count}{A.RESET}")

    # Severity summary
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_parts = []
    for sev in order:
        n = counts.get(sev, 0)
        if n:
            c = SEV_COLOR.get(sev, A.DIM)
            sev_parts.append(f"{c}{sev} {n}{A.RESET}")
    if sev_parts:
        _p("")
        _p("  " + "  -  ".join(sev_parts))
    _p("")


# ---------------------------------------------------------------------------
# Attack surface (tree view)
# ---------------------------------------------------------------------------

def _print_attack_surface_tree(result, extras: dict) -> None:
    """
    Print an attack-surface tree view grouped by category.
    Shows what was actually found - never fabricates data.
    For capabilities not run, shows NOT RUN.
    """
    _section("ATTACK SURFACE")

    by_cat: dict = {}
    for ep in result.endpoints:
        by_cat.setdefault(ep.category, []).append(ep)

    args_flags = extras.get("_args_flags", {})
    w = _w()

    def _tree_group(title: str, eps: list, color: str = "") -> None:
        c = color or A.BRIGHT_WHITE
        _p(f"  {c}{title}{A.RESET}")
        paths = sorted(set(ep.url[:w - 10] for ep in eps))
        for i, path in enumerate(paths[:12]):
            prefix = "└─" if i == len(paths) - 1 or i == 11 else "├─"
            method = ""
            # Find method for this URL
            for ep in eps:
                if ep.url.startswith(path):
                    if ep.method and ep.method not in ("GET", "?", "UNKNOWN", ""):
                        method = f"  {A.DIM}{ep.method}{A.RESET}"
                    break
            _p(f"  {A.DIM}{prefix}{A.RESET} {path}{method}")
        if len(paths) > 12:
            _p(f"  {A.DIM}   ... and {len(paths) - 12} more{A.RESET}")
        _p("")

    # Pages (from crawler - always run unless passive)
    pages_cat = by_cat.get("ROUTE", []) + by_cat.get("ADMIN", []) + by_cat.get("AUTH", [])
    if pages_cat:
        _tree_group("Pages", pages_cat, A.BRIGHT_WHITE)
    else:
        _p(f"  {A.BRIGHT_WHITE}Pages{A.RESET}")
        _p(f"  {A.DIM}└─ /{A.RESET}")
        _p("")

    # API
    api_eps = by_cat.get("API", [])
    if api_eps:
        _tree_group("API", api_eps, A.B_BLUE)

    # Serverless
    serverless = by_cat.get("SERVERLESS", [])
    if serverless:
        _tree_group("Serverless", serverless, A.B_CYAN)

    # Auth
    auth_eps = by_cat.get("AUTH", [])
    if auth_eps:
        _tree_group("Authentication", auth_eps, A.B_BRIGHT_RED)

    # Admin
    admin_eps = by_cat.get("ADMIN", [])
    if admin_eps:
        _tree_group("Admin", admin_eps, A.ORANGE)

    # GraphQL
    gql_eps = by_cat.get("GRAPHQL", [])
    if gql_eps:
        _tree_group("GraphQL", gql_eps, A.BRIGHT_MAGENTA)
    elif args_flags.get("graphql"):
        _p(f"  {A.BRIGHT_WHITE}GraphQL{A.RESET}")
        _p(f"  {A.DIM}└─ Not detected{A.RESET}")
        _p("")

    # WebSockets
    ws_eps = by_cat.get("WEBSOCKET", [])
    if ws_eps:
        _tree_group("WebSockets", ws_eps, A.B_CYAN)
    elif args_flags.get("headless"):
        ws_count = extras.get("headless_stats", {}).get("ws", 0)
        _p(f"  {A.BRIGHT_WHITE}WebSockets{A.RESET}")
        _p(f"  {A.DIM}└─ {ws_count} detected{A.RESET}")
        _p("")
    else:
        _p(f"  {A.BRIGHT_WHITE}WebSockets{A.RESET}")
        _p(f"  {A.DIM}└─ NOT RUN{A.RESET}")
        _p("")

    # XHR/Fetch (from headless)
    if args_flags.get("headless"):
        xhr = extras.get("headless_stats", {}).get("xhr", 0)
        fetch = extras.get("headless_stats", {}).get("fetch", 0)
        _p(f"  {A.BRIGHT_WHITE}XHR / Fetch{A.RESET}")
        _p(f"  {A.DIM}└─ {xhr + fetch} intercepted{A.RESET}")
        _p("")


# ---------------------------------------------------------------------------
# Security findings (redesigned per spec)
# ---------------------------------------------------------------------------

def _print_finding_full(f, show_full_secret: bool = False) -> None:
    """
    Full finding card with structured sections.

    HIGH  JWT Token in HTML Attribute
    JWT_IN_ATTRIBUTE - confidence 88%

    LOCATION
    https://example.com - HTML attribute - line 1892

    EVIDENCE
    eyJhbGci...To7Vo

    REMEDIATION
    Generate authentication tokens server-side at runtime.
    """
    sev    = f.severity.lower()
    lbl_c  = SEV_COLOR.get(f.severity, A.WHITE)
    dot_c  = SEVERITY_DOT_COLOR.get(sev, A.WHITE)
    stat_c = STATUS_COLOR.get((f.status or "").lower(), A.WHITE)
    w = _w()
    rc = A.RESET

    # Title line
    lbl = SEVERITY_LABEL.get(sev, f.severity.upper()).strip()
    _p(f"  {dot_c}┃{rc} {lbl_c}{A.BOLD}{lbl:<6}{rc}  {A.BRIGHT_WHITE}{f.title}{rc}")

    conf_pct = f"{f.confidence:.0%}"
    rule_str = f.rule_id if f.rule_id else ""
    sub_line = f"{A.DIM}{rule_str}{rc}"
    if rule_str:
        sub_line += f"  {A.DIM}-{rc}  {A.DIM}confidence {conf_pct}{rc}"
    else:
        sub_line = f"  {A.DIM}confidence {conf_pct}{rc}"
    _p(f"  {A.DIM}│{rc} {sub_line}")

    # Status badge
    if f.status == "validated":
        _p(f"  {A.DIM}│{rc} {A.B_BRIGHT_RED}CONFIRMED ACTIVE{rc}")
    elif f.status:
        _p(f"  {A.DIM}│{rc} {stat_c}{f.status}{rc}")

    # LOCATION
    _p(f"  {A.DIM}│{rc}")
    _p(f"  {A.DIM}│{rc}  {A.DIM}LOCATION{rc}")
    url  = f.file_url[:w - 14] if f.file_url else ""
    occ  = getattr(f, "occurrences", None) or []
    loc_parts = [url]
    loc_parts.append(f"line {f.line_number}")
    if occ and len(occ) > 1:
        loc_parts.append(f"+{len(occ)-1} more")
    _p(f"  {A.DIM}│{rc}  {A.BRIGHT_WHITE}{'  -  '.join(loc_parts)}{rc}")

    # EVIDENCE
    _p(f"  {A.DIM}│{rc}")
    _p(f"  {A.DIM}│{rc}  {A.DIM}EVIDENCE{rc}")
    raw = f.matched_value or ""
    if show_full_secret:
        ev = raw
    else:
        # Smart redaction: show head + tail
        if len(raw) > 40:
            ev = raw[:20] + A.DIM + "..." + A.RESET + raw[-12:]
        else:
            ev = raw
    _p(f"  {A.DIM}│{rc}  {A.BRIGHT_WHITE}{ev}{rc}")

    # REMEDIATION
    if f.remediation:
        _p(f"  {A.DIM}│{rc}")
        _p(f"  {A.DIM}│{rc}  {A.DIM}REMEDIATION{rc}")
        max_w = w - 14
        wrapped = textwrap.wrap(f.remediation[:200], max_w)
        for line in wrapped[:3]:
            _p(f"  {A.DIM}│{rc}  {A.DIM}{line}{rc}")

    _p("")


def print_findings(findings, verbose: bool = False, show_full_secret: bool = False) -> None:
    """Print all findings - separating security findings from discoveries."""
    real = [f for f in findings if f.status != "likely_false_positive"]
    fps  = [f for f in findings if f.status == "likely_false_positive"]

    if not real and not fps:
        _section("SECURITY FINDINGS")
        _p(f"  {A.DIM}No findings detected above the confidence threshold.{A.RESET}")
        _p("")
        return

    counts: dict = {}
    for f in real:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    order   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    fp_note = f"  {A.DIM}+{len(fps)} excluded{A.RESET}" if fps else ""
    _section("SECURITY FINDINGS", f"{len(real)} confirmed{fp_note}", A.B_BRIGHT_RED)

    # Severity tally
    sev_parts = []
    for sev in order:
        if counts.get(sev):
            c = SEV_COLOR.get(sev, "")
            sev_parts.append(f"{c}{sev}  {A.BRIGHT_WHITE}{counts[sev]}{A.RESET}")
    if sev_parts:
        _p("  " + "   ".join(sev_parts))
        _p("")

    for f in sorted(real, key=lambda x: order.index(x.severity) if x.severity in order else 99):
        _print_finding_full(f, show_full_secret=show_full_secret)

    if fps and verbose:
        _p(f"  {A.DIM}{'─' * 40}{A.RESET}")
        _p(f"  {A.DIM}Likely false positives ({len(fps)}){A.RESET}")
        for f in fps[:10]:
            fname = f.file_url.split("/")[-1] if "/" in f.file_url else f.file_url
            _p(f"  {A.DIM}  - {f.title}  {fname}:{f.line_number}{A.RESET}")
    _p("")


def _print_finding(f, verbose: bool = False) -> None:
    """Backward-compat wrapper."""
    _print_finding_full(f, show_full_secret=True)


# ---------------------------------------------------------------------------
# Discovery section (JS assets, compact)
# ---------------------------------------------------------------------------

def print_js_inventory(js_files, verbose: bool = False, per_file_stats=None) -> None:
    """Compact asset summary - full list only in verbose mode."""
    if not js_files:
        return

    headless_count  = sum(1 for j in js_files if "headless-captured" in (j.technology or ""))
    inline_count    = sum(1 for j in js_files if j.url.startswith("inline:") or j.url.startswith("html:"))
    recovered_count = sum(1 for j in js_files if j.url.startswith("sourcemap://"))
    static_count    = len(js_files) - headless_count - inline_count - recovered_count
    total_size      = sum(j.size_bytes for j in js_files if j.size_bytes)

    _section("JAVASCRIPT ASSETS", str(len(js_files)))

    # Compact summary row
    rows = [
        ("Analyzed",   str(len(js_files))),
        ("Inline",     str(inline_count)),
        ("Static",     str(static_count)),
        ("Browser",    str(headless_count) if headless_count else None),
        ("Recovered",  str(recovered_count) if recovered_count else None),
        ("Total size", f"{total_size/1024:.0f} KB"),
    ]
    for lbl, val in rows:
        if val is not None:
            _p(f"  {_label(lbl)}{val}")
    _p("")

    if not verbose:
        return

    # Verbose: per-file table
    stats_map: dict = {}
    if per_file_stats:
        for s in per_file_stats:
            stats_map[s["url"]] = s

    js_files_only = [j for j in js_files if not j.url.startswith("html:")]
    html_entries  = [s for s in (per_file_stats or []) if s.get("technology") == "html-attrs"]
    w = _w()
    path_w = max(30, w - 52)

    for js in js_files_only:
        size = f"{js.size_bytes/1024:.1f}KB" if js.size_bytes else "?"
        url  = js.url
        tag  = ""

        if url.startswith("sourcemap://"):
            url = url.replace("sourcemap://", "")
            tag = f" {A.B_GREEN}[recovered]{A.RESET}"
        elif url.startswith("inline:") or url.startswith("html:"):
            bare = re.sub(r"^(inline:|html:)", "", url)
            _frag = re.search(r"#script-(\d+)-[a-f0-9]+$", bare)
            if _frag:
                _sn = _frag.group(1)
                _pd = bare.split("#")[0]
                _pd = re.sub(r"^https?://", "", _pd).rstrip("/") or "/"
                url = f"script {_sn} @ {_pd}"
            else:
                url = re.sub(r"^https?://[^/]+", "", bare) or bare
            tag = f" {A.DIM}[inline]{A.RESET}"
        elif "headless-captured" in (js.technology or ""):
            tag = f" {A.B_CYAN}[browser]{A.RESET}"

        _display = re.sub(r"^https?://[^/]+", "", url) or url
        if not _display or _display == "/":
            _display = url.rstrip("/").split("/")[-1] or url

        st = stats_map.get(js.url)
        n_sec = st["secrets"]   if st else 0
        n_ep  = st["endpoints"] if st else 0

        heat = min(4, n_sec * 2 + (1 if n_ep > 10 else 0))
        hot  = A.B_BRIGHT_RED + "█" * heat + A.RESET
        cold = A.DIM + "░" * (4 - heat) + A.RESET

        fname    = _display[:path_w].ljust(path_w + 1)
        sec_c    = A.B_BRIGHT_RED if n_sec > 0 else A.DIM
        ep_c     = A.B_CYAN       if n_ep  > 0 else A.DIM
        stats_s  = f"  {sec_c}s:{n_sec}{A.RESET}  {ep_c}ep:{n_ep}{A.RESET}" if st else f"  {A.DIM}--{A.RESET}"
        smap     = f" {A.B_YELLOW}[map]{A.RESET}" if getattr(js, "has_source_map", False) else ""
        size_str = A.DIM + f"{size:>7}" + A.RESET
        _p(f"  {A.DIM}-{A.RESET} {fname}{tag}{smap}  {size_str}  {hot}{cold}{stats_s}")

    if html_entries:
        _p("")
        _p(f"  {A.DIM}HTML attribute findings:{A.RESET}")
        for he in html_entries:
            _page = re.sub(r"^https?://[^/]+", "", he["url"].replace("html:", "")) or he["url"]
            sec_c = A.B_BRIGHT_RED if he["secrets"] > 0 else A.DIM
            _p(f"  {A.DIM}-{A.RESET} {_page[:path_w].ljust(path_w + 1)}  {A.DIM}[page]{A.RESET}  {sec_c}s:{he['secrets']}{A.RESET}")

    _p("")


# ---------------------------------------------------------------------------
# Secret analysis pill row
# ---------------------------------------------------------------------------

def print_secret_analysis(findings) -> None:
    if not findings:
        return

    def _is_public_id(f):
        return getattr(f, "classification", "") == "PUBLIC_IDENTIFIER" or f.rule_id in ("NETLIFY_SITE_ID",)

    secrets   = [f for f in findings if not _is_public_id(f)]
    pub_ids   = [f for f in findings if _is_public_id(f)]
    total     = len(secrets)
    high_conf = sum(1 for f in secrets if f.confidence >= 0.85 and f.status != "likely_false_positive")
    validated = sum(1 for f in secrets if f.status == "validated")

    _section("SECRET ANALYSIS")

    def _pill(count, label, active_color=""):
        lbr = A.DIM + "[" + A.RESET
        rbr = A.DIM + "]" + A.RESET
        c   = active_color if (active_color and count) else A.DIM
        num = f"{c}{count}{A.RESET}"
        txt = f"{A.DIM} {label}{A.RESET}"
        return f"{lbr} {num}{txt} {rbr}"

    pills = [
        _pill(total,        "detected",        A.BRIGHT_WHITE),
        _pill(high_conf,    "high confidence", A.B_BRIGHT_RED),
        _pill(validated,    "validated",       A.B_BRIGHT_RED),
        _pill(len(pub_ids), "public id",       A.DIM),
    ]
    _p("  " + "  ".join(pills))
    _p("")


# ---------------------------------------------------------------------------
# Feature sections (source maps, webpack, passive, headless)
# ---------------------------------------------------------------------------

def print_source_maps(discovered, valid, recovered, sources, details=None) -> None:
    if not discovered:
        return
    _section("SOURCE MAPS")
    for lbl, val in [("Discovered", str(discovered)), ("Valid", str(valid)),
                     ("Recovered", str(recovered)), ("Sources", str(sources))]:
        _p(f"  {_label(lbl)}{val}")
    if details:
        _p("")
        for d in details:
            _p(f"  {A.BRIGHT_WHITE}{d.get('js','')}{A.RESET}")
            _p(f"  {A.DIM}  +-- {d.get('map','')}{A.RESET}")
            if d.get("sources"):
                _p(f"  {A.DIM}     +-- {d['sources']} original sources{A.RESET}")
    _p("")


def print_webpack(runtime, discovered, downloaded, endpoints=0, findings=0) -> None:
    if not discovered:
        return
    _section("WEBPACK CHUNKS")
    rows = [("Runtime", "detected" if runtime else "not found"),
            ("Discovered", str(discovered)), ("Downloaded", str(downloaded))]
    if endpoints: rows.append(("New endpoints", str(endpoints)))
    if findings:  rows.append(("New findings",  str(findings)))
    for lbl, val in rows:
        _p(f"  {_label(lbl)}{val}")
    _p("")


def print_passive(source, urls, js, unique, new, errors=None) -> None:
    _section("PASSIVE DISCOVERY")
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
    _p("")


def print_headless(pages, js, xhr=0, fetch=0, ws=0, routes=0, endpoints=0,
                   workers=0, timings=None) -> None:
    _section("BROWSER DISCOVERY")
    rows = [("Engine", "Chromium"), ("Pages", str(pages)), ("JS captured", str(js))]
    if xhr or fetch: rows.append(("API calls",  str(xhr + fetch)))
    if ws:           rows.append(("WebSockets", str(ws)))
    if routes:       rows.append(("Routes",     str(routes)))
    if endpoints:    rows.append(("Endpoints",  str(endpoints)))
    if workers:      rows.append(("Workers",    str(workers)))
    for lbl, val in rows:
        _p(f"  {_label(lbl)}{val}")
    if timings:
        _p("")
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
    _p("")


# ---------------------------------------------------------------------------
# Vulnerable libraries
# ---------------------------------------------------------------------------

def _print_libraries(lib_findings) -> None:
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

    _section("VULNERABLE LIBRARIES", f"{total_cves} in {unique_libs}")

    parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts.get(sev):
            c = SEV_COLOR.get(sev, "")
            parts.append(f"{c}{counts[sev]} {sev.lower()}{A.RESET}")
    if parts:
        _p("  " + "   ".join(parts))
    _p("")

    for lib_key in sorted(by_lib.keys(), key=lambda k: -max(c.cvss for c in by_lib[k])):
        cves    = sorted(by_lib[lib_key], key=lambda x: -x.cvss)
        library = cves[0].library
        version = cves[0].version
        fname   = cves[0].source_file.split("/")[-1] if "/" in cves[0].source_file else cves[0].source_file
        top_sev = cves[0].severity
        hc      = SEV_COLOR.get(top_sev, "")

        title_line = f"{hc}{A.BOLD}{library} {version}{A.RESET}  {A.DIM}{fname}{A.RESET}"
        _p(f"  {hc}┃{A.RESET} {title_line}")
        for cve in cves:
            c        = SEV_COLOR.get(cve.severity, "")
            sev_tag  = f"{c}{cve.severity:<8}{A.RESET}"
            cvss_tag = f"{A.DIM}CVSS {cve.cvss}{A.RESET}"
            _p(f"  {A.DIM}│{A.RESET} {sev_tag} {A.CYAN}{cve.cve_id}{A.RESET}  {cvss_tag}")
            _p(f"  {A.DIM}│{A.RESET}          {cve.description}")
            _p(f"  {A.DIM}│{A.RESET}          {A.DIM}Fix: {cve.remediation}{A.RESET}")
        _p("")


# ---------------------------------------------------------------------------
# Passive intelligence
# ---------------------------------------------------------------------------

def _print_intelligence(intel) -> None:
    has = (intel.sitemap_urls or intel.api_endpoints or
           intel.security_txt or intel.openid_config or intel.api_schema)
    if not has:
        return

    _section("PASSIVE INTELLIGENCE")

    if intel.sitemap_urls:
        _p(f"  {_label('Sitemap URLs')}{len(intel.sitemap_urls)}")
        for url in intel.sitemap_urls[:8]:
            _p(f"  {A.DIM}  - {url[:_w()-8]}{A.RESET}")
        if len(intel.sitemap_urls) > 8:
            _p(f"  {A.DIM}  ... and {len(intel.sitemap_urls)-8} more{A.RESET}")

    if intel.api_schema:
        _p(f"\n  {_label('API Schema')}{intel.api_schema.get('type','?')}  {A.DIM}{intel.api_schema.get('url','')}{A.RESET}")
        for ep in intel.api_endpoints[:12]:
            _p(f"  {A.DIM}  - {ep}{A.RESET}")

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
    _p("")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def print_endpoints(endpoints, validation_results=None, verbose: bool = False) -> None:
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

    w = _w()
    _section("ENDPOINTS", str(len(endpoints)))

    shown = 0
    limit = 9999 if verbose else 40
    cat_order = ["AUTH", "ADMIN", "GRAPHQL", "UPLOAD", "DOWNLOAD", "API",
                 "SERVERLESS", "WEBSOCKET", "ROUTE", "UNKNOWN"]

    for cat in cat_order:
        eps = by_cat.get(cat, [])
        if not eps:
            continue
        c = cat_colors.get(cat, A.DIM)
        _p(f"  {c}{A.BOLD}{cat}{A.RESET}  {A.DIM}{len(eps)}{A.RESET}")

        for ep in eps:
            if shown >= limit:
                break
            method = (ep.method or "?").ljust(6)
            url    = ep.url[:w - 18]
            vr     = val_map.get(ep.url)
            mc = (A.B_BRIGHT_RED if ep.method in ("DELETE", "PUT") else
                  A.ORANGE       if ep.method == "POST"             else A.DIM)

            if vr:
                sc2 = (A.B_GREEN      if vr.status_code == 200             else
                       A.B_YELLOW     if vr.status_code in (301, 302, 307) else
                       A.B_BRIGHT_RED if vr.status_code in (401, 403)      else A.DIM)
                ct  = vr.content_type.split(";")[0][:20] if vr.content_type else ""
                row = (f"  {A.DIM}├─{A.RESET} {mc}{method}{A.RESET}  {url}"
                       + f"  {sc2}{vr.status_code}{A.RESET}"
                       + (f"  {A.DIM}{ct}{A.RESET}" if ct else ""))
            else:
                row = f"  {A.DIM}├─{A.RESET} {mc}{method}{A.RESET}  {url}"
            _p(row)

            if verbose:
                bf   = getattr(ep, "body_fields",  None) or []
                qp   = getattr(ep, "query_params", None) or []
                pp   = getattr(ep, "path_params",  None) or []
                auth = getattr(ep, "auth_context", "") or ""
                if bf:
                    _p(f"  {A.DIM}│     body: {', '.join(f['name'] for f in bf[:6])}{A.RESET}")
                if qp:
                    _p(f"  {A.DIM}│     query: {', '.join(f['name'] for f in qp[:6])}{A.RESET}")
                if auth:
                    _p(f"  {A.DIM}│     {A.B_YELLOW}auth: {auth}{A.RESET}")
            shown += 1

        _p("")

    if shown >= limit and not verbose:
        _p(f"  {A.DIM}  ... use -v to show all {len(endpoints)} endpoints{A.RESET}")
    _p("")


# ---------------------------------------------------------------------------
# GraphQL
# ---------------------------------------------------------------------------

def print_graphql(schemas) -> None:
    if not schemas:
        return
    _section("GRAPHQL")
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
    _p("")


# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------

def print_infrastructure(items) -> None:
    if not items:
        return
    by_cls: dict = {}
    for item in items:
        by_cls.setdefault(item.classification, []).append(item)
    _section("INFRASTRUCTURE", str(len(items)))
    for cls, its in sorted(by_cls.items()):
        cls_c = (A.B_BRIGHT_RED if cls in ("PRIVATE_IP", "CLOUD_METADATA") else
                 A.ORANGE       if "HOSTNAME" in cls                         else A.DIM)
        _p(f"\n  {cls_c}{cls}{A.RESET}  {A.DIM}({len(its)}){A.RESET}")
        for item in its[:10]:
            fname = item.source_file.split("/")[-1] if "/" in item.source_file else item.source_file
            _p(f"  {A.DIM}  - {item.value}  line {item.line_number} in {fname}{A.RESET}")
    _p("")


# ---------------------------------------------------------------------------
# Subdomains
# ---------------------------------------------------------------------------

def print_subdomains(subdomains) -> None:
    if not subdomains:
        return
    _section("SUBDOMAINS", str(len(subdomains)))
    for sub in subdomains[:30]:
        _p(f"  {A.DIM}  - {sub}{A.RESET}")
    if len(subdomains) > 30:
        _p(f"  {A.DIM}  ... and {len(subdomains)-30} more{A.RESET}")
    _p("")


# ---------------------------------------------------------------------------
# Endpoint validation
# ---------------------------------------------------------------------------

def print_validation_results(results) -> None:
    interesting = [r for r in results if r.interesting]
    if not interesting:
        return
    _section("ENDPOINT VALIDATION", f"{len(interesting)} interesting")
    for r in interesting:
        sc = (A.B_GREEN      if r.status_code == 200             else
              A.B_YELLOW     if r.status_code in (301, 302, 307) else
              A.B_BRIGHT_RED if r.status_code in (401, 403)      else A.DIM)
        url   = r.endpoint[:_w()-20]
        notes = " - ".join(r.notes[:2]) if r.notes else ""
        _p(f"  {sc}{r.status_code}{A.RESET}  {url}  {A.DIM}{notes}{A.RESET}")
    _p("")


# ---------------------------------------------------------------------------
# Attack surface analysis (existing function - kept for compat)
# ---------------------------------------------------------------------------

def print_attack_surface(surface) -> None:
    if not surface:
        return
    has_content = (surface.get("total_items", 0) > 0 or surface.get("state_change"))
    if not has_content:
        return

    total = surface.get("total_items", 0)
    _section("ATTACK SURFACE ANALYSIS", str(total))

    parts = []
    for key, lbl, color in [
        ("idor",          "IDOR",          A.B_BRIGHT_RED),
        ("injection",     "Injection",     A.ORANGE),
        ("file_ops",      "LFI/Path",      A.ORANGE),
        ("ssrf",          "SSRF",          A.B_YELLOW),
        ("open_redirect", "Open Redirect", A.B_YELLOW),
    ]:
        n = len(surface.get(key, []))
        if n: parts.append(f"{color}{n} {lbl}{A.RESET}")
    if parts:
        _p("  " + "   ".join(parts))
        _p("")

    def _print_group(items, title, color):
        if not items: return
        _p(f"  {color}{A.BOLD}{title}{A.RESET}  {A.DIM}({len(items)}){A.RESET}")
        for it in items[:15]:
            path = it.endpoint_url[:_w()-30]
            _p(f"  {A.DIM}  {it.method:<6}{A.RESET} {path}")
            _p(f"  {A.DIM}         param: {A.RESET}{color}{it.param_name}{A.RESET}  {A.DIM}{it.reason}{A.RESET}")
        if len(items) > 15:
            _p(f"  {A.DIM}  ... and {len(items)-15} more{A.RESET}")
        _p("")

    _print_group(surface.get("idor",          []), "IDOR CANDIDATES",       A.B_BRIGHT_RED)
    _print_group(surface.get("injection",     []), "INJECTION CANDIDATES",  A.ORANGE)
    _print_group(surface.get("file_ops",      []), "PATH TRAVERSAL / LFI", A.ORANGE)
    _print_group(surface.get("ssrf",          []), "SSRF CANDIDATES",       A.B_YELLOW)
    _print_group(surface.get("open_redirect", []), "OPEN REDIRECT",         A.B_YELLOW)

    sc = surface.get("state_change", [])
    if sc:
        _p(f"  {A.BRIGHT_MAGENTA}{A.BOLD}STATE-CHANGING ENDPOINTS{A.RESET}  {A.DIM}({len(sc)}){A.RESET}")
        for ep in sc[:15]:
            mc = A.B_BRIGHT_RED if ep.method in ("DELETE", "PUT") else A.ORANGE
            _p(f"  {mc}  {ep.method:<6}{A.RESET} {ep.url[:_w()-14]}")
        if len(sc) > 15:
            _p(f"  {A.DIM}  ... and {len(sc)-15} more{A.RESET}")
        _p("")


# ---------------------------------------------------------------------------
# Coverage (with progress bars, NOT RUN vs 0 distinction)
# ---------------------------------------------------------------------------

def print_coverage(coverage) -> None:
    if not coverage:
        return

    _section("COVERAGE")

    p  = coverage.pages
    j  = coverage.js
    r  = coverage.routes
    rt = coverage.runtime
    sm = coverage.source_maps

    w      = _w()
    bar_w  = min(20, max(10, w - 50))
    rc     = A.RESET

    def _bar(current, total, color=None) -> str:
        if total <= 0:
            pct = 1.0
        else:
            pct = min(1.0, current / total)
        filled = int(pct * bar_w)
        empty  = bar_w - filled
        c = color or (A.B_GREEN if pct >= 1.0 else A.B_YELLOW)
        return (c + "█" * filled + rc + A.DIM + "░" * empty + rc)

    # Progress bars for crawled items
    _p(f"  {A.DIM}{'Pages':<14}{rc}{_bar(p.visited, p.discovered)}  {A.BRIGHT_WHITE}{p.visited}/{p.discovered}{rc}")
    _p(f"  {A.DIM}{'JavaScript':<14}{rc}{_bar(j.analyzed, j.discovered)}  {A.BRIGHT_WHITE}{j.analyzed}/{j.discovered}{rc}")
    _p(f"  {A.DIM}{'Routes':<14}{rc}{_bar(r.visited, r.discovered)}  {A.BRIGHT_WHITE}{r.visited}/{r.discovered}{rc}")
    _p("")

    # Runtime capabilities - distinguish NOT RUN from 0
    has_rt = any([rt.api_requests, rt.websockets, rt.workers, rt.iframes])
    rt_was_run = coverage.blind_spots and not any(
        "headless" in bs.description.lower() for bs in coverage.blind_spots
    )

    if has_rt:
        parts = []
        if rt.api_requests: parts.append(f"api: {rt.api_requests}")
        if rt.websockets:   parts.append(f"ws: {rt.websockets}")
        if rt.workers:      parts.append(f"workers: {rt.workers}")
        if rt.iframes:      parts.append(f"iframes: {rt.iframes}")
        _p(f"  {A.DIM}{'Runtime':<14}{rc}{A.B_GREEN}COMPLETE{rc}  {A.DIM}{', '.join(parts)}{rc}")
    else:
        _p(f"  {A.DIM}{'Runtime':<14}{rc}{A.DIM}NOT RUN{rc}")

    if sm.discovered > 0:
        sm_color = A.B_GREEN if sm.recovered > 0 else A.B_YELLOW
        _p(f"  {A.DIM}{'Source Maps':<14}{rc}{sm_color}{sm.recovered} recovered{rc}  {A.DIM}of {sm.discovered} found{rc}")
    else:
        # Check if source maps were attempted
        sm_attempted = any("source map" in bs.description.lower() for bs in (coverage.blind_spots or []))
        if sm_attempted:
            _p(f"  {A.DIM}{'Source Maps':<14}{rc}{A.DIM}NOT FOUND{rc}")
        else:
            _p(f"  {A.DIM}{'Source Maps':<14}{rc}{A.DIM}NOT RUN{rc}")

    # Authentication
    auth_missing = any("auth" in bs.description.lower() or "session" in bs.description.lower()
                       for bs in (coverage.blind_spots or []))
    if auth_missing:
        _p(f"  {A.DIM}{'Auth':<14}{rc}{A.B_YELLOW}NOT PROVIDED{rc}")
    else:
        _p(f"  {A.DIM}{'Auth':<14}{rc}{A.B_GREEN}PROVIDED{rc}")

    # Failures
    _p("")
    if p.failed:
        _p(f"  {A.B_YELLOW}!{rc}  {p.failed} page(s) failed to load")
    if p.auth_required:
        _p(f"  {A.B_YELLOW}!{rc}  {p.auth_required} auth-required page(s) skipped")
        for u in p.auth_urls[:3]:
            _p(f"  {A.DIM}     {u}{rc}")
    if j.failed:
        _p(f"  {A.B_YELLOW}!{rc}  {j.failed} JS file(s) failed")
    if r.unvisited:
        _p(f"  {A.B_YELLOW}!{rc}  {r.unvisited} route(s) unvisited")

    _p("")


# ---------------------------------------------------------------------------
# Next action engine
# ---------------------------------------------------------------------------

def _print_next_action(target: str, extras: dict) -> None:
    """
    Analyze what was NOT run and recommend the most useful next command.
    Never recommends flags already used.
    """
    args_flags  = extras.get("_args_flags", {})
    coverage    = extras.get("coverage")
    blind_spots = getattr(coverage, "blind_spots", []) if coverage else []

    missing = []
    flags   = []

    if not args_flags.get("headless"):
        missing.append("runtime discovery")
        flags.append("--headless")

    if not args_flags.get("source_maps"):
        missing.append("source-map recovery")
        flags.append("--source-maps")

    auth_missing = any("auth" in bs.description.lower() or "session" in bs.description.lower()
                       for bs in blind_spots)
    if auth_missing and not args_flags.get("has_cookie"):
        missing.append("authentication")
        flags.append("--cookie 'session=<YOUR_SESSION>'")

    if not args_flags.get("validate"):
        flags.append("--validate")

    if not missing and not flags:
        return

    _section("NEXT ACTION")

    if missing:
        _p(f"  {A.DIM}{', '.join(missing).capitalize()} {'was' if len(missing) == 1 else 'were'} not performed.{A.RESET}")
        _p("")

    _p(f"  {A.DIM}Recommended:{A.RESET}")
    _p("")

    cmd_parts = [f"  bundlespy scan {target}"]
    for flag in flags:
        cmd_parts.append(f"    {flag}")
    _p(A.BRIGHT_WHITE + "\n".join(cmd_parts) + A.RESET)
    _p("")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

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

    w  = _w()
    rc = A.RESET

    _p("")
    _rule()
    _p("")

    # RESULT header
    dur_str  = duration or ""
    result_label = A.B_GREEN + "RESULT" + rc
    dur_right    = A.DIM + dur_str + rc if dur_str else ""
    gap_len      = max(1, w - 2 - len("RESULT") - len(dur_str))
    _p(f"  {result_label}{' ' * gap_len}{dur_right}")
    _p("")

    # Severity summary line
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_parts = []
    for sev in order:
        n = counts.get(sev, 0)
        if n:
            c = SEV_COLOR.get(sev, A.DIM)
            sev_parts.append(f"{c}{sev} {n}{rc}")
    if sev_parts:
        _p("  " + "  -  ".join(sev_parts))
        _p("")

    # Key stats
    js_count = len([j for j in result.js_files if not j.url.startswith("sourcemap://")])
    _p(f"  {A.DIM}{result.pages_crawled} pages  {js_count} JavaScript assets  {len(result.endpoints)} endpoints  {len(real)} findings{rc}")

    # Coverage status
    coverage = extras.get("coverage")
    if coverage:
        blind_spots = getattr(coverage, "blind_spots", []) or []
        has_high_blind = any(bs.severity == "HIGH" for bs in blind_spots)
        cov_label = "PARTIAL" if blind_spots else "COMPLETE"
        cov_color = A.B_YELLOW if has_high_blind else (A.B_GREEN if not blind_spots else A.ORANGE)
        _p(f"  {A.DIM}Coverage:{rc}  {cov_color}{cov_label}{rc}")

    args_flags = extras.get("_args_flags", {})
    if not args_flags.get("headless"):
        _p(f"  {A.DIM}Runtime:{rc}  {A.DIM}NOT RUN{rc}")
    if not args_flags.get("has_cookie"):
        _p(f"  {A.DIM}Auth:{rc}  {A.DIM}NOT PROVIDED{rc}")

    # Validated secrets callout
    if validated:
        _p("")
        _p(f"  {A.B_BRIGHT_RED}[!]{rc} {A.B_BRIGHT_RED}{len(validated)} secret{'s' if len(validated) != 1 else ''} VALIDATED as active{rc}")

    # Report paths
    if report_paths:
        _p("")
        for fmt, path in report_paths.items():
            _p(f"  {A.DIM}{fmt.upper():<8}{rc}  {path}")

    _p("")

    # Verdict
    if counts.get("CRITICAL") or validated:
        _p(f"  {A.B_BRIGHT_RED}Critical findings present. Immediate action required.{rc}")
    elif counts.get("HIGH"):
        _p(f"  {A.ORANGE}Review required: {counts['HIGH']} HIGH severity finding{'s' if counts['HIGH'] != 1 else ''}.{rc}")
    elif counts.get("MEDIUM"):
        _p(f"  {A.B_YELLOW}Medium severity findings present.{rc}")
    else:
        _p(f"  {A.B_GREEN}Scan complete. No critical findings.{rc}")

    _rule()
    _p("")


def _fmt_sev_cell(sev: str, count: int) -> str:
    dot_c = SEVERITY_DOT_COLOR.get(sev.lower(), A.WHITE)
    lbl_c = SEV_COLOR.get(sev, A.WHITE)
    label = SEVERITY_LABEL.get(sev.lower(), sev.upper()).strip()
    rc    = A.RESET
    return (dot_c + "- " + rc + lbl_c + f"{label:<8}" + rc + "  " + A.BRIGHT_WHITE + str(count) + rc)


# ---------------------------------------------------------------------------
# Main report orchestrator
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
    Information hierarchy: target -> status -> overview -> attack surface ->
    security findings -> discovery -> coverage -> next action -> result
    """
    extras = extras or {}

    if extras.get("auth_result"):
        print_auth_result(extras["auth_result"])

    # Scan status (what ran, what was skipped)
    args_flags = extras.get("_args_flags", {})
    if args_flags:
        _print_scan_status(args_flags)

    # Overview panel
    _print_overview(result, extras)

    # Attack surface (tree view)
    _print_attack_surface_tree(result, extras)

    # Passive/headless discovery sections
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

    # Secret analysis
    print_secret_analysis(result.findings)

    # Security findings (redesigned)
    print_findings(result.findings, verbose=verbose, show_full_secret=show_sensitive)

    # Endpoints (tree style)
    print_endpoints(result.endpoints, validation_results=validation_results, verbose=verbose)

    # Attack surface analysis (parameter-level)
    surface = extras.get("attack_surface")
    if surface and (surface.get("total_items", 0) > 0 or surface.get("state_change")):
        print_attack_surface(surface)

    # Coverage
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

    # JS inventory (compact summary always, full list in verbose)
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

    # Next action engine
    _print_next_action(result.target_url, extras)

    print_summary(result, extras=extras, report_paths=report_paths)
