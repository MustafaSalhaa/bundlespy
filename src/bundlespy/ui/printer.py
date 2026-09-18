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
    _p(f"  {A.BRIGHT_WHITE}+{A.RESET}  {label}{det}")


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

    BundleSpy 1.0.0  JavaScript Attack Surface Intelligence
    --------------------------------------------------------

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
# Scan status with risk summary (immediately after target)
# ---------------------------------------------------------------------------

def _print_scan_status(result, args_flags: dict) -> None:
    """
    SCAN STATUS block: pipeline completion + risk summary inline.

    SCAN STATUS
      PARTIAL - 7/9 stages completed

      HIGH 2 - MEDIUM 1 - INFO 1
      2 pages - 5 JS assets - 4 endpoints
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
    done  = sum(1 for _, ran in stages if ran)
    total = len(stages)

    if done == total:
        status_color = A.B_GREEN
        status_label = "COMPLETE"
    else:
        status_color = A.B_YELLOW
        status_label = "PARTIAL"

    _section("SCAN STATUS")
    _p(f"  {status_color}{status_label}{A.RESET}  {A.DIM}{done}/{total} stages completed{A.RESET}")

    # Risk summary inline
    if result is not None:
        real = [f for f in result.findings if f.status != "likely_false_positive"]
        counts: dict = {}
        for f in real:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        parts  = []
        for sev in order:
            n = counts.get(sev, 0)
            if n:
                c = SEV_COLOR.get(sev, A.DIM)
                parts.append(f"{c}{sev} {n}{A.RESET}")

        if parts:
            _p("")
            _p("  " + "  -  ".join(parts))

        js_count = len([j for j in result.js_files if not j.url.startswith("sourcemap://")])
        _p(f"  {A.DIM}{result.pages_crawled} pages - {js_count} JS assets - {len(result.endpoints)} endpoints{A.RESET}")

    _p("")


# ---------------------------------------------------------------------------
# Attack surface (tree view) - shown before findings
# ---------------------------------------------------------------------------

def _print_attack_surface_tree(result, extras: dict) -> None:
    """
    ATTACK SURFACE tree view, grouped by category.
    Shows what was found - never fabricates. Marks NOT RUN capabilities.

    ATTACK SURFACE

      Pages
      +-- /
      +-- /admin

      API
      +-- GET /stock-toggle

      Serverless
      +-- GET /.netlify/functions/stock
      +-- GET /.netlify/functions/create-checkout

      Client Routes
      +-- 1 discovered

      Runtime APIs
      +-- NOT RUN
    """
    _section("ATTACK SURFACE")

    by_cat: dict = {}
    for ep in result.endpoints:
        by_cat.setdefault(ep.category, []).append(ep)

    args_flags = extras.get("_args_flags", {})
    w = _w()
    rc = A.RESET

    def _tree_items(eps: list, limit: int = 15) -> list:
        """Return (path, method) pairs sorted, deduplicated. Uses relative paths."""
        seen: dict = {}
        for ep in eps:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(ep.url)
                path   = parsed.path or ep.url
                if parsed.query:
                    path += "?" + parsed.query
                path = path[:w - 12]
            except Exception:
                path = ep.url[:w - 12]
            if path not in seen:
                seen[path] = ep.method or ""
        return list(seen.items())[:limit]

    def _tree_group(title: str, items: list, color: str = "", extra_note: str = "") -> None:
        c = color or A.BRIGHT_WHITE
        _p(f"  {c}{title}{rc}")
        for i, (path, method) in enumerate(items):
            is_last = (i == len(items) - 1)
            prefix  = "└─" if is_last else "├─"
            meth    = ""
            if method and method not in ("GET", "?", "UNKNOWN", ""):
                meth = f" {A.DIM}{method}{rc}"
            elif method == "GET":
                meth = f" {A.DIM}GET{rc}"
            _p(f"  {A.DIM}{prefix}{rc} {path}{meth}")
        if extra_note:
            _p(f"  {A.DIM}└─ {extra_note}{rc}")
        _p("")

    def _tree_not_run(title: str) -> None:
        _p(f"  {A.BRIGHT_WHITE}{title}{rc}")
        _p(f"  {A.DIM}└─ NOT RUN{rc}")
        _p("")

    def _tree_count(title: str, n: int, label: str = "discovered") -> None:
        _p(f"  {A.BRIGHT_WHITE}{title}{rc}")
        _p(f"  {A.DIM}└─ {n} {label}{rc}")
        _p("")

    # ── Pages ─────────────────────────────────────────────────────────────────
    # Collect unique page paths from all endpoint categories
    crawled = result.pages_crawled or 0
    seen_pages: dict = {}
    for ep in result.endpoints:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(ep.url)
            path   = parsed.path or "/"
            # Normalize: strip trailing slash unless root
            path = path.rstrip("/") or "/"
            if path not in seen_pages:
                seen_pages[path] = ""
        except Exception:
            pass
    # Always include root
    if "/" not in seen_pages and crawled > 0:
        seen_pages["/"] = ""
    page_items = list(seen_pages.items())[:20]

    _p(f"  {A.BRIGHT_WHITE}Pages{rc}")
    if page_items:
        for i, (path, _) in enumerate(page_items):
            is_last = (i == len(page_items) - 1)
            prefix  = "└─" if is_last else "├─"
            _p(f"  {A.DIM}{prefix}{rc} {path}")
    elif crawled > 0:
        _p(f"  {A.DIM}└─ /{rc}")
    else:
        _p(f"  {A.DIM}└─ NOT RUN{rc}")
    _p("")

    # ── Admin ─────────────────────────────────────────────────────────────────
    admin_eps = by_cat.get("ADMIN", [])
    if admin_eps:
        items = _tree_items(admin_eps)
        _tree_group("Admin", items, A.ORANGE)

    # ── API ───────────────────────────────────────────────────────────────────
    api_eps = by_cat.get("API", [])
    if api_eps:
        items = _tree_items(api_eps)
        _tree_group("API", items, A.B_BLUE)

    # ── Serverless ────────────────────────────────────────────────────────────
    serverless = by_cat.get("SERVERLESS", [])
    if serverless:
        items = _tree_items(serverless)
        _tree_group("Serverless", items, A.B_CYAN)

    # ── Auth endpoints ────────────────────────────────────────────────────────
    auth_eps = by_cat.get("AUTH", [])
    if auth_eps:
        items = _tree_items(auth_eps)
        _tree_group("Authentication", items, A.B_BRIGHT_RED)

    # ── Client Routes ─────────────────────────────────────────────────────────
    # From JS router analysis
    coverage    = extras.get("coverage")
    route_stats = getattr(coverage, "routes", None) if coverage else None
    if route_stats and route_stats.discovered > 0:
        _tree_count("Client Routes", route_stats.discovered)
    elif args_flags.get("headless"):
        headless_routes = extras.get("headless_stats", {}).get("routes", 0)
        _tree_count("Client Routes", headless_routes)

    # ── GraphQL ───────────────────────────────────────────────────────────────
    gql_eps = by_cat.get("GRAPHQL", [])
    if gql_eps:
        items = _tree_items(gql_eps)
        _tree_group("GraphQL", items, A.BRIGHT_MAGENTA)

    # ── Runtime APIs (XHR/Fetch) - only meaningful if headless ran ─────────────
    if args_flags.get("headless"):
        xhr   = extras.get("headless_stats", {}).get("xhr", 0)
        fetch = extras.get("headless_stats", {}).get("fetch", 0)
        total = xhr + fetch
        _p(f"  {A.BRIGHT_WHITE}Runtime APIs{rc}")
        _p(f"  {A.DIM}└─ {total} intercepted{rc}")
        _p("")
    else:
        _tree_not_run("Runtime APIs")

    # ── WebSockets ────────────────────────────────────────────────────────────
    ws_eps = by_cat.get("WEBSOCKET", [])
    if ws_eps:
        items = _tree_items(ws_eps)
        _tree_group("WebSockets", items, A.B_CYAN)
    elif args_flags.get("headless"):
        ws_count = extras.get("headless_stats", {}).get("ws", 0)
        if ws_count:
            _tree_count("WebSockets", ws_count, "detected")
        # If headless ran and found 0 WS, we just skip it - not clutter


# ---------------------------------------------------------------------------
# Security findings (redesigned per spec)
# ---------------------------------------------------------------------------

def _classification_label(f) -> str:
    """Convert internal classification to human label."""
    cls = getattr(f, "classification", "") or ""
    mapping = {
        "likely_secret":      "Likely secret",
        "public_identifier":  "Public identifier",
        "PUBLIC_IDENTIFIER":  "Public identifier",
        "JWT":                "JWT",
        "API_KEY":            "API key",
        "PASSWORD":           "Password",
        "TOKEN":              "Token",
        "HASH":               "Hash",
        "PRIVATE_KEY":        "Private key",
        "CERTIFICATE":        "Certificate",
        "CONNECTION_STRING":  "Connection string",
    }
    return mapping.get(cls, cls.replace("_", " ").lower().capitalize() if cls else "")


def _validation_label(f) -> str:
    status = (f.status or "").lower()
    if status == "validated":
        return A.B_BRIGHT_RED + "VALIDATED" + A.RESET
    elif status == "validation_failed":
        return A.DIM + "FAILED" + A.RESET
    elif status == "likely_false_positive":
        return A.DIM + "EXCLUDED" + A.RESET
    else:
        return A.DIM + "NOT VALIDATED" + A.RESET


def _secret_redact(raw: str, show_full: bool = False) -> str:
    """Show head (20) + ... + tail (12) by default. Full value only if show_full."""
    if not raw:
        return ""
    if show_full:
        return raw
    if len(raw) > 40:
        return raw[:20] + A.DIM + "..." + A.RESET + raw[-12:]
    return raw


def _print_finding_full(f, show_full_secret: bool = False) -> None:
    """
    Structured finding card.

    HIGH  JWT Token in HTML Attribute
          JWT_IN_ATTRIBUTE

          Confidence   88%
          Type         JWT
          Validation   NOT VALIDATED

          Location
            https://example.com - line 1892

          Evidence
            eyJhbGci...To7Vo

          Remediation
            Generate authentication tokens server-side at runtime.
    """
    sev   = (f.severity or "INFO").upper()
    lbl_c = SEV_COLOR.get(sev, A.WHITE)
    dot_c = SEVERITY_DOT_COLOR.get(sev.lower(), A.WHITE)
    w     = _w()
    rc    = A.RESET
    ind   = "        "   # 8-space indent for sub-fields

    # ── Title line ─────────────────────────────────────────────────────────
    lbl = SEVERITY_LABEL.get(sev.lower(), sev).strip()
    _p(f"  {dot_c}┃{rc} {lbl_c}{A.BOLD}{lbl:<6}{rc}  {A.BRIGHT_WHITE}{A.BOLD}{f.title}{rc}")

    # ── Rule ID ────────────────────────────────────────────────────────────
    if f.rule_id:
        _p(f"  {A.DIM}│{rc}       {A.DIM}{f.rule_id}{rc}")

    # ── Classification / Confidence / Type / Validation ────────────────────
    _p(f"  {A.DIM}│{rc}")
    conf_pct = f"{f.confidence:.0%}" if f.confidence is not None else "?"
    _p(f"  {A.DIM}│{rc}  {A.DIM}Confidence{rc}   {A.BRIGHT_WHITE}{conf_pct}{rc}")

    cls_label = _classification_label(f)
    if cls_label:
        _p(f"  {A.DIM}│{rc}  {A.DIM}Type{rc}         {A.BRIGHT_WHITE}{cls_label}{rc}")

    _p(f"  {A.DIM}│{rc}  {A.DIM}Validation{rc}   {_validation_label(f)}")

    # ── Status badge (validated = highlight) ───────────────────────────────
    if (f.status or "").lower() == "validated":
        _p(f"  {A.DIM}│{rc}")
        _p(f"  {A.DIM}│{rc}  {A.B_BRIGHT_RED}[!] CONFIRMED ACTIVE{rc}")

    # ── Location ───────────────────────────────────────────────────────────
    _p(f"  {A.DIM}│{rc}")
    _p(f"  {A.DIM}│{rc}  {A.DIM}Location{rc}")
    url      = (f.file_url or "")[:w - 14]
    line_num = f.line_number
    occ      = getattr(f, "occurrences", None) or []
    loc      = url
    if line_num:
        loc += f"  -  line {line_num}"
    if occ and len(occ) > 1:
        loc += f"  +{len(occ)-1} more"
    _p(f"  {A.DIM}│{rc}    {A.BRIGHT_WHITE}{loc}{rc}")

    # ── Evidence ───────────────────────────────────────────────────────────
    raw = f.matched_value or ""
    if raw:
        _p(f"  {A.DIM}│{rc}")
        _p(f"  {A.DIM}│{rc}  {A.DIM}Evidence{rc}")
        ev = _secret_redact(raw, show_full=show_full_secret)
        _p(f"  {A.DIM}│{rc}    {A.BRIGHT_WHITE}{ev}{rc}")

    # ── Remediation ────────────────────────────────────────────────────────
    if f.remediation:
        _p(f"  {A.DIM}│{rc}")
        _p(f"  {A.DIM}│{rc}  {A.DIM}Remediation{rc}")
        max_w   = w - 16
        wrapped = textwrap.wrap(f.remediation[:300], max_w)
        for line in wrapped[:4]:
            _p(f"  {A.DIM}│{rc}    {A.DIM}{line}{rc}")

    _p("")


def print_findings(findings, verbose: bool = False, show_full_secret: bool = False) -> None:
    """
    Print security findings, separating security from informational.

    SECURITY FINDINGS shows HIGH/MEDIUM/LOW/CRITICAL.
    INFORMATION shows INFO findings separately.
    """
    real = [f for f in findings if f.status != "likely_false_positive"]
    fps  = [f for f in findings if f.status == "likely_false_positive"]

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    # Split security vs informational
    security_findings = [f for f in real if (f.severity or "INFO").upper() != "INFO"]
    info_findings     = [f for f in real if (f.severity or "INFO").upper() == "INFO"]

    if not real and not fps:
        _section("SECURITY FINDINGS")
        _p(f"  {A.DIM}No findings detected above the confidence threshold.{A.RESET}")
        _p("")
        return

    # ── SECURITY FINDINGS ─────────────────────────────────────────────────
    if security_findings:
        counts: dict = {}
        for f in security_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        fp_note = f"  {A.DIM}+{len(fps)} excluded{A.RESET}" if fps else ""
        _section("SECURITY FINDINGS", f"{len(security_findings)} findings{fp_note}")

        sev_parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if counts.get(sev):
                c = SEV_COLOR.get(sev, "")
                sev_parts.append(f"{c}{sev}  {A.BRIGHT_WHITE}{counts[sev]}{A.RESET}")
        if sev_parts:
            _p("  " + "   ".join(sev_parts))
            _p("")

        sorted_findings = sorted(
            security_findings,
            key=lambda x: order.index(x.severity) if x.severity in order else 99
        )
        for f in sorted_findings:
            _print_finding_full(f, show_full_secret=show_full_secret)

    elif fps:
        _section("SECURITY FINDINGS")
        _p(f"  {A.DIM}No security findings above threshold.{A.RESET}")
        _p(f"  {A.DIM}+{len(fps)} excluded as likely false positive.{A.RESET}")
        _p("")
    else:
        _section("SECURITY FINDINGS")
        _p(f"  {A.DIM}No security findings detected.{A.RESET}")
        _p("")

    # ── INFORMATION ───────────────────────────────────────────────────────
    if info_findings:
        _section("INFORMATION")
        _p(f"  {A.DIM}{len(info_findings)} informational finding{'s' if len(info_findings) != 1 else ''}{A.RESET}")
        _p("")
        for f in info_findings:
            _print_finding_full(f, show_full_secret=show_full_secret)


def _print_finding(f, verbose: bool = False) -> None:
    """Backward-compat wrapper."""
    _print_finding_full(f, show_full_secret=True)


# ---------------------------------------------------------------------------
# Discovery section - consolidated JS + secrets + libraries
# ---------------------------------------------------------------------------

def _print_discovery(result, extras: dict) -> None:
    """
    DISCOVERY - consolidated summary of what was found.

    DISCOVERY

      JavaScript       5 analyzed
      Inline           5
      External         0
      Total size       12 KB

      Secrets          3 detected
      High confidence  2
      Validated        0
      Public IDs       1

      Libraries        0 known vulnerable
    """
    _section("DISCOVERY")

    js_files = result.js_files or []
    inline_count   = sum(1 for j in js_files if j.url.startswith("inline:") or j.url.startswith("html:"))
    recovered      = sum(1 for j in js_files if j.url.startswith("sourcemap://"))
    external       = len(js_files) - inline_count - recovered
    total_size     = sum(j.size_bytes for j in js_files if j.size_bytes)
    size_kb        = f"{total_size / 1024:.0f} KB" if total_size else "0 KB"

    _p(f"  {_label('JavaScript')}{len(js_files)} analyzed")
    _p(f"  {_label('Inline')}{inline_count}")
    _p(f"  {_label('External')}{external}")
    if recovered:
        _p(f"  {_label('Recovered')}{recovered}")
    _p(f"  {_label('Total size')}{size_kb}")
    _p("")

    # Secrets summary
    findings = result.findings or []

    def _is_public_id(f):
        return (getattr(f, "classification", "") == "PUBLIC_IDENTIFIER"
                or f.rule_id in ("NETLIFY_SITE_ID",))

    real_findings = [f for f in findings if f.status != "likely_false_positive"]
    secrets       = [f for f in real_findings if not _is_public_id(f)]
    pub_ids       = [f for f in real_findings if _is_public_id(f)]
    high_conf     = sum(1 for f in secrets if f.confidence is not None and f.confidence >= 0.85)
    validated     = sum(1 for f in secrets if f.status == "validated")

    sec_c = A.B_BRIGHT_RED if secrets else A.DIM
    _p(f"  {_label('Secrets')}{sec_c}{len(secrets)} detected{A.RESET}")
    if secrets:
        hc_c = A.B_BRIGHT_RED if high_conf else A.DIM
        _p(f"  {_label('High confidence', 16)}{hc_c}{high_conf}{A.RESET}")
        val_c = A.B_BRIGHT_RED if validated else A.DIM
        _p(f"  {_label('Validated')}{val_c}{validated}{A.RESET}")
    if pub_ids:
        _p(f"  {_label('Public IDs')}{A.DIM}{len(pub_ids)}{A.RESET}")
    _p("")

    # Libraries
    lib_findings = extras.get("lib_findings", [])
    if lib_findings:
        lib_c = A.B_BRIGHT_RED
        _p(f"  {_label('Libraries')}{lib_c}{len(lib_findings)} known vulnerable{A.RESET}")
    else:
        _p(f"  {_label('Libraries')}{A.DIM}0 known vulnerable{A.RESET}")
    _p("")


# ---------------------------------------------------------------------------
# JS inventory (verbose) - kept for verbose mode
# ---------------------------------------------------------------------------

def print_js_inventory(js_files, verbose: bool = False, per_file_stats=None) -> None:
    """In normal mode: handled by _print_discovery. Verbose mode: full table."""
    if not js_files or not verbose:
        return

    stats_map: dict = {}
    if per_file_stats:
        for s in per_file_stats:
            stats_map[s["url"]] = s

    w = _w()
    path_w = max(30, w - 52)

    _section("JAVASCRIPT ASSETS (verbose)", str(len(js_files)))

    js_files_only = [j for j in js_files if not j.url.startswith("html:")]
    html_entries  = [s for s in (per_file_stats or []) if s.get("technology") == "html-attrs"]

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

        st    = stats_map.get(js.url)
        n_sec = st["secrets"]   if st else 0
        n_ep  = st["endpoints"] if st else 0

        heat  = min(4, n_sec * 2 + (1 if n_ep > 10 else 0))
        hot   = A.B_BRIGHT_RED + "█" * heat + A.RESET
        cold  = A.DIM + "░" * (4 - heat) + A.RESET

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
# Secret analysis pill row (kept for backward compat, not used in new flow)
# ---------------------------------------------------------------------------

def print_secret_analysis(findings) -> None:
    # Now handled inside _print_discovery - keeping this for backward compat
    pass


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
# Attack surface analysis (parameter-level, existing feature)
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
# Coverage (progress bars, NOT RUN vs 0 vs NOT FOUND semantic precision)
# ---------------------------------------------------------------------------

def print_coverage(coverage, args_flags: dict = None) -> None:
    if not coverage:
        return

    args_flags = args_flags or {}
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
        c = color or (A.B_CYAN if pct >= 1.0 else A.B_YELLOW)
        return (c + "█" * filled + rc + A.DIM + "░" * empty + rc)

    # Progress bars
    _p(f"  {A.DIM}{'Pages':<14}{rc}{_bar(p.visited, p.discovered)}  {A.BRIGHT_WHITE}{p.visited}/{p.discovered}{rc}")
    _p(f"  {A.DIM}{'JavaScript':<14}{rc}{_bar(j.analyzed, j.discovered)}  {A.BRIGHT_WHITE}{j.analyzed}/{j.discovered}{rc}")
    if r.discovered > 0:
        _p(f"  {A.DIM}{'Routes':<14}{rc}{_bar(r.visited, r.discovered)}  {A.BRIGHT_WHITE}{r.visited}/{r.discovered}{rc}")
    _p("")

    # Runtime - NOT RUN vs COMPLETE vs count
    has_rt    = any([rt.api_requests, rt.websockets, rt.workers, rt.iframes])
    headless_was_run = args_flags.get("headless", False)

    if has_rt:
        parts = []
        if rt.api_requests: parts.append(f"api: {rt.api_requests}")
        if rt.websockets:   parts.append(f"ws: {rt.websockets}")
        if rt.workers:      parts.append(f"workers: {rt.workers}")
        if rt.iframes:      parts.append(f"iframes: {rt.iframes}")
        _p(f"  {A.DIM}{'Runtime':<14}{rc}{A.BRIGHT_WHITE}COMPLETE{rc}  {A.DIM}{', '.join(parts)}{rc}")
    elif headless_was_run:
        _p(f"  {A.DIM}{'Runtime':<14}{rc}{A.BRIGHT_WHITE}RUN{rc}  {A.DIM}no dynamic endpoints captured{rc}")
    else:
        _p(f"  {A.DIM}{'Runtime':<14}{rc}{A.DIM}NOT RUN{rc}")

    # Source Maps - semantic precision:
    # NOT RUN  = --source-maps flag was NOT used
    # NOT FOUND = --source-maps was used but none discovered
    # N recovered = maps found and recovered
    sm_was_run = args_flags.get("source_maps", False)
    if sm.discovered > 0:
        sm_color = A.BRIGHT_WHITE if sm.recovered > 0 else A.B_YELLOW
        _p(f"  {A.DIM}{'Source Maps':<14}{rc}{sm_color}{sm.recovered} recovered{rc}  {A.DIM}of {sm.discovered} found{rc}")
    elif sm_was_run:
        # Ran but found nothing
        _p(f"  {A.DIM}{'Source Maps':<14}{rc}{A.DIM}NOT FOUND{rc}")
    else:
        # Never attempted
        _p(f"  {A.DIM}{'Source Maps':<14}{rc}{A.DIM}NOT RUN{rc}")

    # Authentication
    auth_missing = any("auth" in bs.description.lower() or "session" in bs.description.lower()
                       for bs in (coverage.blind_spots or []))
    has_cookie = args_flags.get("has_cookie", False)
    if has_cookie and not auth_missing:
        _p(f"  {A.DIM}{'Auth':<14}{rc}{A.BRIGHT_WHITE}PROVIDED{rc}")
    else:
        _p(f"  {A.DIM}{'Auth':<14}{rc}{A.B_YELLOW}NOT PROVIDED{rc}")

    # Failures / warnings
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
    Analyze what was NOT run and recommend the next useful command.
    Only recommends flags that were NOT already used.
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
    if not args_flags.get("has_cookie") and (auth_missing or not args_flags.get("headless")):
        missing.append("authenticated crawling")
        flags.append("--cookie 'session=<YOUR_SESSION>'")

    if not args_flags.get("validate"):
        flags.append("--validate")

    if not missing and not flags:
        return

    _section("NEXT ACTION")

    if missing:
        # Human-readable sentence
        if len(missing) == 1:
            _p(f"  {A.DIM}{missing[0].capitalize()} was not performed.{A.RESET}")
        elif len(missing) == 2:
            _p(f"  {A.DIM}{missing[0].capitalize()} and {missing[1]} were not performed.{A.RESET}")
        else:
            last    = missing[-1]
            others  = ", ".join(missing[:-1])
            _p(f"  {A.DIM}{others.capitalize()}, and {last} were not performed.{A.RESET}")
        _p("")

    _p(f"  {A.DIM}Recommended:{A.RESET}")
    _p("")
    _p(f"  {A.BRIGHT_WHITE}bundlespy scan {target} \\{A.RESET}")
    for i, flag in enumerate(flags):
        is_last = (i == len(flags) - 1)
        suffix  = "" if is_last else " \\"
        _p(f"  {A.BRIGHT_WHITE}  {flag}{suffix}{A.RESET}")
    _p("")


# ---------------------------------------------------------------------------
# Summary / RESULT section
# ---------------------------------------------------------------------------

def print_summary(result, extras=None, report_paths=None) -> None:
    extras       = extras or {}
    report_paths = report_paths or {}

    findings  = result.findings
    real      = [f for f in findings if f.status != "likely_false_positive"]
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

    # RESULT header right-aligned duration
    dur_str      = duration or ""
    result_label = A.BOLD + A.BRIGHT_WHITE + "RESULT" + rc
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

    # Key stats
    js_count = len([j for j in result.js_files if not j.url.startswith("sourcemap://")])
    _p(f"  {A.DIM}{result.pages_crawled} pages - {js_count} JS assets - {len(result.endpoints)} endpoints{rc}")
    _p("")

    # Coverage status
    coverage    = extras.get("coverage")
    args_flags  = extras.get("_args_flags", {})
    if coverage:
        blind_spots    = getattr(coverage, "blind_spots", []) or []
        has_high_blind = any(bs.severity == "HIGH" for bs in blind_spots)
        cov_label      = "PARTIAL" if blind_spots else "COMPLETE"
        cov_color      = A.B_YELLOW if has_high_blind else (A.B_GREEN if not blind_spots else A.ORANGE)
        _p(f"  {A.DIM}Coverage:{rc}  {cov_color}{cov_label}{rc}")

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
        _p(f"  {A.ORANGE}Review required: {counts['HIGH']} High severity finding{'s' if counts['HIGH'] != 1 else ''}.{rc}")
    elif counts.get("MEDIUM"):
        _p(f"  {A.B_YELLOW}Medium severity findings present.{rc}")
    else:
        _p(f"  {A.DIM}Scan complete. No critical findings.{rc}")

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
    Orchestrate the full scan report.

    Information hierarchy (per spec):
      TARGET (printed by cli.py via print_header)
      -> SCAN STATUS + risk summary
      -> ATTACK SURFACE (tree view)
      -> SECURITY FINDINGS + INFORMATION
      -> DISCOVERY (JS + secrets + libraries consolidated)
      -> COVERAGE (progress bars, NOT RUN precision)
      -> NEXT ACTION (dynamic recommendation)
      -> RESULT
    """
    extras     = extras or {}
    args_flags = extras.get("_args_flags", {})

    # Auth result (shown at very top if auth was attempted)
    if extras.get("auth_result"):
        print_auth_result(extras["auth_result"])

    # SCAN STATUS with inline risk summary
    _print_scan_status(result, args_flags)

    # ATTACK SURFACE tree view (before findings - gives map of app first)
    _print_attack_surface_tree(result, extras)

    # SECURITY FINDINGS (HIGH/MEDIUM/LOW/CRITICAL) + INFORMATION (INFO)
    print_findings(result.findings, verbose=verbose, show_full_secret=False)

    # DISCOVERY - consolidated JS + secrets + libraries
    _print_discovery(result, extras)

    # Verbose: full JS asset table
    if verbose:
        print_js_inventory(result.js_files, verbose=True,
                           per_file_stats=extras.get("per_file_stats"))

    # Feature detail sections (headless, passive, source maps, chunks)
    if extras.get("passive_stats"):
        p = extras["passive_stats"]
        print_passive(p.get("source", ""), p.get("urls", 0), p.get("js", 0),
                      p.get("unique", 0), p.get("new", 0))

    if extras.get("headless_stats") and verbose:
        h = extras["headless_stats"]
        print_headless(h.get("pages", 0), h.get("js", 0), h.get("xhr", 0),
                       h.get("fetch", 0), h.get("ws", 0), h.get("routes", 0),
                       h.get("endpoints", 0))

    intel = extras.get("intel")
    if intel:
        _print_intelligence(intel)

    # Vulnerable libraries detail (verbose)
    if verbose and extras.get("lib_findings"):
        _print_libraries(extras["lib_findings"])

    # Endpoints
    print_endpoints(result.endpoints, validation_results=validation_results, verbose=verbose)

    # Attack surface analysis (parameter-level)
    surface = extras.get("attack_surface")
    if surface and (surface.get("total_items", 0) > 0 or surface.get("state_change")):
        print_attack_surface(surface)

    # COVERAGE
    coverage = extras.get("coverage")
    if coverage:
        print_coverage(coverage, args_flags=args_flags)

    if validation_results:
        print_validation_results(validation_results)

    if graphql_schemas:
        print_graphql(graphql_schemas)

    print_infrastructure(result.infrastructure)

    if subdomains:
        print_subdomains(subdomains)

    # Source map / chunk detail (verbose or if significant)
    if extras.get("source_map_details") and verbose:
        d = extras["source_map_details"]
        print_source_maps(d.get("discovered", 0), d.get("valid", 0),
                          d.get("recovered", 0), d.get("sources", 0), d.get("items", []))

    if extras.get("chunk_stats") and verbose:
        c = extras["chunk_stats"]
        print_webpack(c.get("runtime", False), c.get("discovered", 0),
                      c.get("downloaded", 0), c.get("endpoints", 0), c.get("findings", 0))

    # NEXT ACTION
    _print_next_action(result.target_url, extras)

    # RESULT
    print_summary(result, extras=extras, report_paths=report_paths)
