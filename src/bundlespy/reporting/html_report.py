"""
BundleSpy HTML Report - complete professional intelligence report.
Single self-contained file, no external dependencies except D3 (cdnjs).
Covers every data source BundleSpy produces.
"""

import html
import json
import re as _re
from datetime import datetime
from typing import List, Optional
from ..storage.models import ScanResult, Finding, Endpoint, InfrastructureItem


def _e(s) -> str:
    return html.escape(str(s or ""))

def _j(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), default=str)

def _duration(result: ScanResult) -> str:
    if result.finished_at and result.started_at:
        s = (result.finished_at - result.started_at).total_seconds()
        if s < 60:   return f"{s:.0f}s"
        if s < 3600: return f"{s//60:.0f}m {s%60:.0f}s"
        return f"{s//3600:.0f}h {(s%3600)//60:.0f}m"
    return "N/A"

SEV_COLOR  = {"CRITICAL":"#f87171","HIGH":"#fb923c","MEDIUM":"#fbbf24","LOW":"#60a5fa","INFO":"#94a3b8"}
CAT_COLOR  = {"AUTH":"#a78bfa","ADMIN":"#f87171","API":"#34d399","GRAPHQL":"#c084fc",
              "SERVERLESS":"#fbbf24","WEBSOCKET":"#22d3ee","UPLOAD":"#fb923c",
              "DOWNLOAD":"#60a5fa","ROUTE":"#94a3b8","UNKNOWN":"#475569"}
NODE_COLOR = {"PAGE":"#60a5fa","JS":"#34d399","ENDPOINT":"#a78bfa","SECRET":"#f87171",
              "WORKER":"#fbbf24","PARAMETER":"#94a3b8","HOST":"#fb923c","CHUNK":"#22d3ee",
              "SOURCEMAP":"#86efac","CONFIG":"#c084fc"}


# ── Section renderers ─────────────────────────────────────────────────────────

def _findings_html(findings, extras):
    severity_order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    real = sorted(
        [f for f in findings if f.status != "likely_false_positive"],
        key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99,
    )
    if not real:
        return '<div class="empty-state"><span class="empty-icon">✓</span><p>No secrets detected above confidence threshold</p></div>'

    rows = []
    for f in real:
        sc  = SEV_COLOR.get(f.severity, "#94a3b8")
        pub = getattr(f, "classification", "") == "PUBLIC_IDENTIFIER"
        occ = ""
        if f.occurrences and len(f.occurrences) > 1:
            occ = f'<div class="finding-occ">Also observed in {len(f.occurrences)-1} additional location(s)</div>'
        ctx_block = ""
        if f.context:
            ctx_block = f'<div class="evidence-block"><div class="evidence-label">Context</div><code class="context-val">{_e(f.context[:300])}</code></div>'
        pub_note = '<div class="pub-id-note">Public identifier - not a secret credential</div>' if pub else ""
        rows.append(f"""
<div class="finding-card" data-severity="{_e(f.severity)}">
  <div class="finding-top">
    <div class="finding-left">
      <span class="sev-pill" style="background:{sc}22;color:{sc};border:1px solid {sc}44">{_e(f.severity)}</span>
      <span class="finding-name">{_e(f.title)}</span>
      <span class="rule-id">{_e(f.rule_id)}</span>
    </div>
    <div class="finding-right">
      <span class="conf-bar" title="{f.confidence:.0%} confidence">
        <span class="conf-fill" style="width:{f.confidence*100:.0f}%;background:{sc}"></span>
      </span>
      <span class="conf-label">{f.confidence:.0%}</span>
      <span class="status-pill status-{_e(f.status)}">{_e(f.status.replace("_"," ").title())}</span>
    </div>
  </div>
  <div class="finding-body">
    <div class="finding-grid">
      <div class="fg-item"><div class="fg-key">Location</div><code class="fg-val">{_e(f.file_url)}:{f.line_number}</code></div>
      <div class="fg-item"><div class="fg-key">Source Page</div><code class="fg-val">{_e(f.source_page)}</code></div>
      <div class="fg-item"><div class="fg-key">Category</div><span class="fg-val">{_e(f.category)}</span></div>
      <div class="fg-item"><div class="fg-key">Type</div><span class="fg-val">{_e(getattr(f,"classification","") or f.category)}</span></div>
    </div>
    <div class="evidence-block">
      <div class="evidence-label">Evidence (redacted)</div>
      <code class="evidence-val">{_e(f.redacted_value)}</code>
    </div>
    {ctx_block}
    {pub_note}
    <div class="finding-desc">{_e(f.description)}</div>
    <div class="remediation-block"><span class="rem-label">Remediation</span> {_e(f.remediation)}</div>
    {f'<div class="fp-note">{_e(f.false_positive_notes)}</div>' if f.false_positive_notes else ""}
    {occ}
  </div>
</div>""")
    return "\n".join(rows)


ACCESS_STATE_COLOR = {
    "PUBLIC":        "#3fb950",   # green
    "AUTHENTICATED": "#fbbf24",   # yellow
    "PRIVILEGED":    "#fb923c",   # orange
    "UNKNOWN":       "#6e7681",   # grey
}
ROUTE_STATE_COLOR = {
    "VISITED":      "#3fb950",
    "OBSERVED":     "#60a5fa",
    "AUTH_REQUIRED":"#fbbf24",
    "FORBIDDEN":    "#f87171",
    "REDIRECTED":   "#a78bfa",
    "UNREACHABLE":  "#f87171",
    "DISCOVERED":   "#6e7681",
}


def _access_badge(access_state: str) -> str:
    color = ACCESS_STATE_COLOR.get(access_state, "#6e7681")
    return f'<span class="state-badge" style="background:{color}22;color:{color};border:1px solid {color}44">{_e(access_state)}</span>'


def _route_badge(route_state: str) -> str:
    color = ROUTE_STATE_COLOR.get(route_state, "#6e7681")
    return f'<span class="state-badge" style="background:{color}22;color:{color};border:1px solid {color}44">{_e(route_state.replace("_"," "))}</span>'


def _status_color(status: int) -> str:
    if 200 <= status <= 299: return "#3fb950"
    if status in (301, 302, 307, 308): return "#a78bfa"
    if status == 401: return "#fbbf24"
    if status == 403: return "#f87171"
    if status >= 500: return "#ef4444"
    if status >= 400: return "#f87171"
    return "#6e7681"


def _endpoints_html(endpoints):
    if not endpoints:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No endpoints discovered</p></div>'
    cat_order = ["AUTH","ADMIN","GRAPHQL","API","SERVERLESS","WEBSOCKET","UPLOAD","DOWNLOAD","ROUTE","UNKNOWN"]
    by_cat = {}
    for ep in endpoints:
        by_cat.setdefault(ep.category, []).append(ep)

    # Check if any endpoint has state data
    has_state = any(
        getattr(ep, "access_state", "UNKNOWN") != "UNKNOWN" or
        getattr(ep, "route_state", "DISCOVERED") != "DISCOVERED" or
        getattr(ep, "http_status", 0) != 0
        for ep in endpoints
    )

    parts = []
    for cat in sorted(by_cat, key=lambda c: cat_order.index(c) if c in cat_order else 99):
        cc = CAT_COLOR.get(cat, "#475569")
        rows = ""
        for ep in by_cat[cat]:
            mc = ep.method.lower() if ep.method in ("GET","POST","PUT","DELETE","PATCH","WS","HEAD") else "unknown"
            params = ""
            if ep.path_params:
                names = [p.get("name","?") if isinstance(p,dict) else str(p) for p in ep.path_params]
                params += f'<span class="param-tag">path: {", ".join(_e(n) for n in names)}</span>'
            if ep.query_params:
                names = [p.get("name","?") if isinstance(p,dict) else str(p) for p in ep.query_params]
                params += f'<span class="param-tag query-param">query: {", ".join(_e(n) for n in names)}</span>'
            if ep.body_fields:
                names = [p.get("name","?") if isinstance(p,dict) else str(p) for p in ep.body_fields[:4]]
                params += f'<span class="param-tag body-param">body: {", ".join(_e(n) for n in names)}</span>'
            auth = f'<span class="auth-tag">{_e(ep.auth_context)}</span>' if ep.auth_context else ""
            st = getattr(ep, "source_type", "static")
            st_cls = {"static":"src-static","runtime":"src-runtime","correlated":"src-correlated","browser":"src-browser"}.get(st,"src-static")

            # Stage 6: state columns
            access_state = getattr(ep, "access_state", "UNKNOWN")
            route_state  = getattr(ep, "route_state",  "DISCOVERED")
            http_status  = getattr(ep, "http_status",  0)
            state_cols = ""
            if has_state:
                sc = _status_color(http_status)
                status_cell = f'<span style="color:{sc};font-weight:600;font-family:monospace">{http_status if http_status else "-"}</span>'
                state_cols = f'<td>{_access_badge(access_state)}</td><td>{_route_badge(route_state)}</td><td class="conf-cell">{status_cell}</td>'

            rows += f"""<tr class="ep-row">
  <td><span class="method-badge method-{mc}">{_e(ep.method)}</span></td>
  <td><code class="ep-url">{_e(ep.url)}</code>{params}{auth}</td>
  <td><span class="src-badge {st_cls}">{st}</span></td>
  <td class="conf-cell">{ep.confidence:.0%}</td>
  <td class="src-file"><code>{_e((ep.source_file or "").split("/")[-1])}</code></td>
  {state_cols}
</tr>"""

        state_headers = '<th>Access</th><th>Route</th><th>HTTP</th>' if has_state else ''
        parts.append(f"""<div class="ep-group">
  <div class="ep-group-header" style="border-left:3px solid {cc}">
    <span class="ep-cat" style="color:{cc}">{_e(cat)}</span>
    <span class="ep-count">{len(by_cat[cat])}</span>
  </div>
  <table class="ep-table">
    <thead><tr><th>Method</th><th>Path / URL</th><th>Source</th><th>Conf.</th><th>File</th>{state_headers}</tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>""")
    return "\n".join(parts)


def _js_html(result, extras):
    if not result.js_files:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No JavaScript assets discovered</p></div>'
    per_file = {s["url"]: s for s in extras.get("per_file_stats", [])} if extras else {}
    rows = []
    for js in result.js_files:
        st = getattr(js, "source_type", "static")
        st_color = {"static":"#34d399","browser":"#60a5fa","inline":"#a78bfa","sourcemap":"#86efac","chunk":"#22d3ee"}.get(st,"#94a3b8")
        tech = f'<span class="tech-tag">{_e(js.technology)}</span>' if js.technology else ""
        sm   = '<span class="sm-tag">map</span>' if js.has_source_map else ""
        label = js.url
        if js.url.startswith("inline:"):
            bare = js.url.replace("inline:","").split("#")[0]
            frag = js.url.split("#")[-1] if "#" in js.url else ""
            num  = _re.search(r"script-(\d+)", frag)
            n    = num.group(1) if num else "?"
            try:
                from urllib.parse import urlparse as _up
                p = _up(bare)
                label = f"script {n} @ {p.netloc}{p.path or '/'}"
            except Exception:
                label = js.url
        size = f"{js.size_bytes/1024:.1f} KB" if (js.size_bytes or 0) >= 1024 else (f"{js.size_bytes} B" if js.size_bytes else "N/A")
        stats = per_file.get(js.url, {})
        sec_n  = stats.get("secrets", 0)
        ep_n   = stats.get("endpoints", 0)
        inf_n  = stats.get("infra", 0)
        sec_c  = "style='color:#f87171;font-weight:600'" if sec_n else ""
        rows.append(f"""<tr>
  <td><span class="src-badge" style="background:{st_color}22;color:{st_color};border:1px solid {st_color}44">{st}</span></td>
  <td><code class="js-url">{_e(label)}</code>{tech}{sm}</td>
  <td class="size-cell">{size}</td>
  <td {sec_c}>{sec_n}</td>
  <td>{ep_n}</td>
  <td>{inf_n}</td>
  <td><code class="hash">{js.sha256[:12] if js.sha256 else "N/A"}</code></td>
</tr>""")

    # HTML attribute findings rows
    for s in extras.get("per_file_stats", []) if extras else []:
        if s.get("technology") == "html-attrs":
            url = s.get("url","")
            label = url.replace("html:","") if url.startswith("html:") else url
            sec_n = s.get("secrets", 0)
            rows.append(f"""<tr style="background:rgba(248,81,73,.04)">
  <td><span class="src-badge" style="background:#f8717122;color:#f87171;border:1px solid #f8717144">html</span></td>
  <td><code class="js-url">{_e(label)}</code> <span class="tech-tag" style="background:rgba(248,81,73,.1);color:#f87171">HTML attributes</span></td>
  <td class="size-cell">N/A</td>
  <td style="color:#f87171;font-weight:600">{sec_n}</td>
  <td>N/A</td><td>N/A</td><td>N/A</td>
</tr>""")

    return f"""<table class="data-table">
<thead><tr><th>Type</th><th>Asset</th><th>Size</th><th>Secrets</th><th>Endpoints</th><th>Infra</th><th>SHA-256</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>"""


def _vulnlibs_html(lib_findings):
    if not lib_findings:
        return '<div class="empty-state"><span class="empty-icon">✓</span><p>No known vulnerable libraries detected</p></div>'

    by_lib = {}
    for lf in lib_findings:
        key = f"{lf.library} {lf.version}"
        by_lib.setdefault(key, {"lib": lf.library, "version": lf.version,
                                 "file": getattr(lf,"source_file",""), "cves": []})
        by_lib[key]["cves"].append(lf)

    parts = []
    for key, data in by_lib.items():
        cve_rows = ""
        for cve in data["cves"]:
            sc = SEV_COLOR.get(cve.severity, "#94a3b8")
            cvss_color = "#f87171" if cve.cvss >= 7 else "#fbbf24" if cve.cvss >= 4 else "#94a3b8"
            fix = getattr(cve, "fix", "") or getattr(cve, "remediation", "")
            cve_rows += f"""<tr>
  <td><span class="sev-pill" style="background:{sc}22;color:{sc};border:1px solid {sc}44">{_e(cve.severity)}</span></td>
  <td><code class="cve-id">{_e(cve.cve_id)}</code></td>
  <td><span style="color:{cvss_color};font-weight:600">{cve.cvss}</span></td>
  <td class="cve-desc">{_e(cve.description)}</td>
  <td class="cve-fix">{_e(fix)}</td>
</tr>"""
        filename = data["file"].split("/")[-1] if data["file"] else ""
        parts.append(f"""<div class="vuln-lib-card">
  <div class="vuln-lib-header">
    <div class="vuln-lib-name">{_e(data["lib"])}</div>
    <div class="vuln-lib-meta">
      <span class="version-badge">{_e(data["version"])}</span>
      {f'<code class="lib-file">{_e(filename)}</code>' if filename else ""}
      <span class="cve-count">{len(data["cves"])} CVE{"s" if len(data["cves"])!=1 else ""}</span>
    </div>
  </div>
  <table class="vuln-table">
    <thead><tr><th>Severity</th><th>CVE</th><th>CVSS</th><th>Description</th><th>Fix</th></tr></thead>
    <tbody>{cve_rows}</tbody>
  </table>
</div>""")
    return "\n".join(parts)


def _infra_html(items):
    if not items:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No infrastructure indicators found</p></div>'
    rows = []
    for item in items[:200]:
        color = {"PRIVATE_IP":"#f87171","CLOUD_METADATA":"#f87171","INTERNAL_HOSTNAME":"#fb923c"}.get(item.classification,"#fbbf24")
        rows.append(f"""<tr>
  <td><span class="cls-badge" style="color:{color};font-weight:600">{_e(item.classification)}</span></td>
  <td><code>{_e(item.value)}</code></td>
  <td><code>{_e(item.source_file.split("/")[-1] if item.source_file else "")}</code></td>
  <td>{item.line_number}</td>
  <td class="conf-cell">{item.confidence:.0%}</td>
  <td><span class="action-{item.action}">{_e(item.action.replace("_"," "))}</span></td>
</tr>""")
    return f"""<table class="data-table">
<thead><tr><th>Classification</th><th>Value</th><th>Source</th><th>Line</th><th>Confidence</th><th>Action</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>"""


def _coverage_html(coverage):
    if not coverage:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>Coverage data not available</p></div>'

    def _bar(visited, total, color="#34d399"):
        pct = min(100, int(visited/total*100)) if total else 0
        return f"""<div class="cov-row">
  <div class="cov-label">{visited} / {total}</div>
  <div class="cov-bar-wrap"><div class="cov-bar-fill" style="width:{pct}%;background:{color}"></div></div>
  <div class="cov-pct">{pct}%</div>
</div>"""

    pages  = getattr(coverage, "pages",  None)
    js     = getattr(coverage, "js",     None)
    routes = getattr(coverage, "routes", None)
    spots  = getattr(coverage, "blind_spots", [])

    if not pages and not js and not routes and not spots:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>Coverage data not available</p></div>'

    cov_html = '<div class="cov-grid">'
    if pages:
        cov_html += f"""<div class="cov-card">
  <div class="cov-card-title">Pages</div>
  {_bar(getattr(pages,"visited",0), getattr(pages,"discovered",0))}
  <div class="cov-detail">Discovered: {getattr(pages,"discovered",0)} · Visited: {getattr(pages,"visited",0)}</div>
</div>"""
    if js:
        cov_html += f"""<div class="cov-card">
  <div class="cov-card-title">JavaScript</div>
  {_bar(getattr(js,"analyzed",0), getattr(js,"discovered",0), "#60a5fa")}
  <div class="cov-detail">Discovered: {getattr(js,"discovered",0)} · Analyzed: {getattr(js,"analyzed",0)}</div>
</div>"""
    if routes:
        cov_html += f"""<div class="cov-card">
  <div class="cov-card-title">Routes</div>
  {_bar(getattr(routes,"visited",0), getattr(routes,"discovered",0), "#a78bfa")}
  <div class="cov-detail">Discovered: {getattr(routes,"discovered",0)} · Visited: {getattr(routes,"visited",0)}</div>
</div>"""
    cov_html += "</div>"

    if spots:
        spots_html = ""
        for spot in spots:
            sev = getattr(spot,"severity","LOW")
            sc  = SEV_COLOR.get(sev, "#94a3b8")
            spots_html += f"""<div class="blind-spot" style="border-left:3px solid {sc}44">
  <div class="blind-spot-header">
    <span class="sev-pill" style="background:{sc}22;color:{sc};border:1px solid {sc}44">{_e(sev)}</span>
    <span class="blind-spot-title">{_e(getattr(spot,"title","Blind spot"))}</span>
  </div>
  <div class="blind-spot-desc">{_e(getattr(spot,"description",""))}</div>
  {f'<div class="blind-spot-rec">→ {_e(getattr(spot,"recommendation",""))}</div>' if getattr(spot,"recommendation","") else ""}
</div>"""
        cov_html += f'<div class="blind-spots-section"><div class="subsection-title">Blind Spots</div>{spots_html}</div>'

    return cov_html


def _headless_html(headless_stats):
    if not headless_stats:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>Headless browser was not used in this scan</p></div>'
    timings = headless_stats.get("timings", {})
    api_calls = headless_stats.get("xhr", 0) + headless_stats.get("fetch", 0)
    rows = [
        ("Pages visited",    headless_stats.get("pages", 0)),
        ("JS captured",      headless_stats.get("js", 0)),
        ("API calls (XHR/Fetch)", api_calls),
        ("WebSocket connections", headless_stats.get("ws", 0)),
        ("Routes discovered",headless_stats.get("routes", 0)),
        ("Web Workers",      headless_stats.get("workers", 0)),
    ]
    meta = "".join(f'<tr><td class="meta-key">{k}</td><td class="meta-val">{v}</td></tr>' for k,v in rows)
    timing_rows = ""
    for phase, secs in timings.items():
        if phase != "total":
            timing_rows += f'<tr><td class="meta-key">{_e(phase.replace("_"," ").title())}</td><td class="meta-val">{secs:.1f}s</td></tr>'
    if timings.get("total"):
        timing_rows += f'<tr><td class="meta-key" style="font-weight:700">Total</td><td class="meta-val" style="font-weight:700">{timings["total"]:.1f}s</td></tr>'
    return f"""<div class="two-col">
  <div>
    <div class="subsection-title">Discovery Stats</div>
    <table class="meta-table">{meta}</table>
  </div>
  <div>
    <div class="subsection-title">Phase Timings</div>
    <table class="meta-table">{timing_rows}</table>
  </div>
</div>"""


def _login_html(login_result):
    """Render the auto-login result card for the HTML report."""
    if not login_result:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>Auto-login was not used</p></div>'

    success    = login_result.get("success", False)
    method     = login_result.get("method", "unknown").replace("_", " ").title()
    login_url  = login_result.get("login_url", "")
    final_url  = login_result.get("final_url", "")
    u_field    = login_result.get("username_field", "")
    p_field    = login_result.get("password_field", "")
    cookies    = login_result.get("cookies", [])
    token_keys = login_result.get("token_keys", [])
    ls         = login_result.get("local_storage", {})
    ss         = login_result.get("session_storage", {})
    error_msg  = login_result.get("error_message", "") or login_result.get("error", "")
    steps      = login_result.get("steps", [])

    sc = "#34d399" if success else "#f87171"
    st = "SUCCESS" if success else "FAILED"

    rows = [("Login URL", _e(login_url)), ("Method", _e(method))]
    if u_field:
        rows.append(("Username field", f"<code>{_e(u_field)}</code>"))
    if p_field:
        rows.append(("Password field", f"<code>{_e(p_field)}</code>"))
    if success:
        rows.append(("Final URL", _e(final_url)))
        rows.append(("Cookies captured", str(len(cookies))))
        if token_keys:
            rows.append(("Tokens in storage", f"<code>{_e(', '.join(token_keys[:8]))}</code>"))
        if ls:
            rows.append(("localStorage keys", str(len(ls))))
        if ss:
            rows.append(("sessionStorage keys", str(len(ss))))
    else:
        if error_msg:
            rows.append(("Failure reason", f'<span style="color:#f87171">{_e(error_msg[:200])}</span>'))

    meta = "".join(f'<tr><td class="meta-key">{k}</td><td class="meta-val">{v}</td></tr>' for k, v in rows)

    steps_html = ""
    if steps:
        step_rows = "".join(
            f'<tr><td style="color:#8b949e;padding:3px 0;font-size:12px">· {_e(s)}</td></tr>'
            for s in steps
        )
        steps_html = f"""<div style="margin-top:16px">
  <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#6e7681;margin-bottom:6px">Login Steps</div>
  <table style="width:100%"><tbody>{step_rows}</tbody></table>
</div>"""

    return f"""<div style="border-left:4px solid {sc};padding-left:14px;margin-bottom:16px">
  <div style="color:{sc};font-weight:700;font-size:15px;margin-bottom:6px">● {st}</div>
</div>
<table class="meta-table">{meta}</table>
{steps_html}"""


def _auth_html(auth_result):
    if not auth_result:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No credentials supplied - unauthenticated scan</p></div>'
    verified = auth_result.get("authenticated", False)
    vc = "#34d399" if verified else "#f87171"
    vt = "VERIFIED" if verified else "NOT VERIFIED"
    redirected = auth_result.get("final_url","") != auth_result.get("initial_url","")
    chain = auth_result.get("redirect_chain", [])
    cookies_present = auth_result.get("cookies_present", [])
    reason = auth_result.get("reason", "")
    status = auth_result.get("status", 0)
    sc = "#34d399" if status == 200 else "#fbbf24" if status in (301,302) else "#f87171"
    rows = [
        ("Credentials supplied", "YES" if auth_result.get("credentials_supplied") else "NO"),
        ("Cookies injected",     auth_result.get("cookies_injected", 0)),
        ("Initial URL",          auth_result.get("initial_url", "N/A")),
        ("HTTP status",          f'<span style="color:{sc};font-weight:600">{status}</span>'),
        ("Final URL",            auth_result.get("final_url", "N/A")),
        ("Redirected",           "YES" if redirected else "NO"),
    ]
    if cookies_present:
        rows.append(("Browser cookies", ", ".join(cookies_present[:8])))
    if chain:
        rows.append(("Redirect chain",  " → ".join(chain[:5])))
    meta = "".join(f'<tr><td class="meta-key">{k}</td><td class="meta-val">{v}</td></tr>' for k,v in rows)
    warn = f'<div class="auth-warn">{_e(reason)}</div>' if not verified and reason else ""
    return f"""<div class="auth-status" style="border-left:4px solid {vc};padding-left:14px;margin-bottom:16px">
  <div class="auth-verified" style="color:{vc};font-weight:700;font-size:15px;margin-bottom:6px">● {vt}</div>
</div>
{warn}
<table class="meta-table">{meta}</table>"""


def _subdomains_html(subdomains):
    if not subdomains:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No subdomains harvested</p></div>'
    rows = "".join(f'<tr><td><code>{_e(s)}</code></td></tr>' for s in sorted(subdomains))
    return f'<table class="data-table"><thead><tr><th>Subdomain</th></tr></thead><tbody>{rows}</tbody></table>'


def _graphql_html(graphql_schemas):
    if not graphql_schemas:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No GraphQL schemas introspected</p></div>'
    parts = []
    for schema in graphql_schemas:
        if getattr(schema, "error", None):
            parts.append(f'<div class="gql-error">{_e(schema.endpoint)}: {_e(schema.error)}</div>')
            continue
        queries  = getattr(schema, "queries",  [])
        mutations= getattr(schema, "mutations", [])
        subs     = getattr(schema, "subscriptions", [])
        q_rows = "".join(f'<tr><td><code>{_e(q)}</code></td><td class="gql-type">query</td></tr>' for q in queries[:50])
        m_rows = "".join(f'<tr><td><code>{_e(m)}</code></td><td class="gql-type mutation">mutation</td></tr>' for m in mutations[:50])
        s_rows = "".join(f'<tr><td><code>{_e(s)}</code></td><td class="gql-type subscription">subscription</td></tr>' for s in subs[:20])
        parts.append(f"""<div class="gql-schema">
  <div class="gql-header"><code>{_e(schema.endpoint)}</code>
    <span class="gql-counts">{len(queries)} queries · {len(mutations)} mutations · {len(subs)} subscriptions</span>
  </div>
  <table class="data-table"><thead><tr><th>Operation</th><th>Type</th></tr></thead>
  <tbody>{q_rows}{m_rows}{s_rows}</tbody></table>
</div>""")
    return "\n".join(parts)


def _validation_html(validation_results):
    if not validation_results:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>Endpoint validation was not run</p></div>'
    interesting = [r for r in validation_results if getattr(r,"interesting",False)]
    rows = ""
    for r in validation_results[:200]:
        sc = "#34d399" if getattr(r,"interesting",False) else "#475569"
        status = getattr(r,"status_code",0)
        stat_c = "#34d399" if status == 200 else "#fbbf24" if status in (301,302,307,308) else "#f87171" if status >= 400 else "#94a3b8"
        rows += f"""<tr>
  <td><code class="ep-url">{_e(getattr(r,"url",""))}</code></td>
  <td><span style="color:{stat_c};font-weight:600">{status}</span></td>
  <td>{_e(getattr(r,"content_type",""))}</td>
  <td>{getattr(r,"response_size",0):,}</td>
  <td><span style="color:{sc}">{"✓ Interesting" if getattr(r,"interesting",False) else "-"}</span></td>
</tr>"""
    return f"""<div class="val-summary">
  {len(validation_results)} endpoints probed · <span style="color:#34d399">{len(interesting)} interesting</span>
</div>
<table class="data-table">
<thead><tr><th>URL</th><th>Status</th><th>Content-Type</th><th>Size</th><th>Note</th></tr></thead>
<tbody>{rows}</tbody>
</table>"""


def _sourcemap_html(sm_details):
    if not sm_details or not sm_details.get("discovered"):
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No source maps found</p></div>'
    items = sm_details.get("items", [])
    rows = "".join(f"""<tr>
  <td><code>{_e(i.get("js",""))}</code></td>
  <td><code>{_e(i.get("map",""))}</code></td>
  <td>{i.get("sources",0)}</td>
</tr>""" for i in items)
    return f"""<div class="sm-summary">
  {sm_details.get("discovered",0)} map(s) found · {sm_details.get("sources",0)} source file(s) recovered
</div>
<table class="data-table">
<thead><tr><th>JS File</th><th>Map File</th><th>Sources</th></tr></thead>
<tbody>{rows}</tbody>
</table>"""


def _attack_mapper_html(attack_report) -> str:
    """Render the Attack Surface Mapper results section."""
    if not attack_report:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No attack surface mapping data available.</p></div>'

    results = attack_report.results or []
    if not results:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No attack surface candidates identified.</p></div>'

    # Confidence colour mapping
    CONF_COLOR = {"HIGH": "#f85149", "MEDIUM": "#f0883e", "LOW": "#8b949e"}
    CONF_BG    = {"HIGH": "#3d1515", "MEDIUM": "#3d2215", "LOW": "#1c2128"}

    # Group by category
    from collections import defaultdict
    by_cat = defaultdict(list)
    for r in results:
        by_cat[r.category].append(r)

    # Category display order
    CAT_ORDER = [
        "Access Control", "Injection", "CORS", "Prototype Pollution",
        "XSS", "SSRF", "Open Redirect", "CSRF", "Path Traversal", "Configuration",
    ]
    cats_sorted = sorted(by_cat.keys(), key=lambda c: CAT_ORDER.index(c) if c in CAT_ORDER else 99)

    # Summary tiles
    conf_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        conf_counts[r.confidence] = conf_counts.get(r.confidence, 0) + 1

    tiles = ""
    if conf_counts["HIGH"]:
        tiles += f'<div class="metric-card c-red"><div class="metric-num">{conf_counts["HIGH"]}</div><div class="metric-lbl">High Confidence</div></div>'
    if conf_counts["MEDIUM"]:
        tiles += f'<div class="metric-card c-orange"><div class="metric-num">{conf_counts["MEDIUM"]}</div><div class="metric-lbl">Medium Confidence</div></div>'
    if conf_counts["LOW"]:
        tiles += f'<div class="metric-card c-grey"><div class="metric-num">{conf_counts["LOW"]}</div><div class="metric-lbl">Low Confidence</div></div>'
    tiles += f'<div class="metric-card c-purple"><div class="metric-num">{len(cats_sorted)}</div><div class="metric-lbl">Categories</div></div>'

    html = f'<div class="overview-grid" style="margin-bottom:20px">{tiles}</div>'

    # One card per category
    for cat in cats_sorted:
        items = by_cat[cat]
        rows_html = ""
        for r in items:
            conf       = r.confidence
            c_color    = CONF_COLOR.get(conf, "#8b949e")
            c_bg       = CONF_BG.get(conf, "#1c2128")
            method     = _e(r.method or "")
            url        = _e(r.endpoint_url or "")
            stype      = _e(r.surface_type or "")
            params     = ", ".join(_e(p) for p in (r.parameters or []))
            evidence   = "<br>".join(_e(e) for e in (r.evidence or []))
            burp       = _e(r.burp_notes or "")
            auth       = _e(r.auth_context or "")
            meth_cls   = f"method-{method.lower()}" if method.lower() in ("get","post","put","delete","patch","head") else "method-unknown"

            rows_html += f"""
<div class="finding-card" style="margin-bottom:8px">
  <div class="finding-top">
    <div class="finding-left">
      <span class="method-badge {meth_cls}">{method}</span>
      <span class="finding-name" style="font-size:12px;word-break:break-all">{url}</span>
    </div>
    <div class="finding-right">
      <span class="sev-pill" style="background:{c_bg};color:{c_color}">{conf}</span>
      <span style="font-size:11px;color:var(--text3)">{stype}</span>
    </div>
  </div>
  <div class="finding-body" style="padding:10px 14px">
    {"".join(f'<span class="param-tag query-param" style="margin-right:4px;margin-bottom:4px;display:inline-block">{_e(p)}</span>' for p in (r.parameters or []))}
    {f'<div style="margin-top:8px"><div class="evidence-label">Evidence</div><div style="font-size:11px;color:var(--text2);margin-top:3px">{evidence}</div></div>' if evidence else ""}
    {f'<div style="margin-top:8px"><div class="evidence-label">Auth</div><div style="font-size:11px;color:var(--cyan)">{auth}</div></div>' if auth and auth not in ("", "none", "None") else ""}
    {f'<div style="margin-top:8px"><div class="evidence-label">Burp Notes</div><div style="font-family:SF Mono,Fira Code,Consolas,monospace;font-size:10px;color:var(--text2);white-space:pre-wrap;background:#0a0d13;border:1px solid var(--border);border-radius:4px;padding:8px;margin-top:3px;max-height:80px;overflow:hidden">{burp}</div></div>' if burp else ""}
  </div>
</div>"""

        html += f"""
<div class="card" style="margin-bottom:16px">
  <div class="card-header">
    {_e(cat)}
    <span style="font-size:11px;color:var(--text3);font-weight:400">{len(items)} candidate{"s" if len(items) != 1 else ""}</span>
  </div>
  <div class="card-body" style="padding:12px">{rows_html}</div>
</div>"""

    return html


def _state_intelligence_html(page_states, state_report=None):
    """Render the Application State Intelligence section."""
    if not page_states and state_report is None:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No page state data available - run without --passive to enable HTTP probing</p></div>'

    # Build report on-the-fly if not provided
    if state_report is None:
        try:
            from ..analysis.state_intelligence import build_state_intelligence_report
            class _FakeResult:
                pass
            r = _FakeResult()
            r.page_states = page_states
            r.endpoints = []
            state_report = build_state_intelligence_report(r)
        except Exception:
            pass

    # Access state breakdown
    access_items = []
    if state_report:
        for label, count, color in [
            ("Public",        getattr(state_report, "public",        0), "#3fb950"),
            ("Authenticated", getattr(state_report, "authenticated", 0), "#fbbf24"),
            ("Privileged",    getattr(state_report, "privileged",    0), "#fb923c"),
            ("Unknown",       getattr(state_report, "unknown",       0), "#6e7681"),
        ]:
            if count > 0:
                access_items.append(
                    f'<div class="si-stat"><div class="si-count" style="color:{color}">{count}</div>'
                    f'<div class="si-label">{label}</div></div>'
                )

    route_items = []
    if state_report:
        for label, count, color in [
            ("Visited",       getattr(state_report, "visited",       0), "#3fb950"),
            ("Observed",      getattr(state_report, "observed",      0), "#60a5fa"),
            ("Auth Required", getattr(state_report, "auth_required", 0), "#fbbf24"),
            ("Forbidden",     getattr(state_report, "forbidden",     0), "#f87171"),
            ("Redirected",    getattr(state_report, "redirected",    0), "#a78bfa"),
            ("Unreachable",   getattr(state_report, "unreachable",   0), "#f87171"),
            ("Discovered",    getattr(state_report, "discovered",    0), "#6e7681"),
        ]:
            if count > 0:
                route_items.append(
                    f'<div class="si-stat"><div class="si-count" style="color:{color}">{count}</div>'
                    f'<div class="si-label">{label}</div></div>'
                )

    total = len(page_states) if page_states else (getattr(state_report, "total_urls", 0) if state_report else 0)

    access_html = "".join(access_items) or '<span style="color:var(--text3);font-size:12px">No data</span>'
    route_html  = "".join(route_items)  or '<span style="color:var(--text3);font-size:12px">No data</span>'

    # Notable URL lists
    notable_html = ""
    if state_report:
        auth_gated  = getattr(state_report, "auth_gated_urls",  [])
        forbidden   = getattr(state_report, "forbidden_urls",   [])
        redirected  = getattr(state_report, "redirected_urls",  [])

        def _url_list(urls, color, label):
            if not urls:
                return ""
            items = "".join(f'<div class="si-url-item"><code>{_e(u)}</code></div>' for u in urls[:20])
            more  = f'<div class="si-url-more">and {len(urls)-20} more</div>' if len(urls) > 20 else ""
            return f'<div class="si-url-group"><div class="si-url-label" style="color:{color}">{label} ({len(urls)})</div>{items}{more}</div>'

        notable_html = (
            _url_list(auth_gated, "#fbbf24", "Auth-Gated URLs") +
            _url_list(forbidden,  "#f87171", "Forbidden URLs") +
            _url_list(redirected, "#a78bfa", "Redirected URLs")
        )

    # Per-URL state table (from page_states)
    table_rows = ""
    if page_states:
        for url, rec in list(page_states.items())[:100]:
            rs   = getattr(rec, "route_state",  "DISCOVERED")
            acs  = getattr(rec, "access_state", "UNKNOWN")
            http = getattr(rec, "http_status",  0)
            sc   = _status_color(http)
            table_rows += f"""<tr>
  <td><code style="font-size:10px;word-break:break-all">{_e(url)}</code></td>
  <td>{_access_badge(acs)}</td>
  <td>{_route_badge(rs)}</td>
  <td><span style="color:{sc};font-weight:600;font-family:monospace">{http if http else "-"}</span></td>
</tr>"""
        more_note = f'<div style="padding:8px 12px;font-size:11px;color:var(--text3)">Showing first 100 of {len(page_states)} URLs</div>' if len(page_states) > 100 else ""
        table_html = f"""<div class="subsection-title" style="margin-top:20px">URL State Map</div>
<table class="data-table">
<thead><tr><th>URL</th><th>Access</th><th>Route</th><th>HTTP</th></tr></thead>
<tbody>{table_rows}</tbody>
</table>{more_note}"""
    else:
        table_html = ""

    return f"""<div class="si-overview">
  <div style="font-size:12px;color:var(--text3);margin-bottom:14px">{total} URL{'' if total==1 else 's'} probed during scan</div>
  <div class="two-col" style="margin-bottom:18px">
    <div>
      <div class="subsection-title">Access State</div>
      <div class="si-stats">{access_html}</div>
    </div>
    <div>
      <div class="subsection-title">Route State</div>
      <div class="si-stats">{route_html}</div>
    </div>
  </div>
  {f'<div class="si-notable">{notable_html}</div>' if notable_html else ''}
</div>
{table_html}"""


def _graph_data(result):
    if not result.graph:
        return "null"
    return _j(result.graph.to_dict())


# ── Main generator ────────────────────────────────────────────────────────────

def generate(
    result: ScanResult,
    show_sensitive: bool = False,
    extras: dict = None,
    validation_results: list = None,
    graphql_schemas: list = None,
    subdomains: list = None,
    report_paths: dict = None,
    coverage_ledger=None,   # CoverageLedger | None  (Stage 5)
    state_report=None,      # StateIntelligenceReport | None  (Stage 6)
) -> str:
    extras = extras or {}
    validation_results = validation_results or []
    graphql_schemas    = graphql_schemas    or []
    subdomains         = subdomains         or []

    findings   = result.findings
    real       = [f for f in findings if f.status != "likely_false_positive"]
    fps        = [f for f in findings if f.status == "likely_false_positive"]
    critical   = [f for f in real if f.severity == "CRITICAL"]
    high       = [f for f in real if f.severity == "HIGH"]
    medium     = [f for f in real if f.severity == "MEDIUM"]
    low        = [f for f in real if f.severity == "LOW"]
    info_f     = [f for f in real if f.severity == "INFO"]

    lib_findings    = extras.get("lib_findings",      [])
    headless_stats  = extras.get("headless_stats",    {})
    auth_result     = extras.get("auth_result",       None)
    login_result    = extras.get("login_result",      None)
    coverage        = extras.get("coverage",          None)
    sm_details      = extras.get("source_map_details",{})
    passive_stats   = extras.get("passive_stats",     {})
    chunk_stats     = extras.get("chunk_stats",       {})
    attack_surface  = extras.get("attack_surface",    {})
    attack_report   = extras.get("attack_report",     None)

    # Stage 6: build state report on-the-fly if not supplied
    page_states = getattr(result, "page_states", None) or {}
    if state_report is None and page_states:
        try:
            from ..analysis.state_intelligence import build_state_intelligence_report
            state_report = build_state_intelligence_report(result)
        except Exception:
            pass
    _state_used = bool(page_states or state_report)

    gen_time   = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    scan_start = result.started_at.strftime("%Y-%m-%d %H:%M UTC") if result.started_at else "N/A"
    dur        = _duration(result)
    graph_json = _graph_data(result)
    g_stats    = result.graph.stats().get("by_type", {}) if result.graph else {}

    # Pre-compute filter buttons (Python 3.10: no backslash in f-string expressions)
    _q = "'"  # single quote helper - backslash not allowed in f-string on Python 3.10
    _btn_crit   = (f'<button class="filter-btn" data-sev="CRITICAL" onclick="filterF({_q}CRITICAL{_q},this)">Critical ({len(critical)})</button>' if critical else "")
    _btn_high   = (f'<button class="filter-btn" data-sev="HIGH" onclick="filterF({_q}HIGH{_q},this)">High ({len(high)})</button>' if high else "")
    _btn_med    = (f'<button class="filter-btn" data-sev="MEDIUM" onclick="filterF({_q}MEDIUM{_q},this)">Medium ({len(medium)})</button>' if medium else "")
    _btn_low    = (f'<button class="filter-btn" data-sev="LOW" onclick="filterF({_q}LOW{_q},this)">Low ({len(low)})</button>' if low else "")
    _btn_info   = (f'<button class="filter-btn" data-sev="INFO" onclick="filterF({_q}INFO{_q},this)">Info ({len(info_f)})</button>' if info_f else "")
    _sev_badge  = (
        '<span class="scan-badge critical-badge">CRITICAL FINDINGS</span>' if critical else
        '<span class="scan-badge high-badge">HIGH FINDINGS</span>' if high else
        '<span class="scan-badge clean-badge">SCAN COMPLETE</span>'
    )

    # Nav badges
    _find_badge_cls = "red" if (critical or high) else "orange" if medium else ""
    _lib_badge_cls  = "orange" if lib_findings else ""

    # Headless was used?
    _headless_used = bool(headless_stats)
    _auth_used     = bool(auth_result)
    _login_used    = bool(login_result)
    _sm_used       = bool(sm_details and sm_details.get("discovered"))
    _gql_used      = bool(graphql_schemas)
    _val_used      = bool(validation_results)
    _subs_used     = bool(subdomains)
    _passive_used  = bool(passive_stats)

    _so, _sc = "'", "'"  # quote helpers for onclick JS strings
    _nav_headless = ('<button class="nav-item" onclick="show(' + _so + 'headless' + _sc + ',this)"><span class="nav-icon">⬕</span>Browser Engine</button>' if _headless_used else '')
    _nav_auth     = ('<button class="nav-item" onclick="show(' + _so + 'auth' + _sc + ',this)"><span class="nav-icon">◉</span>Authentication</button>' if _auth_used else '')
    _nav_login    = ('<button class="nav-item" onclick="show(' + _so + 'login' + _sc + ',this)"><span class="nav-icon">⚿</span>Auto-Login</button>' if _login_used else '')
    _nav_srcmaps  = ('<button class="nav-item" onclick="show(' + _so + 'sourcemaps' + _sc + ',this)"><span class="nav-icon">⎔</span>Source Maps</button>' if _sm_used else '')
    _nav_graphql  = ('<button class="nav-item" onclick="show(' + _so + 'graphql' + _sc + ',this)"><span class="nav-icon">⬡</span>GraphQL</button>' if _gql_used else '')
    _nav_val      = ('<button class="nav-item" onclick="show(' + _so + 'validation' + _sc + ',this)"><span class="nav-icon">◎</span>Validation</button>' if _val_used else '')
    _nav_subs     = ('<button class="nav-item" onclick="show(' + _so + 'subdomains' + _sc + ',this)"><span class="nav-icon">⊕</span>Subdomains<span class="nav-badge">' + str(len(subdomains)) + '</span></button>' if _subs_used else '')
    _nav_state    = ('<button class="nav-item" onclick="show(' + _so + 'stateint' + _sc + ',this)"><span class="nav-icon">⊚</span>State Intelligence<span class="nav-badge">' + str(len(page_states)) + '</span></button>' if _state_used else '')
    _attack_report_candidates = attack_report.total_candidates if attack_report else 0
    _nav_mapper   = ('<button class="nav-item" onclick="show(' + _so + 'mapper' + _sc + ',this)"><span class="nav-icon">⦿</span>Attack Surface<span class="nav-badge' + (' orange' if _attack_report_candidates else '') + '">' + str(_attack_report_candidates) + '</span></button>' if attack_report else '')
