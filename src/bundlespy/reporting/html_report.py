"""
BundleSpy HTML Report - Enterprise Attack Surface Intelligence Report
=============================================================================
Professional, self-contained HTML report suitable for real client engagements.
Features: interactive D3 attack surface graph, P1 Trace Engine panel,
severity-filtered findings, full endpoint inventory, and executive summary.

No external dependencies except D3 (cdnjs). Single HTML file output.
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
    return "-"


SEV_COLOR  = {
    "CRITICAL": "#f87171",
    "HIGH":     "#fb923c",
    "MEDIUM":   "#fbbf24",
    "LOW":      "#60a5fa",
    "INFO":     "#94a3b8",
}
CAT_COLOR  = {
    "AUTH":       "#a78bfa",
    "ADMIN":      "#f87171",
    "API":        "#34d399",
    "GRAPHQL":    "#c084fc",
    "SERVERLESS": "#fbbf24",
    "WEBSOCKET":  "#22d3ee",
    "UPLOAD":     "#fb923c",
    "DOWNLOAD":   "#60a5fa",
    "ROUTE":      "#94a3b8",
    "UNKNOWN":    "#475569",
}
NODE_COLOR = {
    "PAGE":      "#60a5fa",
    "JS":        "#34d399",
    "ENDPOINT":  "#a78bfa",
    "SECRET":    "#f87171",
    "WORKER":    "#fbbf24",
    "PARAMETER": "#94a3b8",
    "HOST":      "#fb923c",
    "CHUNK":     "#22d3ee",
    "SOURCEMAP": "#86efac",
    "CONFIG":    "#c084fc",
}
NODE_ICON = {
    "PAGE":      "P",
    "JS":        "JS",
    "ENDPOINT":  "EP",
    "SECRET":    "S",
    "WORKER":    "W",
    "PARAMETER": "pr",
    "HOST":      "H",
    "CHUNK":     "C",
    "SOURCEMAP": "SM",
    "CONFIG":    "Cf",
}


# -- Section renderers ---------------------------------------------------------

def _findings_html(findings, extras):
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    real = sorted(
        [f for f in findings if f.status != "likely_false_positive"],
        key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99,
    )
    if not real:
        return '<div class="empty-state"><div class="empty-icon">+</div><p>No findings above confidence threshold</p></div>'

    rows = []
    for f in real:
        sc  = SEV_COLOR.get(f.severity, "#94a3b8")
        pub = getattr(f, "classification", "") == "PUBLIC_IDENTIFIER"
        occ_html = ""
        if f.occurrences and len(f.occurrences) > 1:
            occ_html = f'<div class="finding-occ">Also observed in {len(f.occurrences) - 1} additional location(s)</div>'
        ctx_block = ""
        if f.context:
            ctx_block = f'''<div class="evidence-block">
  <div class="evidence-label">Context</div>
  <code class="context-val">{_e(f.context[:300])}</code>
</div>'''
        pub_note = '<div class="pub-id-note">Public identifier - not a secret credential</div>' if pub else ""
        fp_note = f'<div class="fp-note">{_e(f.false_positive_notes)}</div>' if f.false_positive_notes else ""
        rows.append(f'''
<div class="finding-card" data-severity="{_e(f.severity)}" data-id="{_e(f.id or "")}">
  <div class="finding-top">
    <div class="finding-left">
      <span class="sev-pill" style="background:{sc}22;color:{sc};border:1px solid {sc}44">{_e(f.severity)}</span>
      <span class="finding-name">{_e(f.title)}</span>
      <span class="rule-id">{_e(f.rule_id)}</span>
    </div>
    <div class="finding-right">
      <div class="conf-wrap" title="{f.confidence:.0%} confidence">
        <div class="conf-bar"><div class="conf-fill" style="width:{f.confidence * 100:.0f}%;background:{sc}"></div></div>
        <span class="conf-label">{f.confidence:.0%}</span>
      </div>
      <span class="status-pill status-{_e(f.status)}">{_e(f.status.replace("_", " ").title())}</span>
    </div>
  </div>
  <div class="finding-body">
    <div class="finding-meta-grid">
      <div class="fmg-item"><span class="fmg-key">Location</span><code class="fmg-val">{_e(f.file_url)}:{f.line_number}</code></div>
      <div class="fmg-item"><span class="fmg-key">Source Page</span><code class="fmg-val">{_e(f.source_page or "-")}</code></div>
      <div class="fmg-item"><span class="fmg-key">Category</span><span class="fmg-val">{_e(f.category)}</span></div>
      <div class="fmg-item"><span class="fmg-key">Type</span><span class="fmg-val">{_e(getattr(f, "classification", "") or f.category)}</span></div>
    </div>
    <div class="evidence-block">
      <div class="evidence-label">Evidence (redacted)</div>
      <code class="evidence-val">{_e(f.redacted_value)}</code>
    </div>
    {ctx_block}
    {pub_note}
    <div class="finding-desc">{_e(f.description)}</div>
    <div class="rem-block"><span class="rem-label">Remediation</span> {_e(f.remediation)}</div>
    {fp_note}
    {occ_html}
  </div>
</div>''')
    return "\n".join(rows)


def _endpoints_html(endpoints):
    if not endpoints:
        return '<div class="empty-state"><div class="empty-icon">-</div><p>No endpoints discovered</p></div>'
    cat_order = ["AUTH", "ADMIN", "GRAPHQL", "API", "SERVERLESS", "WEBSOCKET", "UPLOAD", "DOWNLOAD", "ROUTE", "UNKNOWN"]
    by_cat = {}
    for ep in endpoints:
        by_cat.setdefault(ep.category, []).append(ep)

    parts = []
    for cat in sorted(by_cat, key=lambda c: cat_order.index(c) if c in cat_order else 99):
        cc = CAT_COLOR.get(cat, "#475569")
        rows = ""
        for ep in by_cat[cat]:
            mc = ep.method.lower() if ep.method in ("GET", "POST", "PUT", "DELETE", "PATCH", "WS", "HEAD") else "unknown"
            params = ""
            if ep.path_params:
                names = [p.get("name", "?") if isinstance(p, dict) else str(p) for p in ep.path_params]
                params += f'<span class="param-tag">{", ".join(_e(n) for n in names)}</span>'
            if ep.query_params:
                names = [p.get("name", "?") if isinstance(p, dict) else str(p) for p in ep.query_params]
                params += f'<span class="param-tag query-tag">{", ".join(_e(n) for n in names)}</span>'
            if ep.body_fields:
                names = [p.get("name", "?") if isinstance(p, dict) else str(p) for p in ep.body_fields[:4]]
                params += f'<span class="param-tag body-tag">{", ".join(_e(n) for n in names)}</span>'
            auth = f'<span class="auth-tag">{_e(ep.auth_context)}</span>' if ep.auth_context else ""
            st = getattr(ep, "source_type", "static")
            st_cls = {"static": "src-static", "runtime": "src-runtime", "correlated": "src-corr", "browser": "src-browser"}.get(st, "src-static")
            rows += f'''<tr class="ep-row">
  <td><span class="method-badge method-{mc}">{_e(ep.method)}</span></td>
  <td class="ep-url-cell"><code class="ep-url">{_e(ep.url)}</code>{params}{auth}</td>
  <td><span class="src-badge {st_cls}">{st}</span></td>
  <td class="conf-cell">{ep.confidence:.0%}</td>
  <td class="src-file-cell"><code class="file-ref">{_e((ep.source_file or "").split("/")[-1])}</code></td>
</tr>'''
        parts.append(f'''<div class="ep-group">
  <div class="ep-group-hdr" style="border-left:3px solid {cc}">
    <span class="ep-cat-label" style="color:{cc}">{_e(cat)}</span>
    <span class="ep-count-badge">{len(by_cat[cat])}</span>
  </div>
  <div class="table-wrap">
    <table class="data-table ep-table">
      <thead><tr><th>Method</th><th>Endpoint</th><th>Source</th><th>Confidence</th><th>File</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>''')
    return "\n".join(parts)


def _js_html(result, extras):
    if not result.js_files:
        return '<div class="empty-state"><div class="empty-icon">-</div><p>No JavaScript assets discovered</p></div>'
    per_file = {s["url"]: s for s in extras.get("per_file_stats", [])} if extras else {}
    rows = []
    for js in result.js_files:
        st = getattr(js, "source_type", "static")
        st_color = {
            "static":   "#34d399",
            "browser":  "#60a5fa",
            "inline":   "#a78bfa",
            "sourcemap": "#86efac",
            "chunk":    "#22d3ee",
        }.get(st, "#94a3b8")
        tech = f'<span class="tech-tag">{_e(js.technology)}</span>' if js.technology else ""
        sm   = '<span class="sm-tag">map</span>' if js.has_source_map else ""
        label = js.url
        if js.url.startswith("inline:"):
            bare = js.url.replace("inline:", "").split("#")[0]
            frag = js.url.split("#")[-1] if "#" in js.url else ""
            num  = _re.search(r"script-(\d+)", frag)
            n    = num.group(1) if num else "?"
            try:
                from urllib.parse import urlparse as _up
                p = _up(bare)
                label = f"script {n} @ {p.netloc}{p.path or '/'}"
            except Exception:
                label = js.url
        size = f"{js.size_bytes / 1024:.1f} KB" if js.size_bytes >= 1024 else f"{js.size_bytes} B"
        stats  = per_file.get(js.url, {})
        sec_n  = stats.get("secrets", 0)
        ep_n   = stats.get("endpoints", 0)
        inf_n  = stats.get("infra", 0)
        sec_c  = "color:#f87171;font-weight:600" if sec_n else ""
        rows.append(f'''<tr>
  <td><span class="src-badge" style="background:{st_color}22;color:{st_color};border:1px solid {st_color}44">{st}</span></td>
  <td><code class="js-url">{_e(label)}</code>{tech}{sm}</td>
  <td class="size-cell">{size}</td>
  <td style="{sec_c}">{sec_n}</td>
  <td>{ep_n}</td>
  <td>{inf_n}</td>
  <td><code class="hash-val">{js.sha256[:12] if js.sha256 else "-"}</code></td>
</tr>''')

    # HTML attribute findings rows
    for s in extras.get("per_file_stats", []) if extras else []:
        if s.get("technology") == "html-attrs":
            url   = s.get("url", "")
            label = url.replace("html:", "") if url.startswith("html:") else url
            sec_n = s.get("secrets", 0)
            rows.append(f'''<tr style="background:rgba(248,81,73,.04)">
  <td><span class="src-badge" style="background:#f8717122;color:#f87171;border:1px solid #f8717144">html</span></td>
  <td><code class="js-url">{_e(label)}</code> <span class="tech-tag" style="background:rgba(248,81,73,.1);color:#f87171">HTML attributes</span></td>
  <td class="size-cell">-</td>
  <td style="color:#f87171;font-weight:600">{sec_n}</td>
  <td>-</td><td>-</td><td>-</td>
</tr>''')

    return f'''<div class="table-wrap">
<table class="data-table">
  <thead><tr><th>Type</th><th>Asset</th><th>Size</th><th>Secrets</th><th>Endpoints</th><th>Infra</th><th>SHA-256</th></tr></thead>
  <tbody>{"".join(rows)}</tbody>
</table>
</div>'''


def _vulnlibs_html(lib_findings):
    if not lib_findings:
        return '<div class="empty-state"><div class="empty-icon">+</div><p>No known vulnerable libraries detected</p></div>'

    by_lib = {}
    for lf in lib_findings:
        key = f"{lf.library} {lf.version}"
        by_lib.setdefault(key, {"lib": lf.library, "version": lf.version,
                                 "file": getattr(lf, "source_file", ""), "cves": []})
        by_lib[key]["cves"].append(lf)

    parts = []
    for key, data in by_lib.items():
        cve_rows = ""
        for cve in data["cves"]:
            sc = SEV_COLOR.get(cve.severity, "#94a3b8")
            cvss_color = "#f87171" if cve.cvss >= 7 else "#fbbf24" if cve.cvss >= 4 else "#94a3b8"
            fix = getattr(cve, "fix", "") or getattr(cve, "remediation", "")
            cve_rows += f'''<tr>
  <td><span class="sev-pill" style="background:{sc}22;color:{sc};border:1px solid {sc}44">{_e(cve.severity)}</span></td>
  <td><code class="cve-id">{_e(cve.cve_id)}</code></td>
  <td><span style="color:{cvss_color};font-weight:700">{cve.cvss}</span></td>
  <td class="desc-cell">{_e(cve.description)}</td>
  <td class="fix-cell">{_e(fix)}</td>
</tr>'''
        filename = data["file"].split("/")[-1] if data["file"] else ""
        parts.append(f'''<div class="vuln-lib-card">
  <div class="vuln-lib-hdr">
    <div class="vuln-lib-name">{_e(data["lib"])}</div>
    <div class="vuln-lib-meta">
      <span class="version-badge">{_e(data["version"])}</span>
      {f'<code class="file-ref">{_e(filename)}</code>' if filename else ""}
      <span class="cve-count-badge">{len(data["cves"])} CVE{"s" if len(data["cves"]) != 1 else ""}</span>
    </div>
  </div>
  <div class="table-wrap">
    <table class="data-table">
      <thead><tr><th>Severity</th><th>CVE</th><th>CVSS</th><th>Description</th><th>Fix</th></tr></thead>
      <tbody>{cve_rows}</tbody>
    </table>
  </div>
</div>''')
    return "\n".join(parts)


def _infra_html(items):
    if not items:
        return '<div class="empty-state"><div class="empty-icon">-</div><p>No infrastructure indicators found</p></div>'
    rows = []
    for item in items[:200]:
        color = {
            "PRIVATE_IP":        "#f87171",
            "CLOUD_METADATA":    "#f87171",
            "INTERNAL_HOSTNAME": "#fb923c",
        }.get(item.classification, "#fbbf24")
        rows.append(f'''<tr>
  <td><span style="color:{color};font-weight:600;font-size:11px">{_e(item.classification)}</span></td>
  <td><code>{_e(item.value)}</code></td>
  <td><code class="file-ref">{_e(item.source_file.split("/")[-1] if item.source_file else "")}</code></td>
  <td class="num-cell">{item.line_number}</td>
  <td class="conf-cell">{item.confidence:.0%}</td>
  <td><span class="action-{item.action}">{_e(item.action.replace("_", " "))}</span></td>
</tr>''')
    return f'''<div class="table-wrap">
<table class="data-table">
  <thead><tr><th>Classification</th><th>Value</th><th>Source</th><th>Line</th><th>Confidence</th><th>Action</th></tr></thead>
  <tbody>{"".join(rows)}</tbody>
</table>
</div>'''


def _coverage_html(coverage):
    if not coverage:
        return '<div class="empty-state"><div class="empty-icon">-</div><p>Coverage data not available</p></div>'

    def _bar(visited, total, color="#34d399"):
        pct = min(100, int(visited / total * 100)) if total else 0
        return f'''<div class="cov-row">
  <div class="cov-counts">{visited} / {total}</div>
  <div class="cov-bar-wrap"><div class="cov-bar-fill" style="width:{pct}%;background:{color}"></div></div>
  <div class="cov-pct">{pct}%</div>
</div>'''

    pages  = getattr(coverage, "pages",  None)
    js     = getattr(coverage, "js",     None)
    routes = getattr(coverage, "routes", None)
    spots  = getattr(coverage, "blind_spots", [])

    cov_html = '<div class="cov-grid">'
    if pages:
        cov_html += f'''<div class="cov-card">
  <div class="cov-card-title">Pages</div>
  {_bar(getattr(pages,"visited",0), getattr(pages,"discovered",0))}
  <div class="cov-detail">Discovered: {getattr(pages,"discovered",0)} - Visited: {getattr(pages,"visited",0)}</div>
</div>'''
    if js:
        cov_html += f'''<div class="cov-card">
  <div class="cov-card-title">JavaScript</div>
  {_bar(getattr(js,"analyzed",0), getattr(js,"discovered",0), "#60a5fa")}
  <div class="cov-detail">Discovered: {getattr(js,"discovered",0)} - Analyzed: {getattr(js,"analyzed",0)}</div>
</div>'''
    if routes:
        cov_html += f'''<div class="cov-card">
  <div class="cov-card-title">Routes</div>
  {_bar(getattr(routes,"visited",0), getattr(routes,"discovered",0), "#a78bfa")}
  <div class="cov-detail">Discovered: {getattr(routes,"discovered",0)} - Visited: {getattr(routes,"visited",0)}</div>
</div>'''
    cov_html += "</div>"

    if spots:
        spots_html = ""
        for spot in spots:
            sev = getattr(spot, "severity", "LOW")
            sc  = SEV_COLOR.get(sev, "#94a3b8")
            spots_html += f'''<div class="blind-spot" style="border-left:3px solid {sc}44">
  <div class="blind-spot-hdr">
    <span class="sev-pill" style="background:{sc}22;color:{sc};border:1px solid {sc}44">{_e(sev)}</span>
    <span class="blind-spot-title">{_e(getattr(spot,"title","Blind spot"))}</span>
  </div>
  <div class="blind-spot-desc">{_e(getattr(spot,"description",""))}</div>
  {f'<div class="blind-spot-rec">- {_e(getattr(spot,"recommendation",""))}</div>' if getattr(spot,"recommendation","") else ""}
</div>'''
        cov_html += f'<div class="blind-spots-wrap"><div class="subsection-title">Blind Spots</div>{spots_html}</div>'

    return cov_html


def _headless_html(headless_stats):
    if not headless_stats:
        return '<div class="empty-state"><div class="empty-icon">-</div><p>Headless browser was not used in this scan</p></div>'
    timings  = headless_stats.get("timings", {})
    api_calls = headless_stats.get("xhr", 0) + headless_stats.get("fetch", 0)
    rows = [
        ("Pages visited",         headless_stats.get("pages", 0)),
        ("JS captured",           headless_stats.get("js", 0)),
        ("API calls (XHR/Fetch)", api_calls),
        ("WebSocket connections", headless_stats.get("ws", 0)),
        ("Routes discovered",     headless_stats.get("routes", 0)),
        ("Web Workers",           headless_stats.get("workers", 0)),
    ]
    meta = "".join(f'<tr><td class="mk">{k}</td><td class="mv">{v}</td></tr>' for k, v in rows)
    timing_rows = ""
    for phase, secs in timings.items():
        if phase != "total":
            timing_rows += f'<tr><td class="mk">{_e(phase.replace("_"," ").title())}</td><td class="mv">{secs:.1f}s</td></tr>'
    if timings.get("total"):
        timing_rows += f'<tr><td class="mk" style="font-weight:700">Total</td><td class="mv" style="font-weight:700">{timings["total"]:.1f}s</td></tr>'
    return f'''<div class="two-col">
  <div>
    <div class="subsection-title">Discovery Stats</div>
    <table class="meta-table">{meta}</table>
  </div>
  <div>
    <div class="subsection-title">Phase Timings</div>
    <table class="meta-table">{timing_rows}</table>
  </div>
</div>'''


def _auth_html(auth_result):
    if not auth_result:
        return '<div class="empty-state"><div class="empty-icon">-</div><p>No credentials supplied - unauthenticated scan</p></div>'
    verified = auth_result.get("authenticated", False)
    vc   = "#34d399" if verified else "#f87171"
    vt   = "VERIFIED" if verified else "NOT VERIFIED"
    redirected    = auth_result.get("final_url", "") != auth_result.get("initial_url", "")
    chain         = auth_result.get("redirect_chain", [])
    cookies_present = auth_result.get("cookies_present", [])
    reason        = auth_result.get("reason", "")
    status        = auth_result.get("status", 0)
    sc = "#34d399" if status == 200 else "#fbbf24" if status in (301, 302) else "#f87171"
    rows = [
        ("Credentials supplied", "YES" if auth_result.get("credentials_supplied") else "NO"),
        ("Cookies injected",     auth_result.get("cookies_injected", 0)),
        ("Initial URL",          auth_result.get("initial_url", "-")),
        ("HTTP status",          f'<span style="color:{sc};font-weight:700">{status}</span>'),
        ("Final URL",            auth_result.get("final_url", "-")),
        ("Redirected",           "YES" if redirected else "NO"),
    ]
    if cookies_present:
        rows.append(("Browser cookies", ", ".join(cookies_present[:8])))
    if chain:
        rows.append(("Redirect chain", " - ".join(chain[:5])))
    meta = "".join(f'<tr><td class="mk">{k}</td><td class="mv">{v}</td></tr>' for k, v in rows)
    warn = f'<div class="auth-warn">{_e(reason)}</div>' if not verified and reason else ""
    return f'''<div class="auth-status-bar" style="border-left:4px solid {vc}">
  <div class="auth-verified" style="color:{vc}">- {vt}</div>
</div>
{warn}
<table class="meta-table">{meta}</table>'''


def _subdomains_html(subdomains):
    if not subdomains:
        return '<div class="empty-state"><div class="empty-icon">-</div><p>No subdomains harvested</p></div>'
    rows = "".join(f'<tr><td><code>{_e(s)}</code></td></tr>' for s in sorted(subdomains))
    return f'''<div class="table-wrap">
<table class="data-table">
  <thead><tr><th>Subdomain</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
</div>'''


def _graphql_html(graphql_schemas):
    if not graphql_schemas:
        return '<div class="empty-state"><div class="empty-icon">-</div><p>No GraphQL schemas introspected</p></div>'
    parts = []
    for schema in graphql_schemas:
        if getattr(schema, "error", None):
            parts.append(f'<div class="gql-error">{_e(schema.endpoint)}: {_e(schema.error)}</div>')
            continue
        queries   = getattr(schema, "queries", [])
        mutations = getattr(schema, "mutations", [])
        subs      = getattr(schema, "subscriptions", [])
        q_rows = "".join(f'<tr><td><code>{_e(q)}</code></td><td class="gql-type">query</td></tr>' for q in queries[:50])
        m_rows = "".join(f'<tr><td><code>{_e(m)}</code></td><td class="gql-type gql-mut">mutation</td></tr>' for m in mutations[:50])
        s_rows = "".join(f'<tr><td><code>{_e(s)}</code></td><td class="gql-type gql-sub">subscription</td></tr>' for s in subs[:20])
        parts.append(f'''<div class="gql-schema-card">
  <div class="gql-schema-hdr">
    <code class="gql-ep">{_e(schema.endpoint)}</code>
    <span class="gql-meta">{len(queries)} queries - {len(mutations)} mutations - {len(subs)} subscriptions</span>
  </div>
  <div class="table-wrap">
    <table class="data-table">
      <thead><tr><th>Operation</th><th>Type</th></tr></thead>
      <tbody>{q_rows}{m_rows}{s_rows}</tbody>
    </table>
  </div>
</div>''')
    return "\n".join(parts)


def _validation_html(validation_results):
    if not validation_results:
        return '<div class="empty-state"><div class="empty-icon">-</div><p>Endpoint validation was not run</p></div>'
    interesting = [r for r in validation_results if getattr(r, "interesting", False)]
    rows = ""
    for r in validation_results[:200]:
        status = getattr(r, "status_code", 0)
        stat_c = "#34d399" if status == 200 else "#fbbf24" if status in (301, 302, 307, 308) else "#f87171" if status >= 400 else "#94a3b8"
        is_int = getattr(r, "interesting", False)
        rows += f'''<tr>
  <td><code class="ep-url">{_e(getattr(r,"url",""))}</code></td>
  <td><span style="color:{stat_c};font-weight:700">{status}</span></td>
  <td class="ct-cell">{_e(getattr(r,"content_type",""))}</td>
  <td class="num-cell">{getattr(r,"response_size",0):,}</td>
  <td><span style="color:{"#34d399" if is_int else "#475569"}">{"Interesting" if is_int else "-"}</span></td>
</tr>'''
    return f'''<div class="val-summary">{len(validation_results)} endpoints probed - <span style="color:#34d399;font-weight:600">{len(interesting)} interesting</span></div>
<div class="table-wrap">
<table class="data-table">
  <thead><tr><th>URL</th><th>Status</th><th>Content-Type</th><th>Size</th><th>Note</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
</div>'''


def _sourcemap_html(sm_details):
    if not sm_details or not sm_details.get("discovered"):
        return '<div class="empty-state"><div class="empty-icon">-</div><p>No source maps found</p></div>'
    items = sm_details.get("items", [])
    rows = "".join(f'''<tr>
  <td><code class="file-ref">{_e(i.get("js",""))}</code></td>
  <td><code class="file-ref">{_e(i.get("map",""))}</code></td>
  <td class="num-cell">{i.get("sources",0)}</td>
</tr>''' for i in items)
    return f'''<div class="sm-summary">{sm_details.get("discovered",0)} map(s) found - {sm_details.get("sources",0)} source file(s) recovered</div>
<div class="table-wrap">
<table class="data-table">
  <thead><tr><th>JS File</th><th>Map File</th><th>Sources</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
</div>'''


def _trace_data(result) -> str:
    """Serialise all trace results to JSON for the Trace Panel JS."""
    if not result.graph:
        return "null"
    graph = result.graph
    try:
        from ..storage.graph import NodeType
        traces = []

        # Trace all secrets (upstream paths)
        for secret in graph.nodes_of_kind(NodeType.SECRET)[:30]:
            tr = graph.trace_upstream(secret.id, max_depth=5)
            if tr.steps:
                traces.append(tr.to_dict())

        # Trace all pages (downstream surfaces)
        for page in graph.nodes_of_kind(NodeType.PAGE)[:20]:
            tr = graph.trace_downstream(page.id, max_depth=4)
            if tr.steps:
                traces.append(tr.to_dict())

        return _j(traces)
    except Exception:
        return "[]"


def _graph_data(result) -> str:
    if not result.graph:
        return "null"
    return _j(result.graph.to_dict())


# -- Main generator ------------------------------------------------------------

def generate(
    result: ScanResult,
    show_sensitive: bool = False,
    extras: dict = None,
    validation_results: list = None,
    graphql_schemas: list = None,
    subdomains: list = None,
    report_paths: dict = None,
) -> str:
    extras             = extras or {}
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

    lib_findings   = extras.get("lib_findings",       [])
    headless_stats = extras.get("headless_stats",     {})
    auth_result    = extras.get("auth_result",        None)
    coverage       = extras.get("coverage",           None)
    sm_details     = extras.get("source_map_details", {})

    gen_time   = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    scan_start = result.started_at.strftime("%Y-%m-%d %H:%M UTC") if result.started_at else "-"
    dur        = _duration(result)
    graph_json = _graph_data(result)
    trace_json = _trace_data(result)
    g_stats    = result.graph.stats().get("by_type", {}) if result.graph else {}

    # Risk level
    if critical:
        risk_level = "CRITICAL"
        risk_color = "#f87171"
        risk_bg    = "#3d1515"
    elif high:
        risk_level = "HIGH"
        risk_color = "#fb923c"
        risk_bg    = "#3d2215"
    elif medium:
        risk_level = "MEDIUM"
        risk_color = "#fbbf24"
        risk_bg    = "#3d3015"
    else:
        risk_level = "CLEAN"
        risk_color = "#34d399"
        risk_bg    = "#153d15"

    _headless_used = bool(headless_stats)
    _auth_used     = bool(auth_result)
    _sm_used       = bool(sm_details and sm_details.get("discovered"))
    _gql_used      = bool(graphql_schemas)
    _val_used      = bool(validation_results)
    _subs_used     = bool(subdomains)

    _q = "'"

    def nav_item(icon, label, section, badge_val=None, badge_cls=""):
        badge = ""
        if badge_val is not None:
            badge = f'<span class="nav-badge {badge_cls}">{badge_val}</span>'
        return f'<button class="nav-item" onclick="show({_q}{section}{_q},this)"><span class="nav-icon">{icon}</span>{label}{badge}</button>'

    _find_badge_cls = "badge-red" if (critical or high) else "badge-orange" if medium else ""
    _lib_badge_cls  = "badge-orange" if lib_findings else ""

    nav_discovery = ""
    if _headless_used:
        nav_discovery += nav_item("browser", "Browser Engine", "headless")
    if _auth_used:
        nav_discovery += nav_item("lock", "Authentication", "auth")
    nav_discovery += nav_item("code", "Source Maps", "sourcemaps")
    if _gql_used:
        nav_discovery += nav_item("gql", "GraphQL", "graphql")
    if _val_used:
        nav_discovery += nav_item("check", "Validation", "validation")
    if _subs_used:
        nav_discovery += nav_item("globe", "Subdomains", "subdomains", len(subdomains))

    # Filter buttons
    sev_filter_btns = f'<button class="filter-btn active" onclick="filterFindings({_q}ALL{_q},this)">All ({len(real)})</button>'
    if critical:
        sev_filter_btns += f'<button class="filter-btn" onclick="filterFindings({_q}CRITICAL{_q},this)">Critical ({len(critical)})</button>'
    if high:
        sev_filter_btns += f'<button class="filter-btn" onclick="filterFindings({_q}HIGH{_q},this)">High ({len(high)})</button>'
    if medium:
        sev_filter_btns += f'<button class="filter-btn" onclick="filterFindings({_q}MEDIUM{_q},this)">Medium ({len(medium)})</button>'
    if low:
        sev_filter_btns += f'<button class="filter-btn" onclick="filterFindings({_q}LOW{_q},this)">Low ({len(low)})</button>'
    if info_f:
        sev_filter_btns += f'<button class="filter-btn" onclick="filterFindings({_q}INFO{_q},this)">Info ({len(info_f)})</button>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BundleSpy - Attack Surface Report</title>
<style>
/* ============================================================
   Design tokens
   ============================================================ */
:root {{
  --bg:        #0d1117;
  --surface:   #161b22;
  --surface2:  #1c2128;
  --surface3:  #21262d;
  --border:    #21262d;
  --border2:   #30363d;
  --text:      #e6edf3;
  --text2:     #8b949e;
  --text3:     #6e7681;
  --accent:    #58a6ff;
  --green:     #3fb950;
  --red:       #f85149;
  --orange:    #f0883e;
  --yellow:    #e3b341;
  --purple:    #bc8cff;
  --cyan:      #39d0d8;
  --r:         8px;
  --r-sm:      4px;
  --r-xs:      3px;
  --sidebar-w: 236px;
  --topbar-h:  54px;
}}

/* ============================================================
   Reset / base
   ============================================================ */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ scroll-behavior: smooth; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', sans-serif;
  background: var(--bg);
  color: var(--text);
  font-size: 13px;
  line-height: 1.6;
  min-height: 100vh;
}}
code {{
  font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
  font-size: 11px;
  background: var(--surface3);
  padding: 2px 5px;
  border-radius: var(--r-xs);
  word-break: break-all;
}}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}

/* ============================================================
   Layout
   ============================================================ */
.layout {{ display: flex; min-height: 100vh; }}
.sidebar {{
  width: var(--sidebar-w);
  background: var(--surface);
  border-right: 1px solid var(--border);
  position: fixed; top: 0; left: 0; height: 100vh;
  overflow-y: auto; z-index: 100;
  display: flex; flex-direction: column;
}}
.main {{ margin-left: var(--sidebar-w); flex: 1; display: flex; flex-direction: column; min-width: 0; }}
.topbar {{
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 0 28px;
  height: var(--topbar-h);
  display: flex; align-items: center; justify-content: space-between;
  position: sticky; top: 0; z-index: 50; gap: 16px;
}}
.content {{ padding: 24px 28px 48px; max-width: 1340px; }}

/* ============================================================
   Sidebar
   ============================================================ */
.sidebar-logo {{
  padding: 18px 18px 14px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}}
.logo-wordmark {{ font-size: 15px; font-weight: 800; letter-spacing: -0.5px; }}
.logo-wordmark .logo-accent {{ color: var(--accent); }}
.logo-sub {{ font-size: 10px; color: var(--text3); margin-top: 2px; text-transform: uppercase; letter-spacing: 0.8px; font-weight: 500; }}

.nav-group {{ padding: 10px 10px 4px; }}
.nav-group-label {{
  font-size: 10px; font-weight: 700; color: var(--text3);
  text-transform: uppercase; letter-spacing: 0.9px;
  padding: 0 8px; margin-bottom: 4px;
}}
.nav-item {{
  display: flex; align-items: center; gap: 8px;
  padding: 6px 10px; border-radius: var(--r-sm);
  color: var(--text2); font-size: 12px; cursor: pointer;
  transition: all .15s; border: none; background: none;
  width: 100%; text-align: left; font-family: inherit;
}}
.nav-item:hover {{ background: rgba(88,166,255,.08); color: var(--text); }}
.nav-item.active {{ background: rgba(88,166,255,.12); color: var(--accent); font-weight: 600; }}
.nav-icon {{
  width: 16px; height: 16px; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  font-size: 11px; opacity: .65;
}}
.nav-badge {{
  margin-left: auto; background: var(--surface3); color: var(--text2);
  font-size: 10px; padding: 1px 7px; border-radius: 10px; font-weight: 600;
}}
.nav-badge.badge-red {{ background: #3d1515; color: #f87171; }}
.nav-badge.badge-orange {{ background: #3d2215; color: #fb923c; }}

.sidebar-footer {{
  margin-top: auto; padding: 12px 14px;
  border-top: 1px solid var(--border);
  font-size: 10px; color: var(--text3); line-height: 1.5;
}}

/* ============================================================
   Topbar
   ============================================================ */
.topbar-target {{ display: flex; flex-direction: column; gap: 1px; min-width: 0; flex: 1; }}
.topbar-url {{
  font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
  font-size: 13px; color: var(--accent); font-weight: 600;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}}
.topbar-meta {{ font-size: 11px; color: var(--text3); }}
.risk-badge {{
  padding: 4px 12px; border-radius: 20px;
  font-size: 11px; font-weight: 700; letter-spacing: 0.4px;
  white-space: nowrap; border: 1px solid;
}}

/* ============================================================
   Sections
   ============================================================ */
.section {{ display: none; }}
.section.active {{ display: block; }}
.section-title {{
  font-size: 17px; font-weight: 700; margin-bottom: 20px;
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
}}
.section-count {{ font-size: 12px; color: var(--text3); font-weight: 400; }}
.subsection-title {{
  font-size: 11px; font-weight: 700; color: var(--text3);
  text-transform: uppercase; letter-spacing: 0.6px;
  margin-bottom: 10px; margin-top: 20px;
}}

/* ============================================================
   Cards
   ============================================================ */
.card {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--r); overflow: hidden; margin-bottom: 16px;
}}
.card-header {{
  padding: 11px 16px; border-bottom: 1px solid var(--border);
  font-weight: 600; font-size: 13px;
  display: flex; align-items: center; justify-content: space-between;
}}
.card-body {{ padding: 16px; }}
.card-body-flush {{ padding: 0; }}

/* ============================================================
   Overview grid
   ============================================================ */
.metric-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 10px; margin-bottom: 20px;
}}
.metric-card {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--r); padding: 16px 18px;
  position: relative; overflow: hidden;
}}
.metric-card::after {{
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
}}
.mc-red::after   {{ background: var(--red); }}
.mc-orange::after {{ background: var(--orange); }}
.mc-yellow::after {{ background: var(--yellow); }}
.mc-blue::after  {{ background: var(--accent); }}
.mc-green::after {{ background: var(--green); }}
.mc-purple::after {{ background: var(--purple); }}
.mc-cyan::after  {{ background: var(--cyan); }}
.mc-grey::after  {{ background: var(--text3); }}
.metric-num {{ font-size: 28px; font-weight: 800; line-height: 1; margin-bottom: 3px; }}
.mc-red    .metric-num {{ color: var(--red); }}
.mc-orange .metric-num {{ color: var(--orange); }}
.mc-yellow .metric-num {{ color: var(--yellow); }}
.mc-blue   .metric-num {{ color: var(--accent); }}
.mc-green  .metric-num {{ color: var(--green); }}
.mc-purple .metric-num {{ color: var(--purple); }}
.mc-cyan   .metric-num {{ color: var(--cyan); }}
.mc-grey   .metric-num {{ color: var(--text2); }}
.metric-lbl {{ font-size: 10px; color: var(--text3); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }}

/* ============================================================
   Meta table
   ============================================================ */
.meta-table {{ width: 100%; border-collapse: collapse; }}
.meta-table td {{ padding: 8px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }}
.meta-table tr:last-child td {{ border-bottom: none; }}
.mk {{ color: var(--text3); font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px; font-weight: 600; width: 170px; white-space: nowrap; }}
.mv {{ color: var(--text); font-size: 12px; }}

/* ============================================================
   Findings
   ============================================================ */
.filter-row {{ display: flex; gap: 6px; margin-bottom: 16px; flex-wrap: wrap; }}
.filter-btn {{
  padding: 4px 13px; border-radius: 20px;
  border: 1px solid var(--border2); background: none;
  color: var(--text2); font-size: 11px; cursor: pointer;
  transition: all .15s; font-family: inherit; font-weight: 500;
}}
.filter-btn:hover, .filter-btn.active {{
  border-color: var(--accent); color: var(--accent);
  background: rgba(88,166,255,.08);
}}
.finding-card {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--r); margin-bottom: 10px; overflow: hidden;
  transition: border-color .15s;
}}
.finding-card:hover {{ border-color: var(--border2); }}
.finding-top {{
  display: flex; align-items: center; justify-content: space-between;
  padding: 11px 14px; gap: 10px; flex-wrap: wrap;
}}
.finding-left {{ display: flex; align-items: center; gap: 8px; flex: 1; min-width: 0; }}
.finding-name {{ font-weight: 700; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.rule-id {{
  font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
  font-size: 10px; color: var(--text3);
  background: var(--border); padding: 1px 6px; border-radius: var(--r-xs);
  white-space: nowrap;
}}
.finding-right {{ display: flex; align-items: center; gap: 8px; flex-shrink: 0; }}
.sev-pill {{
  font-size: 10px; font-weight: 700; padding: 2px 8px;
  border-radius: 10px; letter-spacing: 0.4px; white-space: nowrap;
}}
.status-pill {{
  font-size: 10px; padding: 2px 7px; border-radius: var(--r-xs); font-weight: 600;
}}
.status-likely-secret {{ background: #3a2a10; color: #fbbf24; }}
.status-candidate {{ background: #3a2010; color: #fb923c; }}
.status-validated {{ background: #1a3a1a; color: #3fb950; }}
.status-likely-false-positive {{ background: var(--border); color: var(--text3); }}
.conf-wrap {{ display: flex; align-items: center; gap: 6px; }}
.conf-bar {{ width: 52px; height: 3px; background: var(--border2); border-radius: 2px; overflow: hidden; }}
.conf-fill {{ height: 100%; border-radius: 2px; }}
.conf-label {{ font-size: 10px; color: var(--text3); width: 30px; text-align: right; }}
.finding-body {{ padding: 12px 14px; border-top: 1px solid var(--border); }}
.finding-meta-grid {{
  display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 8px; margin-bottom: 12px;
}}
.fmg-item {{ display: flex; flex-direction: column; gap: 2px; }}
.fmg-key {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.4px; color: var(--text3); font-weight: 600; }}
.fmg-val {{ font-size: 11px; }}
.evidence-block {{
  background: #0a0d13; border: 1px solid var(--border);
  border-radius: var(--r-sm); padding: 10px 12px; margin-bottom: 10px;
}}
.evidence-label {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.4px; color: var(--text3); margin-bottom: 5px; font-weight: 600; }}
.evidence-val {{ font-family: 'SF Mono','Fira Code',Consolas,monospace; font-size: 12px; color: #3fb950; background: none; padding: 0; word-break: break-all; }}
.context-val {{ font-family: 'SF Mono','Fira Code',Consolas,monospace; font-size: 11px; color: var(--text2); background: none; padding: 0; display: block; white-space: pre-wrap; word-break: break-all; max-height: 80px; overflow: hidden; }}
.finding-desc {{ font-size: 12px; color: var(--text2); margin-bottom: 8px; line-height: 1.7; }}
.rem-block {{ font-size: 12px; color: var(--text2); padding: 7px 12px; background: rgba(63,185,80,.05); border-left: 2px solid var(--green); border-radius: 0 var(--r-xs) var(--r-xs) 0; margin-bottom: 8px; line-height: 1.7; }}
.rem-label {{ font-weight: 700; color: var(--green); }}
.fp-note {{ font-size: 11px; color: var(--text3); background: rgba(255,255,255,.03); padding: 5px 8px; border-radius: var(--r-xs); margin-top: 5px; }}
.finding-occ {{ font-size: 11px; color: var(--text3); margin-top: 6px; }}
.pub-id-note {{ font-size: 11px; color: var(--cyan); background: rgba(57,208,216,.06); border: 1px solid rgba(57,208,216,.2); border-radius: var(--r-xs); padding: 4px 9px; margin-bottom: 8px; }}

/* ============================================================
   Endpoints
   ============================================================ */
.ep-group {{ margin-bottom: 20px; }}
.ep-group-hdr {{
  display: flex; align-items: center; justify-content: space-between;
  padding: 8px 14px; background: var(--surface);
  border: 1px solid var(--border); border-radius: var(--r) var(--r) 0 0;
}}
.ep-cat-label {{ font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; }}
.ep-count-badge {{ font-size: 11px; color: var(--text3); font-weight: 600; }}
.ep-table .ep-url-cell {{ max-width: 420px; }}
.ep-url {{ font-size: 11px; word-break: break-all; }}
.method-badge {{
  font-family: 'SF Mono','Fira Code',Consolas,monospace;
  font-size: 10px; font-weight: 800; padding: 2px 7px;
  border-radius: var(--r-xs); letter-spacing: 0.2px;
  display: inline-block; white-space: nowrap;
}}
.method-get     {{ background: #1a3a1a; color: #3fb950; }}
.method-post    {{ background: #3a1a1a; color: #f85149; }}
.method-put     {{ background: #3a2a1a; color: #f0883e; }}
.method-delete  {{ background: #3a1a2a; color: #f87171; }}
.method-patch   {{ background: #2a1a3a; color: #bc8cff; }}
.method-ws      {{ background: #1a2a3a; color: #39d0d8; }}
.method-head    {{ background: #2a2a1a; color: #e3b341; }}
.method-unknown {{ background: var(--border); color: var(--text3); }}
.param-tag {{ font-size: 10px; color: var(--purple); background: rgba(188,140,255,.1); border: 1px solid rgba(188,140,255,.2); padding: 1px 5px; border-radius: var(--r-xs); margin-left: 6px; }}
.query-tag {{ color: #39d0d8; background: rgba(57,208,216,.08); border-color: rgba(57,208,216,.2); }}
.body-tag  {{ color: #f0883e; background: rgba(240,136,62,.08); border-color: rgba(240,136,62,.2); }}
.auth-tag  {{ font-size: 10px; color: #39d0d8; background: rgba(57,208,216,.1); border: 1px solid rgba(57,208,216,.2); padding: 1px 5px; border-radius: var(--r-xs); margin-left: 4px; }}
.src-badge {{ font-size: 10px; padding: 2px 6px; border-radius: var(--r-xs); font-weight: 600; }}
.src-static  {{ background: #1a3a1a; color: #3fb950; }}
.src-runtime {{ background: #1a2a3a; color: #60a5fa; }}
.src-corr    {{ background: #2a1a3a; color: #bc8cff; }}
.src-browser {{ background: #1a2a3a; color: #39d0d8; }}
.conf-cell {{ font-size: 11px; color: var(--text3); white-space: nowrap; }}
.src-file-cell {{ max-width: 140px; }}
.file-ref {{ font-size: 10px; color: var(--text3); max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; vertical-align: middle; }}

/* ============================================================
   JS assets
   ============================================================ */
.js-url {{ font-size: 11px; word-break: break-all; }}
.tech-tag {{ font-size: 10px; background: rgba(63,185,80,.1); color: #3fb950; border: 1px solid rgba(63,185,80,.2); padding: 1px 5px; border-radius: var(--r-xs); margin-left: 6px; }}
.sm-tag  {{ font-size: 10px; background: rgba(88,166,255,.1); color: #58a6ff; border: 1px solid rgba(88,166,255,.2); padding: 1px 5px; border-radius: var(--r-xs); margin-left: 4px; }}
.size-cell {{ color: var(--text3); font-size: 11px; white-space: nowrap; }}
.hash-val  {{ font-family: 'SF Mono','Fira Code',Consolas,monospace; font-size: 10px; color: var(--text3); }}

/* ============================================================
   Vulnerable libraries
   ============================================================ */
.vuln-lib-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--r); margin-bottom: 14px; overflow: hidden; }}
.vuln-lib-hdr {{ padding: 12px 16px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }}
.vuln-lib-name {{ font-weight: 800; font-size: 14px; }}
.vuln-lib-meta {{ display: flex; align-items: center; gap: 8px; }}
.version-badge {{ background: rgba(227,179,65,.1); color: #e3b341; border: 1px solid rgba(227,179,65,.3); font-size: 11px; padding: 2px 8px; border-radius: 10px; font-weight: 700; }}
.cve-count-badge {{ font-size: 11px; color: var(--text3); font-weight: 600; }}
.desc-cell {{ color: var(--text2); max-width: 280px; }}
.fix-cell {{ color: var(--text3); font-size: 11px; max-width: 160px; }}

/* ============================================================
   Data table (generic)
   ============================================================ */
.table-wrap {{ overflow-x: auto; }}
.data-table {{
  width: 100%; border-collapse: collapse; font-size: 12px;
}}
.data-table th {{
  background: #0a0d13; padding: 7px 12px; text-align: left;
  font-size: 10px; text-transform: uppercase; letter-spacing: 0.4px;
  color: var(--text3); font-weight: 700; border-bottom: 1px solid var(--border);
  white-space: nowrap;
}}
.data-table td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
.data-table tr:last-child td {{ border-bottom: none; }}
.data-table tr:hover td {{ background: rgba(255,255,255,.015); }}
.num-cell {{ color: var(--text3); text-align: right; font-size: 11px; }}
.ct-cell  {{ color: var(--text2); font-size: 11px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.cve-id {{ font-size: 11px; }}

/* ============================================================
   Coverage
   ============================================================ */
.cov-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px; margin-bottom: 16px; }}
.cov-card {{ background: var(--surface2); border: 1px solid var(--border); border-radius: var(--r); padding: 14px 16px; }}
.cov-card-title {{ font-size: 11px; font-weight: 700; color: var(--text3); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 10px; }}
.cov-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }}
.cov-counts {{ font-size: 11px; color: var(--text2); width: 60px; text-align: right; flex-shrink: 0; }}
.cov-bar-wrap {{ flex: 1; height: 6px; background: var(--border2); border-radius: 3px; overflow: hidden; }}
.cov-bar-fill {{ height: 100%; border-radius: 3px; transition: width .4s; }}
.cov-pct {{ font-size: 11px; color: var(--text2); width: 32px; font-weight: 700; }}
.cov-detail {{ font-size: 10px; color: var(--text3); margin-top: 4px; }}
.blind-spots-wrap {{ margin-top: 16px; }}
.blind-spot {{ padding: 10px 14px; margin-bottom: 8px; background: var(--surface); border-radius: var(--r-sm); border-bottom: 1px solid var(--border); }}
.blind-spot-hdr {{ display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }}
.blind-spot-title {{ font-size: 12px; font-weight: 700; }}
.blind-spot-desc {{ font-size: 12px; color: var(--text2); margin-bottom: 3px; }}
.blind-spot-rec {{ font-size: 11px; color: var(--text3); font-style: italic; }}

/* ============================================================
   Auth
   ============================================================ */
.auth-status-bar {{ border-left: 4px solid; padding: 8px 14px; margin-bottom: 14px; }}
.auth-verified {{ font-weight: 800; font-size: 15px; }}
.auth-warn {{ background: rgba(248,81,73,.08); border: 1px solid rgba(248,81,73,.2); border-radius: var(--r-sm); padding: 9px 13px; font-size: 12px; color: #f87171; margin-bottom: 12px; }}

/* ============================================================
   Source maps / GraphQL / Validation
   ============================================================ */
.sm-summary {{ font-size: 12px; color: var(--text2); margin-bottom: 10px; padding: 8px 13px; background: var(--surface2); border-radius: var(--r-sm); }}
.val-summary {{ font-size: 12px; color: var(--text2); margin-bottom: 10px; }}
.gql-schema-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--r); margin-bottom: 12px; overflow: hidden; }}
.gql-schema-hdr {{ padding: 10px 14px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }}
.gql-ep {{ font-size: 12px; }}
.gql-meta {{ font-size: 11px; color: var(--text3); }}
.gql-type {{ font-size: 10px; color: var(--purple); font-weight: 700; }}
.gql-mut  {{ color: #f87171; }}
.gql-sub  {{ color: #39d0d8; }}
.gql-error {{ color: var(--red); font-size: 12px; padding: 8px; background: rgba(248,81,73,.06); border-radius: var(--r-xs); margin-bottom: 8px; }}

/* ============================================================
   Two-column layout
   ============================================================ */
.two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
@media (max-width: 700px) {{ .two-col {{ grid-template-columns: 1fr; }} }}

/* ============================================================
   Infrastructure
   ============================================================ */
.action-report_only {{ color: var(--yellow); font-weight: 600; }}
.action-investigate {{ color: var(--red); font-weight: 700; }}

/* ============================================================
   Graph canvas
   ============================================================ */
#graph-wrap {{
  width: 100%; height: 580px;
  background: #080b10; border: 1px solid var(--border);
  border-radius: var(--r); position: relative; overflow: hidden;
  margin-bottom: 16px;
}}
#graph-svg {{ width: 100%; height: 100%; }}
.graph-controls {{
  position: absolute; top: 12px; right: 12px;
  display: flex; flex-direction: column; gap: 5px;
}}
.graph-ctrl-btn {{
  background: var(--surface); border: 1px solid var(--border);
  color: var(--text2); width: 30px; height: 30px;
  border-radius: var(--r-sm); cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  font-size: 14px; transition: all .15s; font-family: inherit;
}}
.graph-ctrl-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
.graph-legend {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; }}
.legend-dot {{ width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }}
.legend-item {{ display: flex; align-items: center; gap: 5px; font-size: 11px; color: var(--text3); }}

/* Graph tooltip */
#node-tt {{
  position: absolute; background: var(--surface); border: 1px solid var(--border2);
  border-radius: var(--r); padding: 10px 13px; font-size: 11px;
  pointer-events: none; z-index: 200; max-width: 280px;
  box-shadow: 0 8px 28px rgba(0,0,0,.55); display: none;
}}
.tt-kind {{ font-size: 9px; text-transform: uppercase; letter-spacing: 0.7px; color: var(--text3); margin-bottom: 3px; font-weight: 700; }}
.tt-label {{ font-weight: 700; color: var(--text); margin-bottom: 5px; word-break: break-all; }}
.tt-meta {{ font-size: 10px; color: var(--text2); line-height: 1.6; }}

/* Graph side panel */
#graph-panel {{
  position: absolute; right: 0; top: 0; bottom: 0; width: 290px;
  background: var(--surface); border-left: 1px solid var(--border);
  padding: 14px 16px; overflow-y: auto;
  transform: translateX(100%); transition: transform .25s; z-index: 50;
}}
#graph-panel.open {{ transform: translateX(0); }}
.panel-close {{
  position: absolute; top: 10px; right: 10px;
  background: none; border: none; color: var(--text3); cursor: pointer;
  font-size: 15px; padding: 4px; line-height: 1;
}}
.panel-kind {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.7px; font-weight: 700; margin-bottom: 4px; }}
.panel-label {{ font-size: 13px; font-weight: 700; margin-bottom: 14px; word-break: break-all; }}
.panel-sec {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text3); font-weight: 700; margin: 12px 0 5px; border-bottom: 1px solid var(--border); padding-bottom: 3px; }}
.panel-row {{ display: flex; justify-content: space-between; gap: 8px; margin-bottom: 5px; font-size: 11px; }}
.panel-key {{ color: var(--text3); flex-shrink: 0; }}
.panel-val {{ color: var(--text); text-align: right; word-break: break-all; }}
.nb-list {{ display: flex; flex-direction: column; gap: 3px; margin-top: 4px; }}
.nb-item {{
  font-size: 11px; color: var(--text2); padding: 4px 8px;
  background: var(--bg); border-radius: var(--r-xs); cursor: pointer;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}}
.nb-item:hover {{ color: var(--accent); }}

/* ============================================================
   Trace Panel
   ============================================================ */
#trace-section {{ display: none; }}
#trace-section.active {{ display: block; }}
.trace-selector {{ margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }}
.trace-sel-label {{ font-size: 12px; color: var(--text2); font-weight: 600; }}
.trace-mode-btns {{ display: flex; gap: 6px; }}
.trace-mode-btn {{
  padding: 5px 14px; border-radius: 20px; border: 1px solid var(--border2);
  background: none; color: var(--text2); font-size: 11px; cursor: pointer;
  transition: all .15s; font-family: inherit; font-weight: 600;
}}
.trace-mode-btn.active, .trace-mode-btn:hover {{
  border-color: var(--purple); color: var(--purple);
  background: rgba(188,140,255,.08);
}}
.trace-list {{ display: flex; flex-direction: column; gap: 8px; }}
.trace-card {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--r); overflow: hidden;
}}
.trace-card-hdr {{
  padding: 10px 14px; display: flex; align-items: center;
  gap: 10px; cursor: pointer; user-select: none;
  transition: background .15s;
}}
.trace-card-hdr:hover {{ background: var(--surface2); }}
.trace-origin-kind {{ font-size: 10px; font-weight: 700; padding: 2px 7px; border-radius: var(--r-xs); }}
.trace-origin-label {{ font-weight: 600; font-size: 13px; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.trace-step-count {{ font-size: 11px; color: var(--text3); flex-shrink: 0; }}
.trace-dir-badge {{ font-size: 10px; font-weight: 700; padding: 2px 7px; border-radius: var(--r-xs); flex-shrink: 0; }}
.trace-dir-downstream {{ background: rgba(52,211,153,.1); color: #34d399; border: 1px solid rgba(52,211,153,.2); }}
.trace-dir-upstream   {{ background: rgba(248,113,113,.1); color: #f87171; border: 1px solid rgba(248,113,113,.2); }}
.trace-chain {{ font-size: 11px; color: var(--text3); padding: 6px 14px; background: var(--surface2); border-bottom: 1px solid var(--border); font-family: 'SF Mono','Fira Code',Consolas,monospace; overflow-x: auto; white-space: nowrap; }}
.trace-steps {{ padding: 10px 14px; display: none; }}
.trace-steps.open {{ display: block; }}
.trace-step {{
  display: flex; gap: 12px; align-items: flex-start;
  padding: 8px 0; border-bottom: 1px solid var(--border);
  position: relative;
}}
.trace-step:last-child {{ border-bottom: none; }}
.trace-step-left {{ display: flex; flex-direction: column; align-items: center; gap: 3px; width: 28px; flex-shrink: 0; }}
.trace-depth {{ width: 22px; height: 22px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 10px; font-weight: 800; flex-shrink: 0; }}
.trace-connector {{ width: 1px; flex: 1; min-height: 12px; background: var(--border2); }}
.trace-step-body {{ flex: 1; min-width: 0; }}
.trace-step-nodes {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 5px; }}
.trace-node-chip {{
  font-size: 11px; font-weight: 600; padding: 3px 9px;
  border-radius: var(--r-xs); white-space: nowrap;
}}
.trace-edge-arrow {{ color: var(--text3); font-size: 11px; }}
.trace-edge-label {{
  font-size: 10px; color: var(--text3); background: var(--border);
  padding: 1px 6px; border-radius: var(--r-xs); white-space: nowrap;
}}
.trace-evidence {{ font-size: 11px; color: var(--text2); line-height: 1.6; }}

/* ============================================================
   Notice / disclaimer
   ============================================================ */
.notice {{
  background: rgba(63,185,80,.04); border: 1px solid rgba(63,185,80,.12);
  border-radius: var(--r); padding: 12px 16px; font-size: 12px;
  color: var(--text2); margin-top: 16px; line-height: 1.7;
}}

/* ============================================================
   Empty state
   ============================================================ */
.empty-state {{ text-align: center; padding: 40px 20px; color: var(--text3); }}
.empty-icon {{ font-size: 24px; display: block; margin-bottom: 8px; font-weight: 800; color: var(--border2); }}

/* ============================================================
   Scrollbar
   ============================================================ */
::-webkit-scrollbar {{ width: 5px; height: 5px; }}
::-webkit-scrollbar-track {{ background: var(--bg); }}
::-webkit-scrollbar-thumb {{ background: var(--border2); border-radius: 3px; }}

/* ============================================================
   Responsive
   ============================================================ */
@media (max-width: 900px) {{
  .sidebar {{ width: 52px; }}
  .logo-wordmark, .logo-sub, .nav-group-label, .nav-item span:not(.nav-icon), .nav-badge {{ display: none; }}
  .nav-item {{ justify-content: center; padding: 8px; }}
  .main {{ margin-left: 52px; }}
  .content {{ padding: 16px; }}
}}
</style>
</head>
<body>
<div class="layout">

<!-- ============================================================
     Sidebar
     ============================================================ -->
<aside class="sidebar">
  <div class="sidebar-logo">
    <div class="logo-wordmark">Bundle<span class="logo-accent">Spy</span></div>
    <div class="logo-sub">Attack Surface Intelligence</div>
  </div>

  <nav>
    <div class="nav-group">
      <div class="nav-group-label">Report</div>
      <button class="nav-item active" onclick="show('overview',this)">
        <span class="nav-icon">&#9670;</span>Overview
      </button>
      <button class="nav-item" onclick="show('graph',this)">
        <span class="nav-icon">&#9671;</span>Attack Surface
        <span class="nav-badge">{result.graph.stats()["nodes"] if result.graph else 0}</span>
      </button>
      <button class="nav-item" onclick="show('trace',this)">
        <span class="nav-icon">&#8623;</span>Trace Engine
      </button>
    </div>
    <div class="nav-group">
      <div class="nav-group-label">Intelligence</div>
      <button class="nav-item" onclick="show('findings',this)">
        <span class="nav-icon">&#9873;</span>Findings
        <span class="nav-badge {_find_badge_cls}">{len(real)}</span>
      </button>
      <button class="nav-item" onclick="show('endpoints',this)">
        <span class="nav-icon">&#8644;</span>Endpoints
        <span class="nav-badge">{len(result.endpoints)}</span>
      </button>
      <button class="nav-item" onclick="show('assets',this)">
        <span class="nav-icon">&#9633;</span>JS Assets
        <span class="nav-badge">{len(result.js_files)}</span>
      </button>
      <button class="nav-item" onclick="show('vulnlibs',this)">
        <span class="nav-icon">&#9888;</span>Vuln Libraries
        <span class="nav-badge {_lib_badge_cls}">{len(lib_findings)}</span>
      </button>
      <button class="nav-item" onclick="show('infra',this)">
        <span class="nav-icon">&#8853;</span>Infrastructure
        <span class="nav-badge">{len(result.infrastructure)}</span>
      </button>
    </div>
    <div class="nav-group">
      <div class="nav-group-label">Discovery</div>
      {nav_discovery}
    </div>
    <div class="nav-group">
      <div class="nav-group-label">Quality</div>
      <button class="nav-item" onclick="show('coverage',this)">
        <span class="nav-icon">&#9636;</span>Coverage
      </button>
    </div>
  </nav>

  <div class="sidebar-footer">
    BundleSpy v1.0.0<br>
    {gen_time}
  </div>
</aside>

<!-- ============================================================
     Main area
     ============================================================ -->
<div class="main">

  <!-- Topbar -->
  <div class="topbar">
    <div class="topbar-target">
      <div class="topbar-url">{_e(result.target_url)}</div>
      <div class="topbar-meta">
        Started {scan_start} &nbsp;&#183;&nbsp; Duration {dur} &nbsp;&#183;&nbsp; Report generated {gen_time}
      </div>
    </div>
    <div style="flex-shrink:0">
      <span class="risk-badge" style="color:{risk_color};border-color:{risk_color}44;background:{risk_bg}">{risk_level}</span>
    </div>
  </div>

  <div class="content">

    <!-- ========================================================
         OVERVIEW
         ======================================================== -->
    <div id="section-overview" class="section active">
      <div class="section-title">Overview</div>

      <div class="metric-grid">
        <div class="metric-card {'mc-red' if critical else 'mc-grey'}">
          <div class="metric-num">{len(critical)}</div>
          <div class="metric-lbl">Critical</div>
        </div>
        <div class="metric-card {'mc-orange' if high else 'mc-grey'}">
          <div class="metric-num">{len(high)}</div>
          <div class="metric-lbl">High</div>
        </div>
        <div class="metric-card {'mc-yellow' if medium else 'mc-grey'}">
          <div class="metric-num">{len(medium)}</div>
          <div class="metric-lbl">Medium</div>
        </div>
        <div class="metric-card {'mc-blue' if low else 'mc-grey'}">
          <div class="metric-num">{len(low)}</div>
          <div class="metric-lbl">Low</div>
        </div>
        <div class="metric-card mc-purple">
          <div class="metric-num">{len(result.endpoints)}</div>
          <div class="metric-lbl">Endpoints</div>
        </div>
        <div class="metric-card mc-green">
          <div class="metric-num">{len(result.js_files)}</div>
          <div class="metric-lbl">JS Assets</div>
        </div>
        <div class="metric-card {'mc-orange' if lib_findings else 'mc-grey'}">
          <div class="metric-num">{len(lib_findings)}</div>
          <div class="metric-lbl">Vuln Libraries</div>
        </div>
        <div class="metric-card mc-cyan">
          <div class="metric-num">{result.pages_crawled}</div>
          <div class="metric-lbl">Pages Crawled</div>
        </div>
        <div class="metric-card mc-grey">
          <div class="metric-num">{len(result.infrastructure)}</div>
          <div class="metric-lbl">Infra Indicators</div>
        </div>
        {(f'<div class="metric-card mc-grey"><div class="metric-num">{len(subdomains)}</div><div class="metric-lbl">Subdomains</div></div>') if subdomains else ""}
      </div>

      <div class="card">
        <div class="card-header">Scan Details</div>
        <div class="card-body-flush">
          <table class="meta-table">
            <tr><td class="mk">Target</td><td class="mv"><code>{_e(result.target_url)}</code></td></tr>
            <tr><td class="mk">Scan started</td><td class="mv">{scan_start}</td></tr>
            <tr><td class="mk">Scan duration</td><td class="mv">{dur}</td></tr>
            <tr><td class="mk">Report generated</td><td class="mv">{gen_time}</td></tr>
            <tr><td class="mk">Findings</td><td class="mv">{len(real)} confirmed - {len(fps)} excluded (likely false positive)</td></tr>
            <tr><td class="mk">Endpoints</td><td class="mv">{len(result.endpoints)}</td></tr>
            <tr><td class="mk">JS assets</td><td class="mv">{len(result.js_files)}</td></tr>
            <tr><td class="mk">Vuln libraries</td><td class="mv">{len(lib_findings)} CVE(s) found</td></tr>
            <tr><td class="mk">Infrastructure</td><td class="mv">{len(result.infrastructure)} indicator(s)</td></tr>
            {f'<tr><td class="mk">Auth state</td><td class="mv" style="color:{("#34d399" if auth_result.get("authenticated") else "#f87171")};font-weight:700">{("Verified" if auth_result.get("authenticated") else "Not verified")}</td></tr>' if auth_result else ""}
            {f'<tr><td class="mk">Graph</td><td class="mv">{result.graph.stats()["nodes"]} nodes - {result.graph.stats()["edges"]} relationships</td></tr>' if result.graph else ""}
            {f'<tr><td class="mk">Scan errors</td><td class="mv" style="color:var(--red)">{len(result.errors)}</td></tr>' if result.errors else ""}
          </table>
        </div>
      </div>

      <div class="notice">
        This report was produced by automated static and dynamic analysis. All findings are candidates
        and require manual verification. No credentials were validated, no exploitation was performed,
        and no authentication bypass was attempted. This report may contain sensitive information about
        the target application - handle with appropriate confidentiality.
        <strong>For authorized security assessments only.</strong>
      </div>
    </div>

    <!-- ========================================================
         ATTACK SURFACE GRAPH
         ======================================================== -->
    <div id="section-graph" class="section">
      <div class="section-title">
        Attack Surface Graph
        <span class="section-count">
          {g_stats.get("PAGE",0)} pages - {g_stats.get("JS",0) + g_stats.get("CHUNK",0)} assets -
          {g_stats.get("ENDPOINT",0)} endpoints - {g_stats.get("SECRET",0)} secrets
        </span>
      </div>

      <div class="graph-legend">
        {''.join(f'<div class="legend-item"><div class="legend-dot" style="background:{c}"></div>{k.title()}</div>' for k, c in NODE_COLOR.items())}
      </div>

      <div id="graph-wrap">
        <svg id="graph-svg"></svg>
        <div class="graph-controls">
          <button class="graph-ctrl-btn" onclick="gZoomIn()" title="Zoom in">+</button>
          <button class="graph-ctrl-btn" onclick="gZoomOut()" title="Zoom out">-</button>
          <button class="graph-ctrl-btn" onclick="gReset()" title="Reset view">&#8857;</button>
          <button class="graph-ctrl-btn" onclick="gFit()" title="Fit to screen">&#8689;</button>
        </div>
        <div id="node-tt">
          <div class="tt-kind" id="tt-kind"></div>
          <div class="tt-label" id="tt-label"></div>
          <div class="tt-meta" id="tt-meta"></div>
        </div>
        <div id="graph-panel">
          <button class="panel-close" onclick="closePanel()">&#10005;</button>
          <div class="panel-kind" id="panel-kind"></div>
          <div class="panel-label" id="panel-label"></div>
          <div id="panel-body"></div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">How to use the graph</div>
        <div class="card-body">
          <div style="font-size:12px;color:var(--text2);line-height:1.8">
            <strong style="color:var(--text)">Click any node</strong> to see its full details and connected nodes in the side panel.
            <strong style="color:var(--text)">Drag nodes</strong> to reposition them.
            <strong style="color:var(--text)">Scroll</strong> to zoom.
            <strong style="color:var(--text)">Drag the canvas</strong> to pan.
            Node size reflects importance - larger nodes have more connections.
            Use the <strong style="color:var(--text)">Trace Engine</strong> section to explore attack paths step by step.
          </div>
        </div>
      </div>
    </div>

    <!-- ========================================================
         TRACE ENGINE
         ======================================================== -->
    <div id="section-trace" class="section">
      <div class="section-title">
        Trace Engine
        <span class="section-count">attack path analysis</span>
      </div>

      <div class="card" style="margin-bottom:20px">
        <div class="card-body">
          <div style="font-size:12px;color:var(--text2);line-height:1.8;margin-bottom:12px">
            The Trace Engine shows how every entity in the attack surface connects to every other.
            <strong style="color:var(--text)">Upstream traces</strong> show how an attacker can reach a secret or endpoint.
            <strong style="color:var(--text)">Downstream traces</strong> show what a page or JS file exposes.
            Each step includes the relationship type and evidence.
          </div>
          <div class="trace-selector">
            <span class="trace-sel-label">Show:</span>
            <div class="trace-mode-btns">
              <button class="trace-mode-btn active" onclick="setTraceMode('secrets',this)">Secrets upstream</button>
              <button class="trace-mode-btn" onclick="setTraceMode('pages',this)">Pages downstream</button>
              <button class="trace-mode-btn" onclick="setTraceMode('all',this)">All traces</button>
            </div>
          </div>
        </div>
      </div>

      <div class="trace-list" id="trace-list"></div>
    </div>

    <!-- ========================================================
         FINDINGS
         ======================================================== -->
    <div id="section-findings" class="section">
      <div class="section-title">
        Findings
        <span class="section-count">{len(real)} confirmed - {len(fps)} excluded</span>
      </div>
      <div class="filter-row">{sev_filter_btns}</div>
      <div id="findings-list">{_findings_html(findings, extras)}</div>
    </div>

    <!-- ========================================================
         ENDPOINTS
         ======================================================== -->
    <div id="section-endpoints" class="section">
      <div class="section-title">
        Endpoints
        <span class="section-count">{len(result.endpoints)} discovered</span>
      </div>
      {_endpoints_html(result.endpoints)}
    </div>

    <!-- ========================================================
         JS ASSETS
         ======================================================== -->
    <div id="section-assets" class="section">
      <div class="section-title">
        JavaScript Assets
        <span class="section-count">{len(result.js_files)} analyzed</span>
      </div>
      <div class="card">
        <div class="card-body-flush">
          {_js_html(result, extras)}
        </div>
      </div>
    </div>

    <!-- ========================================================
         VULNERABLE LIBRARIES
         ======================================================== -->
    <div id="section-vulnlibs" class="section">
      <div class="section-title">
        Vulnerable Libraries
        <span class="section-count">{len(lib_findings)} CVE(s) in {len(set(f"{lf.library} {lf.version}" for lf in lib_findings))} library/libraries</span>
      </div>
      {_vulnlibs_html(lib_findings)}
    </div>

    <!-- ========================================================
         INFRASTRUCTURE
         ======================================================== -->
    <div id="section-infra" class="section">
      <div class="section-title">
        Infrastructure Indicators
        <span class="section-count">{len(result.infrastructure)} found</span>
      </div>
      <div class="card">
        <div class="card-body-flush">
          {_infra_html(result.infrastructure)}
        </div>
      </div>
    </div>

    <!-- ========================================================
         BROWSER ENGINE
         ======================================================== -->
    <div id="section-headless" class="section">
      <div class="section-title">Browser Engine Discovery</div>
      <div class="card"><div class="card-body">{_headless_html(headless_stats)}</div></div>
    </div>

    <!-- ========================================================
         AUTHENTICATION
         ======================================================== -->
    <div id="section-auth" class="section">
      <div class="section-title">Authentication Verification</div>
      <div class="card"><div class="card-body">{_auth_html(auth_result)}</div></div>
    </div>

    <!-- ========================================================
         SOURCE MAPS
         ======================================================== -->
    <div id="section-sourcemaps" class="section">
      <div class="section-title">Source Map Analysis</div>
      <div class="card"><div class="card-body">{_sourcemap_html(sm_details)}</div></div>
    </div>

    <!-- ========================================================
         GRAPHQL
         ======================================================== -->
    <div id="section-graphql" class="section">
      <div class="section-title">GraphQL Intelligence</div>
      {_graphql_html(graphql_schemas)}
    </div>

    <!-- ========================================================
         ENDPOINT VALIDATION
         ======================================================== -->
    <div id="section-validation" class="section">
      <div class="section-title">Endpoint Validation</div>
      <div class="card"><div class="card-body">{_validation_html(validation_results)}</div></div>
    </div>

    <!-- ========================================================
         SUBDOMAINS
         ======================================================== -->
    <div id="section-subdomains" class="section">
      <div class="section-title">
        Subdomains
        <span class="section-count">{len(subdomains)} harvested</span>
      </div>
      <div class="card"><div class="card-body-flush">{_subdomains_html(subdomains)}</div></div>
    </div>

    <!-- ========================================================
         COVERAGE
         ======================================================== -->
    <div id="section-coverage" class="section">
      <div class="section-title">Coverage &amp; Blind Spots</div>
      {_coverage_html(coverage)}
    </div>

  </div><!-- /content -->
</div><!-- /main -->
</div><!-- /layout -->

<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
<script>
// ============================================================
// Data
// ============================================================
const GRAPH_DATA  = {graph_json};
const TRACE_DATA  = {trace_json};
const NODE_COLOR  = {_j(NODE_COLOR)};
const NODE_ICON   = {_j(NODE_ICON)};

// ============================================================
// Navigation
// ============================================================
function show(id, btn) {{
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  const sec = document.getElementById('section-' + id);
  if (sec) sec.classList.add('active');
  if (btn) btn.classList.add('active');
  if (id === 'graph') initGraph();
  if (id === 'trace') renderTraces('secrets');
}}

// ============================================================
// Findings filter
// ============================================================
function filterFindings(sev, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(c => {{
    c.style.display = (sev === 'ALL' || c.dataset.severity === sev) ? '' : 'none';
  }});
}}

// ============================================================
// Attack Surface Graph (D3)
// ============================================================
let graphInited = false, svgEl, zoomBeh;

function initGraph() {{
  if (graphInited || !GRAPH_DATA) return;
  graphInited = true;

  const container = document.getElementById('graph-wrap');
  const W = container.clientWidth;
  const H = container.clientHeight;
  const nodes = (GRAPH_DATA.nodes || []).map(n => ({{...n}}));
  const edges = (GRAPH_DATA.edges || []).map(e => ({{...e}}));
  const byId  = {{}};
  nodes.forEach(n => byId[n.id] = n);

  const svg = d3.select('#graph-svg');
  svg.selectAll('*').remove();

  // Arrow markers per node type
  const defs = svg.append('defs');
  Object.entries(NODE_COLOR).forEach(([k, c]) => {{
    defs.append('marker')
      .attr('id', 'arr-' + k)
      .attr('viewBox', '0 -4 8 8')
      .attr('refX', 20).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path').attr('d', 'M0,-4L8,0L0,4')
      .attr('fill', c).attr('opacity', 0.5);
  }});

  const root = svg.append('g');
  zoomBeh = d3.zoom().scaleExtent([0.1, 6]).on('zoom', ev => root.attr('transform', ev.transform));
  svg.call(zoomBeh);

  // Node radius by type
  const R = {{ PAGE:15, JS:12, ENDPOINT:11, SECRET:13, WORKER:10, PARAMETER:6, HOST:12, CHUNK:9, SOURCEMAP:8, CONFIG:8 }};
  // Link distance by edge type
  const LD = {{ LOADS:90, IMPORTS:70, CALLS:110, EXPOSES:90, ACCEPTS:55, OBSERVED_ON:120, RELATED_TO:105, HOSTS:130, REFERENCES:100, RECOVERS:80 }};

  const sim = d3.forceSimulation(nodes)
    .force('link',   d3.forceLink(edges).id(d => d.id).distance(e => LD[e.kind] || 100).strength(0.4))
    .force('charge', d3.forceManyBody().strength(-220))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('coll',   d3.forceCollide(d => (R[d.kind] || 10) + 7));

  // Edge lines
  const link = root.append('g').selectAll('line').data(edges).join('line')
    .attr('stroke', e => {{
      const s = byId[e.source.id || e.source];
      return s ? (NODE_COLOR[s.kind] || '#475569') : '#475569';
    }})
    .attr('stroke-opacity', 0.28)
    .attr('stroke-width', 1.2)
    .attr('marker-end', e => {{
      const s = byId[e.source.id || e.source];
      return s ? 'url(#arr-' + s.kind + ')' : '';
    }});

  // Edge labels for important relationships
  const LABEL_KINDS = new Set(['CALLS', 'EXPOSES', 'RELATED_TO', 'HOSTS']);
  const edgeLabel = root.append('g').selectAll('text')
    .data(edges.filter(e => LABEL_KINDS.has(e.kind))).join('text')
    .attr('font-size', 9).attr('fill', '#475569').attr('text-anchor', 'middle').attr('dy', -3)
    .text(e => e.kind.toLowerCase().replace(/_/g, ' '));

  // Node groups
  const nodeG = root.append('g').selectAll('g').data(nodes).join('g')
    .attr('cursor', 'pointer')
    .call(d3.drag()
      .on('start', (ev, d) => {{ if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }})
      .on('drag',  (ev, d) => {{ d.fx = ev.x; d.fy = ev.y; }})
      .on('end',   (ev, d) => {{ if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }}))
    .on('mouseenter', showTooltip)
    .on('mousemove',  moveTooltip)
    .on('mouseleave', hideTooltip)
    .on('click',      showNodePanel);

  // Node circles
  nodeG.append('circle')
    .attr('r', d => R[d.kind] || 10)
    .attr('fill', d => (NODE_COLOR[d.kind] || '#475569') + '22')
    .attr('stroke', d => NODE_COLOR[d.kind] || '#475569')
    .attr('stroke-width', 1.5);

  // Node icons
  nodeG.append('text')
    .attr('text-anchor', 'middle').attr('dominant-baseline', 'central')
    .attr('font-size', d => (NODE_ICON[d.kind] || '').length > 2 ? 7 : 8)
    .attr('font-weight', '800')
    .attr('fill', d => NODE_COLOR[d.kind] || '#475569')
    .text(d => NODE_ICON[d.kind] || '?');

  // Node labels (only for important types)
  const LABELED = new Set(['PAGE', 'SECRET', 'ENDPOINT', 'HOST']);
  nodeG.filter(d => LABELED.has(d.kind)).append('text')
    .attr('text-anchor', 'middle')
    .attr('y', d => (R[d.kind] || 10) + 12)
    .attr('font-size', 9).attr('fill', '#6e7681')
    .text(d => d.label.length > 26 ? d.label.slice(0, 26) + '...' : d.label);

  sim.on('tick', () => {{
    link
      .attr('x1', e => e.source.x).attr('y1', e => e.source.y)
      .attr('x2', e => e.target.x).attr('y2', e => e.target.y);
    edgeLabel
      .attr('x', e => (e.source.x + e.target.x) / 2)
      .attr('y', e => (e.source.y + e.target.y) / 2);
    nodeG.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
  }});

  svgEl = svg;
}}

function showTooltip(ev, d) {{
  const tt  = document.getElementById('node-tt');
  document.getElementById('tt-kind').textContent  = d.kind;
  document.getElementById('tt-label').textContent = d.label;
  const meta = [];
  if (d.data.url)          meta.push(d.data.url);
  if (d.data.method)       meta.push('Method: ' + d.data.method);
  if (d.data.severity)     meta.push('Severity: ' + d.data.severity);
  if (d.data.source_type)  meta.push('Source: ' + d.data.source_type);
  if (d.data.category)     meta.push('Category: ' + d.data.category);
  document.getElementById('tt-meta').textContent = meta.join(' - ');
  tt.style.display = 'block';
  moveTooltip(ev);
}}
function moveTooltip(ev) {{
  const tt  = document.getElementById('node-tt');
  const box = document.getElementById('graph-wrap').getBoundingClientRect();
  let x = ev.clientX - box.left + 14, y = ev.clientY - box.top + 14;
  if (x + 290 > box.width)  x = ev.clientX - box.left - 290;
  if (y + 100 > box.height) y = ev.clientY - box.top  - 100;
  tt.style.left = x + 'px'; tt.style.top = y + 'px';
}}
function hideTooltip() {{ document.getElementById('node-tt').style.display = 'none'; }}

function showNodePanel(ev, d) {{
  ev.stopPropagation();
  const panel = document.getElementById('graph-panel');
  const c = NODE_COLOR[d.kind] || '#8b949e';

  document.getElementById('panel-kind').textContent  = d.kind;
  document.getElementById('panel-kind').style.color  = c;
  document.getElementById('panel-label').textContent = d.label;

  const data = d.data || {{}};
  const props = [];
  if (data.url)            props.push(['URL',      `<code style="font-size:10px;word-break:break-all">${{data.url}}</code>`]);
  if (data.method)         props.push(['Method',   `<span style="background:${{c}}22;color:${{c}};padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700">${{data.method}}</span>`]);
  if (data.category)       props.push(['Category', data.category]);
  if (data.severity)       props.push(['Severity', `<span style="font-weight:700;color:{SEV_COLOR.get('CRITICAL','#f87171')}">${{data.severity}}</span>`]);
  if (data.source_type)    props.push(['Source',   data.source_type]);
  if (d.confidence < 1)    props.push(['Confidence', `${{(d.confidence * 100).toFixed(0)}}%`]);
  if (data.auth_context)   props.push(['Auth',     data.auth_context]);
  if (data.size_bytes)     props.push(['Size',     `${{(data.size_bytes / 1024).toFixed(1)}} KB`]);
  if (data.redacted_value) props.push(['Value',    `<code style="color:#3fb950">${{data.redacted_value}}</code>`]);
  if (data.line_number)    props.push(['Line',     data.line_number]);

  const propHtml = props.map(([k, v]) => `
    <div class="panel-row"><span class="panel-key">${{k}}</span><span class="panel-val">${{v}}</span></div>`).join('');

  // Connected neighbors
  const all  = GRAPH_DATA.edges || [];
  const byId = {{}};
  (GRAPH_DATA.nodes || []).forEach(n => byId[n.id] = n);
  const outE = all.filter(e => e.source === d.id);
  const inE  = all.filter(e => e.target === d.id);
  const nbItems = [
    ...outE.slice(0, 6).map(e => {{ const n = byId[e.target]; return n ? `<div class="nb-item" title="${{e.kind}}">&#8594; ${{n.label}}</div>` : ''; }}),
    ...inE.slice(0, 4).map(e  => {{ const n = byId[e.source]; return n ? `<div class="nb-item" title="${{e.kind}}">&#8592; ${{n.label}}</div>` : ''; }}),
  ].filter(Boolean);

  document.getElementById('panel-body').innerHTML = `
    ${{propHtml ? `<div class="panel-sec">Properties</div>${{propHtml}}` : ''}}
    ${{nbItems.length ? `<div class="panel-sec">Connections (${{outE.length + inE.length}})</div><div class="nb-list">${{nbItems.join('')}}</div>` : ''}}`;

  panel.classList.add('open');
}}
function closePanel() {{ document.getElementById('graph-panel').classList.remove('open'); }}
function gZoomIn()  {{ if (svgEl && zoomBeh) svgEl.transition().call(zoomBeh.scaleBy, 1.4); }}
function gZoomOut() {{ if (svgEl && zoomBeh) svgEl.transition().call(zoomBeh.scaleBy, 0.7); }}
function gReset()   {{ if (svgEl && zoomBeh) svgEl.transition().call(zoomBeh.transform, d3.zoomIdentity); }}
function gFit() {{
  if (!svgEl || !zoomBeh) return;
  const nodes = GRAPH_DATA && GRAPH_DATA.nodes;
  if (!nodes || !nodes.length) return;
  svgEl.transition().call(zoomBeh.transform, d3.zoomIdentity);
}}
document.getElementById('graph-svg').addEventListener('click', () => {{
  document.getElementById('graph-panel').classList.remove('open');
}});

// ============================================================
// Trace Engine
// ============================================================
let traceMode = 'secrets';

function setTraceMode(mode, btn) {{
  traceMode = mode;
  document.querySelectorAll('.trace-mode-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderTraces(mode);
}}

function renderTraces(mode) {{
  const list = document.getElementById('trace-list');
  if (!list) return;
  if (!TRACE_DATA || !TRACE_DATA.length) {{
    list.innerHTML = '<div class="empty-state"><div class="empty-icon">-</div><p>No trace data available - run a scan with graph output enabled</p></div>';
    return;
  }}

  let traces = TRACE_DATA;
  if (mode === 'secrets')   traces = TRACE_DATA.filter(t => t.direction === 'upstream');
  if (mode === 'pages')     traces = TRACE_DATA.filter(t => t.direction === 'downstream');

  if (!traces.length) {{
    list.innerHTML = '<div class="empty-state"><div class="empty-icon">-</div><p>No traces in this category</p></div>';
    return;
  }}

  list.innerHTML = traces.map((tr, idx) => renderTraceCard(tr, idx)).join('');
}}

function renderTraceCard(tr, idx) {{
  const origin = tr.origin;
  const oc = NODE_COLOR[origin.kind] || '#8b949e';
  const dirCls = tr.direction === 'upstream' ? 'trace-dir-upstream' : 'trace-dir-downstream';
  const dirLabel = tr.direction === 'upstream' ? 'upstream' : 'downstream';

  const stepsHtml = (tr.steps || []).map(step => {{
    const fn = step.from_node;
    const tn = step.to_node;
    const edge = step.edge;
    const fnColor = fn ? (NODE_COLOR[fn.kind] || '#8b949e') : '#8b949e';
    const tnColor = tn ? (NODE_COLOR[tn.kind] || '#8b949e') : '#8b949e';
    const edgeKind = edge ? edge.kind : '';
    return `
<div class="trace-step">
  <div class="trace-step-left">
    <div class="trace-depth" style="background:${{tnColor}}22;color:${{tnColor}};border:1px solid ${{tnColor}}44">${{step.depth}}</div>
    <div class="trace-connector"></div>
  </div>
  <div class="trace-step-body">
    <div class="trace-step-nodes">
      ${{fn ? `<span class="trace-node-chip" style="background:${{fnColor}}18;color:${{fnColor}};border:1px solid ${{fnColor}}33">${{fn.label}}</span>` : ''}}
      ${{fn && tn ? `<span class="trace-edge-arrow">&#8594;</span><span class="trace-edge-label">${{edgeKind}}</span><span class="trace-edge-arrow">&#8594;</span>` : ''}}
      ${{tn ? `<span class="trace-node-chip" style="background:${{tnColor}}18;color:${{tnColor}};border:1px solid ${{tnColor}}33">${{tn.label}}</span>` : ''}}
    </div>
    ${{step.evidence ? `<div class="trace-evidence">${{step.evidence}}</div>` : ''}}
  </div>
</div>`;
  }}).join('');

  const chain = tr.chain || (origin.label + (tr.steps.length ? ' -> ...' : ''));

  return `
<div class="trace-card">
  <div class="trace-card-hdr" onclick="toggleTrace('tr-${{idx}}')">
    <span class="trace-origin-kind" style="background:${{oc}}22;color:${{oc}};border:1px solid ${{oc}}44">${{origin.kind}}</span>
    <span class="trace-origin-label">${{origin.label}}</span>
    <span class="trace-dir-badge ${{dirCls}}">${{dirLabel}}</span>
    <span class="trace-step-count">${{tr.steps.length}} hop${{tr.steps.length !== 1 ? 's' : ''}}</span>
  </div>
  <div class="trace-chain" title="Attack chain">${{chain}}</div>
  <div class="trace-steps" id="tr-${{idx}}">${{stepsHtml}}</div>
</div>`;
}}

function toggleTrace(id) {{
  const el = document.getElementById(id);
  if (el) el.classList.toggle('open');
}}
</script>
</body>
</html>'''
