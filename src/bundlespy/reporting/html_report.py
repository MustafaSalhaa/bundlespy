"""
BundleSpy HTML Report — complete professional intelligence report.
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
    return "—"

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
        return '<div class="empty-state"><span class="empty-icon">✓</span><p>No findings above confidence threshold</p></div>'

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
        pub_note = '<div class="pub-id-note">Public identifier — not a secret credential</div>' if pub else ""
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


def _endpoints_html(endpoints):
    if not endpoints:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No endpoints discovered</p></div>'
    cat_order = ["AUTH","ADMIN","GRAPHQL","API","SERVERLESS","WEBSOCKET","UPLOAD","DOWNLOAD","ROUTE","UNKNOWN"]
    by_cat = {}
    for ep in endpoints:
        by_cat.setdefault(ep.category, []).append(ep)

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
            rows += f"""<tr class="ep-row">
  <td><span class="method-badge method-{mc}">{_e(ep.method)}</span></td>
  <td><code class="ep-url">{_e(ep.url)}</code>{params}{auth}</td>
  <td><span class="src-badge {st_cls}">{st}</span></td>
  <td class="conf-cell">{ep.confidence:.0%}</td>
  <td class="src-file"><code>{_e((ep.source_file or "").split("/")[-1])}</code></td>
</tr>"""
        parts.append(f"""<div class="ep-group">
  <div class="ep-group-header" style="border-left:3px solid {cc}">
    <span class="ep-cat" style="color:{cc}">{_e(cat)}</span>
    <span class="ep-count">{len(by_cat[cat])}</span>
  </div>
  <table class="ep-table">
    <thead><tr><th>Method</th><th>Path / URL</th><th>Source</th><th>Conf.</th><th>File</th></tr></thead>
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
        size = f"{js.size_bytes/1024:.1f} KB" if js.size_bytes >= 1024 else f"{js.size_bytes} B"
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
  <td><code class="hash">{js.sha256[:12] if js.sha256 else "—"}</code></td>
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
  <td class="size-cell">—</td>
  <td style="color:#f87171;font-weight:600">{sec_n}</td>
  <td>—</td><td>—</td><td>—</td>
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


def _auth_html(auth_result):
    if not auth_result:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No credentials supplied — unauthenticated scan</p></div>'
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
        ("Initial URL",          auth_result.get("initial_url", "—")),
        ("HTTP status",          f'<span style="color:{sc};font-weight:600">{status}</span>'),
        ("Final URL",            auth_result.get("final_url", "—")),
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
  <td><span style="color:{sc}">{"✓ Interesting" if getattr(r,"interesting",False) else "—"}</span></td>
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


def _graph_data(result):
    if not result.graph:
        return "null"
    return _j(result.graph.to_dict())


def _intelligence_html(intel) -> str:
    """Render the passive intelligence section from an IntelligenceResult."""
    if not intel:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>Passive intelligence collection was not run</p></div>'

    out = []

    # Technologies detected
    techs = getattr(intel, "technologies", {})
    if techs:
        rows = "".join(
            f'<tr><td class="meta-key">{_e(k)}</td><td class="meta-val"><code>{_e(v)}</code></td></tr>'
            for k, v in techs.items()
        )
        out.append(f"""<div class="card" style="margin-bottom:14px">
  <div class="card-header">Technology Stack <span style="color:var(--text3);font-weight:400;font-size:11px">({len(techs)} detected)</span></div>
  <div class="card-body" style="padding:0"><table class="meta-table">{rows}</table></div>
</div>""")

    # Interesting headers
    interesting = getattr(intel, "interesting_headers", [])
    if interesting:
        rows = "".join(
            f'<tr><td style="padding:6px 14px;border-bottom:1px solid var(--border);color:var(--text2);font-size:12px"><code>{_e(h)}</code></td></tr>'
            for h in interesting
        )
        out.append(f"""<div class="card" style="margin-bottom:14px">
  <div class="card-header">Header Flags <span style="color:var(--text3);font-weight:400;font-size:11px">({len(interesting)} flagged)</span></div>
  <div class="card-body" style="padding:0"><table style="width:100%;border-collapse:collapse">{rows}</table></div>
</div>""")

    # CSP policy
    csp = getattr(intel, "csp_policy", {})
    if csp:
        rows = "".join(
            f'<tr><td class="meta-key" style="font-family:monospace">{_e(d)}</td>'
            f'<td class="meta-val" style="word-break:break-all">{_e(" ".join(vals))}</td></tr>'
            for d, vals in csp.items()
        )
        out.append(f"""<div class="card" style="margin-bottom:14px">
  <div class="card-header">Content Security Policy <span style="color:var(--text3);font-weight:400;font-size:11px">({len(csp)} directives)</span></div>
  <div class="card-body" style="padding:0"><table class="meta-table">{rows}</table></div>
</div>""")

    # Sitemap URLs discovered
    sitemap_urls = getattr(intel, "sitemap_urls", [])
    if sitemap_urls:
        rows = "".join(
            f'<tr><td style="padding:5px 14px;border-bottom:1px solid var(--border);font-size:11px"><code>{_e(u)}</code></td></tr>'
            for u in sitemap_urls[:200]
        )
        more = f'<tr><td style="padding:5px 14px;color:var(--text3);font-size:11px">… and {len(sitemap_urls)-200} more</td></tr>' if len(sitemap_urls) > 200 else ""
        out.append(f"""<div class="card" style="margin-bottom:14px">
  <div class="card-header">Sitemap URLs <span style="color:var(--text3);font-weight:400;font-size:11px">({len(sitemap_urls)} discovered)</span></div>
  <div class="card-body" style="padding:0"><table style="width:100%;border-collapse:collapse">{rows}{more}</table></div>
</div>""")

    # OpenID / OIDC config
    oidc = getattr(intel, "openid_config", None)
    if oidc and isinstance(oidc, dict):
        rows = "".join(
            f'<tr><td class="meta-key">{_e(str(k))}</td><td class="meta-val"><code style="word-break:break-all">{_e(str(v))}</code></td></tr>'
            for k, v in list(oidc.items())[:20]
        )
        out.append(f"""<div class="card" style="margin-bottom:14px">
  <div class="card-header">OpenID Configuration</div>
  <div class="card-body" style="padding:0"><table class="meta-table">{rows}</table></div>
</div>""")

    # API schema found
    api_schema = getattr(intel, "api_schema", None)
    if api_schema:
        schema_url  = api_schema.get("url", "")
        schema_type = api_schema.get("type", "unknown")
        schema_data = api_schema.get("schema", {})
        paths_count = len(schema_data.get("paths", {})) if isinstance(schema_data, dict) else 0
        out.append(f"""<div class="card" style="margin-bottom:14px">
  <div class="card-header">API Schema Discovered</div>
  <div class="card-body" style="padding:0"><table class="meta-table">
    <tr><td class="meta-key">Type</td><td class="meta-val">{_e(schema_type.upper())}</td></tr>
    <tr><td class="meta-key">URL</td><td class="meta-val"><code>{_e(schema_url)}</code></td></tr>
    {f'<tr><td class="meta-key">Paths</td><td class="meta-val">{paths_count} endpoint paths defined</td></tr>' if paths_count else ''}
  </table></div>
</div>""")

    # Security.txt
    sec_txt = getattr(intel, "security_txt", None)
    if sec_txt:
        out.append(f"""<div class="card" style="margin-bottom:14px">
  <div class="card-header">security.txt</div>
  <div class="card-body"><pre style="font-size:11px;color:var(--text2);white-space:pre-wrap;word-break:break-word">{_e(sec_txt[:2000])}</pre></div>
</div>""")

    # API endpoints from JSON responses
    api_endpoints = getattr(intel, "api_endpoints", [])
    if api_endpoints:
        rows = "".join(
            f'<tr><td style="padding:5px 14px;border-bottom:1px solid var(--border);font-size:11px"><code>{_e(ep)}</code></td></tr>'
            for ep in api_endpoints[:100]
        )
        out.append(f"""<div class="card" style="margin-bottom:14px">
  <div class="card-header">API Endpoints from JSON Responses <span style="color:var(--text3);font-weight:400;font-size:11px">({len(api_endpoints)} found)</span></div>
  <div class="card-body" style="padding:0"><table style="width:100%;border-collapse:collapse">{rows}</table></div>
</div>""")

    # Collection errors
    errors = getattr(intel, "errors", [])
    if errors:
        rows = "".join(
            f'<tr><td style="padding:5px 14px;border-bottom:1px solid var(--border);font-size:11px;color:var(--text3)">{_e(e)}</td></tr>'
            for e in errors[:20]
        )
        out.append(f"""<div class="card" style="margin-bottom:14px">
  <div class="card-header" style="color:var(--text3)">Collection Errors ({len(errors)})</div>
  <div class="card-body" style="padding:0"><table style="width:100%;border-collapse:collapse">{rows}</table></div>
</div>""")

    if not out:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No passive intelligence gathered from this target</p></div>'

    return "\n".join(out)


# ── Main generator ────────────────────────────────────────────────────────────

def generate(
    result: ScanResult,
    show_sensitive: bool = False,
    extras: dict = None,
    validation_results: list = None,
    graphql_schemas: list = None,
    subdomains: list = None,
    report_paths: dict = None,
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
    coverage        = extras.get("coverage",          None)
    sm_details      = extras.get("source_map_details",{})
    passive_stats   = extras.get("passive_stats",     {})
    chunk_stats     = extras.get("chunk_stats",       {})
    attack_surface  = extras.get("attack_surface",    {})
    intelligence    = extras.get("intelligence",      None)
    cache_stats     = extras.get("cache_stats",       {})

    gen_time   = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    scan_start = result.started_at.strftime("%Y-%m-%d %H:%M UTC") if result.started_at else "—"
    dur        = _duration(result)
    graph_json = _graph_data(result)
    g_stats    = result.graph.stats().get("by_type", {}) if result.graph else {}

    # Pre-compute filter buttons (Python 3.10: no backslash in f-string expressions)
    _q = "'"  # single quote helper — backslash not allowed in f-string on Python 3.10
    _btn_crit   = (f'<button class="filter-btn" data-sev="CRITICAL" onclick="filterFindings({_q}CRITICAL{_q},this)">Critical ({len(critical)})</button>' if critical else "")
    _btn_high   = (f'<button class="filter-btn" data-sev="HIGH" onclick="filterFindings({_q}HIGH{_q},this)">High ({len(high)})</button>' if high else "")
    _btn_med    = (f'<button class="filter-btn" data-sev="MEDIUM" onclick="filterFindings({_q}MEDIUM{_q},this)">Medium ({len(medium)})</button>' if medium else "")
    _btn_low    = (f'<button class="filter-btn" data-sev="LOW" onclick="filterFindings({_q}LOW{_q},this)">Low ({len(low)})</button>' if low else "")
    _btn_info   = (f'<button class="filter-btn" data-sev="INFO" onclick="filterFindings({_q}INFO{_q},this)">Info ({len(info_f)})</button>' if info_f else "")
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
    _sm_used       = bool(sm_details and sm_details.get("discovered"))
    _gql_used      = bool(graphql_schemas)
    _val_used      = bool(validation_results)
    _subs_used     = bool(subdomains)
    _passive_used  = bool(passive_stats)
    _intel_used    = bool(intelligence)

    _so, _sc = "'", "'"  # quote helpers for onclick JS strings
    _nav_headless = ('<button class="nav-item" onclick="show(' + _so + 'headless' + _sc + ')"><span class="nav-icon">⬕</span>Browser Engine</button>' if _headless_used else '')
    _nav_auth     = ('<button class="nav-item" onclick="show(' + _so + 'auth' + _sc + ')"><span class="nav-icon">◉</span>Authentication</button>' if _auth_used else '')
    _nav_srcmaps  = '<button class="nav-item" onclick="show(' + _so + 'sourcemaps' + _sc + ')"><span class="nav-icon">⎔</span>Source Maps</button>'
    _nav_graphql  = ('<button class="nav-item" onclick="show(' + _so + 'graphql' + _sc + ')"><span class="nav-icon">⬡</span>GraphQL</button>' if _gql_used else '')
    _nav_val      = ('<button class="nav-item" onclick="show(' + _so + 'validation' + _sc + ')"><span class="nav-icon">◎</span>Validation</button>' if _val_used else '')
    _nav_subs     = ('<button class="nav-item" onclick="show(' + _so + 'subdomains' + _sc + ')"><span class="nav-icon">⊕</span>Subdomains<span class="nav-badge">' + str(len(subdomains)) + '</span></button>' if _subs_used else '')
    _intel_techs  = len(getattr(intelligence, "technologies", {})) if intelligence else 0
    _intel_flags  = len(getattr(intelligence, "interesting_headers", [])) if intelligence else 0
    _intel_badge  = f'<span class="nav-badge orange">{_intel_flags}</span>' if _intel_flags else (f'<span class="nav-badge">{_intel_techs}</span>' if _intel_techs else '')
    _nav_intel    = ('<button class="nav-item" onclick="show(' + _so + 'intelligence' + _sc + ')"><span class="nav-icon">◐</span>Recon' + _intel_badge + '</button>' if _intel_used else '')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BundleSpy Report — {_e(result.target_url)}</title>
<style>
:root{{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#21262d;--border2:#30363d;
  --text:#e6edf3;--text2:#8b949e;--text3:#6e7681;
  --accent:#58a6ff;--green:#3fb950;--red:#f85149;--orange:#f0883e;
  --yellow:#e3b341;--purple:#bc8cff;--cyan:#39d0d8;
  --radius:8px;--radius-sm:4px;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Inter',sans-serif;
  background:var(--bg);color:var(--text);font-size:13px;line-height:1.6;min-height:100vh}}
/* ── Layout ── */
.layout{{display:flex;min-height:100vh}}
.sidebar{{width:230px;background:var(--surface);border-right:1px solid var(--border);
  position:fixed;top:0;left:0;height:100vh;overflow-y:auto;z-index:100;display:flex;flex-direction:column}}
.main{{margin-left:230px;flex:1;display:flex;flex-direction:column}}
.topbar{{background:var(--surface);border-bottom:1px solid var(--border);
  padding:14px 28px;display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;z-index:50;gap:16px}}
.content{{padding:24px 28px;max-width:1320px}}
/* ── Sidebar ── */
.sidebar-logo{{padding:18px 16px 12px;border-bottom:1px solid var(--border)}}
.logo-mark{{font-size:15px;font-weight:700;letter-spacing:-0.5px}}
.logo-mark span{{color:var(--accent)}}
.logo-sub{{font-size:10px;color:var(--text3);margin-top:2px;text-transform:uppercase;letter-spacing:0.6px}}
.nav-group{{padding:12px 10px 6px}}
.nav-label{{font-size:10px;font-weight:600;color:var(--text3);text-transform:uppercase;
  letter-spacing:0.8px;padding:0 6px;margin-bottom:5px}}
.nav-item{{display:flex;align-items:center;gap:7px;padding:6px 10px;
  border-radius:var(--radius-sm);color:var(--text2);text-decoration:none;
  font-size:12px;cursor:pointer;transition:all .15s;border:none;
  background:none;width:100%;text-align:left}}
.nav-item:hover{{background:rgba(88,166,255,.08);color:var(--text)}}
.nav-item.active{{background:rgba(88,166,255,.12);color:var(--accent)}}
.nav-icon{{width:15px;text-align:center;flex-shrink:0;font-size:13px;opacity:.7}}
.nav-badge{{margin-left:auto;background:var(--border2);color:var(--text2);
  font-size:10px;padding:1px 6px;border-radius:10px;font-weight:500}}
.nav-badge.red{{background:#3d1515;color:#f87171}}
.nav-badge.orange{{background:#3d2215;color:#fb923c}}
.sidebar-footer{{margin-top:auto;padding:12px 14px;border-top:1px solid var(--border);font-size:10px;color:var(--text3)}}
/* ── Topbar ── */
.topbar-target{{display:flex;flex-direction:column;gap:1px;min-width:0}}
.topbar-url{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:13px;color:var(--accent);font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.topbar-meta{{font-size:11px;color:var(--text3)}}
.scan-badge{{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:0.3px;white-space:nowrap}}
.critical-badge{{color:var(--red);border:1px solid #3d1515;background:#1a0808}}
.high-badge{{color:var(--orange);border:1px solid #3d2215;background:#1a0d08}}
.clean-badge{{color:var(--green);border:1px solid #1a3a1a;background:#081a08}}
/* ── Sections ── */
.section{{display:none}}.section.active{{display:block}}
.section-title{{font-size:16px;font-weight:600;margin-bottom:18px;display:flex;align-items:center;gap:10px}}
.section-title .count{{font-size:12px;color:var(--text3);font-weight:400}}
.subsection-title{{font-size:12px;font-weight:600;color:var(--text2);text-transform:uppercase;
  letter-spacing:0.5px;margin-bottom:10px;margin-top:16px}}
/* ── Cards ── */
.card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;margin-bottom:16px}}
.card-header{{padding:11px 16px;border-bottom:1px solid var(--border);font-weight:600;font-size:13px;display:flex;align-items:center;justify-content:space-between}}
.card-body{{padding:16px}}
/* ── Metric cards ── */
.overview-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin-bottom:18px}}
.metric-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;position:relative;overflow:hidden}}
.metric-card::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px}}
.metric-card.c-red::before{{background:var(--red)}}.metric-card.c-orange::before{{background:var(--orange)}}
.metric-card.c-yellow::before{{background:var(--yellow)}}.metric-card.c-blue::before{{background:var(--accent)}}
.metric-card.c-green::before{{background:var(--green)}}.metric-card.c-grey::before{{background:var(--text3)}}
.metric-card.c-purple::before{{background:var(--purple)}}.metric-card.c-cyan::before{{background:var(--cyan)}}
.metric-num{{font-size:28px;font-weight:700;line-height:1;margin-bottom:3px}}
.metric-card.c-red .metric-num{{color:var(--red)}}.metric-card.c-orange .metric-num{{color:var(--orange)}}
.metric-card.c-yellow .metric-num{{color:var(--yellow)}}.metric-card.c-blue .metric-num{{color:var(--accent)}}
.metric-card.c-green .metric-num{{color:var(--green)}}.metric-card.c-grey .metric-num{{color:var(--text2)}}
.metric-card.c-purple .metric-num{{color:var(--purple)}}.metric-card.c-cyan .metric-num{{color:var(--cyan)}}
.metric-lbl{{font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;font-weight:500}}
/* ── Meta table ── */
.meta-table{{width:100%;border-collapse:collapse}}
.meta-table td{{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top}}
.meta-table tr:last-child td{{border-bottom:none}}
.meta-key{{color:var(--text3);font-size:11px;text-transform:uppercase;letter-spacing:0.4px;font-weight:500;width:170px;white-space:nowrap}}
.meta-val{{color:var(--text);font-size:12px}}
/* ── Findings ── */
.findings-filter{{display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap}}
.filter-btn{{padding:4px 12px;border-radius:20px;border:1px solid var(--border2);
  background:none;color:var(--text2);font-size:11px;cursor:pointer;transition:all .15s;font-family:inherit}}
.filter-btn:hover,.filter-btn.active{{border-color:var(--accent);color:var(--accent);background:rgba(88,166,255,.08)}}
.filter-btn[data-sev="CRITICAL"].active{{border-color:var(--red);color:var(--red);background:rgba(248,81,73,.08)}}
.filter-btn[data-sev="HIGH"].active{{border-color:var(--orange);color:var(--orange);background:rgba(240,136,62,.08)}}
.filter-btn[data-sev="MEDIUM"].active{{border-color:var(--yellow);color:var(--yellow);background:rgba(227,179,65,.08)}}
.finding-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:10px;overflow:hidden}}
.finding-card:hover{{border-color:var(--border2)}}
.finding-top{{display:flex;align-items:center;justify-content:space-between;padding:11px 14px;gap:10px;flex-wrap:wrap}}
.finding-left{{display:flex;align-items:center;gap:8px;flex:1;min-width:0}}
.finding-name{{font-weight:600;font-size:13px}}
.rule-id{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:10px;color:var(--text3);background:var(--border);padding:1px 5px;border-radius:3px}}
.finding-right{{display:flex;align-items:center;gap:8px}}
.sev-pill{{font-size:10px;font-weight:700;padding:2px 7px;border-radius:10px;letter-spacing:0.4px;white-space:nowrap}}
.status-pill{{font-size:10px;padding:2px 6px;border-radius:3px;font-weight:500}}
.status-likely-secret{{background:#3a2a10;color:#fbbf24}}
.status-candidate{{background:#3a2010;color:#fb923c}}
.status-validated{{background:#1a3a1a;color:#3fb950;font-weight:700}}
.status-likely-false-positive{{background:var(--border);color:var(--text3)}}
.conf-bar{{width:55px;height:3px;background:var(--border2);border-radius:2px;overflow:hidden}}
.conf-fill{{height:100%;border-radius:2px}}
.conf-label{{font-size:10px;color:var(--text3);width:28px;text-align:right}}
.finding-body{{padding:12px 14px;border-top:1px solid var(--border)}}
.finding-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px;margin-bottom:10px}}
.fg-key{{font-size:10px;text-transform:uppercase;letter-spacing:0.4px;color:var(--text3);font-weight:500;margin-bottom:2px}}
.fg-val{{font-size:11px}}
code{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:11px;background:var(--border);padding:2px 5px;border-radius:3px;word-break:break-all}}
.evidence-block{{background:#0a0d13;border:1px solid var(--border);border-radius:var(--radius-sm);padding:9px 12px;margin-bottom:8px}}
.evidence-label{{font-size:10px;text-transform:uppercase;letter-spacing:0.4px;color:var(--text3);margin-bottom:5px;font-weight:500}}
.evidence-val{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:12px;color:#3fb950;background:none;padding:0;word-break:break-all}}
.context-val{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:11px;color:var(--text2);background:none;padding:0;display:block;white-space:pre-wrap;word-break:break-all;max-height:72px;overflow:hidden}}
.finding-desc{{font-size:12px;color:var(--text2);margin-bottom:7px}}
.remediation-block{{font-size:12px;color:var(--text2);padding:7px 11px;background:rgba(63,185,80,.06);border-left:2px solid var(--green);border-radius:0 var(--radius-sm) var(--radius-sm) 0;margin-bottom:6px}}
.rem-label{{font-weight:600;color:var(--green)}}
.fp-note{{font-size:11px;color:var(--text3);background:rgba(255,255,255,.03);padding:5px 8px;border-radius:3px;margin-top:5px}}
.finding-occ{{font-size:11px;color:var(--text3);margin-top:6px}}
.pub-id-note{{font-size:11px;color:var(--cyan);background:rgba(57,208,216,.06);border:1px solid rgba(57,208,216,.2);border-radius:3px;padding:4px 8px;margin-bottom:6px}}
/* ── Endpoints ── */
.ep-group{{margin-bottom:18px}}
.ep-group-header{{display:flex;align-items:center;justify-content:space-between;padding:7px 12px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius) var(--radius) 0 0}}
.ep-cat{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.4px}}
.ep-count{{font-size:11px;color:var(--text3)}}
.ep-table{{width:100%;border-collapse:collapse;border:1px solid var(--border);border-top:none;border-radius:0 0 var(--radius) var(--radius);overflow:hidden}}
.ep-table th{{background:#0a0d13;padding:6px 11px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:0.4px;color:var(--text3);font-weight:600;border-bottom:1px solid var(--border)}}
.ep-table td{{padding:7px 11px;border-bottom:1px solid var(--border);vertical-align:middle}}
.ep-table tr:last-child td{{border-bottom:none}}
.ep-table tr:hover td{{background:rgba(88,166,255,.03)}}
.ep-url{{font-size:11px;word-break:break-all}}
.method-badge{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:10px;font-weight:700;padding:2px 6px;border-radius:3px;letter-spacing:0.2px;display:inline-block;white-space:nowrap}}
.method-get{{background:#1a3a1a;color:#3fb950}}.method-post{{background:#3a1a1a;color:#f85149}}
.method-put{{background:#3a2a1a;color:#f0883e}}.method-delete{{background:#3a1a2a;color:#f87171}}
.method-patch{{background:#2a1a3a;color:#bc8cff}}.method-ws{{background:#1a2a3a;color:#39d0d8}}
.method-head{{background:#2a2a1a;color:#e3b341}}.method-unknown{{background:var(--border);color:var(--text3)}}
.param-tag{{font-size:10px;color:var(--purple);background:rgba(188,140,255,.1);border:1px solid rgba(188,140,255,.2);padding:1px 5px;border-radius:3px;margin-left:6px}}
.query-param{{color:#39d0d8;background:rgba(57,208,216,.08);border-color:rgba(57,208,216,.2)}}
.body-param{{color:#f0883e;background:rgba(240,136,62,.08);border-color:rgba(240,136,62,.2)}}
.auth-tag{{font-size:10px;color:#39d0d8;background:rgba(57,208,216,.1);border:1px solid rgba(57,208,216,.2);padding:1px 5px;border-radius:3px;margin-left:4px}}
.src-badge{{font-size:10px;padding:2px 6px;border-radius:3px;font-weight:500}}
.src-static{{background:#1a3a1a;color:#3fb950}}.src-runtime{{background:#1a2a3a;color:#60a5fa}}
.src-correlated{{background:#2a1a3a;color:#bc8cff}}.src-browser{{background:#1a2a3a;color:#39d0d8}}
.conf-cell{{font-size:11px;color:var(--text3);white-space:nowrap}}
.src-file{{max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
/* ── JS assets ── */
.js-url{{font-size:11px;word-break:break-all}}
.tech-tag{{font-size:10px;background:rgba(63,185,80,.1);color:#3fb950;border:1px solid rgba(63,185,80,.2);padding:1px 5px;border-radius:3px;margin-left:6px}}
.sm-tag{{font-size:10px;background:rgba(88,166,255,.1);color:#58a6ff;border:1px solid rgba(88,166,255,.2);padding:1px 5px;border-radius:3px;margin-left:4px}}
.hash{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:10px;color:var(--text3)}}
.size-cell{{color:var(--text3);font-size:11px;white-space:nowrap}}
/* ── Vulnerable libraries ── */
.vuln-lib-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:14px;overflow:hidden}}
.vuln-lib-header{{padding:11px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}}
.vuln-lib-name{{font-weight:700;font-size:14px}}
.vuln-lib-meta{{display:flex;align-items:center;gap:8px}}
.version-badge{{background:rgba(227,179,65,.1);color:#e3b341;border:1px solid rgba(227,179,65,.3);font-size:11px;padding:2px 7px;border-radius:10px;font-weight:600}}
.lib-file{{font-size:11px;color:var(--text3)}}
.cve-count{{font-size:11px;color:var(--text3)}}
.vuln-table{{width:100%;border-collapse:collapse;font-size:12px}}
.vuln-table th{{background:#0a0d13;padding:7px 14px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:0.4px;color:var(--text3);font-weight:600;border-bottom:1px solid var(--border)}}
.vuln-table td{{padding:9px 14px;border-bottom:1px solid var(--border);vertical-align:top}}
.vuln-table tr:last-child td{{border-bottom:none}}
.cve-id{{font-size:11px}}
.cve-desc{{color:var(--text2)}}
.cve-fix{{color:var(--text3);font-size:11px}}
/* ── Infrastructure ── */
.cls-badge{{font-size:11px;font-weight:600}}
.action-report_only{{color:var(--yellow)}}.action-report only{{color:var(--yellow)}}
.action-investigate{{color:var(--red);font-weight:600}}
/* ── Coverage ── */
.cov-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin-bottom:16px}}
.cov-card{{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px}}
.cov-card-title{{font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:10px}}
.cov-row{{display:flex;align-items:center;gap:10px;margin-bottom:6px}}
.cov-label{{font-size:11px;color:var(--text2);width:60px;text-align:right;flex-shrink:0}}
.cov-bar-wrap{{flex:1;height:6px;background:var(--border2);border-radius:3px;overflow:hidden}}
.cov-bar-fill{{height:100%;border-radius:3px;transition:width .4s}}
.cov-pct{{font-size:11px;color:var(--text2);width:32px;font-weight:600}}
.cov-detail{{font-size:10px;color:var(--text3);margin-top:4px}}
.blind-spots-section{{margin-top:16px}}
.blind-spot{{padding:10px 14px;margin-bottom:8px;background:var(--surface);border-radius:var(--radius-sm);border-bottom:1px solid var(--border)}}
.blind-spot-header{{display:flex;align-items:center;gap:8px;margin-bottom:4px}}
.blind-spot-title{{font-size:12px;font-weight:600}}
.blind-spot-desc{{font-size:12px;color:var(--text2);margin-bottom:3px}}
.blind-spot-rec{{font-size:11px;color:var(--text3);font-style:italic}}
/* ── Auth ── */
.auth-warn{{background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.2);border-radius:var(--radius-sm);padding:8px 12px;font-size:12px;color:#f87171;margin-bottom:12px}}
/* ── Two-col layout ── */
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
@media(max-width:700px){{.two-col{{grid-template-columns:1fr}}}}
/* ── Source maps ── */
.sm-summary{{font-size:12px;color:var(--text2);margin-bottom:10px;padding:8px 12px;background:var(--surface2);border-radius:var(--radius-sm)}}
/* ── Validation ── */
.val-summary{{font-size:12px;color:var(--text2);margin-bottom:10px}}
/* ── GraphQL ── */
.gql-schema{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:12px;overflow:hidden}}
.gql-header{{padding:10px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}}
.gql-counts{{font-size:11px;color:var(--text3)}}
.gql-type{{font-size:10px;color:#a78bfa;font-weight:600}}
.gql-type.mutation{{color:#f87171}}.gql-type.subscription{{color:#39d0d8}}
.gql-error{{color:var(--red);font-size:12px;padding:8px;background:rgba(248,81,73,.06);border-radius:3px;margin-bottom:8px}}
/* ── Data table ── */
.data-table{{width:100%;border-collapse:collapse;font-size:12px}}
.data-table th{{background:#0a0d13;padding:7px 11px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:0.4px;color:var(--text3);font-weight:600;border-bottom:1px solid var(--border)}}
.data-table td{{padding:8px 11px;border-bottom:1px solid var(--border);vertical-align:top}}
.data-table tr:last-child td{{border-bottom:none}}
.data-table tr:hover td{{background:rgba(255,255,255,.015)}}
/* ── Graph ── */
#graph-container{{width:100%;height:600px;background:#0a0d13;border:1px solid var(--border);border-radius:var(--radius);position:relative;overflow:hidden}}
#graph-svg{{width:100%;height:100%}}
.graph-controls{{position:absolute;top:12px;right:12px;display:flex;flex-direction:column;gap:5px}}
.graph-btn{{background:var(--surface);border:1px solid var(--border);color:var(--text2);width:28px;height:28px;border-radius:var(--radius-sm);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:13px;transition:all .15s}}
.graph-btn:hover{{border-color:var(--accent);color:var(--accent)}}
.graph-legend{{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}}
.legend-item{{display:flex;align-items:center;gap:4px;font-size:11px;color:var(--text3)}}
.legend-dot{{width:9px;height:9px;border-radius:50%;flex-shrink:0}}
.node-tooltip{{position:absolute;background:var(--surface);border:1px solid var(--border2);border-radius:var(--radius);padding:10px 12px;font-size:11px;pointer-events:none;z-index:200;max-width:260px;box-shadow:0 8px 24px rgba(0,0,0,.5);display:none}}
.tt-kind{{font-size:9px;text-transform:uppercase;letter-spacing:0.6px;color:var(--text3);margin-bottom:3px;font-weight:600}}
.tt-label{{font-weight:600;color:var(--text);margin-bottom:5px;word-break:break-all}}
.tt-meta{{font-size:10px;color:var(--text2)}}
.graph-detail-panel{{position:absolute;right:0;top:0;bottom:0;width:270px;background:var(--surface);border-left:1px solid var(--border);padding:14px;overflow-y:auto;transform:translateX(100%);transition:transform .25s;z-index:50}}
.graph-detail-panel.open{{transform:translateX(0)}}
.detail-close{{position:absolute;top:8px;right:8px;background:none;border:none;color:var(--text3);cursor:pointer;font-size:15px;padding:4px}}
.detail-kind{{font-size:10px;text-transform:uppercase;letter-spacing:0.7px;color:var(--text3);font-weight:600;margin-bottom:5px}}
.detail-label{{font-size:13px;font-weight:600;margin-bottom:12px;word-break:break-all}}
.detail-sec-title{{font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:var(--text3);font-weight:600;margin:10px 0 5px;border-bottom:1px solid var(--border);padding-bottom:3px}}
.detail-row{{display:flex;justify-content:space-between;gap:8px;margin-bottom:4px;font-size:11px}}
.detail-key{{color:var(--text3);flex-shrink:0}}
.detail-val{{color:var(--text);text-align:right;word-break:break-all}}
.detail-chip{{display:inline-block;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:600}}
.neighbor-list{{display:flex;flex-direction:column;gap:3px}}
.neighbor-item{{font-size:11px;color:var(--text2);padding:4px 7px;background:var(--bg);border-radius:3px;cursor:pointer;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.neighbor-item:hover{{color:var(--accent)}}
/* ── Notice ── */
.notice{{background:rgba(63,185,80,.05);border:1px solid rgba(63,185,80,.15);border-radius:var(--radius);padding:10px 14px;font-size:12px;color:var(--text2);margin-top:14px;line-height:1.7}}
/* ── Empty ── */
.empty-state{{text-align:center;padding:36px 20px;color:var(--text3)}}
.empty-icon{{font-size:26px;display:block;margin-bottom:7px}}
/* ── Scrollbar ── */
::-webkit-scrollbar{{width:5px;height:5px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--border2);border-radius:3px}}
</style>
</head>
<body>
<div class="layout">
<aside class="sidebar">
  <div class="sidebar-logo">
    <div class="logo-mark">Bundle<span>Spy</span></div>
    <div class="logo-sub">Attack Surface Intelligence</div>
  </div>
  <nav>
    <div class="nav-group">
      <div class="nav-label">Report</div>
      <button class="nav-item active" onclick="show('overview')"><span class="nav-icon">◈</span>Overview</button>
      <button class="nav-item" onclick="show('graph')"><span class="nav-icon">⬡</span>Attack Surface</button>
    </div>
    <div class="nav-group">
      <div class="nav-label">Intelligence</div>
      <button class="nav-item" onclick="show('findings')"><span class="nav-icon">⚑</span>Findings<span class="nav-badge {_find_badge_cls}">{len(real)}</span></button>
      <button class="nav-item" onclick="show('endpoints')"><span class="nav-icon">⇄</span>Endpoints<span class="nav-badge">{len(result.endpoints)}</span></button>
      <button class="nav-item" onclick="show('assets')"><span class="nav-icon">◻</span>JS Assets<span class="nav-badge">{len(result.js_files)}</span></button>
      <button class="nav-item" onclick="show('vulnlibs')"><span class="nav-icon">⚠</span>Vuln Libraries<span class="nav-badge {_lib_badge_cls}">{len(lib_findings)}</span></button>
      <button class="nav-item" onclick="show('infra')"><span class="nav-icon">⌖</span>Infrastructure<span class="nav-badge">{len(result.infrastructure)}</span></button>
    </div>
    <div class="nav-group">
      <div class="nav-label">Discovery</div>
      {_nav_intel}
      {_nav_headless}
      {_nav_auth}
      {_nav_srcmaps}
      {_nav_graphql}
      {_nav_val}
      {_nav_subs}
    </div>
    <div class="nav-group">
      <div class="nav-label">Quality</div>
      <button class="nav-item" onclick="show('coverage')"><span class="nav-icon">▤</span>Coverage</button>
    </div>
  </nav>
  <div class="sidebar-footer">BundleSpy v1.0.0</div>
</aside>

<div class="main">
  <div class="topbar">
    <div class="topbar-target">
      <div class="topbar-url">{_e(result.target_url)}</div>
      <div class="topbar-meta">Started {scan_start} &nbsp;·&nbsp; Duration {dur} &nbsp;·&nbsp; Report generated {gen_time}</div>
    </div>
    <div style="display:flex;gap:8px;flex-shrink:0">{_sev_badge}</div>
  </div>

  <div class="content">

    <!-- OVERVIEW -->
    <div id="section-overview" class="section active">
      <div class="section-title">Overview</div>
      <div class="overview-grid">
        <div class="metric-card {'c-red' if critical else 'c-grey'}"><div class="metric-num">{len(critical)}</div><div class="metric-lbl">Critical</div></div>
        <div class="metric-card {'c-orange' if high else 'c-grey'}"><div class="metric-num">{len(high)}</div><div class="metric-lbl">High</div></div>
        <div class="metric-card {'c-yellow' if medium else 'c-grey'}"><div class="metric-num">{len(medium)}</div><div class="metric-lbl">Medium</div></div>
        <div class="metric-card {'c-blue' if low else 'c-grey'}"><div class="metric-num">{len(low)}</div><div class="metric-lbl">Low</div></div>
        <div class="metric-card c-purple"><div class="metric-num">{len(result.endpoints)}</div><div class="metric-lbl">Endpoints</div></div>
        <div class="metric-card c-green"><div class="metric-num">{len(result.js_files)}</div><div class="metric-lbl">JS Assets</div></div>
        <div class="metric-card {'c-orange' if lib_findings else 'c-grey'}"><div class="metric-num">{len(lib_findings)}</div><div class="metric-lbl">Vuln Libraries</div></div>
        <div class="metric-card c-cyan"><div class="metric-num">{result.pages_crawled}</div><div class="metric-lbl">Pages Crawled</div></div>
        <div class="metric-card c-grey"><div class="metric-num">{len(result.infrastructure)}</div><div class="metric-lbl">Infra Indicators</div></div>
        {'<div class="metric-card c-grey"><div class="metric-num">'+str(len(subdomains))+'</div><div class="metric-lbl">Subdomains</div></div>' if subdomains else ''}
      </div>
      <div class="card">
        <div class="card-header">Scan Details</div>
        <div class="card-body" style="padding:0">
          <table class="meta-table">
            <tr><td class="meta-key">Target</td><td class="meta-val"><code>{_e(result.target_url)}</code></td></tr>
            <tr><td class="meta-key">Scan started</td><td class="meta-val">{scan_start}</td></tr>
            <tr><td class="meta-key">Scan duration</td><td class="meta-val">{dur}</td></tr>
            <tr><td class="meta-key">Report generated</td><td class="meta-val">{gen_time}</td></tr>
            <tr><td class="meta-key">Findings</td><td class="meta-val">{len(real)} confirmed · {len(fps)} excluded (likely false positive)</td></tr>
            <tr><td class="meta-key">Endpoints</td><td class="meta-val">{len(result.endpoints)}</td></tr>
            <tr><td class="meta-key">JS assets</td><td class="meta-val">{len(result.js_files)}</td></tr>
            <tr><td class="meta-key">Vuln libraries</td><td class="meta-val">{len(lib_findings)} CVE(s) found</td></tr>
            <tr><td class="meta-key">Infrastructure</td><td class="meta-val">{len(result.infrastructure)} indicator(s)</td></tr>
            {f'<tr><td class="meta-key">Auth state</td><td class="meta-val" style="color:{("#34d399" if auth_result.get("authenticated") else "#f87171")}">{("Verified" if auth_result.get("authenticated") else "Not verified")}</td></tr>' if auth_result else ''}
            {f'<tr><td class="meta-key">Graph</td><td class="meta-val">{result.graph.stats()["nodes"]} nodes · {result.graph.stats()["edges"]} relationships</td></tr>' if result.graph else ''}
            {f'<tr><td class="meta-key">Recon</td><td class="meta-val">{_intel_techs} tech detected · {len(getattr(intelligence,"sitemap_urls",[]))} sitemap URLs · {_intel_flags} header flags</td></tr>' if intelligence else ''}
            {f'<tr><td class="meta-key">HTTP cache</td><td class="meta-val">{cache_stats["hits"]} hits · {cache_stats["revalidated"]} revalidated · {cache_stats["misses"]} misses · <span style="color:var(--green)">{cache_stats["saved_bytes"]/1_048_576:.1f} MB saved</span></td></tr>' if cache_stats.get("hits",0)+cache_stats.get("revalidated",0) > 0 else ''}
            {f'<tr><td class="meta-key">Scan errors</td><td class="meta-val" style="color:var(--red)">{len(result.errors)}</td></tr>' if result.errors else ''}
          </table>
        </div>
      </div>
      <div class="notice">
        This report was produced by automated analysis. All findings are candidates and require manual verification.
        No credentials were validated, no authentication was attempted, and no exploitation was performed.
        Handle with appropriate confidentiality. For authorized security assessments only.
      </div>
    </div>

    <!-- ATTACK SURFACE GRAPH -->
    <div id="section-graph" class="section">
      <div class="section-title">Attack Surface Graph
        <span class="count">{g_stats.get("PAGE",0)} pages · {g_stats.get("JS",0)+g_stats.get("CHUNK",0)} assets · {g_stats.get("ENDPOINT",0)} endpoints · {g_stats.get("SECRET",0)} secrets</span>
      </div>
      <div class="graph-legend">
        {''.join(f'<div class="legend-item"><div class="legend-dot" style="background:{c}"></div>{k.title()}</div>' for k,c in NODE_COLOR.items())}
      </div>
      <div id="graph-container">
        <svg id="graph-svg"></svg>
        <div class="graph-controls">
          <button class="graph-btn" onclick="gZoomIn()" title="Zoom in">+</button>
          <button class="graph-btn" onclick="gZoomOut()" title="Zoom out">−</button>
          <button class="graph-btn" onclick="gReset()" title="Reset">⊙</button>
        </div>
        <div class="node-tooltip" id="node-tooltip">
          <div class="tt-kind" id="tt-kind"></div>
          <div class="tt-label" id="tt-label"></div>
          <div class="tt-meta" id="tt-meta"></div>
        </div>
        <div class="graph-detail-panel" id="detail-panel">
          <button class="detail-close" onclick="closeDetail()">✕</button>
          <div class="detail-kind" id="dp-kind"></div>
          <div class="detail-label" id="dp-label"></div>
          <div id="dp-body"></div>
        </div>
      </div>
    </div>

    <!-- FINDINGS -->
    <div id="section-findings" class="section">
      <div class="section-title">Findings <span class="count">{len(real)} confirmed · {len(fps)} excluded</span></div>
      <div class="findings-filter">
        <button class="filter-btn active" data-sev="ALL" onclick="filterF('ALL',this)">All ({len(real)})</button>
        {_btn_crit}{_btn_high}{_btn_med}{_btn_low}{_btn_info}
      </div>
      <div id="findings-list">{_findings_html(findings, extras)}</div>
    </div>

    <!-- ENDPOINTS -->
    <div id="section-endpoints" class="section">
      <div class="section-title">Endpoints <span class="count">{len(result.endpoints)} discovered</span></div>
      {_endpoints_html(result.endpoints)}
    </div>

    <!-- JS ASSETS -->
    <div id="section-assets" class="section">
      <div class="section-title">JavaScript Assets <span class="count">{len(result.js_files)} analyzed</span></div>
      <div class="card"><div class="card-body" style="padding:0">{_js_html(result, extras)}</div></div>
    </div>

    <!-- VULNERABLE LIBRARIES -->
    <div id="section-vulnlibs" class="section">
      <div class="section-title">Vulnerable Libraries <span class="count">{len(lib_findings)} CVE(s) in {len(set(f"{lf.library} {lf.version}" for lf in lib_findings))} library/libraries</span></div>
      {_vulnlibs_html(lib_findings)}
    </div>

    <!-- INFRASTRUCTURE -->
    <div id="section-infra" class="section">
      <div class="section-title">Infrastructure Indicators <span class="count">{len(result.infrastructure)} found</span></div>
      <div class="card"><div class="card-body" style="padding:0">{_infra_html(result.infrastructure)}</div></div>
    </div>

    <!-- BROWSER ENGINE -->
    <div id="section-headless" class="section">
      <div class="section-title">Browser Engine Discovery</div>
      <div class="card"><div class="card-body">{_headless_html(headless_stats)}</div></div>
    </div>

    <!-- AUTHENTICATION -->
    <div id="section-auth" class="section">
      <div class="section-title">Authentication Verification</div>
      <div class="card"><div class="card-body">{_auth_html(auth_result)}</div></div>
    </div>

    <!-- SOURCE MAPS -->
    <div id="section-sourcemaps" class="section">
      <div class="section-title">Source Map Analysis</div>
      <div class="card"><div class="card-body">{_sourcemap_html(sm_details)}</div></div>
    </div>

    <!-- GRAPHQL -->
    <div id="section-graphql" class="section">
      <div class="section-title">GraphQL Intelligence</div>
      {_graphql_html(graphql_schemas)}
    </div>

    <!-- ENDPOINT VALIDATION -->
    <div id="section-validation" class="section">
      <div class="section-title">Endpoint Validation</div>
      <div class="card"><div class="card-body">{_validation_html(validation_results)}</div></div>
    </div>

    <!-- SUBDOMAINS -->
    <div id="section-subdomains" class="section">
      <div class="section-title">Subdomains <span class="count">{len(subdomains)} harvested</span></div>
      <div class="card"><div class="card-body" style="padding:0">{_subdomains_html(subdomains)}</div></div>
    </div>

    <!-- PASSIVE INTELLIGENCE / RECON -->
    <div id="section-intelligence" class="section">
      <div class="section-title">Passive Recon
        <span class="count">{_intel_techs} tech · {len(getattr(intelligence,"sitemap_urls",[]))} sitemap URLs · {_intel_flags} header flags</span>
      </div>
      {_intelligence_html(intelligence)}
    </div>

    <!-- COVERAGE -->
    <div id="section-coverage" class="section">
      <div class="section-title">Coverage &amp; Blind Spots</div>
      {_coverage_html(coverage)}
    </div>

  </div>
</div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
<script>
const GRAPH_DATA = {graph_json};
const NC = {_j(NODE_COLOR)};

// ── Navigation ────────────────────────────────────────────────────────────────
function show(id) {{
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  document.getElementById('section-' + id).classList.add('active');
  event.currentTarget.classList.add('active');
  if (id === 'graph') initGraph();
}}

// ── Findings filter ───────────────────────────────────────────────────────────
function filterF(sev, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(c => {{
    c.style.display = (sev === 'ALL' || c.dataset.severity === sev) ? '' : 'none';
  }});
}}

// ── Graph ─────────────────────────────────────────────────────────────────────
let gInit = false, gSvg, gZoom;

function initGraph() {{
  if (gInit || !GRAPH_DATA) return;
  gInit = true;
  const box = document.getElementById('graph-container');
  const W = box.clientWidth, H = box.clientHeight;
  const nodes = (GRAPH_DATA.nodes || []).map(n => ({{...n}}));
  const edges = (GRAPH_DATA.edges || []).map(e => ({{...e}}));
  const byId = {{}};
  nodes.forEach(n => byId[n.id] = n);

  const svg = d3.select('#graph-svg');
  svg.selectAll('*').remove();

  const defs = svg.append('defs');
  Object.entries(NC).forEach(([k, c]) => {{
    defs.append('marker').attr('id','arr-'+k).attr('viewBox','0 -4 8 8')
      .attr('refX',18).attr('refY',0).attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
      .append('path').attr('d','M0,-4L8,0L0,4').attr('fill',c).attr('opacity',.5);
  }});

  const g = svg.append('g');
  gZoom = d3.zoom().scaleExtent([.15,5]).on('zoom', e => g.attr('transform', e.transform));
  svg.call(gZoom);

  const R = {{PAGE:14,JS:12,ENDPOINT:10,SECRET:12,WORKER:10,PARAMETER:6,HOST:11,CHUNK:9,SOURCEMAP:8,CONFIG:8}};
  const LD = {{LOADS:90,IMPORTS:70,CALLS:110,EXPOSES:90,ACCEPTS:50,OBSERVED_ON:120,RELATED_TO:100,HOSTS:130}};

  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(edges).id(d=>d.id).distance(e=>LD[e.kind]||100).strength(.4))
    .force('charge', d3.forceManyBody().strength(-200))
    .force('center', d3.forceCenter(W/2, H/2))
    .force('col', d3.forceCollide(d=>(R[d.kind]||10)+6));

  const link = g.append('g').selectAll('line').data(edges).join('line')
    .attr('stroke', e => {{ const s = byId[e.source.id||e.source]; return s ? (NC[s.kind]||'#475569') : '#475569'; }})
    .attr('stroke-opacity',.3).attr('stroke-width',1.2)
    .attr('marker-end', e => {{ const s = byId[e.source.id||e.source]; return s ? 'url(#arr-'+s.kind+')' : ''; }});

  const SHOW = new Set(['CALLS','EXPOSES','RELATED_TO']);
  const eLabel = g.append('g').selectAll('text').data(edges.filter(e=>SHOW.has(e.kind))).join('text')
    .attr('font-size',9).attr('fill','#475569').attr('text-anchor','middle').attr('dy',-3)
    .text(e => e.kind.toLowerCase().replace('_',' '));

  const node = g.append('g').selectAll('g').data(nodes).join('g').attr('cursor','pointer')
    .call(d3.drag()
      .on('start',(ev,d)=>{{ if(!ev.active) sim.alphaTarget(.3).restart(); d.fx=d.x;d.fy=d.y; }})
      .on('drag', (ev,d)=>{{ d.fx=ev.x;d.fy=ev.y; }})
      .on('end',  (ev,d)=>{{ if(!ev.active) sim.alphaTarget(0); d.fx=null;d.fy=null; }}))
    .on('mouseenter', showTT).on('mousemove', moveTT).on('mouseleave', hideTT)
    .on('click', showDetail);

  node.append('circle').attr('r', d=>R[d.kind]||10)
    .attr('fill', d=>(NC[d.kind]||'#475569')+'22')
    .attr('stroke', d=>NC[d.kind]||'#475569').attr('stroke-width',1.5);

  const ICONS={{PAGE:'P',JS:'JS',ENDPOINT:'EP',SECRET:'S',WORKER:'W',PARAMETER:'p',HOST:'H',CHUNK:'C',SOURCEMAP:'M',CONFIG:'Cf'}};
  node.append('text').attr('text-anchor','middle').attr('dominant-baseline','central')
    .attr('font-size', d=>d.kind==='JS'?7:8).attr('font-weight','700')
    .attr('fill', d=>NC[d.kind]||'#475569').text(d=>ICONS[d.kind]||'?');

  const LABELED = new Set(['PAGE','SECRET','ENDPOINT']);
  node.filter(d=>LABELED.has(d.kind)).append('text')
    .attr('text-anchor','middle').attr('y', d=>(R[d.kind]||10)+11)
    .attr('font-size',9).attr('fill','#6e7681')
    .text(d=>d.label.length>24?d.label.slice(0,24)+'…':d.label);

  sim.on('tick', ()=>{{
    link.attr('x1',e=>e.source.x).attr('y1',e=>e.source.y).attr('x2',e=>e.target.x).attr('y2',e=>e.target.y);
    eLabel.attr('x',e=>(e.source.x+e.target.x)/2).attr('y',e=>(e.source.y+e.target.y)/2);
    node.attr('transform',d=>`translate(${{d.x}},${{d.y}})`);
  }});
  gSvg = svg;
}}

function showTT(ev,d) {{
  const tt = document.getElementById('node-tooltip');
  document.getElementById('tt-kind').textContent = d.kind;
  document.getElementById('tt-label').textContent = d.label;
  const m = [];
  if(d.data.url)      m.push(d.data.url);
  if(d.data.method)   m.push('Method: '+d.data.method);
  if(d.data.severity) m.push('Severity: '+d.data.severity);
  if(d.data.source_type) m.push('Source: '+d.data.source_type);
  document.getElementById('tt-meta').textContent = m.join(' · ');
  tt.style.display = 'block';
  moveTT(ev);
}}
function moveTT(ev) {{
  const tt = document.getElementById('node-tooltip');
  const b  = document.getElementById('graph-container').getBoundingClientRect();
  let x = ev.clientX-b.left+12, y = ev.clientY-b.top+12;
  if(x+270>b.width)  x = ev.clientX-b.left-270;
  if(y+90>b.height)  y = ev.clientY-b.top-90;
  tt.style.left=x+'px'; tt.style.top=y+'px';
}}
function hideTT() {{ document.getElementById('node-tooltip').style.display='none'; }}

function showDetail(ev,d) {{
  ev.stopPropagation();
  const panel = document.getElementById('detail-panel');
  const c = NC[d.kind]||'#8b949e';
  document.getElementById('dp-kind').textContent = d.kind;
  document.getElementById('dp-kind').style.color = c;
  document.getElementById('dp-label').textContent = d.label;
  const data = d.data||{{}};
  const rows = [];
  if(data.url)           rows.push(['URL',`<code style="font-size:10px;word-break:break-all">${{data.url}}</code>`]);
  if(data.method)        rows.push(['Method',`<span class="detail-chip" style="background:${{c}}22;color:${{c}}">${{data.method}}</span>`]);
  if(data.category)      rows.push(['Category',data.category]);
  if(data.severity)      rows.push(['Severity',data.severity]);
  if(data.source_type)   rows.push(['Source',data.source_type]);
  if(d.confidence<1)     rows.push(['Confidence',`${{(d.confidence*100).toFixed(0)}}%`]);
  if(data.auth_context)  rows.push(['Auth',data.auth_context]);
  if(data.size_bytes)    rows.push(['Size',`${{(data.size_bytes/1024).toFixed(1)}} KB`]);
  if(data.redacted_value) rows.push(['Value',`<code style="color:#3fb950">${{data.redacted_value}}</code>`]);
  if(data.line_number)   rows.push(['Line',data.line_number]);
  const rHtml = rows.map(([k,v])=>`<div class="detail-row"><span class="detail-key">${{k}}</span><span class="detail-val">${{v}}</span></div>`).join('');
  const allEdges = GRAPH_DATA.edges||[];
  const byId = {{}};
  (GRAPH_DATA.nodes||[]).forEach(n=>byId[n.id]=n);
  const out = allEdges.filter(e=>e.source===d.id);
  const inn = allEdges.filter(e=>e.target===d.id);
  const nItems = [...out.slice(0,6).map(e=>{{ const n=byId[e.target]; return n?`<div class="neighbor-item" title="${{e.kind}}">→ ${{n.label}}</div>`:''; }}),
                  ...inn.slice(0,4).map(e=>{{ const n=byId[e.source]; return n?`<div class="neighbor-item" title="${{e.kind}}">← ${{n.label}}</div>`:''; }})]
    .filter(Boolean);
  document.getElementById('dp-body').innerHTML = `
    <div class="detail-sec-title">Properties</div>
    ${{rHtml||'<span style="color:var(--text3);font-size:11px">—</span>'}}
    ${{nItems.length?`<div class="detail-sec-title">Connected (${{out.length+inn.length}})</div><div class="neighbor-list">${{nItems.join('')}}</div>`:''}}`;
  panel.classList.add('open');
}}
function closeDetail() {{ document.getElementById('detail-panel').classList.remove('open'); }}
function gZoomIn()  {{ if(gSvg&&gZoom) gSvg.transition().call(gZoom.scaleBy,1.4); }}
function gZoomOut() {{ if(gSvg&&gZoom) gSvg.transition().call(gZoom.scaleBy,.7); }}
function gReset()   {{ if(gSvg&&gZoom) gSvg.transition().call(gZoom.transform,d3.zoomIdentity); }}
document.getElementById('graph-svg').addEventListener('click',()=>document.getElementById('detail-panel').classList.remove('open'));
</script>
</body>
</html>"""
