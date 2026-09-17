"""
BundleSpy HTML Report
═══════════════════════════════════════════════════════════════════════════════
Standalone, self-contained single-file report.
No external dependencies — works offline, safe to share.
"""

import html
import json
from datetime import datetime
from typing import List, Optional
from ..storage.models import ScanResult, Finding, Endpoint, InfrastructureItem


# ── Helpers ───────────────────────────────────────────────────────────────────

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

SEV_COLOR = {
    "CRITICAL": "#f87171", "HIGH": "#fb923c",
    "MEDIUM":   "#fbbf24", "LOW": "#60a5fa", "INFO": "#94a3b8",
}
SEV_DARK = {
    "CRITICAL": "#7f1d1d", "HIGH": "#7c2d12",
    "MEDIUM":   "#713f12", "LOW": "#1e3a5f",  "INFO": "#1e293b",
}
CAT_COLOR = {
    "AUTH": "#a78bfa", "ADMIN": "#f87171", "API": "#34d399",
    "GRAPHQL": "#c084fc", "SERVERLESS": "#fbbf24", "WEBSOCKET": "#22d3ee",
    "UPLOAD": "#fb923c", "DOWNLOAD": "#60a5fa", "ROUTE": "#94a3b8",
    "UNKNOWN": "#475569",
}
NODE_COLOR = {
    "PAGE":      "#60a5fa", "JS":        "#34d399", "ENDPOINT":  "#a78bfa",
    "SECRET":    "#f87171", "WORKER":    "#fbbf24", "PARAMETER": "#94a3b8",
    "HOST":      "#fb923c", "CHUNK":     "#22d3ee", "SOURCEMAP": "#86efac",
    "CONFIG":    "#c084fc",
}


# ── Section builders ──────────────────────────────────────────────────────────

def _findings_html(findings: List[Finding]) -> str:
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    real = sorted(
        [f for f in findings if f.status != "likely_false_positive"],
        key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99,
    )
    if not real:
        return '<div class="empty-state"><span class="empty-icon">✓</span><p>No findings above confidence threshold</p></div>'

    rows = []
    for f in real:
        sc  = SEV_COLOR.get(f.severity, "#94a3b8")
        occ = ""
        if f.occurrences and len(f.occurrences) > 1:
            occ = f'<div class="finding-occ">Also observed in {len(f.occurrences)-1} other location(s)</div>'
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
    </div>
  </div>
  <div class="finding-body">
    <div class="finding-grid">
      <div class="fg-item"><div class="fg-key">Location</div><code class="fg-val">{_e(f.file_url)}:{f.line_number}</code></div>
      <div class="fg-item"><div class="fg-key">Source Page</div><code class="fg-val">{_e(f.source_page)}</code></div>
      <div class="fg-item"><div class="fg-key">Category</div><span class="fg-val">{_e(f.category)}</span></div>
      <div class="fg-item"><div class="fg-key">Status</div><span class="fg-val status-{_e(f.status)}">{_e(f.status.replace("_"," ").title())}</span></div>
    </div>
    <div class="evidence-block">
      <div class="evidence-label">Evidence</div>
      <code class="evidence-val">{_e(f.redacted_value)}</code>
    </div>
    {'<div class="evidence-block"><div class="evidence-label">Context</div><code class="context-val">'+_e(f.context[:300])+'</code></div>' if f.context else ''}
    <div class="finding-desc">{_e(f.description)}</div>
    <div class="remediation-block"><span class="rem-label">Remediation</span> {_e(f.remediation)}</div>
    {occ}
  </div>
</div>""")
    return "\n".join(rows)


def _endpoints_html(endpoints: List[Endpoint]) -> str:
    if not endpoints:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No endpoints discovered</p></div>'
    by_cat: dict = {}
    for ep in endpoints:
        by_cat.setdefault(ep.category, []).append(ep)

    html_parts = []
    for cat in sorted(by_cat, key=lambda c: ["AUTH","ADMIN","GRAPHQL","API","SERVERLESS","WEBSOCKET","UPLOAD","DOWNLOAD","ROUTE","UNKNOWN"].index(c) if c in ["AUTH","ADMIN","GRAPHQL","API","SERVERLESS","WEBSOCKET","UPLOAD","DOWNLOAD","ROUTE","UNKNOWN"] else 99):
        cc = CAT_COLOR.get(cat, "#475569")
        eps_html = ""
        for ep in by_cat[cat]:
            method_cls = ep.method.lower() if ep.method in ("GET","POST","PUT","DELETE","PATCH","WS") else "unknown"
            params = ""
            if ep.path_params:
                names = [p.get("name","?") if isinstance(p,dict) else str(p) for p in ep.path_params]
                params = f'<span class="param-tag">path: {", ".join(_e(n) for n in names)}</span>'
            if ep.query_params:
                names = [p.get("name","?") if isinstance(p,dict) else str(p) for p in ep.query_params]
                params += f'<span class="param-tag">query: {", ".join(_e(n) for n in names)}</span>'
            auth = f'<span class="auth-tag">{_e(ep.auth_context)}</span>' if ep.auth_context else ""
            src_type = getattr(ep, "source_type", "static")
            src_badge = f'<span class="src-badge src-{src_type}">{src_type}</span>'
            conf_pct = f'{ep.confidence:.0%}'
            eps_html += f"""
<tr class="ep-row">
  <td><span class="method-badge method-{method_cls}">{_e(ep.method)}</span></td>
  <td><code class="ep-url">{_e(ep.url)}</code>{params}{auth}</td>
  <td>{src_badge}</td>
  <td class="conf-cell">{conf_pct}</td>
  <td class="src-file"><code>{_e((ep.source_file or "").split("/")[-1])}</code></td>
</tr>"""
        html_parts.append(f"""
<div class="ep-group">
  <div class="ep-group-header" style="border-left:3px solid {cc}">
    <span class="ep-cat" style="color:{cc}">{_e(cat)}</span>
    <span class="ep-count">{len(by_cat[cat])}</span>
  </div>
  <table class="ep-table">
    <thead><tr><th>Method</th><th>Path / URL</th><th>Source</th><th>Conf.</th><th>File</th></tr></thead>
    <tbody>{eps_html}</tbody>
  </table>
</div>""")
    return "\n".join(html_parts)


def _js_html(result: ScanResult) -> str:
    if not result.js_files:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No JavaScript assets discovered</p></div>'
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
            import re
            num = re.search(r"script-(\d+)", frag)
            n = num.group(1) if num else "?"
            import urllib.parse
            p = urllib.parse.urlparse(bare)
            label = f"script {n} @ {p.netloc}{p.path or '/'}"
        size = f"{js.size_bytes/1024:.1f} KB" if js.size_bytes >= 1024 else f"{js.size_bytes} B"
        rows.append(f"""
<tr>
  <td><span class="src-badge" style="background:{st_color}22;color:{st_color};border:1px solid {st_color}44">{st}</span></td>
  <td><code class="js-url">{_e(label)}</code>{tech}{sm}</td>
  <td class="size-cell">{size}</td>
  <td><code class="hash">{js.sha256[:12] if js.sha256 else "—"}</code></td>
</tr>""")
    return f"""<table class="data-table">
<thead><tr><th>Type</th><th>Asset</th><th>Size</th><th>SHA-256</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>"""


def _infra_html(items: List[InfrastructureItem]) -> str:
    if not items:
        return '<div class="empty-state"><span class="empty-icon">○</span><p>No infrastructure indicators found</p></div>'
    rows = []
    for item in items[:200]:
        color = {"PRIVATE_IP":"#f87171","CLOUD_METADATA":"#f87171","INTERNAL_HOSTNAME":"#fb923c"}.get(item.classification,"#fbbf24")
        rows.append(f"""
<tr>
  <td><span class="cls-badge" style="color:{color}">{_e(item.classification)}</span></td>
  <td><code>{_e(item.value)}</code></td>
  <td><code>{_e(item.source_file.split("/")[-1])}</code></td>
  <td>{item.line_number}</td>
  <td><span class="action-{item.action}">{_e(item.action)}</span></td>
</tr>""")
    return f"""<table class="data-table">
<thead><tr><th>Classification</th><th>Value</th><th>Source</th><th>Line</th><th>Action</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>"""


def _graph_data(result: ScanResult) -> str:
    if not result.graph:
        return "null"
    return _j(result.graph.to_dict())


# ── Main generator ────────────────────────────────────────────────────────────

def generate(result: ScanResult, show_sensitive: bool = False) -> str:
    findings    = result.findings
    real        = [f for f in findings if f.status != "likely_false_positive"]
    fps         = [f for f in findings if f.status == "likely_false_positive"]
    critical    = [f for f in real if f.severity == "CRITICAL"]
    high        = [f for f in real if f.severity == "HIGH"]
    medium      = [f for f in real if f.severity == "MEDIUM"]
    low         = [f for f in real if f.severity == "LOW"]
    info        = [f for f in real if f.severity == "INFO"]
    gen_time    = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    scan_start  = result.started_at.strftime("%Y-%m-%d %H:%M UTC") if result.started_at else "—"
    dur         = _duration(result)
    graph_json  = _graph_data(result)

    # Graph stats
    g_stats = {}
    if result.graph:
        g_stats = result.graph.stats().get("by_type", {})

    # Pre-compute filter buttons (backslash not allowed in f-string expressions on Python < 3.12)
    _btn_critical = f'<button class="filter-btn" data-sev="CRITICAL" onclick="filterFindings(\'CRITICAL\',this)">Critical ({len(critical)})</button>' if critical else ''
    _btn_high     = f'<button class="filter-btn" data-sev="HIGH" onclick="filterFindings(\'HIGH\',this)">High ({len(high)})</button>' if high else ''
    _btn_medium   = f'<button class="filter-btn" data-sev="MEDIUM" onclick="filterFindings(\'MEDIUM\',this)">Medium ({len(medium)})</button>' if medium else ''
    _btn_low      = f'<button class="filter-btn" data-sev="LOW" onclick="filterFindings(\'LOW\',this)">Low ({len(low)})</button>' if low else ''
    _btn_info     = f'<button class="filter-btn" data-sev="INFO" onclick="filterFindings(\'INFO\',this)">Info ({len(info)})</button>' if info else ''

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BundleSpy — {_e(result.target_url)}</title>
<style>
:root {{
  --bg:       #0d1117;
  --surface:  #161b22;
  --border:   #21262d;
  --border2:  #30363d;
  --text:     #e6edf3;
  --text2:    #8b949e;
  --text3:    #6e7681;
  --accent:   #58a6ff;
  --accent2:  #388bfd;
  --green:    #3fb950;
  --red:      #f85149;
  --orange:   #f0883e;
  --yellow:   #e3b341;
  --purple:   #bc8cff;
  --cyan:     #39d0d8;
  --radius:   8px;
  --radius-sm:4px;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Inter',sans-serif;
  background:var(--bg);color:var(--text);font-size:13px;line-height:1.6;
  min-height:100vh}}

/* ── Layout ── */
.layout{{display:flex;min-height:100vh}}
.sidebar{{width:220px;background:var(--surface);border-right:1px solid var(--border);
  position:fixed;top:0;left:0;height:100vh;overflow-y:auto;z-index:100;
  display:flex;flex-direction:column}}
.main{{margin-left:220px;flex:1;display:flex;flex-direction:column}}
.topbar{{background:var(--surface);border-bottom:1px solid var(--border);
  padding:16px 28px;display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;z-index:50}}
.content{{padding:28px;max-width:1280px}}

/* ── Sidebar ── */
.sidebar-logo{{padding:20px 18px 12px;border-bottom:1px solid var(--border)}}
.logo-mark{{font-size:15px;font-weight:700;letter-spacing:-0.5px;color:var(--text)}}
.logo-mark span{{color:var(--accent)}}
.logo-sub{{font-size:11px;color:var(--text3);margin-top:2px}}
.nav-section{{padding:16px 12px 8px}}
.nav-label{{font-size:10px;font-weight:600;color:var(--text3);text-transform:uppercase;
  letter-spacing:0.8px;padding:0 6px;margin-bottom:6px}}
.nav-item{{display:flex;align-items:center;gap:8px;padding:7px 10px;
  border-radius:var(--radius-sm);color:var(--text2);text-decoration:none;
  font-size:13px;cursor:pointer;transition:all .15s;border:none;
  background:none;width:100%;text-align:left}}
.nav-item:hover{{background:rgba(88,166,255,.08);color:var(--text)}}
.nav-item.active{{background:rgba(88,166,255,.12);color:var(--accent)}}
.nav-item .nav-icon{{width:16px;text-align:center;flex-shrink:0;font-size:14px}}
.nav-badge{{margin-left:auto;background:var(--border2);color:var(--text2);
  font-size:10px;padding:1px 6px;border-radius:10px;font-weight:500}}
.nav-badge.red{{background:#3d1515;color:#f87171}}
.nav-badge.orange{{background:#3d2215;color:#fb923c}}
.sidebar-footer{{margin-top:auto;padding:14px 16px;border-top:1px solid var(--border);
  font-size:11px;color:var(--text3)}}

/* ── Topbar ── */
.topbar-target{{display:flex;flex-direction:column;gap:2px}}
.topbar-url{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:13px;
  color:var(--accent);font-weight:500}}
.topbar-meta{{font-size:11px;color:var(--text3)}}
.topbar-badges{{display:flex;gap:8px;align-items:center}}
.scan-badge{{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;
  letter-spacing:0.3px;border:1px solid}}

/* ── Sections ── */
.section{{display:none}}
.section.active{{display:block}}
.section-title{{font-size:17px;font-weight:600;margin-bottom:20px;
  display:flex;align-items:center;gap:10px;color:var(--text)}}
.section-title .count{{font-size:13px;color:var(--text3);font-weight:400}}

/* ── Cards ── */
.card{{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);overflow:hidden;margin-bottom:16px}}
.card-header{{padding:13px 18px;border-bottom:1px solid var(--border);
  font-weight:600;font-size:13px;display:flex;align-items:center;
  justify-content:space-between;color:var(--text)}}
.card-body{{padding:18px}}

/* ── Overview grid ── */
.overview-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin-bottom:20px}}
.metric-card{{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:18px 20px;position:relative;overflow:hidden}}
.metric-card::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px}}
.metric-card.red::before{{background:var(--red)}}
.metric-card.orange::before{{background:var(--orange)}}
.metric-card.yellow::before{{background:var(--yellow)}}
.metric-card.blue::before{{background:var(--accent)}}
.metric-card.green::before{{background:var(--green)}}
.metric-card.grey::before{{background:var(--text3)}}
.metric-card.purple::before{{background:var(--purple)}}
.metric-card.cyan::before{{background:var(--cyan)}}
.metric-num{{font-size:30px;font-weight:700;line-height:1;margin-bottom:4px}}
.metric-card.red .metric-num{{color:var(--red)}}
.metric-card.orange .metric-num{{color:var(--orange)}}
.metric-card.yellow .metric-num{{color:var(--yellow)}}
.metric-card.blue .metric-num{{color:var(--accent)}}
.metric-card.green .metric-num{{color:var(--green)}}
.metric-card.grey .metric-num{{color:var(--text2)}}
.metric-card.purple .metric-num{{color:var(--purple)}}
.metric-card.cyan .metric-num{{color:var(--cyan)}}
.metric-lbl{{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;font-weight:500}}

/* ── Scan meta table ── */
.meta-table{{width:100%;border-collapse:collapse}}
.meta-table td{{padding:9px 14px;border-bottom:1px solid var(--border);vertical-align:top}}
.meta-table tr:last-child td{{border-bottom:none}}
.meta-key{{color:var(--text3);font-size:11px;text-transform:uppercase;
  letter-spacing:0.5px;font-weight:500;width:160px}}
.meta-val{{color:var(--text);font-size:13px}}
.meta-val code{{font-family:'SF Mono','Fira Code',Consolas,monospace;
  font-size:12px;color:var(--accent)}}

/* ── Findings ── */
.findings-filter{{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}}
.filter-btn{{padding:5px 12px;border-radius:20px;border:1px solid var(--border2);
  background:none;color:var(--text2);font-size:12px;cursor:pointer;
  transition:all .15s;font-family:inherit}}
.filter-btn:hover,.filter-btn.active{{border-color:var(--accent);color:var(--accent);
  background:rgba(88,166,255,.08)}}
.filter-btn[data-sev="CRITICAL"].active{{border-color:var(--red);color:var(--red);background:rgba(248,81,73,.08)}}
.filter-btn[data-sev="HIGH"].active{{border-color:var(--orange);color:var(--orange);background:rgba(240,136,62,.08)}}
.filter-btn[data-sev="MEDIUM"].active{{border-color:var(--yellow);color:var(--yellow);background:rgba(227,179,65,.08)}}
.finding-card{{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);margin-bottom:12px;overflow:hidden;
  transition:border-color .2s}}
.finding-card:hover{{border-color:var(--border2)}}
.finding-top{{display:flex;align-items:center;justify-content:space-between;
  padding:13px 16px;gap:12px;flex-wrap:wrap}}
.finding-left{{display:flex;align-items:center;gap:10px;flex:1;min-width:0}}
.finding-name{{font-weight:600;font-size:13px;color:var(--text)}}
.rule-id{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:11px;
  color:var(--text3);background:var(--border);padding:1px 6px;border-radius:3px}}
.finding-right{{display:flex;align-items:center;gap:8px}}
.sev-pill{{font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;
  letter-spacing:0.5px;white-space:nowrap}}
.conf-bar{{width:60px;height:4px;background:var(--border2);border-radius:2px;overflow:hidden}}
.conf-fill{{height:100%;border-radius:2px;transition:width .3s}}
.conf-label{{font-size:11px;color:var(--text3);width:30px;text-align:right}}
.finding-body{{padding:14px 16px;border-top:1px solid var(--border)}}
.finding-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));
  gap:10px;margin-bottom:12px}}
.fg-item{{}}
.fg-key{{font-size:10px;text-transform:uppercase;letter-spacing:0.5px;
  color:var(--text3);font-weight:500;margin-bottom:3px}}
.fg-val{{font-size:12px;color:var(--text)}}
code{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:11px;
  background:var(--border);padding:2px 5px;border-radius:3px;word-break:break-all}}
.evidence-block{{background:#0d1117;border:1px solid var(--border);
  border-radius:var(--radius-sm);padding:10px 14px;margin-bottom:10px}}
.evidence-label{{font-size:10px;text-transform:uppercase;letter-spacing:0.5px;
  color:var(--text3);margin-bottom:6px;font-weight:500}}
.evidence-val{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:12px;
  color:#3fb950;background:none;padding:0;word-break:break-all}}
.context-val{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:11px;
  color:var(--text2);background:none;padding:0;display:block;
  white-space:pre-wrap;word-break:break-all;max-height:80px;overflow:hidden}}
.finding-desc{{font-size:12px;color:var(--text2);margin-bottom:8px}}
.remediation-block{{font-size:12px;color:var(--text2);padding:8px 12px;
  background:rgba(63,185,80,.06);border-left:2px solid var(--green);
  border-radius:0 var(--radius-sm) var(--radius-sm) 0}}
.rem-label{{font-weight:600;color:var(--green)}}
.finding-occ{{font-size:11px;color:var(--text3);margin-top:8px}}
.status-likely-secret{{color:#fbbf24}}
.status-candidate{{color:#fb923c}}
.status-validated{{color:#3fb950;font-weight:600}}

/* ── Endpoints ── */
.ep-group{{margin-bottom:20px}}
.ep-group-header{{display:flex;align-items:center;justify-content:space-between;
  padding:8px 14px;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius) var(--radius) 0 0;margin-bottom:0}}
.ep-cat{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px}}
.ep-count{{font-size:11px;color:var(--text3)}}
.ep-table{{width:100%;border-collapse:collapse;
  border:1px solid var(--border);border-top:none;
  border-radius:0 0 var(--radius) var(--radius);overflow:hidden}}
.ep-table th{{background:#0d1117;padding:7px 12px;text-align:left;
  font-size:10px;text-transform:uppercase;letter-spacing:0.5px;
  color:var(--text3);font-weight:600;border-bottom:1px solid var(--border)}}
.ep-table td{{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:middle}}
.ep-table tr:last-child td{{border-bottom:none}}
.ep-table tr:hover td{{background:rgba(88,166,255,.03)}}
.ep-url{{font-size:12px;word-break:break-all}}
.method-badge{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:10px;
  font-weight:700;padding:2px 6px;border-radius:3px;letter-spacing:0.3px;display:inline-block}}
.method-get{{background:#1a3a1a;color:#3fb950}}
.method-post{{background:#3a1a1a;color:#f85149}}
.method-put{{background:#3a2a1a;color:#f0883e}}
.method-delete{{background:#3a1a2a;color:#f87171}}
.method-patch{{background:#2a1a3a;color:#bc8cff}}
.method-ws{{background:#1a2a3a;color:#39d0d8}}
.method-unknown{{background:var(--border);color:var(--text3)}}
.param-tag{{font-size:10px;color:var(--purple);background:rgba(188,140,255,.1);
  border:1px solid rgba(188,140,255,.2);padding:1px 6px;border-radius:3px;
  margin-left:8px}}
.auth-tag{{font-size:10px;color:#39d0d8;background:rgba(57,208,216,.1);
  border:1px solid rgba(57,208,216,.2);padding:1px 6px;border-radius:3px;
  margin-left:4px}}
.src-badge{{font-size:10px;padding:2px 6px;border-radius:3px;font-weight:500}}
.src-static{{background:#1a3a1a;color:#3fb950}}
.src-runtime{{background:#1a2a3a;color:#60a5fa}}
.src-correlated{{background:#2a1a3a;color:#bc8cff}}
.src-browser{{background:#1a2a3a;color:#39d0d8}}
.conf-cell{{font-size:11px;color:var(--text3)}}
.src-file{{max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}

/* ── JS inventory ── */
.js-url{{font-size:12px;word-break:break-all}}
.tech-tag{{font-size:10px;background:rgba(63,185,80,.1);color:#3fb950;
  border:1px solid rgba(63,185,80,.2);padding:1px 6px;border-radius:3px;margin-left:8px}}
.sm-tag{{font-size:10px;background:rgba(88,166,255,.1);color:#58a6ff;
  border:1px solid rgba(88,166,255,.2);padding:1px 6px;border-radius:3px;margin-left:4px}}
.hash{{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:11px;color:var(--text3)}}
.size-cell{{color:var(--text3);font-size:12px;white-space:nowrap}}

/* ── Infrastructure ── */
.cls-badge{{font-size:11px;font-weight:600}}
.action-report_only{{color:var(--yellow)}}
.action-investigate{{color:var(--red);font-weight:600}}

/* ── Data table ── */
.data-table{{width:100%;border-collapse:collapse;font-size:13px}}
.data-table th{{background:var(--bg);padding:8px 12px;text-align:left;
  font-size:10px;text-transform:uppercase;letter-spacing:0.5px;
  color:var(--text3);font-weight:600;border-bottom:1px solid var(--border)}}
.data-table td{{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}}
.data-table tr:last-child td{{border-bottom:none}}
.data-table tr:hover td{{background:rgba(255,255,255,.02)}}

/* ── Graph ── */
#graph-container{{width:100%;height:580px;background:#0d1117;
  border:1px solid var(--border);border-radius:var(--radius);
  position:relative;overflow:hidden}}
#graph-svg{{width:100%;height:100%}}
.graph-controls{{position:absolute;top:14px;right:14px;display:flex;flex-direction:column;gap:6px}}
.graph-btn{{background:var(--surface);border:1px solid var(--border);color:var(--text2);
  width:30px;height:30px;border-radius:var(--radius-sm);cursor:pointer;
  display:flex;align-items:center;justify-content:center;font-size:14px;
  transition:all .15s}}
.graph-btn:hover{{border-color:var(--accent);color:var(--accent)}}
.graph-legend{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}}
.legend-item{{display:flex;align-items:center;gap:5px;font-size:11px;color:var(--text3)}}
.legend-dot{{width:10px;height:10px;border-radius:50%;flex-shrink:0}}
.node-tooltip{{position:absolute;background:var(--surface);border:1px solid var(--border2);
  border-radius:var(--radius);padding:12px 14px;font-size:12px;pointer-events:none;
  z-index:200;max-width:280px;box-shadow:0 8px 24px rgba(0,0,0,.4);display:none}}
.tooltip-kind{{font-size:10px;text-transform:uppercase;letter-spacing:0.5px;
  color:var(--text3);margin-bottom:4px;font-weight:600}}
.tooltip-label{{font-weight:600;color:var(--text);margin-bottom:6px;word-break:break-all}}
.tooltip-meta{{font-size:11px;color:var(--text2)}}
.graph-detail-panel{{position:absolute;right:0;top:0;bottom:0;width:280px;
  background:var(--surface);border-left:1px solid var(--border);
  padding:16px;overflow-y:auto;transform:translateX(100%);
  transition:transform .25s;z-index:50}}
.graph-detail-panel.open{{transform:translateX(0)}}
.detail-close{{position:absolute;top:10px;right:10px;background:none;border:none;
  color:var(--text3);cursor:pointer;font-size:16px;padding:4px}}
.detail-kind{{font-size:10px;text-transform:uppercase;letter-spacing:0.8px;
  color:var(--text3);font-weight:600;margin-bottom:6px}}
.detail-label{{font-size:14px;font-weight:600;color:var(--text);margin-bottom:14px;
  word-break:break-all}}
.detail-section{{margin-bottom:12px}}
.detail-section-title{{font-size:10px;text-transform:uppercase;letter-spacing:0.5px;
  color:var(--text3);font-weight:600;margin-bottom:6px;border-bottom:1px solid var(--border);padding-bottom:4px}}
.detail-row{{display:flex;justify-content:space-between;align-items:start;
  gap:8px;margin-bottom:5px;font-size:11px}}
.detail-key{{color:var(--text3);flex-shrink:0}}
.detail-val{{color:var(--text);text-align:right;word-break:break-all}}
.detail-chip{{display:inline-block;padding:2px 7px;border-radius:3px;font-size:10px;
  font-weight:600;margin-bottom:4px}}
.neighbor-list{{display:flex;flex-direction:column;gap:4px}}
.neighbor-item{{font-size:11px;color:var(--text2);padding:4px 8px;
  background:var(--bg);border-radius:3px;cursor:pointer}}
.neighbor-item:hover{{color:var(--accent)}}

/* ── Notice / disclaimer ── */
.notice{{background:rgba(63,185,80,.06);border:1px solid rgba(63,185,80,.2);
  border-radius:var(--radius);padding:12px 16px;font-size:12px;color:var(--text2);
  margin-top:16px;line-height:1.7}}
.notice strong{{color:var(--green)}}

/* ── Empty ── */
.empty-state{{text-align:center;padding:40px 20px;color:var(--text3)}}
.empty-icon{{font-size:28px;display:block;margin-bottom:8px}}

/* ── Scrollbar ── */
::-webkit-scrollbar{{width:6px;height:6px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--border2);border-radius:3px}}
::-webkit-scrollbar-thumb:hover{{background:var(--text3)}}
</style>
</head>
<body>
<div class="layout">

<!-- ── Sidebar ── -->
<aside class="sidebar">
  <div class="sidebar-logo">
    <div class="logo-mark">Bundle<span>Spy</span></div>
    <div class="logo-sub">Attack Surface Intelligence</div>
  </div>
  <nav class="nav-section">
    <div class="nav-label">Report</div>
    <button class="nav-item active" onclick="showSection('overview')">
      <span class="nav-icon">◈</span> Overview
    </button>
    <button class="nav-item" onclick="showSection('graph')">
      <span class="nav-icon">⬡</span> Attack Surface
    </button>
    <button class="nav-item" onclick="showSection('findings')">
      <span class="nav-icon">⚑</span> Findings
      <span class="nav-badge {'red' if critical or high else ''}">{len(real)}</span>
    </button>
    <button class="nav-item" onclick="showSection('endpoints')">
      <span class="nav-icon">⇄</span> Endpoints
      <span class="nav-badge">{len(result.endpoints)}</span>
    </button>
    <button class="nav-item" onclick="showSection('assets')">
      <span class="nav-icon">◻</span> JS Assets
      <span class="nav-badge">{len(result.js_files)}</span>
    </button>
    <button class="nav-item" onclick="showSection('infrastructure')">
      <span class="nav-icon">⌖</span> Infrastructure
      <span class="nav-badge">{len(result.infrastructure)}</span>
    </button>
  </nav>
  <div class="sidebar-footer">
    BundleSpy v1.0.0<br>
    Authorized use only
  </div>
</aside>

<!-- ── Main ── -->
<div class="main">
  <div class="topbar">
    <div class="topbar-target">
      <div class="topbar-url">{_e(result.target_url)}</div>
      <div class="topbar-meta">Started {scan_start} &nbsp;·&nbsp; Duration {dur} &nbsp;·&nbsp; Report generated {gen_time}</div>
    </div>
    <div class="topbar-badges">
      {'<span class="scan-badge" style="color:var(--red);border-color:#3d1515;background:#1a0808">CRITICAL FINDINGS</span>' if critical else ''}
      {'<span class="scan-badge" style="color:var(--orange);border-color:#3d2215;background:#1a0d08">HIGH FINDINGS</span>' if not critical and high else ''}
      {'<span class="scan-badge" style="color:var(--green);border-color:#1a3a1a;background:#081a08">COMPLETE</span>' if not critical and not high else ''}
    </div>
  </div>

  <div class="content">

    <!-- ── OVERVIEW ── -->
    <div id="section-overview" class="section active">
      <div class="section-title">Overview</div>

      <div class="overview-grid">
        <div class="metric-card {'red' if critical else 'grey'}">
          <div class="metric-num">{len(critical)}</div>
          <div class="metric-lbl">Critical</div>
        </div>
        <div class="metric-card {'orange' if high else 'grey'}">
          <div class="metric-num">{len(high)}</div>
          <div class="metric-lbl">High</div>
        </div>
        <div class="metric-card {'yellow' if medium else 'grey'}">
          <div class="metric-num">{len(medium)}</div>
          <div class="metric-lbl">Medium</div>
        </div>
        <div class="metric-card {'blue' if low else 'grey'}">
          <div class="metric-num">{len(low)}</div>
          <div class="metric-lbl">Low</div>
        </div>
        <div class="metric-card purple">
          <div class="metric-num">{len(result.endpoints)}</div>
          <div class="metric-lbl">Endpoints</div>
        </div>
        <div class="metric-card green">
          <div class="metric-num">{len(result.js_files)}</div>
          <div class="metric-lbl">JS Assets</div>
        </div>
        <div class="metric-card cyan">
          <div class="metric-num">{result.pages_crawled}</div>
          <div class="metric-lbl">Pages Crawled</div>
        </div>
        <div class="metric-card grey">
          <div class="metric-num">{len(result.infrastructure)}</div>
          <div class="metric-lbl">Infra Indicators</div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">Scan Details</div>
        <div class="card-body" style="padding:0">
          <table class="meta-table">
            <tr><td class="meta-key">Target</td><td class="meta-val"><code>{_e(result.target_url)}</code></td></tr>
            <tr><td class="meta-key">Scan started</td><td class="meta-val">{scan_start}</td></tr>
            <tr><td class="meta-key">Scan duration</td><td class="meta-val">{dur}</td></tr>
            <tr><td class="meta-key">Report generated</td><td class="meta-val">{gen_time}</td></tr>
            <tr><td class="meta-key">Total findings</td><td class="meta-val">{len(real)} confirmed · {len(fps)} excluded as likely false positive</td></tr>
            <tr><td class="meta-key">Endpoints</td><td class="meta-val">{len(result.endpoints)}</td></tr>
            <tr><td class="meta-key">JS assets</td><td class="meta-val">{len(result.js_files)}</td></tr>
            <tr><td class="meta-key">Infrastructure</td><td class="meta-val">{len(result.infrastructure)} indicator(s)</td></tr>
            {f'<tr><td class="meta-key">Graph nodes</td><td class="meta-val">{result.graph.stats()["nodes"]} nodes · {result.graph.stats()["edges"]} relationships</td></tr>' if result.graph else ''}
            {f'<tr><td class="meta-key">Scan errors</td><td class="meta-val" style="color:var(--red)">{len(result.errors)}</td></tr>' if result.errors else ''}
          </table>
        </div>
      </div>

      <div class="notice">
        <strong>Disclaimer.</strong> This report was generated by automated analysis.
        All findings are candidates that require manual verification.
        No credentials were validated, no authentication was attempted,
        and no exploitation was performed. This report is intended exclusively
        for authorized security assessments. Handle with appropriate confidentiality.
      </div>
    </div>

    <!-- ── ATTACK SURFACE GRAPH ── -->
    <div id="section-graph" class="section">
      <div class="section-title">
        Attack Surface Graph
        <span class="count">{g_stats.get("PAGE",0)} pages · {g_stats.get("JS",0)+g_stats.get("CHUNK",0)} assets · {g_stats.get("ENDPOINT",0)} endpoints · {g_stats.get("SECRET",0)} secrets</span>
      </div>

      <div class="graph-legend">
        {''.join(f'<div class="legend-item"><div class="legend-dot" style="background:{c}"></div>{k.title()}</div>' for k,c in NODE_COLOR.items())}
      </div>

      <div id="graph-container">
        <svg id="graph-svg"></svg>
        <div class="graph-controls">
          <button class="graph-btn" onclick="zoomIn()" title="Zoom in">+</button>
          <button class="graph-btn" onclick="zoomOut()" title="Zoom out">−</button>
          <button class="graph-btn" onclick="resetZoom()" title="Reset">⊙</button>
        </div>
        <div class="node-tooltip" id="node-tooltip">
          <div class="tooltip-kind" id="tt-kind"></div>
          <div class="tooltip-label" id="tt-label"></div>
          <div class="tooltip-meta" id="tt-meta"></div>
        </div>
        <div class="graph-detail-panel" id="detail-panel">
          <button class="detail-close" onclick="closeDetail()">✕</button>
          <div class="detail-kind" id="dp-kind"></div>
          <div class="detail-label" id="dp-label"></div>
          <div id="dp-body"></div>
        </div>
      </div>

      {'<div class="card" style="margin-top:16px"><div class="card-header">Graph not available</div><div class="card-body" style="color:var(--text3);font-size:12px">The attack surface graph requires the scan to complete with graph building enabled.</div></div>' if not result.graph else ''}
    </div>

    <!-- ── FINDINGS ── -->
    <div id="section-findings" class="section">
      <div class="section-title">
        Findings
        <span class="count">{len(real)} confirmed · {len(fps)} excluded</span>
      </div>
      <div class="findings-filter">
        <button class="filter-btn active" data-sev="ALL" onclick="filterFindings('ALL',this)">All ({len(real)})</button>
        {_btn_critical}
        {_btn_high}
        {_btn_medium}
        {_btn_low}
        {_btn_info}
      </div>
      <div id="findings-list">
        {_findings_html(findings)}
      </div>
    </div>

    <!-- ── ENDPOINTS ── -->
    <div id="section-endpoints" class="section">
      <div class="section-title">
        Endpoints
        <span class="count">{len(result.endpoints)} discovered</span>
      </div>
      {_endpoints_html(result.endpoints)}
    </div>

    <!-- ── JS ASSETS ── -->
    <div id="section-assets" class="section">
      <div class="section-title">
        JavaScript Assets
        <span class="count">{len(result.js_files)} analyzed</span>
      </div>
      <div class="card">
        <div class="card-body" style="padding:0">
          {_js_html(result)}
        </div>
      </div>
    </div>

    <!-- ── INFRASTRUCTURE ── -->
    <div id="section-infrastructure" class="section">
      <div class="section-title">
        Infrastructure Indicators
        <span class="count">{len(result.infrastructure)} found</span>
      </div>
      <div class="card">
        <div class="card-body" style="padding:0">
          {_infra_html(result.infrastructure)}
        </div>
      </div>
    </div>

  </div><!-- /content -->
</div><!-- /main -->
</div><!-- /layout -->

<!-- ── D3 force graph ── -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
<script>
// ── Navigation ────────────────────────────────────────────────────────────────
function showSection(id) {{
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  document.getElementById('section-' + id).classList.add('active');
  event.currentTarget.classList.add('active');
  if (id === 'graph') initGraph();
}}

// ── Findings filter ───────────────────────────────────────────────────────────
function filterFindings(sev, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(card => {{
    card.style.display = (sev === 'ALL' || card.dataset.severity === sev) ? '' : 'none';
  }});
}}

// ── Attack Surface Graph ──────────────────────────────────────────────────────
const GRAPH_DATA = {graph_json};
const NODE_COLORS = {_j(NODE_COLOR)};

let graphInitialised = false;
let gSvg, gSim, gZoom, gTransform = d3.zoomIdentity;

function initGraph() {{
  if (graphInitialised || !GRAPH_DATA) return;
  graphInitialised = true;

  const container = document.getElementById('graph-container');
  const W = container.clientWidth;
  const H = container.clientHeight;
  const nodes = (GRAPH_DATA.nodes || []).map(n => ({{...n}}));
  const edges = (GRAPH_DATA.edges || []).map(e => ({{...e}}));
  const nodeById = {{}};
  nodes.forEach(n => nodeById[n.id] = n);

  const svg = d3.select('#graph-svg');
  svg.selectAll('*').remove();

  // Defs: arrowheads
  const defs = svg.append('defs');
  Object.entries(NODE_COLORS).forEach(([kind, color]) => {{
    defs.append('marker')
      .attr('id', 'arrow-' + kind)
      .attr('viewBox', '0 -4 8 8')
      .attr('refX', 18).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-4L8,0L0,4')
      .attr('fill', color)
      .attr('opacity', 0.6);
  }});

  const g = svg.append('g');
  gZoom = d3.zoom().scaleExtent([0.2, 4]).on('zoom', e => {{
    gTransform = e.transform;
    g.attr('transform', e.transform);
  }});
  svg.call(gZoom);

  // Node radii by type
  const radii = {{PAGE:14,JS:12,ENDPOINT:10,SECRET:12,WORKER:10,PARAMETER:7,HOST:11,CHUNK:9,SOURCEMAP:8,CONFIG:8}};

  // Link force by edge kind
  const linkDist = {{LOADS:90,IMPORTS:70,CALLS:110,EXPOSES:90,ACCEPTS:55,OBSERVED_ON:120,RELATED_TO:100,HOSTS:130,REFERENCES:100,RECOVERS:80}};

  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(edges).id(d => d.id)
      .distance(e => linkDist[e.kind] || 100).strength(0.4))
    .force('charge', d3.forceManyBody().strength(-220))
    .force('center', d3.forceCenter(W/2, H/2))
    .force('collision', d3.forceCollide(d => (radii[d.kind]||10) + 6));
  gSim = sim;

  // Edges
  const link = g.append('g').selectAll('line')
    .data(edges).join('line')
    .attr('stroke', e => {{
      const src = nodeById[e.source.id || e.source];
      return src ? (NODE_COLORS[src.kind] || '#475569') : '#475569';
    }})
    .attr('stroke-opacity', 0.35)
    .attr('stroke-width', 1.2)
    .attr('marker-end', e => {{
      const src = nodeById[e.source.id || e.source];
      return src ? `url(#arrow-${{src.kind}})` : '';
    }});

  // Edge labels (only for important kinds)
  const SHOW_LABEL = new Set(['CALLS','EXPOSES','RELATED_TO']);
  const edgeLabel = g.append('g').selectAll('text')
    .data(edges.filter(e => SHOW_LABEL.has(e.kind))).join('text')
    .attr('font-size', 9)
    .attr('fill', '#475569')
    .attr('text-anchor', 'middle')
    .attr('dy', -3)
    .text(e => e.kind.toLowerCase().replace('_',' '));

  // Nodes
  const node = g.append('g').selectAll('g')
    .data(nodes).join('g')
    .attr('cursor', 'pointer')
    .call(d3.drag()
      .on('start', (event, d) => {{ if (!event.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }})
      .on('drag',  (event, d) => {{ d.fx=event.x; d.fy=event.y; }})
      .on('end',   (event, d) => {{ if (!event.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }}))
    .on('mouseenter', showTooltip)
    .on('mousemove',  moveTooltip)
    .on('mouseleave', hideTooltip)
    .on('click', showDetail);

  node.append('circle')
    .attr('r', d => radii[d.kind] || 10)
    .attr('fill', d => (NODE_COLORS[d.kind] || '#475569') + '22')
    .attr('stroke', d => NODE_COLORS[d.kind] || '#475569')
    .attr('stroke-width', 1.5);

  // Icon letters
  const ICONS = {{PAGE:'P',JS:'JS',ENDPOINT:'EP',SECRET:'S',WORKER:'W',PARAMETER:'p',HOST:'H',CHUNK:'C',SOURCEMAP:'M',CONFIG:'Cf'}};
  node.append('text')
    .attr('text-anchor', 'middle').attr('dominant-baseline', 'central')
    .attr('font-size', d => d.kind === 'JS' ? 7 : 8)
    .attr('font-weight', '700')
    .attr('fill', d => NODE_COLORS[d.kind] || '#475569')
    .text(d => ICONS[d.kind] || '?');

  // Labels for important nodes
  const LABEL_KINDS = new Set(['PAGE','SECRET','ENDPOINT']);
  node.filter(d => LABEL_KINDS.has(d.kind)).append('text')
    .attr('text-anchor', 'middle').attr('y', d => (radii[d.kind]||10) + 11)
    .attr('font-size', 9).attr('fill', '#8b949e')
    .text(d => d.label.length > 22 ? d.label.slice(0,22)+'…' : d.label);

  sim.on('tick', () => {{
    link.attr('x1', e => e.source.x).attr('y1', e => e.source.y)
        .attr('x2', e => e.target.x).attr('y2', e => e.target.y);
    edgeLabel.attr('x', e => (e.source.x + e.target.x)/2)
             .attr('y', e => (e.source.y + e.target.y)/2);
    node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
  }});
  gSvg = svg;
}}

// ── Tooltip ───────────────────────────────────────────────────────────────────
function showTooltip(event, d) {{
  const tt = document.getElementById('node-tooltip');
  document.getElementById('tt-kind').textContent = d.kind;
  document.getElementById('tt-label').textContent = d.label;
  const meta = [];
  if (d.data.url)      meta.push(d.data.url);
  if (d.data.method)   meta.push('Method: ' + d.data.method);
  if (d.data.severity) meta.push('Severity: ' + d.data.severity);
  if (d.data.source_type) meta.push('Source: ' + d.data.source_type);
  document.getElementById('tt-meta').textContent = meta.join(' · ');
  tt.style.display = 'block';
  moveTooltip(event);
}}
function moveTooltip(event) {{
  const tt  = document.getElementById('node-tooltip');
  const box = document.getElementById('graph-container').getBoundingClientRect();
  let x = event.clientX - box.left + 12;
  let y = event.clientY - box.top  + 12;
  if (x + 290 > box.width)  x = event.clientX - box.left - 290;
  if (y + 100 > box.height) y = event.clientY - box.top  - 100;
  tt.style.left = x + 'px';
  tt.style.top  = y + 'px';
}}
function hideTooltip() {{ document.getElementById('node-tooltip').style.display='none'; }}

// ── Detail panel ──────────────────────────────────────────────────────────────
function showDetail(event, d) {{
  event.stopPropagation();
  const panel = document.getElementById('detail-panel');
  const c = NODE_COLORS[d.kind] || '#8b949e';
  document.getElementById('dp-kind').textContent = d.kind;
  document.getElementById('dp-kind').style.color = c;
  document.getElementById('dp-label').textContent = d.label;

  const rows = [];
  const data = d.data || {{}};
  const skip = new Set(['url']);
  if (data.url)          rows.push(['URL',          `<code style="font-size:10px;word-break:break-all">${{data.url}}</code>`]);
  if (data.method)       rows.push(['Method',       `<span class="detail-chip" style="background:${{c}}22;color:${{c}}">${{data.method}}</span>`]);
  if (data.category)     rows.push(['Category',     data.category]);
  if (data.severity)     rows.push(['Severity',     data.severity]);
  if (data.source_type)  rows.push(['Source',       data.source_type]);
  if (data.confidence)   rows.push(['Confidence',   `${{(d.confidence*100).toFixed(0)}}%`]);
  if (data.auth_context) rows.push(['Auth',         data.auth_context]);
  if (data.size_bytes)   rows.push(['Size',         (data.size_bytes/1024).toFixed(1) + ' KB']);
  if (data.classification) rows.push(['Class',      data.classification]);
  if (data.line_number)  rows.push(['Line',         data.line_number]);
  if (data.redacted_value) rows.push(['Value',      `<code style="color:#3fb950">${{data.redacted_value}}</code>`]);

  const rowsHtml = rows.map(([k,v]) =>
    `<div class="detail-row"><span class="detail-key">${{k}}</span><span class="detail-val">${{v}}</span></div>`
  ).join('');

  // Neighbors from graph data (edges)
  const allEdges = (GRAPH_DATA.edges || []);
  const outgoing = allEdges.filter(e => e.source === d.id);
  const incoming = allEdges.filter(e => e.target === d.id);
  const nodeById = {{}};
  (GRAPH_DATA.nodes || []).forEach(n => nodeById[n.id] = n);

  let neighborsHtml = '';
  if (outgoing.length || incoming.length) {{
    const items = [];
    outgoing.slice(0,6).forEach(e => {{
      const n = nodeById[e.target];
      if (n) items.push(`<div class="neighbor-item" onclick="focusNode('${{n.id}}')" title="${{e.kind}}">→ ${{n.label}}</div>`);
    }});
    incoming.slice(0,4).forEach(e => {{
      const n = nodeById[e.source];
      if (n) items.push(`<div class="neighbor-item" onclick="focusNode('${{n.id}}')" title="${{e.kind}}">← ${{n.label}}</div>`);
    }});
    if (items.length) {{
      neighborsHtml = `<div class="detail-section">
        <div class="detail-section-title">Connected nodes (${{outgoing.length + incoming.length}})</div>
        <div class="neighbor-list">${{items.join('')}}</div>
      </div>`;
    }}
  }}

  document.getElementById('dp-body').innerHTML = `
    <div class="detail-section">
      <div class="detail-section-title">Properties</div>
      ${{rowsHtml || '<span style="color:var(--text3);font-size:11px">No properties</span>'}}
    </div>
    ${{neighborsHtml}}`;
  panel.classList.add('open');
}}

function closeDetail() {{
  document.getElementById('detail-panel').classList.remove('open');
}}

function focusNode(id) {{
  // Highlight node in graph by ID (future: pan to it)
  gSvg && gSvg.selectAll('circle').attr('stroke-width', d => d.id === id ? 3 : 1.5);
}}

// ── Zoom controls ─────────────────────────────────────────────────────────────
function zoomIn()    {{ if (gSvg && gZoom) gSvg.transition().call(gZoom.scaleBy, 1.4); }}
function zoomOut()   {{ if (gSvg && gZoom) gSvg.transition().call(gZoom.scaleBy, 0.7); }}
function resetZoom() {{ if (gSvg && gZoom) gSvg.transition().call(gZoom.transform, d3.zoomIdentity); }}

// Close detail panel when clicking on svg background
document.getElementById('graph-svg').addEventListener('click', () => {{
  document.getElementById('detail-panel').classList.remove('open');
}});
</script>
</body>
</html>"""
