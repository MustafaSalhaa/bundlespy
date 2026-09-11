"""
HTML report generator.
Produces a standalone, self-contained HTML report with no external dependencies.
All CSS and JS is inline so the file works offline and can be shared directly.
"""

import html
import json
from datetime import datetime
from typing import List
from ..storage.models import ScanResult, Finding, Endpoint, InfrastructureItem


SEVERITY_COLOR = {
    "CRITICAL": "#e53e3e",
    "HIGH":     "#dd6b20",
    "MEDIUM":   "#d69e2e",
    "LOW":      "#3182ce",
    "INFO":     "#718096",
}

SEVERITY_BG = {
    "CRITICAL": "#fff5f5",
    "HIGH":     "#fffaf0",
    "MEDIUM":   "#fffff0",
    "LOW":      "#ebf8ff",
    "INFO":     "#f7fafc",
}


def _e(s) -> str:
    """HTML-escape a value safely."""
    return html.escape(str(s or ""))


def _finding_row(f: Finding, show_sensitive: bool = False) -> str:
    color  = SEVERITY_COLOR.get(f.severity, "#718096")
    bg     = SEVERITY_BG.get(f.severity, "#f7fafc")
    value  = f.matched_value if show_sensitive else f.redacted_value
    fp_note = f'<div class="fp-note">FP note: {_e(f.false_positive_notes)}</div>' if f.false_positive_notes else ""
    occ    = ""
    if len(f.occurrences) > 1:
        occ = f'<div class="occurrences">Also found in: {_e(", ".join(f.occurrences[1:4]))}</div>'

    return f"""
<div class="finding" style="border-left: 4px solid {color}; background: {bg};">
  <div class="finding-header">
    <span class="badge" style="background:{color};">{_e(f.severity)}</span>
    <span class="finding-title">{_e(f.title)}</span>
    <span class="confidence">Confidence: {f.confidence:.0%}</span>
    <span class="status status-{f.status.replace('_','-')}">{_e(f.status)}</span>
  </div>
  <div class="finding-body">
    <div class="meta-row"><span class="label">File</span><code>{_e(f.file_url)}</code></div>
    <div class="meta-row"><span class="label">Line</span>{f.line_number}</div>
    <div class="meta-row"><span class="label">Category</span>{_e(f.category)}</div>
    <div class="meta-row"><span class="label">Value</span><code class="secret-value">{_e(value)}</code></div>
    <div class="meta-row"><span class="label">Context</span><code class="context">{_e(f.context[:200])}</code></div>
    <div class="meta-row"><span class="label">Description</span>{_e(f.description)}</div>
    <div class="meta-row"><span class="label">Remediation</span>{_e(f.remediation)}</div>
    {fp_note}
    {occ}
  </div>
</div>"""


def _endpoint_rows(endpoints: List[Endpoint]) -> str:
    if not endpoints:
        return "<p class='empty'>No endpoints discovered.</p>"
    by_cat: dict = {}
    for ep in endpoints:
        by_cat.setdefault(ep.category, []).append(ep)

    rows = ""
    for cat in sorted(by_cat):
        rows += f'<tr class="cat-header"><td colspan="4">{_e(cat)}</td></tr>'
        for ep in by_cat[cat][:50]:
            rows += f"""<tr>
  <td><code>{_e(ep.url)}</code></td>
  <td>{_e(ep.method)}</td>
  <td>{_e(ep.source_file.split("/")[-1])}</td>
  <td>{ep.line_number}</td>
</tr>"""
    return f"""<table class="data-table">
<thead><tr><th>Path / URL</th><th>Method</th><th>Source File</th><th>Line</th></tr></thead>
<tbody>{rows}</tbody>
</table>"""


def _infra_rows(items: List[InfrastructureItem]) -> str:
    if not items:
        return "<p class='empty'>No infrastructure indicators found.</p>"
    rows = ""
    for item in items[:100]:
        color = "#e53e3e" if item.classification in ("PRIVATE_IP", "CLOUD_METADATA") else "#dd6b20"
        rows += f"""<tr>
  <td><span class="badge" style="background:{color};">{_e(item.classification)}</span></td>
  <td><code>{_e(item.value)}</code></td>
  <td>{_e(item.source_file.split("/")[-1])}</td>
  <td>{item.line_number}</td>
  <td>{_e(item.action)}</td>
</tr>"""
    return f"""<table class="data-table">
<thead><tr><th>Type</th><th>Value</th><th>Source File</th><th>Line</th><th>Action</th></tr></thead>
<tbody>{rows}</tbody>
</table>"""


def _js_inventory(result: ScanResult) -> str:
    if not result.js_files:
        return "<p class='empty'>No JavaScript files discovered.</p>"
    rows = ""
    for js in result.js_files[:200]:
        tech = f'<span class="tech-badge">{_e(js.technology)}</span>' if js.technology else ""
        sm   = '<span class="sm-badge">source map</span>' if js.has_source_map else ""
        rows += f"""<tr>
  <td><code>{_e(js.url)}</code></td>
  <td>{js.size_bytes:,}</td>
  <td>{tech}{sm}</td>
  <td><code class="hash">{js.sha256[:12]}...</code></td>
</tr>"""
    return f"""<table class="data-table">
<thead><tr><th>URL</th><th>Size (bytes)</th><th>Technology</th><th>SHA-256</th></tr></thead>
<tbody>{rows}</tbody>
</table>"""


def generate(result: ScanResult, show_sensitive: bool = False) -> str:
    """Generate a standalone HTML report."""

    findings   = result.findings
    critical   = [f for f in findings if f.severity == "CRITICAL"]
    high       = [f for f in findings if f.severity == "HIGH"]
    medium     = [f for f in findings if f.severity == "MEDIUM"]
    low        = [f for f in findings if f.severity == "LOW"]
    fps        = [f for f in findings if f.status == "likely_false_positive"]
    real       = [f for f in findings if f.status != "likely_false_positive"]

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sorted_findings = sorted(
        real,
        key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99
    )

    finding_html = "".join(_finding_row(f, show_sensitive) for f in sorted_findings)
    if not finding_html:
        finding_html = "<p class='empty'>No findings above the confidence threshold.</p>"

    scan_duration = ""
    if result.finished_at and result.started_at:
        delta = (result.finished_at - result.started_at).total_seconds()
        scan_duration = f"{delta:.1f}s"

    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BundleSpy Report - {_e(result.target_url)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #f7fafc; color: #2d3748; font-size: 14px; line-height: 1.6; }}
  .header {{ background: #1a202c; color: #fff; padding: 24px 32px; }}
  .header h1 {{ font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }}
  .header .sub {{ color: #a0aec0; font-size: 13px; margin-top: 4px; }}
  .header .target {{ color: #63b3ed; font-family: monospace; }}
  .nav {{ background: #2d3748; display: flex; gap: 2px; padding: 0 32px; }}
  .nav a {{ color: #a0aec0; text-decoration: none; padding: 10px 16px; font-size: 13px;
            border-bottom: 2px solid transparent; display: block; }}
  .nav a:hover {{ color: #fff; border-bottom-color: #4299e1; }}
  .main {{ max-width: 1200px; margin: 0 auto; padding: 24px 32px; }}
  .section {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
              margin-bottom: 24px; overflow: hidden; }}
  .section-header {{ padding: 16px 20px; border-bottom: 1px solid #e2e8f0;
                     background: #f8fafc; font-weight: 600; font-size: 15px; }}
  .section-body {{ padding: 20px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                 gap: 16px; margin-bottom: 24px; }}
  .stat-card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
                padding: 16px; text-align: center; }}
  .stat-card .num {{ font-size: 32px; font-weight: 700; line-height: 1; }}
  .stat-card .lbl {{ color: #718096; font-size: 12px; margin-top: 4px; text-transform: uppercase;
                     letter-spacing: 0.5px; }}
  .stat-card.critical .num {{ color: #e53e3e; }}
  .stat-card.high .num {{ color: #dd6b20; }}
  .stat-card.medium .num {{ color: #d69e2e; }}
  .stat-card.low .num {{ color: #3182ce; }}
  .stat-card.ok .num {{ color: #38a169; }}
  .finding {{ border-radius: 6px; margin-bottom: 16px; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 10px; padding: 12px 16px;
                     flex-wrap: wrap; }}
  .finding-title {{ font-weight: 600; font-size: 14px; flex: 1; }}
  .finding-body {{ padding: 12px 16px; border-top: 1px solid rgba(0,0,0,0.06); }}
  .meta-row {{ display: grid; grid-template-columns: 110px 1fr; gap: 8px;
               margin-bottom: 8px; align-items: start; }}
  .label {{ font-weight: 600; color: #4a5568; font-size: 12px; text-transform: uppercase;
            letter-spacing: 0.3px; padding-top: 2px; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; color: #fff; font-size: 11px;
            font-weight: 700; letter-spacing: 0.5px; white-space: nowrap; }}
  .confidence {{ color: #718096; font-size: 12px; }}
  .status {{ font-size: 11px; padding: 2px 6px; border-radius: 3px; font-weight: 500; }}
  .status-likely-secret {{ background: #fed7d7; color: #9b2c2c; }}
  .status-candidate {{ background: #feebc8; color: #7b341e; }}
  .status-likely-false-positive {{ background: #e2e8f0; color: #4a5568; }}
  code {{ font-family: 'SF Mono', 'Fira Code', Consolas, monospace; font-size: 12px;
          background: #edf2f7; padding: 2px 6px; border-radius: 3px; word-break: break-all; }}
  .secret-value {{ background: #2d3748; color: #68d391; }}
  .context {{ display: block; white-space: pre-wrap; word-break: break-all; max-height: 60px;
              overflow: hidden; }}
  .fp-note {{ background: #fffbeb; border: 1px solid #f6e05e; border-radius: 4px;
              padding: 6px 10px; font-size: 12px; color: #744210; margin-top: 8px; }}
  .occurrences {{ font-size: 12px; color: #718096; margin-top: 6px; }}
  .data-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .data-table th {{ background: #f8fafc; padding: 8px 12px; text-align: left;
                    font-weight: 600; border-bottom: 2px solid #e2e8f0;
                    font-size: 11px; text-transform: uppercase; letter-spacing: 0.3px; }}
  .data-table td {{ padding: 8px 12px; border-bottom: 1px solid #f0f4f8; vertical-align: top; }}
  .data-table tr:last-child td {{ border-bottom: none; }}
  .cat-header td {{ background: #edf2f7; font-weight: 700; color: #2d3748;
                    font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .tech-badge {{ background: #c6f6d5; color: #22543d; padding: 1px 6px; border-radius: 3px;
                 font-size: 11px; margin-right: 4px; }}
  .sm-badge {{ background: #bee3f8; color: #2a4365; padding: 1px 6px; border-radius: 3px;
               font-size: 11px; }}
  .hash {{ font-size: 11px; color: #718096; }}
  .empty {{ color: #a0aec0; font-style: italic; padding: 12px 0; }}
  .notice {{ background: #f0fff4; border: 1px solid #9ae6b4; border-radius: 6px;
             padding: 12px 16px; font-size: 13px; color: #276749; margin-top: 16px; }}
  .errors {{ background: #fff5f5; border: 1px solid #feb2b2; border-radius: 6px;
             padding: 12px 16px; font-size: 12px; color: #742a2a; margin-top: 16px; }}
  .scan-meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 12px; font-size: 13px; }}
  .scan-meta-item {{ display: flex; flex-direction: column; gap: 2px; }}
  .scan-meta-item .key {{ color: #718096; font-size: 11px; text-transform: uppercase;
                          letter-spacing: 0.3px; }}
  .scan-meta-item .val {{ font-weight: 500; }}
  .footer {{ text-align: center; color: #a0aec0; font-size: 12px; padding: 24px;
             border-top: 1px solid #e2e8f0; margin-top: 32px; }}
</style>
</head>
<body>

<div class="header">
  <h1>BundleSpy - JavaScript Intelligence Report</h1>
  <div class="sub">Target: <span class="target">{_e(result.target_url)}</span>
  &nbsp;|&nbsp; Generated: {generated_at}
  &nbsp;|&nbsp; Author: Mustafa Salha</div>
</div>

<div class="nav">
  <a href="#summary">Summary</a>
  <a href="#findings">Findings ({len(real)})</a>
  <a href="#endpoints">Endpoints ({len(result.endpoints)})</a>
  <a href="#infrastructure">Infrastructure ({len(result.infrastructure)})</a>
  <a href="#inventory">JS Inventory ({len(result.js_files)})</a>
</div>

<div class="main">

  <!-- SUMMARY -->
  <div id="summary" class="section">
    <div class="section-header">Executive Summary</div>
    <div class="section-body">

      <div class="stats-grid">
        <div class="stat-card"><div class="num">{result.pages_crawled}</div><div class="lbl">Pages Crawled</div></div>
        <div class="stat-card"><div class="num">{len(result.js_files)}</div><div class="lbl">JS Files</div></div>
        <div class="stat-card"><div class="num">{len(result.endpoints)}</div><div class="lbl">Endpoints</div></div>
        <div class="stat-card"><div class="num">{len(result.infrastructure)}</div><div class="lbl">Infra Indicators</div></div>
        <div class="stat-card critical"><div class="num">{len(critical)}</div><div class="lbl">Critical</div></div>
        <div class="stat-card high"><div class="num">{len(high)}</div><div class="lbl">High</div></div>
        <div class="stat-card medium"><div class="num">{len(medium)}</div><div class="lbl">Medium</div></div>
        <div class="stat-card low"><div class="num">{len(low)}</div><div class="lbl">Low</div></div>
        <div class="stat-card"><div class="num">{len(fps)}</div><div class="lbl">Likely FP</div></div>
      </div>

      <div class="scan-meta">
        <div class="scan-meta-item"><div class="key">Target</div><div class="val">{_e(result.target_url)}</div></div>
        <div class="scan-meta-item"><div class="key">Started</div><div class="val">{result.started_at.strftime('%Y-%m-%d %H:%M UTC') if result.started_at else '-'}</div></div>
        <div class="scan-meta-item"><div class="key">Duration</div><div class="val">{scan_duration or '-'}</div></div>
        <div class="scan-meta-item"><div class="key">Total Findings</div><div class="val">{len(findings)}</div></div>
      </div>

      <div class="notice">
        No credentials were validated. No authentication was attempted.
        No exploitation was performed. Private network targets were not contacted.
        All findings are potential and require manual verification.
      </div>

      {"<div class='errors'><strong>Scan errors (" + str(len(result.errors)) + "):</strong><br>" + "<br>".join(_e(e) for e in result.errors[:10]) + "</div>" if result.errors else ""}
    </div>
  </div>

  <!-- FINDINGS -->
  <div id="findings" class="section">
    <div class="section-header">Findings ({len(real)} confirmed candidates, {len(fps)} likely false positives excluded)</div>
    <div class="section-body">
      {finding_html}
    </div>
  </div>

  <!-- ENDPOINTS -->
  <div id="endpoints" class="section">
    <div class="section-header">Endpoint Intelligence ({len(result.endpoints)})</div>
    <div class="section-body">
      {_endpoint_rows(result.endpoints)}
    </div>
  </div>

  <!-- INFRASTRUCTURE -->
  <div id="infrastructure" class="section">
    <div class="section-header">Infrastructure Intelligence ({len(result.infrastructure)})</div>
    <div class="section-body">
      {_infra_rows(result.infrastructure)}
    </div>
  </div>

  <!-- JS INVENTORY -->
  <div id="inventory" class="section">
    <div class="section-header">JavaScript File Inventory ({len(result.js_files)})</div>
    <div class="section-body">
      {_js_inventory(result)}
    </div>
  </div>

</div>

<div class="footer">
  BundleSpy 1.0.0 - JavaScript Intelligence and Secret Exposure Scanner
  &nbsp;|&nbsp; Author: Mustafa Salha
  &nbsp;|&nbsp; For authorized security assessments only
</div>

</body>
</html>"""
