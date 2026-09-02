"""Interactive HTML report generator with charts, filtering, and dark mode."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from aegisx.core.context import ScanContext
from aegisx.reporters.base_reporter import BaseReporter


class HTMLReporter(BaseReporter):
    """Generates an interactive HTML security assessment report."""

    format_name = "html"
    file_extension = ".html"

    def generate(self) -> str:
        ctx = self.context
        stats = ctx.get_stats()
        findings = sorted(ctx.findings, key=lambda f: f.severity_order, reverse=True)

        findings_json = json.dumps([
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "cvss": f.cvss_score,
                "cwe": f.cwe_id,
                "owasp": f.owasp_category,
                "url": f.url,
                "endpoint": f.endpoint,
                "method": f.method,
                "parameter": f.parameter,
                "description": f.description,
                "evidence": f.evidence,
                "payload": f.payload,
                "remediation": f.remediation,
                "references": f.references,
                "scanner": f.scanner_name,
            }
            for f in findings
        ], ensure_ascii=False)

        exploit_json = json.dumps([
            {
                "finding_id": r.finding_id,
                "exploit": r.exploit_name,
                "success": r.success,
                "payload": r.payload,
                "evidence": r.evidence,
            }
            for r in ctx.exploit_results
        ], ensure_ascii=False)

        return HTML_TEMPLATE.format(
            target=ctx.target_url,
            scan_id=ctx.scan_id,
            started=ctx.started_at,
            finished=ctx.finished_at or "In Progress",
            duration=f"{stats.scan_duration_seconds:.1f}",
            total=stats.total_findings,
            critical=stats.critical_count,
            high=stats.high_count,
            medium=stats.medium_count,
            low=stats.low_count,
            info=stats.info_count,
            scanners=", ".join(stats.scanners_used) or "None",
            findings_json=findings_json,
            exploit_json=exploit_json,
            version="0.1.0",
        )


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aegisx-Agent Security Report — {target}</title>
<style>
:root {{
  --bg: #0f172a; --surface: #1e293b; --border: #334155;
  --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
  --critical: #ef4444; --high: #f97316; --medium: #eab308;
  --low: #3b82f6; --info: #6b7280; --success: #22c55e;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Inter', -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
header {{ text-align: center; padding: 3rem 0; border-bottom: 1px solid var(--border); }}
header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
header .subtitle {{ color: var(--muted); font-size: 0.9rem; }}
.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 2rem 0; }}
.stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; text-align: center; }}
.stat-card .number {{ font-size: 2.5rem; font-weight: 700; }}
.stat-card .label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
.stat-card.critical .number {{ color: var(--critical); }}
.stat-card.high .number {{ color: var(--high); }}
.stat-card.medium .number {{ color: var(--medium); }}
.stat-card.low .number {{ color: var(--low); }}
.stat-card.total .number {{ color: var(--accent); }}
.filters {{ display: flex; gap: 0.5rem; flex-wrap: wrap; margin: 2rem 0; }}
.filter-btn {{ padding: 0.5rem 1rem; border-radius: 8px; border: 1px solid var(--border); background: var(--surface); color: var(--text); cursor: pointer; font-size: 0.85rem; transition: all 0.2s; }}
.filter-btn:hover {{ border-color: var(--accent); }}
.filter-btn.active {{ background: var(--accent); color: var(--bg); border-color: var(--accent); }}
.findings-list {{ display: flex; flex-direction: column; gap: 1rem; }}
.finding-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; border-left: 4px solid var(--border); transition: all 0.2s; }}
.finding-card:hover {{ border-color: var(--accent); }}
.finding-card.severity-critical {{ border-left-color: var(--critical); }}
.finding-card.severity-high {{ border-left-color: var(--high); }}
.finding-card.severity-medium {{ border-left-color: var(--medium); }}
.finding-card.severity-low {{ border-left-color: var(--low); }}
.finding-card.severity-info {{ border-left-color: var(--info); }}
.finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem; }}
.finding-title {{ font-size: 1.1rem; font-weight: 600; }}
.severity-badge {{ padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
.severity-badge.critical {{ background: rgba(239,68,68,0.2); color: var(--critical); }}
.severity-badge.high {{ background: rgba(249,115,22,0.2); color: var(--high); }}
.severity-badge.medium {{ background: rgba(234,179,8,0.2); color: var(--medium); }}
.severity-badge.low {{ background: rgba(59,130,246,0.2); color: var(--low); }}
.severity-badge.info {{ background: rgba(107,114,128,0.2); color: var(--info); }}
.finding-meta {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 0.75rem; font-size: 0.85rem; color: var(--muted); }}
.finding-meta span {{ display: flex; align-items: center; gap: 0.25rem; }}
.finding-desc {{ margin-bottom: 0.75rem; font-size: 0.9rem; }}
.finding-evidence {{ background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; font-family: monospace; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; }}
.finding-remediation {{ background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); border-radius: 8px; padding: 1rem; font-size: 0.85rem; }}
.finding-remediation strong {{ color: var(--success); }}
.chart-container {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin: 2rem 0; }}
.bar-chart {{ display: flex; align-items: end; gap: 0.5rem; height: 150px; padding-top: 1rem; }}
.bar {{ flex: 1; border-radius: 6px 6px 0 0; position: relative; min-height: 4px; transition: all 0.3s; }}
.bar .count {{ position: absolute; top: -25px; left: 50%; transform: translateX(-50%); font-size: 0.8rem; font-weight: 600; }}
.bar .label {{ position: absolute; bottom: -25px; left: 50%; transform: translateX(-50%); font-size: 0.7rem; color: var(--muted); }}
.hidden {{ display: none !important; }}
footer {{ text-align: center; padding: 2rem 0; color: var(--muted); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 3rem; }}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>🛡️ Aegisx-Agent Security Report</h1>
  <div class="subtitle">{target} — Scan ID: {scan_id}</div>
  <div class="subtitle" style="margin-top:0.5rem">Started: {started} | Finished: {finished} | Duration: {duration}s</div>
</header>

<div class="stats-grid">
  <div class="stat-card total"><div class="number">{total}</div><div class="label">Total Findings</div></div>
  <div class="stat-card critical"><div class="number">{critical}</div><div class="label">Critical</div></div>
  <div class="stat-card high"><div class="number">{high}</div><div class="label">High</div></div>
  <div class="stat-card medium"><div class="number">{medium}</div><div class="label">Medium</div></div>
  <div class="stat-card low"><div class="number">{low}</div><div class="label">Low</div></div>
</div>

<div class="chart-container">
  <h3 style="margin-bottom:1rem; font-size:0.9rem; color:var(--muted)">Severity Distribution</h3>
  <div class="bar-chart">
    <div class="bar" style="height:{critical}%25; background:var(--critical)"><div class="count">{critical}</div><div class="label">Critical</div></div>
    <div class="bar" style="height:{high}%25; background:var(--high)"><div class="count">{high}</div><div class="label">High</div></div>
    <div class="bar" style="height:{medium}%25; background:var(--medium)"><div class="count">{medium}</div><div class="label">Medium</div></div>
    <div class="bar" style="height:{low}%25; background:var(--low)"><div class="count">{low}</div><div class="label">Low</div></div>
    <div class="bar" style="height:{info}%25; background:var(--info)"><div class="count">{info}</div><div class="label">Info</div></div>
  </div>
</div>

<div class="filters">
  <button class="filter-btn active" onclick="filterFindings('all')">All ({total})</button>
  <button class="filter-btn" onclick="filterFindings('critical')">🔴 Critical ({critical})</button>
  <button class="filter-btn" onclick="filterFindings('high')">🟠 High ({high})</button>
  <button class="filter-btn" onclick="filterFindings('medium')">🟡 Medium ({medium})</button>
  <button class="filter-btn" onclick="filterFindings('low')">🔵 Low ({low})</button>
</div>

<div class="findings-list" id="findings-list"></div>

<footer>
  Generated by Aegisx-Agent v{version} — Autonomous Security Scanner<br>
  Scanners: {scanners}
</footer>
</div>

<script>
const findings = {findings_json};
const exploits = {exploit_json};

function renderFindings(filter) {{
  const list = document.getElementById('findings-list');
  const filtered = filter === 'all' ? findings : findings.filter(f => f.severity === filter);

  list.innerHTML = filtered.map(f => `
    <div class="finding-card severity-${{f.severity}}">
      <div class="finding-header">
        <div class="finding-title">${{f.id}}: ${{f.title}}</div>
        <span class="severity-badge ${{f.severity}}">${{f.severity}}</span>
      </div>
      <div class="finding-meta">
        <span>🎯 ${{f.cwe || 'N/A'}}</span>
        <span>📋 ${{f.owasp || 'N/A'}}</span>
        <span>📊 CVSS: ${{f.cvss}}</span>
        ${{f.parameter ? `<span>📝 Param: ${{f.parameter}}</span>` : ''}}
        ${{f.method ? `<span>🔀 ${{f.method}}</span>` : ''}}
      </div>
      <div class="finding-desc">${{f.description}}</div>
      ${{f.evidence ? `<div class="finding-evidence">${{f.evidence.substring(0, 500)}}</div>` : ''}}
      ${{f.payload ? `<div class="finding-evidence" style="border-color:var(--high)">Payload: ${{f.payload}}</div>` : ''}}
      <div class="finding-remediation"><strong>🔧 Remediation:</strong> ${{f.remediation}}</div>
    </div>
  `).join('');

  if (filtered.length === 0) {{
    list.innerHTML = '<div style="text-align:center; padding:3rem; color:var(--muted)">✅ No findings for this filter</div>';
  }}
}}

function filterFindings(filter) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  renderFindings(filter);
}}

// Initial render
renderFindings('all');
</script>
</body>
</html>"""
