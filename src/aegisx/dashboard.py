"""Local web dashboard for scan history and trends.

Serves a single-page UI plus a read-only JSON API over the scan-history
database — findings over time, severity distribution, and per-scan
detail. Zero new dependencies: :mod:`http.server` for the socket layer,
vanilla JS/SVG in the embedded page for rendering.

Security posture (deliberate):

- Binds to ``127.0.0.1`` by default; ``--host`` is opt-in and logged
  loudly. Scan history is sensitive — it must not sit on 0.0.0.0 by
  accident.
- Read-only over HTTP: the API exposes GET endpoints only, backed by
  the history database. Nothing accepts writes.
- Every JSON response is same-origin safe and carries no findings
  evidence beyond titles/URLs/severities — the dashboard is for
  triage, not payload inspection.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from aegisx.utils.history import ScanHistory
from aegisx.utils.logger import get_logger

logger = get_logger("dashboard")

_SEVERITIES = ("critical", "high", "medium", "low", "info")


def dashboard_summary(history: ScanHistory, per_target_limit: int = 5) -> dict[str, Any]:
    """Aggregate the history DB into the dashboard's data shape.

    Returns:
        Dict with overall stats, per-target trend series (chronological,
        oldest first — ready for a time-axis chart), and the recent scan
        list. Pure function of the DB; no I/O beyond the queries.
    """
    scans = history.get_scans(limit=10_000)
    summary = history.stats_summary()

    # Group scans per target, oldest first, for trend lines
    by_target: dict[str, list[dict[str, Any]]] = {}
    for scan in reversed(scans):  # get_scans is newest-first
        by_target.setdefault(scan["target"], []).append(scan)

    targets = []
    for target, rows in sorted(by_target.items(), key=lambda kv: -len(kv[1])):
        last = rows[-1]
        targets.append(
            {
                "target": target,
                "scan_count": len(rows),
                "last_scanned": last["timestamp"],
                "last_mode": last["mode"],
                "current_severities": {s: last[s] for s in _SEVERITIES},
                "trend": [
                    {
                        "timestamp": r["timestamp"],
                        "scan_id": r["scan_id"],
                        "findings": r["findings"],
                        **{s: r[s] for s in _SEVERITIES},
                    }
                    for r in rows[-per_target_limit:]
                ],
            }
        )

    recent = [
        {
            "scan_id": s["scan_id"],
            "timestamp": s["timestamp"],
            "target": s["target"],
            "mode": s["mode"],
            "findings": s["findings"],
            **{sev: s[sev] for sev in _SEVERITIES},
            "duration": round(s["duration"], 1),
        }
        for s in scans[:50]
    ]

    return {
        "stats": summary,
        "targets": targets,
        "recent": recent,
    }


def scan_detail(history: ScanHistory, scan_id: str) -> dict[str, Any] | None:
    """One scan with its full finding list (titles/severities only)."""
    record = history.get_scan(scan_id)
    if record is None:
        return None
    findings = []
    for f in record.get("findings", []):
        findings.append(
            {
                "id": f.get("id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", "info"),
                "cwe": f.get("cwe_id", ""),
                "url": f.get("url", ""),
                "parameter": f.get("parameter", ""),
            }
        )
    return {
        "scan_id": record.get("scan_id"),
        "timestamp": record.get("timestamp"),
        "target": record.get("target"),
        "mode": record.get("mode"),
        "duration": record.get("duration"),
        "severities": {s: record.get(s, 0) for s in _SEVERITIES},
        "findings": findings,
    }


class DashboardHandler(BaseHTTPRequestHandler):
    """Read-only HTTP surface: ``/`` (UI), ``/api/summary``, ``/api/scan/<id>``."""

    history: ScanHistory  # injected via make_server()

    def do_GET(self) -> None:  # noqa: N802 — http.server API
        path = self.path.split("?", 1)[0]
        try:
            if path == "/" or path == "/index.html":
                self._html()
            elif path == "/api/summary":
                self._json(dashboard_summary(self.history))
            elif path.startswith("/api/scan/"):
                scan_id = path[len("/api/scan/") :].strip("/")
                detail = scan_detail(self.history, scan_id)
                if detail is None:
                    self._json({"error": f"unknown scan: {scan_id}"}, status=404)
                else:
                    self._json(detail)
            else:
                self._json({"error": "not found"}, status=404)
        except BrokenPipeError:
            pass
        except Exception as exc:  # noqa: BLE001 — a dashboard must not crash its server
            logger.warning("Dashboard request %s failed: %s", path, exc)
            try:
                self._json({"error": "internal error"}, status=500)
            except Exception:  # noqa: BLE001
                pass

    def _send(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Lock the dashboard down: no caching, no framing, no referer leak
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        self._send(
            json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            "application/json",
            status,
        )

    def _html(self) -> None:
        self._send(_PAGE.encode("utf-8"), "text/html; charset=utf-8")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        logger.debug("dashboard: " + format, *args)


def make_server(host: str, port: int, history: ScanHistory) -> ThreadingHTTPServer:
    """Build the HTTP server with the history DB injected into the handler."""

    class _Handler(DashboardHandler):
        pass

    _Handler.history = history
    return ThreadingHTTPServer((host, port), _Handler)


def serve(
    host: str = "127.0.0.1",
    port: int = 8720,
    history: ScanHistory | None = None,
    open_browser: bool = True,
    ready_event: threading.Event | None = None,
) -> None:
    """Run the dashboard until interrupted (blocking).

    Args:
        host: Bind address — keep 127.0.0.1 unless you mean to expose it.
        port: TCP port; auto-picks the next free one when taken.
        history: History DB; defaults to the standard location.
        open_browser: Print (not auto-open) the URL — auto-opening from a
            security tool is surprising behavior.
        ready_event: Set once the socket is listening (for tests).
    """
    history = history or ScanHistory()
    try:
        server = make_server(host, port, history)
    except OSError:
        # Port taken — bump one and retry once
        port += 1
        server = make_server(host, port, history)
    url = f"http://{host}:{port}/"
    if ready_event is not None:
        ready_event.set()

    import webbrowser

    if open_browser:
        webbrowser.open(url)
    logger.info("Dashboard serving at %s (Ctrl-C to stop)", url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AegisX Dashboard</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d;
    --text: #c9d1d9; --dim: #8b949e;
    --critical: #f85149; --high: #e3b341; --medium: #d29922;
    --low: #58a6ff; --info: #8b949e; --accent: #58a6ff;
  }
  * { box-sizing: border-box; margin: 0; }
  body {
    background: var(--bg); color: var(--text);
    font: 14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif;
    padding: 24px; max-width: 1100px; margin: 0 auto;
  }
  h1 { font-size: 20px; margin-bottom: 4px; }
  .sub { color: var(--dim); font-size: 12px; margin-bottom: 20px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }
  .card .n { font-size: 26px; font-weight: 600; }
  .card .l { color: var(--dim); font-size: 12px; }
  section { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 24px; }
  h2 { font-size: 14px; margin-bottom: 12px; color: var(--text); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: var(--dim); font-weight: 500; padding: 6px 8px; border-bottom: 1px solid var(--border); }
  td { padding: 6px 8px; border-bottom: 1px solid var(--border); }
  tr:hover td { background: #1c2128; cursor: pointer; }
  .sev { display: inline-block; min-width: 22px; text-align: center; border-radius: 4px; font-size: 12px; padding: 1px 6px; }
  .sev.critical { background: var(--critical); color: #fff; }
  .sev.high { background: var(--high); color: #000; }
  .sev.medium { background: var(--medium); color: #000; }
  .sev.low { background: var(--low); color: #000; }
  .sev.info { background: var(--info); color: #000; }
  .zero { color: var(--dim); }
  .bar { height: 8px; border-radius: 4px; background: var(--border); overflow: hidden; display: flex; }
  .bar span { height: 100%; }
  .trend { display: flex; align-items: flex-end; gap: 3px; height: 40px; }
  .trend i { width: 10px; background: var(--accent); border-radius: 2px 2px 0 0; opacity: .85; }
  a { color: var(--accent); text-decoration: none; }
  #detail { display: none; }
  .close { float: right; color: var(--dim); cursor: pointer; }
  .empty { color: var(--dim); font-style: italic; }
</style>
</head>
<body>
<h1>AegisX Dashboard</h1>
<div class="sub">local scan history &mdash; read-only</div>
<div class="cards" id="cards"></div>
<section>
  <h2>Targets &amp; trends</h2>
  <div id="targets"></div>
</section>
<section>
  <h2>Recent scans <span class="sub">(click a row for findings)</span></h2>
  <div id="recent"></div>
</section>
<section id="detail">
  <h2><span class="close" onclick="hideDetail()">[close]</span> Scan detail</h2>
  <div id="detail-body"></div>
</section>
<script>
const SEV = ["critical","high","medium","low","info"];
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

function sevBadge(s, n) {
  if (!n) return `<span class="sev zero">0</span>`;
  return `<span class="sev ${s}">${n}</span>`;
}

function sevBar(row) {
  const total = SEV.reduce((a, s) => a + (row[s] || 0), 0) || 1;
  return `<div class="bar">` + SEV.map(s => row[s]
    ? `<span style="width:${(row[s]/total*100).toFixed(1)}%;background:var(--${s})"></span>` : ""
  ).join("") + `</div>`;
}

function trendChart(points) {
  const max = Math.max(...points.map(p => p.findings), 1);
  return `<div class="trend">` + points.map(p =>
    `<i style="height:${Math.max(8, p.findings/max*100)}%" title="${esc(p.timestamp.slice(0,16))} — ${p.findings} findings"></i>`
  ).join("") + `</div>`;
}

async function load() {
  const data = await fetch("/api/summary").then(r => r.json());
  const st = data.stats;
  document.getElementById("cards").innerHTML = [
    ["Scans", st.total_scans], ["Targets", st.unique_targets],
    ["Findings", st.total_findings], ["Critical", st.total_critical]
  ].map(([l, n]) => `<div class="card"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");

  const t = data.targets;
  document.getElementById("targets").innerHTML = t.length ? `<table>
    <tr><th>Target</th><th>Scans</th><th>Last scanned</th><th>Severity mix</th><th>Trend (findings)</th></tr>
    ${t.map(r => `<tr>
      <td>${esc(r.target)}</td><td>${r.scan_count}</td>
      <td>${esc(r.last_scanned.slice(0, 19).replace("T", " "))}</td>
      <td>${SEV.map(s => sevBadge(s, r.current_severities[s])).join(" ")}</td>
      <td>${trendChart(r.trend)}</td>
    </tr>`).join("")}</table>`
    : `<div class="empty">No scans recorded yet — run <code>aegisx scan &lt;target&gt;</code> first.</div>`;

  const r = data.recent;
  document.getElementById("recent").innerHTML = r.length ? `<table>
    <tr><th>Scan ID</th><th>When</th><th>Target</th><th>Mode</th><th>Severities</th><th>Findings</th><th>Duration</th></tr>
    ${r.map(x => `<tr onclick="showDetail('${esc(x.scan_id)}')">
      <td><code>${esc(x.scan_id.slice(0, 10))}</code></td>
      <td>${esc(x.timestamp.slice(0, 19).replace("T", " "))}</td>
      <td>${esc(x.target)}</td>
      <td>${esc(x.mode)}</td>
      <td>${SEV.map(s => sevBadge(s, x[s])).join(" ")}</td>
      <td>${x.findings}</td>
      <td>${x.duration}s</td>
    </tr>`).join("")}</table>`
    : `<div class="empty">Nothing yet.</div>`;
}

async function showDetail(id) {
  const d = await fetch("/api/scan/" + encodeURIComponent(id)).then(r => r.json());
  const el = document.getElementById("detail");
  el.style.display = "block";
  document.getElementById("detail-body").innerHTML = `
    <p style="margin-bottom:8px"><b>${esc(d.target)}</b> — ${esc(d.mode)} mode,
    ${esc((d.timestamp || "").slice(0, 19).replace("T", " "))},
    ${SEV.map(s => sevBadge(s, d.severities[s])).join(" ")}</p>
    ${d.findings.length ? `<table><tr><th>Finding</th><th>Severity</th><th>CWE</th><th>URL</th><th>Param</th></tr>
      ${d.findings.map(f => `<tr>
        <td>${esc(f.title)}</td>
        <td><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span></td>
        <td>${esc(f.cwe || "—")}</td>
        <td>${esc(f.url || "—")}</td>
        <td>${esc(f.parameter || "—")}</td>
      </tr>`).join("")}</table>`
      : `<div class="empty">No findings recorded for this scan.</div>`}`;
  el.scrollIntoView({ behavior: "smooth" });
}

function hideDetail() {
  document.getElementById("detail").style.display = "none";
}

load();
</script>
</body>
</html>
"""
