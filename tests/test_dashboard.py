"""Tests for the local web dashboard (aggregation + HTTP surface).

The server is started on an ephemeral port against a temp history DB —
no fixed ports, no real data touched.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from aegisx.core.context import ScanStats
from aegisx.dashboard import dashboard_summary, make_server, scan_detail
from aegisx.utils.history import ScanHistory


@pytest.fixture()
def history(tmp_path):
    """A history DB seeded with two targets and a few scans."""
    db = ScanHistory(db_path=tmp_path / "history.db")
    seeds = [
        # (scan_id, target, findings, critical, high, medium, low, info)
        ("s1", "https://old.example.com", 5, 0, 1, 2, 2, 0),
        ("s2", "https://old.example.com", 3, 0, 0, 1, 2, 0),
        ("s3", "https://live.example.com", 1, 1, 0, 0, 0, 0),
    ]
    for scan_id, target, total, crit, high, med, low, info in seeds:
        stats = ScanStats(
            total_findings=total,
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            info_count=info,
            scan_duration_seconds=4.2,
            scanners_used=["web_scanner"],
        )
        findings = []
        if total:
            findings.append(
                {
                    "id": f"VF-{scan_id}",
                    "title": f"Finding for {scan_id}",
                    "severity": "high" if high else ("critical" if crit else "medium"),
                    "cwe_id": "CWE-79",
                    "url": f"{target}/vulnerable",
                    "parameter": "q",
                }
            )
        db.record_scan(scan_id, target, "quick", stats, findings)
    return db


@pytest.fixture()
def server(history):
    """A dashboard server on 127.0.0.1 with an ephemeral port."""
    srv = make_server("127.0.0.1", 0, history)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _get(url: str) -> tuple[int, bytes]:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, resp.read()


class TestAggregation:
    def test_summary_shape(self, history):
        data = dashboard_summary(history)
        assert data["stats"]["total_scans"] == 3
        assert data["stats"]["unique_targets"] == 2
        assert data["stats"]["total_findings"] == 9
        assert data["stats"]["total_critical"] == 1

    def test_targets_sorted_by_scan_count(self, history):
        data = dashboard_summary(history)
        assert data["targets"][0]["target"] == "https://old.example.com"
        assert data["targets"][0]["scan_count"] == 2
        # trend is oldest-first, capped
        trend = data["targets"][0]["trend"]
        assert [t["scan_id"] for t in trend] == ["s1", "s2"]
        assert trend[-1]["findings"] == 3

    def test_recent_newest_first(self, history):
        data = dashboard_summary(history)
        assert data["recent"][0]["scan_id"] == "s3"

    def test_scan_detail_lists_findings(self, history):
        detail = scan_detail(history, "s1")
        assert detail is not None
        assert detail["severities"]["high"] == 1
        assert detail["findings"][0]["title"] == "Finding for s1"
        assert detail["findings"][0]["cwe"] == "CWE-79"

    def test_scan_detail_unknown_id(self, history):
        assert scan_detail(history, "nope") is None


class TestHTTP:
    def test_index_serves_html_with_security_headers(self, server):
        port = server.server_address[1]
        req = urllib.request.Request(f"http://127.0.0.1:{port}/")
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode()
            headers = resp.headers
        assert "AegisX Dashboard" in body
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["Cache-Control"] == "no-store"

    def test_api_summary(self, server):
        port = server.server_address[1]
        status, body = _get(f"http://127.0.0.1:{port}/api/summary")
        assert status == 200
        data = json.loads(body)
        assert data["stats"]["total_scans"] == 3
        assert any(t["target"] == "https://live.example.com" for t in data["targets"])

    def test_api_scan_detail(self, server):
        port = server.server_address[1]
        status, body = _get(f"http://127.0.0.1:{port}/api/scan/s3")
        assert status == 200
        data = json.loads(body)
        assert data["severities"]["critical"] == 1

    def test_api_scan_unknown_returns_404(self, server):
        port = server.server_address[1]
        try:
            _get(f"http://127.0.0.1:{port}/api/scan/ghost")
            raised = False
        except urllib.error.HTTPError as exc:
            raised = exc.code == 404
        assert raised, "unknown scan must 404"

    def test_unknown_path_returns_404(self, server):
        port = server.server_address[1]
        try:
            _get(f"http://127.0.0.1:{port}/nope")
            raised = False
        except urllib.error.HTTPError as exc:
            raised = exc.code == 404
        assert raised

    def test_no_write_endpoints(self, server):
        port = server.server_address[1]
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/summary",
            data=b"{}",
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            raised = False
        except urllib.error.HTTPError as exc:
            raised = exc.code == 501
        assert raised, "POST must be rejected — the API is read-only"


class TestEmptyHistory:
    def test_summary_on_empty_db(self, tmp_path):
        db = ScanHistory(db_path=tmp_path / "empty.db")
        data = dashboard_summary(db)
        assert data["stats"]["total_scans"] == 0
        assert data["targets"] == []
        assert data["recent"] == []
