"""Tests for SQLite scan history and SIEM JSON export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisx.core.context import ScanStats
from aegisx.utils.history import ScanHistory


@pytest.fixture
def history(tmp_path: Path) -> ScanHistory:
    """History database in a temp directory."""
    return ScanHistory(db_path=tmp_path / "history.db")


@pytest.fixture
def stats() -> ScanStats:
    return ScanStats(
        total_findings=3,
        critical_count=1,
        high_count=1,
        medium_count=1,
        low_count=0,
        info_count=0,
        scan_duration_seconds=12.5,
        scanners_used=["web_scanner", "secret_scanner"],
    )


class TestRecordAndList:
    def test_record_scan_persists(self, history, stats):
        history.record_scan("scan-001", "https://a.com", "quick", stats)
        scans = history.get_scans()
        assert len(scans) == 1
        assert scans[0]["scan_id"] == "scan-001"
        assert scans[0]["target"] == "https://a.com"
        assert scans[0]["critical"] == 1

    def test_filter_by_target(self, history, stats):
        history.record_scan("scan-001", "https://a.com", "quick", stats)
        history.record_scan("scan-002", "https://b.com", "full", stats)
        assert len(history.get_scans()) == 2
        assert len(history.get_scans(target="https://a.com")) == 1
        assert history.get_scans(target="https://a.com")[0]["scan_id"] == "scan-001"

    def test_limit(self, history, stats):
        for i in range(5):
            history.record_scan(f"scan-{i:03d}", "https://a.com", "quick", stats)
        assert len(history.get_scans(limit=3)) == 3

    def test_invalid_db_path_never_raises_on_record(self, tmp_path, stats):
        # Point at a directory — connection will fail, record must not raise
        bad = ScanHistory(db_path=tmp_path / "a" / "history.db")
        bad.record_scan("x", "https://a.com", "quick", stats)  # parent created, fine
        # Truly broken: db path is a directory itself
        bad2 = ScanHistory(db_path=tmp_path)
        bad2.record_scan("y", "https://a.com", "quick", stats)  # must not raise


class TestGetScan:
    def test_get_scan_with_findings(self, history, stats):
        findings = [{"title": "SQLi", "severity": "critical", "url": "https://a.com/x"}]
        history.record_scan("scan-001", "https://a.com", "full", stats, findings)
        record = history.get_scan("scan-001")
        assert record is not None
        assert record["findings"] == findings

    def test_get_scan_missing_returns_none(self, history):
        assert history.get_scan("nonexistent") is None


class TestCompare:
    def test_compare_detects_new_and_resolved(self, history, stats):
        old_findings = [
            {"title": "OldSQLi", "severity": "critical", "url": "https://a.com/x"},
            {"title": "OldXSS", "severity": "high", "url": "https://a.com/y"},
        ]
        new_findings = [
            {"title": "OldSQLi", "severity": "critical", "url": "https://a.com/x"},
            {"title": "NewSSRF", "severity": "medium", "url": "https://a.com/z"},
        ]
        history.record_scan("old", "https://a.com", "full", stats, old_findings)
        history.record_scan("new", "https://a.com", "full", stats, new_findings)

        diff = history.compare_scans("old", "new")
        assert [f["title"] for f in diff["new_findings"]] == ["NewSSRF"]
        assert [f["title"] for f in diff["resolved_findings"]] == ["OldXSS"]
        assert diff["severity_delta"]["critical"] == 0

    def test_compare_missing_scan_raises(self, history, stats):
        history.record_scan("a", "https://a.com", "quick", stats)
        with pytest.raises(ValueError):
            history.compare_scans("a", "missing")


class TestExportAndSummary:
    def test_export_json(self, history, stats, tmp_path):
        history.record_scan("scan-001", "https://a.com", "quick", stats)
        out = history.export_json(tmp_path / "export.json")
        data = json.loads(out.read_text())
        assert len(data) == 1
        assert data[0]["scan_id"] == "scan-001"

    def test_stats_summary(self, history, stats):
        history.record_scan("scan-001", "https://a.com", "quick", stats)
        history.record_scan("scan-002", "https://b.com", "full", stats)
        summary = history.stats_summary()
        assert summary["total_scans"] == 2
        assert summary["unique_targets"] == 2
        assert summary["total_findings"] == 6
        assert summary["total_critical"] == 2

    def test_wal_mode_enabled(self, history):
        conn = history._connect()
        try:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            conn.close()
        assert mode == "wal"


class TestOrchestratorIntegration:
    """Scan pipeline must write history automatically."""

    @pytest.mark.asyncio
    async def test_scan_records_history(self, tmp_path: Path):
        import httpx
        import respx

        from aegisx.core.config import AegisxConfig, ScanMode
        from aegisx.core.orchestrator import AegisxOrchestrator

        config = AegisxConfig(
            target_url="https://test.example.com",
            scan_mode=ScanMode.QUICK,
            enabled_scanners=[],
            exploit_verification=False,
            report_output=tmp_path,
        )

        with respx.mock:
            respx.get("https://test.example.com").mock(
                return_value=httpx.Response(200, text="<html></html>")
            )
            orch = AegisxOrchestrator(config)
            await orch.run()

        db = ScanHistory(db_path=tmp_path / "history.db")
        scans = db.get_scans()
        assert len(scans) == 1
        assert scans[0]["target"] == "https://test.example.com"
