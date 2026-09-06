"""Tests for SIEM JSON export (jsonl + json formats)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisx.core.context import ScanContext
from aegisx.utils.siem_export import (
    SIEMExporter,
    context_to_events,
    export_siem,
    summary_event,
)


@pytest.fixture
def ctx(config, sqli_finding, xss_finding) -> ScanContext:
    """Populated scan context."""
    context = ScanContext(config=config, target_url=config.target_url)
    context.add_finding(sqli_finding)
    context.add_finding(xss_finding)
    context.finish()
    return context


class TestEventShape:
    def test_one_event_per_finding(self, ctx):
        events = context_to_events(ctx)
        assert len(events) == 2

    def test_event_fields_flat_and_stable(self, ctx):
        event = context_to_events(ctx)[0]
        assert event["event"]["kind"] == "alert"
        assert event["event"]["dataset"] == "aegisx.findings"
        assert event["vulnerability"]["id"] == "VF-TEST0001"
        assert event["vulnerability"]["severity"] == "critical"
        assert event["@timestamp"]

    def test_summary_event_counts(self, ctx):
        summary = summary_event(ctx)
        assert summary["event"]["kind"] == "metric"
        assert summary["vulnerability"]["total"] == 2
        assert summary["vulnerability"]["by_severity"]["critical"] == 1

    def test_info_severity_normalized(self, ctx, xss_finding):
        from aegisx.core.config import Severity

        xss_finding.severity = Severity.INFO
        events = context_to_events(ctx)
        assert events[-1]["event"]["severity"] == "informational"


class TestWrite:
    def test_jsonl_output(self, ctx, tmp_path: Path):
        out = export_siem(ctx, tmp_path / "events.jsonl", fmt="jsonl")
        lines = out.read_text().strip().split("\n")
        assert len(lines) == 3  # 1 summary + 2 findings
        for line in lines:
            assert isinstance(json.loads(line), dict)

    def test_json_array_output(self, ctx, tmp_path: Path):
        out = export_siem(ctx, tmp_path / "events.json", fmt="json")
        data = json.loads(out.read_text())
        assert isinstance(data, list)
        assert len(data) == 3

    def test_no_summary_option(self, ctx, tmp_path: Path):
        exporter = SIEMExporter(ctx, include_summary=False)
        events = exporter.build_events()
        assert len(events) == 2

    def test_invalid_format_raises(self, ctx, tmp_path: Path):
        exporter = SIEMExporter(ctx)
        with pytest.raises(ValueError, match="Unknown SIEM export format"):
            exporter.write(tmp_path / "x.txt", fmt="xml")
