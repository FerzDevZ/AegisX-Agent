"""Tests for report generation modules.

Covers Markdown, JSON, SARIF, and HTML reporters with
happy-path and edge-case (empty findings) scenarios.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from aegisx.core.context import ScanContext
from aegisx.reporters.html_reporter import HTMLReporter
from aegisx.reporters.json_reporter import JSONReporter
from aegisx.reporters.markdown_reporter import MarkdownReporter
from aegisx.reporters.sarif_reporter import SARIFReporter


@pytest.fixture
def empty_context(config) -> ScanContext:
    """Scan context with no findings."""
    return ScanContext(config=config, target_url=config.target_url)


@pytest.fixture
def finding_context(config, sqli_finding, xss_finding) -> ScanContext:
    """Scan context populated with sample findings."""
    ctx = ScanContext(config=config, target_url=config.target_url)
    ctx.add_finding(sqli_finding)
    ctx.add_finding(xss_finding)
    return ctx


class TestMarkdownReporter:
    """Test Markdown report generation."""

    def test_generates_valid_markdown(self, finding_context):
        reporter = MarkdownReporter(finding_context)
        content = reporter.generate()

        assert "# Aegisx-Agent Scan Report" in content or "Aegisx" in content
        assert "SQL Injection" in content
        assert "test.example.com" in content

    def test_empty_findings(self, empty_context):
        reporter = MarkdownReporter(empty_context)
        content = reporter.generate()
        assert content  # Should still produce a report
        assert "0" in content  # Summary shows zero findings

    def test_save_writes_file(self, finding_context):
        reporter = MarkdownReporter(finding_context)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = reporter.save(Path(tmpdir))
            assert path.exists()
            assert path.suffix == ".md"
            assert path.stat().st_size > 0


class TestJSONReporter:
    """Test JSON report generation."""

    def test_generates_valid_json(self, finding_context):
        reporter = JSONReporter(finding_context)
        content = reporter.generate()

        data = json.loads(content)  # Must be valid JSON
        assert data["target_url"] == "https://test.example.com"
        assert data["stats"]["total_findings"] == 2
        assert len(data["findings"]) == 2

    def test_empty_findings(self, empty_context):
        reporter = JSONReporter(empty_context)
        data = json.loads(reporter.generate())
        assert data["stats"]["total_findings"] == 0
        assert data["findings"] == []

    def test_finding_fields_present(self, finding_context):
        reporter = JSONReporter(finding_context)
        data = json.loads(reporter.generate())
        finding = data["findings"][0]
        assert "id" in finding
        assert "severity" in finding
        assert "title" in finding


class TestSARIFReporter:
    """Test SARIF v2.1.0 report generation."""

    def test_valid_sarif_structure(self, finding_context):
        reporter = SARIFReporter(finding_context)
        content = reporter.generate()
        data = json.loads(content)

        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1

        run = data["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert len(run["results"]) == 2

    def test_sarif_rules_from_findings(self, finding_context):
        reporter = SARIFReporter(finding_context)
        data = json.loads(reporter.generate())

        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2  # One rule per unique finding type

    def test_empty_findings(self, empty_context):
        reporter = SARIFReporter(empty_context)
        data = json.loads(reporter.generate())
        run = data["runs"][0]
        assert run["results"] == []

    def test_sarif_severity_mapping(self, finding_context):
        reporter = SARIFReporter(finding_context)
        data = json.loads(reporter.generate())

        results = data["runs"][0]["results"]
        for result in results:
            assert "level" in result
            assert result["level"] in {"error", "warning", "note", "none"}


class TestHTMLReporter:
    """Test HTML report generation."""

    def test_generates_valid_html(self, finding_context):
        reporter = HTMLReporter(finding_context)
        content = reporter.generate()

        assert "<!DOCTYPE html>" in content or "<html" in content
        assert "SQL Injection" in content

    def test_html_escapes_user_content(self, empty_context, sqli_finding):
        sqli_finding.title = "<script>alert(1)</script>"
        ctx = ScanContext(config=empty_context.config, target_url=empty_context.target_url)
        ctx.add_finding(sqli_finding)

        reporter = HTMLReporter(ctx)
        content = reporter.generate()
        # Raw <script> must not appear un-escaped in the report body
        assert "<script>alert(1)</script>" not in content

    def test_empty_findings(self, empty_context):
        reporter = HTMLReporter(empty_context)
        content = reporter.generate()
        assert "<html" in content

    def test_save_writes_html_file(self, finding_context):
        reporter = HTMLReporter(finding_context)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = reporter.save(Path(tmpdir))
            assert path.exists()
            assert path.suffix == ".html"
            assert path.stat().st_size > 0


class TestReporterRegistration:
    """Reporters must be discoverable by the plugin manager."""

    def test_format_names_unique(self):
        names = {
            MarkdownReporter.format_name,
            JSONReporter.format_name,
            SARIFReporter.format_name,
            HTMLReporter.format_name,
        }
        assert len(names) == 4

    def test_file_extensions(self):
        assert MarkdownReporter.file_extension == ".md"
        assert JSONReporter.file_extension == ".json"
        assert SARIFReporter.file_extension == ".sarif"
        assert HTMLReporter.file_extension == ".html"
