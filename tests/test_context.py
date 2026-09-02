"""Tests for scan context, findings, and exploit results."""

from __future__ import annotations

import pytest

from aegisx.core.config import AegisxConfig, Severity
from aegisx.core.context import (
    ExploitResult,
    Finding,
    ScanContext,
    ScanStats,
)


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self) -> None:
        """Finding has required fields and auto-generated id."""
        f = Finding(title="SQL Injection", severity=Severity.CRITICAL)
        assert f.title == "SQL Injection"
        assert f.severity == Severity.CRITICAL
        assert f.id.startswith("VF-")
        assert len(f.id) == 12  # VF- + 8 hex chars

    def test_finding_severity_order(self) -> None:
        """severity_order returns correct numeric values."""
        assert Finding(severity=Severity.CRITICAL).severity_order == 5
        assert Finding(severity=Severity.HIGH).severity_order == 4
        assert Finding(severity=Severity.MEDIUM).severity_order == 3
        assert Finding(severity=Severity.LOW).severity_order == 2
        assert Finding(severity=Severity.INFO).severity_order == 1

    def test_finding_defaults(self) -> None:
        """Finding has sensible defaults."""
        f = Finding()
        assert f.cvss_score == 0.0
        assert f.cwe_id == ""
        assert f.references == []
        assert f.raw_data == {}
        assert f.timestamp != ""


class TestExploitResult:
    """Tests for ExploitResult dataclass."""

    def test_exploit_result_creation(self) -> None:
        r = ExploitResult(
            finding_id="VF-001",
            exploit_name="sqli_exploit",
            success=True,
            payload="' OR 1=1--",
            evidence="Full table dumped",
        )
        assert r.finding_id == "VF-001"
        assert r.success is True
        assert r.payload == "' OR 1=1--"

    def test_exploit_result_failure(self) -> None:
        r = ExploitResult(
            finding_id="VF-002",
            exploit_name="xss_exploit",
            success=False,
            evidence="Payload not reflected",
        )
        assert r.success is False


class TestScanContext:
    """Tests for ScanContext state management."""

    def test_context_creation(self, config: AegisxConfig) -> None:
        ctx = ScanContext(config=config, target_url="https://test.com")
        assert ctx.target_url == "https://test.com"
        assert ctx.scan_id != ""
        assert ctx.findings == []
        assert ctx.exploit_results == []

    def test_add_finding(self, context: ScanContext) -> None:
        """Adding a finding registers it in context."""
        f = Finding(title="XSS", severity=Severity.HIGH)
        context.add_finding(f)
        assert len(context.findings) == 1
        assert context.findings[0].title == "XSS"

    def test_add_finding_deduplication(self, context: ScanContext) -> None:
        """Same title+endpoint is deduplicated."""
        f1 = Finding(title="XSS", endpoint="/search", severity=Severity.MEDIUM)
        f2 = Finding(title="XSS", endpoint="/search", severity=Severity.HIGH)
        context.add_finding(f1)
        context.add_finding(f2)
        assert len(context.findings) == 1
        # Severity should be upgraded
        assert context.findings[0].severity == Severity.HIGH

    def test_add_finding_different_endpoints(self, context: ScanContext) -> None:
        """Same title but different endpoints are separate findings."""
        f1 = Finding(title="XSS", endpoint="/search")
        f2 = Finding(title="XSS", endpoint="/profile")
        context.add_finding(f1)
        context.add_finding(f2)
        assert len(context.findings) == 2

    def test_add_exploit_result(self, context: ScanContext) -> None:
        r = ExploitResult(finding_id="VF-001", exploit_name="test", success=True)
        context.add_exploit_result(r)
        assert len(context.exploit_results) == 1

    def test_get_findings_by_severity(self, context: ScanContext) -> None:
        context.add_finding(Finding(title="A", severity=Severity.CRITICAL))
        context.add_finding(Finding(title="B", severity=Severity.HIGH))
        context.add_finding(Finding(title="C", severity=Severity.HIGH))
        context.add_finding(Finding(title="D", severity=Severity.LOW))

        critical = context.get_findings_by_severity(Severity.CRITICAL)
        high = context.get_findings_by_severity(Severity.HIGH)
        low = context.get_findings_by_severity(Severity.LOW)
        info = context.get_findings_by_severity(Severity.INFO)

        assert len(critical) == 1
        assert len(high) == 2
        assert len(low) == 1
        assert len(info) == 0

    def test_get_stats(self, context: ScanContext) -> None:
        context.add_finding(Finding(title="A", severity=Severity.CRITICAL, scanner_name="web"))
        context.add_finding(Finding(title="B", severity=Severity.HIGH, scanner_name="web"))
        context.add_finding(Finding(title="C", severity=Severity.HIGH, scanner_name="secret"))

        stats = context.get_stats()
        assert stats.total_findings == 3
        assert stats.critical_count == 1
        assert stats.high_count == 2
        assert stats.medium_count == 0
        assert stats.scanners_used == ["web", "secret"]

    def test_finish(self, context: ScanContext) -> None:
        context.add_finding(Finding(title="Test", severity=Severity.LOW))
        stats = context.finish()
        assert stats.total_findings == 1
        assert context.finished_at != ""

    def test_to_dict(self, context: ScanContext) -> None:
        context.add_finding(Finding(
            title="SQLi",
            severity=Severity.CRITICAL,
            cwe_id="CWE-89",
            scanner_name="web",
        ))
        context.finish()

        data = context.to_dict()
        assert "scan_id" in data
        assert data["target_url"] == "https://test.example.com"
        assert data["stats"]["total_findings"] == 1
        assert data["stats"]["critical"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["cwe_id"] == "CWE-89"

    def test_to_dict_sorted_by_severity(self, context: ScanContext) -> None:
        """Findings in to_dict are sorted by severity descending."""
        context.add_finding(Finding(title="Low", severity=Severity.LOW))
        context.add_finding(Finding(title="Critical", severity=Severity.CRITICAL))
        context.add_finding(Finding(title="Medium", severity=Severity.MEDIUM))

        data = context.to_dict()
        severances = [f["severity"] for f in data["findings"]]
        assert severances == ["critical", "medium", "low"]
