"""Shared test fixtures for Aegisx-Agent test suite."""

from __future__ import annotations

import pytest

from aegisx.core.config import AegisxConfig, ReportFormat, ScanMode, Severity
from aegisx.core.context import ExploitResult, Finding, ScanContext


@pytest.fixture
def config() -> AegisxConfig:
    """Default test configuration."""
    return AegisxConfig(
        target_url="https://test.example.com",
        scan_mode=ScanMode.QUICK,
        report_format=ReportFormat.MARKDOWN,
        timeout_seconds=5,
        user_agent="AegisxTest/0.1.0",
    )


@pytest.fixture
def context(config: AegisxConfig) -> ScanContext:
    """Default test scan context."""
    return ScanContext(config=config, target_url=config.target_url)


@pytest.fixture
def sqli_finding() -> Finding:
    """A sample SQL Injection finding."""
    return Finding(
        id="VF-TEST0001",
        title="SQL Injection",
        description="Parameter 'q' is vulnerable to SQL injection.",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cwe_id="CWE-89",
        owasp_category="A03:2021",
        url="https://test.example.com/search",
        endpoint="/search",
        method="GET",
        parameter="q",
        evidence="SQL syntax error in response",
        payload="' OR '1'='1",
        remediation="Use parameterized queries.",
        references=["https://cwe.mitre.org/data/definitions/89.html"],
        scanner_name="web_scanner",
    )


@pytest.fixture
def xss_finding() -> Finding:
    """A sample XSS finding."""
    return Finding(
        id="VF-TEST0002",
        title="Cross-Site Scripting (XSS)",
        description="Parameter 'name' reflects user input without encoding.",
        severity=Severity.HIGH,
        cvss_score=7.1,
        cwe_id="CWE-79",
        owasp_category="A03:2021",
        url="https://test.example.com/profile",
        endpoint="/profile",
        method="POST",
        parameter="name",
        evidence="<script>alert(1)</script> found in response",
        payload="<script>alert(1)</script>",
        remediation="Encode all output.",
        references=["https://cwe.mitre.org/data/definitions/79.html"],
        scanner_name="web_scanner",
    )


@pytest.fixture
def missing_header_finding() -> Finding:
    """A sample missing security header finding."""
    return Finding(
        id="VF-TEST0003",
        title="Missing HSTS Header",
        description="Strict-Transport-Security header is not set.",
        severity=Severity.MEDIUM,
        cwe_id="CWE-319",
        owasp_category="A05:2021",
        url="https://test.example.com",
        endpoint="/",
        method="GET",
        remediation="Add HSTS header.",
        scanner_name="config_scanner",
    )


@pytest.fixture
def secret_finding() -> Finding:
    """A sample exposed secret finding."""
    return Finding(
        id="VF-TEST0004",
        title="Exposed AWS Access Key",
        description="AWS key found in response body.",
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        cwe_id="CWE-798",
        owasp_category="A07:2021",
        url="https://test.example.com/config",
        evidence="AKIAIOSFODNN7EXAMPLE",
        scanner_name="secret_scanner",
    )


@pytest.fixture
def info_finding() -> Finding:
    """A sample info-level finding."""
    return Finding(
        id="VF-TEST0005",
        title="Server Version Disclosure",
        description="Server header reveals version.",
        severity=Severity.LOW,
        cwe_id="CWE-200",
        owasp_category="A05:2021",
        url="https://test.example.com",
        evidence="Server: nginx/1.18.0",
        scanner_name="web_scanner",
    )
