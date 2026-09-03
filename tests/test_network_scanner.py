"""Unit tests for the network scanner module.

Tests port scanning, service detection, SSL analysis, and dangerous service identification.
"""

from __future__ import annotations

import pytest

from aegisx.core.config import AegisxConfig
from aegisx.core.context import ScanContext, Severity
from aegisx.scanners.network_scanner import (
    COMMON_PORTS,
    DANGEROUS_SERVICES,
    NetworkScanner,
    PortResult,
)


@pytest.fixture
def config() -> AegisxConfig:
    return AegisxConfig(target_url="https://test.example.com")


@pytest.fixture
def context(config: AegisxConfig) -> ScanContext:
    return ScanContext(config=config, target_url=config.target_url)


@pytest.fixture
def scanner(context: ScanContext) -> NetworkScanner:
    return NetworkScanner(context=context)


class TestCommonPorts:
    """Test port definitions."""

    def test_common_ports_dict(self):
        assert isinstance(COMMON_PORTS, dict)
        assert len(COMMON_PORTS) >= 20
        assert 80 in COMMON_PORTS
        assert 443 in COMMON_PORTS
        assert 22 in COMMON_PORTS

    def test_dangerous_services_dict(self):
        assert isinstance(DANGEROUS_SERVICES, dict)
        assert 23 in DANGEROUS_SERVICES  # Telnet
        assert 3306 in DANGEROUS_SERVICES  # MySQL
        assert 6379 in DANGEROUS_SERVICES  # Redis
        assert 27017 in DANGEROUS_SERVICES  # MongoDB

    def test_dangerous_service_severity(self):
        """DANGEROUS_SERVICES values are tuples: (name, reason, Severity)."""
        for port, (name, reason, severity) in DANGEROUS_SERVICES.items():
            assert isinstance(name, str)
            assert isinstance(reason, str)
            assert isinstance(severity, Severity)


class TestNetworkScannerInit:
    """Test scanner initialization."""

    def test_init(self, scanner):
        assert scanner is not None
        assert scanner.name == "network_scanner"

    @pytest.mark.asyncio
    async def test_validate_target_returns_bool(self, scanner):
        """validate_target() returns a boolean."""
        result = await scanner.validate_target()
        assert isinstance(result, bool)


class TestPortResult:
    """Test PortResult dataclass."""

    def test_port_result_creation(self):
        result = PortResult(
            port=80,
            is_open=True,
            service="HTTP",
            banner="nginx",
        )
        assert result.port == 80
        assert result.is_open is True
        assert result.service == "HTTP"
        assert result.banner == "nginx"

    def test_port_result_defaults(self):
        result = PortResult(port=9999, is_open=False)
        assert result.is_open is False
        assert result.service == ""
        assert result.banner == ""


class TestDangerousServices:
    """Test dangerous service detection."""

    def test_telnet_is_critical(self):
        name, reason, severity = DANGEROUS_SERVICES[23]
        assert severity == Severity.CRITICAL
        assert "plaintext" in reason.lower() or "credential" in reason.lower()

    def test_redis_is_critical(self):
        name, reason, severity = DANGEROUS_SERVICES[6379]
        assert severity == Severity.CRITICAL

    def test_mysql_exposed_is_critical(self):
        name, reason, severity = DANGEROUS_SERVICES[3306]
        assert severity == Severity.CRITICAL

    def test_ftp_severity(self):
        name, reason, severity = DANGEROUS_SERVICES[21]
        assert severity in [Severity.HIGH, Severity.CRITICAL]


class TestPortCVSS:
    """Test CVSS score calculation for ports."""

    def test_calculate_port_cvss_critical_port(self):
        score = NetworkScanner._calculate_port_cvss(23)
        assert score >= 7.0

    def test_calculate_port_cvss_high_port(self):
        score = NetworkScanner._calculate_port_cvss(21)
        assert score >= 4.0

    def test_calculate_port_cvss_unknown_port(self):
        score = NetworkScanner._calculate_port_cvss(9999)
        assert score <= 4.0


class TestSSLAnalysis:
    """Test SSL/TLS certificate analysis."""

    def test_analyze_certificate_cn_matches(self, scanner):
        # SSL cert subject format: ((('commonName', 'example.com'),),)
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Let's Encrypt"),),),
            "notAfter": "Sep  3 00:00:00 2027 GMT",
        }
        findings = scanner._analyze_certificate(cert, "example.com")
        assert not any("CN" in f.title or "mismatch" in f.title.lower() for f in findings)

    def test_analyze_certificate_cn_mismatch(self, scanner):
        cert = {
            "subject": ((("commonName", "other.com"),),),
            "issuer": ((("commonName", "Let's Encrypt"),),),
            "notAfter": "Sep  3 00:00:00 2027 GMT",
        }
        findings = scanner._analyze_certificate(cert, "example.com")
        assert any("CN" in f.title or "mismatch" in f.title.lower() for f in findings)

    def test_analyze_certificate_expired(self, scanner):
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Let's Encrypt"),),),
            "notAfter": "Jan  1 00:00:00 2020 GMT",
        }
        findings = scanner._analyze_certificate(cert, "example.com")
        assert any("expir" in f.title.lower() or "Expiry" in f.title for f in findings)
