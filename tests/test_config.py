"""Tests for core configuration (AegisxConfig)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegisx.core.config import (
    AegisxConfig,
    ReportFormat,
    ScanMode,
    Severity,
    load_config,
)


class TestAegisxConfig:
    """Tests for AegisxConfig."""

    def test_default_config(self) -> None:
        """Config has sensible defaults."""
        config = AegisxConfig()
        assert config.scan_mode == ScanMode.QUICK
        assert config.max_depth == 3
        assert config.timeout_seconds == 30
        assert config.exploit_verification is False
        assert config.sandbox_enabled is True
        assert config.report_format == ReportFormat.MARKDOWN
        assert config.verbose is False

    def test_custom_config(self) -> None:
        """Config accepts custom values."""
        config = AegisxConfig(
            target_url="https://example.com",
            scan_mode=ScanMode.FULL,
            max_depth=5,
            timeout_seconds=60,
            exploit_verification=True,
        )
        assert config.target_url == "https://example.com"
        assert config.scan_mode == ScanMode.FULL
        assert config.max_depth == 5
        assert config.timeout_seconds == 60
        assert config.exploit_verification is True

    def test_load_config_with_overrides(self) -> None:
        """load_config accepts keyword overrides."""
        config = load_config(target_url="https://override.com", scan_mode="passive")
        assert config.target_url == "https://override.com"
        assert config.scan_mode == ScanMode.PASSIVE

    def test_scope_validation_rejects_urls(self) -> None:
        """Scope entries must be domains, not full URLs."""
        with pytest.raises(ValidationError, match="domains, not full URLs"):
            AegisxConfig(scope=["https://example.com"])

    def test_scope_validation_accepts_domains(self) -> None:
        """Scope entries can be bare domains."""
        config = AegisxConfig(scope=["example.com", "api.example.com"])
        assert config.scope == ["example.com", "api.example.com"]

    def test_is_in_scope_no_scope(self) -> None:
        """Without explicit scope, only the target domain is in scope."""
        config = AegisxConfig(target_url="https://example.com")
        assert config.is_in_scope("https://example.com/page") is True
        assert config.is_in_scope("https://other.com/page") is False

    def test_is_in_scope_with_scope(self) -> None:
        """With explicit scope, domains must match."""
        config = AegisxConfig(
            target_url="https://example.com",
            scope=["example.com", "api.example.com"],
        )
        assert config.is_in_scope("https://example.com/page") is True
        assert config.is_in_scope("https://api.example.com/data") is True
        assert config.is_in_scope("https://evil.com/steal") is False
        assert config.is_in_scope("https://notexample.com/page") is False

    def test_is_in_scope_subdomain(self) -> None:
        """Subdomains of scoped domains are in scope."""
        config = AegisxConfig(
            target_url="https://example.com",
            scope=["example.com"],
        )
        assert config.is_in_scope("https://sub.example.com/page") is True

    def test_get_auth_headers_no_token(self) -> None:
        """No token means no auth headers."""
        config = AegisxConfig()
        assert config.get_auth_headers() == {}

    def test_get_auth_headers_with_token(self) -> None:
        """Token is added as Bearer auth header."""
        config = AegisxConfig(auth_token="my-secret-token")
        headers = config.get_auth_headers()
        assert headers == {"Authorization": "Bearer my-secret-token"}

    def test_get_auth_headers_already_bearer(self) -> None:
        """Token that already starts with 'bearer' is not double-prefixed."""
        config = AegisxConfig(auth_token="Bearer already-token")
        headers = config.get_auth_headers()
        assert headers == {"Authorization": "Bearer already-token"}

    def test_max_depth_bounds(self) -> None:
        """max_depth must be between 1 and 10."""
        with pytest.raises(ValidationError):
            AegisxConfig(max_depth=0)
        with pytest.raises(ValidationError):
            AegisxConfig(max_depth=11)
        config = AegisxConfig(max_depth=1)
        assert config.max_depth == 1

    def test_rate_limit_bounds(self) -> None:
        """max_requests_per_second must be between 0.1 and 100."""
        with pytest.raises(ValidationError):
            AegisxConfig(max_requests_per_second=0.0)
        config = AegisxConfig(max_requests_per_second=100.0)
        assert config.max_requests_per_second == 100.0


class TestEnums:
    """Tests for enum types."""

    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_scan_mode_values(self) -> None:
        assert ScanMode.PASSIVE.value == "passive"
        assert ScanMode.QUICK.value == "quick"
        assert ScanMode.FULL.value == "full"
        assert ScanMode.STEALTH.value == "stealth"

    def test_report_format_values(self) -> None:
        assert ReportFormat.MARKDOWN.value == "markdown"
        assert ReportFormat.JSON.value == "json"
        assert ReportFormat.SARIF.value == "sarif"
        assert ReportFormat.HTML.value == "html"
        assert ReportFormat.ALL.value == "all"
