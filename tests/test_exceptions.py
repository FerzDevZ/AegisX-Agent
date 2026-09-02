"""Tests for the exception hierarchy."""

from __future__ import annotations

import pytest

from aegisx.core.exceptions import (
    AegisxError,
    ConfigError,
    ExploitError,
    ExploitSandboxError,
    KnowledgeBaseError,
    PluginError,
    RateLimitError,
    ReportError,
    ScanError,
    ScanTargetError,
    ScannerPluginError,
    ScopeError,
)


class TestExceptionHierarchy:
    """Verify exception inheritance chain."""

    @pytest.mark.parametrize(
        "exc_class",
        [
            ConfigError,
            ScanError,
            ScanTargetError,
            ScannerPluginError,
            ExploitError,
            ExploitSandboxError,
            ReportError,
            PluginError,
            ScopeError,
            RateLimitError,
            KnowledgeBaseError,
        ],
    )
    def test_all_inherit_from_aegisx_error(self, exc_class: type) -> None:
        """All custom exceptions inherit from AegisxError."""
        assert issubclass(exc_class, AegisxError)

    def test_scan_hierarchy(self) -> None:
        """ScanTargetError and ScannerPluginError inherit from ScanError."""
        assert issubclass(ScanTargetError, ScanError)
        assert issubclass(ScannerPluginError, ScanError)
        assert issubclass(RateLimitError, ScanError)

    def test_exploit_hierarchy(self) -> None:
        """ExploitSandboxError inherits from ExploitError."""
        assert issubclass(ExploitSandboxError, ExploitError)


class TestExceptionMessages:
    """Verify exception messages and details."""

    def test_base_exception_message(self) -> None:
        exc = AegisxError("something broke")
        assert str(exc) == "something broke"

    def test_exception_with_details(self) -> None:
        exc = AegisxError("error", details={"file": "config.py", "line": "42"})
        assert exc.details["file"] == "config.py"
        assert exc.details["line"] == "42"

    def test_exception_details_default_empty(self) -> None:
        exc = AegisxError("error")
        assert exc.details == {}

    def test_config_error(self) -> None:
        with pytest.raises(ConfigError, match="invalid config"):
            raise ConfigError("invalid config")

    def test_scan_error(self) -> None:
        with pytest.raises(ScanError, match="scan failed"):
            raise ScanError("scan failed")

    def test_scope_error(self) -> None:
        with pytest.raises(ScopeError, match="out of scope"):
            raise ScopeError("out of scope")
