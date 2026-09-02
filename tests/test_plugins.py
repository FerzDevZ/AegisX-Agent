"""Tests for the plugin manager."""

from __future__ import annotations

import pytest

from aegisx.plugins import PluginManager


class DummyScanner:
    name = "dummy_scanner"
    description = "A dummy scanner for testing"


class DummyExploit:
    name = "dummy_exploit"
    description = "A dummy exploit for testing"


class DummyReporter:
    format_name = "dummy_reporter"
    description = "A dummy reporter for testing"


class TestPluginManager:
    """Tests for PluginManager."""

    def test_register_scanner(self) -> None:
        pm = PluginManager()
        pm.register_scanner("dummy", DummyScanner)
        assert pm.get_scanner("dummy") is DummyScanner
        assert "dummy" in pm.list_scanners()

    def test_register_exploit(self) -> None:
        pm = PluginManager()
        pm.register_exploit("dummy", DummyExploit)
        assert pm.get_exploit("dummy") is DummyExploit
        assert "dummy" in pm.list_exploits()

    def test_register_reporter(self) -> None:
        pm = PluginManager()
        pm.register_reporter("dummy", DummyReporter)
        assert pm.get_reporter("dummy") is DummyReporter
        assert "dummy" in pm.list_reporters()

    def test_get_nonexistent_returns_none(self) -> None:
        pm = PluginManager()
        assert pm.get_scanner("nonexistent") is None
        assert pm.get_exploit("nonexistent") is None
        assert pm.get_reporter("nonexistent") is None

    def test_overwrite_registration(self) -> None:
        """Overwriting a registration replaces the old one."""
        pm = PluginManager()
        pm.register_scanner("dup", DummyScanner)

        class NewScanner:
            name = "new_scanner"

        pm.register_scanner("dup", NewScanner)
        assert pm.get_scanner("dup") is NewScanner
        assert len(pm.list_scanners()) == 1

    def test_summary(self) -> None:
        pm = PluginManager()
        pm.register_scanner("s1", DummyScanner)
        pm.register_exploit("e1", DummyExploit)
        pm.register_reporter("r1", DummyReporter)

        summary = pm.summary()
        assert summary == {
            "scanners": ["s1"],
            "exploits": ["e1"],
            "reporters": ["r1"],
        }

    def test_empty_summary(self) -> None:
        pm = PluginManager()
        summary = pm.summary()
        assert summary == {"scanners": [], "exploits": [], "reporters": []}

    def test_load_from_nonexistent_directory(self) -> None:
        """Loading from a nonexistent directory is a no-op."""
        from pathlib import Path

        pm = PluginManager()
        pm.load_from_directory(Path("/nonexistent/path"))
        assert pm.list_scanners() == []
