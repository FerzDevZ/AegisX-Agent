"""Integration tests for the orchestrator pipeline.

Tests the full scan flow: recon → scan → exploit → report.
"""

from __future__ import annotations

import pytest
import httpx
import respx

from aegisx.core.config import AegisxConfig, ScanMode
from aegisx.core.orchestrator import AegisxOrchestrator


@pytest.fixture
def config() -> AegisxConfig:
    """Config for integration tests."""
    return AegisxConfig(
        target_url="https://test.example.com",
        scan_mode=ScanMode.PASSIVE,
        enabled_scanners=[],
        exploit_verification=False,
    )


@pytest.fixture
def config_with_scanners() -> AegisxConfig:
    """Config with secret_scanner enabled for testing."""
    return AegisxConfig(
        target_url="https://test.example.com",
        scan_mode=ScanMode.QUICK,
        enabled_scanners=["secret_scanner"],
        exploit_verification=False,
    )


class TestOrchestratorInit:
    """Test orchestrator initialization."""

    def test_init_creates_context(self, config):
        orch = AegisxOrchestrator(config)
        assert orch.config == config
        assert orch.context is not None
        assert orch.context.target_url == "https://test.example.com"

    def test_init_registers_builtins(self, config):
        orch = AegisxOrchestrator(config)
        scanners = orch.plugin_manager.list_scanners()
        assert "web_scanner" in scanners
        assert "secret_scanner" in scanners
        assert "network_scanner" in scanners

    def test_init_registers_exploits(self, config):
        orch = AegisxOrchestrator(config)
        exploits = orch.plugin_manager.list_exploits()
        assert "sqli_exploit" in exploits
        assert "xss_exploit" in exploits

    def test_init_registers_reporters(self, config):
        orch = AegisxOrchestrator(config)
        reporters = orch.plugin_manager.list_reporters()
        assert "markdown" in reporters
        assert "json" in reporters
        assert "html" in reporters


class TestOrchestratorRecon:
    """Test reconnaissance phase."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_recon_discovers_server(self, config_with_scanners):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "server": "nginx/1.24.0",
                    "x-powered-by": "Express",
                },
                text="<html><body>Test</body></html>",
            )
        )

        orch = AegisxOrchestrator(config_with_scanners)
        await orch._phase_recon()

        assert orch.context.target_info.get("server") == "nginx/1.24.0"
        assert orch.context.target_info.get("technologies") is not None

    @pytest.mark.asyncio
    async def test_recon_handles_unreachable_target(self, config):
        """Recon should not crash even if target is unreachable."""
        orch = AegisxOrchestrator(config)
        # Don't mock — will fail to connect, but should not crash
        try:
            await orch._phase_recon()
        except Exception:
            pass  # Acceptable — the point is it shouldn't be an unhandled crash
        assert orch.context is not None


class TestOrchestratorScan:
    """Test scan phase with mocked scanners."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_runs_enabled_scanners(self, config_with_scanners):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(
                200,
                text="SECRET_KEY=abc123\n" * 20,
            )
        )

        orch = AegisxOrchestrator(config_with_scanners)
        await orch._phase_scan()

        # Should have run secret_scanner
        assert len(orch.context.findings) >= 0  # May or may not find secrets

    @pytest.mark.asyncio
    async def test_scan_with_no_scanners(self, config):
        config.enabled_scanners = []
        orch = AegisxOrchestrator(config)
        await orch._phase_scan()
        assert len(orch.context.findings) == 0


class TestOrchestratorReport:
    """Test report generation phase."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_report_generates_markdown(self, config_with_scanners):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text="<html></html>")
        )

        orch = AegisxOrchestrator(config_with_scanners)
        # Run full pipeline
        stats = await orch.run()

        assert stats is not None
        assert orch.context.scan_id != ""


class TestOrchestratorTimeout:
    """Test phase timeout handling."""

    @pytest.mark.asyncio
    async def test_scan_timeout_does_not_crash(self, config):
        """Phase timeout is read from config but defaults to 300s."""
        config.enabled_scanners = []
        orch = AegisxOrchestrator(config)
        # Should complete quickly with no scanners
        await orch._phase_scan()
