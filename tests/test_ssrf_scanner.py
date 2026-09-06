"""Tests for the SSRF & open-redirect detection scanner."""

from __future__ import annotations

import httpx
import pytest
import respx

from aegisx.core.config import AegisxConfig
from aegisx.core.context import ScanContext
from aegisx.scanners.ssrf_scanner import (
    SSRFScanner,
    _build_probe_url,
    _params_with_urls,
    check_blind_ssrf,
    check_open_redirect,
)


def _config(**overrides) -> AegisxConfig:
    defaults = dict(
        target_url="https://test.example.com/",
        enabled_scanners=["ssrf_scanner"],
        timeout_seconds=5,
    )
    defaults.update(overrides)
    return AegisxConfig(**defaults)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_params_with_urls_finds_url_params(self):
        probes = _params_with_urls("https://t.example.com/page?next=/home&id=7")
        names = [p for _, p in probes]
        assert names == ["next"]  # only present URL-ish params, path preserved
        assert all(base.endswith("/page") for base, _ in probes)

    def test_params_with_urls_probes_path_only_pages(self):
        probes = _params_with_urls("https://t.example.com/search")
        assert probes and all(base.endswith("/search") for base, _ in probes)

    def test_params_with_urls_skips_non_url_queries(self):
        assert _params_with_urls("https://t.example.com/x?id=7&sort=asc") == []

    def test_build_probe_url_preserves_other_params(self):
        out = _build_probe_url("https://t.example.com/x?a=1&b=2", "url", "https://probe.test/")
        assert "a=1" in out and "b=2" in out and "url=" in out


# ---------------------------------------------------------------------------
# Open redirect detection
# ---------------------------------------------------------------------------


class TestOpenRedirect:
    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_302_to_external_host(self):
        respx.get(url__startswith="https://test.example.com/").mock(
            return_value=httpx.Response(
                302, headers={"Location": "https://aegisx-probe.example.com/redirect-test"}
            )
        )
        finding = await check_open_redirect(_config(), "https://test.example.com/login", "next")
        assert finding is not None
        assert finding.cwe_id == "CWE-601"
        assert finding.parameter == "next"
        assert finding.severity.value == "medium"

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_finding_on_internal_redirect(self):
        """A redirect staying on-origin is normal behavior — not a finding."""
        respx.get(url__startswith="https://test.example.com/").mock(
            return_value=httpx.Response(302, headers={"Location": "https://test.example.com/done"})
        )
        finding = await check_open_redirect(_config(), "https://test.example.com/login", "next")
        assert finding is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_finding_on_200(self):
        respx.get(url__startswith="https://test.example.com/").mock(
            return_value=httpx.Response(200, text="ok")
        )
        finding = await check_open_redirect(_config(), "https://test.example.com/login", "next")
        assert finding is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_network_error_returns_none(self):
        respx.get(url__startswith="https://test.example.com/").mock(
            side_effect=httpx.ConnectError("down")
        )
        finding = await check_open_redirect(_config(), "https://test.example.com/", "next")
        assert finding is None


# ---------------------------------------------------------------------------
# Blind SSRF detection
# ---------------------------------------------------------------------------


class TestBlindSSRF:
    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_connection_refused_reflection(self):
        respx.get(url__startswith="https://test.example.com/").mock(
            return_value=httpx.Response(500, text="Error: connection refused to 127.0.0.1:80")
        )
        finding = await check_blind_ssrf(_config(), "https://test.example.com/fetch", "url")
        assert finding is not None
        assert finding.cwe_id == "CWE-918"
        assert finding.severity.value == "high"

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_passwd_reflection(self):
        respx.get(url__startswith="https://test.example.com/").mock(
            return_value=httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash")
        )
        finding = await check_blind_ssrf(_config(), "https://test.example.com/fetch", "url")
        assert finding is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_finding_on_clean_response(self):
        respx.get(url__startswith="https://test.example.com/").mock(
            return_value=httpx.Response(200, text="<html>Welcome</html>")
        )
        finding = await check_blind_ssrf(_config(), "https://test.example.com/fetch", "url")
        assert finding is None


# ---------------------------------------------------------------------------
# Scanner integration
# ---------------------------------------------------------------------------


class TestSSRFScanner:
    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_finds_open_redirect_end_to_end(self):
        respx.get(url__startswith="https://test.example.com/").mock(side_effect=_routing_responder)
        config = _config()
        context = ScanContext(config=config, target_url=config.target_url)
        scanner = SSRFScanner(context)
        findings = await scanner.run()
        assert any(f.cwe_id == "CWE-601" for f in findings)
        assert all(f.scanner_name == "ssrf_scanner" for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_clean_target_no_findings(self):
        respx.get(url__startswith="https://test.example.com/").mock(
            return_value=httpx.Response(200, text="<html>home</html>")
        )
        config = _config()
        context = ScanContext(config=config, target_url=config.target_url)
        scanner = SSRFScanner(context)
        findings = await scanner.run()
        assert findings == []

    def test_scanner_registered_as_builtin(self):
        from aegisx.core.orchestrator import AegisxOrchestrator

        orch = AegisxOrchestrator(_config())
        assert "ssrf_scanner" in orch.plugin_manager.list_scanners()
        assert orch.config.enabled_scanners and "ssrf_scanner" in orch.config.enabled_scanners

    def test_scanner_metadata(self):
        assert SSRFScanner.name == "ssrf_scanner"
        assert "CWE" in SSRFScanner.description or "Forgery" in SSRFScanner.description


def _routing_responder(request: httpx.Request) -> httpx.Response:
    """Crawl-safe responder: normal pages for crawls, redirect for probes."""
    url = str(request.url)
    # Any request carrying our probe value on a URL-ish param gets redirected
    if (
        any(f"{p}=" in url for p in ("next", "redirect", "url", "goto", "target"))
        and "aegisx-probe" in url
    ):
        return httpx.Response(
            302, headers={"Location": "https://aegisx-probe.example.com/redirect-test"}
        )
    return httpx.Response(
        200,
        text=("<html><a href='/about'>About</a><a href='/login?next=/dashboard'>Login</a></html>"),
    )
