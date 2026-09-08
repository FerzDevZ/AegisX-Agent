"""Tests for the SSTI scanner and SSTI/CORS/traversal exploit verifiers."""

from __future__ import annotations

import httpx
import pytest
import respx

from aegisx.core.config import AegisxConfig
from aegisx.core.context import Finding, ScanContext, Severity
from aegisx.exploits.cors_exploit import CORSExploit
from aegisx.exploits.ssti_exploit import SSTIExploit
from aegisx.exploits.traversal_exploit import PathTraversalExploit
from aegisx.scanners.ssti_scanner import (
    SSTIScanner,
    _build_probe_url,
    _params_with_templates,
    check_ssti,
)

BASE = "https://test.example.com"


def _config(**overrides) -> AegisxConfig:
    defaults = dict(
        target_url=f"{BASE}/",
        enabled_scanners=["ssti_scanner"],
        timeout_seconds=5,
    )
    defaults.update(overrides)
    return AegisxConfig(**defaults)


def _finding(**overrides) -> Finding:
    defaults = dict(
        title="SSTI",
        severity=Severity.CRITICAL,
        cwe_id="CWE-1336",
        url=f"{BASE}/greet?name=world",
        endpoint="/greet",
        parameter="name",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# SSTI scanner helpers
# ---------------------------------------------------------------------------


class TestSSTIHelpers:
    def test_build_probe_url_preserves_params(self):
        out = _build_probe_url(f"{BASE}/x?a=1&b=2", "tpl", "{{7*7}}")
        assert "a=1" in out and "b=2" in out and "tpl=%7B%7B7%2A7%7D%7D" in out

    def test_params_with_templates_prefers_template_params(self):
        probes = _params_with_templates(f"{BASE}/render?tpl=home&id=7")
        assert probes == [(f"{BASE}/render", "tpl")]

    def test_params_with_templates_falls_back_to_first_param(self):
        probes = _params_with_templates(f"{BASE}/render?foo=bar")
        assert probes == [(f"{BASE}/render", "foo")]

    def test_params_with_templates_fallback_q_on_clean_path(self):
        probes = _params_with_templates(f"{BASE}/render")
        assert probes == [(f"{BASE}/render", "q")]


# ---------------------------------------------------------------------------
# SSTI scanner detection
# ---------------------------------------------------------------------------


class TestSSTIDetection:
    @pytest.mark.asyncio
    @respx.mock
    async def test_jinja_evaluation_detected(self):
        # specific routes first (respx matches in order)
        respx.get(path="/greet", params__contains={"name": "{{7*7}}"}).mock(
            return_value=httpx.Response(200, text="Hello 49")
        )
        respx.get(host="test.example.com", path="/greet").mock(
            return_value=httpx.Response(200, text="Hello world")
        )
        findings = await check_ssti(_config(), f"{BASE}/greet?name=world")
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe_id == "CWE-1336"
        assert f.severity == Severity.CRITICAL
        assert f.parameter == "name"

    @pytest.mark.asyncio
    @respx.mock
    async def test_marker_already_in_baseline_is_not_a_hit(self):
        # baseline itself contains "49" — a page that legitimately mentions it
        respx.get(host="test.example.com", path="/greet").mock(
            return_value=httpx.Response(200, text="Room 49 welcome")
        )
        findings = await check_ssti(_config(), f"{BASE}/greet?name=world")
        assert findings == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_clean_page_no_findings(self):
        respx.get(host="test.example.com", path="/greet").mock(
            return_value=httpx.Response(200, text="Hello world")
        )
        findings = await check_ssti(_config(), f"{BASE}/greet?name=world")
        assert findings == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_dead_target_no_crash(self):
        respx.route(host="test.example.com").mock(side_effect=httpx.ConnectError("down"))
        findings = await check_ssti(_config(), f"{BASE}/greet?name=world")
        assert findings == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_scanner_run_end_to_end(self):
        # /search is in the crawler's COMMON_PATHS and 'search' is a template
        # param — the scanner will probe it with q/template params.
        respx.get(path="/search", params__contains={"search": "{{7*7}}"}).mock(
            return_value=httpx.Response(200, text="results 49")
        )
        respx.get(path="/search", params__contains={"q": "{{7*7}}"}).mock(
            return_value=httpx.Response(200, text="results 49")
        )
        respx.get(host="test.example.com", path__startswith="/").mock(
            return_value=httpx.Response(200, text="nothing here")
        )
        cfg = _config()
        ctx = ScanContext(config=cfg, target_url=cfg.target_url)
        scanner = SSTIScanner(ctx)
        findings = await scanner.run()
        assert len(findings) >= 1
        assert findings[0].scanner_name == "ssti_scanner"


# ---------------------------------------------------------------------------
# SSTI exploit verifier
# ---------------------------------------------------------------------------


class TestSSTIExploit:
    @pytest.mark.asyncio
    @respx.mock
    async def test_confirms_jinja_via_7x7(self):
        respx.get(path="/greet", params__contains={"name": "aegisxbaseline"}).mock(
            return_value=httpx.Response(200, text="Hello world")
        )
        respx.get(path="/greet", params__contains={"name": "{{7*7}}"}).mock(
            return_value=httpx.Response(200, text="Hello 49")
        )
        ex = SSTIExploit(ScanContext(config=_config(), target_url=f"{BASE}/"))
        result = await ex.verify(_finding(), "{{7*7}}")
        assert result.success is True
        assert "49" in result.evidence
        assert result.severity_after == Severity.CRITICAL

    @pytest.mark.asyncio
    @respx.mock
    async def test_not_vulnerable(self):
        respx.get(host="test.example.com", path="/greet").mock(
            return_value=httpx.Response(200, text="Hello world")
        )
        ex = SSTIExploit(ScanContext(config=_config(), target_url=f"{BASE}/"))
        result = await ex.verify(_finding(), "{{7*7}}")
        assert result.success is False

    @pytest.mark.asyncio
    async def test_no_url(self):
        ex = SSTIExploit(ScanContext(config=_config(), target_url=f"{BASE}/"))
        result = await ex.verify(_finding(url=""), "{{7*7}}")
        assert result.success is False and "Could not build" in result.evidence

    def test_generate_payloads(self):
        ex = SSTIExploit(ScanContext(config=_config(), target_url=f"{BASE}/"))
        payloads = ex.generate_payloads(_finding())
        assert "{{7*7}}" in payloads and len(payloads) >= 5


# ---------------------------------------------------------------------------
# CORS exploit verifier
# ---------------------------------------------------------------------------


class TestCORSExploit:
    @pytest.mark.asyncio
    @respx.mock
    async def test_reflected_origin_with_credentials(self):
        respx.get(f"{BASE}/").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "access-control-allow-origin": "https://evil-attacker.com",
                    "access-control-allow-credentials": "true",
                },
            )
        )
        ex = CORSExploit(ScanContext(config=_config(), target_url=f"{BASE}/"))
        result = await ex.verify(
            _finding(title="CORS", cwe_id="CWE-942", url=f"{BASE}/", parameter=""),
            "https://evil-attacker.com",
        )
        assert result.success is True
        assert result.severity_after == Severity.HIGH
        assert "credentials" in result.evidence

    @pytest.mark.asyncio
    @respx.mock
    async def test_wildcard_with_credentials(self):
        respx.get(f"{BASE}/").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "access-control-allow-origin": "*",
                    "access-control-allow-credentials": "true",
                },
            )
        )
        ex = CORSExploit(ScanContext(config=_config(), target_url=f"{BASE}/"))
        result = await ex.verify(
            _finding(title="CORS", cwe_id="CWE-942", url=f"{BASE}/", parameter=""),
            "https://any-origin.test",
        )
        assert result.success is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_strict_cors_not_vulnerable(self):
        respx.get(f"{BASE}/").mock(
            return_value=httpx.Response(
                200, headers={"access-control-allow-origin": "https://trusted.example.com"}
            )
        )
        ex = CORSExploit(ScanContext(config=_config(), target_url=f"{BASE}/"))
        result = await ex.verify(
            _finding(title="CORS", cwe_id="CWE-942", url=f"{BASE}/", parameter=""),
            "https://evil-attacker.com",
        )
        assert result.success is False


# ---------------------------------------------------------------------------
# Path traversal exploit verifier
# ---------------------------------------------------------------------------


class TestTraversalExploit:
    @pytest.mark.asyncio
    @respx.mock
    async def test_confirms_passwd_read(self):
        respx.get(
            path="/download",
            params__contains={"file": "../../../../etc/passwd"},
        ).mock(
            return_value=httpx.Response(
                200,
                text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            )
        )
        ex = PathTraversalExploit(ScanContext(config=_config(), target_url=f"{BASE}/"))
        result = await ex.verify(
            _finding(
                title="Path Traversal",
                cwe_id="CWE-22",
                url=f"{BASE}/download?file=report.pdf",
                endpoint="/download",
                parameter="file",
            ),
            "../../../../etc/passwd",
        )
        assert result.success is True
        assert "/etc/passwd" in result.evidence
        assert result.severity_after == Severity.HIGH

    @pytest.mark.asyncio
    @respx.mock
    async def test_encoded_payload_confirmed(self):
        respx.get(
            path="/download",
            params__contains={"file": "..%2F..%2F..%2F..%2Fetc%2Fpasswd"},
        ).mock(return_value=httpx.Response(200, text="root:x:0:0:root"))
        ex = PathTraversalExploit(ScanContext(config=_config(), target_url=f"{BASE}/"))
        result = await ex.verify(
            _finding(title="PT", cwe_id="CWE-22", url=f"{BASE}/download?file=x", parameter="file"),
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        )
        assert result.success is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_blocked_response_not_vulnerable(self):
        respx.get(host="test.example.com", path="/download").mock(
            return_value=httpx.Response(403, text="Forbidden")
        )
        ex = PathTraversalExploit(ScanContext(config=_config(), target_url=f"{BASE}/"))
        result = await ex.verify(
            _finding(title="PT", cwe_id="CWE-22", url=f"{BASE}/download?file=x", parameter="file"),
            "../../../../etc/passwd",
        )
        assert result.success is False

    def test_generate_payloads_ordered(self):
        ex = PathTraversalExploit(ScanContext(config=_config(), target_url=f"{BASE}/"))
        payloads = ex.generate_payloads(_finding())
        assert payloads[0] == "../../../../etc/passwd"
        assert len(payloads) >= 5
