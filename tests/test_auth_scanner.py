"""Tests for the auth scanner (JWT / session / OAuth checks)."""

from __future__ import annotations

import base64
import json
import time

import httpx
import pytest
import respx

from aegisx.core.config import AegisxConfig
from aegisx.core.context import ScanContext
from aegisx.scanners.auth_scanner import (
    AuthScanner,
    analyze_jwt,
    check_jwt,
    check_oauth,
    check_session_management,
)


def _config(**overrides) -> AegisxConfig:
    defaults = dict(
        target_url="https://test.example.com/",
        enabled_scanners=["auth_scanner"],
        timeout_seconds=5,
    )
    defaults.update(overrides)
    return AegisxConfig(**defaults)


def _make_jwt(header: dict, payload: dict) -> str:
    """Build an unsigned JWT-shaped string for tests."""
    def enc(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{enc(header)}.{enc(payload)}.sig"


# ---------------------------------------------------------------------------
# JWT analysis
# ---------------------------------------------------------------------------


class TestJWTAnalysis:
    def test_valid_decode(self):
        facts = analyze_jwt(_make_jwt({"alg": "HS256"}, {"sub": "1", "exp": 2**32}))
        assert facts is not None
        assert facts["alg"] == "HS256"
        assert facts["expires"] is True

    def test_invalid_token_returns_none(self):
        assert analyze_jwt("not-a-jwt") is None
        assert analyze_jwt("a.b.c") is None

    def test_alg_none_detected(self):
        facts = analyze_jwt(_make_jwt({"alg": "none"}, {"sub": "1"}))
        assert facts["alg"] == "none"

    def test_missing_exp(self):
        facts = analyze_jwt(_make_jwt({"alg": "HS256"}, {"sub": "1"}))
        assert facts["expires"] is False

    def test_long_lifetime_detected(self):
        now = int(time.time())
        facts = analyze_jwt(
            _make_jwt({"alg": "HS256"}, {"sub": "1", "iat": now, "exp": now + 30 * 86400})
        )
        assert facts["lifetime_seconds"] > 24 * 3600


class TestJWTFindingGeneration:
    @respx.mock
    @pytest.mark.asyncio
    async def test_alg_none_finding_critical(self):
        token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "role": "admin"})
        respx.get(url__startswith="https://test.example.com/").mock(
            return_value=httpx.Response(200, text=f"token={token}")
        )
        findings = await check_jwt(_config(), ["https://test.example.com/"])
        alg_none = [f for f in findings if f.cwe_id == "CWE-347"]
        assert alg_none, "alg=none must produce a CWE-347 finding"
        assert alg_none[0].severity.value == "critical"

    @respx.mock
    @pytest.mark.asyncio
    async def test_missing_exp_finding(self):
        token = _make_jwt({"alg": "HS256"}, {"sub": "1", "role": "user"})
        respx.get(url__startswith="https://test.example.com/").mock(
            return_value=httpx.Response(200, text=f"Bearer {token}")
        )
        findings = await check_jwt(_config(), ["https://test.example.com/"])
        assert any(f.cwe_id == "CWE-613" for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_sensitive_claim_finding(self):
        token = _make_jwt({"alg": "HS256"}, {"sub": "1", "exp": 2**32, "password": "hunter2"})
        respx.get(url__startswith="https://test.example.com/").mock(
            return_value=httpx.Response(200, text=token)
        )
        findings = await check_jwt(_config(), ["https://test.example.com/"])
        assert any(f.cwe_id == "CWE-312" for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_healthy_jwt_no_findings(self):
        now = int(time.time())
        token = _make_jwt(
            {"alg": "RS256"}, {"sub": "1", "iat": now, "exp": now + 600}
        )
        respx.get(url__startswith="https://test.example.com/").mock(
            return_value=httpx.Response(200, text=token)
        )
        findings = await check_jwt(_config(), ["https://test.example.com/"])
        assert findings == []


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------


class TestSessionManagement:
    @pytest.mark.asyncio
    async def test_session_id_in_url_detected(self):
        url = "https://test.example.com/dashboard?sessionid=abc123&view=main"
        with respx.mock:
            respx.get(url).mock(return_value=httpx.Response(200, text="ok"))
            findings = await check_session_management(_config(), [url])
        assert any(f.cwe_id == "CWE-598" for f in findings)

    @pytest.mark.asyncio
    async def test_clean_url_no_findings(self):
        url = "https://test.example.com/dashboard?view=main"
        with respx.mock:
            respx.get(url).mock(return_value=httpx.Response(200, text="ok"))
            findings = await check_session_management(_config(), [url])
        assert findings == []


# ---------------------------------------------------------------------------
# OAuth
# ---------------------------------------------------------------------------


class TestOAuth:
    @pytest.mark.asyncio
    async def test_missing_state_detected(self):
        page = (
            '<a href="https://auth.example.com/authorize'
            '?client_id=abc&response_type=code&redirect_uri=https://test.example.com/cb">'
            "Login</a>"
        )
        with respx.mock:
            respx.get(url__startswith="https://test.example.com/").mock(
                return_value=httpx.Response(200, text=page)
            )
            findings = await check_oauth(_config(), ["https://test.example.com/"])
        assert any(f.cwe_id == "CWE-352" for f in findings)

    @pytest.mark.asyncio
    async def test_state_present_no_csrf_finding(self):
        page = (
            '<a href="https://auth.example.com/authorize'
            "?client_id=abc&response_type=code&state=xyz123"
            '&redirect_uri=https://test.example.com/cb">Login</a>'
        )
        with respx.mock:
            respx.get(url__startswith="https://test.example.com/").mock(
                return_value=httpx.Response(200, text=page)
            )
            findings = await check_oauth(_config(), ["https://test.example.com/"])
        assert not any(f.cwe_id == "CWE-352" for f in findings)

    @pytest.mark.asyncio
    async def test_wildcard_redirect_uri_flagged(self):
        page = (
            '<a href="https://auth.example.com/authorize'
            "?client_id=abc&response_type=code&state=xyz"
            '&redirect_uri=https://test.example.com/callback/*">Login</a>'
        )
        with respx.mock:
            respx.get(url__startswith="https://test.example.com/").mock(
                return_value=httpx.Response(200, text=page)
            )
            findings = await check_oauth(_config(), ["https://test.example.com/"])
        assert any(f.cwe_id == "CWE-601" for f in findings)

    @pytest.mark.asyncio
    async def test_no_oauth_links_no_findings(self):
        with respx.mock:
            respx.get(url__startswith="https://test.example.com/").mock(
                return_value=httpx.Response(200, text="<a href='/about'>About</a>")
            )
            findings = await check_oauth(_config(), ["https://test.example.com/"])
        assert findings == []


# ---------------------------------------------------------------------------
# Scanner integration
# ---------------------------------------------------------------------------


class TestAuthScanner:
    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_end_to_end_finds_alg_none(self):
        token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "role": "admin"})
        respx.get(url__startswith="https://test.example.com/").mock(
            return_value=httpx.Response(200, text=f"session={token}")
        )
        config = _config()
        context = ScanContext(config=config, target_url=config.target_url)
        scanner = AuthScanner(context)
        findings = await scanner.run()
        assert any(f.cwe_id == "CWE-347" for f in findings)
        assert all(f.scanner_name == "auth_scanner" for f in findings)

    def test_scanner_registered_and_enabled_by_default(self):
        from aegisx.core.orchestrator import AegisxOrchestrator

        orch = AegisxOrchestrator(_config())
        assert "auth_scanner" in orch.plugin_manager.list_scanners()
        assert "auth_scanner" in orch.config.enabled_scanners

    def test_metadata(self):
        assert AuthScanner.name == "auth_scanner"
        assert "JWT" in AuthScanner.description
