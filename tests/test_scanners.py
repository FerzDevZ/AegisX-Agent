"""Tests for secret_scanner, config_scanner, dependency_scanner, network_scanner."""

from __future__ import annotations

import re

import pytest
import httpx
import respx

from aegisx.core.config import AegisxConfig, ScanMode
from aegisx.core.context import ScanContext, Severity
from aegisx.scanners.secret_scanner import SecretScanner
from aegisx.scanners.config_scanner import ConfigScanner
from aegisx.scanners.dependency_scanner import DependencyScanner
from aegisx.scanners.network_scanner import NetworkScanner, COMMON_PORTS, DANGEROUS_SERVICES


# ── Fixtures ───────────────────────────────────────────────────

@pytest.fixture
def config() -> AegisxConfig:
    return AegisxConfig(
        target_url="https://test.example.com",
        scan_mode=ScanMode.QUICK,
        timeout_seconds=5,
        user_agent="AegisxTest/0.1.0",
    )


@pytest.fixture
def context(config: AegisxConfig) -> ScanContext:
    return ScanContext(config=config, target_url=config.target_url)


# ═══════════════════════════════════════════════════════════════
# SecretScanner Tests
# ═══════════════════════════════════════════════════════════════

class TestSecretScanner:
    def test_init(self, context):
        s = SecretScanner(context=context)
        assert s.name == "secret_scanner"
        assert "hardcoded" in s.description.lower()

    @respx.mock
    @pytest.mark.asyncio
    async def test_validate_target_reachable(self, context):
        respx.get("https://test.example.com").mock(return_value=httpx.Response(200))
        s = SecretScanner(context=context)
        assert await s.validate_target() is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_validate_target_unreachable(self, context):
        respx.get("https://test.example.com").mock(side_effect=httpx.ConnectError("fail"))
        s = SecretScanner(context=context)
        assert await s.validate_target() is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_aws_key(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text="aws_access_key_id = AKIA1234567890ABCDEF")
        )
        for path in SecretScanner.SECRET_PATHS:
            respx.get(f"https://test.example.com{path}").mock(return_value=httpx.Response(404))
        s = SecretScanner(context=context)
        findings = await s.scan()
        assert any("AWS" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_private_key(self, context):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY5unA67hqlYMd4Prn7dOt2\n-----END RSA PRIVATE KEY-----"
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text=content)
        )
        for path in SecretScanner.SECRET_PATHS:
            respx.get(f"https://test.example.com{path}").mock(return_value=httpx.Response(404))
        s = SecretScanner(context=context)
        findings = await s.scan()
        assert any("Private Key" in f.title for f in findings), f"Got: {[f.title for f in findings]}"

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_database_url(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text='database_url="postgres://admin:secret@db:5432/prod"')
        )
        for path in SecretScanner.SECRET_PATHS:
            respx.get(f"https://test.example.com{path}").mock(return_value=httpx.Response(404))
        s = SecretScanner(context=context)
        findings = await s.scan()
        assert any("Database" in f.title or "PostgreSQL" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_skips_false_positive_aws_example(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text="AKIAIOSFODNN7EXAMPLE")
        )
        for path in SecretScanner.SECRET_PATHS:
            respx.get(f"https://test.example.com{path}").mock(return_value=httpx.Response(404))
        s = SecretScanner(context=context)
        findings = await s.scan()
        aws_findings = [f for f in findings if "AWS" in f.title]
        assert len(aws_findings) == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_findings_on_clean_page(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text="<html><body>Hello World</body></html>")
        )
        for path in SecretScanner.SECRET_PATHS:
            respx.get(f"https://test.example.com{path}").mock(return_value=httpx.Response(404))
        s = SecretScanner(context=context)
        findings = await s.scan()
        assert len(findings) == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_scan_env_file(self, context):
        import re as _re

        def _responder(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/.env" in url:
                return httpx.Response(200, text='api_key = "my-super-secret-api-key-12345"')
            return httpx.Response(404)

        route = respx.route(method="GET", url=_re.compile(r"https://test\.example\.com/.*"))
        route.side_effect = _responder
        s = SecretScanner(context=context)
        findings = await s.scan()
        # Should find the exposed API key
        assert any("API Key" in f.title for f in findings), f"Got: {[f.title for f in findings]}"

    def test_secret_patterns_compile(self):
        for pattern, name, _, _ in SecretScanner.SECRET_PATTERNS:
            re.compile(pattern)


# ═══════════════════════════════════════════════════════════════
# ConfigScanner Tests
# ═══════════════════════════════════════════════════════════════

class TestConfigScanner:
    def test_init(self, context):
        s = ConfigScanner(context=context)
        assert s.name == "config_scanner"

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_debug_mode(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text="Debug mode is ON. Stack trace visible.")
        )
        s = ConfigScanner(context=context)
        findings = await s.scan()
        assert any("Debug" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_default_page(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text="<h1>Welcome to nginx</h1>\n<p>nginx welcome page</p>")
        )
        s = ConfigScanner(context=context)
        findings = await s.scan()
        assert any("Default" in f.title for f in findings), f"Got: {[f.title for f in findings]}"

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_directory_listing(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text="<title>Index of /</title><pre>file1.txt</pre>")
        )
        s = ConfigScanner(context=context)
        findings = await s.scan()
        assert any("Directory Listing" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_exposed_admin(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text="<h1>Admin Login</h1><form>")
        )
        s = ConfigScanner(context=context)
        findings = await s.scan()
        assert any("Admin Panel" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_x_powered_by(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, headers={"X-Powered-By": "Express"})
        )
        s = ConfigScanner(context=context)
        findings = await s.scan()
        assert any("X-Powered-By" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_cors_wildcard_with_credentials(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "access-control-allow-origin": "*",
                    "access-control-allow-credentials": "true",
                },
            )
        )
        s = ConfigScanner(context=context)
        findings = await s.scan()
        assert any("CORS" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_findings_on_clean_site(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text="<html><body>Safe site</body></html>")
        )
        s = ConfigScanner(context=context)
        findings = await s.scan()
        assert not any(f.title.startswith("Debug") or f.title.startswith("Default") for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_sensitive_paths_exposed(self, context):
        import re as _re

        def _responder(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/.env" in url:
                return httpx.Response(200, text="SECRET_KEY=abc123\n" * 20)
            return httpx.Response(404)

        route = respx.route(method="GET", url=_re.compile(r"https://test\.example\.com/.*"))
        route.side_effect = _responder

        s = ConfigScanner(context=context)
        findings = await s.scan()
        env_findings = [f for f in findings if "Environment" in f.title or "env" in f.title.lower()]
        assert len(env_findings) > 0, f"Got: {[f.title for f in findings]}"


# ═══════════════════════════════════════════════════════════════
# DependencyScanner Tests
# ═══════════════════════════════════════════════════════════════

class TestDependencyScanner:
    def test_init(self, context):
        s = DependencyScanner(context=context)
        assert s.name == "dependency_scanner"

    @pytest.mark.asyncio
    async def test_validate_always_true(self, context):
        s = DependencyScanner(context=context)
        assert await s.validate_target() is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_jquery_old(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text='<script src="jquery-1.12.4.min.js"></script>')
        )
        s = DependencyScanner(context=context)
        findings = await s.scan()
        assert any("jQuery" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_angularjs_eol(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text='<script src="angular-1.7.9.min.js"></script>')
        )
        s = DependencyScanner(context=context)
        findings = await s.scan()
        assert any("AngularJS" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_findings_on_modern_site(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text='<script src="jquery-3.7.1.min.js"></script>')
        )
        s = DependencyScanner(context=context)
        findings = await s.scan()
        assert len(findings) == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_findings_on_empty_page(self, context):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text="<html></html>")
        )
        s = DependencyScanner(context=context)
        findings = await s.scan()
        assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════
# NetworkScanner Tests
# ═══════════════════════════════════════════════════════════════

class TestNetworkScanner:
    def test_init(self, context):
        s = NetworkScanner(context=context)
        assert s.name == "network_scanner"

    def test_common_ports_dict(self):
        assert 80 in COMMON_PORTS
        assert 443 in COMMON_PORTS
        assert 3306 in COMMON_PORTS
        assert COMMON_PORTS[80] == "HTTP"
        assert COMMON_PORTS[443] == "HTTPS"

    def test_dangerous_services_dict(self):
        assert 23 in DANGEROUS_SERVICES
        assert 3306 in DANGEROUS_SERVICES
        assert 6379 in DANGEROUS_SERVICES
        assert DANGEROUS_SERVICES[23][2] == Severity.CRITICAL

    def test_cvss_calculation(self):
        assert NetworkScanner._calculate_port_cvss(3306) == 9.0
        assert NetworkScanner._calculate_port_cvss(23) == 8.0
        assert NetworkScanner._calculate_port_cvss(25) == 5.0
        assert NetworkScanner._calculate_port_cvss(9999) == 3.0

    def test_cn_matches_hostname_exact(self, context):
        s = NetworkScanner(context=context)
        assert s._cn_matches_hostname("example.com", "example.com") is True

    def test_cn_matches_hostname_wildcard(self, context):
        s = NetworkScanner(context=context)
        assert s._cn_matches_hostname("*.example.com", "sub.example.com") is True
        assert s._cn_matches_hostname("*.example.com", "example.com") is True
        assert s._cn_matches_hostname("*.example.com", "evil.com") is False

    def test_cn_matches_hostname_mismatch(self, context):
        s = NetworkScanner(context=context)
        assert s._cn_matches_hostname("other.com", "example.com") is False
