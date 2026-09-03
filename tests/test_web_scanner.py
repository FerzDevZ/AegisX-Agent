"""Tests for web scanner sub-modules."""

from __future__ import annotations

import re

import pytest
import httpx
import respx

from aegisx.core.config import AegisxConfig, ScanMode
from aegisx.core.context import ScanContext, Severity
from aegisx.scanners.web.crawler import crawl_pages, _is_in_scope
from aegisx.scanners.web.header_scanner import (
    check_security_headers,
    check_cors,
    check_info_disclosure,
    check_http_methods,
    REQUIRED_HEADERS,
)
from aegisx.scanners.web.cookie_scanner import check_cookie_security
from aegisx.scanners.web.auth_scanner import check_auth_bypass
from aegisx.scanners.web.param_scanner import (
    check_sqli,
    check_xss,
    check_path_traversal,
    _extract_forms,
)
from aegisx.scanners.web.api_scanner import check_api_endpoints
from aegisx.scanners.web_scanner import WebScanner


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


# ── Scope Enforcement ──────────────────────────────────────────

class TestScopeEnforcement:
    def test_same_domain_in_scope(self, config):
        assert _is_in_scope("https://test.example.com/page", config) is True

    def test_different_domain_out_of_scope(self, config):
        assert _is_in_scope("https://evil.com/steal", config) is False

    def test_subdomain_out_of_scope_default(self, config):
        assert _is_in_scope("https://sub.test.example.com/", config) is False

    def test_scope_with_subdomains(self):
        config = AegisxConfig(
            target_url="https://test.example.com",
            scope=["example.com"],
        )
        assert _is_in_scope("https://sub.example.com/", config) is True
        assert _is_in_scope("https://evil.com/", config) is False

    def test_http_scheme_allowed(self, config):
        assert _is_in_scope("http://test.example.com/page", config) is True

    def test_file_scheme_rejected(self, config):
        assert _is_in_scope("file:///etc/passwd", config) is False

    def test_empty_scope_matches_target_only(self):
        config = AegisxConfig(target_url="https://myapp.com")
        assert _is_in_scope("https://myapp.com/dashboard", config) is True
        assert _is_in_scope("https://other.com/", config) is False


# ── Crawler ────────────────────────────────────────────────────

COMMON_MOCK_PATHS = [
    "/login", "/admin", "/dashboard", "/api", "/search",
    "/register", "/signup", "/signin", "/panel", "/settings",
    "/services", "/profile", "/account", "/api/v1", "/graphql",
    "/wp-admin", "/wp-login.php", "/swagger", "/docs", "/api-docs",
    "/.env", "/config", "/debug",
]


class TestCrawler:
    @respx.mock
    @pytest.mark.asyncio
    async def test_crawl_discovers_links(self, config):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text='<a href="/about">About</a><a href="/contact">Contact</a>')
        )
        respx.get("https://test.example.com/about").mock(return_value=httpx.Response(200))
        respx.get("https://test.example.com/contact").mock(return_value=httpx.Response(200))
        for path in COMMON_MOCK_PATHS:
            respx.get(f"https://test.example.com{path}").mock(return_value=httpx.Response(404))

        urls = await crawl_pages(config, concurrency=5)
        assert "https://test.example.com" in urls
        assert "https://test.example.com/about" in urls
        assert "https://test.example.com/contact" in urls

    @respx.mock
    @pytest.mark.asyncio
    async def test_crawl_skips_out_of_scope(self, config):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, text='<a href="https://evil.com/steal">Evil</a>')
        )
        for path in COMMON_MOCK_PATHS:
            respx.get(f"https://test.example.com{path}").mock(return_value=httpx.Response(404))
        urls = await crawl_pages(config, concurrency=5)
        assert "https://evil.com/steal" not in urls


# ── Header Scanner ─────────────────────────────────────────────

class TestHeaderScanner:
    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_missing_headers(self, config):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, headers={"Server": "nginx"})
        )
        findings = await check_security_headers(config)
        assert len(findings) == len(REQUIRED_HEADERS)
        titles = [f.title for f in findings]
        assert any("Content-Security-Policy" in t for t in titles)
        assert any("HSTS" in t for t in titles)

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_findings_when_all_headers_present(self, config):
        headers = {h["header"]: "yes" for h in REQUIRED_HEADERS}
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, headers=headers)
        )
        findings = await check_security_headers(config)
        assert len(findings) == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_waf_challenge_detected(self, config):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, headers={"x-vercel-mitigated": "challenge"})
        )
        findings = await check_security_headers(config)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    @respx.mock
    @pytest.mark.asyncio
    async def test_cors_wildcard(self, config):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, headers={"access-control-allow-origin": "*"})
        )
        findings = await check_cors(config)
        assert any("Wildcard" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_cors_origin_reflection(self, config):
        """CORS code sends Origin: https://evil-attacker.com, checks if reflected back."""
        route = respx.get("https://test.example.com")
        route.side_effect = [
            # First request: evil-attacker.com origin reflected with credentials
            httpx.Response(
                200,
                headers={
                    "access-control-allow-origin": "https://evil-attacker.com",
                    "access-control-allow-credentials": "true",
                },
            ),
            # Second request: null origin (not reflected)
            httpx.Response(200),
        ]
        findings = await check_cors(config)
        assert any("Origin Reflection" in f.title for f in findings)
        reflection = [f for f in findings if "Origin Reflection" in f.title][0]
        assert reflection.severity == Severity.HIGH

    @respx.mock
    @pytest.mark.asyncio
    async def test_info_disclosure_server_version(self, config):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(200, headers={"Server": "nginx/1.18.0"})
        )
        findings = await check_info_disclosure(config)
        assert any("Server Version" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_http_methods_trace(self, config):
        respx.route(method="OPTIONS", url="https://test.example.com").mock(
            return_value=httpx.Response(200, headers={"Allow": "GET, POST, TRACE"})
        )
        findings = await check_http_methods(config)
        assert any("TRACE" in f.title for f in findings)


# ── Cookie Scanner ─────────────────────────────────────────────

class TestCookieScanner:
    @respx.mock
    @pytest.mark.asyncio
    async def test_insecure_cookies(self, config):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(
                200,
                content=b"ok",
                headers=[("set-cookie", "session=abc123; Path=/")],
            )
        )
        findings = await check_cookie_security(config)
        # Should find: missing Secure (https target), missing HttpOnly, missing SameSite
        assert len(findings) == 3
        titles = [f.title for f in findings]
        assert any("Insecure Cookie" in t for t in titles)
        assert any("HttpOnly" in t for t in titles)
        assert any("SameSite" in t for t in titles)

    @respx.mock
    @pytest.mark.asyncio
    async def test_secure_cookies_no_findings(self, config):
        respx.get("https://test.example.com").mock(
            return_value=httpx.Response(
                200,
                content=b"ok",
                headers=[("set-cookie", "session=abc123; Secure; HttpOnly; SameSite=Strict")],
            )
        )
        findings = await check_cookie_security(config)
        assert len(findings) == 0


# ── Auth Scanner ───────────────────────────────────────────────

class TestAuthScanner:
    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_exposed_admin(self, config):
        respx.get("https://test.example.com/admin").mock(
            return_value=httpx.Response(200, text="<h1>Admin Dashboard</h1>")
        )
        findings = await check_auth_bypass(config, ["https://test.example.com/admin"])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    @respx.mock
    @pytest.mark.asyncio
    async def test_admin_redirect_not_flagged(self, config):
        # Mock both the admin endpoint and the login redirect target
        respx.get("https://test.example.com/admin").mock(
            return_value=httpx.Response(302, headers={"Location": "/login"})
        )
        respx.get("https://test.example.com/login").mock(
            return_value=httpx.Response(200, text="Login page")
        )
        findings = await check_auth_bypass(config, ["https://test.example.com/admin"])
        assert len(findings) == 0


# ── Param Scanner ──────────────────────────────────────────────

class TestParamScanner:
    @respx.mock
    @pytest.mark.asyncio
    async def test_sqli_detection(self, config):
        """SQLi: payload with SQL error in response."""
        import re as _re

        def _sqli_responder(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            # Return SQL error when payload contains URL-encoded single quote
            # SQLi payloads are URL-encoded: ' becomes %27
            if "%27" in url:
                return httpx.Response(
                    200, text="You have an error in your SQL syntax near line 1"
                )
            return httpx.Response(200, text="normal page")

        route = respx.route(method="GET", url=_re.compile(r"https://test\.example\.com/.*"))
        route.side_effect = _sqli_responder
        findings = await check_sqli(config, "https://test.example.com/search?q=hello")
        assert any("SQL Injection" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_xss_detection(self, config):
        """XSS: payload reflected in response body."""
        route = respx.get(re.compile(r"https://test\.example\.com/search.*"))

        def _xss_responder(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "%3Cscript%3E" in url or "<script>" in url:
                return httpx.Response(200, text='<div><script>alert(1)</script></div>')
            return httpx.Response(200, text="normal page")

        route.side_effect = _xss_responder
        findings = await check_xss(config, "https://test.example.com/search?q=hello")
        assert any("XSS" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_path_traversal_detection(self, config):
        """Path traversal: /etc/passwd content returned."""
        route = respx.get(re.compile(r"https://test\.example\.com/view.*"))
        route.side_effect = [
            httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash"),
        ] + [httpx.Response(200, text="not found")] * 50
        findings = await check_path_traversal(config, "https://test.example.com/view")
        assert any("Path Traversal" in f.title for f in findings)

    def test_extract_forms(self):
        html = '''
        <form action="/login" method="post">
            <input name="username" type="text">
            <input name="password" type="password">
        </form>
        '''
        forms = _extract_forms(html, "https://test.example.com")
        assert len(forms) == 1
        url, params = forms[0]
        assert url == "https://test.example.com/login"
        assert "username" in params
        assert "password" in params


# ── API Scanner ────────────────────────────────────────────────

ALL_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/graphql",
    "/login", "/register", "/signup", "/signin",
    "/admin", "/dashboard", "/panel",
    "/search", "/query", "/upload", "/files",
    "/wp-admin", "/wp-login.php", "/.env", "/config",
    "/debug", "/swagger", "/docs", "/api-docs",
]


class TestApiScanner:
    @respx.mock
    @pytest.mark.asyncio
    async def test_swagger_exposed(self, config):
        respx.get("https://test.example.com/swagger").mock(
            return_value=httpx.Response(200, text='{"swagger": "2.0"}')
        )
        for path in ALL_API_PATHS:
            if path != "/swagger":
                respx.get(f"https://test.example.com{path}").mock(return_value=httpx.Response(404))
        findings = await check_api_endpoints(config)
        assert any("API Documentation" in f.title for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_graphql_introspection(self, config):
        def _api_responder(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/graphql":
                return httpx.Response(200, text='{"data": {"__schema": {"queryType": {"name": "Query"}}, "graphql": true}}')
            return httpx.Response(404)

        route = respx.route(method="GET", url=re.compile(r"https://test\.example\.com/.*"))
        route.side_effect = _api_responder
        findings = await check_api_endpoints(config)
        assert any("GraphQL" in f.title for f in findings), f"Got: {[f.title for f in findings]}"


# ── WebScanner Orchestrator ────────────────────────────────────

class TestWebScanner:
    def test_init(self, context):
        scanner = WebScanner(context=context)
        assert scanner.name == "web_scanner"
        assert scanner.description == "OWASP Top 10 web vulnerability scanner"

    @respx.mock
    @pytest.mark.asyncio
    async def test_validate_target_reachable(self, context):
        respx.get("https://test.example.com").mock(return_value=httpx.Response(200))
        scanner = WebScanner(context=context)
        assert await scanner.validate_target() is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_validate_target_unreachable(self, context):
        respx.get("https://test.example.com").mock(side_effect=httpx.ConnectError("fail"))
        scanner = WebScanner(context=context)
        assert await scanner.validate_target() is False
