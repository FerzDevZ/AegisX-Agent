"""Configuration scanner — detects security misconfigurations.

Improvements:
- Checks multiple pages, not just root
- More header checks
- Detects exposed admin panels
- Checks for common framework-specific issues
"""

from __future__ import annotations

from urllib.parse import urljoin

import httpx

from aegisx.core.context import Finding, ScanContext, Severity
from aegisx.scanners.base_scanner import BaseScanner
from aegisx.utils.http_client import create_client
from aegisx.utils.logger import get_logger

logger = get_logger("config_scanner")


class ConfigScanner(BaseScanner):
    """Scans for security misconfigurations."""

    name = "config_scanner"
    description = "Detects security misconfigurations (debug mode, default creds, etc.)"

    # Paths to check for misconfigurations
    CHECK_PATHS = [
        "/", "/admin", "/login", "/wp-admin",
        "/debug", "/.env", "/config",
        "/robots.txt", "/sitemap.xml",
    ]

    async def validate_target(self) -> bool:
        """Validate target is reachable."""
        try:
            async with create_client(self.config) as client:
                response = await client.get(self.config.target_url)
                return response.status_code < 500
        except Exception:
            return False

    async def scan(self) -> list[Finding]:
        """Execute configuration checks."""
        findings = []

        try:
            async with create_client(self.config) as client:
                # Check main page
                response = await client.get(
                    self.config.target_url,
                    headers={"User-Agent": self.config.user_agent},
                )

                findings += self._check_debug_mode(response)
                findings += self._check_default_page(response)
                findings += self._check_directory_listing(response)
                findings += self._check_http_methods(response)
                findings += self._check_server_info(response)
                findings += self._check_exposed_admin(response)
                findings += self._check_cors_misconfig(response)
                findings += self._check_cache_control(response)

        except Exception as e:
            logger.error("Config scan failed: %s", e)

        # Check sensitive paths (async)
        try:
            async with create_client(self.config) as client:
                findings += await self._check_sensitive_paths(client)
        except Exception as e:
            logger.error("Sensitive paths check failed: %s", e)

        return findings

    def _check_debug_mode(self, response: httpx.Response) -> list[Finding]:
        """Check if debug mode is enabled."""
        findings = []
        body = response.text.lower()

        debug_indicators = [
            ("debug mode", "Debug mode appears to be enabled"),
            ("stack trace", "Stack trace is visible in responses"),
            ("traceback", "Python traceback is visible"),
            ("phpinfo()", "phpinfo() output is exposed"),
            ("django debug", "Django debug mode may be active"),
            ("laravel debug", "Laravel debug mode may be active"),
            ("application error", "Application error page exposed"),
            ("whoops", "Whoops error handler exposed"),
            ("error_status: 500", "Server error status exposed"),
        ]

        for indicator, description in debug_indicators:
            if indicator in body:
                findings.append(Finding(
                    title="Debug Mode / Error Details Exposed",
                    description=(
                        f"{description}. Debug mode in production exposes sensitive "
                        "information including stack traces and environment variables."
                    ),
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-215",
                    owasp_category="A05:2021",
                    url=str(response.url),
                    method="GET",
                    evidence=description,
                    remediation=(
                        "Disable debug mode in production. "
                        "Use environment-specific configuration."
                    ),
                ))
                break

        return findings

    def _check_default_page(self, response: httpx.Response) -> list[Finding]:
        """Check for default installation pages."""
        findings = []
        body = response.text.lower()

        default_indicators = [
            ("apache2 ubuntu default page", "Apache default page"),
            ("nginx welcome", "Nginx default page"),
            ("iis-10.0", "IIS default page"),
            ("tomcat", "Tomcat default page"),
            ("welcome to docker", "Docker default page"),
            ("it works!", "Apache default page"),
            ("apache http server", "Apache default page"),
        ]

        for indicator, name in default_indicators:
            if indicator in body:
                findings.append(Finding(
                    title=f"Default Installation Page: {name}",
                    description=(
                        f"The server displays the {name}. "
                        "Default pages reveal server technology and version."
                    ),
                    severity=Severity.LOW,
                    cwe_id="CWE-200",
                    owasp_category="A05:2021",
                    url=str(response.url),
                    method="GET",
                    remediation=f"Replace the {name} with application content.",
                ))
                break

        return findings

    def _check_directory_listing(self, response: httpx.Response) -> list[Finding]:
        """Check if directory listing is enabled."""
        findings = []
        body = response.text.lower()

        listing_indicators = [
            "index of /",
            "directory listing for",
            "parent directory",
            "<title>index of",
            "name last modified size",
        ]

        if any(indicator in body for indicator in listing_indicators):
            findings.append(Finding(
                title="Directory Listing Enabled",
                description=(
                    "The server displays directory contents when no index file exists. "
                    "This exposes file structure and potentially sensitive files."
                ),
                severity=Severity.MEDIUM,
                cwe_id="CWE-548",
                owasp_category="A01:2021",
                url=str(response.url),
                method="GET",
                remediation=(
                    "Disable directory listing in web server configuration. "
                    "Add index files to directories."
                ),
            ))

        return findings

    def _check_http_methods(self, response: httpx.Response) -> list[Finding]:
        """Check for dangerous HTTP methods enabled."""
        findings = []

        allow = response.headers.get("allow", "")
        dangerous_methods = ["TRACE", "DEBUG"]

        for method in dangerous_methods:
            if method in allow.upper():
                findings.append(Finding(
                    title=f"Dangerous HTTP Method: {method}",
                    description=(
                        f"The {method} HTTP method is enabled. "
                        + ("TRACE can be used for cross-site tracing attacks." if method == "TRACE"
                           else f"{method} may expose additional attack surface.")
                    ),
                    severity=Severity.HIGH if method == "TRACE" else Severity.LOW,
                    cwe_id="CWE-16",
                    owasp_category="A05:2021",
                    url=str(response.url),
                    method=method,
                    evidence=f"Allow: {allow}",
                    remediation=f"Disable the {method} method in web server configuration.",
                ))

        return findings

    def _check_server_info(self, response: httpx.Response) -> list[Finding]:
        """Check for excessive server information exposure."""
        findings = []

        headers = {k.lower(): v for k, v in response.headers.items()}

        # Check X-Powered-By
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            findings.append(Finding(
                title="X-Powered-By Header Exposed",
                description=(
                    f"The X-Powered-By header reveals: '{powered_by}'. "
                    "This exposes the technology stack."
                ),
                severity=Severity.LOW,
                cwe_id="CWE-200",
                owasp_category="A05:2021",
                url=str(response.url),
                method="GET",
                evidence=f"X-Powered-By: {powered_by}",
                remediation="Remove the X-Powered-By header from production.",
            ))

        # Check for verbose error pages
        if response.status_code >= 400:
            body = response.text.lower()
            error_indicators = [
                "exception", "stack trace", "traceback",
                "debug", "error in", "line number",
                "nullpointer", "sqlstate",
            ]
            if any(indicator in body for indicator in error_indicators):
                findings.append(Finding(
                    title="Verbose Error Page",
                    description=(
                        "The server displays detailed error information including "
                        "stack traces or debug information."
                    ),
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-209",
                    owasp_category="A05:2021",
                    url=str(response.url),
                    method="GET",
                    evidence=response.text[:500],
                    remediation=(
                        "Configure custom error pages that don't expose "
                        "internal details. Log errors server-side only."
                    ),
                ))

        return findings

    def _check_exposed_admin(self, response: httpx.Response) -> list[Finding]:
        """Check for exposed admin panels."""
        findings = []
        body = response.text.lower()

        # Check for common admin panel indicators
        admin_indicators = [
            ("admin login", "Admin login page exposed"),
            ("administrator login", "Administrator login exposed"),
            ("phpmyadmin", "phpMyAdmin exposed"),
            ("adminer", "Adminer database admin exposed"),
            ("cpanel", "cPanel exposed"),
            ("webmin", "Webmin exposed"),
        ]

        for indicator, description in admin_indicators:
            if indicator in body:
                findings.append(Finding(
                    title="Admin Panel Exposed",
                    description=(
                        f"{description}. Exposed admin panels are "
                        "prime targets for brute-force attacks."
                    ),
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-284",
                    owasp_category="A07:2021",
                    url=str(response.url),
                    method="GET",
                    evidence=f"Indicator: {indicator}",
                    remediation="Restrict admin panel access to internal networks or VPN.",
                ))
                break

        return findings

    def _check_cors_misconfig(self, response: httpx.Response) -> list[Finding]:
        """Check for CORS misconfiguration."""
        findings = []

        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "")

        if acao == "*" and acac.lower() == "true":
            findings.append(Finding(
                title="CORS Wildcard with Credentials",
                description=(
                    "Access-Control-Allow-Origin is '*' with credentials enabled. "
                    "This is a critical misconfiguration allowing credential theft."
                ),
                severity=Severity.HIGH,
                cvss_score=8.0,
                cwe_id="CWE-942",
                owasp_category="A05:2021",
                url=str(response.url),
                method="GET",
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                remediation="Restrict CORS origins and never use '*' with credentials.",
            ))

        return findings

    def _check_cache_control(self, response: httpx.Response) -> list[Finding]:
        """Check for missing Cache-Control headers on sensitive pages."""
        findings = []

        cache_control = response.headers.get("cache-control", "")
        pragma = response.headers.get("pragma", "")

        # Check if sensitive page lacks cache control
        if not cache_control and not pragma:
            body = response.text.lower()
            sensitive_indicators = ["login", "password", "admin", "auth", "token"]

            for indicator in sensitive_indicators:
                if indicator in str(response.url).lower() or indicator in body[:1000]:
                    findings.append(Finding(
                        title="Missing Cache-Control on Sensitive Page",
                        description=(
                            "This page contains sensitive content but lacks Cache-Control "
                            "headers. Browsers may cache sensitive data."
                        ),
                        severity=Severity.LOW,
                        cwe_id="CWE-525",
                        owasp_category="A05:2021",
                        url=str(response.url),
                        method="GET",
                        remediation="Add 'Cache-Control: no-store' to sensitive pages.",
                    ))
                    break

        return findings

    async def _check_sensitive_paths(self, client: httpx.AsyncClient) -> list[Finding]:
        """Check for exposed sensitive files and paths."""
        findings = []

        sensitive_checks = [
            ("/.env", "Environment File", Severity.HIGH, 7.5),
            ("/.git/config", "Git Configuration", Severity.HIGH, 7.0),
            ("/.git/HEAD", "Git HEAD Reference", Severity.MEDIUM, 5.0),
            ("/server-status", "Apache Server Status", Severity.MEDIUM, 5.0),
            ("/server-info", "Apache Server Info", Severity.MEDIUM, 5.0),
            ("/phpinfo.php", "PHP Info Page", Severity.MEDIUM, 5.0),
            ("/debug/vars", "Go Debug Vars", Severity.HIGH, 7.0),
            ("/debug/pprof/", "Go Debug Profiling", Severity.HIGH, 7.0),
            ("/elmah.axd", "ELMAH Error Log", Severity.HIGH, 7.5),
            ("/trace.axd", "ASP.NET Trace", Severity.HIGH, 7.5),
        ]

        for path, name, severity, cvss in sensitive_checks:
            try:
                url = urljoin(self.config.target_url, path)
                response = await client.get(
                    url,
                    headers={"User-Agent": self.config.user_agent},
                    follow_redirects=False,
                )

                if response.status_code == 200:
                    # Verify it's actual content, not a custom 404
                    body = response.text.lower()
                    if len(response.text) > 100 and not ("not found" in body or "404" in body):
                        findings.append(Finding(
                            title=f"Sensitive Path Exposed: {name}",
                            description=(
                                f"{name} is accessible at {path}. "
                                "This may expose sensitive configuration or debugging information."
                            ),
                            severity=severity,
                            cvss_score=cvss,
                            cwe_id="CWE-200",
                            owasp_category="A05:2021",
                            url=url,
                            endpoint=path,
                            method="GET",
                            evidence=response.text[:300],
                            remediation=f"Restrict access to {path} or remove it entirely.",
                        ))

            except httpx.RequestError:
                continue

        return findings
