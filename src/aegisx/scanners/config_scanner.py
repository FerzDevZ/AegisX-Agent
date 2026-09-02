"""Configuration scanner — detects security misconfigurations."""

from __future__ import annotations

import httpx

from aegisx.core.context import Finding, ScanContext, Severity
from aegisx.scanners.base_scanner import BaseScanner
from aegisx.utils.logger import get_logger

logger = get_logger("config_scanner")


class ConfigScanner(BaseScanner):
    """Scans for security misconfigurations."""

    name = "config_scanner"
    description = "Detects security misconfigurations (debug mode, default creds, etc.)"

    async def validate_target(self) -> bool:
        """Validate target is reachable."""
        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                response = await client.get(
                    self.config.target_url,
                    headers={"User-Agent": self.config.user_agent},
                )
                return response.status_code < 500
        except Exception:
            return False

    async def scan(self) -> list[Finding]:
        """Execute configuration checks."""
        findings = []

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                response = await client.get(
                    self.config.target_url,
                    headers={"User-Agent": self.config.user_agent},
                )

                findings += self._check_debug_mode(response)
                findings += self._check_default_page(response)
                findings += self._check_directory_listing(response)
                findings += self._check_http_methods(response)
                findings += self._check_server_info(response)

        except Exception as e:
            logger.error("Config scan failed: %s", e)

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
        ]

        for indicator, description in debug_indicators:
            if indicator in body:
                findings.append(Finding(
                    title="Debug Mode Enabled",
                    description=(
                        f"{description}. Debug mode in production exposes sensitive "
                        "information including stack traces, environment variables, "
                        "and internal application details."
                    ),
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-215",
                    owasp_category="A05:2021",
                    url=str(response.url),
                    method="GET",
                    evidence=description,
                    remediation=(
                        "Disable debug mode in production. "
                        "Use environment-specific configuration. "
                        "Ensure DEBUG=False in Django, APP_DEBUG=false in Laravel."
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
                    "Add index files to directories. Configure proper access controls."
                ),
            ))

        return findings

    def _check_http_methods(self, response: httpx.Response) -> list[Finding]:
        """Check for dangerous HTTP methods enabled."""
        findings = []

        # The response we have is from a GET; we can check Allow header
        allow = response.headers.get("allow", "")
        dangerous_methods = ["TRACE", "DEBUG", "OPTIONS"]

        for method in dangerous_methods:
            if method in allow.upper():
                severity = Severity.HIGH if method == "TRACE" else Severity.LOW
                findings.append(Finding(
                    title=f"Dangerous HTTP Method: {method}",
                    description=(
                        f"The {method} HTTP method is enabled. "
                        + ("TRACE can be used for cross-site tracing attacks." if method == "TRACE"
                           else f"{method} may expose additional attack surface.")
                    ),
                    severity=severity,
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

        # Check X-Powered-By
        powered_by = response.headers.get("x-powered-by", "")
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
