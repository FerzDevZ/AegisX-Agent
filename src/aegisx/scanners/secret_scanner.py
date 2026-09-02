"""Secret scanner — detects hardcoded secrets and sensitive data in responses.

Improvements:
- Scans JavaScript files for embedded secrets
- More comprehensive path list
- Scans linked resources
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from aegisx.core.context import Finding, ScanContext, Severity
from aegisx.scanners.base_scanner import BaseScanner
from aegisx.utils.logger import get_logger

logger = get_logger("secret_scanner")


class SecretScanner(BaseScanner):
    """Scans target responses for exposed secrets and sensitive data."""

    name = "secret_scanner"
    description = "Detects hardcoded secrets, API keys, and sensitive data exposure"

    # Regex patterns for common secrets
    SECRET_PATTERNS = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key", Severity.CRITICAL, 9.0),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", Severity.CRITICAL, 9.0),
        (r"sk-[A-Za-z0-9]{48}", "OpenAI API Key", Severity.CRITICAL, 9.0),
        (r"xox[bpsa]-[A-Za-z0-9-]+", "Slack Token", Severity.CRITICAL, 9.0),
        (r"eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}", "JWT Token", Severity.HIGH, 7.5),
        (r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}", "API Key", Severity.HIGH, 7.0),
        (r"(?i)secret[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}", "Secret Key", Severity.HIGH, 7.0),
        (r"(?i)password\s*[:=]\s*['\"]?[^\s'\"]{8,}", "Hardcoded Password", Severity.HIGH, 7.5),
        (r"(?i)database[_-]?url\s*[:=]\s*['\"]?[^\s'\"]+", "Database URL", Severity.CRITICAL, 9.0),
        (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Key", Severity.CRITICAL, 9.5),
        (r"(?i)bearer\s+[A-Za-z0-9_\-\.]+", "Bearer Token", Severity.HIGH, 7.0),
        (r"(?i)basic\s+[A-Za-z0-9+/=]{20,}", "Basic Auth Credentials", Severity.HIGH, 7.0),
        (r"(?i)mysql://[^\s]+", "MySQL Connection String", Severity.CRITICAL, 9.0),
        (r"(?i)postgres(ql)?://[^\s]+", "PostgreSQL Connection String", Severity.CRITICAL, 9.0),
        (r"(?i)mongodb(\+srv)?://[^\s]+", "MongoDB Connection String", Severity.CRITICAL, 9.0),
        (r"(?i)redis://[^\s]+", "Redis Connection String", Severity.HIGH, 7.0),
        (r"sk_live_[A-Za-z0-9]+", "Stripe Live Key", Severity.CRITICAL, 9.5),
        (r"rk_live_[A-Za-z0-9]+", "Stripe Restricted Key", Severity.CRITICAL, 9.5),
        (r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}", "AWS Secret Key", Severity.CRITICAL, 9.5),
    ]

    # Extended list of paths to scan
    SECRET_PATHS = [
        "/.env", "/.env.local", "/.env.production", "/.env.development",
        "/.env.staging", "/.env.backup",
        "/config.json", "/config.yml", "/config.yaml", "/config.js",
        "/config.php", "/config.py", "/config.rb",
        "/wp-config.php", "/wp-config.php.bak",
        "/.git/config", "/.git/HEAD",
        "/.htaccess", "/.htpasswd",
        "/server.js", "/app.js", "/main.js", "/bundle.js",
        "/robots.txt", "/sitemap.xml",
        "/swagger.json", "/openapi.json", "/swagger-ui/",
        "/graphql", "/graphiql",
        "/debug", "/debug/vars", "/debug/pprof/",
        "/phpinfo.php", "/info.php", "/test.php",
        "/server-status", "/server-info",
        "/elmah.axd", "/trace.axd",
        "/backup", "/backup.sql", "/backup.zip", "/dump.sql",
        "/database.sql", "/db.sql",
        "/package.json", "/composer.json", "/Gemfile",
        "/Dockerfile", "/docker-compose.yml",
        "/.aws/credentials",
        "/firebase.json",
        "/.ssh/authorized_keys",
    ]

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
        """Scan target for exposed secrets."""
        findings = []

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                # 1. Scan main page
                response = await client.get(
                    self.config.target_url,
                    headers={"User-Agent": self.config.user_agent},
                )

                findings += self._scan_content(
                    response.text,
                    self.config.target_url,
                    "Response Body",
                )

                # 2. Scan headers
                for header, value in response.headers.items():
                    findings += self._scan_content(
                        f"{header}: {value}",
                        self.config.target_url,
                        f"Header: {header}",
                    )

                # 3. Scan common paths
                for path in self.SECRET_PATHS:
                    try:
                        url = urljoin(self.config.target_url, path)
                        resp = await client.get(
                            url,
                            headers={"User-Agent": self.config.user_agent},
                            follow_redirects=False,
                        )
                        if resp.status_code == 200:
                            findings += self._scan_content(
                                resp.text[:3000],
                                url,
                                f"Path: {path}",
                            )
                    except httpx.RequestError:
                        continue

                # 4. Scan JavaScript files found in HTML
                findings += await self._scan_js_files(client, response.text)

        except Exception as e:
            logger.error("Secret scan failed: %s", e)

        return findings

    async def _scan_js_files(self, client: httpx.AsyncClient, html: str) -> list[Finding]:
        """Find and scan JavaScript files for secrets."""
        findings = []

        # Find script src attributes
        script_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE)
        js_urls = script_pattern.findall(html)

        for js_url in js_urls[:5]:  # Limit to 5 JS files
            try:
                if js_url.startswith("//"):
                    js_url = "https:" + js_url
                elif js_url.startswith("/"):
                    js_url = urljoin(self.config.target_url, js_url)
                elif not js_url.startswith("http"):
                    js_url = urljoin(self.config.target_url, js_url)

                resp = await client.get(
                    js_url,
                    headers={"User-Agent": self.config.user_agent},
                )
                if resp.status_code == 200:
                    findings += self._scan_content(
                        resp.text[:5000],
                        js_url,
                        f"JS File: {js_url}",
                    )
            except httpx.RequestError:
                continue

        return findings

    def _scan_content(
        self, content: str, url: str, source: str
    ) -> list[Finding]:
        """Scan content for secret patterns."""
        findings = []

        for pattern, name, severity, cvss in self.SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                # Skip common false positives
                if self._is_false_positive(match, name):
                    continue

                evidence = match[:100] + "..." if len(match) > 100 else match

                findings.append(Finding(
                    title=f"Exposed {name}",
                    description=(
                        f"A {name} was found in {source}. "
                        "Exposed credentials can be used by attackers to access "
                        "the associated service."
                    ),
                    severity=severity,
                    cvss_score=cvss,
                    cwe_id="CWE-798",
                    owasp_category="A07:2021",
                    url=url,
                    evidence=evidence,
                    remediation=(
                        f"Rotate the exposed {name} immediately. "
                        "Move all secrets to environment variables or a secrets manager."
                    ),
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                    ],
                ))

        return findings

    def _is_false_positive(self, match: str, name: str) -> bool:
        """Check for common false positives."""
        # AWS example key
        if name == "AWS Access Key" and "EXAMPLE" in match:
            return True
        # Placeholder values
        if match in ["your-api-key", "xxx", "changeme", "placeholder", "test"]:
            return True
        # Too short to be real
        if len(match) < 10:
            return True
        return False
