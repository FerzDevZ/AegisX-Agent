"""Secret scanner — detects hardcoded secrets and sensitive data in responses."""

from __future__ import annotations

import re

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
        (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}", "JWT Token", Severity.HIGH, 7.5),
        (r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}", "API Key", Severity.HIGH, 7.0),
        (r"(?i)secret[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}", "Secret Key", Severity.HIGH, 7.0),
        (r"(?i)password\s*[:=]\s*['\"]?[^\s'\"]{8,}", "Hardcoded Password", Severity.HIGH, 7.5),
        (r"(?i)database[_-]?url\s*[:=]\s*['\"]?[^\s'\"]+", "Database URL", Severity.CRITICAL, 9.0),
        (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private Key", Severity.CRITICAL, 9.5),
        (r"(?i)bearer\s+[A-Za-z0-9_\-\.]+", "Bearer Token", Severity.HIGH, 7.0),
        (r"(?i)basic\s+[A-Za-z0-9+/=]{20,}", "Basic Auth Credentials", Severity.HIGH, 7.0),
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
                # Scan main page
                response = await client.get(
                    self.config.target_url,
                    headers={"User-Agent": self.config.user_agent},
                )

                findings += self._scan_content(
                    response.text,
                    self.config.target_url,
                    "Response Body",
                )

                # Scan headers
                for header, value in response.headers.items():
                    findings += self._scan_content(
                        f"{header}: {value}",
                        self.config.target_url,
                        f"Header: {header}",
                    )

                # Scan common paths that might expose secrets
                secret_paths = [
                    "/.env", "/.env.local", "/.env.production",
                    "/config.json", "/config.yml", "/config.yaml",
                    "/wp-config.php", "/.git/config",
                    "/server.js", "/app.js", "/.htaccess",
                    "/robots.txt", "/sitemap.xml",
                    "/swagger.json", "/openapi.json",
                ]

                for path in secret_paths:
                    try:
                        url = urljoin(self.config.target_url, path)
                        resp = await client.get(
                            url,
                            headers={"User-Agent": self.config.user_agent},
                            follow_redirects=False,
                        )
                        if resp.status_code == 200:
                            findings += self._scan_content(
                                resp.text[:2000],  # Limit to avoid large responses
                                url,
                                f"Path: {path}",
                            )
                    except httpx.RequestError:
                        continue

        except Exception as e:
            logger.error("Secret scan failed: %s", e)

        return findings

    def _scan_content(
        self, content: str, url: str, source: str
    ) -> list[Finding]:
        """Scan content for secret patterns."""
        findings = []

        for pattern, name, severity, cvss in self.SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                # Truncate for evidence
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
                        "Move all secrets to environment variables or a secrets manager. "
                        "Add the secret to .gitignore if it was in source code. "
                        "Implement secret scanning in CI/CD pipeline."
                    ),
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                    ],
                ))

        return findings


def urljoin(base: str, path: str) -> str:
    """Join base URL with a path."""
    if base.endswith("/"):
        return base + path.lstrip("/")
    return base + "/" + path.lstrip("/")
