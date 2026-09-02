"""Authentication bypass scanner.

Checks if protected pages (admin, dashboard, settings) are accessible
without authentication.
"""

from __future__ import annotations

import httpx

from aegisx.core.config import AegisxConfig
from aegisx.core.context import Finding, Severity
from aegisx.utils.logger import get_logger

logger = get_logger("auth_scanner")

# Paths that typically require authentication
PROTECTED_PATHS = ["/admin", "/dashboard", "/panel", "/settings", "/profile"]

# Keywords that indicate a real protected page (not a login redirect)
DASHBOARD_KEYWORDS = ["dashboard", "admin", "panel", "settings", "profile"]


async def check_auth_bypass(
    config: AegisxConfig,
    urls: list[str],
) -> list[Finding]:
    """Check if protected pages are accessible without authentication."""
    findings: list[Finding] = []

    try:
        async with httpx.AsyncClient(
            timeout=config.timeout_seconds,
            follow_redirects=True,
            verify=False,  # noqa: S501
        ) as client:
            for url in urls:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                path = parsed.path.rstrip("/")

                if not any(path.startswith(pp) for pp in PROTECTED_PATHS):
                    continue

                try:
                    response = await client.get(
                        url,
                        headers={"User-Agent": config.user_agent},
                    )

                    if response.status_code == 200:
                        body = response.text.lower()
                        if any(kw in body for kw in DASHBOARD_KEYWORDS):
                            findings.append(Finding(
                                title="Protected Page Accessible Without Auth",
                                description=(
                                    f"The page {path} is accessible without authentication. "
                                    "Protected pages should require login and return 401/403."
                                ),
                                severity=Severity.HIGH,
                                cvss_score=7.5,
                                cwe_id="CWE-306",
                                owasp_category="A07:2021",
                                url=url,
                                endpoint=path,
                                method="GET",
                                evidence=f"HTTP {response.status_code} — page content accessible",
                                remediation="Add authentication middleware to protect sensitive pages.",
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Authentication_Testing/"
                                ],
                            ))

                except (httpx.RequestError, httpx.TimeoutException) as exc:
                    logger.debug("Auth bypass check for %s failed: %s", url, exc)

    except Exception as exc:
        logger.warning("Auth bypass check failed: %s", exc)

    return findings
