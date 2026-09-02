"""Cookie security scanner.

Checks Set-Cookie headers for missing Secure, HttpOnly, and SameSite flags.
"""

from __future__ import annotations

import httpx

from aegisx.core.config import AegisxConfig
from aegisx.core.context import Finding, Severity
from aegisx.utils.logger import get_logger

logger = get_logger("cookie_scanner")


async def check_cookie_security(config: AegisxConfig) -> list[Finding]:
    """Check for insecure cookie configuration."""
    findings: list[Finding] = []

    try:
        async with httpx.AsyncClient(
            timeout=config.timeout_seconds,
            follow_redirects=True,
            verify=False,  # noqa: S501
        ) as client:
            response = await client.get(
                config.target_url,
                headers={"User-Agent": config.user_agent},
            )

            cookie_headers = response.headers.get_list("set-cookie")
            is_https = config.target_url.startswith("https")

            for cookie in cookie_headers:
                cookie_lower = cookie.lower()
                cookie_name = cookie.split("=")[0].strip()

                # Missing Secure flag
                if is_https and "secure" not in cookie_lower:
                    findings.append(Finding(
                        title=f"Insecure Cookie: {cookie_name}",
                        description=(
                            f"Cookie '{cookie_name}' is missing the Secure flag. "
                            "It will be sent over unencrypted HTTP connections."
                        ),
                        severity=Severity.LOW,
                        cwe_id="CWE-614",
                        owasp_category="A05:2021",
                        url=config.target_url,
                        method="GET",
                        evidence=f"Set-Cookie: {cookie[:200]}",
                        remediation="Add the Secure flag to all cookies.",
                    ))

                # Missing HttpOnly flag
                if "httponly" not in cookie_lower:
                    findings.append(Finding(
                        title=f"Cookie Missing HttpOnly: {cookie_name}",
                        description=(
                            f"Cookie '{cookie_name}' is missing the HttpOnly flag. "
                            "It can be accessed via JavaScript (XSS attacks)."
                        ),
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-1004",
                        owasp_category="A05:2021",
                        url=config.target_url,
                        method="GET",
                        evidence=f"Set-Cookie: {cookie[:200]}",
                        remediation="Add the HttpOnly flag to all cookies.",
                    ))

                # Missing SameSite attribute
                if "samesite" not in cookie_lower:
                    findings.append(Finding(
                        title=f"Cookie Missing SameSite: {cookie_name}",
                        description=(
                            f"Cookie '{cookie_name}' is missing the SameSite attribute. "
                            "It may be vulnerable to CSRF attacks."
                        ),
                        severity=Severity.LOW,
                        cwe_id="CWE-1275",
                        owasp_category="A01:2021",
                        url=config.target_url,
                        method="GET",
                        evidence=f"Set-Cookie: {cookie[:200]}",
                        remediation="Add SameSite=Lax or SameSite=Strict to all cookies.",
                    ))

    except (httpx.RequestError, httpx.TimeoutException) as exc:
        logger.debug("Cookie security check failed: %s", exc)

    return findings
