"""Security header and CORS scanner.

Checks for missing security headers, CORS misconfigurations,
information disclosure, and dangerous HTTP methods.
"""

from __future__ import annotations

import re

import httpx

from aegisx.core.config import AegisxConfig
from aegisx.core.context import Finding, Severity
from aegisx.utils.http_client import create_client
from aegisx.utils.logger import get_logger

logger = get_logger("header_scanner")

# Headers that should be present on every response
REQUIRED_HEADERS: list[dict[str, str]] = [
    {
        "header": "content-security-policy",
        "title": "Missing Content-Security-Policy Header",
        "description": "CSP header is not set. Without CSP, the application is vulnerable to XSS, data injection, and clickjacking attacks.",
        "severity": "MEDIUM",
        "cwe": "CWE-693",
    },
    {
        "header": "strict-transport-security",
        "title": "Missing HSTS Header",
        "description": "Strict-Transport-Security header is not set. Users can be downgraded to HTTP via MITM attacks.",
        "severity": "MEDIUM",
        "cwe": "CWE-319",
    },
    {
        "header": "x-content-type-options",
        "title": "Missing X-Content-Type-Options Header",
        "description": "X-Content-Type-Options header is not set. Browsers may MIME-sniff responses, leading to security issues.",
        "severity": "LOW",
        "cwe": "CWE-693",
    },
    {
        "header": "x-frame-options",
        "title": "Missing X-Frame-Options Header",
        "description": "X-Frame-Options header is not set. The application may be embedded in iframes for clickjacking attacks.",
        "severity": "MEDIUM",
        "cwe": "CWE-1021",
    },
    {
        "header": "referrer-policy",
        "title": "Missing Referrer-Policy Header",
        "description": "Referrer-Policy header is not set. Sensitive URL information may leak to third parties.",
        "severity": "LOW",
        "cwe": "CWE-200",
    },
    {
        "header": "permissions-policy",
        "title": "Missing Permissions-Policy Header",
        "description": "Permissions-Policy header is not set. Browser features like camera, microphone, and geolocation are not restricted.",
        "severity": "LOW",
        "cwe": "CWE-693",
    },
]


def _severity(value: str) -> Severity:
    return Severity(value.lower())


async def check_security_headers(config: AegisxConfig) -> list[Finding]:
    """Check for missing security headers on the target."""
    findings: list[Finding] = []

    try:
        async with create_client(config) as client:
            response = await client.get(config.target_url)
            headers = {k.lower(): v for k, v in response.headers.items()}

            # WAF/CDN challenge detection
            if headers.get("x-vercel-mitigated") == "challenge":
                findings.append(Finding(
                    title="WAF/CDN Challenge Detected",
                    description=(
                        "Vercel is serving a challenge page (WAF). Security headers may be "
                        "missing from the challenge response but present on the real page."
                    ),
                    severity=Severity.INFO,
                    cwe_id="CWE-16",
                    owasp_category="A05:2021",
                    url=config.target_url,
                    endpoint="/",
                    method="GET",
                    evidence=f"x-vercel-mitigated: {headers.get('x-vercel-mitigated')}",
                    remediation="Configure WAF to allow security scanner User-Agents.",
                ))
                return findings

            # Check each required header
            for check in REQUIRED_HEADERS:
                if check["header"] not in headers:
                    findings.append(Finding(
                        title=check["title"],
                        description=check["description"],
                        severity=_severity(check["severity"]),
                        cwe_id=check["cwe"],
                        owasp_category="A05:2021",
                        url=config.target_url,
                        endpoint="/",
                        method="GET",
                        remediation=f"Add the {check['header']} header to all HTTP responses.",
                        references=["https://owasp.org/www-project-secure-headers/"],
                    ))

    except (httpx.RequestError, httpx.TimeoutException) as exc:
        logger.warning("Security header check failed: %s", exc)

    return findings


async def check_cors(config: AegisxConfig) -> list[Finding]:
    """Check for overly permissive CORS configuration."""
    findings: list[Finding] = []

    try:
        async with create_client(config) as client:
            # Test 1: Wildcard origin
            response = await client.get(
                config.target_url,
                headers={
                    "Origin": "https://evil-attacker.com",
                },
            )
            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                findings.append(Finding(
                    title="Wildcard CORS Configuration",
                    description=(
                        "Access-Control-Allow-Origin is set to '*', allowing any origin "
                        "to make cross-origin requests. This can lead to data theft."
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=5.0,
                    cwe_id="CWE-942",
                    owasp_category="A05:2021",
                    url=config.target_url,
                    method="GET",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="Restrict CORS to specific trusted origins. Never use '*' with credentials.",
                    references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                ))
            elif acao == "https://evil-attacker.com":
                findings.append(Finding(
                    title="CORS Origin Reflection",
                    description=(
                        "The server reflects the attacker-controlled Origin header back "
                        "in Access-Control-Allow-Origin, bypassing CORS protections. "
                        + ("With credentials, this allows full account takeover." if acac == "true" else "")
                    ),
                    severity=Severity.HIGH if acac == "true" else Severity.MEDIUM,
                    cvss_score=8.1 if acac == "true" else 6.0,
                    cwe_id="CWE-942",
                    owasp_category="A05:2021",
                    url=config.target_url,
                    method="GET",
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    remediation="Validate Origin against a whitelist before reflecting it.",
                ))

            # Test 2: Null origin
            response2 = await client.get(
                config.target_url,
                headers={
                    "User-Agent": config.user_agent,
                    "Origin": "null",
                },
            )
            acao2 = response2.headers.get("access-control-allow-origin", "")
            if acao2 == "null":
                findings.append(Finding(
                    title="CORS Null Origin Allowed",
                    description=(
                        "The server accepts 'null' as a valid Origin. Attackers can "
                        "exploit this using sandboxed iframes."
                    ),
                    severity=Severity.MEDIUM,
                    cvss_score=5.0,
                    cwe_id="CWE-942",
                    owasp_category="A05:2021",
                    url=config.target_url,
                    method="GET",
                    evidence=f"Access-Control-Allow-Origin: {acao2}",
                    remediation="Reject 'null' origin in CORS configuration.",
                ))

    except (httpx.RequestError, httpx.TimeoutException) as exc:
        logger.warning("CORS check failed: %s", exc)

    return findings


async def check_info_disclosure(config: AegisxConfig) -> list[Finding]:
    """Check for information disclosure in response headers and body."""
    findings: list[Finding] = []

    try:
        async with create_client(config) as client:
            response = await client.get(config.target_url)
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Server header version
            server = headers.get("server", "")
            if server and any(c.isdigit() for c in server):
                findings.append(Finding(
                    title="Server Version Disclosure",
                    description=f"The Server header reveals version information: '{server}'. This helps attackers identify specific vulnerabilities.",
                    severity=Severity.LOW,
                    cwe_id="CWE-200",
                    owasp_category="A05:2021",
                    url=config.target_url,
                    method="GET",
                    evidence=f"Server: {server}",
                    remediation="Remove or obfuscate the Server header version information.",
                ))

            # X-Powered-By
            powered_by = headers.get("x-powered-by", "")
            if powered_by:
                findings.append(Finding(
                    title="X-Powered-By Header Disclosure",
                    description=f"The X-Powered-By header reveals: '{powered_by}'. This exposes the technology stack to attackers.",
                    severity=Severity.LOW,
                    cwe_id="CWE-200",
                    owasp_category="A05:2021",
                    url=config.target_url,
                    method="GET",
                    evidence=f"X-Powered-By: {powered_by}",
                    remediation="Remove the X-Powered-By header from production responses.",
                ))

            # Source maps
            if "sourceMappingURL" in response.text:
                findings.append(Finding(
                    title="Source Map Exposed",
                    description="A source map reference was found in the response. Source maps expose the original source code to attackers.",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-200",
                    owasp_category="A05:2021",
                    url=config.target_url,
                    method="GET",
                    evidence="sourceMappingURL found in response",
                    remediation="Remove source maps from production builds.",
                ))

            # HTML comments with sensitive keywords
            sensitive_patterns = [
                "todo", "fixme", "hack", "bug", "password",
                "secret", "key", "token", "admin", "debug",
                "internal", "private", "backup",
            ]
            comments = re.findall(r"<!--(.*?)-->", response.text, re.DOTALL)
            for comment in comments:
                comment_lower = comment.lower()
                for pattern in sensitive_patterns:
                    if pattern in comment_lower:
                        findings.append(Finding(
                            title="Sensitive Information in HTML Comment",
                            description=f"HTML comment contains sensitive keyword '{pattern}'. Comments may expose internal information.",
                            severity=Severity.LOW,
                            cwe_id="CWE-615",
                            owasp_category="A05:2021",
                            url=config.target_url,
                            method="GET",
                            evidence=comment.strip()[:200],
                            remediation="Remove sensitive information from HTML comments.",
                        ))
                        break

    except (httpx.RequestError, httpx.TimeoutException) as exc:
        logger.warning("Info disclosure check failed: %s", exc)

    return findings


async def check_http_methods(config: AegisxConfig) -> list[Finding]:
    """Check for dangerous HTTP methods (TRACE, DELETE, PUT, PATCH)."""
    findings: list[Finding] = []

    try:
        async with create_client(config) as client:
            response = await client.options(config.target_url)
            allow = response.headers.get("allow", "").upper()
            dangerous = {"TRACE": "High", "DELETE": "Low", "PUT": "Low", "PATCH": "Low"}

            for method, sev in dangerous.items():
                if method in allow:
                    findings.append(Finding(
                        title=f"HTTP Method Allowed: {method}",
                        description=(
                            f"The {method} HTTP method is enabled. "
                            + ("TRACE can be used for cross-site tracing attacks." if method == "TRACE"
                               else f"{method} may expose additional attack surface.")
                        ),
                        severity=Severity.HIGH if method == "TRACE" else Severity.LOW,
                        cwe_id="CWE-16",
                        owasp_category="A05:2021",
                        url=config.target_url,
                        method=method,
                        evidence=f"Allow: {allow}",
                        remediation=f"Disable the {method} method if not needed.",
                    ))

    except (httpx.RequestError, httpx.TimeoutException) as exc:
        logger.debug("HTTP methods check failed: %s", exc)

    return findings
