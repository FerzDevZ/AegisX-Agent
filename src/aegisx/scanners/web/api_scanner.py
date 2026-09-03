"""API endpoint scanner.

Discovers exposed API documentation (Swagger/OpenAPI, GraphQL introspection)
and verbose error messages at common API paths.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from aegisx.core.config import AegisxConfig
from aegisx.core.context import Finding, Severity
from aegisx.utils.http_client import create_client
from aegisx.utils.logger import get_logger

logger = get_logger("api_scanner")

# Paths commonly hosting API docs or sensitive endpoints
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/graphql",
    "/login", "/register", "/signup", "/signin",
    "/admin", "/dashboard", "/panel",
    "/search", "/query",
    "/upload", "/files",
    "/wp-admin", "/wp-login.php",
    "/.env", "/config", "/debug",
    "/swagger", "/docs", "/api-docs",
]

ERROR_INDICATORS = [
    "exception", "stack trace", "traceback",
    "error in", "line number", "sql state",
    "nullpointer", "typeerror", "referenceerror",
]


async def check_api_endpoints(config: AegisxConfig) -> list[Finding]:
    """Discover exposed API endpoints, docs, and verbose errors."""
    findings: list[Finding] = []
    parsed = urlparse(config.target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    try:
        async with create_client(config) as client:
            for path in API_PATHS:
                try:
                    url = f"{base_url}{path}"
                    resp = await client.get(url)
                    body = resp.text.lower()

                    if resp.status_code == 200:
                        # Swagger / OpenAPI
                        if "swagger" in body or "openapi" in body:
                            findings.append(Finding(
                                title="API Documentation Exposed",
                                description=f"API documentation found at {path}. This exposes the full API surface to attackers.",
                                severity=Severity.MEDIUM,
                                cwe_id="CWE-200",
                                owasp_category="A05:2021",
                                url=url,
                                endpoint=path,
                                method="GET",
                                evidence=resp.text[:300],
                                remediation="Restrict API documentation to internal networks.",
                            ))

                        # GraphQL introspection
                        if "graphql" in body and "__schema" in body:
                            findings.append(Finding(
                                title="GraphQL Introspection Enabled",
                                description="GraphQL introspection is enabled, exposing the entire schema to attackers.",
                                severity=Severity.MEDIUM,
                                cwe_id="CWE-200",
                                owasp_category="A05:2021",
                                url=url,
                                endpoint=path,
                                method="GET",
                                remediation="Disable GraphQL introspection in production.",
                            ))

                    # Verbose error messages
                    if resp.status_code >= 400:
                        if any(ind in body for ind in ERROR_INDICATORS):
                            findings.append(Finding(
                                title=f"Verbose Error at {path}",
                                description=f"The endpoint {path} returns detailed error information.",
                                severity=Severity.LOW,
                                cwe_id="CWE-209",
                                owasp_category="A05:2021",
                                url=url,
                                endpoint=path,
                                method="GET",
                                evidence=resp.text[:300],
                                remediation="Use custom error pages.",
                            ))

                except (httpx.RequestError, httpx.TimeoutException):
                    continue

    except Exception as exc:
        logger.debug("API endpoint check failed: %s", exc)

    return findings
