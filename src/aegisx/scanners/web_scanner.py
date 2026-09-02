"""OWASP Top 10 web vulnerability scanner.

Thin orchestrator that delegates to focused sub-modules:
- web/crawler:       async parallel page discovery
- web/header_scanner: security headers + CORS + info disclosure
- web/cookie_scanner: cookie flag analysis
- web/auth_scanner:  authentication bypass detection
- web/param_scanner: SQLi, XSS, path traversal injection
- web/api_scanner:   API endpoint discovery
"""

from __future__ import annotations

import asyncio

from aegisx.core.context import Finding, ScanContext
from aegisx.scanners.base_scanner import BaseScanner
from aegisx.scanners.web.crawler import crawl_pages
from aegisx.scanners.web.header_scanner import (
    check_security_headers,
    check_cors,
    check_info_disclosure,
    check_http_methods,
)
from aegisx.scanners.web.cookie_scanner import check_cookie_security
from aegisx.scanners.web.auth_scanner import check_auth_bypass
from aegisx.scanners.web.param_scanner import (
    check_sqli,
    check_xss,
    check_path_traversal,
)
from aegisx.scanners.web.api_scanner import check_api_endpoints
from aegisx.utils.logger import get_logger

logger = get_logger("web_scanner")


class WebScanner(BaseScanner):
    """Scans for OWASP Top 10 web vulnerabilities."""

    name = "web_scanner"
    description = "OWASP Top 10 web vulnerability scanner"

    async def validate_target(self) -> bool:
        """Validate that the target is reachable."""
        import httpx

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                resp = await client.get(
                    self.config.target_url,
                    headers={"User-Agent": self.config.user_agent},
                )
                return resp.status_code < 500
        except (httpx.RequestError, httpx.TimeoutException) as exc:
            logger.error("Cannot reach target: %s", exc)
            return False

    async def scan(self) -> list[Finding]:
        """Execute all web vulnerability checks using sub-modules."""
        findings: list[Finding] = []

        # Phase 1: Parallel crawl
        discovered_urls = await crawl_pages(self.config, concurrency=10)

        # Phase 2: Static checks (all run in parallel)
        header_tasks = [
            check_security_headers(self.config),
            check_cors(self.config),
            check_info_disclosure(self.config),
            check_http_methods(self.config),
            check_cookie_security(self.config),
            check_api_endpoints(self.config),
        ]
        static_results = await asyncio.gather(*header_tasks, return_exceptions=True)
        for result in static_results:
            if isinstance(result, list):
                findings.extend(result)
            else:
                logger.warning("Static check failed: %s", result)

        # Phase 3: Auth bypass on discovered pages
        auth_findings = await check_auth_bypass(self.config, discovered_urls)
        findings.extend(auth_findings)

        # Phase 4: Injection tests per discovered page (concurrent, 5 at a time)
        injection_sem = asyncio.Semaphore(5)

        async def _inject_one(url: str) -> list[Finding]:
            async with injection_sem:
                results = await asyncio.gather(
                    check_sqli(self.config, url),
                    check_xss(self.config, url),
                    check_path_traversal(self.config, url),
                    return_exceptions=True,
                )
                out: list[Finding] = []
                for r in results:
                    if isinstance(r, list):
                        out.extend(r)
                    else:
                        logger.debug("Injection check failed for %s: %s", url, r)
                return out

        inject_tasks = [_inject_one(url) for url in discovered_urls]
        inject_results = await asyncio.gather(*inject_tasks)
        for url_findings in inject_results:
            findings.extend(url_findings)

        return findings
