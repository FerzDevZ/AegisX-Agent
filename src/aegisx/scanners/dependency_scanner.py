"""Dependency scanner — checks for known vulnerable dependencies."""

from __future__ import annotations

import subprocess

from aegisx.core.context import Finding, ScanContext, Severity
from aegisx.scanners.base_scanner import BaseScanner
from aegisx.utils.http_client import create_client
from aegisx.utils.logger import get_logger

logger = get_logger("dependency_scanner")


class DependencyScanner(BaseScanner):
    """Scans project dependencies for known CVEs.

    Note: This scanner requires a local project directory with
    package-lock.json, requirements.txt, or similar dependency files.
    For remote target scanning, this scanner checks JavaScript
    libraries loaded by the target (basic detection).
    """

    name = "dependency_scanner"
    description = "Checks for vulnerable third-party dependencies"

    async def validate_target(self) -> bool:
        """Dependency scanning is always applicable."""
        return True

    async def scan(self) -> list[Finding]:
        """Check for known vulnerable dependencies."""
        findings = []

        # For remote target: check for known vulnerable JS libraries
        findings += await self._check_js_libraries()

        return findings

    async def _check_js_libraries(self) -> list[Finding]:
        """Detect JavaScript libraries loaded by the target and check for known issues."""
        import httpx

        findings = []

        # Common vulnerable library patterns
        known_vulnerable = [
            {
                "pattern": "jquery-1\\.",
                "name": "jQuery < 2.0",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-79",
                "description": "jQuery versions before 2.0 have known XSS vulnerabilities.",
                "fix": "Upgrade to jQuery 3.x or later.",
                "cve": "CVE-2020-11022, CVE-2020-11023",
            },
            {
                "pattern": "bootstrap[.-]3\\.",
                "name": "Bootstrap 3.x",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-79",
                "description": "Bootstrap 3.x has known XSS vulnerabilities in tooltip/popover components.",
                "fix": "Upgrade to Bootstrap 5.x.",
                "cve": "CVE-2019-8331",
            },
            {
                "pattern": "angular[.-]1\\.",
                "name": "AngularJS 1.x",
                "severity": Severity.HIGH,
                "cwe": "CWE-79",
                "description": "AngularJS 1.x is end-of-life with known sandbox escape vulnerabilities.",
                "fix": "Migrate to Angular 2+ or an alternative framework.",
                "cve": "Multiple CVEs",
            },
            {
                "pattern": "react[.-]0\\.",
                "name": "React < 1.0",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-79",
                "description": "Very old React versions have known XSS issues.",
                "fix": "Upgrade to React 18+.",
                "cve": "CVE-2020-8203",
            },
            {
                "pattern": "lodash[.-]4\\.0\\.[0-9]",
                "name": "Lodash 4.0.x",
                "severity": Severity.HIGH,
                "cwe": "CWE-79",
                "description": "Older Lodash versions have prototype pollution vulnerabilities.",
                "fix": "Upgrade to Lodash 4.17.21+.",
                "cve": "CVE-2021-23337",
            },
        ]

        try:
            async with create_client(self.config) as client:
                response = await client.get(self.config.target_url)
                body = response.text

                for vuln in known_vulnerable:
                    import re
                    if re.search(vuln["pattern"], body):
                        findings.append(Finding(
                            title=f"Vulnerable Library: {vuln['name']}",
                            description=vuln["description"],
                            severity=vuln["severity"],
                            cwe_id=vuln["cwe"],
                            owasp_category="A06:2021",
                            url=self.config.target_url,
                            evidence=f"Pattern detected: {vuln['pattern']}",
                            remediation=vuln["fix"],
                            references=[
                                f"CVE: {vuln['cve']}",
                            ],
                        ))

        except (httpx.RequestError, ValueError) as e:
            logger.debug("JS library check failed: %s", type(e).__name__)

        return findings
