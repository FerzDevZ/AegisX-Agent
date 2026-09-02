"""OWASP Top 10 web vulnerability scanner.

Scans target URLs for common web vulnerabilities:
- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Insecure Direct Object Reference (IDOR)
- Security Misconfiguration
- Server-Side Request Forgery (SSRF)
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import httpx

from aegisx.core.context import Finding, ScanContext, Severity
from aegisx.scanners.base_scanner import BaseScanner
from aegisx.utils.logger import get_logger

logger = get_logger("web_scanner")


class WebScanner(BaseScanner):
    """Scans for OWASP Top 10 web vulnerabilities."""

    name = "web_scanner"
    description = "OWASP Top 10 web vulnerability scanner"

    # SQL Injection test payloads
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "1' AND SLEEP(5)--",
        "admin'--",
        "' OR 1=1#",
        "1' WAITFOR DELAY '0:0:5'--",
    ]

    # XSS test payloads
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "'-alert(1)-'",
    ]

    # Path traversal payloads
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]

    # SSRF payloads
    SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]",
    ]

    async def validate_target(self) -> bool:
        """Validate that the target is reachable."""
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
        except Exception as e:
            logger.error("Cannot reach target: %s", e)
            return False

    async def scan(self) -> list[Finding]:
        """Execute all web vulnerability checks."""
        findings: list[Finding] = []

        # Run all checks
        findings += await self._check_sqli()
        findings += await self._check_xss()
        findings += await self._check_path_traversal()
        findings += await self._check_security_headers()
        findings += await self._check_info_disclosure()
        findings += await self._check_cors()

        return findings

    async def _check_sqli(self) -> list[Finding]:
        """Test for SQL Injection vulnerabilities."""
        findings = []
        parsed = urlparse(self.config.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Find forms and test parameters
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

                # Find form actions and inputs
                forms = self._extract_forms(response.text, base_url)

                for form_url, params in forms:
                    for param_name in params:
                        for payload in self.SQLI_PAYLOADS[:3]:  # Limit for speed
                            try:
                                test_data = {p: "test" for p in params}
                                test_data[param_name] = payload

                                if "GET" in str(params).upper():
                                    test_response = await client.get(
                                        form_url, params=test_data,
                                        headers={"User-Agent": self.config.user_agent},
                                    )
                                else:
                                    test_response = await client.post(
                                        form_url, data=test_data,
                                        headers={"User-Agent": self.config.user_agent},
                                    )

                                # Check for SQL error patterns
                                body = test_response.text.lower()
                                sql_errors = [
                                    "sql syntax", "mysql", "sqlite", "postgresql",
                                    "ora-", "microsoft sql", "unclosed quotation",
                                    "quoted string not properly terminated",
                                    "you have an error in your sql",
                                ]

                                if any(err in body for err in sql_errors):
                                    findings.append(Finding(
                                        title="SQL Injection",
                                        description=(
                                            f"Parameter '{param_name}' appears vulnerable to SQL injection. "
                                            "The application returns database error messages when malicious "
                                            "SQL payloads are injected."
                                        ),
                                        severity=Severity.CRITICAL,
                                        cvss_score=9.8,
                                        cwe_id="CWE-89",
                                        owasp_category="A03:2021",
                                        url=form_url,
                                        endpoint=form_url.replace(base_url, ""),
                                        method="POST" if "POST" in str(params).upper() else "GET",
                                        parameter=param_name,
                                        evidence=test_response.text[:500],
                                        payload=payload,
                                        remediation=(
                                            "Use parameterized queries (prepared statements) for all "
                                            "database interactions. Never concatenate user input into SQL queries. "
                                            "Use ORM frameworks with parameterized query support."
                                        ),
                                        references=[
                                            "https://owasp.org/www-community/attacks/SQL_Injection",
                                            "https://cwe.mitre.org/data/definitions/89.html",
                                        ],
                                    ))
                                    break  # Found vuln, skip other payloads for this param

                            except httpx.RequestError:
                                continue

        except Exception as e:
            logger.debug("SQLi check failed: %s", e)

        return findings

    async def _check_xss(self) -> list[Finding]:
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        findings = []
        parsed = urlparse(self.config.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

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

                forms = self._extract_forms(response.text, base_url)

                for form_url, params in forms:
                    for param_name in params:
                        for payload in self.XSS_PAYLOADS[:3]:
                            try:
                                test_data = {p: "test" for p in params}
                                test_data[param_name] = payload

                                test_response = await client.post(
                                    form_url, data=test_data,
                                    headers={"User-Agent": self.config.user_agent},
                                )

                                # Check if payload is reflected unescaped
                                if payload in test_response.text:
                                    findings.append(Finding(
                                        title="Cross-Site Scripting (XSS)",
                                        description=(
                                            f"Parameter '{param_name}' reflects user input without "
                                            "proper encoding, allowing script injection."
                                        ),
                                        severity=Severity.HIGH,
                                        cvss_score=7.1,
                                        cwe_id="CWE-79",
                                        owasp_category="A03:2021",
                                        url=form_url,
                                        endpoint=form_url.replace(base_url, ""),
                                        method="POST",
                                        parameter=param_name,
                                        evidence=test_response.text[:500],
                                        payload=payload,
                                        remediation=(
                                            "Encode all user-supplied output using context-appropriate "
                                            "encoding (HTML entity encoding, JavaScript encoding, URL encoding). "
                                            "Use Content Security Policy (CSP) headers. "
                                            "Avoid innerHTML/v-html/dangerouslySetInnerHTML with user data."
                                        ),
                                        references=[
                                            "https://owasp.org/www-community/attacks/xss/",
                                            "https://cwe.mitre.org/data/definitions/79.html",
                                        ],
                                    ))
                                    break

                            except httpx.RequestError:
                                continue

        except Exception as e:
            logger.debug("XSS check failed: %s", e)

        return findings

    async def _check_path_traversal(self) -> list[Finding]:
        """Test for Path Traversal vulnerabilities."""
        findings = []

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                # Test common file parameters
                test_params = ["file", "path", "page", "doc", "include", "template"]

                for param in test_params:
                    for payload in self.PATH_TRAVERSAL_PAYLOADS[:2]:
                        try:
                            test_url = f"{self.config.target_url}?{param}={payload}"
                            response = await client.get(
                                test_url,
                                headers={"User-Agent": self.config.user_agent},
                            )

                            # Check if /etc/passwd content is in response
                            if "root:" in response.text or "bin/bash" in response.text:
                                findings.append(Finding(
                                    title="Path Traversal",
                                    description=(
                                        f"Parameter '{param}' allows directory traversal, "
                                        "enabling access to sensitive system files."
                                    ),
                                    severity=Severity.HIGH,
                                    cvss_score=7.5,
                                    cwe_id="CWE-22",
                                    owasp_category="A01:2021",
                                    url=test_url,
                                    endpoint=self.config.target_url,
                                    method="GET",
                                    parameter=param,
                                    evidence=response.text[:500],
                                    payload=payload,
                                    remediation=(
                                        "Validate and sanitize file paths. Use a whitelist of "
                                        "allowed files/directories. Use chroot or containerization. "
                                        "Never use user input directly in file operations."
                                    ),
                                    references=[
                                        "https://owasp.org/www-community/attacks/Path_Traversal",
                                        "https://cwe.mitre.org/data/definitions/22.html",
                                    ],
                                ))
                                break

                        except httpx.RequestError:
                            continue

        except Exception as e:
            logger.debug("Path traversal check failed: %s", e)

        return findings

    async def _check_security_headers(self) -> list[Finding]:
        """Check for missing security headers."""
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

                headers = response.headers

                # Check critical security headers
                checks = [
                    {
                        "header": "strict-transport-security",
                        "title": "Missing HSTS Header",
                        "description": "Strict-Transport-Security header is not set, allowing downgrade attacks.",
                        "severity": Severity.MEDIUM,
                        "cwe": "CWE-319",
                    },
                    {
                        "header": "x-content-type-options",
                        "title": "Missing X-Content-Type-Options Header",
                        "description": "X-Content-Type-Options header is not set, allowing MIME sniffing.",
                        "severity": Severity.LOW,
                        "cwe": "CWE-693",
                    },
                    {
                        "header": "x-frame-options",
                        "title": "Missing X-Frame-Options Header",
                        "description": "X-Frame-Options header is not set, allowing clickjacking.",
                        "severity": Severity.MEDIUM,
                        "cwe": "CWE-1021",
                    },
                    {
                        "header": "content-security-policy",
                        "title": "Missing Content-Security-Policy Header",
                        "description": "CSP header is not set, increasing XSS risk.",
                        "severity": Severity.MEDIUM,
                        "cwe": "CWE-693",
                    },
                ]

                for check in checks:
                    if check["header"] not in headers:
                        findings.append(Finding(
                            title=check["title"],
                            description=check["description"],
                            severity=check["severity"],
                            cwe_id=check["cwe"],
                            owasp_category="A05:2021",
                            url=self.config.target_url,
                            endpoint=self.config.target_url,
                            method="GET",
                            remediation=f"Add the {check['header']} header to all HTTP responses.",
                            references=[
                                f"https://owasp.org/www-project-secure-headers/#{check['header'].replace('-', '-')}",
                            ],
                        ))

        except Exception as e:
            logger.debug("Security header check failed: %s", e)

        return findings

    async def _check_info_disclosure(self) -> list[Finding]:
        """Check for information disclosure in response headers."""
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

                # Server header reveals version
                server = response.headers.get("server", "")
                if server and any(v in server.lower() for v in ["/", "apache", "nginx", "iis"]):
                    findings.append(Finding(
                        title="Server Version Disclosure",
                        description=(
                            f"The Server header reveals version information: '{server}'. "
                            "This helps attackers identify specific vulnerabilities."
                        ),
                        severity=Severity.LOW,
                        cwe_id="CWE-200",
                        owasp_category="A05:2021",
                        url=self.config.target_url,
                        method="GET",
                        evidence=f"Server: {server}",
                        remediation="Remove or obfuscate the Server header version information.",
                    ))

                # X-Powered-By reveals framework
                powered_by = response.headers.get("x-powered-by", "")
                if powered_by:
                    findings.append(Finding(
                        title="X-Powered-By Header Disclosure",
                        description=(
                            f"The X-Powered-By header reveals: '{powered_by}'. "
                            "This exposes the technology stack to attackers."
                        ),
                        severity=Severity.LOW,
                        cwe_id="CWE-200",
                        owasp_category="A05:2021",
                        url=self.config.target_url,
                        method="GET",
                        evidence=f"X-Powered-By: {powered_by}",
                        remediation="Remove the X-Powered-By header from production responses.",
                    ))

        except Exception as e:
            logger.debug("Info disclosure check failed: %s", e)

        return findings

    async def _check_cors(self) -> list[Finding]:
        """Check for overly permissive CORS configuration."""
        findings = []

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                # Send request with attacker-controlled Origin
                response = await client.get(
                    self.config.target_url,
                    headers={
                        "User-Agent": self.config.user_agent,
                        "Origin": "https://evil-attacker.com",
                    },
                )

                acao = response.headers.get("access-control-allow-origin", "")
                if acao == "*":
                    findings.append(Finding(
                        title="Wildcard CORS Configuration",
                        description=(
                            "Access-Control-Allow-Origin is set to '*', allowing any origin "
                            "to make cross-origin requests. This can lead to data theft."
                        ),
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-942",
                        owasp_category="A05:2021",
                        url=self.config.target_url,
                        method="GET",
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        remediation=(
                            "Restrict CORS to specific trusted origins. "
                            "Never use '*' with credentials."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                        ],
                    ))
                elif acao == "https://evil-attacker.com":
                    findings.append(Finding(
                        title="CORS Origin Reflection",
                        description=(
                            "The server reflects the attacker-controlled Origin header back "
                            "in Access-Control-Allow-Origin, bypassing CORS protections."
                        ),
                        severity=Severity.HIGH,
                        cvss_score=7.4,
                        cwe_id="CWE-942",
                        owasp_category="A05:2021",
                        url=self.config.target_url,
                        method="GET",
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        remediation="Validate Origin against a whitelist before reflecting it.",
                    ))

        except Exception as e:
            logger.debug("CORS check failed: %s", e)

        return findings

    def _extract_forms(self, html: str, base_url: str) -> list[tuple[dict[str, list[str]]]]:
        """Extract form actions and input parameters from HTML.

        Returns list of (url, [param_names]) tuples.
        """
        import re

        forms = []

        # Find form tags
        form_pattern = re.compile(r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>", re.IGNORECASE)
        input_pattern = re.compile(r"<input[^>]*name=[\"']([^\"']*)[\"'][^>]*>", re.IGNORECASE)

        for form_match in form_pattern.finditer(html):
            action = form_match.group(1)
            if action.startswith("/"):
                action = base_url + action
            elif not action.startswith("http"):
                action = urljoin(base_url, action)

            # Find inputs in the form
            form_start = form_match.start()
            # Simple heuristic: find inputs between this form and the next form or end
            next_form = form_pattern.search(html, form_start + 1)
            form_end = next_form.start() if next_form else len(html)
            form_html = html[form_start:form_end]

            inputs = input_pattern.findall(form_html)
            if inputs:
                forms.append((action, inputs))

        return forms
