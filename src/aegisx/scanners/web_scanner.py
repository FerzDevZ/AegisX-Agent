"""OWASP Top 10 web vulnerability scanner.

Major improvements:
- Tests URL query parameters (not just form inputs)
- Tests common API endpoints
- Better error pattern detection
- Tests multiple HTTP methods
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

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
        "admin'--",
        "' OR 1=1#",
        "1' AND 1=1--",
        "1' OR 'a'='a",
    ]

    # XSS test payloads
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "'-alert(1)-'",
        "<iframe src=javascript:alert(1)>",
    ]

    # Common URL parameters to test
    COMMON_PARAMS = [
        "q", "search", "query", "id", "page", "name", "url",
        "file", "path", "redirect", "callback", "next", "continue",
        "test", "debug", "cmd", "exec", "eval", "input",
    ]

    # Common API paths to check
    COMMON_PATHS = [
        "/api", "/api/v1", "/api/v2", "/graphql",
        "/login", "/register", "/signup", "/signin",
        "/admin", "/dashboard", "/panel",
        "/search", "/query",
        "/upload", "/files",
        "/wp-admin", "/wp-login.php",
        "/.env", "/config", "/debug",
        "/swagger", "/docs", "/api-docs",
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

        # Phase 1: Crawl to discover pages
        discovered_urls = await self._crawl_pages()
        logger.info("Discovered %d pages to scan", len(discovered_urls))

        # Phase 2: Run all checks on discovered pages
        findings += await self._check_security_headers()
        findings += await self._check_cors()
        findings += await self._check_info_disclosure()
        findings += await self._check_http_methods()
        findings += await self._check_cookie_security()
        findings += await self._check_api_endpoints()
        findings += await self._check_auth_bypass(discovered_urls)

        # Phase 3: Test all discovered pages for injection
        for url in discovered_urls:
            findings += await self._check_sqli_for_url(url)
            findings += await self._check_xss_for_url(url)
            findings += await self._check_path_traversal_for_url(url)

        return findings

    async def _crawl_pages(self) -> list[str]:
        """Crawl the target to discover pages and endpoints."""
        discovered = set()
        discovered.add(self.config.target_url)

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                # Fetch root page
                response = await client.get(
                    self.config.target_url,
                    headers={"User-Agent": self.config.user_agent},
                )

                parsed = urlparse(self.config.target_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"

                # Extract all links from HTML
                link_pattern = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)
                links = link_pattern.findall(response.text)

                for link in links:
                    if link.startswith("/"):
                        full_url = base_url + link
                    elif link.startswith("http") and parsed.netloc in link:
                        full_url = link
                    else:
                        continue

                    # Only scan our target domain
                    if self.config.is_in_scope(full_url):
                        discovered.add(full_url)

                # Add common paths to check
                common_paths = [
                    "/login", "/register", "/signup", "/signin",
                    "/admin", "/dashboard",
                    "/services", "/search",
                    "/api", "/graphql",
                    "/profile", "/account",
                    "/settings",
                ]
                for path in common_paths:
                    url = base_url + path
                    if self.config.is_in_scope(url):
                        try:
                            r = await client.get(
                                url,
                                headers={"User-Agent": self.config.user_agent},
                                follow_redirects=True,
                            )
                            if r.status_code < 400:
                                discovered.add(url)
                        except httpx.RequestError:
                            pass

        except Exception as e:
            logger.debug("Crawl failed: %s", e)

        return list(discovered)

    async def _check_sqli_for_url(self, url: str) -> list[Finding]:
        """Test a specific URL for SQL Injection."""
        findings = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Parameters to test (existing URL params + common injectable params)
        test_param_names = set()
        existing_params = parse_qs(parsed.query)
        test_param_names.update(existing_params.keys())
        # Always test these common injectable params
        test_param_names.update(["search", "q", "query", "id", "category", "location", "sort"])

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                # Get baseline response
                baseline = await client.get(
                    url,
                    headers={"User-Agent": self.config.user_agent},
                )
                baseline_len = len(baseline.text)

                for param_name in test_param_names:
                    for payload in self.SQLI_PAYLOADS[:3]:
                        try:
                            test_params = {p: v[0] if isinstance(v, list) else v
                                          for p, v in existing_params.items()}
                            test_params[param_name] = payload
                            separator = "&" if parsed.query else "?"
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{separator}{urlencode(test_params)}"

                            response = await client.get(
                                test_url,
                                headers={"User-Agent": self.config.user_agent},
                            )

                            body = response.text.lower()
                            sql_errors = [
                                "sql syntax", "mysql", "sqlite", "postgresql",
                                "ora-", "microsoft sql", "unclosed quotation",
                                "quoted string not properly terminated",
                                "you have an error in your sql",
                                "warning: mysql", "uncaught exception",
                                "odbc", "jdbc",
                            ]

                            # Check for SQL errors or significant response difference
                            if any(err in body for err in sql_errors):
                                findings.append(Finding(
                                    title="SQL Injection (URL Parameter)",
                                    description=f"Parameter '{param_name}' in {parsed.path} is vulnerable to SQL injection.",
                                    severity=Severity.CRITICAL,
                                    cvss_score=9.8,
                                    cwe_id="CWE-89",
                                    owasp_category="A03:2021",
                                    url=test_url,
                                    endpoint=parsed.path,
                                    method="GET",
                                    parameter=param_name,
                                    evidence=response.text[:500],
                                    payload=payload,
                                    remediation="Use parameterized queries.",
                                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                                ))
                                break

                        except httpx.RequestError:
                            continue

                # Test forms on this page
                forms = self._extract_forms(baseline.text, base_url)

                for form_url, params in forms:
                    for param_name in params:
                        for payload in self.SQLI_PAYLOADS[:3]:
                            try:
                                test_data = {p: "test" for p in params}
                                test_data[param_name] = payload
                                test_response = await client.post(
                                    form_url, data=test_data,
                                    headers={"User-Agent": self.config.user_agent},
                                )
                                body = test_response.text.lower()
                                sql_errors = [
                                    "sql syntax", "mysql", "sqlite", "postgresql",
                                    "ora-", "unclosed quotation",
                                ]
                                if any(err in body for err in sql_errors):
                                    findings.append(Finding(
                                        title="SQL Injection (Form)",
                                        description=f"Parameter '{param_name}' in form at {parsed.path} is vulnerable.",
                                        severity=Severity.CRITICAL,
                                        cvss_score=9.8,
                                        cwe_id="CWE-89",
                                        owasp_category="A03:2021",
                                        url=form_url,
                                        endpoint=parsed.path,
                                        method="POST",
                                        parameter=param_name,
                                        evidence=test_response.text[:500],
                                        payload=payload,
                                        remediation="Use parameterized queries.",
                                    ))
                                    break
                            except httpx.RequestError:
                                continue

        except Exception as e:
            logger.warning("SQLi check for %s failed: %s", url, e)

        return findings

    async def _check_xss_for_url(self, url: str) -> list[Finding]:
        """Test a specific URL for XSS via URL params and common injectable params."""
        findings = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Parameters to test
        test_param_names = set()
        existing_params = parse_qs(parsed.query)
        test_param_names.update(existing_params.keys())
        test_param_names.update(["search", "q", "query", "name", "category", "location"])

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                for param_name in test_param_names:
                    for payload in self.XSS_PAYLOADS[:3]:
                        try:
                            test_params = {p: v[0] if isinstance(v, list) else v
                                          for p, v in existing_params.items()}
                            test_params[param_name] = payload
                            separator = "&" if parsed.query else "?"
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{separator}{urlencode(test_params)}"

                            response = await client.get(
                                test_url,
                                headers={"User-Agent": self.config.user_agent},
                            )

                            if payload in response.text:
                                findings.append(Finding(
                                    title="Cross-Site Scripting (XSS) — Reflected",
                                    description=f"Parameter '{param_name}' in {parsed.path} reflects user input without encoding.",
                                    severity=Severity.HIGH,
                                    cvss_score=7.1,
                                    cwe_id="CWE-79",
                                    owasp_category="A03:2021",
                                    url=test_url,
                                    endpoint=parsed.path,
                                    method="GET",
                                    parameter=param_name,
                                    evidence=response.text[:500],
                                    payload=payload,
                                    remediation="Encode all output and use CSP.",
                                    references=["https://owasp.org/www-community/attacks/xss/"],
                                ))
                                break
                        except httpx.RequestError:
                            continue

                # Test forms
                response = await client.get(
                    url,
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
                                if payload in test_response.text:
                                    findings.append(Finding(
                                        title="Cross-Site Scripting (XSS) — Form",
                                        description=f"Parameter '{param_name}' reflects input without encoding.",
                                        severity=Severity.HIGH,
                                        cvss_score=7.1,
                                        cwe_id="CWE-79",
                                        owasp_category="A03:2021",
                                        url=form_url,
                                        endpoint=parsed.path,
                                        method="POST",
                                        parameter=param_name,
                                        evidence=test_response.text[:500],
                                        payload=payload,
                                        remediation="Encode all output and use CSP.",
                                    ))
                                    break
                            except httpx.RequestError:
                                continue

        except Exception as e:
            logger.warning("XSS check for %s failed: %s", url, e)

        return findings

    async def _check_path_traversal_for_url(self, url: str) -> list[Finding]:
        """Test a specific URL for Path Traversal."""
        findings = []

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                test_params = ["file", "path", "page", "doc", "include", "template",
                               "src", "img", "load", "read", "view"]

                for param in test_params:
                    payloads = ["../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd"]
                    for payload in payloads:
                        try:
                            separator = "&" if "?" in url else "?"
                            test_url = f"{url}{separator}{param}={payload}"
                            response = await client.get(
                                test_url,
                                headers={"User-Agent": self.config.user_agent},
                            )
                            if "root:" in response.text or "bin/bash" in response.text:
                                parsed = urlparse(url)
                                findings.append(Finding(
                                    title="Path Traversal",
                                    description=f"Parameter '{param}' allows directory traversal.",
                                    severity=Severity.HIGH,
                                    cvss_score=7.5,
                                    cwe_id="CWE-22",
                                    owasp_category="A01:2021",
                                    url=test_url,
                                    endpoint=parsed.path,
                                    method="GET",
                                    parameter=param,
                                    evidence=response.text[:500],
                                    payload=payload,
                                    remediation="Validate and sanitize file paths.",
                                ))
                                break
                        except httpx.RequestError:
                            continue

        except Exception as e:
            logger.debug("Path traversal check for %s failed: %s", url, e)

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

                headers = {k.lower(): v for k, v in response.headers.items()}

                checks = [
                    {
                        "header": "content-security-policy",
                        "title": "Missing Content-Security-Policy Header",
                        "description": "CSP header is not set. Without CSP, the application is vulnerable to XSS, data injection, and clickjacking attacks.",
                        "severity": Severity.MEDIUM,
                        "cwe": "CWE-693",
                    },
                    {
                        "header": "strict-transport-security",
                        "title": "Missing HSTS Header",
                        "description": "Strict-Transport-Security header is not set. Users can be downgraded to HTTP via MITM attacks.",
                        "severity": Severity.MEDIUM,
                        "cwe": "CWE-319",
                    },
                    {
                        "header": "x-content-type-options",
                        "title": "Missing X-Content-Type-Options Header",
                        "description": "X-Content-Type-Options header is not set. Browsers may MIME-sniff responses, leading to security issues.",
                        "severity": Severity.LOW,
                        "cwe": "CWE-693",
                    },
                    {
                        "header": "x-frame-options",
                        "title": "Missing X-Frame-Options Header",
                        "description": "X-Frame-Options header is not set. The application may be embedded in iframes for clickjacking attacks.",
                        "severity": Severity.MEDIUM,
                        "cwe": "CWE-1021",
                    },
                    {
                        "header": "referrer-policy",
                        "title": "Missing Referrer-Policy Header",
                        "description": "Referrer-Policy header is not set. Sensitive URL information may leak to third parties.",
                        "severity": Severity.LOW,
                        "cwe": "CWE-200",
                    },
                    {
                        "header": "permissions-policy",
                        "title": "Missing Permissions-Policy Header",
                        "description": "Permissions-Policy header is not set. Browser features like camera, microphone, and geolocation are not restricted.",
                        "severity": Severity.LOW,
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
                            endpoint="/",
                            method="GET",
                            remediation=f"Add the {check['header']} header to all HTTP responses.",
                            references=[
                                f"https://owasp.org/www-project-secure-headers/",
                            ],
                        ))

        except Exception as e:
            logger.debug("Security header check failed: %s", e)

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
                # Test 1: Wildcard origin
                response = await client.get(
                    self.config.target_url,
                    headers={
                        "User-Agent": self.config.user_agent,
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
                            "in Access-Control-Allow-Origin, bypassing CORS protections. "
                            + ("With credentials, this allows full account takeover." if acac == "true" else "")
                        ),
                        severity=Severity.HIGH if acac == "true" else Severity.MEDIUM,
                        cvss_score=8.1 if acac == "true" else 6.0,
                        cwe_id="CWE-942",
                        owasp_category="A05:2021",
                        url=self.config.target_url,
                        method="GET",
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        remediation="Validate Origin against a whitelist before reflecting it.",
                    ))

                # Test 2: Null origin
                response2 = await client.get(
                    self.config.target_url,
                    headers={
                        "User-Agent": self.config.user_agent,
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
                        url=self.config.target_url,
                        method="GET",
                        evidence=f"Access-Control-Allow-Origin: {acao2}",
                        remediation="Reject 'null' origin in CORS configuration.",
                    ))

        except Exception as e:
            logger.debug("CORS check failed: %s", e)

        return findings

    async def _check_info_disclosure(self) -> list[Finding]:
        """Check for information disclosure in response."""
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

                headers = {k.lower(): v for k, v in response.headers.items()}
                body = response.text.lower()

                # Server header reveals version
                server = headers.get("server", "")
                if server:
                    # Check if it reveals version info
                    has_version = any(c.isdigit() for c in server)
                    if has_version:
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
                powered_by = headers.get("x-powered-by", "")
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

                # Check for source maps
                if "sourceMappingURL" in response.text:
                    findings.append(Finding(
                        title="Source Map Exposed",
                        description=(
                            "A source map reference was found in the response. "
                            "Source maps expose the original source code to attackers."
                        ),
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-200",
                        owasp_category="A05:2021",
                        url=self.config.target_url,
                        method="GET",
                        evidence="sourceMappingURL found in response",
                        remediation="Remove source maps from production builds.",
                    ))

                # Check for HTML comments with sensitive info
                comments = re.findall(r"<!--(.*?)-->", response.text, re.DOTALL)
                sensitive_patterns = [
                    "todo", "fixme", "hack", "bug", "password",
                    "secret", "key", "token", "admin", "debug",
                    "internal", "private", "backup",
                ]
                for comment in comments:
                    comment_lower = comment.lower()
                    for pattern in sensitive_patterns:
                        if pattern in comment_lower:
                            findings.append(Finding(
                                title="Sensitive Information in HTML Comment",
                                description=(
                                    f"HTML comment contains sensitive keyword '{pattern}'. "
                                    "Comments may expose internal information."
                                ),
                                severity=Severity.LOW,
                                cwe_id="CWE-615",
                                owasp_category="A05:2021",
                                url=self.config.target_url,
                                method="GET",
                                evidence=comment.strip()[:200],
                                remediation="Remove sensitive information from HTML comments.",
                            ))
                            break

        except Exception as e:
            logger.debug("Info disclosure check failed: %s", e)

        return findings

    async def _check_sqli(self) -> list[Finding]:
        """Test for SQL Injection via URL parameters and forms."""
        findings = []
        parsed = urlparse(self.config.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                # 1. Test URL query parameters
                existing_params = parse_qs(parsed.query)
                if existing_params:
                    for param_name in existing_params:
                        for payload in self.SQLI_PAYLOADS[:3]:
                            try:
                                test_params = {p: v[0] if isinstance(v, list) else v
                                              for p, v in existing_params.items()}
                                test_params[param_name] = payload
                                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                                response = await client.get(
                                    test_url,
                                    headers={"User-Agent": self.config.user_agent},
                                )

                                body = response.text.lower()
                                sql_errors = [
                                    "sql syntax", "mysql", "sqlite", "postgresql",
                                    "ora-", "microsoft sql", "unclosed quotation",
                                    "quoted string not properly terminated",
                                    "you have an error in your sql",
                                    "warning: mysql", "uncaught exception",
                                    "odbc sql server", "jdbc",
                                ]

                                if any(err in body for err in sql_errors):
                                    findings.append(Finding(
                                        title="SQL Injection (URL Parameter)",
                                        description=(
                                            f"Parameter '{param_name}' in URL appears vulnerable to SQL injection. "
                                            "The application returns database error messages."
                                        ),
                                        severity=Severity.CRITICAL,
                                        cvss_score=9.8,
                                        cwe_id="CWE-89",
                                        owasp_category="A03:2021",
                                        url=test_url,
                                        endpoint=parsed.path,
                                        method="GET",
                                        parameter=param_name,
                                        evidence=response.text[:500],
                                        payload=payload,
                                        remediation=(
                                            "Use parameterized queries (prepared statements). "
                                            "Never concatenate user input into SQL queries."
                                        ),
                                        references=[
                                            "https://owasp.org/www-community/attacks/SQL_Injection",
                                        ],
                                    ))
                                    break
                            except httpx.RequestError:
                                continue

                # 2. Test forms
                response = await client.get(
                    self.config.target_url,
                    headers={"User-Agent": self.config.user_agent},
                )
                forms = self._extract_forms(response.text, base_url)

                for form_url, params in forms:
                    for param_name in params:
                        for payload in self.SQLI_PAYLOADS[:3]:
                            try:
                                test_data = {p: "test" for p in params}
                                test_data[param_name] = payload

                                test_response = await client.post(
                                    form_url, data=test_data,
                                    headers={"User-Agent": self.config.user_agent},
                                )

                                body = test_response.text.lower()
                                sql_errors = [
                                    "sql syntax", "mysql", "sqlite", "postgresql",
                                    "ora-", "microsoft sql", "unclosed quotation",
                                    "quoted string not properly terminated",
                                    "you have an error in your sql",
                                ]

                                if any(err in body for err in sql_errors):
                                    findings.append(Finding(
                                        title="SQL Injection (Form)",
                                        description=(
                                            f"Parameter '{param_name}' in form appears vulnerable to SQL injection."
                                        ),
                                        severity=Severity.CRITICAL,
                                        cvss_score=9.8,
                                        cwe_id="CWE-89",
                                        owasp_category="A03:2021",
                                        url=form_url,
                                        endpoint=form_url.replace(base_url, ""),
                                        method="POST",
                                        parameter=param_name,
                                        evidence=test_response.text[:500],
                                        payload=payload,
                                        remediation="Use parameterized queries.",
                                        references=[
                                            "https://owasp.org/www-community/attacks/SQL_Injection",
                                        ],
                                    ))
                                    break
                            except httpx.RequestError:
                                continue

        except Exception as e:
            logger.debug("SQLi check failed: %s", e)

        return findings

    async def _check_xss(self) -> list[Finding]:
        """Test for XSS via URL parameters and forms."""
        findings = []
        parsed = urlparse(self.config.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                # 1. Test URL query parameters
                existing_params = parse_qs(parsed.query)
                if existing_params:
                    for param_name in existing_params:
                        for payload in self.XSS_PAYLOADS[:3]:
                            try:
                                test_params = {p: v[0] if isinstance(v, list) else v
                                              for p, v in existing_params.items()}
                                test_params[param_name] = payload
                                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                                response = await client.get(
                                    test_url,
                                    headers={"User-Agent": self.config.user_agent},
                                )

                                if payload in response.text:
                                    findings.append(Finding(
                                        title="Cross-Site Scripting (XSS) — Reflected",
                                        description=(
                                            f"Parameter '{param_name}' reflects user input without "
                                            "proper encoding, allowing script injection."
                                        ),
                                        severity=Severity.HIGH,
                                        cvss_score=7.1,
                                        cwe_id="CWE-79",
                                        owasp_category="A03:2021",
                                        url=test_url,
                                        endpoint=parsed.path,
                                        method="GET",
                                        parameter=param_name,
                                        evidence=response.text[:500],
                                        payload=payload,
                                        remediation=(
                                            "Encode all user-supplied output. "
                                            "Use Content Security Policy (CSP) headers."
                                        ),
                                        references=[
                                            "https://owasp.org/www-community/attacks/xss/",
                                        ],
                                    ))
                                    break
                            except httpx.RequestError:
                                continue

                # 2. Test forms
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

                                if payload in test_response.text:
                                    findings.append(Finding(
                                        title="Cross-Site Scripting (XSS) — Form",
                                        description=(
                                            f"Parameter '{param_name}' reflects user input without encoding."
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
                                        remediation="Encode all output and use CSP.",
                                        references=[
                                            "https://owasp.org/www-community/attacks/xss/",
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
                test_params = ["file", "path", "page", "doc", "include", "template",
                               "src", "img", "load", "read", "view"]

                for param in test_params:
                    payloads = [
                        "../../../etc/passwd",
                        "..%2F..%2F..%2Fetc%2Fpasswd",
                        "....//....//....//etc/passwd",
                    ]
                    for payload in payloads:
                        try:
                            test_url = f"{self.config.target_url}?{param}={payload}"
                            response = await client.get(
                                test_url,
                                headers={"User-Agent": self.config.user_agent},
                            )

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
                                    endpoint="/",
                                    method="GET",
                                    parameter=param,
                                    evidence=response.text[:500],
                                    payload=payload,
                                    remediation=(
                                        "Validate and sanitize file paths. "
                                        "Use a whitelist of allowed files/directories."
                                    ),
                                    references=[
                                        "https://owasp.org/www-community/attacks/Path_Traversal",
                                    ],
                                ))
                                break
                        except httpx.RequestError:
                            continue

        except Exception as e:
            logger.debug("Path traversal check failed: %s", e)

        return findings

    async def _check_api_endpoints(self) -> list[Finding]:
        """Check for exposed API endpoints and error messages."""
        findings = []

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                parsed = urlparse(self.config.target_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"

                for path in self.COMMON_PATHS:
                    try:
                        url = f"{base_url}{path}"
                        response = await client.get(
                            url,
                            headers={"User-Agent": self.config.user_agent},
                        )

                        body = response.text.lower()

                        # Check for exposed API documentation
                        if response.status_code == 200:
                            if "swagger" in body or "openapi" in body:
                                findings.append(Finding(
                                    title="API Documentation Exposed",
                                    description=(
                                        f"API documentation found at {path}. "
                                        "This exposes the full API surface to attackers."
                                    ),
                                    severity=Severity.MEDIUM,
                                    cwe_id="CWE-200",
                                    owasp_category="A05:2021",
                                    url=url,
                                    endpoint=path,
                                    method="GET",
                                    evidence=response.text[:300],
                                    remediation="Restrict API documentation to internal networks.",
                                ))

                            # Check for GraphQL introspection
                            if "graphql" in body and "__schema" in body:
                                findings.append(Finding(
                                    title="GraphQL Introspection Enabled",
                                    description=(
                                        "GraphQL introspection is enabled, exposing the "
                                        "entire schema to attackers."
                                    ),
                                    severity=Severity.MEDIUM,
                                    cwe_id="CWE-200",
                                    owasp_category="A05:2021",
                                    url=url,
                                    endpoint=path,
                                    method="GET",
                                    remediation="Disable GraphQL introspection in production.",
                                ))

                        # Check for verbose error messages
                        if response.status_code >= 400:
                            error_indicators = [
                                "exception", "stack trace", "traceback",
                                "error in", "line number", "sql state",
                                "nullpointer", "typeerror", "referenceerror",
                            ]
                            if any(indicator in body for indicator in error_indicators):
                                findings.append(Finding(
                                    title=f"Verbose Error at {path}",
                                    description=(
                                        f"The endpoint {path} returns detailed error information."
                                    ),
                                    severity=Severity.LOW,
                                    cwe_id="CWE-209",
                                    owasp_category="A05:2021",
                                    url=url,
                                    endpoint=path,
                                    method="GET",
                                    evidence=response.text[:300],
                                    remediation="Use custom error pages.",
                                ))

                    except httpx.RequestError:
                        continue

        except Exception as e:
            logger.debug("API endpoint check failed: %s", e)

        return findings

    async def _check_http_methods(self) -> list[Finding]:
        """Check for dangerous HTTP methods."""
        findings = []

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                # Send OPTIONS request
                response = await client.options(
                    self.config.target_url,
                    headers={"User-Agent": self.config.user_agent},
                )

                allow = response.headers.get("allow", "").upper()
                dangerous = {"TRACE": "High", "DELETE": "Low", "PUT": "Low", "PATCH": "Low"}

                for method, severity in dangerous.items():
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
                            url=self.config.target_url,
                            method=method,
                            evidence=f"Allow: {allow}",
                            remediation=f"Disable the {method} method if not needed.",
                        ))

        except Exception as e:
            logger.debug("HTTP methods check failed: %s", e)

        return findings

    async def _check_cookie_security(self) -> list[Finding]:
        """Check for insecure cookie configuration."""
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

                # Get all Set-Cookie headers
                cookie_headers = response.headers.get_list("set-cookie")

                for cookie in cookie_headers:
                    cookie_lower = cookie.lower()

                    # Check for missing Secure flag
                    if "secure" not in cookie_lower and "https" in self.config.target_url:
                        cookie_name = cookie.split("=")[0].strip()
                        findings.append(Finding(
                            title=f"Insecure Cookie: {cookie_name}",
                            description=(
                                f"Cookie '{cookie_name}' is missing the Secure flag. "
                                "It will be sent over unencrypted HTTP connections."
                            ),
                            severity=Severity.LOW,
                            cwe_id="CWE-614",
                            owasp_category="A05:2021",
                            url=self.config.target_url,
                            method="GET",
                            evidence=f"Set-Cookie: {cookie[:200]}",
                            remediation="Add the Secure flag to all cookies.",
                        ))

                    # Check for missing HttpOnly flag
                    if "httponly" not in cookie_lower:
                        cookie_name = cookie.split("=")[0].strip()
                        findings.append(Finding(
                            title=f"Cookie Missing HttpOnly: {cookie_name}",
                            description=(
                                f"Cookie '{cookie_name}' is missing the HttpOnly flag. "
                                "It can be accessed via JavaScript (XSS attacks)."
                            ),
                            severity=Severity.MEDIUM,
                            cwe_id="CWE-1004",
                            owasp_category="A05:2021",
                            url=self.config.target_url,
                            method="GET",
                            evidence=f"Set-Cookie: {cookie[:200]}",
                            remediation="Add the HttpOnly flag to all cookies.",
                        ))

                    # Check for missing SameSite attribute
                    if "samesite" not in cookie_lower:
                        cookie_name = cookie.split("=")[0].strip()
                        findings.append(Finding(
                            title=f"Cookie Missing SameSite: {cookie_name}",
                            description=(
                                f"Cookie '{cookie_name}' is missing the SameSite attribute. "
                                "It may be vulnerable to CSRF attacks."
                            ),
                            severity=Severity.LOW,
                            cwe_id="CWE-1275",
                            owasp_category="A01:2021",
                            url=self.config.target_url,
                            method="GET",
                            evidence=f"Set-Cookie: {cookie[:200]}",
                            remediation="Add SameSite=Lax or SameSite=Strict to all cookies.",
                        ))

        except Exception as e:
            logger.debug("Cookie security check failed: %s", e)

        return findings

    async def _check_auth_bypass(self, urls: list[str]) -> list[Finding]:
        """Check if protected pages are accessible without authentication."""
        findings = []

        protected_paths = ["/admin", "/dashboard", "/panel", "/settings", "/profile"]

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                for url in urls:
                    parsed = urlparse(url)
                    path = parsed.path.rstrip("/")

                    # Check if this is a protected path
                    is_protected = any(path.startswith(pp) for pp in protected_paths)
                    if not is_protected:
                        continue

                    response = await client.get(
                        url,
                        headers={"User-Agent": self.config.user_agent},
                    )

                    # If we get 200 on a protected path without auth, it's a finding
                    if response.status_code == 200:
                        body = response.text.lower()
                        # Check if it's actually a dashboard/admin page (not a login redirect)
                        if any(kw in body for kw in ["dashboard", "admin", "panel", "settings", "profile"]):
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
                                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Authentication_Testing/"],
                            ))

        except Exception as e:
            logger.warning("Auth bypass check failed: %s", e)

        return findings

    def _extract_forms(self, html: str, base_url: str) -> list[tuple[str, list[str]]]:
        """Extract form actions and input parameters from HTML."""
        forms = []

        form_pattern = re.compile(r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>", re.IGNORECASE)
        input_pattern = re.compile(r"<input[^>]*name=[\"']([^\"']*)[\"'][^>]*>", re.IGNORECASE)

        for form_match in form_pattern.finditer(html):
            action = form_match.group(1)
            if action.startswith("/"):
                action = base_url + action
            elif not action.startswith("http"):
                action = urljoin(base_url, action)

            form_start = form_match.start()
            next_form = form_pattern.search(html, form_start + 1)
            form_end = next_form.start() if next_form else len(html)
            form_html = html[form_start:form_end]

            inputs = input_pattern.findall(form_html)
            if inputs:
                forms.append((action, inputs))

        return forms
