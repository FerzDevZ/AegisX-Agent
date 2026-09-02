"""Parameter injection scanner.

Tests URL parameters and form inputs for SQL Injection, XSS,
and Path Traversal vulnerabilities.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

import httpx

from aegisx.core.config import AegisxConfig
from aegisx.core.context import Finding, Severity
from aegisx.utils.logger import get_logger

logger = get_logger("param_scanner")

# ── Payloads ───────────────────────────────────────────────────

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

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "'-alert(1)-'",
    "<iframe src=javascript:alert(1)>",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
]

SQL_ERROR_PATTERNS = [
    "sql syntax", "mysql", "sqlite", "postgresql",
    "ora-", "microsoft sql", "unclosed quotation",
    "quoted string not properly terminated",
    "you have an error in your sql",
    "warning: mysql", "uncaught exception",
    "odbc", "jdbc",
]

INJECTABLE_PARAMS = ["search", "q", "query", "id", "category", "location", "sort"]
TRAVERSAL_PARAMS = ["file", "path", "page", "doc", "include", "template",
                    "src", "img", "load", "read", "view"]

# ── Helpers ────────────────────────────────────────────────────


def _extract_forms(html: str, base_url: str) -> list[tuple[str, list[str]]]:
    """Extract form actions and input parameter names from HTML."""
    forms: list[tuple[str, list[str]]] = []
    form_re = re.compile(r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>", re.IGNORECASE)
    input_re = re.compile(r"<input[^>]*name=[\"']([^\"']*)[\"'][^>]*>", re.IGNORECASE)

    for form_match in form_re.finditer(html):
        action = form_match.group(1)
        if action.startswith("/"):
            action = base_url + action
        elif not action.startswith("http"):
            action = urljoin(base_url, action)

        form_start = form_match.start()
        next_form = form_re.search(html, form_start + 1)
        form_end = next_form.start() if next_form else len(html)
        form_html = html[form_start:form_end]

        inputs = input_re.findall(form_html)
        if inputs:
            forms.append((action, inputs))
    return forms


# ── SQL Injection ──────────────────────────────────────────────


async def check_sqli(
    config: AegisxConfig,
    url: str,
) -> list[Finding]:
    """Test a URL for SQL Injection via params and forms."""
    findings: list[Finding] = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    existing_params = parse_qs(parsed.query)
    test_param_names: set[str] = set(existing_params.keys()) | set(INJECTABLE_PARAMS)

    try:
        async with httpx.AsyncClient(
            timeout=config.timeout_seconds,
            follow_redirects=True,
            verify=False,  # noqa: S501
        ) as client:
            # Get baseline for form extraction
            try:
                baseline = await client.get(
                    url, headers={"User-Agent": config.user_agent},
                )
            except (httpx.RequestError, httpx.TimeoutException):
                baseline = None

            # --- URL parameter SQLi ---
            for param_name in test_param_names:
                for payload in SQLI_PAYLOADS[:3]:
                    try:
                        test_params = {
                            p: v[0] if isinstance(v, list) else v
                            for p, v in existing_params.items()
                        }
                        test_params[param_name] = payload
                        sep = "&" if parsed.query else "?"
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{sep}{urlencode(test_params)}"

                        resp = await client.get(
                            test_url, headers={"User-Agent": config.user_agent},
                        )
                        body = resp.text.lower()
                        if any(err in body for err in SQL_ERROR_PATTERNS):
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
                                evidence=resp.text[:500],
                                payload=payload,
                                remediation="Use parameterized queries.",
                                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                            ))
                            break
                    except (httpx.RequestError, httpx.TimeoutException):
                        continue

            # --- Form SQLi ---
            if baseline is not None:
                forms = _extract_forms(baseline.text, base_url)
                for form_url, params in forms:
                    for param_name in params:
                        for payload in SQLI_PAYLOADS[:3]:
                            try:
                                test_data = {p: "test" for p in params}
                                test_data[param_name] = payload
                                resp = await client.post(
                                    form_url, data=test_data,
                                    headers={"User-Agent": config.user_agent},
                                )
                                body = resp.text.lower()
                                if any(err in body for err in SQL_ERROR_PATTERNS):
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
                                        evidence=resp.text[:500],
                                        payload=payload,
                                        remediation="Use parameterized queries.",
                                    ))
                                    break
                            except (httpx.RequestError, httpx.TimeoutException):
                                continue

    except Exception as exc:
        logger.warning("SQLi check for %s failed: %s", url, exc)

    return findings


# ── Cross-Site Scripting ───────────────────────────────────────


async def check_xss(
    config: AegisxConfig,
    url: str,
) -> list[Finding]:
    """Test a URL for XSS via params and forms."""
    findings: list[Finding] = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    existing_params = parse_qs(parsed.query)
    test_param_names: set[str] = set(existing_params.keys()) | {"search", "q", "query", "name", "category", "location"}

    try:
        async with httpx.AsyncClient(
            timeout=config.timeout_seconds,
            follow_redirects=True,
            verify=False,  # noqa: S501
        ) as client:
            # --- URL parameter XSS ---
            for param_name in test_param_names:
                for payload in XSS_PAYLOADS[:3]:
                    try:
                        test_params = {
                            p: v[0] if isinstance(v, list) else v
                            for p, v in existing_params.items()
                        }
                        test_params[param_name] = payload
                        sep = "&" if parsed.query else "?"
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{sep}{urlencode(test_params)}"

                        resp = await client.get(
                            test_url, headers={"User-Agent": config.user_agent},
                        )
                        if payload in resp.text:
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
                                evidence=resp.text[:500],
                                payload=payload,
                                remediation="Encode all output and use CSP.",
                                references=["https://owasp.org/www-community/attacks/xss/"],
                            ))
                            break
                    except (httpx.RequestError, httpx.TimeoutException):
                        continue

            # --- Form XSS ---
            try:
                resp = await client.get(url, headers={"User-Agent": config.user_agent})
                forms = _extract_forms(resp.text, base_url)
            except (httpx.RequestError, httpx.TimeoutException):
                forms = []

            for form_url, params in forms:
                for param_name in params:
                    for payload in XSS_PAYLOADS[:3]:
                        try:
                            test_data = {p: "test" for p in params}
                            test_data[param_name] = payload
                            resp = await client.post(
                                form_url, data=test_data,
                                headers={"User-Agent": config.user_agent},
                            )
                            if payload in resp.text:
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
                                    evidence=resp.text[:500],
                                    payload=payload,
                                    remediation="Encode all output and use CSP.",
                                ))
                                break
                        except (httpx.RequestError, httpx.TimeoutException):
                            continue

    except Exception as exc:
        logger.warning("XSS check for %s failed: %s", url, exc)

    return findings


# ── Path Traversal ─────────────────────────────────────────────


async def check_path_traversal(
    config: AegisxConfig,
    url: str,
) -> list[Finding]:
    """Test a URL for Path Traversal vulnerabilities."""
    findings: list[Finding] = []
    parsed = urlparse(url)

    try:
        async with httpx.AsyncClient(
            timeout=config.timeout_seconds,
            follow_redirects=True,
            verify=False,  # noqa: S501
        ) as client:
            for param in TRAVERSAL_PARAMS:
                for payload in PATH_TRAVERSAL_PAYLOADS:
                    try:
                        sep = "&" if "?" in url else "?"
                        test_url = f"{url}{sep}{param}={payload}"
                        resp = await client.get(
                            test_url, headers={"User-Agent": config.user_agent},
                        )
                        if "root:" in resp.text or "bin/bash" in resp.text:
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
                                evidence=resp.text[:500],
                                payload=payload,
                                remediation="Validate and sanitize file paths.",
                                references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                            ))
                            break
                    except (httpx.RequestError, httpx.TimeoutException):
                        continue

    except Exception as exc:
        logger.debug("Path traversal check for %s failed: %s", url, exc)

    return findings
