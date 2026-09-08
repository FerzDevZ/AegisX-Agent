"""SSTI (Server-Side Template Injection) detection scanner.

Probes template-taking parameters for server-side template injection
(CWE-1336). Detection complements the ``ssti_exploit`` verifier: the
scanner flags parameters where template expressions evaluate, the
exploit confirms with engine-specific payloads.

Method: inject arithmetic payloads (``{{7*7}}``, ``${7*7}``, ``<%= 7*7 %>``,
``#{7*7}``) and compare each response against a same-parameter baseline.
A hit requires the evaluated result (``49``) to appear where the baseline
did not have it — this filters out pages that simply contain "49" already.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from aegisx.core.config import AegisxConfig
from aegisx.core.context import Finding, Severity
from aegisx.scanners.base_scanner import BaseScanner
from aegisx.utils.http_client import create_client
from aegisx.utils.logger import get_logger

logger = get_logger("ssti_scanner")

# Arithmetic payloads per template engine family: (label, payload, marker).
# marker = the exact evaluated output we look for in the response body.
SSTI_PAYLOADS: list[tuple[str, str, str]] = [
    ("jinja2", "{{7*7}}", "49"),
    ("jinja2_expression", "{{ 7 * 7 }}", "49"),
    ("twig", "{{7*7}}", "49"),  # same syntax family as jinja
    ("erb", "<%= 7*7 %>", "49"),
    ("freemarker", "${7*7}", "49"),
    ("pebble", "{{7*7}}", "49"),
    ("velocity", "#set($x=7*7)${x}", "49"),
    ("mako", "${7*7}", "49"),
    ("smarty", "{7*7}", "49"),
    ("nunjucks", "{{7*7}}", "49"),
]

# Parameter names that commonly feed a template engine
TEMPLATE_PARAMS = [
    "template",
    "tpl",
    "view",
    "render",
    "page",
    "name",
    "file",
    "layout",
    "theme",
    "content",
    "body",
    "message",
    "greeting",
    "preview",
    "email_template",
    "subject",
    "title",
    "text",
    "html",
    "format",
]

_MAX_PAGES = 20


def _build_probe_url(base_url: str, param: str, payload: str) -> str:
    """Inject *payload* into *param*, preserving other query parameters."""
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    query = urlencode(params, doseq=True)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"


def _params_with_templates(url: str) -> list[tuple[str, str]]:
    """Return (base_url, param) probes: present template-ish params, or the
    canonical first param if the page has a query string, or ``q`` fallback."""
    parsed = urlparse(url)
    if not parsed.scheme:
        return []
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    present = [p for p in parse_qs(parsed.query, keep_blank_values=True) if p in TEMPLATE_PARAMS]
    if present:
        return [(base, p) for p in present]
    query_keys = list(parse_qs(parsed.query, keep_blank_values=True))
    if query_keys:
        return [(base, query_keys[0])]
    return [(base, "q")]


async def check_ssti(config: AegisxConfig, url: str) -> list[Finding]:
    """Probe one URL's template-ish parameters for expression evaluation."""
    findings: list[Finding] = []
    probes = _params_with_templates(url)
    if not probes:
        return findings

    try:
        async with create_client(config) as client:
            for base_url, param in probes:
                try:
                    baseline_resp = await client.get(
                        _build_probe_url(base_url, param, "aegisxbaseline"),
                        headers={"User-Agent": config.user_agent},
                    )
                    baseline_body = baseline_resp.text
                except (httpx.RequestError, httpx.TimeoutException):
                    continue

                for label, payload, marker in SSTI_PAYLOADS:
                    try:
                        resp = await client.get(
                            _build_probe_url(base_url, param, payload),
                            headers={"User-Agent": config.user_agent},
                        )
                    except (httpx.RequestError, httpx.TimeoutException):
                        continue
                    body = resp.text
                    # The marker must appear now and NOT have appeared in the
                    # baseline response for the same parameter.
                    if marker in body and marker not in baseline_body:
                        findings.append(
                            Finding(
                                title="Server-Side Template Injection (SSTI)",
                                description=(
                                    f"Parameter '{param}' evaluates template expressions: "
                                    f"payload '{payload}' ({label}) produced '{marker}' in the "
                                    "response. Template engines that evaluate user input allow "
                                    "remote code execution."
                                ),
                                severity=Severity.CRITICAL,
                                cvss_score=9.8,
                                cwe_id="CWE-1336",
                                owasp_category="A03:2021",
                                url=resp.url
                                and str(resp.url)
                                or _build_probe_url(base_url, param, payload),
                                endpoint=urlparse(base_url).path,
                                method="GET",
                                parameter=param,
                                evidence=f"payload={payload!r} engine={label} marker={marker!r} found in response",
                                payload=payload,
                                remediation=(
                                    "Never pass user input to template engines as template "
                                    "source. Render user data as variables, not as template text; "
                                    "use sandboxed environments where templating is unavoidable."
                                ),
                                references=[
                                    "https://portswigger.net/research/server-side-template-injection",
                                    "https://cwe.mitre.org/data/definitions/1336.html",
                                ],
                            )
                        )
                        break  # one confirmed engine per parameter is enough
    except (httpx.RequestError, httpx.TimeoutException, ValueError) as exc:
        logger.debug("SSTI check failed for %s: %s", url, type(exc).__name__)

    return findings


class SSTIScanner(BaseScanner):
    """Server-Side Template Injection detection scanner."""

    name = "ssti_scanner"
    description = "Detects server-side template injection in template-taking parameters"
    enabled_by_default = True

    async def validate_target(self) -> bool:
        """Applicable to any reachable HTTP target."""
        return True

    async def scan(self) -> list[Finding]:
        """Probe the target root and discovered pages for SSTI."""
        from aegisx.scanners.web.crawler import crawl_pages

        findings: list[Finding] = []

        try:
            pages = await crawl_pages(self.config, concurrency=5)
        except (httpx.RequestError, ValueError) as exc:
            logger.debug("Crawl failed: %s", type(exc).__name__)
            pages = []

        candidates = list(dict.fromkeys([self.config.target_url, *pages]))[:_MAX_PAGES]
        logger.info("SSTI: probing %d page(s)", len(candidates))

        for page in candidates:
            page_findings = await check_ssti(self.config, page)
            for f in page_findings:
                self.add_finding(f)
                findings.append(f)

        return findings
