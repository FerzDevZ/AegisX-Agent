"""SSRF & open-redirect detection scanner.

Finds URL-taking parameters and probes them for Server-Side Request
Forgery (CWE-918) and unvalidated open redirects (CWE-601). Detection
complements the ``ssrf_exploit`` verifier (CWE-918): the scanner flags
suspicious input surfaces, the exploit confirms exploitability.

All probe URLs (both the parameter values we inject and the requests we
send) stay inside the authorized scan scope — the scanner never makes a
request to attacker-controlled infrastructure.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from aegisx.core.config import AegisxConfig
from aegisx.core.context import Finding, Severity
from aegisx.scanners.base_scanner import BaseScanner
from aegisx.utils.http_client import create_client
from aegisx.utils.logger import get_logger

logger = get_logger("ssrf_scanner")

# Parameter names that commonly take a URL the server may fetch or
# redirect to. Long but cheap: it is just dictionary membership.
URL_PARAMS = [
    "url", "uri", "link", "redirect", "redirect_url", "redirect_uri",
    "return", "return_url", "returnTo", "rurl", "r_uri", "next", "next_url",
    "goto", "go", "target", "dest", "destination", "continue", "continue_url",
    "callback", "callback_url", "cb", "forward", "out", "outs", "view",
    "img", "image", "src", "source", "fetch", "load", "file", "path",
    "domain", "site", "feed", "host", "reference", "u", "r",
]

# External host we place in parameter values to see whether the server
# fetches/redirects there. Kept inert: example.com serves a plain page.
_PROBE_HOST = "aegisx-probe.example.com"

# Internal-only schemes/hosts we try as values to detect blind fetch
# behavior through error message reflection.
_INTERNAL_HINTS = [
    "http://127.0.0.1:80/",
    "http://localhost:22/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
]

# Error-message fragments suggesting the server actually attempted the
# internal request (blind SSRF reflection).
_INTERNAL_ERROR_SIGNATURES = [
    r"connection refused",
    r"econnrefused",
    r"getaddrinfo",
    r"name or service not known",
    r"temporary failure in name resolution",
    r"connection timed out",
    r"no route to host",
    r"ssh-2\.0",
    r"redis",
    r"root:x:0:0:",
]

# Response markers proving an open redirect occurred.
_REDIRECT_RESPONSE_PATTERN = re.compile(
    r"^(?:https?:)?//" + re.escape(_PROBE_HOST), re.IGNORECASE
)

_MAX_PROBE_PARAMS_PER_PAGE = 8
_MAX_PAGES = 30


def _urls_from_context(config: AegisxConfig) -> list[str]:
    """Collect candidate URLs: target root plus pages found by the crawler."""
    urls = [config.target_url]
    pages = getattr(config, "discovered_pages", None)
    if isinstance(pages, list):
        urls.extend(u for u in pages if isinstance(u, str))
    return urls[:_MAX_PAGES]


def _params_with_urls(url: str) -> list[tuple[str, str]]:
    """Return (base_url, param_name) probes for URL-ish query parameters.

    A page contributes probes when it either already carries a known
    URL-ish parameter, or has no query at all (the path itself is then
    probed with each canonical parameter name, preserving the path).
    """
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    existing = parse_qs(parsed.query)

    url_params_present = [p for p in URL_PARAMS if p in existing]
    if url_params_present:
        # Probe the parameters actually present (highest signal)
        return [(base, p) for p in url_params_present[:_MAX_PROBE_PARAMS_PER_PAGE]]

    if not existing:
        # Path-only URL: probe canonical parameter names on this path
        return [(base, p) for p in URL_PARAMS[:_MAX_PROBE_PARAMS_PER_PAGE]]

    # Query exists but none of the params are URL-ish — skip this page
    return []


def _build_probe_url(base: str, param: str, value: str) -> str:
    """Rebuild ``base`` with ``param`` set to ``value``, preserving others."""
    parsed = urlparse(base)
    existing = parse_qs(parsed.query)
    flat = {k: v[0] for k, v in existing.items()}
    flat[param] = value
    sep = "&" if parsed.query else "?"
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{sep}{urlencode(flat)}"


async def check_open_redirect(
    config: AegisxConfig,
    url: str,
    param: str,
) -> Finding | None:
    """Probe one URL parameter for an open redirect.

    Sends the URL with ``param`` pointed at an external benign host; a
    3xx Location header or rendered link landing on that host indicates
    the server redirects without validation (CWE-601).
    """
    probe_value = f"https://{_PROBE_HOST}/redirect-test"
    probe_url = _build_probe_url(url, param, probe_value)
    try:
        async with create_client(config, follow_redirects=False) as client:
            resp = await client.get(probe_url)
    except httpx.RequestError:
        return None

    location = resp.headers.get("location", "")
    if resp.status_code in (301, 302, 303, 307, 308) and _REDIRECT_RESPONSE_PATTERN.match(
        location
    ):
        return Finding(
            title=f"Open Redirect via '{param}' parameter",
            description=(
                f"The '{param}' parameter at {url} redirects to an external, "
                "attacker-controlled host without validation. Attackers can "
                "abuse this for phishing that appears to come from your domain."
            ),
            severity=Severity.MEDIUM,
            cvss_score=6.1,
            cwe_id="CWE-601",
            owasp_category="A01:2021",
            url=probe_url,
            endpoint=urlparse(url).path or "/",
            method="GET",
            parameter=param,
            payload=probe_value,
            evidence=f"HTTP {resp.status_code} → Location: {location[:200]}",
            remediation=(
                "Validate redirect targets against an allow-list of trusted "
                "hosts, or use server-side mapping keys instead of raw URLs. "
                "Reject absolute URLs that leave your origin."
            ),
            references=[
                "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
            ],
        )
    return None


async def check_blind_ssrf(
    config: AegisxConfig,
    url: str,
    param: str,
) -> Finding | None:
    """Probe one URL parameter for blind SSRF reflection.

    Injects an internal URL (loopback / file scheme) and inspects the
    response for error signatures suggesting the server attempted the
    fetch itself (CWE-918).
    """
    probe_url = _build_probe_url(url, param, _INTERNAL_HINTS[0])
    try:
        async with create_client(config) as client:
            resp = await client.get(probe_url)
    except httpx.RequestError:
        return None

    body_head = resp.text[:20_000].lower()
    for pattern in _INTERNAL_ERROR_SIGNATURES:
        if re.search(pattern, body_head):
            return Finding(
                title=f"Possible Blind SSRF via '{param}' parameter",
                description=(
                    f"Submitting an internal URL in the '{param}' parameter at "
                    f"{url} produced a response consistent with the server "
                    f"attempting to fetch it (matched '{pattern}'). The server "
                    "likely makes outbound requests from user-supplied URLs."
                ),
                severity=Severity.HIGH,
                cvss_score=8.6,
                cwe_id="CWE-918",
                owasp_category="A10:2021",
                url=probe_url,
                endpoint=urlparse(url).path or "/",
                method="GET",
                parameter=param,
                payload=_INTERNAL_HINTS[0],
                evidence=f"Response body matched internal-fetch signature: {pattern}",
                remediation=(
                    "Never fetch user-supplied URLs directly. Enforce an "
                    "allow-list of permitted hosts, block link-local/loopback/"
                    "private ranges (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, "
                    "::1), resolve DNS before connecting and re-check the IP, "
                    "and disable redirects for outbound fetches."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                    "CWE-918",
                ],
            )
    return None


class SSRFScanner(BaseScanner):
    """Detects SSRF input surfaces and open redirects across discovered pages."""

    name = "ssrf_scanner"
    description = (
        "Detects URL parameters vulnerable to Server-Side Request Forgery "
        "and open redirects"
    )

    async def validate_target(self) -> bool:
        """Applicable to any reachable HTTP target."""
        return True

    async def scan(self) -> list[Finding]:
        """Probe URL-ish parameters on the target root for SSRF/redirect."""
        from aegisx.scanners.web.crawler import crawl_pages

        findings: list[Finding] = []

        try:
            pages = await crawl_pages(self.config, concurrency=5)
        except (httpx.RequestError, ValueError) as exc:
            logger.debug("Crawl failed: %s", type(exc).__name__)
            pages = []

        candidates = list(dict.fromkeys([self.config.target_url, *pages]))[:_MAX_PAGES]
        probes: list[tuple[str, str]] = []
        for page in candidates:
            probes.extend(_params_with_urls(page))

        logger.info(
            "SSRF: probing %d URL parameter(s) on %d page(s)",
            len(probes), len(candidates),
        )

        for base_url, param in probes:
            # Values are internal/benign hosts; requests stay in scope.
            redirect = await check_open_redirect(self.config, base_url, param)
            if redirect:
                self.add_finding(redirect)
                findings.append(redirect)
            blind = await check_blind_ssrf(self.config, base_url, param)
            if blind:
                self.add_finding(blind)
                findings.append(blind)

        return findings
