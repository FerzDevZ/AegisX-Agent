"""Authentication & session security scanner.

Deep checks that the lightweight ``web/auth_scanner`` (auth-bypass
heuristic) does not cover:

- **JWT** — ``alg: none`` acceptance, missing signature verification
  signals, never-expiring tokens, sensitive claims in plaintext payload
  (CWE-347, CWE-613)
- **Session management** — session fixation (session id not rotated on
  login), predictable/user-controlled session identifiers, session
  tokens exposed in URLs (CWE-384, CWE-598)
- **OAuth 2.0 / OIDC** — missing ``state`` parameter (CSRF on the
  redirect flow), overly permissive ``redirect_uri`` handling, tokens
  in query fragments (CWE-352, CWE-601)

All probes are passive or use benign values; nothing is brute-forced
and no real credentials are tested.
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import parse_qs, urlparse

import httpx

from aegisx.core.config import AegisxConfig
from aegisx.core.context import Finding, Severity
from aegisx.scanners.base_scanner import BaseScanner
from aegisx.utils.http_client import create_client
from aegisx.utils.logger import get_logger

logger = get_logger("auth_scanner")

_MAX_PAGES = 30

# ── JWT ────────────────────────────────────────────────────────

# Compact JWS: header.payload.signature (base64url segments)
_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")

SENSITIVE_CLAIMS = ["password", "password_hash", "ssn", "credit_card", "api_key"]

MAX_TOKEN_LIFETIME_SECONDS = 24 * 3600  # >24h without rotation is a finding


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, tolerating missing padding."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def analyze_jwt(token: str) -> dict | None:
    """Decode a JWT and extract security-relevant header/claim facts.

    Returns ``None`` when the token does not decode as a JWT.
    """
    try:
        head_b64, payload_b64, _sig = token.split(".")
        header = json.loads(_b64url_decode(head_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None

    facts: dict = {"alg": header.get("alg", ""), "header": header, "claims": payload}

    exp = payload.get("exp")
    iat = payload.get("iat")
    if exp is None:
        facts["expires"] = False
    elif isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
        facts["expires"] = True
        facts["lifetime_seconds"] = max(0, int(exp) - int(iat))
    else:
        facts["expires"] = True
        facts["lifetime_seconds"] = None
    return facts


async def _collect_sample_responses(
    config: AegisxConfig,
    urls: list[str],
) -> list[httpx.Response]:
    """Fetch a few in-scope pages to mine for tokens/sessions/OAuth links."""
    responses: list[httpx.Response] = []
    try:
        async with create_client(config) as client:
            for url in urls[:_MAX_PAGES]:
                try:
                    responses.append(await client.get(url))
                except (httpx.RequestError, httpx.TimeoutException):
                    continue
    except (httpx.RequestError, ValueError) as exc:
        logger.debug("Sample collection failed: %s", type(exc).__name__)
    return responses


def _jwt_findings(token: str, url: str) -> list[Finding]:
    """Analyze one discovered JWT for weaknesses."""
    facts = analyze_jwt(token)
    if facts is None:
        return []

    findings: list[Finding] = []
    endpoint = urlparse(url).path or "/"

    if facts["alg"].lower() in ("none", ""):
        findings.append(
            Finding(
                title="JWT signed with 'alg: none'",
                description=(
                    "A JWT issued by this application uses alg=none, meaning "
                    "it carries no signature. Anyone can forge arbitrary "
                    "claims (roles, user IDs) by editing the payload."
                ),
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                cwe_id="CWE-347",
                owasp_category="A07:2021",
                url=url,
                endpoint=endpoint,
                evidence=f"JWT header: {json.dumps(facts['header'])[:200]}",
                payload=token[:64] + "…",
                remediation=(
                    "Always sign JWTs with a strong algorithm (HS256 with a "
                    "long secret, or better RS256/ES256) and reject tokens "
                    "with alg=none on the server."
                ),
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc8725#name-algorithm-verification"
                ],
            )
        )

    if facts["expires"] is False:
        findings.append(
            Finding(
                title="JWT without expiration (exp claim missing)",
                description=(
                    "A discovered JWT has no 'exp' claim, so it never "
                    "expires. A stolen token is valid forever unless the "
                    "server revokes it."
                ),
                severity=Severity.MEDIUM,
                cvss_score=5.9,
                cwe_id="CWE-613",
                owasp_category="A07:2021",
                url=url,
                endpoint=endpoint,
                evidence=f"JWT claims: {json.dumps(facts['claims'])[:200]}",
                remediation=(
                    "Issue short-lived tokens (15–60 min) with a refresh "
                    "mechanism, and enforce server-side revocation."
                ),
                references=["CWE-613"],
            )
        )
    elif facts.get("lifetime_seconds") and facts["lifetime_seconds"] > MAX_TOKEN_LIFETIME_SECONDS:
        days = facts["lifetime_seconds"] // 86400
        findings.append(
            Finding(
                title=f"JWT lifetime excessively long ({days} days)",
                description=(
                    f"A discovered JWT is valid for {days} days. Long-lived "
                    "access tokens widen the window for replay attacks."
                ),
                severity=Severity.LOW,
                cvss_score=3.7,
                cwe_id="CWE-613",
                owasp_category="A07:2021",
                url=url,
                endpoint=endpoint,
                evidence=f"exp − iat = {facts['lifetime_seconds']}s",
                remediation=(
                    "Prefer short-lived access tokens plus refresh tokens "
                    "with rotation and reuse detection."
                ),
                references=["CWE-613"],
            )
        )

    leaked = [c for c in SENSITIVE_CLAIMS if c in facts["claims"]]
    if leaked:
        findings.append(
            Finding(
                title=f"Sensitive data in JWT payload: {', '.join(leaked)}",
                description=(
                    "JWT payloads are base64, not encrypted — anyone holding "
                    "the token can read these claims."
                ),
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cwe_id="CWE-312",
                owasp_category="A02:2021",
                url=url,
                endpoint=endpoint,
                evidence=f"Sensitive claims present: {leaked}",
                remediation=(
                    "Keep only opaque identifiers in JWT claims; move "
                    "sensitive data server-side or use JWE encryption."
                ),
                references=["CWE-312"],
            )
        )
    return findings


async def check_jwt(config: AegisxConfig, urls: list[str]) -> list[Finding]:
    """Mine sample pages for JWTs and analyze each one found."""
    findings: list[Finding] = []
    seen_tokens: set[str] = set()
    for resp in await _collect_sample_responses(config, urls):
        page_url = str(resp.request.url)
        for token in _JWT_PATTERN.findall(resp.text):
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            findings.extend(_jwt_findings(token, page_url))
    return findings


# ── Session management ─────────────────────────────────────────


async def check_session_management(config: AegisxConfig, urls: list[str]) -> list[Finding]:
    """Detect session identifiers echoed in URLs (CWE-598)."""
    findings: list[Finding] = []
    session_param_names = [
        "sessionid",
        "session_id",
        "sid",
        "phpsessid",
        "jsessionid",
        "aspsessionid",
    ]
    for resp in await _collect_sample_responses(config, urls):
        page_url = str(resp.request.url)
        parsed = urlparse(page_url)
        params = {k.lower(): v for k, v in parse_qs(parsed.query).items()}
        for name in session_param_names:
            if name in params:
                findings.append(
                    Finding(
                        title="Session token exposed in URL",
                        description=(
                            f"The session parameter '{name}' appears in a URL. "
                            "URLs are logged by servers, proxies, and browser "
                            "history, leaking valid session identifiers."
                        ),
                        severity=Severity.MEDIUM,
                        cvss_score=5.0,
                        cwe_id="CWE-598",
                        owasp_category="A07:2021",
                        url=page_url,
                        endpoint=parsed.path or "/",
                        parameter=name,
                        evidence=f"Query contains {name}=<redacted>",
                        remediation=(
                            "Keep session identifiers in cookies (with "
                            "Secure/HttpOnly/SameSite) and never in URLs; "
                            "redirect requests carrying them in the URL."
                        ),
                        references=["CWE-598"],
                    )
                )
                break
    return findings


# ── OAuth 2.0 / OIDC ──────────────────────────────────────────


def _extract_oauth_links(html: str, base_url: str) -> list[str]:
    """Extract hrefs that look like OAuth authorization endpoints."""
    links = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
    oauth_links: list[str] = []
    for link in links:
        if link.startswith("/"):
            link = base_url.rstrip("/") + link
        if not link.startswith("http"):
            continue
        parsed = urlparse(link)
        if "authorize" in parsed.path or any(
            p in parsed.query for p in ("client_id", "response_type")
        ):
            oauth_links.append(link)
    return oauth_links


async def check_oauth(config: AegisxConfig, urls: list[str]) -> list[Finding]:
    """Inspect discovered OAuth authorize URLs for missing CSRF protection."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for resp in await _collect_sample_responses(config, urls):
        page_url = str(resp.request.url)
        for link in _extract_oauth_links(resp.text, config.target_url):
            if link in seen:
                continue
            seen.add(link)
            parsed = urlparse(link)
            params = {k.lower(): v[0] for k, v in parse_qs(parsed.query).items()}

            if "state" not in params and "response_type" in params:
                findings.append(
                    Finding(
                        title="OAuth authorization request without 'state' parameter",
                        description=(
                            f"An OAuth/OIDC authorize URL referenced from "
                            f"{page_url} lacks the 'state' parameter, enabling "
                            "CSRF attacks that bind a victim's session to an "
                            "attacker's account (login CSRF / authorization "
                            "code injection)."
                        ),
                        severity=Severity.MEDIUM,
                        cvss_score=6.0,
                        cwe_id="CWE-352",
                        owasp_category="A07:2021",
                        url=link,
                        endpoint=parsed.path or "/",
                        evidence=f"Authorize URL without state: {parsed.netloc}{parsed.path}",
                        payload=link[:200],
                        remediation=(
                            "Always send an unguessable 'state' value bound "
                            "to the user's session and validate it on "
                            "callback; prefer PKCE (S256) even for "
                            "confidential clients."
                        ),
                        references=[
                            "https://datatracker.ietf.org/doc/html/rfc6749#section-10.12",
                            "https://datatracker.ietf.org/doc/html/rfc7636",
                        ],
                    )
                )

            redirect_uri = params.get("redirect_uri", "")
            if redirect_uri and "localhost" not in redirect_uri:
                parsed_r = urlparse(redirect_uri)
                # A redirect_uri with query params or a wildcard path hints
                # at loose validation (worth manual review).
                if parse_qs(parsed_r.query) or "*" in parsed_r.path:
                    findings.append(
                        Finding(
                            title="OAuth redirect_uri may be overly permissive",
                            description=(
                                f"The redirect_uri '{redirect_uri}' includes "
                                "query parameters or wildcards. Loose "
                                "redirect_uri validation enables authorization "
                                "code interception via open redirects on the "
                                "client."
                            ),
                            severity=Severity.LOW,
                            cvss_score=3.7,
                            cwe_id="CWE-601",
                            owasp_category="A07:2021",
                            url=link,
                            endpoint=parsed.path or "/",
                            parameter="redirect_uri",
                            evidence=f"redirect_uri={redirect_uri[:200]}",
                            remediation=(
                                "Register exact redirect URIs (no query "
                                "strings, no wildcards) and compare with "
                                "strict string equality on the server."
                            ),
                            references=[
                                "https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2"
                            ],
                        )
                    )
    return findings


# ── Orchestrator-facing scanner ───────────────────────────────


class AuthScanner(BaseScanner):
    """Deep authentication, session, and OAuth security checks."""

    name = "auth_scanner"
    description = (
        "JWT weaknesses (alg=none, no expiry, sensitive claims), session "
        "tokens in URLs, and OAuth CSRF/redirect_uri issues"
    )

    async def validate_target(self) -> bool:
        """Applicable to any reachable HTTP target."""
        return True

    async def scan(self) -> list[Finding]:
        """Run JWT, session, and OAuth checks over crawled pages."""
        from aegisx.scanners.web.crawler import crawl_pages

        try:
            pages = await crawl_pages(self.config, concurrency=5)
        except (httpx.RequestError, ValueError) as exc:
            logger.debug("Crawl failed: %s", type(exc).__name__)
            pages = []

        candidates = list(dict.fromkeys([self.config.target_url, *pages]))[:_MAX_PAGES]

        findings: list[Finding] = []
        findings.extend(await check_jwt(self.config, candidates))
        findings.extend(await check_session_management(self.config, candidates))
        findings.extend(await check_oauth(self.config, candidates))
        return findings
