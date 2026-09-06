"""Tool registry for the AI agent — schemas plus dispatcher.

Exposes the existing Aegisx engine (recon, scanners, exploits, reports,
HTTP) as OpenAI-format tool definitions the LLM can call. Every tool is
**scope-enforced server-side**: the LLM cannot reach a URL outside the
authorized scope even if it tries.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urlparse

from aegisx.ai.redaction import redact
from aegisx.core.config import AegisxConfig
from aegisx.core.context import ScanContext
from aegisx.utils.logger import get_logger

logger = get_logger("ai.tools")

# Domains the agent may never touch, even by accident
_SSRF_BLACKLIST_HOSTS = {
    "169.254.169.254",  # cloud metadata
    "metadata.google.internal",
    "100.100.100.200",  # aliyun metadata
}


def _f(
    name: str,
    desc: str,
    params: dict[str, Any],
    required: list[str] | None = None,
) -> dict[str, Any]:
    """Build one OpenAI function tool schema."""
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": desc,
            "parameters": {
                "type": "object",
                "properties": params,
                "required": required or [],
            },
        },
    }


TOOL_SCHEMAS: list[dict[str, Any]] = [
    _f(
        "run_recon",
        "Passive reconnaissance of the target: server banner, technologies, "
        "DNS, robots.txt. Always run this first.",
        {},
    ),
    _f(
        "run_scanner",
        "Run one or more scanners against the target. Use after recon.",
        {
            "scanner_names": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Scanner IDs: web_scanner, secret_scanner, "
                "config_scanner, dependency_scanner, network_scanner. "
                "Empty = run all enabled by default.",
            },
        },
    ),
    _f(
        "verify_exploit",
        "Verify one finding is actually exploitable using the matching exploit "
        "module (SQLi, XSS, CSRF, SSRF). Only call when the user authorized "
        "exploit verification.",
        {"finding_id": {"type": "string", "description": "Finding ID like VF-XXXXXXXX"}},
        ["finding_id"],
    ),
    _f(
        "get_findings",
        "List all findings from the current scan, optionally filtered by severity.",
        {
            "min_severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
            },
        },
    ),
    _f(
        "http_request",
        "Send a single HTTP request to a URL inside the authorized scope and "
        "return status, headers, and a truncated body. Use for manual checks.",
        {
            "url": {"type": "string", "description": "Absolute URL"},
            "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS"]},
        },
        ["url"],
    ),
    _f(
        "generate_report",
        "Generate the final report. Always call this as the last step.",
        {"format": {"type": "string", "enum": ["markdown", "json", "sarif", "html"]}},
    ),
    _f(
        "compare_history",
        "Compare two previous scans of this target and report new, resolved, "
        "and changed findings. Without arguments, compares the two most "
        "recent scans recorded in history.",
        {
            "old_scan_id": {"type": "string", "description": "Baseline scan ID (optional)"},
            "new_scan_id": {"type": "string", "description": "Latest scan ID (optional)"},
        },
    ),
    _f(
        "probe_ssrf",
        "Discover URL-taking parameters on the target and probe them for "
        "open redirects (CWE-601) and blind SSRF (CWE-918). All probes are "
        "benign and stay inside the authorized scope. Call after run_scanner "
        "on targets with URL parameters. Optionally probe a specific page "
        "and parameter.",
        {
            "url": {
                "type": "string",
                "description": "Specific in-scope page to probe (optional; default: crawl) ",
            },
            "param": {
                "type": "string",
                "description": "Specific parameter to probe (requires url)",
            },
        },
    ),
    _f(
        "probe_auth",
        "Mine an in-scope page for JWTs, session identifiers, and OAuth "
        "authorization links, then analyze them: JWT alg=none, missing/long "
        "expiry, sensitive claims; session tokens in URLs; OAuth requests "
        "missing 'state'. Findings are registered automatically and decoded "
        "token facts are returned so you can reason about them. Use on "
        "login/auth/profile pages.",
        {
            "url": {
                "type": "string",
                "description": "Specific in-scope page to analyze (optional; default: target root)",
            },
        },
    ),
]


class ToolDispatcher:
    """Executes agent tool calls against the scan context and engine."""

    def __init__(self, config: AegisxConfig, context: ScanContext) -> None:
        """Bind the dispatcher to a config and its scan context."""
        self.config = config
        self.context = context
        self.total_requests = 0
        # Duplicate-call damping: weak models tend to repeat identical
        # tool calls; cached/hinted responses keep the loop converging.
        self._call_counts: dict[str, int] = {}
        self._results: dict[str, str] = {}
        self.last_call_was_duplicate = False
        # One shared orchestrator instance avoids re-registering built-in
        # plugins (and the associated warnings) on every tool call.
        from aegisx.core.orchestrator import AegisxOrchestrator

        self._orchestrator = AegisxOrchestrator(config)

    # --- scope enforcement -------------------------------------------------

    def _assert_in_scope(self, url: str) -> None:
        """Reject URLs outside the scan scope or hitting metadata endpoints."""
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if host in _SSRF_BLACKLIST_HOSTS:
            raise PermissionError(f"Blocked: {host} is a cloud metadata endpoint")
        if not self.config.is_in_scope(url):
            raise PermissionError(
                f"Blocked: {url} is outside the authorized scope "
                f"(scope={self.config.scope or [urlparse(self.config.target_url).hostname]})"
            )

    # --- tool implementations ---------------------------------------------

    async def _tool_recon(self, _args: dict[str, Any]) -> str:
        """Run the orchestrator recon phase and summarize target info."""
        await self._orchestrator._phase_recon()
        info = self.context.target_info or {}
        return json.dumps(
            {
                "server": info.get("server", "unknown"),
                "technologies": info.get("technologies", []),
                "http_status": info.get("status_code"),
                "target": self.config.target_url,
            },
            ensure_ascii=False,
        )

    async def _tool_scan(self, args: dict[str, Any]) -> str:
        """Run the requested scanners (or all enabled) and report counts."""

        requested = [s for s in args.get("scanner_names", []) if s]
        original = self.config.enabled_scanners
        if requested:
            unknown = [s for s in requested if s not in original]
            if unknown:
                return json.dumps(
                    {"error": f"Unknown scanners: {unknown}. Available: {original}"}
                )
            self.config.enabled_scanners = requested
        try:
            await self._orchestrator._phase_scan()
        finally:
            self.config.enabled_scanners = original

        from collections import Counter

        by_severity = Counter(f.severity.value for f in self.context.findings)
        return json.dumps(
            {
                "scanners_run": requested or original,
                "total_findings": len(self.context.findings),
                "by_severity": dict(by_severity),
            },
            ensure_ascii=False,
        )

    async def _tool_verify_exploit(self, args: dict[str, Any]) -> str:
        """Run the matching exploit module against one finding."""

        finding_id = str(args.get("finding_id", ""))
        finding = next((f for f in self.context.findings if f.id == finding_id), None)
        if finding is None:
            return json.dumps({"error": f"Finding {finding_id} not found"})

        if not self.config.exploit_verification:
            return json.dumps(
                {"error": "Exploit verification not authorized. "
                "User must run with --exploit flag."}
            )

        plugin_manager = self._orchestrator.plugin_manager
        exploit_name = plugin_manager.get_exploit_for_finding(finding)
        if exploit_name is None:
            return json.dumps({"error": f"No exploit module can verify {finding_id}"})
        exploit_cls = plugin_manager.get_exploit(exploit_name)
        exploit = exploit_cls(context=self.context)  # type: ignore[misc]
        result = await exploit.run(finding)
        return json.dumps(
            {
                "finding_id": finding_id,
                "exploit": exploit_name,
                "verified": bool(result and result.success),
                "evidence": (result.evidence[:300] if result and result.evidence else None),
            },
            ensure_ascii=False,
        )

    async def _tool_get_findings(self, args: dict[str, Any]) -> str:
        """List findings, optionally filtered by minimum severity."""
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_sev = args.get("min_severity", "info")
        threshold = order.get(min_sev, 0)
        findings = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "cvss": f.cvss_score,
                "url": f.url,
                "endpoint": f.endpoint,
                "evidence": (f.evidence[:200] if f.evidence else None),
            }
            for f in self.context.findings
            if order.get(f.severity.value, 0) >= threshold
        ]
        return json.dumps(findings, ensure_ascii=False)

    async def _tool_http_request(self, args: dict[str, Any]) -> str:
        """Make one scope-checked HTTP request and return a summary."""
        url = str(args.get("url", ""))
        method = str(args.get("method", "GET")).upper()
        self._assert_in_scope(url)

        from aegisx.utils.http_client import create_client

        self.total_requests += 1
        async with create_client(self.config) as client:
            resp = await client.request(
                method, url, headers={"User-Agent": self.config.user_agent}
            )
        body = resp.text[:1_500] if method != "HEAD" else ""
        return json.dumps(
            {
                "status": resp.status_code,
                "headers": dict(list(resp.headers.items())[:15]),
                "body_preview": body,
            },
            ensure_ascii=False,
        )

    async def _tool_generate_report(self, args: dict[str, Any]) -> str:
        """Generate and save a report in the requested format."""
        from aegisx.core.config import ReportFormat

        fmt_name = args.get("format", "markdown")
        try:
            fmt = ReportFormat(fmt_name)
        except ValueError:
            return json.dumps({"error": f"Unknown format: {fmt_name}"})

        original = self.config.report_format
        self.config.report_format = fmt
        try:
            await self._orchestrator._phase_report()
        finally:
            self.config.report_format = original

        files = sorted(
            p.name for p in self.config.report_output.glob("aegisx-report-*")
        )
        return json.dumps(
            {"format": fmt_name, "files": files, "directory": str(self.config.report_output)}
        )

    async def _tool_probe_ssrf(self, args: dict[str, Any]) -> str:
        """Probe URL parameters for open redirect / blind SSRF."""
        from aegisx.scanners.ssrf_scanner import (
            _params_with_urls,
            check_blind_ssrf,
            check_open_redirect,
        )

        url = str(args.get("url") or self.config.target_url)
        # The tool only requests in-scope pages; scope check is explicit.
        self._assert_in_scope(url)
        param = str(args.get("param") or "")

        probes = [(url.split("?")[0], param)] if param else _params_with_urls(url)

        if not probes:
            return json.dumps(
                {
                    "probed": 0,
                    "note": "No URL-taking parameters found on this page. "
                    "Try another in-scope path, or call without arguments to "
                    "probe the target root.",
                },
                ensure_ascii=False,
            )

        findings = []
        for base, p in probes:
            redirect = await check_open_redirect(self.config, base, p)
            if redirect:
                self.context.add_finding(redirect)
                findings.append(redirect)
            blind = await check_blind_ssrf(self.config, base, p)
            if blind:
                self.context.add_finding(blind)
                findings.append(blind)

        return json.dumps(
            {
                "probed": len(probes),
                "parameters": [p for _, p in probes],
                "new_findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "cwe": f.cwe_id,
                        "evidence": (f.evidence[:200] if f.evidence else None),
                    }
                    for f in findings
                ],
                "total_findings_in_scan": len(self.context.findings),
            },
            ensure_ascii=False,
        )

    async def _tool_probe_auth(self, args: dict[str, Any]) -> str:
        """Mine a page for JWTs/sessions/OAuth and analyze them."""
        from aegisx.scanners.auth_scanner import (
            _JWT_PATTERN,
            _extract_oauth_links,
            analyze_jwt,
            check_jwt,
            check_oauth,
            check_session_management,
        )

        url = str(args.get("url") or self.config.target_url)
        self._assert_in_scope(url)  # explicit scope gate (blocked → error JSON)

        findings: list = []
        try:
            from aegisx.utils.http_client import create_client

            async with create_client(self.config) as client:
                resp = await client.get(url)
        except Exception as exc:  # noqa: BLE001 — surfaced to the LLM as JSON
            return json.dumps({"error": f"fetch failed: {type(exc).__name__}: {exc}"})

        # --- decoded token facts (for model reasoning) -------------------
        token_facts: list[dict[str, Any]] = []
        for token in list(dict.fromkeys(_JWT_PATTERN.findall(resp.text)))[:5]:
            facts = analyze_jwt(token)
            if facts is None:
                continue
            exp = facts["claims"].get("exp")
            iat = facts["claims"].get("iat")
            numeric = isinstance(exp, (int, float)) and isinstance(iat, (int, float))
            lifetime = int(exp) - int(iat) if numeric else None
            token_facts.append(
                {
                    "token_preview": token[:24] + "…",
                    "alg": facts["alg"],
                    "has_expiry": facts["expires"],
                    "lifetime_seconds": lifetime,
                    "sensitive_claims": [
                        c for c in ("password", "password_hash", "ssn", "credit_card", "api_key")
                        if c in facts["claims"]
                    ],
                    "claim_names": sorted(facts["claims"].keys()),
                }
            )

        # --- full checks register findings in context --------------------
        findings.extend(await check_jwt(self.config, [url]))
        findings.extend(await check_session_management(self.config, [url]))
        findings.extend(await check_oauth(self.config, [url]))
        for f in findings:
            self.context.add_finding(f)

        # --- OAuth link facts -------------------------------------------
        oauth_links = _extract_oauth_links(resp.text, self.config.target_url)[:5]
        oauth_facts = []
        for link in oauth_links:
            from urllib.parse import parse_qs as _pqs
            from urllib.parse import urlparse as _up

            q = {k.lower(): v[0] for k, v in _pqs(_up(link).query).items()}
            oauth_facts.append(
                {
                    "host": _up(link).netloc,
                    "has_state": "state" in q,
                    "response_type": q.get("response_type"),
                    "redirect_uri": (q.get("redirect_uri") or "")[:100],
                }
            )

        return json.dumps(
            {
                "url": url,
                "jwt_tokens_found": len(token_facts),
                "jwt_facts": token_facts,
                "oauth_links_found": len(oauth_facts),
                "oauth_facts": oauth_facts,
                "new_findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "cwe": f.cwe_id,
                        "evidence": (f.evidence[:200] if f.evidence else None),
                    }
                    for f in findings
                ],
                "total_findings_in_scan": len(self.context.findings),
            },
            ensure_ascii=False,
        )

    async def _tool_compare_history(self, args: dict[str, Any]) -> str:
        """Diff two historical scans (default: two most recent for this target)."""
        from aegisx.utils.history import ScanHistory

        history = ScanHistory()
        old_id = args.get("old_scan_id") or None
        new_id = args.get("new_scan_id") or None

        if not (old_id and new_id):
            target = self.config.target_url
            recent = history.get_scans(target=target, limit=2)
            if len(recent) < 2:
                # Fall back to any two most recent scans overall
                recent = history.get_scans(limit=2)
            if len(recent) < 2:
                return json.dumps(
                    {
                        "error": "Need at least 2 recorded scans to compare. "
                        "Run 'aegisx scan' first, or pass old_scan_id/new_scan_id.",
                    }
                )
            old_id = old_id or recent[1]["scan_id"]
            new_id = new_id or recent[0]["scan_id"]

        diff = history.compare_scans(old_id, new_id)
        return json.dumps(
            {
                "old_scan": old_id,
                "new_scan": new_id,
                "severity_delta": diff.get("severity_delta", {}),
                "new_findings": [
                    {"title": f.get("title"), "severity": f.get("severity")}
                    for f in diff.get("new_findings", [])
                ],
                "resolved_findings": [
                    {"title": f.get("title"), "severity": f.get("severity")}
                    for f in diff.get("resolved_findings", [])
                ],
            },
            ensure_ascii=False,
        )

    # --- dispatch ----------------------------------------------------------

    async def execute(self, name: str, args: dict[str, Any]) -> str:
        """Dispatch one tool call by name. Errors become JSON strings.

        Identical repeat calls are damped: the 2nd returns the cached
        result plus a hint, the 3rd+ returns only a hint. This stops
        weak models from burning their iteration budget in loops.
        """
        handlers = {
            "run_recon": self._tool_recon,
            "run_scanner": self._tool_scan,
            "verify_exploit": self._tool_verify_exploit,
            "get_findings": self._tool_get_findings,
            "http_request": self._tool_http_request,
            "generate_report": self._tool_generate_report,
            "compare_history": self._tool_compare_history,
            "probe_ssrf": self._tool_probe_ssrf,
            "probe_auth": self._tool_probe_auth,
        }
        handler = handlers.get(name)
        if handler is None:
            return json.dumps({"error": f"Unknown tool: {name}"})

        key = f"{name}:{json.dumps(args, sort_keys=True, ensure_ascii=False)}"
        self._call_counts[key] = self._call_counts.get(key, 0) + 1
        count = self._call_counts[key]
        self.last_call_was_duplicate = count > 1

        if count == 2 and key in self._results:
            return (
                self._results[key]
                + "\n\n[NOTE: identical repeat call — result unchanged. "
                "Do not call this tool again with the same arguments.]"
            )
        if count > 2 and key in self._results:
            return json.dumps(
                {
                    "hint": "Duplicate call blocked. You already have this "
                    "result. Pick a different action or produce your final "
                    "summary now.",
                }
            )

        try:
            output = await handler(args)
        except PermissionError as exc:
            logger.warning("[bold red]SCOPE[/] %s", exc)
            return json.dumps({"error": str(exc), "blocked": True})
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — tool errors go back to the LLM
            logger.debug("Tool %s failed: %s", name, exc)
            return json.dumps({"error": f"{type(exc).__name__}: {exc}"})

        # Never let live credentials reach the LLM provider
        output = redact(output)

        self._results[key] = output
        return output
