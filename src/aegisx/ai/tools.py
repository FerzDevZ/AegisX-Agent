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

        self._results[key] = output
        return output
