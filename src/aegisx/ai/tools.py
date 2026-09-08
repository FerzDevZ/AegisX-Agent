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
from urllib.parse import quote as _quote
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

# High-signal fuzz set for fuzz_param: one probe per vulnerability class.
# Small by design — the model can iterate, the target must not suffer.
_FUZZ_PAYLOADS: list[tuple[str, str]] = [
    ("sqli_quote", "'\"`()"),
    ("sqli_or", "' OR '1'='1"),
    ("sqli_union", "1 UNION SELECT NULL-- -"),
    ("ssti_jinja", "{{7*7}}"),
    ("ssti_dollar", "${7*7}"),
    ("xss_reflect", '"><script>alert(1)</script>'),
    ("traversal", "../../../../etc/passwd"),
    ("format_string", "%s%s%s%s"),
]

_SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "sqlite3.operationalerror",
    "ora-01756",
]
_TRAVERSAL_SIGNATURE = "root:x:0:0:"

# Common sensitive/interesting paths for enum_paths (default set)
_ENUM_PATHS = [
    "/admin",
    "/admin/login",
    "/administrator",
    "/api",
    "/api/v1",
    "/backup",
    "/backup.zip",
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/composer.json",
    "/composer.lock",
    "/config.php",
    "/config.php.bak",
    "/db.sql",
    "/debug",
    "/docs",
    "/.DS_Store",
    "/dump.sql",
    "/package.json",
    "/phpinfo.php",
    "/phpmyadmin",
    "/server-status",
    "/sitemap.xml",
    "/uploads",
    "/wp-admin",
    "/wp-config.php.bak",
    "/wp-login.php",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/cgi-bin/",
    "/actuator/health",
    "/console",
    "/graphql",
    "/.svn/entries",
    "/robots.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/swagger.json",
    "/openapi.json",
]


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
    _f(
        "store_note",
        "Save a note to your persistent scratchpad. Notes survive context "
        "trimming — write down key facts, hunches, and open questions as "
        "you work. The full note list is returned on every write.",
        {"note": {"type": "string", "description": "The note text (one fact per note works best)"}},
        ["note"],
    ),
    _f(
        "fuzz_param",
        "Fuzz one parameter on an in-scope URL with a small high-signal "
        "payload set (SQLi, SSTI, XSS reflection, path traversal) and "
        "diff each response against a baseline. Returns observations only — "
        "register nothing yourself; strong signals should be verified with "
        "verify_exploit.",
        {
            "url": {"type": "string", "description": "In-scope URL with the parameter"},
            "param": {"type": "string", "description": "Parameter name to fuzz"},
        },
        ["url", "param"],
    ),
    _f(
        "diff_responses",
        "Fetch two in-scope URLs and compare status, length, and body hash. "
        "Use to confirm blind injection (payload URL vs baseline URL) or to "
        "distinguish soft-404s from real pages.",
        {
            "url_a": {"type": "string", "description": "First in-scope URL (baseline)"},
            "url_b": {"type": "string", "description": "Second in-scope URL (variant)"},
        },
        ["url_a", "url_b"],
    ),
    _f(
        "enum_paths",
        "Probe a target for common sensitive/interesting paths (admin panels, "
        "backups, VCS dirs, configs, API docs). Uses HEAD requests with a "
        "small concurrency cap. Returns paths that did not 404.",
        {
            "paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Custom path list (optional; default: builtin ~40 paths)",
            },
        },
    ),
    _f(
        "lookup_cwe",
        "Look up the OWASP Top 10 category, description, and remediation "
        "guidance for a CWE id (e.g. CWE-89) or an OWASP code (e.g. A03). "
        "Use it to ground severity reasoning and remediation advice.",
        {
            "query": {
                "type": "string",
                "description": "CWE id like 'CWE-89' or OWASP code like 'A03'",
            }
        },
        ["query"],
    ),
    _f(
        "spawn_agent",
        "Spawn a specialist sub-agent that runs its own tool loop and "
        "reports back. Specialties: recon (attack-surface mapping), vuln "
        "(vulnerability hunting), exploit (verification — requires --exploit "
        "authorization). Findings land in the shared scan context; the "
        "sub-agent's summary is returned here. Use on broad targets; skip "
        "on tiny ones.",
        {
            "specialty": {
                "type": "string",
                "enum": ["recon", "vuln", "exploit"],
                "description": "Specialist type to spawn",
            },
            "focus": {
                "type": "string",
                "description": "Optional area to concentrate on, e.g. 'https://target/admin panel'",
            },
            "max_iterations": {
                "type": "integer",
                "description": "Sub-agent loop budget (1-12, default 8)",
            },
        },
        ["specialty"],
    ),
]

# Restricted toolsets per spawn_agent specialty. Sub-agents are voters of
# scope, not of privilege: every tool still goes through the same shared
# dispatcher (scope checks, duplicate damping) — the map only narrows what
# each specialist may call. spawn_agent itself is absent everywhere: no
# recursive spawning.
SPECIALTY_TOOLS: dict[str, list[str]] = {
    "recon": ["run_recon", "enum_paths", "http_request", "get_findings"],
    "vuln": [
        "run_scanner",
        "probe_ssrf",
        "probe_auth",
        "fuzz_param",
        "diff_responses",
        "http_request",
        "get_findings",
    ],
    "exploit": ["verify_exploit", "get_findings", "http_request", "diff_responses"],
}


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
        # spawn_agent wiring: the orchestrating agent registers itself so
        # the handler can reach the parent's provider and result sink.
        self.owner: Any = None
        self.spawn_depth = 0  # 0 = orchestrator, 1 = sub-agent (cannot spawn)
        # Token usage produced by tools themselves (sub-agent runs) —
        # drained into the parent result by the agent loop.
        self.last_tool_usage: dict[str, int] = {}
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
                return json.dumps({"error": f"Unknown scanners: {unknown}. Available: {original}"})
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
                {"error": "Exploit verification not authorized. User must run with --exploit flag."}
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
            resp = await client.request(method, url, headers={"User-Agent": self.config.user_agent})
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

        files = sorted(p.name for p in self.config.report_output.glob("aegisx-report-*"))
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
                        c
                        for c in ("password", "password_hash", "ssn", "credit_card", "api_key")
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

    async def _tool_store_note(self, args: dict[str, Any]) -> str:
        """Append a note to the persistent scratchpad and echo all notes."""
        note = str(args.get("note", "")).strip()
        if not note:
            return json.dumps({"error": "empty note"})
        self.context.agent_notes.append(note[:500])
        return json.dumps(
            {
                "saved": True,
                "total_notes": len(self.context.agent_notes),
                "notes": self.context.agent_notes,
            },
            ensure_ascii=False,
        )

    async def _tool_fuzz_param(self, args: dict[str, Any]) -> str:
        """Fuzz one parameter with a high-signal payload set; return diffs.

        Observations only — the model reasons over the diffs and confirms
        with verify_exploit before anything is reported. Auto-registering
        here would produce false positives on WAF/error pages.
        """
        url = str(args.get("url", ""))
        param = str(args.get("param", ""))
        if not url or not param:
            return json.dumps({"error": "url and param are required"})
        self._assert_in_scope(url)

        from aegisx.utils.http_client import create_client

        base_url = url.split("?")[0]
        separator = "&" if "?" in base_url else "?"

        def _with(value: str) -> str:
            return f"{base_url}{separator}{param}={value}"

        async with create_client(self.config) as client:
            baseline = await client.get(_with("aegisxbaseline"))
            observations = []
            for label, payload in _FUZZ_PAYLOADS:
                resp = await client.get(_with(_quote(payload, safe="")))
                body = resp.text
                body_lower = body.lower()
                signals: list[str] = []
                if resp.status_code != baseline.status_code:
                    signals.append(f"status {baseline.status_code}->{resp.status_code}")
                if len(body) - len(baseline.text) > 200:
                    signals.append(f"length +{len(body) - len(baseline.text)}")
                if any(s in body_lower for s in _SQL_ERROR_SIGNATURES):
                    signals.append("sql_error_string")
                if _TRAVERSAL_SIGNATURE in body:
                    signals.append("passwd_file_contents")
                if "alert(1)" in body:
                    signals.append("xss_reflected_unescaped")
                if label.startswith("ssti") and "49" in body and "49" not in baseline.text:
                    signals.append("template_expression_evaluated")
                observations.append(
                    {
                        "payload_label": label,
                        "status": resp.status_code,
                        "length": len(body),
                        "signals": signals,
                    }
                )

        self.total_requests += 1 + len(_FUZZ_PAYLOADS)
        return json.dumps(
            {
                "url": base_url,
                "param": param,
                "baseline": {"status": baseline.status_code, "length": len(baseline.text)},
                "observations": observations,
                "note": "Observations only. Confirm strong signals with verify_exploit.",
            },
            ensure_ascii=False,
        )

    async def _tool_diff_responses(self, args: dict[str, Any]) -> str:
        """Compare two in-scope responses (status, length, body hash)."""
        import hashlib

        url_a = str(args.get("url_a", ""))
        url_b = str(args.get("url_b", ""))
        if not url_a or not url_b:
            return json.dumps({"error": "url_a and url_b are required"})
        self._assert_in_scope(url_a)
        self._assert_in_scope(url_b)

        from aegisx.utils.http_client import create_client

        self.total_requests += 2
        async with create_client(self.config) as client:
            ra = await client.get(url_a)
            rb = await client.get(url_b)

        ha = hashlib.sha256(ra.content).hexdigest()[:16]
        hb = hashlib.sha256(rb.content).hexdigest()[:16]
        return json.dumps(
            {
                "a": {"url": url_a, "status": ra.status_code, "length": len(ra.text), "sha256": ha},
                "b": {"url": url_b, "status": rb.status_code, "length": len(rb.text), "sha256": hb},
                "same_body": ha == hb,
                "same_status": ra.status_code == rb.status_code,
            },
            ensure_ascii=False,
        )

    async def _tool_enum_paths(self, args: dict[str, Any]) -> str:
        """Probe common paths with HEAD requests; report non-404s."""
        from urllib.parse import urljoin as _urljoin

        from aegisx.utils.http_client import create_client

        paths = [str(p) for p in args.get("paths", []) if str(p).startswith("/")][:100]
        if not paths:
            paths = list(_ENUM_PATHS)
        origin = (
            f"{urlparse(self.config.target_url).scheme}://{urlparse(self.config.target_url).netloc}"
        )

        semaphore = asyncio.Semaphore(5)

        async def _probe(client: Any, path: str) -> dict[str, Any] | None:
            url = _urljoin(origin, path)
            self._assert_in_scope(url)
            async with semaphore:
                try:
                    resp = await client.head(url)
                except Exception:  # noqa: BLE001 — a dead path is just a miss
                    return None
            if resp.status_code == 404:
                return None
            return {"path": path, "status": resp.status_code}

        self.total_requests += len(paths)
        async with create_client(self.config) as client:
            results = await asyncio.gather(*(_probe(client, p) for p in paths))
        hits = [r for r in results if r is not None]
        return json.dumps(
            {
                "probed": len(paths),
                "hits": hits,
                "note": "403/401 = exists but blocked; 405 = HEAD refused, try http_request",
            },
            ensure_ascii=False,
        )

    async def _tool_lookup_cwe(self, args: dict[str, Any]) -> str:
        """Ground severity/remediation reasoning in the OWASP knowledge base."""
        from aegisx.knowledge.owasp_top10 import get_category, get_category_by_cwe

        query = str(args.get("query", "")).strip().upper()
        if not query:
            return json.dumps({"error": "query required (e.g. CWE-89 or A03)"})

        if query.startswith("A") and query[1:].isdigit():
            category = get_category(query)
            matched = None
        else:
            cwe_id = query if query.startswith("CWE-") else f"CWE-{query}"
            category = get_category_by_cwe(cwe_id)
            matched = cwe_id
        if category is None:
            return json.dumps({"error": f"no OWASP category found for {query}"})

        return json.dumps(
            {
                "query": query,
                "owasp": f"{category.code}:{category.year} {category.name}",
                "description": category.description,
                "remediation": category.remediation,
                "matched_cwe": matched,
                "category_cwes_count": len(category.cwe_ids),
                "references": category.references[:3],
            },
            ensure_ascii=False,
        )

    async def _tool_spawn_agent(self, args: dict[str, Any]) -> str:
        """Run a specialist sub-agent loop and return its summary.

        The sub-agent shares this dispatcher (one scope-enforcement point,
        one duplicate-damping table) and the parent's scan context, so its
        findings flow into the orchestrator's report automatically. Its
        token usage is parked in ``last_tool_usage`` for the parent loop
        to drain into the run totals.
        """
        from aegisx.ai.agent import AegisxAgent
        from aegisx.ai.prompts import SPECIALTY_PROMPTS

        specialty = str(args.get("specialty", "")).strip().lower()
        if specialty not in SPECIALTY_TOOLS:
            return json.dumps(
                {"error": f"Unknown specialty {specialty!r}. Valid: {sorted(SPECIALTY_TOOLS)}"}
            )
        if specialty == "exploit" and not self.config.exploit_verification:
            return json.dumps(
                {"error": "exploit sub-agent requires --exploit authorization on this run"}
            )
        if self.spawn_depth >= 1:
            return json.dumps({"error": "sub-agents cannot spawn further agents"})
        if self.owner is None:
            return json.dumps({"error": "no orchestrator agent attached"})

        try:
            budget = int(args.get("max_iterations", 8))
        except (TypeError, ValueError):
            budget = 8
        budget = max(1, min(budget, 12))
        focus = str(args.get("focus", "")).strip()

        parent = self.owner
        # Sub-agents get the primary provider, not the voting wrapper —
        # peer review is for the orchestrator's final report only.
        primary = getattr(parent.provider, "primary", parent.provider)

        self.spawn_depth += 1
        try:
            sub = AegisxAgent(
                self.config,
                context=self.context,
                provider=primary,
                dispatcher=self,
                allowed_tools=SPECIALTY_TOOLS[specialty],
                system_prompt=SPECIALTY_PROMPTS[specialty],
                max_iterations=budget,
            )
            sub.session_store = None  # only the orchestrator checkpoints
            if focus:
                sub.messages[-1]["content"] += f"\n\nSPECIALTY FOCUS: {focus}"
            sub_result = await sub.run()
        finally:
            self.spawn_depth -= 1

        self.last_tool_usage["prompt_tokens"] = (
            self.last_tool_usage.get("prompt_tokens", 0) + sub_result.prompt_tokens
        )
        self.last_tool_usage["completion_tokens"] = (
            self.last_tool_usage.get("completion_tokens", 0) + sub_result.completion_tokens
        )
        return json.dumps(
            {
                "specialty": specialty,
                "stopped_reason": sub_result.stopped_reason,
                "iterations": sub_result.iterations_used,
                "tool_calls": sub_result.tool_calls_made,
                "total_findings_in_scan": len(self.context.findings),
                "agent_summary": (sub_result.final_message or "(no summary)")[:1_500],
            },
            ensure_ascii=False,
        )

    # --- dispatch ----------------------------------------------------------

    async def execute(
        self,
        name: str,
        args: dict[str, Any],
        allowed_tools: set[str] | list[str] | None = None,
    ) -> str:
        """Dispatch one tool call by name. Errors become JSON strings.

        ``allowed_tools`` narrows the callable set for restricted callers
        (specialist sub-agents); ``None`` means unrestricted (orchestrator).

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
            "store_note": self._tool_store_note,
            "fuzz_param": self._tool_fuzz_param,
            "diff_responses": self._tool_diff_responses,
            "enum_paths": self._tool_enum_paths,
            "lookup_cwe": self._tool_lookup_cwe,
            "spawn_agent": self._tool_spawn_agent,
        }
        handler = handlers.get(name)
        if handler is None:
            return json.dumps({"error": f"Unknown tool: {name}"})
        if allowed_tools is not None and name not in allowed_tools:
            return json.dumps(
                {"error": f"Tool {name!r} is not available to this agent", "blocked": True}
            )

        key = f"{name}:{json.dumps(args, sort_keys=True, ensure_ascii=False)}"
        self._call_counts[key] = self._call_counts.get(key, 0) + 1
        count = self._call_counts[key]
        self.last_call_was_duplicate = count > 1

        if count == 2 and key in self._results:
            return (
                self._results[key] + "\n\n[NOTE: identical repeat call — result unchanged. "
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
