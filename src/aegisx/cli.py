"""Aegisx-Agent CLI — Command-line interface for the security scanner.

Usage:
    aegisx scan https://example.com
    aegisx scan https://example.com --mode full --report html
    aegisx pentest https://example.com --exploit
    aegisx plugins list
    aegisx info
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aegisx import __version__
from aegisx.core.config import AegisxConfig, ReportFormat, ScanMode
from aegisx.core.orchestrator import AegisxOrchestrator
from aegisx.plugins import get_plugin_manager
from aegisx.utils.notify import load_notify_config

app = typer.Typer(
    name="aegisx",
    help=(
        "🛡️ [bold]Aegisx-Agent[/] — Autonomous AI-Powered Security Scanner\n\n"
        "Three-phase pipeline: recon → scan → verify → report.\n"
        "Optional AI agent mode: bring your own OpenAI-compatible LLM.\n\n"
        "[dim]Common tasks:[/]\n"
        "  Quick scan:            [cyan]aegisx scan https://example.com[/]\n"
        "  Everything:            [cyan]aegisx pentest https://example.com[/]\n"
        "  AI pentest:            [cyan]aegisx agent https://example.com[/]\n"
        "  Setup AI (first time): [cyan]aegisx ai-config[/]\n"
        "  Past scans:            [cyan]aegisx history[/]\n\n"
        "[dim]Run 'aegisx COMMAND --help' for detailed options.[/]"
    ),
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(help="Target URL to scan (e.g. https://example.com)"),
    mode: ScanMode = typer.Option(
        ScanMode.QUICK,
        "--mode",
        "-m",
        help="Scan mode: passive, quick, full, stealth",
    ),
    report: ReportFormat = typer.Option(
        ReportFormat.MARKDOWN,
        "--report",
        "-r",
        help="Report format: markdown, json, sarif, html, all",
    ),
    output: Path = typer.Option(
        Path("reports/"),
        "--output",
        "-o",
        help="Report output directory",
    ),
    scope: str | None = typer.Option(
        None,
        "--scope",
        "-s",
        help="Comma-separated domain whitelist (default: target domain only)",
    ),
    max_depth: int = typer.Option(3, "--depth", "-d", help="Max crawl depth (1-10)"),
    rps: float = typer.Option(10.0, "--rps", help="Max requests per second"),
    exploit: bool = typer.Option(
        False,
        "--exploit",
        "-e",
        help="Enable exploit verification (requires consent)",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    auth_token: str | None = typer.Option(None, "--auth", help="Auth token for target"),
    user_agent: str = typer.Option(
        f"AegisxAgent/{__version__} (Security Scanner)",
        "--user-agent",
        "-ua",
        help="Custom User-Agent string",
    ),
    proxy: str | None = typer.Option(
        None,
        "--proxy",
        "-p",
        help="Proxy URL for requests (e.g. http://127.0.0.1:8080 for Burp/ZAP)",
    ),
    siem: Path | None = typer.Option(
        None,
        "--siem",
        help="Export SIEM events (JSON-lines) to this file after the scan",
    ),
    notify: str | None = typer.Option(
        None,
        "--notify",
        help="Webhook URL (Slack/Discord) to push the findings summary to",
    ),
) -> None:
    """Scan a target for vulnerabilities."""
    # Validate target URL
    if not target.startswith(("http://", "https://")):
        console.print("[red]ERROR[/] Target must start with http:// or https://")
        raise typer.Exit(code=1)

    # Build config
    config_kwargs = {
        "target_url": target,
        "scan_mode": mode,
        "report_format": report,
        "report_output": output,
        "max_depth": max_depth,
        "max_requests_per_second": rps,
        "exploit_verification": exploit,
        "verbose": verbose,
        "user_agent": user_agent,
    }

    if scope:
        config_kwargs["scope"] = [s.strip() for s in scope.split(",")]
    if auth_token:
        config_kwargs["auth_token"] = auth_token
    if proxy:
        config_kwargs["proxy"] = proxy

    config = AegisxConfig(**config_kwargs)

    # Print banner
    _print_banner()

    # Run orchestrator
    orchestrator = AegisxOrchestrator(config)
    stats = asyncio.run(orchestrator.run())

    # Optional SIEM export (one event per finding, JSON-lines)
    if siem:
        from aegisx.utils.siem_export import export_siem

        out = export_siem(orchestrator.context, siem, fmt="jsonl")
        console.print(f"[green]✓[/] SIEM events exported to [cyan]{out}[/]")

    # Optional webhook notification (best-effort, never fails the scan)
    webhook = notify or load_notify_config()
    if webhook:
        from aegisx.utils.notify import send_notification

        result = asyncio.run(
            send_notification(
                webhook,
                list(orchestrator.context.findings),
                target,
                orchestrator.context.scan_id,
                report_path=str(output) if output else "",
            )
        )
        if result.ok:
            console.print("[green]✓[/] Notification sent to webhook")
        else:
            console.print("[yellow]⚠[/] Notification delivery failed (scan unaffected)")

    # Exit with code based on findings
    if stats.critical_count > 0:
        raise typer.Exit(code=2)
    if stats.high_count > 0:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command()
def pentest(
    target: str = typer.Argument(help="Target URL to pentest"),
    report: ReportFormat = typer.Option(ReportFormat.ALL, "--report", "-r"),
    output: Path = typer.Option(Path("reports/"), "--output", "-o"),
    verbose: bool = typer.Option(True, "--verbose", "-v"),
) -> None:
    """Full penetration test: all scanners + exploit verification + all reports.

    Runs every scanner (web, secret, config, dependency), then attempts
    to verify each finding with the exploit modules (SQLi, XSS, CSRF,
    SSRF), and finally generates all four report formats.

    Exploit verification is always ON here — you will be asked to
    confirm authorization before anything runs. Equivalent to:
    [cyan]aegisx scan <target> --mode full --exploit --report all[/]
    """
    if not target.startswith(("http://", "https://")):
        console.print("[red]ERROR[/] Target must start with http:// or https://")
        raise typer.Exit(code=1)

    # Confirm authorization
    console.print(
        Panel(
            "[bold red]⚠️  AUTHORIZATION REQUIRED[/]\n\n"
            "Full penetration testing requires explicit authorization.\n"
            "You confirm you have permission to test this target.",
            title="Legal Notice",
            border_style="red",
        )
    )

    confirm = typer.confirm("Do you have authorization to test this target?")
    if not confirm:
        console.print("[red]Aborted.[/] Authorization required.")
        raise typer.Exit(code=0)

    config = AegisxConfig(
        target_url=target,
        scan_mode=ScanMode.FULL,
        report_format=report,
        report_output=output,
        exploit_verification=True,
        verbose=verbose,
        enabled_scanners=[
            "web_scanner",
            "secret_scanner",
            "config_scanner",
            "dependency_scanner",
        ],
    )

    _print_banner()

    orchestrator = AegisxOrchestrator(config)
    stats = asyncio.run(orchestrator.run())

    if stats.critical_count > 0:
        raise typer.Exit(code=2)
    if stats.high_count > 0:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


def _print_delta(piece: str) -> None:
    """Print one streaming content delta to the terminal as it arrives."""
    console.out(piece, end="", markup=False, highlight=False, soft_wrap=True)


@app.command()
def agent(
    target: str = typer.Argument(None, help="Target URL for the AI to assess"),
    ai_provider: str = typer.Option(
        "custom",
        "--ai-provider",
        help="AI preset: custom, deepseek, openai, groq, openrouter, ollama",
    ),
    ai_base_url: str | None = typer.Option(
        None, "--ai-base-url", help="OpenAI-compatible base URL"
    ),
    ai_api_key: str | None = typer.Option(
        None, "--ai-api-key", help="AI API key (or set AEGISX_AI_API_KEY)"
    ),
    ai_model: str | None = typer.Option(None, "--ai-model", help="Model name"),
    max_iterations: int = typer.Option(25, "--max-iterations", help="Agent loop budget"),
    exploit: bool = typer.Option(
        False, "--exploit", "-e", help="Authorize exploit verification tools"
    ),
    output: Path = typer.Option(Path("reports/"), "--output", "-o"),
    continue_id: str | None = typer.Option(
        None,
        "--continue",
        "-c",
        help="Resume an interrupted agent run by scan ID ('list' shows sessions)",
    ),
    stream: bool = typer.Option(
        False,
        "--stream",
        "-s",
        help="Stream the model's output as it is generated (falls back automatically)",
    ),
    vote: str | None = typer.Option(
        None,
        "--vote",
        help=(
            "Comma-separated peer models that cross-review the final "
            "assessment (multi-model voting). Example: --vote gpt-4o-mini,llama3.1"
        ),
    ),
) -> None:
    """Autonomous AI-driven pentest — the LLM plans and runs the assessment.

    Requires an AI endpoint: set AEGISX_AI_BASE_URL / AEGISX_AI_API_KEY /
    AEGISX_AI_MODEL (or use --ai-* flags / --ai-provider presets).
    Verify setup first with: [cyan]aegisx ai-config[/]

    The AI follows a pentest methodology (recon → scan → review →
    verify → report) using tools that are scope-enforced by the harness.
    Add [cyan]--exploit[/] to also authorize exploit-verification tools.

    Interrupted a run? Resume it with [cyan]aegisx agent --continue <scan-id>[/]
    — list saved sessions with [cyan]aegisx agent --list-sessions[/].
    """
    from aegisx.ai.sessions import SessionStore

    store = SessionStore()

    # --list-sessions mode: show saved runs and exit
    if continue_id == "list":
        rows = store.list_sessions(limit=10)
        if not rows:
            console.print("[dim]No saved agent sessions.[/]")
            return
        table = Table(title="📋 Saved Agent Sessions")
        table.add_column("Scan ID", style="cyan")
        table.add_column("Target")
        table.add_column("Status")
        table.add_column("Iters", justify="right")
        table.add_column("Tool Calls", justify="right")
        table.add_column("Updated")
        for r in rows:
            status_style = {
                "running": "[yellow]running[/]",
                "done": "[green]done[/]",
                "budget": "[red]budget[/]",
                "error": "[red]error[/]",
            }.get(r["status"], r["status"])
            table.add_row(
                r["scan_id"],
                r["target_url"][:40],
                status_style,
                str(r["iterations"]),
                str(r["tool_calls"]),
                r["updated_at"][:19],
            )
        console.print(table)
        return

    # Resume mode: load the session, ignore the target argument
    resuming = bool(continue_id)
    if resuming:
        state = store.load(continue_id)
        if state is None:
            console.print(f"[red]ERROR[/] No such session: {continue_id}")
            console.print("[dim]List sessions with: aegisx agent --continue list[/]")
            raise typer.Exit(code=1)
        target = state.target_url
    elif not target or not target.startswith(("http://", "https://")):
        console.print("[red]ERROR[/] Target must start with http:// or https://")
        console.print("[dim]Resume a run instead: aegisx agent --continue <scan-id>")
        console.print("[dim]List saved runs:       aegisx agent --continue list[/]")
        raise typer.Exit(code=1)

    config = AegisxConfig(
        target_url=target,
        scan_mode=ScanMode.QUICK,
        report_output=output,
        exploit_verification=exploit,
        ai_provider=ai_provider,
        ai_max_iterations=max_iterations,
    )
    if ai_base_url:
        config.ai_base_url = ai_base_url
    if ai_api_key:
        config.ai_api_key = ai_api_key
    if ai_model:
        config.ai_model = ai_model
    if vote:
        config.ai_vote_models = [m.strip() for m in vote.split(",") if m.strip()]

    _print_banner()

    from aegisx.ai import AegisxAgent

    try:
        bot = AegisxAgent(config)
    except ValueError as exc:
        console.print(f"[red]AI config error:[/] {exc}")
        console.print(
            "[dim]Set AEGISX_AI_BASE_URL / AEGISX_AI_API_KEY / AEGISX_AI_MODEL "
            "or use --ai-provider deepseek (etc.)[/]"
        )
        raise typer.Exit(code=1)

    if stream:
        bot.on_delta = _print_delta

    console.print(
        Panel(
            f"[bold]AegisX Brain[/] — autonomous assessment\n"
            f"Endpoint: [cyan]{bot.provider.base_url}[/]\n"
            f"Model: [cyan]{bot.provider.model}[/]\n"
            f"Max iterations: {config.ai_max_iterations}\n"
            f"Exploit tools: {'[red]AUTHORIZED[/]' if exploit else '[dim]disabled[/]'}\n"
            f"Streaming: {'[green]on[/]' if stream else '[dim]off[/]'}\n"
            f"Peer voting: "
            f"{', '.join(config.ai_vote_models) if config.ai_vote_models else '[dim]off[/]'}",
            title="🧠 AI Agent" + (" — resuming" if resuming else ""),
            border_style="magenta",
        )
    )

    try:
        result = asyncio.run(bot.resume(continue_id)) if resuming else asyncio.run(bot.run())
    except ValueError as exc:
        console.print(f"[red]ERROR[/] {exc}")
        raise typer.Exit(code=1) from None
    except KeyboardInterrupt:
        console.print(
            f"\n[yellow]Interrupted.[/] Resume with: "
            f"[cyan]aegisx agent --continue {bot.context.scan_id}[/]"
        )
        raise typer.Exit(code=130) from None

    if result.stopped_reason == "error":
        console.print(f"[bold red]Agent failed:[/] {result.error}")
        raise typer.Exit(code=1)

    console.print(
        f"\n[dim]Iterations: {result.iterations_used}, "
        f"tool calls: {result.tool_calls_made}, "
        f"stopped: {result.stopped_reason}[/]\n"
    )
    console.print(Panel(result.final_message or "(no summary)", title="📋 AI Assessment"))


@app.command()
def ask(
    question: str = typer.Argument(help="Question about the most recent scan"),
    ai_provider: str = typer.Option("custom", "--ai-provider", help="AI preset"),
    ai_base_url: str | None = typer.Option(None, "--ai-base-url"),
    ai_api_key: str | None = typer.Option(None, "--ai-api-key"),
    ai_model: str | None = typer.Option(None, "--ai-model"),
) -> None:
    """Ask the AI about the most recent scan history entry.

    Example: [cyan]aegisx ask \"which finding should I fix first?\"[/]
    Requires an AI endpoint — see [cyan]aegisx ai-config[/].
    """
    from aegisx.utils.history import ScanHistory

    db = ScanHistory()
    scans = db.get_scans(limit=1)
    if not scans:
        console.print("[yellow]No scan history found.[/] Run `aegisx scan <target>` first.")
        raise typer.Exit(code=1)

    latest = db.get_scan(scans[0]["scan_id"])
    scan_summary = json.dumps(
        {
            "target": latest.get("target"),
            "mode": latest.get("mode"),
            "timestamp": latest.get("timestamp"),
            "findings": latest.get("findings", [])[:20],
        },
        ensure_ascii=False,
        default=str,
    )

    config = AegisxConfig(
        target_url=latest.get("target", ""),
        ai_provider=ai_provider,
    )
    if ai_base_url:
        config.ai_base_url = ai_base_url
    if ai_api_key:
        config.ai_api_key = ai_api_key
    if ai_model:
        config.ai_model = ai_model

    from aegisx.ai.provider import AIProvider, AIProviderError

    try:
        provider = AIProvider(config)
    except ValueError as exc:
        console.print(f"[red]AI config error:[/] {exc}")
        raise typer.Exit(code=1)

    console.print(f"[dim]Asking {provider.model} about {latest.get('target')}…[/]")
    try:
        chat = asyncio.run(
            provider.chat(
                [
                    {
                        "role": "system",
                        "content": (
                            "You are a senior security analyst. Answer questions "
                            "about the scan result provided. Be precise and cite "
                            "finding IDs. JSON scan data follows."
                        ),
                    },
                    {
                        "role": "user",
                        "content": f"Scan data:\n{scan_summary}\n\nQuestion: {question}",
                    },
                ]
            )
        )
    except AIProviderError as exc:
        console.print(f"[bold red]AI error:[/] {exc}")
        raise typer.Exit(code=1)

    console.print(Panel(chat.content or "(no answer)", title="🧠 Answer"))


@app.command("ai-config")
def ai_config(
    base_url: str | None = typer.Option(None, "--base-url", help="Base URL to test"),
    api_key: str | None = typer.Option(None, "--api-key", help="API key to test"),
    model: str | None = typer.Option(None, "--model", help="Model to test"),
    provider: str = typer.Option("custom", "--provider", help="Preset to test"),
) -> None:
    """Test AI endpoint connectivity and show the config that will be used."""
    from aegisx.ai.provider import AIProvider

    config = AegisxConfig(
        target_url="https://config-check.invalid",
        ai_provider=provider,
    )
    # Apply flags only when given, so .env values are not overridden
    if base_url:
        config.ai_base_url = base_url
    if api_key:
        config.ai_api_key = api_key
    if model:
        config.ai_model = model
    try:
        bot = AIProvider(config)
    except ValueError as exc:
        console.print(f"[red]Config error:[/] {exc}")
        raise typer.Exit(code=1)

    table = Table(title="🧠 AI Provider Configuration", border_style="magenta")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    table.add_row("Provider", config.ai_provider)
    table.add_row("Base URL", bot.base_url)
    table.add_row("Model", bot.model)
    table.add_row("API Key", (bot.api_key[:4] + "…") if bot.api_key else "(none — local endpoint?)")
    console.print(table)

    console.print("[dim]Testing connectivity…[/]")
    ok, detail = asyncio.run(bot.health_check())
    if ok:
        console.print(f"[green]✓ AI endpoint reachable[/] — {detail}")
    else:
        console.print(f"[red]✗ AI endpoint failed[/] — {detail}")
        raise typer.Exit(code=1)


@app.command()
def recon(
    target: str = typer.Argument(help="Target URL for reconnaissance"),
    verbose: bool = typer.Option(True, "--verbose", "-v"),
) -> None:
    """Passive reconnaissance — gather target information without active scanning."""
    if not target.startswith(("http://", "https://")):
        console.print("[red]ERROR[/] Target must start with http:// or https://")
        raise typer.Exit(code=1)

    config = AegisxConfig(
        target_url=target,
        scan_mode=ScanMode.PASSIVE,
        verbose=verbose,
        enabled_scanners=[],
    )

    _print_banner()

    orchestrator = AegisxOrchestrator(config)
    asyncio.run(orchestrator.run())


@app.command("history")
def history(
    target: str = typer.Option(None, "--target", "-t", help="Filter by target URL"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max entries to show"),
    export_json: Path = typer.Option(None, "--export", help="Export full history to a JSON file"),
) -> None:
    """Show scan history recorded by previous runs."""
    from rich.table import Table as RichTable

    from aegisx.utils.history import ScanHistory

    db = ScanHistory()

    if export_json:
        out = db.export_json(export_json)
        console.print(f"[green]✓[/] History exported to [cyan]{out}[/]")
        return

    scans = db.get_scans(target=target, limit=limit)
    if not scans:
        console.print("[yellow]No scan history found.[/] Run `aegisx scan <target>` first.")
        return

    summary = db.stats_summary()
    console.print(
        f"[bold]History:[/] {summary['total_scans']} scans, "
        f"{summary['unique_targets']} targets, "
        f"{summary['total_critical']} critical findings total\n"
    )

    table = RichTable(title="📜 Scan History", border_style="blue")
    table.add_column("Scan ID", style="cyan")
    table.add_column("Timestamp")
    table.add_column("Target")
    table.add_column("Mode")
    table.add_column("🔴", justify="right")
    table.add_column("🟠", justify="right")
    table.add_column("🟡", justify="right")
    table.add_column("Total", justify="right")

    for s in scans:
        table.add_row(
            s["scan_id"],
            s["timestamp"][:19].replace("T", " "),
            s["target"][:40],
            s["mode"],
            str(s["critical"]),
            str(s["high"]),
            str(s["medium"]),
            str(s["findings"]),
        )
    console.print(table)


@app.command()
def monitor(
    target: str = typer.Argument(help="Target URL to watch (e.g. https://example.com)"),
    every: int = typer.Option(
        3600,
        "--every",
        "-e",
        help="Seconds between scan cycles (default: 1 hour)",
    ),
    notify: str | None = typer.Option(
        None,
        "--notify",
        help="Webhook URL (Slack/Discord) for new-finding alerts",
    ),
    max_cycles: int = typer.Option(
        0, "--cycles", "-c", help="Stop after N cycles (0 = run forever)"
    ),
    mode: ScanMode = typer.Option(ScanMode.QUICK, "--mode", "-m", help="Scan mode"),
    scope: str | None = typer.Option(
        None, "--scope", "-s", help="Comma-separated domain whitelist"
    ),
) -> None:
    """Continuous monitoring — re-scan on an interval, alert only on NEW findings."""
    if not target.startswith(("http://", "https://")):
        console.print("[red]ERROR[/] Target must start with http:// or https://")
        raise typer.Exit(code=1)

    from aegisx.monitoring import Monitor

    webhook = notify or load_notify_config()
    config_kwargs: dict = {
        "target_url": target,
        "scan_mode": mode,
    }
    if scope:
        config_kwargs["scope"] = [s.strip() for s in scope.split(",")]

    monitor_obj = Monitor(
        AegisxConfig(**config_kwargs),
        interval_seconds=every,
        webhook_url=webhook,
        max_cycles=max_cycles or None,
    )

    console.print(
        Panel(
            f"[bold]Continuous Monitoring[/]\n\n"
            f"Target:    [cyan]{target}[/]\n"
            f"Interval:  every {every}s\n"
            f"Webhook:   {'configured' if webhook else '[dim]none[/]'}\n"
            f"Cycles:    {max_cycles if max_cycles else '[dim]forever (Ctrl-C to stop)[/]'}",
            title="📡 Monitor",
            border_style="blue",
        )
    )

    try:
        cycles = asyncio.run(monitor_obj.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped by user.[/]")
        raise typer.Exit(code=0)

    # Final summary
    table = Table(title="📡 Monitoring Summary", border_style="blue")
    table.add_column("Cycle", justify="right")
    table.add_column("Scan ID", style="cyan")
    table.add_column("Findings", justify="right")
    table.add_column("New", justify="right")
    table.add_column("Resolved", justify="right")
    table.add_column("Duration", justify="right")
    table.add_column("Status")
    for c in cycles:
        table.add_row(
            str(c.cycle),
            c.scan_id or "—",
            str(c.total_findings),
            str(len(c.new_findings)),
            str(c.resolved_count),
            f"{c.duration_seconds:.1f}s",
            "[red]error[/]" if c.error else "[green]ok[/]",
        )
    console.print(table)


@app.command()
def dashboard(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help=(
            "Bind address. Keep 127.0.0.1 — scan history is sensitive; "
            "only override when you mean to expose it"
        ),
    ),
    port: int = typer.Option(8720, "--port", "-p", help="TCP port (auto-bumps if taken)"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open the browser"),
) -> None:
    """Open the local dashboard: scan history, severity trends, per-scan findings.

    Read-only, binds to 127.0.0.1 by default, zero new dependencies.
    """
    from aegisx.dashboard import serve
    from aegisx.utils.history import ScanHistory

    if host != "127.0.0.1":
        console.print(
            f"[bold yellow]WARNING[/] Binding the dashboard to {host} exposes "
            "your scan history to the network."
        )

    try:  # noqa: SIM105 — explicit Ctrl-C handling, not suppression
        serve(host=host, port=port, history=ScanHistory(), open_browser=not no_browser)
    except KeyboardInterrupt:
        pass


@app.command("plugins")
def list_plugins() -> None:
    """List all available scanner, exploit, and reporter plugins."""
    pm = get_plugin_manager()
    pm.load_entry_points()
    # Register built-in scanners
    from aegisx.scanners.config_scanner import ConfigScanner
    from aegisx.scanners.dependency_scanner import DependencyScanner
    from aegisx.scanners.secret_scanner import SecretScanner
    from aegisx.scanners.ssti_scanner import SSTIScanner
    from aegisx.scanners.web_scanner import WebScanner

    pm.register_scanner(WebScanner.name, WebScanner)
    pm.register_scanner(SecretScanner.name, SecretScanner)
    pm.register_scanner(ConfigScanner.name, ConfigScanner)
    pm.register_scanner(DependencyScanner.name, DependencyScanner)
    pm.register_scanner(SSTIScanner.name, SSTIScanner)

    # Register built-in reporters
    from aegisx.reporters.html_reporter import HTMLReporter
    from aegisx.reporters.json_reporter import JSONReporter
    from aegisx.reporters.markdown_reporter import MarkdownReporter
    from aegisx.reporters.sarif_reporter import SARIFReporter

    for cls in [MarkdownReporter, JSONReporter, SARIFReporter, HTMLReporter]:
        pm.register_reporter(cls.format_name, cls)

    table = Table(title="📦 Aegisx-Agent Plugins")
    table.add_column("Type", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Description")

    # Scanners
    for name in pm.list_scanners():
        table.add_row("Scanner", name, "")

    # Exploits
    for name in pm.list_exploits():
        table.add_row("Exploit", name, "")

    # Reporters
    for name in pm.list_reporters():
        table.add_row("Reporter", name, "")

    if not (pm.list_scanners() or pm.list_exploits() or pm.list_reporters()):
        table.add_row("—", "No plugins loaded", "Install plugins or check configuration")

    console.print(table)


@app.command()
def info() -> None:
    """Show Aegisx-Agent version and system information."""

    panel_content = Text()
    panel_content.append(f"Aegisx-Agent v{__version__}\n", style="bold green")
    panel_content.append("Autonomous AI-powered Security Scanner\n\n", style="dim")
    panel_content.append("Components:\n", style="bold")
    panel_content.append("  • Core Engine: ", style="cyan")
    panel_content.append("✓ Loaded\n")
    panel_content.append("  • Plugin System: ", style="cyan")
    panel_content.append("✓ pluggy-based\n")
    panel_content.append("  • CVSS Scorer: ", style="cyan")
    panel_content.append("✓ v3.1\n")
    panel_content.append("  • OWASP KB: ", style="cyan")
    panel_content.append("✓ Top 10 2021\n")
    panel_content.append("  • Report Formats: ", style="cyan")
    panel_content.append("Markdown, JSON, SARIF\n")

    console.print(Panel(panel_content, title="🛡️ Aegisx-Agent", border_style="green"))


def _print_banner() -> None:
    """Print the Aegisx-Agent banner."""
    banner = (
        "[bold green]"
        "    _          _ _ _   _   _____                     _             \n"
        "   / \\   _ __ (_) | |_(_)_|__  /___ _ __ ___  _ __ (_)_ __   __ _ \n"
        "  / _ \\ | '__| | | __| | |/ / / _ \\ '__/ _ \\| '_ \\| | '_ \\ / _` |\n"
        " / ___ \\| |   | | |_| |   < /  __/ | | (_) | | | | | | | | | (_| |\n"
        "/_/   \\_\\_|   |_|\\__|_|_|\\_\\\\___|_|  \\___/|_| |_|_|_| |_|\\__, |\n"
        "                                                           |___/ "
        "[/]\n"
        f"[dim]  v{__version__} — Autonomous Security Scanner[/]\n"
    )
    console.print(banner)


if __name__ == "__main__":
    app()
