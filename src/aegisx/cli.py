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
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from aegisx import __version__
from aegisx.core.config import AegisxConfig, ReportFormat, ScanMode
from aegisx.core.orchestrator import AegisxOrchestrator
from aegisx.plugins import get_plugin_manager
from aegisx.utils.logger import setup_logging

app = typer.Typer(
    name="aegisx",
    help="🛡️ Aegisx-Agent — Autonomous Security Scanner",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(help="Target URL to scan (e.g. https://example.com)"),
    mode: ScanMode = typer.Option(
        ScanMode.QUICK,
        "--mode", "-m",
        help="Scan mode: passive, quick, full, stealth",
    ),
    report: ReportFormat = typer.Option(
        ReportFormat.MARKDOWN,
        "--report", "-r",
        help="Report format: markdown, json, sarif, html, all",
    ),
    output: Path = typer.Option(
        Path("reports/"),
        "--output", "-o",
        help="Report output directory",
    ),
    scope: Optional[str] = typer.Option(
        None,
        "--scope", "-s",
        help="Comma-separated domain whitelist (default: target domain only)",
    ),
    max_depth: int = typer.Option(3, "--depth", "-d", help="Max crawl depth (1-10)"),
    rps: float = typer.Option(10.0, "--rps", help="Max requests per second"),
    exploit: bool = typer.Option(
        False,
        "--exploit", "-e",
        help="Enable exploit verification (requires consent)",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    auth_token: Optional[str] = typer.Option(None, "--auth", help="Auth token for target"),
    user_agent: str = typer.Option(
        "AegisxAgent/0.1.0 (Security Scanner)",
        "--user-agent", "-ua",
        help="Custom User-Agent string",
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

    config = AegisxConfig(**config_kwargs)

    # Print banner
    _print_banner()

    # Run orchestrator
    orchestrator = AegisxOrchestrator(config)
    stats = asyncio.run(orchestrator.run())

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
    """Full penetration test with exploit verification.

    This runs a comprehensive scan with ALL scanners enabled and
    exploit verification turned on. Use only on authorized targets.
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


@app.command("plugins")
def list_plugins() -> None:
    """List all available scanner, exploit, and reporter plugins."""
    pm = get_plugin_manager()
    pm.load_entry_points()

    # Register built-in scanners
    from aegisx.scanners.web_scanner import WebScanner
    from aegisx.scanners.secret_scanner import SecretScanner
    from aegisx.scanners.config_scanner import ConfigScanner
    from aegisx.scanners.dependency_scanner import DependencyScanner

    pm.register_scanner(WebScanner.name, WebScanner)
    pm.register_scanner(SecretScanner.name, SecretScanner)
    pm.register_scanner(ConfigScanner.name, ConfigScanner)
    pm.register_scanner(DependencyScanner.name, DependencyScanner)

    # Register built-in reporters
    from aegisx.reporters.markdown_reporter import MarkdownReporter
    from aegisx.reporters.json_reporter import JSONReporter
    from aegisx.reporters.sarif_reporter import SARIFReporter
    from aegisx.reporters.html_reporter import HTMLReporter

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
    from aegisx.core.config import AegisxConfig

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
        "[dim]  v0.1.0 — Autonomous Security Scanner[/]\n"
    )
    console.print(banner)


if __name__ == "__main__":
    app()
