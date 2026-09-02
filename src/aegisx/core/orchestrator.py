"""Main orchestrator — the brain of Aegisx-Agent.

Coordinates the three-phase pipeline:
    Phase 1: Reconnaissance (target discovery, tech fingerprinting)
    Phase 2: Scanning & Exploitation (vulnerability detection + verification)
    Phase 3: Reporting & Remediation (generate reports, suggest fixes)

The orchestrator discovers and runs registered scanner/exploit/reporter plugins.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from aegisx.core.config import AegisxConfig, ReportFormat, ScanMode
from aegisx.core.context import ScanContext, ScanStats
from aegisx.plugins import get_plugin_manager, PluginManager
from aegisx.utils.logger import get_logger, setup_logging

if TYPE_CHECKING:
    from aegisx.scanners.base_scanner import BaseScanner
    from aegisx.exploits.base_exploit import BaseExploit

logger = get_logger("orchestrator")


class AegisxOrchestrator:
    """Coordinates the full scan pipeline.

    Usage:
        config = AegisxConfig(target_url="https://example.com", scan_mode="full")
        orchestrator = AegisxOrchestrator(config)
        stats = await orchestrator.run()
    """

    def __init__(self, config: AegisxConfig) -> None:
        self.config = config
        self.context = ScanContext(config=config, target_url=config.target_url)
        self.plugin_manager = get_plugin_manager()

        # Auto-register built-in scanners
        self._register_builtins()

        # Setup logging
        setup_logging(level=config.log_level, verbose=config.verbose)

    async def run(self) -> ScanStats:
        """Execute the full scan pipeline.

        Returns:
            ScanStats with findings summary.
        """
        logger.info(
            "[bold green]AEGISX[/] Starting scan of [cyan]%s[/] in [magenta]%s[/] mode",
            self.config.target_url,
            self.config.scan_mode.value,
        )

        # Load plugins
        self._load_plugins()

        # Phase 1: Reconnaissance (only in quick/full/stealth modes)
        if self.config.scan_mode in (ScanMode.QUICK, ScanMode.FULL, ScanMode.STEALTH):
            await self._phase_recon()

        # Phase 2: Scanning & Exploitation
        await self._phase_scan()

        # Exploit verification (only in full mode with explicit consent)
        if self.config.scan_mode == ScanMode.FULL and self.config.exploit_verification:
            await self._phase_exploit()

        # Phase 3: Reporting
        stats = await self._phase_report()

        return stats

    def _register_builtins(self) -> None:
        """Register built-in scanner, exploit, and reporter plugins."""
        from aegisx.scanners.web_scanner import WebScanner
        from aegisx.scanners.secret_scanner import SecretScanner
        from aegisx.scanners.config_scanner import ConfigScanner
        from aegisx.scanners.dependency_scanner import DependencyScanner
        from aegisx.reporters.markdown_reporter import MarkdownReporter
        from aegisx.reporters.json_reporter import JSONReporter
        from aegisx.reporters.sarif_reporter import SARIFReporter

        for cls in [WebScanner, SecretScanner, ConfigScanner, DependencyScanner]:
            self.plugin_manager.register_scanner(cls.name, cls)
        for cls in [MarkdownReporter, JSONReporter, SARIFReporter]:
            self.plugin_manager.register_reporter(cls.format_name, cls)

    def _load_plugins(self) -> None:
        """Discover and load all registered plugins."""
        self.plugin_manager.load_entry_points()

        for plugin_dir in self.config.plugin_dirs:
            self.plugin_manager.load_from_directory(plugin_dir)

        loaded = self.plugin_manager.summary()
        logger.info(
            "[blue]PLUGINS[/] Loaded %d scanner(s), %d exploit(s), %d reporter(s)",
            len(loaded["scanners"]),
            len(loaded["exploits"]),
            len(loaded["reporters"]),
        )

    async def _phase_recon(self) -> None:
        """Phase 1: Reconnaissance — discover target info and attack surface."""
        logger.info("[bold blue]PHASE 1[/] Reconnaissance")

        # Basic target validation
        if not self.config.target_url:
            logger.error("[red]ERROR[/] No target URL configured")
            return

        # Basic tech fingerprinting via HTTP headers
        try:
            import httpx

            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                verify=False,  # noqa: S501
            ) as client:
                headers = self.config.get_auth_headers()
                headers["User-Agent"] = self.config.user_agent

                response = await client.get(
                    self.config.target_url,
                    headers=headers,
                )

                self.context.target_info = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "server": response.headers.get("server", "unknown"),
                    "content_type": response.headers.get("content-type", ""),
                    "technologies": self._detect_technologies(response),
                    "security_headers": self._check_security_headers(response),
                }

                logger.info(
                    "[green]RECON[/] Target responded with HTTP %d (Server: %s)",
                    response.status_code,
                    self.context.target_info["server"],
                )

        except Exception as e:
            logger.error("[red]RECON[/] Failed to reach target: %s", e)

    async def _phase_scan(self) -> None:
        """Phase 2: Run all enabled scanner modules."""
        logger.info("[bold blue]PHASE 2[/] Scanning")

        enabled = self.config.enabled_scanners
        scan_tasks: list[asyncio.Task[list]] = []

        for scanner_name in enabled:
            scanner_cls = self.plugin_manager.get_scanner(scanner_name)
            if scanner_cls is None:
                logger.warning("[yellow]SKIP[/] Scanner not found: %s", scanner_name)
                continue

            scanner: BaseScanner = scanner_cls(context=self.context)
            task = asyncio.create_task(scanner.run(), name=f"scanner-{scanner_name}")
            scan_tasks.append(task)

        if scan_tasks:
            results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            total_findings = sum(
                len(r) for r in results if isinstance(r, list)
            )
            logger.info(
                "[bold green]SCAN[/] Phase 2 complete: [bold]%d[/] total findings",
                total_findings,
            )
        else:
            logger.warning("[yellow]SCAN[/] No scanners enabled or available")

    async def _phase_exploit(self) -> None:
        """Phase 2.5: Verify findings with exploit modules."""
        logger.info("[bold blue]EXPLOIT[/] Verifying findings with exploit modules")

        exploit_count = 0
        verified_count = 0

        for finding in self.context.findings:
            for exploit_name in self.plugin_manager.list_exploits():
                exploit_cls = self.plugin_manager.get_exploit(exploit_name)
                if exploit_cls is None:
                    continue

                exploit: BaseExploit = exploit_cls(context=self.context)
                result = await exploit.run(finding)
                exploit_count += 1

                if result and result.success:
                    verified_count += 1

        logger.info(
            "[bold magenta]EXPLOIT[/] %d/%d exploit attempts succeeded",
            verified_count,
            exploit_count,
        )

    async def _phase_report(self) -> ScanStats:
        """Phase 3: Generate reports in configured formats."""
        logger.info("[bold blue]PHASE 3[/] Report Generation")

        stats = self.context.finish()

        from aegisx.reporters.markdown_reporter import MarkdownReporter
        from aegisx.reporters.json_reporter import JSONReporter
        from aegisx.reporters.sarif_reporter import SARIFReporter

        reporter_map = {
            ReportFormat.MARKDOWN: MarkdownReporter,
            ReportFormat.JSON: JSONReporter,
            ReportFormat.SARIF: SARIFReporter,
        }

        output_dir = self.config.report_output

        if self.config.report_format == ReportFormat.ALL:
            for fmt, reporter_cls in reporter_map.items():
                reporter = reporter_cls(context=self.context)
                filepath = reporter.save(output_dir)
                logger.info("[green]REPORT[/] Generated %s: %s", fmt.value, filepath)
        else:
            reporter_cls = reporter_map.get(self.config.report_format, MarkdownReporter)
            reporter = reporter_cls(context=self.context)
            filepath = reporter.save(output_dir)
            logger.info("[green]REPORT[/] Generated %s: %s", self.config.report_format.value, filepath)

        # Print summary
        self._print_summary(stats)

        return stats

    def _detect_technologies(self, response: "httpx.Response") -> list[str]:
        """Detect technologies from HTTP response headers."""
        technologies = []
        server = response.headers.get("server", "").lower()
        powered_by = response.headers.get("x-powered-by", "").lower()

        if server:
            technologies.append(f"Server: {server}")
        if powered_by:
            technologies.append(f"Framework: {powered_by}")

        # Detect common technologies
        headers_str = str(response.headers).lower()
        if "x-amz-cf-id" in headers_str or "x-amz-cf-pop" in headers_str:
            technologies.append("CDN: AWS CloudFront")
        if "cf-ray" in headers_str:
            technologies.append("CDN: Cloudflare")
        if "x-vercel" in headers_str or "x-nextjs" in headers_str:
            technologies.append("Framework: Next.js/Vercel")

        return technologies

    def _check_security_headers(self, response: "httpx.Response") -> dict[str, bool]:
        """Check for recommended security headers."""
        recommended = {
            "strict-transport-security": False,
            "x-content-type-options": False,
            "x-frame-options": False,
            "content-security-policy": False,
            "x-xss-protection": False,
            "referrer-policy": False,
            "permissions-policy": False,
        }

        for header in recommended:
            if header in response.headers:
                recommended[header] = True

        return recommended

    def _print_summary(self, stats: ScanStats) -> None:
        """Print a colorful scan summary to the terminal."""
        from rich.table import Table
        from rich.console import Console

        console = Console()
        table = Table(title="🛡️ Aegisx-Agent Scan Summary", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold")

        table.add_row("Scan ID", self.context.scan_id)
        table.add_row("Target", self.config.target_url)
        table.add_row("Mode", self.config.scan_mode.value)
        table.add_row("Duration", f"{stats.scan_duration_seconds:.1f}s")
        table.add_row("Scanners Used", ", ".join(stats.scanners_used) or "None")
        table.add_row("─" * 20, "─" * 20)
        table.add_row("🔴 Critical", str(stats.critical_count), style="red" if stats.critical_count else "")
        table.add_row("🟠 High", str(stats.high_count), style="dark_orange" if stats.high_count else "")
        table.add_row("🟡 Medium", str(stats.medium_count), style="yellow" if stats.medium_count else "")
        table.add_row("🔵 Low", str(stats.low_count), style="blue" if stats.low_count else "")
        table.add_row("⚪ Info", str(stats.info_count))
        table.add_row("─" * 20, "─" * 20)
        table.add_row("Total Findings", str(stats.total_findings), style="bold")

        console.print(table)
