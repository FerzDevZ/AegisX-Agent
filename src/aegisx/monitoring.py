"""Continuous monitoring — scheduled scans with new-finding alerts.

The :class:`Monitor` re-scans a target on an interval and alerts only on
**new** findings (diffed against the previous run via
:class:`~aegisx.utils.history.ScanHistory.compare_scans`). Designed for
long-running operation::

    aegisx monitor https://target.com --every 3600 --notify <webhook>

Every cycle records history and can push notifications, so it composes
with the rest of the tooling.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from aegisx.core.config import AegisxConfig
from aegisx.core.context import Finding
from aegisx.utils.history import ScanHistory
from aegisx.utils.logger import get_logger
from aegisx.utils.notify import send_notification

logger = get_logger("monitor")


@dataclass
class MonitorCycle:
    """Result of one monitoring cycle."""

    cycle: int
    scan_id: str
    started_at: str
    duration_seconds: float
    total_findings: int
    new_findings: list[Finding] = field(default_factory=list)
    resolved_count: int = 0
    notified: bool = False
    error: str = ""


class Monitor:
    """Re-scans a target on an interval and alerts on new findings."""

    def __init__(
        self,
        config: AegisxConfig,
        *,
        interval_seconds: int = 3600,
        webhook_url: str | None = None,
        max_cycles: int | None = None,
        history: ScanHistory | None = None,
        cooldown_seconds: int = 0,
    ) -> None:
        """Configure the monitor loop.

        Args:
            config: Scan configuration (target, scanners, mode).
            interval_seconds: Seconds between scan cycles.
            webhook_url: Optional webhook to push new findings to.
            max_cycles: Stop after N cycles (``None`` = run forever).
            history: History handle (default: standard location).
            cooldown_seconds: Extra pause between cycles (testing hook).
        """
        self.config = config
        self.interval_seconds = max(1, interval_seconds)
        self.webhook_url = webhook_url
        self.max_cycles = max_cycles
        self.history = history or ScanHistory()
        self._cooldown_seconds = cooldown_seconds
        self.last_scan_id: str | None = None
        self.last_new_findings: list[Finding] = []

    async def _run_scan_cycle(self) -> tuple[str, list[Finding]]:
        """Execute one full scan and return (scan_id, findings)."""
        from aegisx.core.context import ScanContext
        from aegisx.core.orchestrator import AegisxOrchestrator

        context = ScanContext(config=self.config, target_url=self.config.target_url)
        orch = AegisxOrchestrator(self.config)
        orch.context = context
        await orch.run()
        return context.scan_id, list(context.findings)

    async def _notify_new(self, cycle_result: MonitorCycle) -> bool:
        """Push new findings to the webhook (best-effort)."""
        if not self.webhook_url or not cycle_result.new_findings:
            return False
        result = await send_notification(
            self.webhook_url,
            cycle_result.new_findings,
            self.config.target_url,
            cycle_result.scan_id,
        )
        return result.ok

    async def run_cycle(self, cycle_number: int) -> MonitorCycle:
        """Run one scan-diff-alert cycle."""
        started = time.monotonic()
        cycle = MonitorCycle(
            cycle=cycle_number,
            scan_id="",
            started_at=datetime.now(UTC).isoformat(),
            duration_seconds=0.0,
            total_findings=0,
        )
        try:
            scan_id, findings = await self._run_scan_cycle()
        except Exception as exc:  # noqa: BLE001 — a failed cycle must not kill the monitor
            cycle.error = f"{type(exc).__name__}: {exc}"
            cycle.duration_seconds = time.monotonic() - started
            logger.error("[bold red]MONITOR[/] cycle %d failed: %s", cycle_number, cycle.error)
            return cycle

        cycle.scan_id = scan_id
        cycle.total_findings = len(findings)
        cycle.duration_seconds = time.monotonic() - started

        # Diff against the previous cycle's scan
        if self.last_scan_id:
            diff = self.history.compare_scans(self.last_scan_id, scan_id)
            new_titles = {n.get("title") for n in diff.get("new_findings", [])}
            cycle.new_findings = [f for f in findings if f.title in new_titles]
            cycle.resolved_count = len(diff.get("resolved_findings", []))
        else:
            # First cycle establishes the baseline; announcing the full
            # backlog would be noisy.
            cycle.new_findings = []

        self.last_scan_id = scan_id
        self.last_new_findings = cycle.new_findings
        cycle.notified = await self._notify_new(cycle)

        logger.info(
            "[bold blue]MONITOR[/] cycle %d: %d findings (%d new, %d resolved) in %.1fs%s",
            cycle_number,
            cycle.total_findings,
            len(cycle.new_findings),
            cycle.resolved_count,
            cycle.duration_seconds,
            " — notified" if cycle.notified else "",
        )
        return cycle

    async def run(self) -> list[MonitorCycle]:
        """Run the monitoring loop until max_cycles or cancellation."""
        cycles: list[MonitorCycle] = []
        n = 0
        while self.max_cycles is None or n < self.max_cycles:
            n += 1
            result = await self.run_cycle(n)
            cycles.append(result)
            if self.max_cycles is not None and n >= self.max_cycles:
                break
            await asyncio.sleep(self.interval_seconds + self._cooldown_seconds)
        return cycles
