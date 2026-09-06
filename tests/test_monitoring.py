"""Tests for webhook notifications and the continuous monitor."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from aegisx.core.config import AegisxConfig
from aegisx.core.context import Finding, ScanStats, Severity
from aegisx.monitoring import Monitor, MonitorCycle
from aegisx.utils.history import ScanHistory
from aegisx.utils.notify import build_payload, send_notification


def _finding(title: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        url="https://test.example.com/",
        endpoint="/",
        scanner_name="test_scanner",
    )


def _config(**overrides: Any) -> AegisxConfig:
    kwargs: dict[str, Any] = {"target_url": "https://test.example.com"}
    kwargs.update(overrides)
    return AegisxConfig(**kwargs)


@pytest.fixture()
def history_db(tmp_path, monkeypatch):
    """Hermetic history DB per test."""
    monkeypatch.setenv("AEGISX_HISTORY_DB", str(tmp_path / "history.db"))
    return ScanHistory()


# ---------------------------------------------------------------- notify


class TestNotifyPayload:
    def test_slack_style_default(self) -> None:
        payload = build_payload(
            [_finding("Open Redirect", Severity.MEDIUM)],
            target="https://test.example.com",
            scan_id="abc123",
        )
        assert "text" in payload
        assert "Open Redirect" in payload["text"]
        assert "abc123" in payload["text"]
        assert "*1*" in payload["text"]  # new-findings count

    def test_discord_style_uses_content_key(self) -> None:
        payload = build_payload(
            [_finding("X", Severity.HIGH)],
            target="https://test.example.com",
            scan_id="abc123",
            style="discord",
        )
        assert "content" in payload and "text" not in payload

    def test_more_than_ten_findings_truncated(self) -> None:
        many = [_finding(f"Finding {i}", Severity.LOW) for i in range(14)]
        payload = build_payload(many, "https://t.example.com", "sid")
        assert "…and 4 more" in payload["text"]

    def test_no_findings_message(self) -> None:
        payload = build_payload([], "https://t.example.com", "sid")
        assert "No new findings" in payload["text"]

    def test_payload_json_serializable(self) -> None:
        payload = build_payload([_finding("T", Severity.CRITICAL)], "https://t.example.com", "sid")
        assert is_json_ok(payload)

    def test_report_path_included(self) -> None:
        payload = build_payload(
            [_finding("T", Severity.LOW)],
            "https://t.example.com",
            "sid",
            report_path="reports/r.md",
        )
        assert "reports/r.md" in payload["text"]


def is_json_ok(payload: dict[str, Any]) -> bool:
    import json

    try:
        json.dumps(payload)
        return True
    except (TypeError, ValueError):
        return False


class TestSendNotification:
    @respx.mock
    @pytest.mark.asyncio
    async def test_success_slack(self) -> None:
        route = respx.post("https://hooks.slack.com/services/T000/B000/XYZ").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = await send_notification(
            "https://hooks.slack.com/services/T000/B000/XYZ",
            [_finding("Bug", Severity.HIGH)],
            "https://t.example.com",
            "sid",
        )
        assert result.ok is True
        assert result.status_code == 200
        assert route.called

    @respx.mock
    @pytest.mark.asyncio
    async def test_failure_is_not_fatal(self) -> None:
        respx.post("https://hooks.slack.com/services/fail").mock(
            return_value=httpx.Response(500, text="boom")
        )
        result = await send_notification(
            "https://hooks.slack.com/services/fail",
            [_finding("Bug")],
            "https://t.example.com",
            "sid",
        )
        assert result.ok is False
        assert result.status_code == 500

    @respx.mock
    @pytest.mark.asyncio
    async def test_network_error_is_not_fatal(self) -> None:
        respx.post("https://hooks.slack.com/services/net").mock(side_effect=httpx.ConnectError("x"))
        result = await send_notification(
            "https://hooks.slack.com/services/net",
            [],
            "https://t.example.com",
            "sid",
        )
        assert result.ok is False
        assert result.error

    @pytest.mark.asyncio
    async def test_empty_url_short_circuits(self) -> None:
        result = await send_notification("", [], "https://t.example.com", "sid")
        assert result.ok is False


# ---------------------------------------------------------------- monitor


class _StubOrchestrator:
    """Replaces AegisxOrchestrator inside Monitor._run_scan_cycle."""

    def __init__(self, config: AegisxConfig, scripts: list[list[Finding]]) -> None:
        self._scripts = scripts
        self.call_count = 0

    async def run(self) -> ScanStats:  # noqa: ARG002
        findings = (
            self._scripts[min(self.call_count, len(self._scripts) - 1)]
            if self.call_count < len(self._scripts)
            else []
        )
        self.call_count += 1
        return ScanStats(
            total_findings=len(findings),
            scanners_used=["stub"],
        )


class TestMonitor:
    @pytest.fixture(autouse=True)
    def _no_real_sleep(self, monkeypatch):
        """The monitor loop must not actually sleep 3600s in tests."""

        async def fake_sleep(seconds: float) -> None:  # noqa: ARG001
            return None

        monkeypatch.setattr("aegisx.monitoring.asyncio.sleep", fake_sleep)

    def _monitor(
        self,
        scripts: list[list[Finding]],
        history_db: ScanHistory,
        **kwargs: Any,
    ) -> tuple[Monitor, list[_StubOrchestrator]]:
        instances: list[_StubOrchestrator] = []

        class _Factory:
            def __new__(cls, config):  # type: ignore[no-untyped-def]
                inst = _StubOrchestrator(config, scripts)
                instances.append(inst)
                return inst

        import aegisx.monitoring as mon

        original = mon.AegisxOrchestrator
        mon.AegisxOrchestrator = _Factory  # type: ignore[misc]
        monitor = Monitor(
            _config(**kwargs.pop("config_kwargs", {})),
            history=history_db,
            **kwargs,
        )
        mon.AegisxOrchestrator = original
        return monitor, instances

    async def _patch_run_scan(self, monitor: Monitor, scripts: list[list[Finding]]) -> None:
        """Monkeypatch the scan cycle to return scripted findings."""

        counter = {"n": 0}

        async def fake_scan() -> tuple[str, list[Finding]]:
            counter["n"] += 1
            findings = scripts[min(counter["n"] - 1, len(scripts) - 1)]
            scan_id = f"scan-{counter['n']:04d}"
            monitor.history.record_scan(
                scan_id=scan_id,
                target=monitor.config.target_url,
                mode="quick",
                stats=ScanStats(total_findings=len(findings)),
                findings=[f.to_dict() for f in findings],
            )
            return scan_id, findings

        monitor._run_scan_cycle = fake_scan  # type: ignore[method-assign]

    @pytest.mark.asyncio
    async def test_first_cycle_is_baseline_no_notification(self, history_db: ScanHistory) -> None:
        scripts = [[_finding("Only Finding")]]
        monitor = Monitor(
            _config(),
            history=history_db,
            webhook_url="https://hooks.slack.com/services/x",
            max_cycles=1,
        )
        await self._patch_run_scan(monitor, scripts)
        with respx.mock:
            respx.post("https://hooks.slack.com/services/x").mock(return_value=httpx.Response(200))
            cycles = await monitor.run()

        assert len(cycles) == 1
        assert cycles[0].new_findings == []  # baseline: announce nothing
        assert cycles[0].notified is False

    @pytest.mark.asyncio
    async def test_new_findings_detected_and_notified(self, history_db: ScanHistory) -> None:
        scripts = [
            [_finding("Base Finding")],
            [_finding("Base Finding"), _finding("Brand New Bug", Severity.HIGH)],
        ]
        monitor = Monitor(
            _config(),
            history=history_db,
            webhook_url="https://hooks.slack.com/services/x",
            max_cycles=2,
        )
        await self._patch_run_scan(monitor, scripts)
        with respx.mock:
            route = respx.post("https://hooks.slack.com/services/x").mock(
                return_value=httpx.Response(200)
            )
            cycles = await monitor.run()

        assert len(cycles) == 2
        assert [f.title for f in cycles[1].new_findings] == ["Brand New Bug"]
        assert cycles[1].notified is True
        assert route.call_count == 1

    @pytest.mark.asyncio
    async def test_resolved_findings_counted(self, history_db: ScanHistory) -> None:
        scripts = [
            [_finding("Gone Later")],
            [],
        ]
        monitor = Monitor(
            _config(),
            history=history_db,
            max_cycles=2,
        )
        await self._patch_run_scan(monitor, scripts)
        cycles = await monitor.run()
        assert cycles[1].resolved_count == 1
        assert cycles[1].new_findings == []

    @pytest.mark.asyncio
    async def test_failed_cycle_does_not_kill_monitor(self, history_db: ScanHistory) -> None:
        monitor = Monitor(_config(), history=history_db, max_cycles=2)

        call_n = {"n": 0}

        async def flaky_scan() -> tuple[str, list[Finding]]:
            call_n["n"] += 1
            if call_n["n"] == 1:
                raise RuntimeError("network exploded")
            scan_id = f"scan-{call_n['n']:04d}"
            monitor.history.record_scan(
                scan_id=scan_id,
                target=monitor.config.target_url,
                mode="quick",
                stats=ScanStats(),
                findings=[],
            )
            return scan_id, []

        monitor._run_scan_cycle = flaky_scan  # type: ignore[method-assign]
        cycles = await monitor.run()
        assert len(cycles) == 2
        assert cycles[0].error  # recorded, not raised
        assert cycles[1].error == ""

    @pytest.mark.asyncio
    async def test_interval_respected_between_cycles(
        self, history_db: ScanHistory, monkeypatch
    ) -> None:
        sleeps: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        monkeypatch.setattr("aegisx.monitoring.asyncio.sleep", fake_sleep)
        monitor = Monitor(
            _config(),
            history=history_db,
            interval_seconds=123,
            cooldown_seconds=7,
            max_cycles=2,
        )
        await self._patch_run_scan(monitor, [[], []])
        await monitor.run()
        assert sleeps == [130]


def test_monitor_cycle_dataclass_defaults() -> None:
    cycle = MonitorCycle(
        cycle=1, scan_id="s", started_at="t", duration_seconds=0.1, total_findings=0
    )
    assert cycle.new_findings == []
    assert cycle.resolved_count == 0
    assert cycle.notified is False
