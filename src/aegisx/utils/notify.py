"""Webhook notifications for new findings (Slack / Discord / generic).

One responsibility: POST a small JSON payload describing new findings
to a user-supplied webhook URL. Supports the Slack incoming-webhook
format, the Discord webhook format, and any endpoint accepting
``{"text": ...}`` (auto-detected from the URL, overridable).

Delivery is best-effort by design: a notification failure must never
fail the scan itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from aegisx.core.context import Finding
from aegisx.utils.logger import get_logger

logger = get_logger("notify")

_TIMEOUT_SECONDS = 15
_MAX_FINDINGS_PER_MESSAGE = 10

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


@dataclass
class NotifyResult:
    """Outcome of one webhook delivery."""

    ok: bool
    status_code: int | None = None
    error: str = ""


def _format_finding_line(finding: Finding) -> str:
    """One compact markdown line per finding."""
    emoji = _SEVERITY_EMOJI.get(finding.severity.value, "•")
    loc = finding.endpoint or finding.url or ""
    return f"{emoji} *[{finding.severity.value.upper()}]* {finding.title} — `{loc}`"


def build_payload(
    findings: list[Finding],
    target: str,
    scan_id: str,
    report_path: str = "",
    style: str = "auto",
) -> dict[str, Any]:
    """Build the webhook JSON body for a list of new findings.

    Args:
        findings: New findings to announce (may be empty).
        target: Scanned target URL.
        scan_id: Scan identifier for correlation.
        report_path: Optional local report path to include.
        style: ``slack``, ``discord``, or ``auto`` (detect from URL host).

    Returns:
        JSON-serializable payload dict.
    """
    if style == "auto":
        style = "discord" if "discord.com" in target or "discordapp.com" in target else "slack"

    count = len(findings)
    if count:
        lines = [_format_finding_line(f) for f in findings[:_MAX_FINDINGS_PER_MESSAGE]]
        if count > _MAX_FINDINGS_PER_MESSAGE:
            lines.append(f"…and {count - _MAX_FINDINGS_PER_MESSAGE} more")
        summary = "\n".join(lines)
    else:
        summary = "No new findings. 🎉"

    text = (
        f"*🛡️ AegisX-Agent scan finished*\n"
        f"Target: `{target}`\n"
        f"Scan: `{scan_id}`\n"
        f"New findings: *{count}*\n"
        f"{summary}"
    )
    if report_path:
        text += f"\nReport: `{report_path}`"

    if style == "discord":
        return {"content": text}
    return {"text": text}


async def send_notification(
    webhook_url: str,
    findings: list[Finding],
    target: str,
    scan_id: str,
    report_path: str = "",
    style: str = "auto",
) -> NotifyResult:
    """POST the findings payload to a webhook. Never raises.

    Args:
        webhook_url: Slack/Discord/generic incoming webhook URL.
        findings: New findings to announce.
        target: Scanned target URL.
        scan_id: Scan identifier.
        report_path: Optional report path to include.
        style: ``slack``, ``discord``, or ``auto``.

    Returns:
        :class:`NotifyResult` describing success/failure.
    """
    if not webhook_url:
        return NotifyResult(ok=False, error="empty webhook URL")
    payload = build_payload(findings, target, scan_id, report_path, style)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            resp = await client.post(webhook_url, json=payload)
        ok = 200 <= resp.status_code < 300
        if not ok:
            logger.warning("Notification failed: HTTP %d — %s", resp.status_code, resp.text[:120])
        else:
            logger.info("Notification sent (HTTP %d)", resp.status_code)
        return NotifyResult(ok=ok, status_code=resp.status_code)
    except httpx.HTTPError as exc:
        logger.warning("Notification delivery failed: %s", type(exc).__name__)
        return NotifyResult(ok=False, error=type(exc).__name__)


def load_notify_config(env: dict[str, str] | None = None) -> str | None:
    """Resolve the notification webhook URL from the environment.

    Checks ``AEGISX_NOTIFY_WEBHOOK``. Returns ``None`` when unset.
    """
    import os

    source = env if env is not None else dict(os.environ)
    return source.get("AEGISX_NOTIFY_WEBHOOK") or None


def is_json_serializable(payload: dict[str, Any]) -> bool:
    """True when the payload can be JSON-encoded (test helper)."""
    try:
        json.dumps(payload)
        return True
    except (TypeError, ValueError):
        return False
