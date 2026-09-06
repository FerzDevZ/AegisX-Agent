"""SIEM-friendly JSON export.

Converts scan findings into flat, event-per-finding records suitable for
ingestion by SIEM platforms (Splunk HEC, Elastic ECS, Sentinel, Wazuh).
Each finding becomes one event with normalized severity, ISO-8601
timestamps, and stable field names.

Entry points:

- :func:`context_to_events` — convert a :class:`ScanContext` into a list
  of SIEM event dicts (one per finding).
- :class:`SIEMExporter` — write events (and an optional scan summary
  event) to a JSON-lines or JSON-array file.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegisx.core.context import ScanContext
from aegisx.utils.logger import get_logger

logger = get_logger("siem")

# Normalized severity levels accepted by most SIEM platforms
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
}


def context_to_events(ctx: ScanContext) -> list[dict[str, Any]]:
    """Convert a completed scan context into SIEM event dicts.

    Each finding becomes one flat event with stable field names:
    ``@timestamp``, ``event.kind``, ``event.category``,
    ``event.severity``, ``vulnerability.*``, ``destination.*``,
    ``url.full``, ``http.request.method``.
    """
    events: list[dict[str, Any]] = []
    scan_ts = ctx.finished_at or datetime.now(UTC).isoformat()

    for f in ctx.findings:
        events.append(
            {
                "@timestamp": scan_ts,
                "event": {
                    "kind": "alert",
                    "category": ["vulnerability"],
                    "type": "info",
                    "severity": _SEVERITY_MAP.get(f.severity.value, "informational"),
                    "module": "aegisx-agent",
                    "dataset": "aegisx.findings",
                },
                "scan": {
                    "id": ctx.scan_id,
                    "target": ctx.target_url,
                    "mode": ctx.config.scan_mode.value,
                },
                "vulnerability": {
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "score": f.cvss_score,
                    "cwe": f.cwe_id,
                    "owasp_category": f.owasp_category,
                    "scanner": f.scanner_name,
                },
                "destination": {
                    "domain": ctx.target_url,
                },
                "url": {"full": f.url, "path": f.endpoint},
                "http": {"request": {"method": f.method}},
                "aegisx": {
                    "parameter": f.parameter,
                    "payload": f.payload,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "references": f.references or [],
                },
            }
        )
    return events


def summary_event(ctx: ScanContext) -> dict[str, Any]:
    """Build one summary event for the scan as a whole."""
    stats = ctx.get_stats()
    return {
        "@timestamp": ctx.finished_at or datetime.now(UTC).isoformat(),
        "event": {
            "kind": "metric",
            "category": ["vulnerability"],
            "type": "summary",
            "module": "aegisx-agent",
            "dataset": "aegisx.scan_summary",
        },
        "scan": {
            "id": ctx.scan_id,
            "target": ctx.target_url,
            "mode": ctx.config.scan_mode.value,
            "duration_seconds": round(stats.scan_duration_seconds, 2),
            "scanners_used": stats.scanners_used,
        },
        "vulnerability": {
            "total": stats.total_findings,
            "by_severity": {
                "critical": stats.critical_count,
                "high": stats.high_count,
                "medium": stats.medium_count,
                "low": stats.low_count,
                "informational": stats.info_count,
            },
        },
    }


class SIEMExporter:
    """Write scan context as SIEM-ready events to disk.

    Supports two output shapes:

    - ``jsonl`` (default): one JSON object per line — ideal for Splunk
      HEC batch uploads and Filebeat tailing.
    - ``json``: a single JSON array — ideal for one-shot HTTP uploads.
    """

    def __init__(self, ctx: ScanContext, include_summary: bool = True) -> None:
        """Create an exporter for a completed scan context.

        Args:
            ctx: The scan context to export.
            include_summary: Prepend a scan-summary event before findings.
        """
        self.ctx = ctx
        self.include_summary = include_summary

    def build_events(self) -> list[dict[str, Any]]:
        """Assemble the full event list (summary + per-finding events)."""
        events: list[dict[str, Any]] = []
        if self.include_summary:
            events.append(summary_event(self.ctx))
        events.extend(context_to_events(self.ctx))
        return events

    def write(self, output_path: Path | str, fmt: str = "jsonl") -> Path:
        """Write events to ``output_path``.

        Args:
            output_path: Destination file.
            fmt: ``"jsonl"`` for JSON-lines or ``"json"`` for an array.

        Returns:
            Path to the written file.
        """
        events = self.build_events()
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "jsonl":
            with out.open("w", encoding="utf-8") as fh:
                for event in events:
                    fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
        elif fmt == "json":
            out.write_text(
                json.dumps(events, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        else:
            raise ValueError(f"Unknown SIEM export format: {fmt!r} (use 'jsonl' or 'json')")

        logger.info("Exported %d SIEM events to %s", len(events), out)
        return out


def export_siem(
    ctx: ScanContext,
    output_path: Path | str,
    fmt: str = "jsonl",
    include_summary: bool = True,
) -> Path:
    """Convenience wrapper: export a scan context as SIEM events."""
    return SIEMExporter(ctx, include_summary=include_summary).write(output_path, fmt=fmt)
