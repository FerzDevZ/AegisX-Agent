"""SQLite-backed scan history database.

Persists every completed scan so results can be tracked over time,
compared across runs, and exported. Uses :mod:`aiosqlite` (already a
core dependency) with WAL mode for safe concurrent reads.

Schema
------
scans table:
    scan_id      — unique scan identifier (primary key)
    timestamp    — ISO-8601 UTC completion time
    target       — scanned URL
    mode         — scan mode (quick/full/passive)
    findings     — total finding count
    critical/high/medium/low/info — counts by severity
    duration     — wall-clock seconds
    scanners     — comma-separated scanner names
    findings_json — full finding list for diffing/replay
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegisx.core.context import ScanStats
from aegisx.utils.logger import get_logger

logger = get_logger("history")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id       TEXT PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    target        TEXT NOT NULL,
    mode          TEXT NOT NULL,
    findings      INTEGER NOT NULL DEFAULT 0,
    critical      INTEGER NOT NULL DEFAULT 0,
    high          INTEGER NOT NULL DEFAULT 0,
    medium        INTEGER NOT NULL DEFAULT 0,
    low           INTEGER NOT NULL DEFAULT 0,
    info          INTEGER NOT NULL DEFAULT 0,
    duration      REAL NOT NULL DEFAULT 0.0,
    scanners      TEXT NOT NULL DEFAULT '',
    findings_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
"""


class ScanHistory:
    """Async interface to the local scan history database."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        """Create a history handle.

        Args:
            db_path: Path to the SQLite file. Defaults to
                ``~/.aegisx/history.db``.
        """
        if db_path is None:
            db_path = os.environ.get("AEGISX_HISTORY_DB") or (
                Path.home() / ".aegisx" / "history.db"
            )
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self):
        """Open a synchronous connection and ensure the schema exists."""
        import sqlite3

        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_SCHEMA)
        return conn

    def record_scan(
        self,
        scan_id: str,
        target: str,
        mode: str,
        stats: ScanStats,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        """Persist a completed scan. Never raises — history is best-effort."""
        try:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO scans
                        (scan_id, timestamp, target, mode, findings, critical,
                         high, medium, low, info, duration, scanners, findings_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        datetime.now(UTC).isoformat(),
                        target,
                        mode,
                        stats.total_findings,
                        stats.critical_count,
                        stats.high_count,
                        stats.medium_count,
                        stats.low_count,
                        stats.info_count,
                        stats.scan_duration_seconds,
                        ",".join(stats.scanners_used),
                        json.dumps(findings or [], ensure_ascii=False, default=str),
                    ),
                )
                conn.commit()
            finally:
                conn.close()
            logger.debug("Recorded scan %s in history", scan_id)
        except Exception as exc:  # noqa: BLE001 — history must never break a scan
            logger.warning("Failed to record scan history: %s", exc)

    def get_scans(
        self,
        target: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List recent scans, newest first.

        Args:
            target: Filter by target URL (optional).
            limit: Maximum number of rows.

        Returns:
            List of scan records (without the bulky findings_json).
        """
        conn = self._connect()
        try:
            if target:
                rows = conn.execute(
                    """SELECT scan_id, timestamp, target, mode, findings,
                              critical, high, medium, low, info, duration, scanners
                       FROM scans WHERE target = ?
                       ORDER BY timestamp DESC LIMIT ?""",
                    (target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT scan_id, timestamp, target, mode, findings,
                              critical, high, medium, low, info, duration, scanners
                       FROM scans ORDER BY timestamp DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
        finally:
            conn.close()

        keys = [
            "scan_id", "timestamp", "target", "mode", "findings",
            "critical", "high", "medium", "low", "info", "duration", "scanners",
        ]
        return [dict(zip(keys, row, strict=True)) for row in rows]

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Fetch a single scan record including full findings JSON."""
        conn = self._connect()
        try:
            cursor = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            columns = [desc[0] for desc in cursor.description]
        finally:
            conn.close()

        if row is None:
            return None
        record = dict(zip(columns, row, strict=True))
        record["findings"] = json.loads(record.pop("findings_json", "[]"))
        return record

    def compare_scans(self, old_id: str, new_id: str) -> dict[str, Any]:
        """Compare two scans of the same target and report the delta.

        Returns:
            Dict with ``new_findings`` and ``resolved_findings`` lists
            (keyed by finding id/title), plus severity count deltas.
        """
        old = self.get_scan(old_id)
        new = self.get_scan(new_id)
        if old is None or new is None:
            raise ValueError(f"Scan not found: {old_id if old is None else new_id}")

        def _key(f: dict[str, Any]) -> str:
            return f"{f.get('title', '?')}@{f.get('url', f.get('endpoint', '?'))}"

        old_map = {_key(f): f for f in old.get("findings", [])}
        new_map = {_key(f): f for f in new.get("findings", [])}

        severity_fields = ("critical", "high", "medium", "low", "info")
        return {
            "old_scan": old_id,
            "new_scan": new_id,
            "new_findings": [f for k, f in new_map.items() if k not in old_map],
            "resolved_findings": [f for k, f in old_map.items() if k not in new_map],
            "severity_delta": {
                s: new.get(s, 0) - old.get(s, 0) for s in severity_fields
            },
        }

    def export_json(self, output_path: Path | str) -> Path:
        """Export all scan history to a JSON file."""
        scans = self.get_scans(limit=10_000)
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(scans, indent=2, ensure_ascii=False))
        logger.info("Exported %d scans to %s", len(scans), out)
        return out

    def stats_summary(self) -> dict[str, Any]:
        """Aggregate stats across the whole history."""
        conn = self._connect()
        try:
            row = conn.execute(
                """SELECT COUNT(*), COUNT(DISTINCT target),
                          COALESCE(SUM(findings), 0), COALESCE(SUM(critical), 0)
                   FROM scans"""
            ).fetchone()
        finally:
            conn.close()
        return {
            "total_scans": row[0],
            "unique_targets": row[1],
            "total_findings": row[2],
            "total_critical": row[3],
        }
