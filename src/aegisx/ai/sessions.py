"""Persisted agent sessions — resume interrupted AegisX Brain runs.

Every agent iteration is checkpointed to ``~/.aegisx/sessions/<scan_id>.json``
(atomic write). If a run dies — Ctrl-C, network loss, laptop sleep — it can
be continued with::

    aegisx agent --continue <scan_id>

Only harness-visible state is persisted: the message transcript (which is
already secret-redacted at tool boundaries), iteration/tool counters, and
token usage. Tool results already in the transcript are replayed to the
model as context; no tool is re-executed on resume.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegisx.utils.logger import get_logger

logger = get_logger("ai.sessions")


@dataclass
class AgentSessionState:
    """Serializable checkpoint of one agent run."""

    scan_id: str
    target_url: str
    model: str = ""
    endpoint: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    iterations_used: int = 0
    tool_calls_made: int = 0
    http_requests_made: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    messages: list[dict[str, Any]] = field(default_factory=list)
    final_message: str = ""
    status: str = "running"  # running | done | error | budget
    error: str = ""


class SessionStore:
    """Filesystem-backed store for :class:`AgentSessionState`."""

    def __init__(self, base_dir: Path | str | None = None) -> None:
        """Point the store at a directory (default ``~/.aegisx/sessions``).

        The ``AEGISX_SESSIONS_DIR`` environment variable overrides the
        default (used by tests to stay hermetic).
        """
        if base_dir is None:
            import os

            base_dir = os.environ.get("AEGISX_SESSIONS_DIR") or (
                Path.home() / ".aegisx" / "sessions"
            )
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, scan_id: str) -> Path:
        """Return the checkpoint file path for one scan id."""
        return self.base_dir / f"{scan_id}.json"

    def save(self, state: AgentSessionState) -> Path:
        """Atomically persist a checkpoint and return its path."""
        state.updated_at = datetime.now(UTC).isoformat()
        path = self.path_for(state.scan_id)
        try:
            fd, tmp_name = tempfile.mkstemp(
                dir=self.base_dir, prefix=".tmp-session-", suffix=".json"
            )
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(asdict(state), fh, ensure_ascii=False, default=str)
            os.replace(tmp_name, path)  # atomic on POSIX and Windows
        except Exception as exc:  # noqa: BLE001 — checkpointing is best-effort
            logger.warning("Session checkpoint failed: %s", exc)
            return path
        logger.debug("Session %s checkpointed (%s)", state.scan_id, state.status)
        return path

    def load(self, scan_id: str) -> AgentSessionState | None:
        """Load one session, or ``None`` if unknown/corrupt."""
        path = self.path_for(scan_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return AgentSessionState(**data)
        except Exception as exc:  # noqa: BLE001 — corrupt files must not crash
            logger.warning("Session %s unreadable: %s", scan_id, exc)
            return None

    def latest(self) -> AgentSessionState | None:
        """Return the most recently updated session, if any."""
        sessions = self.list_sessions(limit=1)
        return self.load(sessions[0]["scan_id"]) if sessions else None

    def list_sessions(self, limit: int = 10) -> list[dict[str, Any]]:
        """List sessions newest-first (metadata only, no messages)."""
        rows: list[dict[str, Any]] = []
        for path in self.base_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                rows.append(
                    {
                        "scan_id": data.get("scan_id", path.stem),
                        "target_url": data.get("target_url", ""),
                        "status": data.get("status", ""),
                        "updated_at": data.get("updated_at", ""),
                        "iterations": data.get("iterations_used", 0),
                        "tool_calls": data.get("tool_calls_made", 0),
                    }
                )
            except Exception as exc:  # noqa: BLE001 — skip unreadable files
                logger.debug("Skipping unreadable session %s: %s", path.name, exc)
                continue
        rows.sort(key=lambda r: r["updated_at"], reverse=True)
        return rows[:limit]

    def delete(self, scan_id: str) -> bool:
        """Remove one session file. Returns True if it existed."""
        path = self.path_for(scan_id)
        if path.exists():
            path.unlink()
            return True
        return False
