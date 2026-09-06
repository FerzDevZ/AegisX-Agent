"""Secret redaction for AI-bound content.

The AI agent sends scan evidence to an external LLM provider. Findings
from secret_scanner (and HTTP bodies) may contain live credentials —
those must be masked before leaving the machine.

``redact()`` is applied to every tool result inside the dispatcher, so
nothing the model sees can carry a usable credential. The pattern set
mirrors ``secret_scanner`` but is intentionally broader: anything that
looks like a bearer token, AWS key, connection string, or private key
block gets replaced with ``[REDACTED:<label>]``.
"""

from __future__ import annotations

import re

# (compiled pattern, label) — replaced with [REDACTED:<label>]
_REDACTION_RULES: list[tuple[re.Pattern[str], str]] = [
    # Cloud & SaaS keys
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws-access-key"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b", re.IGNORECASE), "aws-session-key"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"), "github-token"),
    (re.compile(r"\bgho_[A-Za-z0-9]{36,}\b"), "github-oauth"),
    (re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"), "groq-key"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "openai-style-key"),
    (re.compile(r"\brk_[A-Za-z0-9_-]{20,}\b"), "stripe-restricted-key"),
    (re.compile(r"\b(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{16,}\b"), "stripe-key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "slack-token"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "google-api-key"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "gitlab-token"),
    # Bearer / auth headers
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"), "bearer-token"),
    (re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{16,}"), "basic-auth"),
    # JSON Web Tokens (three base64url segments)
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "jwt"),
    # Database connection strings with inline credentials
    (
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://"
            r"[^:\s/]+:[^@\s/]+@[^\s]+",
            re.IGNORECASE,
        ),
        "db-connection-string",
    ),
    # Generic query-string secrets
    (
        re.compile(
            r"(?i)\b(?:api[_-]?key|token|secret|password|passwd|pwd|access[_-]?key)"
            r"([=:])\s*[\"']?([A-Za-z0-9._~+/=-]{12,})[\"']?"
        ),
        "key-value-secret",
    ),
    # Private key blocks (mask the whole blob) — when the END marker is
    # missing (truncated evidence), consume to end-of-string so partial
    # key material never leaks
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?"
            r"(?:-----END [A-Z ]*PRIVATE KEY-----|(?![\s\S]))"
        ),
        "private-key",
    ),
]

# Marker injected by this module — redact() is idempotent on output
_REDACTED_MARKER = "[REDACTED:"


def redact(text: str) -> str:
    """Mask credentials in ``text`` before it is sent to an LLM.

    Idempotent: already-redacted content passes through unchanged and
    never double-masks. Replacement markers carry a label so analysts
    can tell *what* was masked without seeing the value.
    """
    if not text or text.startswith(_REDACTED_MARKER):
        return text

    # Private-key blocks first (multi-line), then line-oriented rules
    pk_pattern, pk_label = _REDACTION_RULES[-1]
    text = pk_pattern.sub(f"[REDACTED:{pk_label}]", text)
    for pattern, label in _REDACTION_RULES[:-1]:
        text = pattern.sub(f"[REDACTED:{label}]", text)
    return text


def redact_mapping(data: dict) -> dict:
    """Redact every string value in a flat dict (non-destructive copy)."""
    return {k: redact(v) if isinstance(v, str) else v for k, v in data.items()}


def count_secrets_found(text: str) -> int:
    """Count redaction markers present in already-redacted text."""
    return len(re.findall(r"\[REDACTED:[a-z-]+\]", text))
