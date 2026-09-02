"""Exception hierarchy for Aegisx-Agent.

All custom exceptions inherit from AegisxError for clean catch-all handling.
Each subsystem has its own base exception for granular error handling.
"""


class AegisxError(Exception):
    """Base exception for all Aegisx-Agent errors."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


class ConfigError(AegisxError):
    """Configuration loading or validation failed."""


class ScanError(AegisxError):
    """Scanner execution failed."""


class ScanTargetError(ScanError):
    """Target is unreachable, invalid, or out of scope."""


class ScannerPluginError(ScanError):
    """A scanner plugin failed during execution."""


class ExploitError(AegisxError):
    """Exploit generation or execution failed."""


class ExploitSandboxError(ExploitError):
    """Sandboxed exploit execution failed (isolation breach or crash)."""


class ReportError(AegisxError):
    """Report generation failed."""


class PluginError(AegisxError):
    """Plugin loading or registration failed."""


class ScopeError(AegisxError):
    """Target is outside the authorized scan scope."""


class RateLimitError(ScanError):
    """Rate limit exceeded — scan paused to avoid DoS on target."""


class KnowledgeBaseError(AegisxError):
    """Knowledge base query or lookup failed."""
