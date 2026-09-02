"""Configuration management for Aegisx-Agent.

Uses pydantic-settings for type-safe config loaded from env vars and .env file.
All security-sensitive values (API keys, credentials) come from environment only.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScanMode(str, Enum):
    """Scan intensity modes."""

    PASSIVE = "passive"  # Recon + fingerprinting only, no active probing
    QUICK = "quick"  # Fast scan of common vulnerabilities
    FULL = "full"  # Comprehensive scan with exploit verification
    STEALTH = "stealth"  # Slow, low-profile scan to avoid detection


class ReportFormat(str, Enum):
    """Available report output formats."""

    MARKDOWN = "markdown"
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"
    ALL = "all"


class Severity(str, Enum):
    """Vulnerability severity levels (CVSS-aligned)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AegisxConfig(BaseSettings):
    """Main configuration for Aegisx-Agent.

    All fields can be set via environment variables prefixed with AEGISX_.
    Example: AEGISX_SCAN_MODE=full
    """

    model_config = SettingsConfigDict(
        env_prefix="AEGISX_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Scan Settings ---
    scan_mode: ScanMode = Field(default=ScanMode.QUICK, description="Scan intensity")
    target_url: str = Field(default="", description="Target URL to scan")
    scope: list[str] = Field(
        default_factory=list,
        description="Allowed target domains/IPs (whitelist). Empty = only target_url domain.",
    )
    max_depth: int = Field(default=3, ge=1, le=10, description="Max crawl depth")
    max_requests_per_second: float = Field(
        default=10.0, ge=0.1, le=100.0, description="Rate limit (req/s)"
    )
    timeout_seconds: int = Field(default=30, ge=5, le=300, description="HTTP timeout")
    user_agent: str = Field(
        default="AegisxAgent/0.1.0 (Security Scanner)",
        description="HTTP User-Agent string",
    )

    # --- Scanner Modules ---
    enabled_scanners: list[str] = Field(
        default_factory=lambda: [
            "web_scanner",
            "secret_scanner",
            "config_scanner",
            "dependency_scanner",
            "network_scanner",
        ],
        description="List of scanner modules to enable",
    )

    # --- Exploit Settings ---
    exploit_verification: bool = Field(
        default=False,
        description="Enable exploit verification (requires explicit consent)",
    )
    sandbox_enabled: bool = Field(
        default=True, description="Run exploits in Docker sandbox"
    )
    sandbox_image: str = Field(
        default="aegisx-sandbox:latest", description="Docker image for sandbox"
    )

    # --- Reporting ---
    report_format: ReportFormat = Field(
        default=ReportFormat.MARKDOWN, description="Output report format"
    )
    report_output: Path = Field(
        default=Path("reports/"), description="Report output directory"
    )

    # --- Authentication (for target-specific auth) ---
    auth_token: str = Field(default="", description="Auth token for target (optional)")
    auth_header: str = Field(
        default="Authorization", description="Auth header name"
    )
    cookies: dict[str, str] = Field(
        default_factory=dict, description="Cookies to include in requests"
    )

    # --- Plugin System ---
    plugin_dirs: list[Path] = Field(
        default_factory=lambda: [Path("plugins/")],
        description="Directories to search for scanner plugins",
    )

    # --- Logging ---
    log_level: str = Field(default="INFO", description="Log level (DEBUG/INFO/WARNING/ERROR)")
    verbose: bool = Field(default=False, description="Enable verbose output")

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: list[str]) -> list[str]:
        """Ensure scope entries are reasonable."""
        for entry in v:
            if not entry.strip():
                continue
            if entry.startswith(("http://", "https://")):
                raise ValueError(
                    f"Scope entries should be domains, not full URLs: {entry}"
                )
        return v

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL falls within the authorized scan scope."""
        from urllib.parse import urlparse

        if not self.scope:
            # No explicit scope — only the target domain is in scope
            target_domain = urlparse(self.target_url).hostname or ""
            url_domain = urlparse(url).hostname or ""
            return url_domain == target_domain

        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        return any(
            hostname == s or hostname.endswith(f".{s}") for s in self.scope if s.strip()
        )

    def get_auth_headers(self) -> dict[str, str]:
        """Build authentication headers from config."""
        headers: dict[str, str] = {}
        if self.auth_token:
            if self.auth_token.lower().startswith("bearer "):
                headers[self.auth_header] = self.auth_token
            else:
                headers[self.auth_header] = f"Bearer {self.auth_token}"
        return headers


def load_config(**overrides: Any) -> AegisxConfig:
    """Load configuration with optional overrides.

    Usage:
        config = load_config(target_url="https://example.com", scan_mode="full")
    """
    return AegisxConfig(**overrides)
