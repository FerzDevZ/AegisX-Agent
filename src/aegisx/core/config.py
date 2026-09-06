"""Configuration management for Aegisx-Agent.

Uses pydantic-settings for type-safe config loaded from env vars and .env file.
All security-sensitive values (API keys, credentials) come from environment only.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any
import os

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

    # --- Proxy Settings ---
    proxy: str = Field(
        default="", description="Proxy URL for routing requests (e.g. http://127.0.0.1:8080 for Burp/ZAP)"
    )

    # --- Request Limits ---
    max_response_size: int = Field(
        default=5_000_000, ge=100_000, le=50_000_000,
        description="Max response body size in bytes"
    )

    # --- Plugin System ---
    plugin_dirs: list[Path] = Field(
        default_factory=lambda: [Path("plugins/")],
        description="Directories to search for scanner plugins",
    )

    # --- Logging ---
    log_level: str = Field(default="INFO", description="Log level (DEBUG/INFO/WARNING/ERROR)")
    verbose: bool = Field(default=False, description="Enable verbose output")

    # --- AI Agent Settings (AegisX Brain) ---
    ai_provider: str = Field(
        default="custom",
        description="AI provider preset: custom, deepseek, openai, groq, openrouter, ollama",
    )
    ai_base_url: str = Field(
        default="",
        description="OpenAI-compatible chat completions base URL (overrides preset)",
    )
    ai_api_key: str = Field(
        default="",
        description="API key for the AI provider (keep secret; prefer AEGISX_AI_API_KEY env var)",
    )
    ai_model: str = Field(
        default="",
        description="Model name (overrides preset default)",
    )
    ai_max_iterations: int = Field(
        default=25, ge=1, le=100,
        description="Max agent loop iterations per run",
    )
    ai_max_tokens: int = Field(
        default=4_000, ge=256, le=32_000,
        description="Max tokens per LLM completion",
    )
    ai_temperature: float = Field(
        default=0.2, ge=0.0, le=2.0,
        description="LLM temperature (low = deterministic tool use)",
    )

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

    def resolve_ai_endpoint(self) -> tuple[str, str, str]:
        """Resolve the effective AI endpoint as ``(base_url, api_key, model)``.

        Precedence: explicit fields > provider preset > defaults.
        Raises ValueError for unknown presets.
        """
        presets: dict[str, tuple[str, str, str]] = {
            # preset: (base_url, env_var_suffix, default_model)
            "custom": ("", "AEGISX_AI_API_KEY", ""),
            "deepseek": ("https://api.deepseek.com/v1", "AEGISX_AI_API_KEY", "deepseek-chat"),
            "openai": ("https://api.openai.com/v1", "AEGISX_AI_API_KEY", "gpt-4o-mini"),
            "groq": ("https://api.groq.com/openai/v1", "AEGISX_AI_API_KEY", "llama-3.3-70b-versatile"),
            "openrouter": ("https://openrouter.ai/api/v1", "AEGISX_AI_API_KEY", "openai/gpt-4o-mini"),
            "ollama": ("http://localhost:11434/v1", "AEGISX_AI_API_KEY", "llama3.1"),
        }
        if self.ai_provider not in presets:
            raise ValueError(
                f"Unknown AI provider preset: {self.ai_provider!r}. "
                f"Valid: {', '.join(sorted(presets))}"
            )

        base_url, _env_suffix, default_model = presets[self.ai_provider]
        base_url = self.ai_base_url or base_url
        if not base_url:
            raise ValueError(
                "AI base URL is not configured. Set AEGISX_AI_BASE_URL "
                "or use --ai-base-url, or pick a preset with --ai-provider."
            )
        base_url = base_url.rstrip("/")

        api_key = self.ai_api_key or os.environ.get("AEGISX_AI_API_KEY", "")
        model = self.ai_model or default_model
        if not model:
            raise ValueError(
                "AI model is not configured. Set AEGISX_AI_MODEL or use --ai-model."
            )
        return base_url, api_key, model

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
