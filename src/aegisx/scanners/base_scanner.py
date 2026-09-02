"""Abstract base scanner interface.

All scanner modules (web, network, secret, etc.) inherit from BaseScanner.
The orchestrator calls scan() on each registered scanner and collects findings.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from aegisx.core.context import Finding, ScanContext
from aegisx.utils.logger import get_logger

logger = get_logger("scanner")


class BaseScanner(ABC):
    """Abstract base class for all vulnerability scanners.

    Subclasses MUST implement:
        - name: unique identifier for the scanner
        - description: human-readable description
        - scan(): the actual scanning logic
    """

    name: ClassVar[str] = "base"
    description: ClassVar[str] = "Base scanner"
    enabled_by_default: ClassVar[bool] = False

    def __init__(self, context: ScanContext) -> None:
        self.context = context
        self.config = context.config
        self._findings: list[Finding] = []

    @abstractmethod
    async def scan(self) -> list[Finding]:
        """Execute the scan and return findings.

        Returns:
            List of Finding objects discovered during the scan.
        """
        ...

    @abstractmethod
    async def validate_target(self) -> bool:
        """Validate that the target is scannable by this module.

        Returns:
            True if the target is valid for this scanner.
        """
        ...

    def add_finding(self, finding: Finding) -> None:
        """Add a finding and register it in the scan context."""
        finding.scanner_name = self.name
        self._findings.append(finding)
        self.context.add_finding(finding)
        logger.info(
            "[bold red]FINDING[/] [%s] %s — %s",
            finding.severity.value.upper(),
            finding.title,
            finding.endpoint or finding.url,
        )

    async def run(self) -> list[Finding]:
        """Run the scanner with validation and error handling.

        This is the entry point called by the orchestrator.
        Do NOT override scan() — override this only for special lifecycle needs.
        """
        logger.info("[bold blue]SCANNER[/] Starting [cyan]%s[/]", self.name)

        try:
            is_valid = await self.validate_target()
            if not is_valid:
                logger.warning(
                    "[yellow]SKIP[/] Scanner %s: target not applicable", self.name
                )
                return []
        except Exception as e:
            logger.error("[red]ERROR[/] Scanner %s validation failed: %s", self.name, e)
            return []

        try:
            findings = await self.scan()
            # Ensure all findings are registered in context
            for finding in findings:
                finding.scanner_name = self.name
                self.context.add_finding(finding)
            logger.info(
                "[green]DONE[/] Scanner %s found [bold]%d[/] issue(s)",
                self.name,
                len(findings),
            )
            return findings
        except Exception as e:
            logger.error("[red]FAIL[/] Scanner %s crashed: %s", self.name, e)
            return []
