"""Abstract base reporter interface.

Reporters take scan findings and produce formatted output (Markdown, JSON, SARIF, HTML).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

from aegisx.core.context import ScanContext
from aegisx.utils.logger import get_logger

logger = get_logger("reporter")


class BaseReporter(ABC):
    """Abstract base class for report generators.

    Subclasses MUST implement:
        - format_name: identifier (e.g. "markdown", "json", "sarif")
        - file_extension: output file extension (e.g. ".md")
        - generate(): produce the report content
    """

    format_name: ClassVar[str] = "base"
    file_extension: ClassVar[str] = ".txt"

    def __init__(self, context: ScanContext) -> None:
        self.context = context

    @abstractmethod
    def generate(self) -> str:
        """Generate the report content as a string.

        Returns:
            The complete report as a string.
        """
        ...

    def get_filename(self) -> str:
        """Generate output filename based on scan ID."""
        return f"aegisx-report-{self.context.scan_id}{self.file_extension}"

    def save(self, output_dir: Path | None = None) -> Path:
        """Generate and save the report to a file.

        Args:
            output_dir: Directory to save to. Defaults to config report_output.

        Returns:
            Path to the saved report file.
        """
        if output_dir is None:
            output_dir = self.context.config.report_output

        output_dir.mkdir(parents=True, exist_ok=True)
        filepath = output_dir / self.get_filename()

        content = self.generate()
        filepath.write_text(content, encoding="utf-8")

        logger.info("[green]REPORT[/] Saved %s report to %s", self.format_name, filepath)
        return filepath
