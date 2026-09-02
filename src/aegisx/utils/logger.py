"""Structured logging for Aegisx-Agent.

Provides colored, structured logs via Rich for terminal output,
and structured JSON logs for machine consumption.
"""

from __future__ import annotations

import logging
import sys

from rich.console import Console
from rich.logging import RichHandler

console = Console(stderr=True)

_LOG_FORMAT = "%(message)s"
_DATE_FORMAT = "%H:%M:%S"

_configured = False


def setup_logging(level: str = "INFO", verbose: bool = False) -> logging.Logger:
    """Configure and return the Aegisx logger.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR).
        verbose: If True, show DEBUG level output.

    Returns:
        Configured logger instance.
    """
    global _configured  # noqa: PLW0603

    logger = logging.getLogger("aegisx")

    if _configured:
        return logger

    log_level = logging.DEBUG if verbose else getattr(logging, level.upper(), logging.INFO)

    handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
        tracebacks_show_locals=verbose,
    )
    handler.setLevel(log_level)

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)
    handler.setFormatter(formatter)

    logger.setLevel(log_level)
    logger.addHandler(handler)
    logger.propagate = False

    _configured = True
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger for a specific module."""
    return logging.getLogger(f"aegisx.{name}")
