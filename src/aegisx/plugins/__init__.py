"""Plugin manager for Aegisx-Agent.

Uses pluggy for a clean, extensible plugin architecture.
Community developers can write custom scanners without modifying core code.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from aegisx.utils.logger import get_logger

if TYPE_CHECKING:
    from aegisx.scanners.base_scanner import BaseScanner
    from aegisx.exploits.base_exploit import BaseExploit
    from aegisx.reporters.base_reporter import BaseReporter

logger = get_logger("plugins")


class PluginManager:
    """Manages discovery, loading, and registration of scanner/exploit/reporter plugins.

    Plugin discovery:
        1. Built-in modules (scanners/, exploits/, reporters/ in this package)
        2. Entry points: packages can register via `aegisx.scanners` entry point
        3. Plugin directories: scan configured directories for Python files
    """

    def __init__(self) -> None:
        self._scanner_classes: dict[str, type[BaseScanner]] = {}
        self._exploit_classes: dict[str, type[BaseExploit]] = {}
        self._reporter_classes: dict[str, type[BaseReporter]] = {}

    def register_scanner(self, name: str, scanner_cls: type[BaseScanner]) -> None:
        """Register a scanner class."""
        if name in self._scanner_classes:
            logger.warning("Overwriting scanner plugin: %s", name)
        self._scanner_classes[name] = scanner_cls
        logger.debug("Registered scanner: %s", name)

    def register_exploit(self, name: str, exploit_cls: type[BaseExploit]) -> None:
        """Register an exploit class."""
        if name in self._exploit_classes:
            logger.warning("Overwriting exploit plugin: %s", name)
        self._exploit_classes[name] = exploit_cls
        logger.debug("Registered exploit: %s", name)

    def register_reporter(self, name: str, reporter_cls: type[BaseReporter]) -> None:
        """Register a reporter class."""
        if name in self._reporter_classes:
            logger.warning("Overwriting reporter plugin: %s", name)
        self._reporter_classes[name] = reporter_cls
        logger.debug("Registered reporter: %s", name)

    def get_scanner(self, name: str) -> type[BaseScanner] | None:
        """Get a scanner class by name."""
        return self._scanner_classes.get(name)

    def get_exploit(self, name: str) -> type[BaseExploit] | None:
        """Get an exploit class by name."""
        return self._exploit_classes.get(name)

    def get_reporter(self, name: str) -> type[BaseReporter] | None:
        """Get a reporter class by name."""
        return self._reporter_classes.get(name)

    def list_scanners(self) -> list[str]:
        """List all registered scanner names."""
        return list(self._scanner_classes.keys())

    def list_exploits(self) -> list[str]:
        """List all registered exploit names."""
        return list(self._exploit_classes.keys())

    def list_reporters(self) -> list[str]:
        """List all registered reporter names."""
        return list(self._reporter_classes.keys())

    def load_entry_points(self) -> None:
        """Discover and load plugins registered via entry points.

        Third-party packages can register plugins by adding to their pyproject.toml:

            [project.entry-points."aegisx.scanners"]
            my_scanner = "my_package.scanner:MyScanner"
        """
        all_eps = importlib.metadata.entry_points()

        for ep in all_eps.select(group="aegisx.scanners"):
            try:
                cls = ep.load()
                self.register_scanner(ep.name, cls)
                logger.info("Loaded scanner plugin from entry point: %s", ep.name)
            except (ImportError, AttributeError, TypeError) as e:
                logger.error("Failed to load scanner plugin '%s': %s", ep.name, type(e).__name__)

        for ep in all_eps.select(group="aegisx.exploits"):
            try:
                cls = ep.load()
                self.register_exploit(ep.name, cls)
                logger.info("Loaded exploit plugin from entry point: %s", ep.name)
            except (ImportError, AttributeError, TypeError) as e:
                logger.error("Failed to load exploit plugin '%s': %s", ep.name, type(e).__name__)

        for ep in all_eps.select(group="aegisx.reporters"):
            try:
                cls = ep.load()
                self.register_reporter(ep.name, cls)
                logger.info("Loaded reporter plugin from entry point: %s", ep.name)
            except (ImportError, AttributeError, TypeError) as e:
                logger.error("Failed to load reporter plugin '%s': %s", ep.name, type(e).__name__)

    def load_from_directory(self, directory: Path) -> None:
        """Scan a directory for Python files and load plugins from them.

        Each .py file should define a module-level `register(manager)` function
        that calls manager.register_scanner/register_exploit/register_reporter.
        """
        if not directory.exists():
            return

        for py_file in directory.glob("*.py"):
            if py_file.name.startswith("_"):
                continue

            module_name = f"aegisx_plugins.{py_file.stem}"
            try:
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                if hasattr(module, "register"):
                    module.register(self)
                    logger.info("Loaded plugin from file: %s", py_file.name)
            except (ImportError, AttributeError, TypeError, SyntaxError) as e:
                logger.error("Failed to load plugin file '%s': %s", py_file.name, type(e).__name__)

    def summary(self) -> dict[str, list[str]]:
        """Return a summary of all loaded plugins."""
        return {
            "scanners": self.list_scanners(),
            "exploits": self.list_exploits(),
            "reporters": self.list_reporters(),
        }


# Global plugin manager instance
_plugin_manager: PluginManager | None = None


def get_plugin_manager() -> PluginManager:
    """Get or create the global plugin manager."""
    global _plugin_manager  # noqa: PLW0603
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager
