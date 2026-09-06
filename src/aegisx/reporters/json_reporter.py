"""JSON report generator for machine-readable output."""

from __future__ import annotations

import json

from aegisx.reporters.base_reporter import BaseReporter


class JSONReporter(BaseReporter):
    """Generates a machine-readable JSON security report."""

    format_name = "json"
    file_extension = ".json"

    def generate(self) -> str:
        """Serialize the full scan context (stats + findings) as pretty-printed JSON."""
        data = self.context.to_dict()
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)
