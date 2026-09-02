"""SARIF (Static Analysis Results Interchange Format) reporter.

Generates SARIF v2.1.0 compatible output for GitHub Code Scanning integration.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from aegisx.core.context import ScanContext
from aegisx.reporters.base_reporter import BaseReporter


class SARIFReporter(BaseReporter):
    """Generates SARIF v2.1.0 format output for GitHub integration."""

    format_name = "sarif"
    file_extension = ".sarif"

    def generate(self) -> str:
        ctx = self.context
        findings = sorted(ctx.findings, key=lambda f: f.severity_order, reverse=True)

        results = []
        rules = []

        for finding in findings:
            result = self._finding_to_sarif_result(finding)
            results.append(result)
            rule = self._finding_to_sarif_rule(finding)
            rules.append(rule)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Aegisx-Agent",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/aegisx/aegisx-agent",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": ctx.started_at,
                            "endTimeUtc": ctx.finished_at
                            or datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                }
            ],
        }

        return json.dumps(sarif, indent=2, ensure_ascii=False, default=str)

    def _finding_to_sarif_result(self, finding: "Finding") -> dict:
        """Convert a Finding to SARIF result format."""
        level_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "none",
        }

        result: dict = {
            "ruleId": finding.cwe_id or f"AEGISX-{finding.id}",
            "level": level_map.get(finding.severity.value, "warning"),
            "message": {"text": finding.description or finding.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.endpoint or finding.url or "unknown",
                            "uriBaseId": "%SRCROOT%",
                        }
                    }
                }
            ],
            "properties": {
                "aegisx_id": finding.id,
                "cvss_score": finding.cvss_score,
                "owasp_category": finding.owasp_category,
                "severity": finding.severity.value,
            },
        }

        if finding.evidence:
            result["properties"]["evidence"] = finding.evidence
        if finding.payload:
            result["properties"]["payload"] = finding.payload
        if finding.remediation:
            result["fixes"] = [
                {
                    "description": {"text": finding.remediation},
                    "artifactChanges": [],
                }
            ]

        return result

    def _finding_to_sarif_rule(self, finding: "Finding") -> dict:
        """Convert a Finding to SARIF rule definition."""
        return {
            "id": finding.cwe_id or f"AEGISX-{finding.id}",
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "helpUri": finding.references[0] if finding.references else None,
            "properties": {
                "precision": "very-high",
                "problem.severity": finding.severity.value,
            },
        }
