"""Markdown report generator for Aegisx-Agent."""

from __future__ import annotations

from aegisx.core.config import Severity
from aegisx.core.context import ScanContext
from aegisx.reporters.base_reporter import BaseReporter


class MarkdownReporter(BaseReporter):
    """Generates a comprehensive Markdown security assessment report."""

    format_name = "markdown"
    file_extension = ".md"

    def generate(self) -> str:
        ctx = self.context
        stats = ctx.get_stats()
        findings = sorted(ctx.findings, key=lambda f: f.severity_order, reverse=True)

        sections = [
            self._header(ctx),
            self._executive_summary(stats),
            self._severity_table(stats),
            self._findings_by_severity(findings, Severity.CRITICAL),
            self._findings_by_severity(findings, Severity.HIGH),
            self._findings_by_severity(findings, Severity.MEDIUM),
            self._findings_by_severity(findings, Severity.LOW),
            self._findings_by_severity(findings, Severity.INFO),
            self._exploit_results(ctx),
            self._footer(),
        ]

        return "\n\n".join(section for section in sections if section)

    def _header(self, ctx: ScanContext) -> str:
        return (
            f"# 🛡️ Aegisx-Agent Security Assessment Report\n\n"
            f"| Field | Value |\n"
            f"|-------|-------|\n"
            f"| **Target** | `{ctx.target_url}` |\n"
            f"| **Scan ID** | `{ctx.scan_id}` |\n"
            f"| **Started** | {ctx.started_at} |\n"
            f"| **Finished** | {ctx.finished_at or 'In Progress'} |"
        )

    def _executive_summary(self, stats: "ScanStats") -> str:
        total = stats.total_findings
        if total == 0:
            return "## Executive Summary\n\n✅ **No vulnerabilities found.** The target appears secure against the scanned attack vectors."

        risk_level = "CRITICAL" if stats.critical_count else "HIGH" if stats.high_count else "MEDIUM" if stats.medium_count else "LOW"
        return (
            f"## Executive Summary\n\n"
            f"⚠️ **Risk Level: {risk_level}**\n\n"
            f"A total of **{total}** security issue(s) were identified across "
            f"{len(stats.scanners_used)} scanner module(s). "
            f"The scan completed in **{stats.scan_duration_seconds:.1f}** seconds."
        )

    def _severity_table(self, stats: "ScanStats") -> str:
        return (
            "## Findings Overview\n\n"
            "| Severity | Count | Action Required |\n"
            "|----------|-------|------------------|\n"
            f"| 🔴 Critical | {stats.critical_count} | Immediate fix — block release |\n"
            f"| 🟠 High | {stats.high_count} | Fix before production |\n"
            f"| 🟡 Medium | {stats.medium_count} | Schedule fix |\n"
            f"| 🔵 Low | {stats.low_count} | Fix when convenient |\n"
            f"| ⚪ Info | {stats.info_count} | Awareness only |"
        )

    def _findings_by_severity(self, findings: list["Finding"], severity: Severity) -> str:
        filtered = [f for f in findings if f.severity == severity]
        if not filtered:
            return ""

        severity_icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }
        icon = severity_icons.get(severity, "")
        title = severity.value.upper()

        lines = [f"## {icon} {title} Findings ({len(filtered)})\n"]

        for f in filtered:
            lines.append(f"### {f.id}: {f.title}\n")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| **Severity** | {f.severity.value.upper()} |")
            lines.append(f"| **CVSS** | {f.cvss_score} |")
            if f.cwe_id:
                lines.append(f"| **CWE** | {f.cwe_id} |")
            if f.owasp_category:
                lines.append(f"| **OWASP** | {f.owasp_category} |")
            if f.endpoint:
                lines.append(f"| **Endpoint** | `{f.method} {f.endpoint}` |")
            if f.parameter:
                lines.append(f"| **Parameter** | `{f.parameter}` |")
            lines.append("")

            if f.description:
                lines.append(f"**Description:** {f.description}\n")
            if f.evidence:
                lines.append(f"**Evidence:**\n```\n{f.evidence}\n```\n")
            if f.payload:
                lines.append(f"**Payload:**\n```\n{f.payload}\n```\n")
            if f.remediation:
                lines.append(f"**Remediation:** {f.remediation}\n")
            if f.references:
                lines.append("**References:**")
                for ref in f.references:
                    lines.append(f"- {ref}")
                lines.append("")

        return "\n".join(lines)

    def _exploit_results(self, ctx: ScanContext) -> str:
        if not ctx.exploit_results:
            return ""

        lines = ["## 🔓 Exploit Verification Results\n"]
        lines.append("| Finding | Exploit | Success | Evidence |")
        lines.append("|---------|---------|---------|----------|")

        for r in ctx.exploit_results:
            status = "✅ YES" if r.success else "❌ NO"
            lines.append(f"| {r.finding_id} | {r.exploit_name} | {status} | {r.evidence[:80]} |")

        return "\n".join(lines)

    def _footer(self) -> str:
        return (
            "---\n\n"
            "*Generated by Aegisx-Agent v0.1.0 — Autonomous Security Scanner*\n\n"
            "*This report should be reviewed by a qualified security professional. "
            "Automated scanning may produce false positives or miss context-specific vulnerabilities.*"
        )
