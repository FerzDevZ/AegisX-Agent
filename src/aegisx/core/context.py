"""Session context manager for scan state and findings.

Tracks the entire lifecycle of a scan: target info, findings, exploit results,
and scan metadata. Acts as the shared state object passed between agents/modules.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from aegisx.core.config import AegisxConfig, Severity


@dataclass
class Finding:
    """A single vulnerability finding from a scanner."""

    id: str = field(default_factory=lambda: f"VF-{uuid.uuid4().hex[:8].upper()}")
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_id: str = ""  # e.g. "CWE-89"
    owasp_category: str = ""  # e.g. "A03:2021"
    url: str = ""
    endpoint: str = ""
    method: str = ""
    parameter: str = ""
    evidence: str = ""
    payload: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    scanner_name: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def severity_order(self) -> int:
        """Numeric severity for sorting (higher = more severe)."""
        order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return order.get(self.severity, 0)


@dataclass
class ExploitResult:
    """Result of an exploit verification attempt."""

    finding_id: str
    exploit_name: str
    success: bool
    payload: str = ""
    response_snippet: str = ""
    evidence: str = ""
    severity_before: Severity = Severity.INFO
    severity_after: Severity = Severity.INFO
    remediation: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class ScanStats:
    """Statistics for a completed scan."""

    total_requests: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    scan_duration_seconds: float = 0.0
    scanners_used: list[str] = field(default_factory=list)


@dataclass
class ScanContext:
    """Shared state for an entire scan session.

    Passed to every scanner, exploit module, and reporter.
    This is the single source of truth for a scan run.
    """

    config: AegisxConfig = field(default_factory=AegisxConfig)
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    target_url: str = ""
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finished_at: str = ""

    # Collected data
    findings: list[Finding] = field(default_factory=list)
    exploit_results: list[ExploitResult] = field(default_factory=list)
    target_info: dict[str, Any] = field(default_factory=dict)
    crawl_urls: list[str] = field(default_factory=list)

    # Timing
    _start_time: float = field(default_factory=time.time, repr=False)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding and deduplicate by title+endpoint."""
        for existing in self.findings:
            if existing.title == finding.title and existing.endpoint == finding.endpoint:
                # Update severity if new one is higher
                if finding.severity_order > existing.severity_order:
                    existing.severity = finding.severity
                    existing.evidence = finding.evidence
                return
        self.findings.append(finding)

    def add_exploit_result(self, result: ExploitResult) -> None:
        """Add an exploit verification result."""
        self.exploit_results.append(result)

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_stats(self) -> ScanStats:
        """Compute scan statistics."""
        return ScanStats(
            total_findings=len(self.findings),
            critical_count=len(self.get_findings_by_severity(Severity.CRITICAL)),
            high_count=len(self.get_findings_by_severity(Severity.HIGH)),
            medium_count=len(self.get_findings_by_severity(Severity.MEDIUM)),
            low_count=len(self.get_findings_by_severity(Severity.LOW)),
            info_count=len(self.get_findings_by_severity(Severity.INFO)),
            scan_duration_seconds=time.time() - self._start_time,
            scanners_used=list({f.scanner_name for f in self.findings if f.scanner_name}),
        )

    def finish(self) -> ScanStats:
        """Mark scan as finished and return stats."""
        self.finished_at = datetime.now(timezone.utc).isoformat()
        return self.get_stats()

    def to_dict(self) -> dict[str, Any]:
        """Serialize context for report generation."""
        stats = self.get_stats()
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stats": {
                "total_findings": stats.total_findings,
                "critical": stats.critical_count,
                "high": stats.high_count,
                "medium": stats.medium_count,
                "low": stats.low_count,
                "info": stats.info_count,
                "duration_seconds": round(stats.scan_duration_seconds, 2),
                "scanners_used": stats.scanners_used,
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "cvss_score": f.cvss_score,
                    "cwe_id": f.cwe_id,
                    "owasp_category": f.owasp_category,
                    "url": f.url,
                    "endpoint": f.endpoint,
                    "method": f.method,
                    "parameter": f.parameter,
                    "evidence": f.evidence,
                    "payload": f.payload,
                    "remediation": f.remediation,
                    "references": f.references,
                    "scanner_name": f.scanner_name,
                }
                for f in sorted(self.findings, key=lambda x: x.severity_order, reverse=True)
            ],
            "exploit_results": [
                {
                    "finding_id": r.finding_id,
                    "exploit_name": r.exploit_name,
                    "success": r.success,
                    "payload": r.payload,
                    "evidence": r.evidence,
                }
                for r in self.exploit_results
            ],
        }
