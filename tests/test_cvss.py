"""Tests for CVSS v3.1 scoring engine."""

from __future__ import annotations

from aegisx.core.config import Severity
from aegisx.reporters.cvss import CVSSScorer, CVSSVector


class TestCVSSVector:
    """Tests for CVSSVector."""

    def test_default_vector(self) -> None:
        v = CVSSVector()
        assert v.attack_vector == "N"
        assert v.attack_complexity == "L"
        assert v.to_vector_string().startswith("CVSS:3.1/")

    def test_to_vector_string(self) -> None:
        v = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        expected = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert v.to_vector_string() == expected


class TestCVSSScorer:
    """Tests for CVSS score calculation."""

    def test_critical_score(self) -> None:
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical)."""
        score = CVSSScorer.from_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8

    def test_high_score(self) -> None:
        """AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N = 8.1 (High)."""
        score = CVSSScorer.from_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N")
        assert score == 8.1

    def test_medium_score(self) -> None:
        """AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N = 4.2 (Medium)."""
        score = CVSSScorer.from_string("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N")
        assert score == 4.2

    def test_low_score(self) -> None:
        """AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N = 2.5 (Low)."""
        score = CVSSScorer.from_string("CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N")
        assert score == 2.5

    def test_none_impact(self) -> None:
        """No confidentiality, integrity, or availability impact = 0.0."""
        score = CVSSScorer.from_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert score == 0.0

    def test_calculate_from_vector(self) -> None:
        """Direct calculation from CVSSVector."""
        v = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        score = CVSSScorer.calculate(v)
        assert score == 9.8

    def test_changed_scope(self) -> None:
        """Changed scope adjusts the formula."""
        score = CVSSScorer.from_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score >= 9.0  # Should be critical

    def test_severity_mapping(self) -> None:
        assert CVSSScorer.severity_from_score(9.8) == Severity.CRITICAL
        assert CVSSScorer.severity_from_score(8.0) == Severity.HIGH
        assert CVSSScorer.severity_from_score(5.0) == Severity.MEDIUM
        assert CVSSScorer.severity_from_score(2.0) == Severity.LOW
        assert CVSSScorer.severity_from_score(0.0) == Severity.INFO

    def test_severity_boundaries(self) -> None:
        """Boundary values for severity classification."""
        assert CVSSScorer.severity_from_score(9.0) == Severity.CRITICAL
        assert CVSSScorer.severity_from_score(8.9) == Severity.HIGH
        assert CVSSScorer.severity_from_score(7.0) == Severity.HIGH
        assert CVSSScorer.severity_from_score(6.9) == Severity.MEDIUM
        assert CVSSScorer.severity_from_score(4.0) == Severity.MEDIUM
        assert CVSSScorer.severity_from_score(3.9) == Severity.LOW
        assert CVSSScorer.severity_from_score(0.1) == Severity.LOW

    def test_from_string_parses_correctly(self) -> None:
        """from_string correctly parses vector components."""
        # All low values
        score = CVSSScorer.from_string("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")
        assert score == 0.0
