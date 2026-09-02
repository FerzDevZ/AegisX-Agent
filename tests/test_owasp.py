"""Tests for OWASP Top 10 knowledge base."""

from __future__ import annotations

from aegisx.knowledge.owasp_top10 import (
    OWASP_TOP_10,
    get_category,
    get_category_by_cwe,
    get_remediation_for_cwe,
)


class TestOWASPTop10:
    """Tests for OWASP Top 10 mappings."""

    def test_all_ten_categories_exist(self) -> None:
        """All OWASP Top 10 categories are present."""
        expected_codes = {"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"}
        assert set(OWASP_TOP_10.keys()) == expected_codes

    def test_category_has_required_fields(self) -> None:
        """Each category has name, description, CWE IDs, and remediation."""
        for code, cat in OWASP_TOP_10.items():
            assert cat.code == code, f"{code} has wrong code"
            assert cat.year == 2021, f"{code} has wrong year"
            assert cat.name != "", f"{code} missing name"
            assert cat.description != "", f"{code} missing description"
            assert len(cat.cwe_ids) > 0, f"{code} has no CWE IDs"
            assert cat.remediation != "", f"{code} missing remediation"
            assert len(cat.references) > 0, f"{code} has no references"

    def test_get_category_by_code(self) -> None:
        cat = get_category("A03")
        assert cat is not None
        assert cat.name == "Injection"

    def test_get_category_invalid(self) -> None:
        assert get_category("A99") is None

    def test_cwe_to_owasp_mapping(self) -> None:
        """CWE-89 (SQL Injection) maps to A03 (Injection)."""
        cat = get_category_by_cwe("CWE-89")
        assert cat is not None
        assert cat.code == "A03"

    def test_cwe_79_maps_to_injection(self) -> None:
        """CWE-79 (XSS) maps to A03 (Injection)."""
        cat = get_category_by_cwe("CWE-79")
        assert cat is not None
        assert cat.code == "A03"

    def test_cwe_287_maps_to_auth(self) -> None:
        """CWE-287 (Improper Auth) maps to A07."""
        cat = get_category_by_cwe("CWE-287")
        assert cat is not None
        assert cat.code == "A07"

    def test_cwe_not_found(self) -> None:
        """Unknown CWE returns None."""
        assert get_category_by_cwe("CWE-99999") is None

    def test_remediation_for_known_cwe(self) -> None:
        """Known CWE returns non-empty remediation."""
        remediation = get_remediation_for_cwe("CWE-89")
        assert remediation != ""
        assert "parameterized" in remediation.lower()

    def test_remediation_for_unknown_cwe(self) -> None:
        """Unknown CWE returns generic message."""
        remediation = get_remediation_for_cwe("CWE-99999")
        assert "CWE entry" in remediation

    def test_owasp_a01_has_cwe_862(self) -> None:
        """A01 (Broken Access Control) includes CWE-862 (Missing Authorization)."""
        cat = get_category("A01")
        assert "CWE-862" in cat.cwe_ids

    def test_owasp_a10_has_cwe_918(self) -> None:
        """A10 (SSRF) includes CWE-918."""
        cat = get_category("A10")
        assert "CWE-918" in cat.cwe_ids
