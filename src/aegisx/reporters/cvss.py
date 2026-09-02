"""CVSS v3.1 scoring engine for Aegisx-Agent.

Calculates CVSS base scores from vector components.
Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from aegisx.core.config import Severity


@dataclass
class CVSSVector:
    """CVSS v3.1 vector components."""

    attack_vector: str = "N"  # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = "L"  # L=Low, H=High
    privileges_required: str = "N"  # N=None, L=Low, H=High
    user_interaction: str = "N"  # N=None, R=Required
    scope: str = "U"  # U=Unchanged, C=Changed
    confidentiality: str = "N"  # N=None, L=Low, H=High
    integrity: str = "N"  # N=None, L=Low, H=High
    availability: str = "N"  # N=None, L=Low, H=High

    def to_vector_string(self) -> str:
        """Render as CVSS vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/"
            f"A:{self.availability}"
        )


# CVSS v3.1 lookup tables
_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_UI_WEIGHTS = {"N": 0.85, "R": 0.62}

_PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

_IMPACT_WEIGHTS = {"N": 0.00, "L": 0.22, "H": 0.56}


class CVSSScorer:
    """CVSS v3.1 base score calculator."""

    @staticmethod
    def calculate(vector: CVSSVector) -> float:
        """Calculate CVSS v3.1 base score from vector components.

        Args:
            vector: CVSS vector components.

        Returns:
            Base score rounded to one decimal place (0.0 - 10.0).
        """
        # Exploitability sub-score
        av = _AV_WEIGHTS.get(vector.attack_vector, 0.85)
        ac = _AC_WEIGHTS.get(vector.attack_complexity, 0.77)
        ui = _UI_WEIGHTS.get(vector.user_interaction, 0.85)

        if vector.scope == "U":
            pr = _PR_WEIGHTS_UNCHANGED.get(vector.privileges_required, 0.85)
        else:
            pr = _PR_WEIGHTS_CHANGED.get(vector.privileges_required, 0.85)

        exploitability = 8.22 * av * ac * pr * ui

        # Impact sub-score
        c = _IMPACT_WEIGHTS.get(vector.confidentiality, 0.00)
        i = _IMPACT_WEIGHTS.get(vector.integrity, 0.00)
        a = _IMPACT_WEIGHTS.get(vector.availability, 0.00)

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        if vector.scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Base score
        if impact <= 0:
            return 0.0

        if vector.scope == "U":
            base_score = min(exploitability + impact, 10.0)
        else:
            base_score = min(1.08 * (exploitability + impact), 10.0)

        return round(math.ceil(base_score * 10) / 10, 1)

    @staticmethod
    def severity_from_score(score: float) -> Severity:
        """Map a CVSS score to a severity label."""
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score >= 0.1:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def from_string(vector_string: str) -> float:
        """Parse a CVSS vector string and calculate the score.

        Args:
            vector_string: e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        Returns:
            Base score.
        """
        components = {}
        for part in vector_string.split("/"):
            if ":" in part:
                key, value = part.split(":", 1)
                components[key] = value

        vector = CVSSVector(
            attack_vector=components.get("AV", "N"),
            attack_complexity=components.get("AC", "L"),
            privileges_required=components.get("PR", "N"),
            user_interaction=components.get("UI", "N"),
            scope=components.get("S", "U"),
            confidentiality=components.get("C", "N"),
            integrity=components.get("I", "N"),
            availability=components.get("A", "N"),
        )

        return CVSSScorer.calculate(vector)
