"""Typed results of the metadata-exposure ("what can an observer learn?") view.

The security answer says how well the tunnel is protected.  This answer says what
is still visible *around* it, which is a different question with a different
audience: a privacy officer does not care about the security score, they care
about who can tell that this site talks to that site at 03:12 every night.

Both answers come from the same evidence: the observations here cite fields of the
analysis document (:mod:`fera.analysis`) rather than restating them, so the two
views cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

PRIVACY_SCHEMA_VERSION = "privacy-v1"

Topic = Literal["identity", "configuration", "activity", "cleartext", "inference"]
Exposure = Literal["none", "low", "medium", "high", "unknown"]

#: Contribution of one observation to the 0-100 risk score, by exposure level.
EXPOSURE_POINTS: dict[Exposure, int] = {"high": 4, "medium": 3, "low": 2, "none": 1, "unknown": 0}

EXPOSURE_BANDS: tuple[tuple[int, str], ...] = ((25, "low"), (50, "moderate"), (75, "elevated"), (101, "high"))


def exposure_band(privacy_risk: int) -> str:
    """Band label for a 0-100 exposure score (higher means more exposed)."""
    for threshold, label in EXPOSURE_BANDS:
        if privacy_risk < threshold:
            return label
    return "high"


@dataclass(frozen=True)
class Observation:
    """One thing an off-path observer can learn, with the evidence for it."""

    id: str
    title: str
    topic: Topic
    exposure: Exposure
    finding: str
    evidence: tuple[str, ...] = ()
    mitigations: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Observation:
        return cls(
            id=str(payload.get("id", "")),
            title=str(payload.get("title", "")),
            topic=str(payload.get("topic", "activity")),  # type: ignore[arg-type]
            exposure=str(payload.get("exposure", "unknown")),  # type: ignore[arg-type]
            finding=str(payload.get("finding", "")),
            evidence=tuple(str(item) for item in (payload.get("evidence") or ())),
            mitigations=tuple(str(item) for item in (payload.get("mitigations") or ())),
        )

    @property
    def evaluable(self) -> bool:
        """False when the capture did not contain what this check needs."""
        return self.exposure != "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "topic": self.topic,
            "exposure": self.exposure,
            "finding": self.finding,
            "evidence": list(self.evidence),
            "mitigations": list(self.mitigations),
        }


@dataclass(frozen=True)
class PrivacyReport:
    """Whole-capture privacy view: observations, score, coverage, caveats."""

    analysis_id: str
    observations: tuple[Observation, ...]
    privacy_risk: int
    exposure_level: str
    top_observable: str | None
    coverage: int
    inputs: dict[str, Any] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    schema_version: str = PRIVACY_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> PrivacyReport:
        return cls(
            analysis_id=str(payload.get("analysis_id", "")),
            observations=tuple(Observation.from_dict(item) for item in (payload.get("observations") or ())),
            privacy_risk=int(payload.get("privacy_risk", 0)),
            exposure_level=str(payload.get("exposure_level", "unknown")),
            top_observable=(None if payload.get("top_observable") in (None, "") else str(payload["top_observable"])),
            coverage=int(payload.get("coverage", 0)),
            inputs=dict(payload.get("inputs") or {}),
            limitations=tuple(str(item) for item in (payload.get("limitations") or ())),
            schema_version=str(payload.get("schema_version", PRIVACY_SCHEMA_VERSION)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "analysis_id": self.analysis_id,
            "privacy_risk": self.privacy_risk,
            "exposure_level": self.exposure_level,
            "top_observable": self.top_observable,
            "coverage": self.coverage,
            "observations": [item.to_dict() for item in self.observations],
            "inputs": dict(self.inputs),
            "limitations": list(self.limitations),
        }

    def summary(self) -> dict[str, Any]:
        """Compact view for the bundle ``summary`` block."""
        return {
            "privacy_risk": self.privacy_risk,
            "exposure_level": self.exposure_level,
            "top_observable": self.top_observable,
            "coverage": self.coverage,
            "observations": len(self.observations),
        }


__all__ = [
    "EXPOSURE_BANDS",
    "EXPOSURE_POINTS",
    "PRIVACY_SCHEMA_VERSION",
    "Exposure",
    "Observation",
    "PrivacyReport",
    "Topic",
    "exposure_band",
]
