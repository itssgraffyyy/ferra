"""Structured models for the deterministic security assessment stage.

Everything the assessment stage emits is one :class:`SecurityFinding` per rule
plus an aggregate :class:`SecurityAssessment`.  The models deliberately contain
*no* scoring logic: a finding records how many points a rule deducted and why,
and :mod:`fera.security.scoring` is the only place that turns verdicts into a
number.

Two invariants are enforced at construction time instead of being trusted to
callers: a ``NOT_VERIFIABLE`` finding never deducts points, and every finding
states its evidence status so a reader can always tell whether a verdict came
from the wire, from the testbed configuration, or from a model.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..common.errors import ConfigValidationError
from .evidence import EvidenceRef, EvidenceStatus

#: Schema identifier of a serialised :class:`SecurityAssessment`.
SECURITY_SCHEMA_VERSION = "fera_security_assessment_v1"


class SecurityCategory(str, Enum):
    """The fixed set of weighted assessment categories."""

    CRYPTOGRAPHY = "cryptography"
    KEY_EXCHANGE = "key_exchange"
    SA_SECURITY = "sa_security"
    REPLAY_PROTECTION = "replay_protection"
    CONFIGURATION = "configuration"
    METADATA_PRIVACY = "metadata_privacy"

    @property
    def display(self) -> str:
        """Human readable label used in the terminal report."""
        return self.value.replace("_", " ").title()


class FindingStatus(str, Enum):
    """Verdict of one rule."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"

    @property
    def is_weakness(self) -> bool:
        return self in (FindingStatus.FAIL, FindingStatus.WARNING)


class Severity(str, Enum):
    """Severity of a weakness; ``INFO`` never deducts points."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self]


#: Weakest first; the index is also the sort key for "worst finding first".
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)

SEVERITY_RANK: dict[Severity, int] = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}


class RiskLevel(str, Enum):
    """Qualitative band derived from the numeric scores."""

    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return RISK_LEVEL_ORDER.index(self)


#: Least severe first; used for "worst wins" aggregation.
RISK_LEVEL_ORDER: tuple[RiskLevel, ...] = (
    RiskLevel.LOW,
    RiskLevel.MODERATE,
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
)


def worst_risk(levels: Iterable[RiskLevel]) -> RiskLevel:
    """Return the most severe level in ``levels`` (``LOW`` when empty)."""
    present = list(levels)
    if not present:
        return RiskLevel.LOW
    return max(present, key=lambda level: level.rank)


def _as_enum(raw: Any, enum_type: type[Enum], *, field_name: str) -> Any:
    """Parse ``raw`` into ``enum_type`` or fail loudly on schema drift."""
    if isinstance(raw, enum_type):
        return raw
    try:
        return enum_type(raw)
    except ValueError as exc:
        allowed = ", ".join(str(member.value) for member in enum_type)
        raise ConfigValidationError(
            f"{field_name} must be one of: {allowed} (got {raw!r})",
            details={field_name: raw},
        ) from exc


def _as_float(raw: Any, *, field_name: str, low: float, high: float) -> float:
    """Parse ``raw`` into a float inside ``[low, high]``."""
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            f"{field_name} must be a number (got {raw!r})",
            details={field_name: raw},
        ) from exc
    if not low <= value <= high:
        raise ConfigValidationError(
            f"{field_name} must be within [{low}, {high}] (got {value})",
            details={field_name: value},
        )
    return value


@dataclass(frozen=True)
class SecurityFinding:
    """The atomic unit of the assessment: one rule, one verdict, one evidence.

    ``points_deducted`` is the *final* bounded deduction for this finding
    (rule maximum x status factor x evidence factor).  Rules never compute it;
    :mod:`fera.security.scoring` does, which keeps the deduction model in one
    place and makes double counting impossible by construction.
    """

    rule_id: str
    category: SecurityCategory
    title: str
    status: FindingStatus
    severity: Severity
    evidence_status: EvidenceStatus
    confidence: float
    explanation: str
    points_deducted: float = 0.0
    recommendation: str = ""
    dedup_key: str = ""
    evidence: tuple[EvidenceRef, ...] = ()
    references: tuple[str, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ConfigValidationError("a finding needs a rule_id")
        object.__setattr__(self, "confidence", round(float(self.confidence), 4))
        object.__setattr__(self, "points_deducted", round(max(0.0, float(self.points_deducted)), 2))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "references", tuple(self.references))
        if self.status in (FindingStatus.NOT_VERIFIABLE, FindingStatus.PASS) and self.points_deducted:
            raise ConfigValidationError(
                f"{self.rule_id}: {self.status.value} findings must not deduct points "
                f"(got {self.points_deducted})",
                details={"rule_id": self.rule_id, "points_deducted": self.points_deducted},
            )

    @property
    def deducts(self) -> bool:
        """Whether this finding lowers the security score."""
        return self.points_deducted > 0.0

    @property
    def evidence_sources(self) -> tuple[str, ...]:
        return tuple(ref.source for ref in self.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category.value,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "evidence_status": self.evidence_status.value,
            "confidence": self.confidence,
            "points_deducted": self.points_deducted,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "dedup_key": self.dedup_key,
            "evidence": [ref.to_dict() for ref in self.evidence],
            "references": list(self.references),
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> SecurityFinding:
        evidence = document.get("evidence") or ()
        details = document.get("details")
        return cls(
            rule_id=str(document.get("rule_id", "")),
            category=_as_enum(document.get("category"), SecurityCategory, field_name="category"),
            title=str(document.get("title", "")),
            status=_as_enum(document.get("status"), FindingStatus, field_name="status"),
            severity=_as_enum(document.get("severity"), Severity, field_name="severity"),
            evidence_status=_as_enum(
                document.get("evidence_status"), EvidenceStatus, field_name="evidence_status"
            ),
            confidence=_as_float(
                document.get("confidence", 0.0), field_name="confidence", low=0.0, high=1.0
            ),
            explanation=str(document.get("explanation", "")),
            points_deducted=_as_float(
                document.get("points_deducted", 0.0),
                field_name="points_deducted",
                low=0.0,
                high=100.0,
            ),
            recommendation=str(document.get("recommendation", "")),
            dedup_key=str(document.get("dedup_key", "")),
            evidence=tuple(EvidenceRef.from_dict(item) for item in evidence),
            references=tuple(str(item) for item in (document.get("references") or ())),
            details=dict(details) if isinstance(details, Mapping) else {},
        )


@dataclass(frozen=True)
class CategoryScore:
    """Weighted score of one assessment category."""

    category: SecurityCategory
    weight: float
    max_score: float
    deducted: float
    score: float
    status_counts: Mapping[str, int]
    assessed_rules: int
    unverified_rules: int
    coverage: float
    findings: tuple[SecurityFinding, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "weight": self.weight,
            "max_score": self.max_score,
            "deducted": self.deducted,
            "score": self.score,
            "status_counts": dict(self.status_counts),
            "assessed_rules": self.assessed_rules,
            "unverified_rules": self.unverified_rules,
            "coverage": self.coverage,
            "findings": [finding.rule_id for finding in self.findings],
        }


@dataclass(frozen=True)
class ThreatObservation:
    """One entry of the threat matrix.

    ``evidence`` always names the evidence status of the underlying property, so
    a threat that exists only because something could not be verified says so
    explicitly instead of claiming an attack was observed.
    """

    threat_id: str
    threat: str
    category: SecurityCategory
    likelihood: str
    impact: str
    risk: RiskLevel
    evidence: str
    recommendation: str
    rule_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "threat": self.threat,
            "category": self.category.value,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk": self.risk.value,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "rule_ids": list(self.rule_ids),
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> ThreatObservation:
        return cls(
            threat_id=str(document.get("threat_id", "")),
            threat=str(document.get("threat", "")),
            category=_as_enum(document.get("category"), SecurityCategory, field_name="category"),
            likelihood=str(document.get("likelihood", "")),
            impact=str(document.get("impact", "")),
            risk=_as_enum(document.get("risk"), RiskLevel, field_name="risk"),
            evidence=str(document.get("evidence", "")),
            recommendation=str(document.get("recommendation", "")),
            rule_ids=tuple(str(item) for item in (document.get("rule_ids") or ())),
        )


@dataclass(frozen=True)
class Recommendation:
    """A prioritised, deduplicated remediation item."""

    priority: int
    recommendation: str
    reason: str
    severity: Severity
    rule_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "priority": self.priority,
            "recommendation": self.recommendation,
            "reason": self.reason,
            "severity": self.severity.value,
            "rule_ids": list(self.rule_ids),
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> Recommendation:
        return cls(
            priority=int(document.get("priority", 0)),
            recommendation=str(document.get("recommendation", "")),
            reason=str(document.get("reason", "")),
            severity=_as_enum(document.get("severity"), Severity, field_name="severity"),
            rule_ids=tuple(str(item) for item in (document.get("rule_ids") or ())),
        )


@dataclass(frozen=True)
class MetadataExposure:
    """What an observer can learn without breaking any cryptography.

    ``observable`` describes metadata that is visible in the capture; the
    ``ml_*`` fields describe what a model additionally inferred from it and are
    only populated when an inference result was supplied.  ``inference_risk``
    always refers to metadata leakage - never to a cryptographic weakness.
    """

    observable: Mapping[str, Any]
    fingerprintability: str
    inference_risk: RiskLevel
    ml_available: bool
    ml_predicted_class: str | None = None
    ml_confidence: float | None = None
    ml_probabilities: Mapping[str, float] = field(default_factory=dict)
    ml_model: str = ""
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "observable": dict(self.observable),
            "fingerprintability": self.fingerprintability,
            "inference_risk": self.inference_risk.value,
            "ml_available": self.ml_available,
            "ml_predicted_class": self.ml_predicted_class,
            "ml_confidence": self.ml_confidence,
            "ml_probabilities": dict(self.ml_probabilities),
            "ml_model": self.ml_model,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> MetadataExposure:
        probabilities = document.get("ml_probabilities") or {}
        confidence = document.get("ml_confidence")
        return cls(
            observable=dict(document.get("observable") or {}),
            fingerprintability=str(document.get("fingerprintability", "not_assessed")),
            inference_risk=_as_enum(document.get("inference_risk"), RiskLevel, field_name="inference_risk"),
            ml_available=bool(document.get("ml_available", False)),
            ml_predicted_class=document.get("ml_predicted_class"),
            ml_confidence=(
                None
                if confidence is None
                else _as_float(confidence, field_name="ml_confidence", low=0.0, high=1.0)
            ),
            ml_probabilities={str(key): float(value) for key, value in probabilities.items()},
            ml_model=str(document.get("ml_model", "")),
            notes=tuple(str(item) for item in (document.get("notes") or ())),
        )


@dataclass(frozen=True)
class SecurityAssessment:
    """The complete result of one security assessment.

    ``security_score`` and ``risk_score`` always add up to 100, and
    ``evidence_coverage`` is reported next to them so a high score can never be
    read as "safe" when most rules could not be verified.  ``inputs`` records
    which artefacts were consumed (never ground truth: the assessment stage has
    no code path that reads a labelled sample).
    """

    analysis_id: str
    security_score: int
    risk_score: int
    risk_level: RiskLevel
    evidence_coverage: float
    summary: str
    category_scores: tuple[CategoryScore, ...] = ()
    findings: tuple[SecurityFinding, ...] = ()
    threat_matrix: tuple[ThreatObservation, ...] = ()
    recommendations: tuple[Recommendation, ...] = ()
    metadata_exposure: MetadataExposure | None = None
    policy: Mapping[str, Any] = field(default_factory=dict)
    evidence: Mapping[str, int] = field(default_factory=dict)
    inputs: Mapping[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    schema_version: str = SECURITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "category_scores", tuple(self.category_scores))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "threat_matrix", tuple(self.threat_matrix))
        object.__setattr__(self, "recommendations", tuple(self.recommendations))
        object.__setattr__(self, "warnings", tuple(self.warnings))
        object.__setattr__(self, "limitations", tuple(self.limitations))

    @property
    def weaknesses(self) -> tuple[SecurityFinding, ...]:
        """Findings that deducted points, worst first."""
        ranked = (finding for finding in self.findings if finding.status.is_weakness and finding.deducts)
        return tuple(sorted(ranked, key=lambda item: (-item.points_deducted, item.rule_id)))

    @property
    def unverified(self) -> tuple[SecurityFinding, ...]:
        """Rules the capture could not answer (never scored)."""
        return tuple(finding for finding in self.findings if finding.status is FindingStatus.NOT_VERIFIABLE)

    def finding(self, rule_id: str) -> SecurityFinding | None:
        return next((item for item in self.findings if item.rule_id == rule_id), None)

    def category_score(self, category: SecurityCategory) -> CategoryScore | None:
        return next((item for item in self.category_scores if item.category is category), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "analysis_id": self.analysis_id,
            "security_score": self.security_score,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "evidence_coverage": self.evidence_coverage,
            "summary": self.summary,
            "category_scores": [item.to_dict() for item in self.category_scores],
            "findings": [item.to_dict() for item in self.findings],
            "threat_matrix": [item.to_dict() for item in self.threat_matrix],
            "recommendations": [item.to_dict() for item in self.recommendations],
            "metadata_exposure": (self.metadata_exposure.to_dict() if self.metadata_exposure else None),
            "policy": dict(self.policy),
            "evidence": dict(self.evidence),
            "inputs": dict(self.inputs),
            "warnings": list(self.warnings),
            "limitations": list(self.limitations),
        }



    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> SecurityAssessment:
        categories = document.get("category_scores") or ()
        exposure = document.get("metadata_exposure")
        findings = tuple(SecurityFinding.from_dict(item) for item in (document.get("findings") or ()))
        by_rule_id = {finding.rule_id: finding for finding in findings}
        return cls(
            analysis_id=str(document.get("analysis_id", "")),
            security_score=int(document.get("security_score", 0)),
            risk_score=int(document.get("risk_score", 0)),
            risk_level=_as_enum(document.get("risk_level"), RiskLevel, field_name="risk_level"),
            evidence_coverage=_as_float(
                document.get("evidence_coverage", 0.0), field_name="evidence_coverage", low=0.0, high=1.0
            ),
            summary=str(document.get("summary", "")),
            category_scores=tuple(
                CategoryScore(
                    category=_as_enum(item.get("category"), SecurityCategory, field_name="category"),
                    weight=float(item.get("weight", 0.0)),
                    max_score=float(item.get("max_score", 0.0)),
                    deducted=float(item.get("deducted", 0.0)),
                    score=float(item.get("score", 0.0)),
                    status_counts=dict(item.get("status_counts") or {}),
                    assessed_rules=int(item.get("assessed_rules", 0)),
                    unverified_rules=int(item.get("unverified_rules", 0)),
                    coverage=float(item.get("coverage", 0.0)),
                    findings=tuple(
                        by_rule_id[rule_id] for rule_id in (item.get("findings") or ()) if rule_id in by_rule_id
                    ),
                )
                for item in categories
            ),
            findings=findings,
            threat_matrix=tuple(
                ThreatObservation.from_dict(item) for item in (document.get("threat_matrix") or ())
            ),
            recommendations=tuple(
                Recommendation.from_dict(item) for item in (document.get("recommendations") or ())
            ),
            metadata_exposure=(MetadataExposure.from_dict(exposure) if isinstance(exposure, Mapping) else None),
            policy=dict(document.get("policy") or {}),
            evidence={str(key): int(value) for key, value in (document.get("evidence") or {}).items()},
            inputs=dict(document.get("inputs") or {}),
            warnings=tuple(str(item) for item in (document.get("warnings") or ())),
            limitations=tuple(str(item) for item in (document.get("limitations") or ())),
            schema_version=str(document.get("schema_version", SECURITY_SCHEMA_VERSION)),
        )

    def render_text(self) -> str:
        """Render the compact human readable report."""
        lines = [
            f"security score : {self.security_score}/100  (risk {self.risk_score} - {self.risk_level.value})",
            f"evidence cover : {self.evidence_coverage:.0%} verifiable of {len(self.findings)} rule(s)",
            f"summary        : {self.summary}",
            "",
            "categories:",
        ]
        for item in self.category_scores:
            lines.append(
                f"  {item.category.display:<20}: {item.score:>6.1f}/{item.max_score:<6.1f} "
                f"weight {item.weight:.2f}  cover {item.coverage:.0%}"
            )
        if self.weaknesses:
            lines.extend(["", "weaknesses:"])
            for finding in self.weaknesses:
                lines.append(
                    f"  [{finding.severity.value}] {finding.rule_id} {finding.title} "
                    f"(-{finding.points_deducted:.1f}, {finding.evidence_status.value})"
                )
                lines.append(f"      {finding.explanation}")
        unverified = self.unverified
        if unverified:
            lines.extend(["", "not verifiable from this capture (0 points, lowers coverage):"])
            for finding in unverified:
                lines.append(f"  {finding.rule_id} {finding.title}: {finding.explanation}")
        if self.threat_matrix:
            lines.extend(["", "threat matrix:"])
            for threat in self.threat_matrix:
                lines.append(
                    f"  [{threat.risk.value}] {threat.threat_id} {threat.threat} "
                    f"(likelihood {threat.likelihood}, impact {threat.impact})"
                )
                lines.append(f"      evidence: {threat.evidence}")
        if self.recommendations:
            lines.extend(["", "recommendations:"])
            for advice in self.recommendations:
                lines.append(f"  {advice.priority}. [{advice.severity.value}] {advice.recommendation}")
                lines.append(f"     why: {advice.reason} ({', '.join(advice.rule_ids)})")
        if self.metadata_exposure is not None:
            lines.extend(["", "metadata exposure:"])
            exposure = self.metadata_exposure
            lines.append(f"  fingerprintability : {exposure.fingerprintability}")
            lines.append(f"  inference risk     : {exposure.inference_risk.value}")
            if exposure.ml_available:
                lines.append(
                    f"  ml prediction      : {exposure.ml_predicted_class} "
                    f"(confidence {exposure.ml_confidence:.2f}) [{exposure.ml_model}]"
                )
            else:
                lines.append("  ml prediction      : none supplied (INFERRED rules are NOT_VERIFIABLE)")
        if self.limitations:
            lines.extend(["", "limitations:"])
            lines.extend(f"  - {item}" for item in self.limitations)
        return "\n".join(lines)


__all__ = [
    "RISK_LEVEL_ORDER",
    "SECURITY_SCHEMA_VERSION",
    "SEVERITY_ORDER",
    "SEVERITY_RANK",
    "CategoryScore",
    "EvidenceRef",
    "EvidenceStatus",
    "FindingStatus",
    "MetadataExposure",
    "Recommendation",
    "RiskLevel",
    "SecurityAssessment",
    "SecurityCategory",
    "SecurityFinding",
    "Severity",
    "ThreatObservation",
    "worst_risk",
]

