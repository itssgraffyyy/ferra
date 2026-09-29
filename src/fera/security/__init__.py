"""Prompt 4: deterministic, evidence-graded security assessment.

This package turns the structured output of the protocol analyser
(:mod:`fera.analysis`), the statistical classifier (:mod:`fera.ml`) and the
testbed's own configuration into findings, a threat matrix and a score.  It
contains no protocol parsing and no machine learning of its own; it also never
reads ground truth, so a score can never be influenced by the answer key.

Every verdict is graded by :class:`~fera.security.evidence.EvidenceStatus`:

``OBSERVED``
    the property is visible in clear text in the capture;
``CONFIGURED``
    the property comes from the testbed configuration, not from the wire;
``INFERRED``
    the property was produced by the ML stage, together with its confidence;
``NOT_VERIFIABLE``
    a passive capture cannot decide the property at all.

Only the first three may change the score.  ``NOT_VERIFIABLE`` lowers
``evidence_coverage`` instead, which keeps "unknown" visibly different from
"weak" and from "fine".

The pipeline runs in one direction and each stage is a separate module:

``context``
    adapts an analysis document (plus optional configuration and prediction)
    into :class:`~fera.security.context.AssessmentContext`;
``rules``
    holds the catalogue; every rule is a pure function of that context;
``scoring``
    is the only place verdicts become points
    (:func:`~fera.security.scoring.score_rules`);
``models``
    is what a caller serialises, and :mod:`fera.security.policy` holds the
    generated tables both of them read.
"""

from __future__ import annotations

from .context import (
    AlgorithmUse,
    AssessmentContext,
    ConfiguredParameters,
    EspFlowObservation,
    ExchangeObservation,
    ProposalObservation,
    SequenceObservation,
)
from .evidence import (
    EVIDENCE_PRECEDENCE,
    EvidenceRef,
    EvidenceStatus,
    count_evidence,
    status_from_evidence_kind,
    strongest,
)
from .ml_contract import TrafficPrediction, load_prediction, prediction_from_analysis
from .models import (
    SECURITY_SCHEMA_VERSION,
    SEVERITY_ORDER,
    CategoryScore,
    FindingStatus,
    MetadataExposure,
    Recommendation,
    RiskLevel,
    SecurityAssessment,
    SecurityCategory,
    SecurityFinding,
    Severity,
    ThreatObservation,
    worst_risk,
)
from .policy import (
    CATEGORY_WEIGHTS,
    COVERAGE_WEIGHTS,
    DH_POLICIES,
    ENCRYPTION_POLICIES,
    EVIDENCE_FACTORS,
    INTEGRITY_POLICIES,
    POLICY_ALIASES,
    PRF_POLICIES,
    RISK_BANDS,
    STATUS_FACTORS,
    TIER_BASE_POINTS,
    TIER_SEVERITY,
    AlgorithmPolicy,
    LifetimeCeilings,
    MetadataThresholds,
    PolicyTier,
    canonical_dh,
    canonical_encryption,
    canonical_integrity,
    canonical_prf,
    check_policy,
    dh_policy,
    encryption_policy,
    evidence_factor,
    integrity_policy,
    is_aead,
    policy_catalogue,
    prf_policy,
    risk_level,
)
from .rules import (
    EXPOSURE_POINTS,
    GAP_POINTS,
    INFERENCE_POINTS,
    INFORMATIONAL_POINTS,
    RULE_INDEX,
    RULES,
    STANDARD_POINTS,
    TIER_RANK,
    Rule,
    RuleVerdict,
    applicable_rules,
    describe_rules,
)
from .scoring import (
    PROPERTY_STRENGTH,
    ScoredFinding,
    ScoringResult,
    apply_rule,
    base_points_for,
    deduction_model,
    score_rules,
    verdict_evidence_status,
)

__all__ = [
    "CATEGORY_WEIGHTS",
    "COVERAGE_WEIGHTS",
    "DH_POLICIES",
    "ENCRYPTION_POLICIES",
    "EVIDENCE_FACTORS",
    "EVIDENCE_PRECEDENCE",
    "EXPOSURE_POINTS",
    "GAP_POINTS",
    "INFERENCE_POINTS",
    "INFORMATIONAL_POINTS",
    "INTEGRITY_POLICIES",
    "POLICY_ALIASES",
    "PRF_POLICIES",
    "PROPERTY_STRENGTH",
    "RISK_BANDS",
    "RULE_INDEX",
    "RULES",
    "SECURITY_SCHEMA_VERSION",
    "SEVERITY_ORDER",
    "STANDARD_POINTS",
    "STATUS_FACTORS",
    "TIER_BASE_POINTS",
    "TIER_RANK",
    "TIER_SEVERITY",
    "AlgorithmPolicy",
    "AlgorithmUse",
    "AssessmentContext",
    "CategoryScore",
    "ConfiguredParameters",
    "EspFlowObservation",
    "EvidenceRef",
    "EvidenceStatus",
    "ExchangeObservation",
    "FindingStatus",
    "LifetimeCeilings",
    "MetadataExposure",
    "MetadataThresholds",
    "PolicyTier",
    "ProposalObservation",
    "Recommendation",
    "RiskLevel",
    "Rule",
    "RuleVerdict",
    "ScoredFinding",
    "ScoringResult",
    "SecurityAssessment",
    "SecurityCategory",
    "SecurityFinding",
    "SequenceObservation",
    "Severity",
    "ThreatObservation",
    "TrafficPrediction",
    "applicable_rules",
    "apply_rule",
    "base_points_for",
    "canonical_dh",
    "canonical_encryption",
    "canonical_integrity",
    "canonical_prf",
    "check_policy",
    "count_evidence",
    "deduction_model",
    "describe_rules",
    "dh_policy",
    "encryption_policy",
    "evidence_factor",
    "integrity_policy",
    "is_aead",
    "load_prediction",
    "policy_catalogue",
    "prediction_from_analysis",
    "prf_policy",
    "risk_level",
    "score_rules",
    "status_from_evidence_kind",
    "strongest",
    "verdict_evidence_status",
    "worst_risk",
]
