"""Turning one analysed capture into a published assessment.

The engine is a straight line, and this module is where the line is drawn::

    analysis document -> AssessmentContext -> rules -> score_rules
                                                         |
                          threat matrix + recommendations + metadata exposure
                                                         |
                                                SecurityAssessment

Nothing here decides anything.  The rules decide, :func:`~fera.security.scoring.score_rules`
prices them, and this module collects what already exists, adding only the three
things that are pure presentation: the summary sentence, the limitations list and
the metadata exposure block.  ``security_score`` is the rounded headline; the
per-category ledger keeps the exact arithmetic so a reader can reconcile the two.

Ground truth is never an input.  ``inputs`` records what was consumed and says in
words that the answer key was not one of them.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..analysis.models import ProtocolAnalysis
from .context import AssessmentContext, ConfiguredParameters
from .ml_contract import TrafficPrediction
from .models import (
    FindingStatus,
    MetadataExposure,
    Recommendation,
    RiskLevel,
    SecurityAssessment,
    SecurityFinding,
)
from .policy import (
    METADATA_THRESHOLDS,
    MIN_PACKETS_FOR_SEQUENCE_ANALYSIS,
    POLICY_ID,
    POLICY_VERSION,
    risk_level,
)
from .rules import RULES, Rule, applicable_rules
from .scoring import ScoringResult, deduction_model, score_rules
from .threats import threat_matrix

#: Fingerprintability vocabulary.  ``not_assessed`` means there was no traffic to
#: measure, which is different from "measured and found unrevealing".
FINGERPRINTABILITY_LEVELS: tuple[str, ...] = ("not_assessed", "LOW", "MODERATE", "HIGH")

#: At or above this confidence the model has labelled the traffic convincingly
#: enough that the inference risk is banded high rather than moderate.
INFERENCE_RISK_CONFIDENCE_HIGH = 0.8

#: Dimensions of metadata an observer can measure; at or above these counts the
#: traffic is considered markedly more fingerprintable.
FINGERPRINT_DIMENSIONS_HIGH = 4
FINGERPRINT_DIMENSIONS_MODERATE = 2


def assess_security(
    analysis: ProtocolAnalysis | Mapping[str, Any],
    *,
    configured: ConfiguredParameters | Mapping[str, Any] | None = None,
    traffic: TrafficPrediction | Mapping[str, Any] | str | None = None,
    rules: Sequence[Rule] | None = None,
    analysis_id: str | None = None,
    inputs: Mapping[str, Any] | None = None,
) -> SecurityAssessment:
    """Assess one analysed capture end to end.

    ``rules`` exists for tests and for focused runs; the default is every rule
    whose applicability predicate accepts this capture, in catalogue order.
    ``configured`` is the testbed's own configuration (graded ``CONFIGURED``) and
    ``traffic`` an ML prediction (graded ``INFERRED``); both are optional, and
    omitting them costs coverage rather than points.
    """
    context = AssessmentContext.from_analysis(
        analysis, configured=configured, traffic=traffic, analysis_id=analysis_id
    )
    applied = tuple(rules) if rules is not None else applicable_rules(context)
    result = score_rules(context, applied)
    security_score = int(round(result.security_score))
    band = risk_level(security_score)
    return SecurityAssessment(
        analysis_id=context.analysis_id,
        security_score=security_score,
        risk_score=100 - security_score,
        risk_level=band,
        evidence_coverage=result.evidence_coverage,
        summary=summary_for(context, result, security_score, band),
        category_scores=result.categories,
        findings=result.findings,
        threat_matrix=threat_matrix(result.findings),
        recommendations=recommendations_for(result.findings),
        metadata_exposure=metadata_exposure(context),
        policy=policy_summary(applied),
        evidence=result.evidence_counts,
        inputs=provenance(context, inputs),
        warnings=context.analysis_warnings,
        limitations=limitations_for(context, result),
    )


def recommendations_for(findings: Sequence[SecurityFinding]) -> tuple[Recommendation, ...]:
    """Turn charged weaknesses into a prioritised to-do list.

    One entry per distinct piece of advice: four rules that all say "use AES-GCM"
    are one action, not four, and the entry records every rule that asked for it.
    Priority follows severity first and the size of the deduction second, so the
    list can be worked from the top down.  Rules that passed, and rules that
    could not be verified, advise nothing.
    """
    grouped: dict[str, list[SecurityFinding]] = {}
    for finding in findings:
        if not finding.status.is_weakness or not finding.recommendation:
            continue
        grouped.setdefault(finding.recommendation, []).append(finding)

    def rank(item: tuple[str, list[SecurityFinding]]) -> tuple[int, float, str]:
        members = item[1]
        return (
            -max(member.severity.rank for member in members),
            -max(member.points_deducted for member in members),
            item[0],
        )

    ordered = sorted(grouped.items(), key=rank)
    plan: list[Recommendation] = []
    for priority, (advice, members) in enumerate(ordered, start=1):
        lead = max(members, key=lambda member: (member.severity.rank, member.points_deducted))
        plan.append(
            Recommendation(
                priority=priority,
                recommendation=advice,
                reason=lead.explanation,
                severity=max((member.severity for member in members), key=lambda severity: severity.rank),
                rule_ids=tuple(sorted({member.rule_id for member in members})),
            )
        )
    return tuple(plan)


def observable_dimensions(context: AssessmentContext) -> tuple[str, ...]:
    """What an observer can measure without breaking any cryptography.

    Each dimension is a question the capture answers with a counted fact rather
    than a guess: how many associations exist, how much was sent, whether sizes
    or timings were visible at all, and whether a NAT sits in the path.  A
    dimension missing from this list is missing because the capture does not
    contain the fact, not because the traffic was found to be unremarkable.
    """
    dimensions: list[str] = []
    if context.spi_count > 1:
        dimensions.append("association_split")
    if context.esp_packets >= MIN_PACKETS_FOR_SEQUENCE_ANALYSIS:
        dimensions.append("volume")
    if any(flow.src and flow.dst for flow in context.esp_flows):
        dimensions.append("peer_addresses")
    if any(flow.udp_encapsulated for flow in context.esp_flows):
        dimensions.append("nat_binding")
    features = context.traffic.features if context.traffic is not None else {}
    if any(name in features for name in ("esp_len_min", "esp_len_max", "esp_len_std", "esp_avg_len")):
        dimensions.append("payload_sizes")
    if any(name in features for name in ("esp_iat_mean_s", "esp_iat_std_s", "esp_span_s")):
        dimensions.append("timing")
    return tuple(dimensions)


def fingerprintability(context: AssessmentContext) -> str:
    """How many independent dimensions of the metadata are actually measurable."""
    count = len(observable_dimensions(context))
    if count == 0:
        return "not_assessed"
    if count >= FINGERPRINT_DIMENSIONS_HIGH:
        return "HIGH"
    if count >= FINGERPRINT_DIMENSIONS_MODERATE:
        return "MODERATE"
    return "LOW"


def inference_risk(context: AssessmentContext) -> RiskLevel:
    """Risk that the metadata alone identifies what the traffic is.

    A complete prediction is the strongest statement available here: the metadata
    has already been used to label the traffic successfully, so the band follows
    the model's own confidence.  Without one, the band follows how many
    dimensions there are to measure at all - an unverifiable inference is not
    evidence of safety, and this field never claims otherwise.
    """
    prediction = context.traffic
    if prediction is not None and prediction.complete_metadata:
        if prediction.confidence >= INFERENCE_RISK_CONFIDENCE_HIGH:
            return RiskLevel.HIGH
        if prediction.confidence >= METADATA_THRESHOLDS.prediction_confidence_min:
            return RiskLevel.MODERATE
        return RiskLevel.LOW
    if len(observable_dimensions(context)) >= FINGERPRINT_DIMENSIONS_HIGH:
        return RiskLevel.MODERATE
    return RiskLevel.LOW


def metadata_exposure(context: AssessmentContext) -> MetadataExposure:
    """The metadata block: counted facts first, inferences second.

    ``observable`` is always populated from the capture.  The ``ml_*`` fields are
    filled only when a prediction carried enough metadata to interpret it, so a
    bare guess is reported as unverifiable instead of being given a confidence
    number the report cannot justify.
    """
    observable = context.metadata_summary()
    prediction = context.traffic
    available = prediction is not None and prediction.complete_metadata
    notes: list[str] = []
    if prediction is None:
        notes.append(
            "no traffic-class prediction was supplied, so nothing was inferred from the metadata: "
            "the inference rule reports NOT_VERIFIABLE rather than assume safety"
        )
    elif not available:
        notes.append(
            f"a prediction of class {prediction.predicted_class!r} at confidence {prediction.confidence:.2f} "
            "was supplied without a model id, version or feature schema, so it is reported as not "
            "verifiable instead of being charged against the deployment"
        )
    else:
        notes.append(
            f"the prediction comes from {prediction.model_id}@{prediction.model_version} "
            f"(feature schema {prediction.feature_schema}); it is evidence of class INFERRED and is "
            "discounted by its confidence"
        )
        if prediction.confidence < METADATA_THRESHOLDS.prediction_confidence_min:
            notes.append(
                f"confidence {prediction.confidence:.2f} is below the reporting threshold "
                f"{METADATA_THRESHOLDS.prediction_confidence_min:.2f}: the exposure is stated as unproven"
            )
    dimensions = observable_dimensions(context)
    notes.append(f"observable dimensions: {', '.join(dimensions) or 'none'}")
    truncated = int(context.scan.get("truncated_frames", 0) or 0)
    if truncated:
        notes.append(f"{truncated} frame(s) were truncated, so the metadata is incomplete")
    ml_predicted_class: str | None = None
    ml_confidence: float | None = None
    ml_probabilities: dict[str, float] = {}
    ml_model = ""
    if prediction is not None and available:
        ml_predicted_class = prediction.predicted_class
        ml_confidence = prediction.confidence
        ml_probabilities = {str(key): float(value) for key, value in prediction.probabilities.items()}
        ml_model = f"{prediction.model_id}@{prediction.model_version}"
    return MetadataExposure(
        observable=observable,
        fingerprintability=fingerprintability(context),
        inference_risk=inference_risk(context),
        ml_available=available,
        ml_predicted_class=ml_predicted_class,
        ml_confidence=ml_confidence,
        ml_probabilities=ml_probabilities,
        ml_model=ml_model,
        notes=tuple(notes),
    )


def summary_for(
    context: AssessmentContext, result: ScoringResult, security_score: int, band: RiskLevel
) -> str:
    """One sentence a reader can quote without reading the ledger.

    The score is never stated bare: it travels with the number of rules behind
    it, how many of them charged points, and how many could not be answered.
    """
    weaknesses = tuple(
        finding for finding in result.findings if finding.status.is_weakness and finding.deducts
    )
    unverified = tuple(
        finding for finding in result.findings if finding.status is FindingStatus.NOT_VERIFIABLE
    )
    charged = round(sum(finding.points_deducted for finding in weaknesses), 2)
    parts = [
        f"security score {security_score}/100 ({band.value} risk) over {len(result.findings)} rule(s)"
    ]
    if weaknesses:
        parts.append(f"{len(weaknesses)} weakness(es) charged {charged:g} point(s)")
    else:
        parts.append("no rule charged a point")
    if unverified:
        parts.append(f"{len(unverified)} rule(s) could not be verified from this capture")
    parts.append(f"evidence coverage {result.evidence_coverage:.0%}")
    if context.configured is not None:
        parts.append("part of the evidence is testbed configuration rather than the wire")
    if context.traffic is not None:
        parts.append("an ML prediction contributed inferred evidence")
    return "; ".join(parts)


def limitations_for(context: AssessmentContext, result: ScoringResult) -> tuple[str, ...]:
    """What this assessment cannot claim, stated next to the score.

    The first items hold for every capture this engine reads, because they are
    properties of the method; the rest depend on what was supplied to this run.
    """
    unverified = tuple(
        finding for finding in result.findings if finding.status is FindingStatus.NOT_VERIFIABLE
    )
    items = [
        "the assessment is passive: no key material is used and no packet was decrypted",
        "a rule that could not be verified lowers evidence_coverage and never the score",
        "the headline score is rounded to an integer; the per-category ledger keeps the exact arithmetic",
    ]
    if unverified:
        items.append(
            f"{len(unverified)} rule(s) could not be verified: "
            + ", ".join(finding.rule_id for finding in unverified)
        )
    if context.configured is None:
        items.append(
            "no testbed configuration was supplied, so configuration-versus-wire comparisons could "
            "not be made"
        )
    else:
        items.append(
            "configured values describe an intention and are discounted to 0.85 of an observation"
        )
    if not context.has_esp:
        items.append("the capture holds no ESP traffic, so tunnel properties were not assessed")
    if context.traffic is None:
        items.append("no ML prediction was supplied, so the metadata inference rule is not verifiable")
    return tuple(items)


def policy_summary(applied: Sequence[Rule]) -> dict[str, Any]:
    """The policy version and the rules that produced this score.

    Recorded inside the assessment so a report from six months ago can still be
    compared with a fresh one, or shown to have used different rules.
    """
    return {
        "policy_id": POLICY_ID,
        "policy_version": POLICY_VERSION,
        "formula": deduction_model()["formula"],
        "rule_count": len(RULES),
        "rules_applied": [rule.rule_id for rule in applied],
    }


def provenance(context: AssessmentContext, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Which artefacts this assessment consumed, and what it did not.

    ``ground_truth`` is present as a refusal rather than as a path: the stage has
    no code path that loads a labelled sample, and the report says so.
    """
    record: dict[str, Any] = {
        "analysis": context.analysis_id,
        "pcap": context.pcap_path,
        "method": context.method,
        "packets": context.packets,
        "configured_parameters": context.configured is not None,
        "ml_prediction": context.traffic.predicted_class if context.traffic is not None else "",
        "ground_truth": "not read: no code path in this stage loads a labelled sample",
    }
    if extra:
        record.update({str(key): value for key, value in extra.items()})
    return record


__all__ = [
    "FINGERPRINTABILITY_LEVELS",
    "FINGERPRINT_DIMENSIONS_HIGH",
    "FINGERPRINT_DIMENSIONS_MODERATE",
    "INFERENCE_RISK_CONFIDENCE_HIGH",
    "assess_security",
    "fingerprintability",
    "inference_risk",
    "limitations_for",
    "metadata_exposure",
    "observable_dimensions",
    "policy_summary",
    "provenance",
    "recommendations_for",
    "summary_for",
]

