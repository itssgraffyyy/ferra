"""Unit tests for the assessment models (:mod:`fera.security.models`).

Two guarantees the scoring stage relies on are pinned here: a verdict that is
not verifiable can never cost points, and every artefact round-trips through
JSON so a report written by one run stays readable by the next.
"""

from __future__ import annotations

import json

import pytest

from fera.common.errors import ConfigValidationError
from fera.security.evidence import (
    EVIDENCE_PRECEDENCE,
    EvidenceRef,
    EvidenceStatus,
    count_evidence,
    status_from_evidence_kind,
    strongest,
)
from fera.security.models import (
    SECURITY_SCHEMA_VERSION,
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


def make_finding(**overrides: object) -> SecurityFinding:
    """One cryptography finding with sane defaults for the tests to bend."""
    payload: dict[str, object] = {
        "rule_id": "CRYPTO-001",
        "category": SecurityCategory.CRYPTOGRAPHY,
        "title": "Encryption algorithm strength",
        "status": FindingStatus.PASS,
        "severity": Severity.INFO,
        "evidence_status": EvidenceStatus.OBSERVED,
        "confidence": 1.0,
        "explanation": "ENCR_AES_GCM_16 is a recommended AEAD transform",
    }
    payload.update(overrides)
    return SecurityFinding(**payload)  # type: ignore[arg-type]


def test_evidence_hierarchy_is_strongest_first() -> None:
    assert [status.value for status in EVIDENCE_PRECEDENCE] == [
        "OBSERVED",
        "CONFIGURED",
        "INFERRED",
        "NOT_VERIFIABLE",
    ]
    assert EvidenceStatus.OBSERVED.rank < EvidenceStatus.CONFIGURED.rank
    assert strongest(EvidenceStatus.NOT_VERIFIABLE, EvidenceStatus.CONFIGURED) is EvidenceStatus.CONFIGURED
    assert strongest(EvidenceStatus.INFERRED, EvidenceStatus.OBSERVED) is EvidenceStatus.OBSERVED
    assert strongest() is EvidenceStatus.NOT_VERIFIABLE


def test_only_verifiable_evidence_may_change_the_score() -> None:
    assert EvidenceStatus.OBSERVED.contributes_to_score
    assert EvidenceStatus.CONFIGURED.contributes_to_score
    assert EvidenceStatus.INFERRED.contributes_to_score
    assert not EvidenceStatus.NOT_VERIFIABLE.contributes_to_score


def test_prompt2_provenance_maps_without_upgrading() -> None:
    assert status_from_evidence_kind("OBSERVED") is EvidenceStatus.OBSERVED
    assert status_from_evidence_kind("not_verifiable") is EvidenceStatus.NOT_VERIFIABLE
    assert status_from_evidence_kind(None) is EvidenceStatus.NOT_VERIFIABLE
    # an unknown label is never promoted to a grade that could score points
    assert status_from_evidence_kind("PROBABLY_FINE") is EvidenceStatus.NOT_VERIFIABLE


def test_count_evidence_reports_every_status() -> None:
    counts = count_evidence([EvidenceRef.observed("a", "x"), EvidenceRef.not_verifiable("b", "y")])
    assert counts == {"OBSERVED": 1, "CONFIGURED": 0, "INFERRED": 0, "NOT_VERIFIABLE": 1}


def test_evidence_ref_round_trips() -> None:
    ref = EvidenceRef.configured("testbed.experiment_config", "pfs = on", pfs=True)
    assert EvidenceRef.from_dict(ref.to_dict()) == ref


@pytest.mark.parametrize("status", [FindingStatus.NOT_VERIFIABLE, FindingStatus.PASS])
def test_a_non_weakness_never_deducts_points(status: FindingStatus) -> None:
    with pytest.raises(ConfigValidationError) as error:
        make_finding(status=status, severity=Severity.LOW, points_deducted=5.0)
    assert "must not deduct points" in error.value.message


def test_finding_round_trips_through_a_document() -> None:
    finding = make_finding(
        status=FindingStatus.FAIL,
        severity=Severity.HIGH,
        points_deducted=12.0,
        recommendation="Offer AES-GCM instead of 3DES",
        evidence=(EvidenceRef.observed("analysis.ike_exchanges.proposals", "ENCR_3DES offered"),),
        references=("RFC 8221 section 2",),
        details={"offered": ["ENCR_3DES"]},
    )
    document = finding.to_dict()
    assert document["evidence_status"] == "OBSERVED"
    assert SecurityFinding.from_dict(document) == finding


def test_finding_rejects_an_unknown_status_instead_of_guessing() -> None:
    document = make_finding().to_dict()
    document["status"] = "MAYBE"
    with pytest.raises(ConfigValidationError) as error:
        SecurityFinding.from_dict(document)
    assert "status" in error.value.message


def test_finding_rejects_an_out_of_range_confidence() -> None:
    document = make_finding().to_dict()
    document["confidence"] = 1.4
    with pytest.raises(ConfigValidationError):
        SecurityFinding.from_dict(document)


def test_worst_risk_picks_the_most_severe_band() -> None:
    assert worst_risk([]) is RiskLevel.LOW
    assert worst_risk([RiskLevel.LOW, RiskLevel.CRITICAL, RiskLevel.MODERATE]) is RiskLevel.CRITICAL


def assessment_fixture() -> SecurityAssessment:
    """One complete assessment holding all three kinds of finding.

    The weakness costs points, the passing finding does not, and the third rule
    could not be answered by the capture at all - which is exactly the
    distinction the report has to keep readable.
    """
    weakness = make_finding(
        rule_id="CRYPTO-003",
        status=FindingStatus.FAIL,
        severity=Severity.HIGH,
        points_deducted=15.0,
        explanation="ENCR_3DES is offered for the child SA",
        recommendation="Offer ENCR_AES_GCM_16 only",
        evidence=(EvidenceRef.observed("analysis.ike_exchanges.proposals", "ENCR_3DES offered"),),
    )
    passing = make_finding(rule_id="CRYPTO-001", title="Encryption algorithm strength")
    unverified = make_finding(
        rule_id="REPLAY-004",
        category=SecurityCategory.REPLAY_PROTECTION,
        title="Replay window state",
        status=FindingStatus.NOT_VERIFIABLE,
        severity=Severity.INFO,
        evidence_status=EvidenceStatus.NOT_VERIFIABLE,
        explanation="the receiving policy is not visible on the wire",
        evidence=(EvidenceRef.not_verifiable("analysis.esp_flows", "no replay evidence"),),
    )
    crypto = CategoryScore(
        category=SecurityCategory.CRYPTOGRAPHY,
        weight=0.30,
        max_score=30.0,
        deducted=15.0,
        score=15.0,
        status_counts={"FAIL": 1, "PASS": 1},
        assessed_rules=2,
        unverified_rules=0,
        coverage=1.0,
        findings=(weakness, passing),
    )
    replay = CategoryScore(
        category=SecurityCategory.REPLAY_PROTECTION,
        weight=0.15,
        max_score=15.0,
        deducted=0.0,
        score=15.0,
        status_counts={"NOT_VERIFIABLE": 1},
        assessed_rules=0,
        unverified_rules=1,
        coverage=0.0,
        findings=(unverified,),
    )
    return SecurityAssessment(
        analysis_id="analysis-fixture",
        security_score=85,
        risk_score=15,
        risk_level=RiskLevel.LOW,
        evidence_coverage=0.5,
        summary="3 rules, 1 weakness, 1 not verifiable",
        category_scores=(crypto, replay),
        findings=(weakness, passing, unverified),
        threat_matrix=(
            ThreatObservation(
                threat_id="T-3DES",
                threat="Offline decryption of a weak child SA cipher",
                category=SecurityCategory.CRYPTOGRAPHY,
                likelihood="MEDIUM",
                impact="HIGH",
                risk=RiskLevel.HIGH,
                evidence="OBSERVED (analysis.ike_exchanges.proposals)",
                recommendation="Offer ENCR_AES_GCM_16 only",
                rule_ids=("CRYPTO-003",),
            ),
        ),
        recommendations=(
            Recommendation(
                priority=1,
                recommendation="Offer ENCR_AES_GCM_16 only",
                reason="3DES is deprecated by RFC 8221",
                severity=Severity.HIGH,
                rule_ids=("CRYPTO-003",),
            ),
        ),
        metadata_exposure=MetadataExposure(
            observable={"esp_flows": 2, "distinct_esp_spi": 2},
            fingerprintability="moderate",
            inference_risk=RiskLevel.MODERATE,
            ml_available=False,
            notes=("no model was supplied",),
        ),
        policy={"profile": "generated"},
        evidence={"OBSERVED": 4, "CONFIGURED": 0, "INFERRED": 0, "NOT_VERIFIABLE": 1},
        inputs={"analysis": "analysis-fixture.json"},
        warnings=("capture is short",),
        limitations=("passive capture only",),
    )


def test_weaknesses_unverified_and_passes_stay_separate() -> None:
    assessment = assessment_fixture()
    assert [finding.rule_id for finding in assessment.weaknesses] == ["CRYPTO-003"]
    assert [finding.rule_id for finding in assessment.unverified] == ["REPLAY-004"]
    # a passing rule is neither a weakness nor an unverified question
    assert all(finding.rule_id != "CRYPTO-001" for finding in assessment.weaknesses + assessment.unverified)
    assert assessment.finding("REPLAY-004") is not None
    assert assessment.finding("NOPE-000") is None
    assert assessment.category_score(SecurityCategory.CRYPTOGRAPHY) is not None
    assert assessment.category_score(SecurityCategory.KEY_EXCHANGE) is None


def test_weaknesses_are_ordered_worst_first() -> None:
    small = make_finding(
        rule_id="CONFIG-001", status=FindingStatus.WARNING, severity=Severity.LOW, points_deducted=2.0
    )
    large = make_finding(
        rule_id="KEYX-001", status=FindingStatus.FAIL, severity=Severity.CRITICAL, points_deducted=20.0
    )
    assessment = SecurityAssessment(
        analysis_id="ordering",
        security_score=78,
        risk_score=22,
        risk_level=RiskLevel.MODERATE,
        evidence_coverage=1.0,
        summary="two weaknesses",
        findings=(small, large),
    )
    assert [finding.rule_id for finding in assessment.weaknesses] == ["KEYX-001", "CONFIG-001"]


def test_a_non_verifiable_finding_never_cheats_the_score() -> None:
    unverifiable = make_finding(
        rule_id="REPLAY-001",
        status=FindingStatus.NOT_VERIFIABLE,
        severity=Severity.CRITICAL,
        evidence_status=EvidenceStatus.NOT_VERIFIABLE,
    )
    assessment = SecurityAssessment(
        analysis_id="honesty",
        security_score=100,
        risk_score=0,
        risk_level=RiskLevel.LOW,
        evidence_coverage=0.0,
        summary="nothing scored",
        findings=(unverifiable,),
    )
    assert assessment.weaknesses == ()
    assert len(assessment.unverified) == 1
    assert unverifiable.deducts is False


def test_assessment_round_trips_through_json() -> None:
    assessment = assessment_fixture()
    document = json.loads(json.dumps(assessment.to_dict()))
    assert document["schema_version"] == SECURITY_SCHEMA_VERSION
    restored = SecurityAssessment.from_dict(document)
    assert restored.to_dict() == assessment.to_dict()
    assert restored.category_scores[0].category is SecurityCategory.CRYPTOGRAPHY
    assert restored.risk_level is RiskLevel.LOW
    assert restored.metadata_exposure is not None
    assert restored.metadata_exposure.ml_available is False
    assert restored.threat_matrix[0].rule_ids == ("CRYPTO-003",)
    assert restored.limitations == ("passive capture only",)


def test_assessment_rejects_an_unknown_risk_level() -> None:
    document = assessment_fixture().to_dict()
    document["risk_level"] = "APOCALYPTIC"
    with pytest.raises(ConfigValidationError) as error:
        SecurityAssessment.from_dict(document)
    assert "risk_level" in error.value.message


def test_render_text_keeps_the_three_groups_apart() -> None:
    text = assessment_fixture().render_text()
    assert "security score : 85/100" in text
    assert "risk 15 - LOW" in text
    assert "evidence cover : 50%" in text
    assert "[HIGH] CRYPTO-003 Encryption algorithm strength" in text
    assert "not verifiable from this capture (0 points, lowers coverage):" in text
    assert "REPLAY-004 Replay window state" in text
    assert "[HIGH] T-3DES" in text
    assert "1. [HIGH] Offer ENCR_AES_GCM_16 only" in text
    assert "ml prediction      : none supplied" in text
    assert "- passive capture only" in text


def test_render_text_says_so_when_a_model_was_used() -> None:
    assessment = assessment_fixture()
    exposure = assessment.metadata_exposure
    assert exposure is not None
    with_model = SecurityAssessment(
        analysis_id=assessment.analysis_id,
        security_score=assessment.security_score,
        risk_score=assessment.risk_score,
        risk_level=assessment.risk_level,
        evidence_coverage=assessment.evidence_coverage,
        summary=assessment.summary,
        findings=assessment.findings,
        metadata_exposure=MetadataExposure(
            observable=exposure.observable,
            fingerprintability=exposure.fingerprintability,
            inference_risk=RiskLevel.MODERATE,
            ml_available=True,
            ml_predicted_class="vpn_traffic",
            ml_confidence=0.87,
            ml_probabilities={"vpn_traffic": 0.87, "web": 0.13},
            ml_model="traffic_classifier_v1",
        ),
    )
    assert "ml prediction      : vpn_traffic (confidence 0.87) [traffic_classifier_v1]" in with_model.render_text()
    document = with_model.to_dict()["metadata_exposure"]
    assert document["ml_probabilities"] == {"vpn_traffic": 0.87, "web": 0.13}
    assert document["ml_available"] is True
