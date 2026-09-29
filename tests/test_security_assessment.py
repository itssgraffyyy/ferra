"""End-to-end tests for the assessment engine (:mod:`fera.security.assessment`).

Two captures are assessed: one that is weak in ways a passive observer can see
(3DES, MODP 1024, MD5, replay reuse, two SPIs) and one that is as clean as the
baseline allows.  Expectations are either exact numbers taken from the policy
tables or properties that must hold for any capture, so these tests fail when
the engine changes behaviour rather than when it changes wording.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from conftest import ethernet_ipv4, write_pcap
from fera.analysis import analyze_pcap
from fera.common.errors import ConfigValidationError
from fera.security import (
    CATEGORY_WEIGHTS,
    COVERAGE_WEIGHTS,
    EVIDENCE_FACTORS,
    RULE_INDEX,
    STATUS_FACTORS,
    FindingStatus,
    PolicyTier,
    RiskLevel,
    SecurityAssessment,
    SecurityCategory,
    assess_security,
    threat_matrix,
)
from fera.security.evidence import EvidenceStatus
from fera.security.policy import ENCRYPTION_POLICIES, TIER_BASE_POINTS
from fera.security.threats import THREAT_INDEX

IKE_TRANSFORMS = [
    {"type_name": "ENCRYPTION_ALGORITHM", "name": "ENCR_3DES", "key_bits": 192, "aead": False},
    {"type_name": "INTEGRITY_ALGORITHM", "name": "AUTH_HMAC_MD5_96", "key_bits": 128, "aead": False},
    {"type_name": "PSEUDORANDOM_FUNCTION", "name": "PRF_HMAC_MD5", "key_bits": 128, "aead": False},
    {"type_name": "DIFFIE_HELLMAN_GROUP", "name": "MODP_1024", "key_bits": 1024, "aead": False},
]
CHILD_TRANSFORMS = IKE_TRANSFORMS[:2]
STRONG_TRANSFORMS = [
    {"type_name": "ENCRYPTION_ALGORITHM", "name": "ENCR_AES_GCM_16", "key_bits": 128, "aead": True},
    {"type_name": "PSEUDORANDOM_FUNCTION", "name": "PRF_HMAC_SHA2_256", "key_bits": 256, "aead": False},
    {"type_name": "DIFFIE_HELLMAN_GROUP", "name": "ECP_256", "key_bits": 256, "aead": False},
]

WEAK_CONFIG = {
    "encryption": "3des",
    "integrity": "hmac_md5_96",
    "prf": "hmac_md5",
    "dh_group": 2,
    "pfs": True,
    "pfs_dh_group": 2,
    "ike_version": 2,
    "ike_sa_lifetime_s": 3 * 86400,
    "child_sa_lifetime_s": 86400,
}

PREDICTION = {
    "predicted_class": "bulk_transfer",
    "confidence": 0.91,
    "probabilities": {"bulk_transfer": 0.91, "interactive": 0.09},
    "model_id": "traffic_classifier",
    "model_version": "0.1.0",
    "feature_schema": "fera_features_v1",
    "features": {
        "esp_len_min": 200.0,
        "esp_len_max": 1400.0,
        "esp_len_std": 120.0,
        "esp_avg_len": 800.0,
        "esp_iat_mean_s": 0.02,
        "esp_iat_std_s": 0.01,
        "esp_span_s": 1.4,
    },
}


def flow(spi: str, packets: int, **overrides: object) -> dict:
    """One ESP flow as the analyser writes it, with sensible defaults."""
    document = {
        "spi": spi,
        "packets": packets,
        "bytes_total": packets * 1000,
        "src": "10.0.1.1",
        "dst": "10.0.2.1",
        "first_frame": 7,
        "last_frame": 7 + packets,
        "sequence_gaps": 0,
        "sequence_replays": 0,
        "sequence_monotonic": True,
        "udp_encapsulated": False,
        "encapsulation": "unknown",
    }
    document.update(overrides)
    return document


def capture(
    *,
    ike_transforms: list[dict],
    child_transforms: list[dict],
    dh_groups: list[int],
    flows: list[dict],
    prediction: dict | None,
) -> dict:
    """An analysis document with one IKE SA proposal and one child proposal."""
    return {
        "pcap_path": "data/raw/exp_004_weak/capture.pcap",
        "method": "pcap_scan",
        "packets": 64,
        "ike_packets": 6,
        "esp_packets": sum(item["packets"] for item in flows),
        "ike_exchanges": [
            {
                "frame_index": 1,
                "ike_version": 2,
                "exchange_name": "IKE_SA_INIT",
                "initiator": True,
                "payload_types": [33, 34, 40],
                "proposals": [
                    {
                        "protocol_name": "IKE",
                        "proposal_number": 1,
                        "spi": "",
                        "dh_groups": dh_groups,
                        "transforms": ike_transforms,
                    },
                    {
                        "protocol_name": "ESP",
                        "proposal_number": 1,
                        "spi": flows[0]["spi"] if flows else "",
                        "dh_groups": dh_groups,
                        "transforms": child_transforms,
                    },
                ],
            }
        ],
        "esp_flows": flows,
        "details": {
            "scan": {"captured_bytes": 49000, "ipv4_packets": 64, "ipv6_packets": 0, "truncated_frames": 0},
            "pfs": {"status": "OBSERVED", "kind": "OBSERVED", "child_sa_dh_groups": dh_groups},
        },
        "warnings": ["1 frame was truncated"],
        **({"ml": prediction} if prediction else {}),
    }


def weak_document(prediction: dict | None = None) -> dict:
    """3DES, MD5, MODP 1024, a reused sequence number and two visible SPIs."""
    return capture(
        ike_transforms=IKE_TRANSFORMS,
        child_transforms=CHILD_TRANSFORMS,
        dh_groups=[2],
        flows=[
            flow("9f3a71c4", 40, sequence_gaps=2, sequence_replays=1),
            flow("1c0ffee2", 18, sequence_monotonic=False, udp_encapsulated=True, encapsulation="esp-in-udp"),
        ],
        prediction=prediction,
    )


def clean_document(*, prediction: dict | None = None, flows: list[dict] | None = None) -> dict:
    """AES-GCM, ECP-256 and PFS: nothing a passive observer can fault."""
    return capture(
        ike_transforms=STRONG_TRANSFORMS,
        child_transforms=[STRONG_TRANSFORMS[0]],
        dh_groups=[19],
        flows=flows if flows is not None else [flow("9f3a71c4", 40)],
        prediction=prediction,
    )


def test_a_weak_capture_is_scored_and_charged() -> None:
    assessment = assess_security(weak_document(PREDICTION), configured=WEAK_CONFIG)
    assert assessment.analysis_id == "capture"
    assert 0 < assessment.security_score < 60
    assert assessment.security_score + assessment.risk_score == 100
    assert assessment.risk_level is RiskLevel.CRITICAL
    assert assessment.finding("CRYPTO-004") is not None
    child_cipher = assessment.finding("CRYPTO-004")
    assert child_cipher is not None
    assert child_cipher.status is FindingStatus.FAIL
    assert child_cipher.evidence_status is EvidenceStatus.OBSERVED
    assert child_cipher.points_deducted > 0
    assert child_cipher.recommendation
    assert assessment.summary.startswith(f"security score {assessment.security_score}/100")
    assert "weakness(es) charged" in assessment.summary
    # every category stays inside its own ceiling, whatever the rules found
    assert all(category.deducted <= category.max_score for category in assessment.category_scores)


def test_points_are_base_times_status_times_evidence() -> None:
    """The published number is exactly the documented product, rule by rule."""
    assessment = assess_security(weak_document(PREDICTION), configured=WEAK_CONFIG)
    observed = assessment.finding("CRYPTO-004")
    assert observed is not None
    tier = ENCRYPTION_POLICIES["ENCR_3DES"].tier
    assert observed.points_deducted == round(
        TIER_BASE_POINTS[tier] * STATUS_FACTORS[observed.status] * EVIDENCE_FACTORS[observed.evidence_status],
        2,
    )
    configured = assessment.finding("KEYX-005")
    assert configured is not None
    assert configured.evidence_status is EvidenceStatus.CONFIGURED
    lifetime_tier = PolicyTier(configured.details["tier"])
    assert configured.points_deducted == round(
        TIER_BASE_POINTS[lifetime_tier]
        * STATUS_FACTORS[configured.status]
        * EVIDENCE_FACTORS[EvidenceStatus.CONFIGURED],
        2,
    )
    # the same weakness is worth more when the wire proves it than when a file claims it
    assert EVIDENCE_FACTORS[EvidenceStatus.CONFIGURED] < EVIDENCE_FACTORS[EvidenceStatus.OBSERVED]
    assert "rekey at most every" in configured.recommendation
    assert "above this baseline's" in configured.explanation


def test_a_clean_capture_scores_well_and_only_reports_metadata_exposure() -> None:
    assessment = assess_security(clean_document())
    assert assessment.security_score >= 95
    assert assessment.risk_level is RiskLevel.LOW
    assert assessment.finding("CRYPTO-004") is not None
    assert assessment.finding("CRYPTO-004").status is FindingStatus.PASS
    for finding in assessment.weaknesses:
        assert finding.status.is_weakness
        assert finding.points_deducted > 0
    threat_ids = {observation.threat_id for observation in assessment.threat_matrix}
    assert "T-TUNNEL-CIPHER" not in threat_ids
    assert "T-DH-WEAK" not in threat_ids
    assert "T-PLAINTEXT-TRAFFIC" not in threat_ids
    assert "T-SPI-VISIBILITY" in threat_ids


def test_no_verifiable_finding_ever_deducts_but_lowers_coverage() -> None:
    assessment = assess_security(weak_document(PREDICTION))
    assert assessment.unverified
    for finding in assessment.unverified:
        assert finding.points_deducted == 0.0
        assert finding.deducts is False
        assert finding.evidence_status is EvidenceStatus.NOT_VERIFIABLE
    assert assessment.evidence_coverage < 1.0
    assert "could not be verified" in assessment.summary
    # the threat matrix states that nothing was observed for those rules
    unverified_threat = next(
        (
            observation
            for observation in assessment.threat_matrix
            if observation.threat_id == "T-REPLAY-WINDOW-UNKNOWN"
        ),
        None,
    )
    assert unverified_threat is not None
    assert unverified_threat.evidence.startswith("NOT_VERIFIABLE")
    assert "not observed" in unverified_threat.evidence


def test_assessment_is_deterministic() -> None:
    first = assess_security(weak_document(PREDICTION), configured=WEAK_CONFIG)
    second = assess_security(weak_document(PREDICTION), configured=WEAK_CONFIG)
    assert first.to_dict() == second.to_dict()
    assert first.render_text() == second.render_text()


def test_evidence_coverage_is_the_mean_of_the_coverage_weights() -> None:
    assessment = assess_security(weak_document(PREDICTION), configured=WEAK_CONFIG)
    expected = round(
        sum(COVERAGE_WEIGHTS[finding.evidence_status] for finding in assessment.findings)
        / max(1, len(assessment.findings)),
        4,
    )
    assert assessment.evidence_coverage == expected
    assert 0.0 < assessment.evidence_coverage < 1.0


def test_rules_parameter_narrows_the_run() -> None:
    case = assess_security(weak_document(), rules=[RULE_INDEX["CRYPTO-004"]])
    assert [finding.rule_id for finding in case.findings] == ["CRYPTO-004"]
    assert case.policy["rules_applied"] == ["CRYPTO-004"]
    assert case.policy["rule_count"] == len(RULE_INDEX)
    # one finding, priced by the tier table and capped by the category weight
    tiered = case.findings[0]
    assert tiered.points_deducted == TIER_BASE_POINTS[ENCRYPTION_POLICIES["ENCR_3DES"].tier]
    assert case.security_score == 100 - min(tiered.points_deducted, CATEGORY_WEIGHTS[SecurityCategory.CRYPTOGRAPHY] * 100)


def test_a_prediction_is_reported_only_when_it_can_be_interpreted() -> None:
    anonymous = {**PREDICTION, "model_id": "", "model_version": "", "feature_schema": ""}
    uninterpretable = assess_security(weak_document(anonymous))
    finding = uninterpretable.finding("META-003")
    assert finding is not None
    assert finding.status is FindingStatus.NOT_VERIFIABLE
    assert finding.points_deducted == 0.0
    exposure = uninterpretable.metadata_exposure
    assert exposure is not None
    assert exposure.ml_available is False
    assert exposure.ml_predicted_class is None
    assert exposure.ml_model == ""
    assert any("without a model id" in note for note in exposure.notes)

    interpretable = assess_security(weak_document(PREDICTION))
    charged = interpretable.finding("META-003")
    assert charged is not None
    assert charged.status is FindingStatus.WARNING
    assert charged.evidence_status is EvidenceStatus.INFERRED
    assert charged.points_deducted > 0
    assert charged.confidence == pytest.approx(PREDICTION["confidence"])
    declared = interpretable.metadata_exposure
    assert declared is not None
    assert declared.ml_available is True
    assert declared.ml_model == "traffic_classifier@0.1.0"
    assert declared.ml_confidence == pytest.approx(0.91)
    assert declared.inference_risk is RiskLevel.HIGH
    assert declared.fingerprintability == "HIGH"
    assert declared.observable["distinct_esp_spi"] == 2
    dimensions = next(note for note in declared.notes if note.startswith("observable dimensions"))
    assert "association_split" in dimensions and "nat_binding" in dimensions


def test_a_labelled_sample_is_refused_rather_than_scored() -> None:
    with pytest.raises(ConfigValidationError) as error:
        assess_security(weak_document(), traffic={"label": "vpn_traffic"})
    assert "refusing a labelled sample" in error.value.message


def test_the_threat_matrix_traces_every_entry_to_a_finding() -> None:
    assert threat_matrix(()) == ()
    assessment = assess_security(weak_document(PREDICTION))
    for observation in assessment.threat_matrix:
        definition = THREAT_INDEX[observation.threat_id]
        assert observation.rule_ids
        assert set(observation.rule_ids) <= set(definition.rule_ids)
        assert observation.risk is definition.risk
        for rule_id in observation.rule_ids:
            assert assessment.finding(rule_id) is not None


def test_an_assessment_round_trips_through_json() -> None:
    assessment = assess_security(weak_document(PREDICTION), configured=WEAK_CONFIG)
    document = json.loads(json.dumps(assessment.to_dict()))
    restored = SecurityAssessment.from_dict(document)
    assert restored.to_dict() == assessment.to_dict()
    assert restored.render_text() == assessment.render_text()
    assert restored.security_score == assessment.security_score
    assert restored.policy["rules_applied"] == assessment.policy["rules_applied"]


def test_analysis_and_assessment_compose_on_one_capture(tmp_path: Path) -> None:
    """Prompt 2 output feeds Prompt 4 unchanged: no adapter, no hand editing."""
    pcap = write_pcap(tmp_path / "weak.pcap", _weak_capture_frames())
    analysis = analyze_pcap(pcap).analysis
    assert analysis.ike_packets == 1
    assessment = assess_security(analysis)
    assert assessment.analysis_id == "weak"
    assert assessment.inputs["pcap"] == str(pcap)
    assert assessment.security_score < 100
    child_cipher = assessment.finding("CRYPTO-004")
    assert child_cipher is not None
    assert child_cipher.status is FindingStatus.FAIL
    assert child_cipher.evidence_status is EvidenceStatus.OBSERVED
    assert "ENCR_3DES" in child_cipher.explanation
    assert assessment.risk_level in (RiskLevel.MODERATE, RiskLevel.HIGH, RiskLevel.CRITICAL)


# --- a byte-exact weak capture, built the way tests/test_analysis.py does it -----
def _sa_payload(protocol_id: int, spi: bytes, transforms: list[tuple[int, int]]) -> bytes:
    blob = b""
    for index, (transform_type, transform_id) in enumerate(transforms):
        following = 0 if index == len(transforms) - 1 else 3
        blob += struct.pack("!BBHBBH", following, 0, 8, transform_type, 0, transform_id)
    proposal_length = 8 + len(spi) + len(blob)
    proposal = struct.pack("!BBHBBBB", 0, 0, proposal_length, 1, protocol_id, len(spi), 0) + spi + blob
    return struct.pack("!BBH", 0, 0, 4 + len(proposal)) + proposal


def _ike_sa_init() -> bytes:
    # ENCR_3DES (3), AUTH_HMAC_MD5_96 (2), PRF_HMAC_MD5 (1), DH group 2 (MODP 1024)
    payload = _sa_payload(3, bytes.fromhex("c0a81401"), [(1, 3), (2, 2), (3, 1), (4, 2)])
    header = struct.pack(
        "!16sBBBBII",
        bytes.fromhex("11111111111111112222222222222222"),
        33,
        0x20,
        34,
        0x01,
        0,
        28 + len(payload),
    )
    return header + payload


def _weak_capture_frames() -> list[bytes]:
    frames = [ethernet_ipv4(17, src_port=500, dst_port=500, payload=_ike_sa_init())]
    for sequence in range(1, 25):
        payload = struct.pack("!II", 0xAABBCCDD, sequence) + b"\xAA" * 16
        frames.append(ethernet_ipv4(50, payload=payload))
    return frames
