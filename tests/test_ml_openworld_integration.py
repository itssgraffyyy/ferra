"""End-to-end UNKNOWN (open-world) integration tests.

These prove the *wiring*, not the science.  A stub estimator on synthetic rows
can demonstrate that a decision propagates from ``openworld.decide`` through
``TrafficModel.predict``, the security contract and the assessment without
crashing or inventing a finding.  They cannot demonstrate that the thresholds
are any good: that needs the real strongSwan ESP dataset, which does not exist
yet.

The two failure modes these exist to prevent are:

* an UNKNOWN silently becoming a security FAIL or a raised severity, and
* a consumer re-deriving the decision from the confidence number instead of
  reading the backend's verdict.
"""

from __future__ import annotations

import pytest

from fera.ml import openworld as ow
from fera.ml.features import FEATURE_SCHEMA, FEATURE_WHITELIST, FeatureVector
from fera.ml.inference import TrafficModel, policy_from_metadata
from fera.security.ml_contract import load_prediction

CLASSES = ("voip_like", "web")


class _StubEstimator:
    """Minimal probability-capable estimator returning a fixed distribution."""

    classes_ = CLASSES

    def __init__(self, probabilities: list[float]) -> None:
        self._probabilities = probabilities

    def predict_proba(self, _rows: list[list[float]]) -> list[list[float]]:
        return [self._probabilities]


def _model(probabilities: list[float], policy: ow.RejectionPolicy) -> TrafficModel:
    from pathlib import Path

    return TrafficModel(
        model_id="stub-model",
        model_version="1",
        feature_schema=FEATURE_SCHEMA,
        classes=CLASSES,
        algorithm="Stub",
        trained_at="2026-01-01T00:00:00Z",
        dataset={},
        metrics={},
        notes=(),
        path=Path("stub"),
        estimator=_StubEstimator(probabilities),
        open_world=policy,
    )


def _vector() -> FeatureVector:
    return FeatureVector(pcap_path="stub", features=dict.fromkeys(FEATURE_WHITELIST, 1.0))


def test_confident_prediction_stays_known() -> None:
    document = _model([0.97, 0.03], ow.default_policy()).predict(_vector())

    assert document["decision"] == ow.DECISION_KNOWN
    assert document["predicted_class"] == "voip_like"
    assert document["rejected"] is False
    assert document["rejection_reason"] is None

def test_unknown_is_not_the_same_claim_as_not_verifiable() -> None:
    document = _model([0.3, 0.25], ow.default_policy()).predict(_vector())
    block = document["open_world"]

    assert block["evidence_status"] == "INFERRED"
    assert block["decision"] == ow.DECISION_UNKNOWN
    # The payload must state what UNKNOWN does not mean.
    notes = " ".join(block["notes"]).lower()
    assert "not_verifiable" in notes or "not verifiable" in notes
    assert "malicious" in notes or "anomalous" in notes


def test_threshold_provenance_is_persisted_and_flagged() -> None:
    placeholder = _model([0.97, 0.03], ow.default_policy()).predict(_vector())
    assert placeholder["open_world"]["experimental"] is True
    assert placeholder["open_world"]["threshold_source"] == ow.SOURCE_PLACEHOLDER
    assert placeholder["calibrated"] is False

    validated = ow.RejectionPolicy(
        confidence_threshold=0.9,
        source=ow.SOURCE_VALIDATION,
        calibrated=True,
        calibration_method="sigmoid",
    )
    document = _model([0.97, 0.03], validated).predict(_vector())
    assert document["open_world"]["experimental"] is False
    assert document["open_world"]["threshold_source"] == ow.SOURCE_VALIDATION


def test_old_artifact_without_open_world_loads_with_rejection_disabled() -> None:
    """A pre-Differentiator#2 artefact must not have thresholds invented for it."""
    policy = policy_from_metadata({"classes": ["web"]})
    assert policy.enabled is False
    assert ow.decide({"web": 0.05, "video": 0.05}, policy).decision == ow.DECISION_KNOWN

    assert policy_from_metadata({"open_world": {}}).enabled is False


def test_security_contract_keeps_unknown_from_becoming_a_failure() -> None:
    document = _model([0.3, 0.25], ow.default_policy()).predict(_vector())
    prediction = load_prediction(document)

    assert prediction is not None
    assert prediction.is_unknown is True
    assert prediction.decision == ow.DECISION_UNKNOWN
    assert prediction.closest_known_class in set(CLASSES)
    assert prediction.effective_class in set(CLASSES)
    assert prediction.to_dict()["rejected"] is True


def test_security_rule_reports_unknown_as_not_verifiable_not_fail() -> None:
    """UNKNOWN must not raise severity or become a weakness."""
    from fera.security.assessment import assess_security

    analysis = {"ipsec_detected": True, "esp_packets": 10, "esp_flows": [], "ike_exchanges": []}
    unknown = assess_security(analysis, traffic=_model([0.3, 0.25], ow.default_policy()).predict(_vector()), analysis_id="t")
    known = assess_security(analysis, traffic=_model([0.97, 0.03], ow.default_policy()).predict(_vector()), analysis_id="t")

    text = " ".join(str(f.explanation) for f in unknown.findings)
    assert "not a weakness" in text
    assert unknown.security_score >= known.security_score
    assert unknown.risk_level != "CRITICAL"


@pytest.mark.parametrize("probabilities", [[0.5, 0.5], [0.34, 0.33], [0.2, 0.2]])
def test_ambiguous_traffic_is_never_forced_into_a_class(probabilities) -> None:
    """Whatever the input, exactly one of KNOWN/UNKNOWN is reported."""
    document = _model(probabilities, ow.default_policy()).predict(_vector())

    assert document["decision"] in {ow.DECISION_KNOWN, ow.DECISION_UNKNOWN}
    assert bool(document["rejected"]) is (document["decision"] == ow.DECISION_UNKNOWN)
    if document["rejected"]:
        assert document["predicted_class"] == ow.UNKNOWN_LABEL
    else:
        assert document["predicted_class"] in set(CLASSES)

def test_low_confidence_becomes_unknown_through_the_real_pipeline() -> None:
    """The decision is made in inference, not re-derived by a consumer."""
    document = _model([0.30, 0.25], ow.default_policy()).predict(_vector())

    assert document["decision"] == ow.DECISION_UNKNOWN
    assert document["predicted_class"] == ow.UNKNOWN_LABEL
    assert document["rejection_reason"] == ow.REASON_LOW_CONFIDENCE
    # The known-class evidence must survive rejection.
    assert document["closest_known_class"] in set(CLASSES)
    assert set(document["probabilities"]) == set(CLASSES)
    assert document["top_alternatives"]
    assert document["evidence_status"] == "INFERRED"
