"""Experiment-manifest tests.

The manifest is what makes a result auditable later, so the properties tested
here are about *consistency*, not convenience:

* a run cannot be written VALID on the strength of gates alone while its
  capture shows no ESP - the historical failure, one level up;
* status is **derived** from the state and capture, never asserted separately;
* ground truth is CONFIGURED and comes from the experiment definition, never
  from classifier output;
* privacy provenance survives serialisation intact, so a simulated
  countermeasure cannot quietly become a verified one in a manifest.
"""

from __future__ import annotations

import pytest

from fera.capture.sanity import ValidationStatus
from fera.common.errors import FeraError
from fera.experiment.capture import CaptureEvidence
from fera.experiment.gates import EVIDENCE_GATES, ExperimentState, Stage
from fera.experiment.manifest import (
    MANIFEST_SCHEMA,
    STATUS_BLOCKED,
    STATUS_INCOMPLETE,
    STATUS_INVALID,
    STATUS_VALID,
    ExperimentManifest,
    IpsecGroundTruth,
    NetworkCondition,
)


def _evidence(*, esp: bool = True, status: str = ValidationStatus.VALID.value) -> CaptureEvidence:
    return CaptureEvidence(
        path="captures/x.pcap",
        sha256="ab" * 32,
        size_bytes=4096,
        status=status,
        packets=120,
        ike_detected=True,
        esp_detected=esp,
        ipv4_detected=True,
        ipv6_detected=False,
        nat_t_possible=True,
    )


def _state() -> ExperimentState:
    return ExperimentState(
        experiment_id="exp-000",
        session_id="sess-1",
        configuration_id="cfg-aes128-gcm",
        repeat_id=1,
        traffic_class="web",
    )


def _fully_gated() -> ExperimentState:
    state = _state()
    for gate in EVIDENCE_GATES:
        state.satisfy(gate)
    return state


def test_planned_run_is_incomplete_not_valid() -> None:
    manifest = ExperimentManifest(state=_state())
    assert manifest.status == STATUS_INCOMPLETE
    assert manifest.state.dataset_eligible is False


def test_fully_gated_run_with_esp_capture_is_valid() -> None:
    manifest = ExperimentManifest(state=_fully_gated(), capture=_evidence(esp=True))
    manifest.validate()
    assert manifest.status == STATUS_VALID
    assert manifest.state.dataset_eligible is True


def test_gates_alone_cannot_make_a_run_valid() -> None:
    """Every gate set but no capture at all: refuse rather than report VALID."""
    manifest = ExperimentManifest(state=_fully_gated(), capture=None)
    with pytest.raises(FeraError) as excinfo:
        manifest.validate()
    assert "no capture" in str(excinfo.value)
    assert manifest.status == STATUS_INCOMPLETE


def test_esp_gate_contradicted_by_capture_is_refused() -> None:
    """The historical failure: gates say ESP, the capture shows none."""
    manifest = ExperimentManifest(state=_fully_gated(), capture=_evidence(esp=False))

    with pytest.raises(FeraError) as excinfo:
        manifest.validate()
    assert "does not evidence ESP" in str(excinfo.value)
    # And it can never be reported VALID.
    assert manifest.status == STATUS_INCOMPLETE

def test_ground_truth_is_marked_configured_not_observed() -> None:
    ipsec = IpsecGroundTruth(encryption="aes256", aead=True, pfs=True, ip_version=6)
    document = ipsec.to_dict()

    assert document["evidence_status"] == "CONFIGURED"
    assert document["aead"] is True
    assert document["pfs"] is True
    assert document["ip_version"] == 6
    # A manifest has no field for a classifier's prediction: ground truth here
    # comes from the configuration.
    manifest = ExperimentManifest(state=_state(), ipsec=ipsec).to_dict()
    assert "predicted" not in str(manifest).lower()
    assert manifest["ipsec"]["evidence_status"] == "CONFIGURED"


def test_network_condition_records_netem_state() -> None:
    network = NetworkCondition(condition="lossy", loss_percent=2.0, jitter_ms=15.0, applied=True)
    document = network.to_dict()
    assert document["loss_percent"] == 2.0
    assert document["jitter_ms"] == 15.0
    assert document["applied"] is True
    assert NetworkCondition.from_dict(document).condition == "lossy"


def test_privacy_provenance_survives_serialisation() -> None:
    manifest = ExperimentManifest(
        state=_state(),
        countermeasure={"name": "simulated_size_normalization", "state": "SIMULATED_COUNTERMEASURE"},
        privacy_provenance="SIMULATED_COUNTERMEASURE",
    )
    restored = ExperimentManifest.from_dict(manifest.to_dict())

    assert restored.privacy_provenance == "SIMULATED_COUNTERMEASURE"
    assert restored.countermeasure["state"] == "SIMULATED_COUNTERMEASURE"


def test_manifest_round_trips_with_lineage_and_capture_hash() -> None:
    manifest = ExperimentManifest(
        state=_fully_gated(),
        capture=_evidence(),
        environment={"host": "testbed-a", "strongswan": "5.9.5"},
        traffic_class="video_like",
    )
    document = manifest.to_dict()
    assert document["schema"] == MANIFEST_SCHEMA

    restored = ExperimentManifest.from_dict(document)
    assert restored.state.session_id == "sess-1"
    assert restored.state.configuration_id == "cfg-aes128-gcm"
    assert restored.state.repeat_id == 1
    assert restored.traffic_class == "video_like"
    assert restored.environment["strongswan"] == "5.9.5"
    assert restored.capture is not None
    assert restored.capture.sha256 == "ab" * 32
    assert restored.status == STATUS_VALID


def test_lineage_distinguishes_experiment_session_and_configuration() -> None:
    lineage = ExperimentManifest(state=_state()).to_dict()["lineage"]
    assert lineage["experiment_id"] == "exp-000"
    assert lineage["session_id"] == "sess-1"
    assert lineage["configuration_id"] == "cfg-aes128-gcm"
    # Repeats share a configuration but not a session: that is the independence
    # boundary grouped splitting needs.
    assert lineage["repeat_id"] == 1


def test_failed_run_is_invalid_and_skips_validation() -> None:
    state = _fully_gated()
    state.fail("capture was empty")
    manifest = ExperimentManifest(state=state, capture=_evidence())

    assert manifest.status == STATUS_INVALID
    assert manifest.state.dataset_eligible is False
    manifest.validate()  # a failed run is finished, not inconsistent


def test_blocked_run_reports_blocked() -> None:
    state = _state()
    state.stage = Stage.BLOCKED
    assert ExperimentManifest(state=state).status == STATUS_BLOCKED
