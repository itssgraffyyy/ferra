"""Part 3 privacy-intelligence tests.

These assert **software correctness**, not privacy effectiveness:

* the countermeasure transformation is deterministic and its byte arithmetic is
  right;
* a simulated countermeasure cannot be promoted to testbed-verified;
* Attacker A never trains on the mitigated data it is scored on;
* Attacker B's train/test groups stay disjoint;
* unmeasured cost dimensions report ``NOT_MEASURED`` rather than a number.

Every metric produced here comes from synthetic fixtures.  None of it is
experimental evidence, and the module's own status field says so.
"""

from __future__ import annotations

import pytest

from fera.common.errors import FeraError
from fera.ml.dataset import DATASET_SCHEMA, EVIDENCE_STATUS, LABEL_FIELD, DatasetSample
from fera.ml.features import FEATURE_SCHEMA, FEATURE_WHITELIST
from fera.privacy.countermeasure import (
    CONFIGURED_NOT_VERIFIED,
    NOT_MEASURED,
    SIMULATED,
    TESTBED_VERIFIED,
    CountermeasureProvenance,
    SizeNormalizationCountermeasure,
    SizeNormalizationParameters,
    assert_provenance_permits_claims,
)
from fera.privacy.experiment import (
    ATTACKER_A,
    ATTACKER_B,
    STATUS_EXPERIMENTAL,
    STATUS_SIMULATED,
    run_privacy_experiment,
)

CLASSES = ("web", "video_like", "voip_like")


def _sample(label: str, group: int, index: int, split: str) -> DatasetSample:
    position = CLASSES.index(label)
    features = {
        name: float(index + 1) * (order + 1) / 10.0
        for order, name in enumerate(FEATURE_WHITELIST)
    }
    # Distinct sizes per class: size is the channel the countermeasure targets.
    features["esp_avg_len"] = 300.0 + 200.0 * position + 10.0 * index
    features["avg_packet_len"] = 280.0 + 200.0 * position
    features["esp_len_min"] = 200.0 + 100.0 * position
    features["esp_len_max"] = 500.0 + 200.0 * position
    features["esp_len_std"] = 20.0 + 5.0 * position
    features["esp_iat_mean_s"] = 0.01 + 0.02 * position
    return DatasetSample(
        document={
            "schema": DATASET_SCHEMA,
            "feature_schema": FEATURE_SCHEMA,
            "experiment_id": f"exp-{label}-{group}",
            "capture_id": f"cap-{label}-{group}-{index}",
            "split_key": f"exp-{label}-{group}",
            "split": split,
            LABEL_FIELD: label,
            "label_basis": "configuration",
            "evidence_status": EVIDENCE_STATUS,
            "features": features,
            "provenance": {"pcap_path": f"captures/{label}-{index}.pcap"},
        }
    )


@pytest.fixture
def dataset() -> list[DatasetSample]:
    rows: list[DatasetSample] = []
    for label in CLASSES:
        for group, split in enumerate(("train", "val", "test")):
            for index in range(3):
                rows.append(_sample(label, group, index + group * 3, split))
    return rows


def _countermeasure(mode: str = "bucket", bucket: int = 256) -> SizeNormalizationCountermeasure:
    return SizeNormalizationCountermeasure(
        SizeNormalizationParameters(mode=mode, bucket_size=bucket, max_pad_size=1400)
    )


# ------------------------------------------------------------ provenance


def test_simulated_provenance_permits_no_experimental_claim() -> None:
    provenance = CountermeasureProvenance(state=SIMULATED)
    assert provenance.is_simulated is True
    assert provenance.permits_experimental_claims is False
    with pytest.raises(FeraError):
        assert_provenance_permits_claims(provenance, claiming_experimental=True)


def test_testbed_verified_requires_capture_evidence() -> None:
    with pytest.raises(FeraError):
        CountermeasureProvenance(state=TESTBED_VERIFIED)
    ok = CountermeasureProvenance(
        state=TESTBED_VERIFIED, evidence_capture="captures/x.pcap", evidence_sha256="ab" * 32
    )
    assert ok.permits_experimental_claims is True
    assert_provenance_permits_claims(ok, claiming_experimental=True)


def test_configured_but_unverified_is_not_experimental() -> None:
    provenance = CountermeasureProvenance(state=CONFIGURED_NOT_VERIFIED)
    assert provenance.permits_experimental_claims is False
    with pytest.raises(FeraError):
        assert_provenance_permits_claims(provenance, claiming_experimental=True)


def test_software_countermeasure_is_simulated_by_construction() -> None:
    assert _countermeasure().provenance().state == SIMULATED


def test_unknown_provenance_state_is_refused() -> None:
    with pytest.raises(FeraError):
        CountermeasureProvenance(state="DEFINITELY_VERIFIED")


# ------------------------------------------------- countermeasure mechanics


def test_bucket_transformation_is_deterministic() -> None:
    countermeasure = _countermeasure(bucket=256)
    rows = [[100.0] * len(FEATURE_WHITELIST), [257.0] * len(FEATURE_WHITELIST)]
    first = countermeasure.apply(rows, FEATURE_WHITELIST)
    second = countermeasure.apply(rows, FEATURE_WHITELIST)
    assert first == second
    size_index = FEATURE_WHITELIST.index("esp_avg_len")
    assert first[0][size_index] == 256.0
    assert first[1][size_index] == 512.0


def test_transformation_never_shrinks_a_packet() -> None:
    parameters = SizeNormalizationParameters(mode="bucket", bucket_size=256)
    for length in (1, 100, 255, 256, 257, 1399, 1400, 5000):
        assert parameters.transmit_length(length) >= length


def test_fixed_mode_pads_to_the_target() -> None:
    # target_size must be >= max_pad_size, or the guard refuses a configuration
    # that would claim a constant size while leaving large packets unpadded.
    parameters = SizeNormalizationParameters(mode="fixed", target_size=1400, max_pad_size=1400)
    assert parameters.transmit_length(100) == 1400
    assert parameters.transmit_length(500) == 1400
    # Beyond max_pad_size a packet is transmitted unchanged: padding must not lie.
    assert parameters.transmit_length(1500) == 1500


def test_invalid_padding_configuration_is_refused() -> None:
    with pytest.raises(FeraError):
        SizeNormalizationParameters(mode="fixed", target_size=100, max_pad_size=1400)
    with pytest.raises(FeraError):
        SizeNormalizationParameters(mode="bucket", bucket_size=0)
    with pytest.raises(FeraError):
        SizeNormalizationParameters(mode="nonsense")
    with pytest.raises(FeraError):
        SizeNormalizationParameters(mode="bucket").transmit_length(0)


def test_non_size_features_pass_through_untouched() -> None:
    countermeasure = _countermeasure()
    original = [[100.0] * len(FEATURE_WHITELIST)]
    original[0][FEATURE_WHITELIST.index("esp_iat_mean_s")] = 0.5
    transformed = countermeasure.apply(original, FEATURE_WHITELIST)
    assert transformed[0][FEATURE_WHITELIST.index("esp_iat_mean_s")] == 0.5
    assert transformed[0][FEATURE_WHITELIST.index("esp_avg_len")] == 256.0

# ----------------------------------------------------------- experiment


def _run(dataset):
    return run_privacy_experiment(
        dataset, _countermeasure(), candidates=("logistic_regression",)
    )


def test_experiment_is_stamped_as_simulated_by_default(dataset) -> None:
    report = _run(dataset)
    assert report["status"] == STATUS_SIMULATED
    assert report["provenance"]["state"] == SIMULATED
    assert report["provenance"]["permits_experimental_claims"] is False


def test_experiment_cannot_claim_experimental_evidence(dataset) -> None:
    with pytest.raises(FeraError):
        run_privacy_experiment(
            dataset,
            _countermeasure(),
            candidates=("logistic_regression",),
            status=STATUS_EXPERIMENTAL,
            claiming_experimental=True,
        )


def test_labels_groups_and_splits_survive_the_transformation(dataset) -> None:
    report = _run(dataset)
    # The countermeasure must not be able to alter experiment structure.
    assert report["dataset"]["split_groups"]["ok"] is True
    assert report["dataset"]["countermeasure_changed_data"] is True
    assert set(report["dataset"]["classes"]) == set(CLASSES)


def test_attacker_a_is_frozen_and_never_trained_on_mitigated_data(dataset) -> None:
    attacker_a = _run(dataset)["attacker_a"]
    assert attacker_a["name"] == ATTACKER_A
    assert attacker_a["trained_on"] == "baseline"
    assert attacker_a["evaluated_on"] == "mitigated"
    assert any("never used to fit" in note for note in attacker_a["notes"])


def test_attacker_b_retrains_on_mitigated_data(dataset) -> None:
    attacker_b = _run(dataset)["attacker_b"]
    assert attacker_b["name"] == ATTACKER_B
    assert attacker_b["trained_on"] == "mitigated"
    assert "held-out" in attacker_b["evaluated_on"]


def test_comparison_arithmetic_is_consistent(dataset) -> None:
    report = _run(dataset)
    baseline = report["baseline"]["macro_f1"]
    for key in ("attacker_a", "attacker_b"):
        block = report[key]
        assert block["delta_macro_f1"] == pytest.approx(block["macro_f1"] - baseline, abs=1e-6)
        assert block["baseline_macro_f1"] == baseline


def test_cost_block_reports_bytes_and_refuses_to_infer_performance(dataset) -> None:
    cost = _run(dataset)["cost"]
    assert cost["cost_side"]["byte_overhead"] is not None
    assert cost["cost_side"]["byte_overhead"] >= 0
    for key in ("latency", "throughput", "jitter"):
        assert cost["not_measured"][key] == NOT_MEASURED


def test_majority_baseline_is_reported_for_context(dataset) -> None:
    assert _run(dataset)["baseline"]["majority_baseline"]["classifier"] == "majority_class"


def test_experiment_serialises_to_plain_json_types(dataset) -> None:
    import json

    report = _run(dataset)
    assert json.loads(json.dumps(report))["schema"] == report["schema"]


def test_limitations_state_what_is_not_measured(dataset) -> None:
    joined = " ".join(_run(dataset)["limitations"]).lower()
    assert "not proof of anonymity" in joined
    assert "not experimental evidence" in joined
    assert "traffic flow confidentiality" in joined

def test_byte_overhead_arithmetic_is_correct() -> None:
    countermeasure = _countermeasure(bucket=256)
    rows = [[500.0] * len(FEATURE_WHITELIST), [700.0] * len(FEATURE_WHITELIST)]
    overhead = countermeasure.overhead(rows, FEATURE_WHITELIST)
    # 500 -> 512, 700 -> 768
    assert overhead["original_bytes"] == 1200
    assert overhead["transformed_bytes"] == 1280
    assert overhead["byte_overhead"] == 80
    assert overhead["byte_overhead_percent"] == pytest.approx(100 * 80 / 1200)


def test_unmeasured_costs_are_never_numbers() -> None:
    overhead = _countermeasure().overhead([[400.0] * len(FEATURE_WHITELIST)], FEATURE_WHITELIST)
    for key in ("latency", "throughput", "jitter"):
        assert overhead[key] == NOT_MEASURED


def test_countermeasure_needs_the_features_it_operates_on() -> None:
    with pytest.raises(FeraError):
        _countermeasure().apply([[1.0, 2.0]], ["unrelated_a", "unrelated_b"])
    provenance = CountermeasureProvenance(state=CONFIGURED_NOT_VERIFIED)
    assert provenance.permits_experimental_claims is False
    with pytest.raises(FeraError):
        assert_provenance_permits_claims(provenance, claiming_experimental=True)

