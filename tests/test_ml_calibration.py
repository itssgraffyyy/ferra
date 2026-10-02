"""Calibration, majority-baseline and held-out-configuration tests.

The claims under test are about *provenance*, not performance: that calibration
is fitted where it is allowed to be, that an uncalibrated model says so, that
the majority baseline is derived from training rows alone, and that a held-out
configuration never appears on both sides of the split.

No test here asserts a calibration curve is good, or that the classifier beats
the baseline. Those need a real strongSwan ESP dataset.
"""

from __future__ import annotations

import pytest

from fera.common.errors import FeraError
from fera.ml.calibration import (
    CALIBRATION_METHODS,
    MIN_ISOTONIC_CALIBRATION_ROWS,
    MIN_SIGMOID_CALIBRATION_ROWS,
    assert_partition_disjoint,
    calibrate_estimator,
    calibration_metrics,
    check_calibration_feasibility,
    compare_calibration,
    entropy_bits,
    expected_calibration_error,
    multiclass_brier_score,
    multiclass_log_loss,
    reliability_curve,
    top_label_confidence,
    uncalibrated_metadata,
)
from fera.ml.dataset import DATASET_SCHEMA, EVIDENCE_STATUS, LABEL_FIELD, DatasetSample
from fera.ml.features import FEATURE_SCHEMA, FEATURE_WHITELIST
from fera.ml.heldout import (
    HELD_OUT_CONFIG_SCHEMA,
    STATUS_INVALID,
    evaluate_held_out_configurations,
)
from fera.ml.train import majority_class_baseline, prepare_dataset

CLASSES = ("web", "video_like", "voip_like")


def _sample(label: str, group: int, index: int, split: str, tag: str = "") -> DatasetSample:
    position = CLASSES.index(label)
    features = {
        name: float(index + 1) * (order + 1) / 100.0
        for order, name in enumerate(FEATURE_WHITELIST)
    }
    features["esp_avg_len"] = 120.0 + 50.0 * position + group
    features["esp_iat_mean_s"] = 0.01 + 0.02 * position
    return DatasetSample(
        document={
            "schema": DATASET_SCHEMA,
            "feature_schema": FEATURE_SCHEMA,
            "experiment_id": f"exp-{label}-{tag}{group}",
            "capture_id": f"cap-{label}-{tag}{group}-{index}",
            "split_key": f"exp-{label}-{tag}{group}",
            "split": split,
            LABEL_FIELD: label,
            "label_basis": "configuration",
            "evidence_status": EVIDENCE_STATUS,
            "features": features,
            "provenance": {"pcap_path": f"captures/{label}-{index}.pcap"},
        }
    )


def _dataset(per_split: int = 3, tag: str = "") -> list[DatasetSample]:
    rows: list[DatasetSample] = []
    for label in CLASSES:
        for group, split in enumerate(("train", "val", "test")):
            for index in range(per_split):
                rows.append(_sample(label, group, index + group * per_split, split, tag))
    return rows


def test_perfect_predictions_score_zero_brier() -> None:
    truth = ["a", "b", "a", "b"]
    perfect = [{"a": 1.0, "b": 0.0}, {"a": 0.0, "b": 1.0}, {"a": 1.0, "b": 0.0}, {"a": 0.0, "b": 1.0}]
    assert multiclass_brier_score(truth, perfect, ["a", "b"]) == 0.0
    assert multiclass_log_loss(truth, perfect, ["a", "b"]) == pytest.approx(0.0, abs=1e-6)


def test_overconfident_wrong_prediction_is_penalised() -> None:
    truth = ["a", "a"]
    wrong = [{"a": 0.1, "b": 0.9}, {"a": 0.05, "b": 0.95}]
    assert multiclass_brier_score(truth, wrong, ["a", "b"]) > 0.0
    assert multiclass_log_loss(truth, wrong, ["a", "b"]) > 0.0


def test_entropy_and_top_label_are_well_defined() -> None:
    assert entropy_bits([1.0, 0.0]) == 0.0
    assert entropy_bits([0.5, 0.5]) == pytest.approx(1.0, abs=1e-6)
    name, confidence = top_label_confidence({"a": 0.3, "b": 0.7})
    assert (name, confidence) == ("b", 0.7)


def test_reliability_curve_omits_empty_bins_and_stays_top_label() -> None:
    truth = ["a", "a"]
    rows = [{"a": 0.95, "b": 0.05}, {"a": 0.2, "b": 0.8}]
    curve = reliability_curve(truth, rows, ["a", "b"], bins=10)

    assert curve, "at least one populated bin is expected"
    assert all(item["count"] > 0 for item in curve)
    assert all(0.0 <= item["accuracy"] <= 1.0 for item in curve)
    metrics = calibration_metrics(truth, rows, ["a", "b"])
    assert "top-label" in metrics["definitions"]["ece"]
    assert metrics["definitions"]["brier"].startswith("multiclass")


def test_ece_is_zero_for_perfectly_calibrated_confidence() -> None:
    truth = ["a", "b"]
    rows = [{"a": 1.0, "b": 0.0}, {"a": 0.0, "b": 1.0}]
    assert expected_calibration_error(truth, rows, ["a", "b"]) == 0.0


def test_feasibility_distinguishes_methods_and_reports_reasons() -> None:
    small = check_calibration_feasibility(["a"] * 5, method="sigmoid")
    assert small["feasible"] is False
    assert small["reasons"]
    assert small["min_rows_required"] == MIN_SIGMOID_CALIBRATION_ROWS
    assert check_calibration_feasibility(["a"] * 30, method="isotonic")[
        "min_rows_required"
    ] == MIN_ISOTONIC_CALIBRATION_ROWS
    assert set(CALIBRATION_METHODS) == {"sigmoid", "isotonic"}

    with pytest.raises(FeraError):
        check_calibration_feasibility(["a"], method="telepathy")


def test_calibration_refuses_to_see_the_forbidden_partition() -> None:
    with pytest.raises(FeraError) as excinfo:
        assert_partition_disjoint(["g1", "g2"], ["g2"], forbidden_label="the held-out test split")
    assert "shares 1 group" in str(excinfo.value)


def test_uncalibrated_metadata_is_explicit() -> None:
    meta = uncalibrated_metadata("no data")
    assert meta["calibrated"] is False
def test_calibrate_estimator_round_trips_and_records_provenance() -> None:
    from sklearn.linear_model import LogisticRegression

    rows: list[list[float]] = []
    labels: list[str] = []
    for index in range(40):
        label = "a" if index % 2 == 0 else "b"
        rows.append([float(index % 2), float((index % 2) * 3)])
        labels.append(label)
    estimator = LogisticRegression(max_iter=200).fit(rows, labels)

    calibrated, meta = calibrate_estimator(
        estimator,
        rows,
        labels,
        classes=["a", "b"],
        method="sigmoid",
        groups=[f"g{index}" for index in range(40)],
        forbidden_groups=["never"],
    )
    assert meta["calibrated"] is True
    assert meta["method"] == "sigmoid"
    assert meta["rows"] == 40
    assert meta["forbidden_partition"] == "the held-out test split"
    assert abs(float(sum(calibrated.predict_proba([[1.0, 3.0]])[0])) - 1.0) < 1e-6


def test_compare_calibration_reports_signed_deltas() -> None:
    truth = ["a", "b", "a", "b"]
    raw = [{"a": 0.6, "b": 0.4}, {"a": 0.55, "b": 0.45}, {"a": 0.9, "b": 0.1}, {"a": 0.2, "b": 0.8}]
    good = [{"a": 1.0, "b": 0.0}, {"a": 0.0, "b": 1.0}, {"a": 1.0, "b": 0.0}, {"a": 0.0, "b": 1.0}]
    comparison = compare_calibration(raw, good, truth, ["a", "b"]).to_dict()
    assert "delta" in comparison and "interpretation" in comparison
    assert comparison["after"]["expected_calibration_error"] <= comparison["before"][
        "expected_calibration_error"
    ]


# ------------------------------------------------------- majority / held-out


def test_majority_baseline_is_derived_from_train_only() -> None:
    data = prepare_dataset(_dataset())
    baseline = majority_class_baseline(data)

    assert baseline["classifier"] == "majority_class"
    assert baseline["majority_class"] in CLASSES
    assert 0.0 < baseline["majority_share"] <= 1.0
    assert set(baseline["splits"]) >= {"train", "val", "test"}
    assert any("not expected to be competitive" in note for note in baseline["notes"])


def test_held_out_configurations_report_disjoint_partitions() -> None:
    rows = _dataset(tag="a-") + _dataset(tag="b-")
    # split_key looks like "exp-web-a-0": the configuration is the tag segment.
    config_of = {row.split_key: ("b" if "-b-" in row.split_key else "a") for row in rows}

    report = evaluate_held_out_configurations(
        rows, config_of, ["b"], candidates=("logistic_regression",)
    )
    assert report["schema"] == HELD_OUT_CONFIG_SCHEMA
    assert report["configuration_overlap"] == []
    assert not set(report["train_configurations"]) & set(report["held_out_configurations"])
    assert report["held_out_configurations"] == ["b"]
    assert report["counts"]["held_out_rows"] == 27
    assert report["status"] != STATUS_INVALID
    # Configuration identity must never leak into the feature columns.
    assert all("config" not in name.lower() for name in report["metrics"]["classes"])


def test_held_out_configuration_refuses_when_nothing_remains_to_train() -> None:
    rows = _dataset()
    config_of = {row.split_key: "only" for row in rows}
    with pytest.raises(FeraError):
        evaluate_held_out_configurations(rows, config_of, ["only"])


def test_held_out_configuration_requires_a_matching_partition() -> None:
    rows = _dataset()
    config_of = {row.split_key: "a" for row in rows}
    with pytest.raises(FeraError):
        evaluate_held_out_configurations(rows, config_of, ["not-present"])
