"""Leave-one-class-out open-world evaluation tests.

The important assertions here are the *negative* ones: that the held-out class
genuinely never reaches training, selection, calibration or threshold choice.
A test that only checked "the function returns a document" would pass even if the
experiment measured the class it was supposed to hide.

The numbers these fixtures produce are **not** experimental evidence.  They are
assertions about plumbing; the rejection behaviour itself depends entirely on a
real strongSwan ESP dataset that does not exist yet.
"""

from __future__ import annotations

import pytest

from fera.common.errors import FeraError
from fera.ml.dataset import DATASET_SCHEMA, EVIDENCE_STATUS, LABEL_FIELD, DatasetSample
from fera.ml.features import FEATURE_SCHEMA, FEATURE_WHITELIST
from fera.ml.heldout import (
    HELD_OUT_CLASS_SCHEMA,
    STATUS_FIXTURE,
    STATUS_INVALID,
    held_out_class_experiment,
)

LABELS = ("web", "video_like", "voip_like")
HELD_OUT = "voip_like"


def _sample(label: str, group: int, index: int, split: str) -> DatasetSample:
    position = LABELS.index(label)
    features = {
        name: float(index + 1) * (order + 1) / 100.0
        for order, name in enumerate(FEATURE_WHITELIST)
    }
    # Give each class a distinct, consistent signature so training is meaningful.
    features["esp_avg_len"] = 120.0 + 50.0 * position
    features["esp_iat_mean_s"] = 0.01 + 0.02 * position
    features["esp_fwd_packet_share"] = 0.3 + 0.2 * position
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
    for label in LABELS:
        for group, split in enumerate(("train", "val", "test")):
            for index in range(3):
                rows.append(_sample(label, group, index + group * 3, split))
    return rows


def test_held_out_class_is_absent_from_the_model(dataset) -> None:
    """The core leakage guarantee: the hidden class is not a known class."""
    report = held_out_class_experiment(dataset, HELD_OUT, candidates=("logistic_regression",))

    assert report["schema"] == HELD_OUT_CLASS_SCHEMA
    assert report["held_out_class"] == HELD_OUT
    assert HELD_OUT not in report["known_classes"]
    assert report["leakage_check"]["held_out_class_in_model_classes"] is False


def test_held_out_experiment_groups_do_not_overlap(dataset) -> None:
    report = held_out_class_experiment(dataset, HELD_OUT, candidates=("logistic_regression",))

    check = report["leakage_check"]
    assert check["overlapping_groups"] == []
    assert not set(check["unknown_groups"]) & set(check["known_groups"])
    assert report["counts"]["unknown_rows"] == 9
    assert report["counts"]["unknown_groups"] == 3


def test_threshold_is_chosen_without_seeing_the_unknown_pool(dataset) -> None:
    """The sweep must contain no unknown rows at all."""
    report = held_out_class_experiment(dataset, HELD_OUT, candidates=("logistic_regression",))

    assert report["threshold_source"] == "VALIDATION-DERIVED"
    assert all(row["unknown_rows"] == 0 for row in report["threshold_sweep"]["rows"])
    assert all(
        row["status"] == "UNVERIFIED - UNKNOWN VALIDATION DATA REQUIRED"
        for row in report["threshold_sweep"]["rows"]
    )


def test_report_is_labelled_as_fixture_not_experiment(dataset) -> None:
    """A fixture run must never present itself as experimental evidence."""
    report = held_out_class_experiment(dataset, HELD_OUT, candidates=("logistic_regression",))

    assert report["status"] == STATUS_FIXTURE
    assert "NOT EXPERIMENTAL EVIDENCE" in report["status"]
    assert "not experimental" in " ".join(report["notes"]).lower()


def test_limitations_are_not_mistaken_for_structural_failure(dataset) -> None:
    """Too little calibration data is a caveat, not an invalid experiment."""
    report = held_out_class_experiment(dataset, HELD_OUT, candidates=("logistic_regression",))

    # This fixture's validation split is far below the calibration minimum.
    assert report["calibration"]["calibrated"] is False
    assert report["limitations"], "an uncalibrated run must say so"
    assert report["reasons"] == [], "a caveat must not invalidate the measurement"
    assert report["status"] != STATUS_INVALID


def test_open_world_metrics_are_reported_honestly(dataset) -> None:
    report = held_out_class_experiment(dataset, HELD_OUT, candidates=("logistic_regression",))
    metrics = report["open_world_metrics"]

    assert metrics["unknown_rows"] == 9
    assert metrics["unknown_rejection_rate"] is not None
    assert 0.0 <= metrics["coverage"] <= 1.0
    # acceptance and false-rejection are complements
    assert abs(
        metrics["known_acceptance_rate"] + metrics["known_false_rejection_rate"] - 1.0
    ) < 1e-9


def test_closed_set_metrics_score_only_accepted_rows(dataset) -> None:
    """A rejected row has no class, so it must not be scored as a wrong one."""
    report = held_out_class_experiment(dataset, HELD_OUT, candidates=("logistic_regression",))

    if report["known_metrics"] is not None:
        assert report["known_metrics"]["sample_count"] <= report["counts"]["test_rows"]


def test_unknown_class_must_exist(dataset) -> None:
    with pytest.raises(FeraError):
        held_out_class_experiment(dataset, "not_a_class", candidates=("logistic_regression",))


def test_experiment_is_deterministic(dataset) -> None:
    first = held_out_class_experiment(dataset, HELD_OUT, candidates=("logistic_regression",))
    second = held_out_class_experiment(dataset, HELD_OUT, candidates=("logistic_regression",))

    assert first["threshold"] == second["threshold"]
    assert first["open_world_metrics"] == second["open_world_metrics"]
