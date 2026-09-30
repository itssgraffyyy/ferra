"""Training and feature-set ablation tests.

These cover the two honesty guarantees that are easy to break and invisible in a
passing score: an ablation must never persist a deployable artefact, and it must
report a blocked feature set as a *result* rather than aborting the comparison.
No tshark, no VPN, no real captures - the dataset is a small synthetic one.
"""

from __future__ import annotations

import math

import pytest

from fera.common.errors import ErrorCode, FeraError
from fera.ml.dataset import DATASET_SCHEMA, EVIDENCE_STATUS, LABEL_FIELD, DatasetSample
from fera.ml.feature_sets import FEATURE_SETS, SHORTCUT_CANDIDATE_FEATURES
from fera.ml.features import FEATURE_SCHEMA, FEATURE_WHITELIST
from fera.ml.metrics import macro_f1
from fera.ml.train import (
    ABLATION_SCHEMA,
    DEFAULT_ABLATION_SETS,
    ablate_feature_sets,
    resolve_features,
    train_traffic_model,
)

#: Two real classes from the dataset vocabulary, so every split holds both.
LABELS = ("web", "video_like")


def _sample(group: int, index: int, label: str, split: str) -> DatasetSample:
    """One deterministic labelled row.

    ``group`` is the experiment key: every row sharing a group must sit in the
    same split, because :func:`fera.ml.train.prepare_dataset` refuses a dataset
    whose group keys straddle the train/test boundary.
    """
    features = {
        name: float(index + 1) * (position + 1) / 100.0
        for position, name in enumerate(FEATURE_WHITELIST)
    }
    features["ike_packet_count"] = float(index)  # a shortcut candidate
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
    """12 rows: 2 groups x 2 captures x 3 splits, per label, both labels everywhere.

    Each (label, split) pair is one group, so a group never straddles a split.
    """
    samples: list[DatasetSample] = []
    for label in LABELS:
        for group, split in enumerate(("train", "val", "test")):
            for index in range(2):
                samples.append(_sample(group, index + group * 2, label, split))
    return samples


def test_ablation_compares_the_shortcut_suspects_against_the_full_set(dataset) -> None:
    report = ablate_feature_sets(dataset, candidates=("logistic_regression",))

    assert report["schema"] == ABLATION_SCHEMA
    assert report["feature_sets"] == list(DEFAULT_ABLATION_SETS) == ["all", "esp_core"]
    assert report["comparable"] is True
    assert [row["feature_set"] for row in report["results"]] == ["all", "esp_core"]
    assert all(row["status"] == "trained" for row in report["results"])

    baseline, reduced = report["results"]
    # The baseline has no delta to report against; that is not a missing value.
    assert baseline["delta_test_macro_f1"] is None
    assert reduced["delta_test_macro_f1"] is not None
    assert reduced["feature_count"] < baseline["feature_count"]
    assert reduced["feature_count"] == len(FEATURE_SETS["esp_core"])


def test_ablation_drops_the_shortcut_candidate_columns(dataset) -> None:
    report = ablate_feature_sets(dataset, candidates=("logistic_regression",))
    reduced = next(row for row in report["results"] if row["feature_set"] == "esp_core")
    names = resolve_features(FEATURE_SETS["esp_core"])
    assert not set(names) & set(SHORTCUT_CANDIDATE_FEATURES)
    assert set(names) <= set(FEATURE_WHITELIST)
    assert reduced["feature_count"] == len(names)



def test_ablation_persists_nothing(dataset, monkeypatch) -> None:
    """An ablation is an experiment; it must not leave a deployable artefact."""
    from fera.ml import train as train_module

    written: list[object] = []

    def _record(*args: object, **kwargs: object) -> None:
        written.append(args)

    monkeypatch.setattr(train_module, "write_model", _record)

    report = ablate_feature_sets(dataset, candidates=("logistic_regression",))

    assert written == []
    # Nor may a report claim a path or an artefact it never created.
    assert all(row.get("artefact") is None for row in report["results"])


def test_ablation_reports_a_blocked_set_instead_of_aborting(dataset) -> None:
    """A set that cannot train is recorded as a result, not raised as a crash."""
    report = ablate_feature_sets(
        dataset, feature_sets=("all", "auxiliary"), candidates=("logistic_regression",)
    )

    assert report["comparable"] is True
    auxiliary = next(row for row in report["results"] if row["feature_set"] == "auxiliary")
    assert auxiliary["status"] in {"trained", "blocked"}
    if auxiliary["status"] == "blocked":
        assert auxiliary["error"]["code"]
    assert report["performance_status"]


def test_unknown_feature_set_is_a_configuration_error(dataset) -> None:
    report = ablate_feature_sets(dataset, feature_sets=("not_a_set",), candidates=("logistic_regression",))

    row = report["results"][0]
    assert row["status"] == "blocked"
    assert row["error"]["code"] == ErrorCode.CONFIG_VALIDATION_FAILED.value
    assert "available" in row["error"]["details"]


def test_training_a_single_set_reports_a_measured_selection(dataset) -> None:
    report = train_traffic_model(
        dataset, feature_set="all", candidates=("logistic_regression",), persist=False
    )

    assert report["selection"]["winner"] in {"logistic_regression"}
    assert set(report["feature_names"]) == set(FEATURE_WHITELIST)
    assert report["performance_status"]
    macro = macro_f1(dict(report["test"]))
    assert 0.0 <= macro <= 1.0
    assert not math.isnan(macro)


def test_training_refuses_a_dataset_with_a_single_class() -> None:
    """One class cannot be learned; that must be refused, not scored as 1.0."""
    single = [_sample(0, index, LABELS[0], "train") for index in range(2)]
    with pytest.raises(FeraError) as excinfo:
        train_traffic_model(single, feature_set="all", candidates=("logistic_regression",), persist=False)

    assert isinstance(excinfo.value.code, ErrorCode)
