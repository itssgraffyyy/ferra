"""Dataset pipeline tests: labels, splits, exports and leakage guards."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pytest

from conftest import ike_and_esp_frames, make_config, write_pcap
from fera.common.errors import ErrorCode, FeraError
from fera.common.paths import ProjectPaths
from fera.common.serialization import write_json
from fera.dataset.ground_truth import build_ground_truth
from fera.dataset.schema import TrafficClass
from fera.ml import FEATURE_WHITELIST, extract_features
from fera.ml.dataset import (
    DATASET_CSV,
    DATASET_JSONL,
    DATASET_SCHEMA,
    DATASET_SUMMARY,
    EVIDENCE_STATUS,
    KEY_COLUMNS,
    LABEL_FIELD,
    SPLITS,
    DatasetSample,
    build_dataset,
    build_sample,
    load_dataset,
    split_groups,
    split_integrity,
    split_of,
    validate_document,
    write_dataset,
    write_jsonl,
)


def write_run(
    paths: ProjectPaths,
    topology: Any,
    experiment_id: str,
    *,
    traffic_type: TrafficClass = TrafficClass.ICMP,
    valid: bool = True,
    dry_run: bool = False,
    with_pcap: bool = True,
    traffic_class_override: str | None = None,
) -> Path:
    """Write one synthetic experiment run exactly as the runner would.

    Returns the ground-truth path.  The pcap holds the same deterministic frame
    mix for every run, so the only thing that differs between runs is the label
    - which is what makes leakage visible in a test.
    """
    config = make_config(experiment_id, traffic_type=traffic_type)
    experiment_dir = paths.raw / experiment_id
    experiment_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = experiment_dir / "capture.pcap"
    if with_pcap:
        write_pcap(pcap_path, ike_and_esp_frames())
    relative_pcap = paths.relative(pcap_path)
    document = build_ground_truth(
        config,
        topology,
        execution_status="SUCCESS",
        dry_run=dry_run,
        valid_capture=valid,
        integration_verified=valid,
        error_code=None if valid else "CAPTURE_VALIDATION_FAILED",
        error_message=None if valid else "capture validation failed",
        pcap_path=str(pcap_path),
        pcap_relative_path=relative_pcap,
        capture_details={"tool": "tc", "size_bytes": pcap_path.stat().st_size if with_pcap else 0},
        validation={
            "status": "VALID" if valid else "INVALID",
            "valid": valid,
            "method": "pcap_scan",
            "packets": 7,
            "ike_detected": True,
            "esp_detected": valid,
            "reasons": [] if valid else ["no ESP (IP protocol 50) found in the capture"],
        },
        experiment_config_path=f"configs/experiments/{experiment_id}.yaml",
    ).to_dict()
    if traffic_class_override is not None:
        document["traffic_class"] = traffic_class_override
    return write_json(experiment_dir / "ground_truth.json", document)


def test_build_dataset_joins_labels_with_features(sandbox_paths: ProjectPaths, topology: Any) -> None:
    write_run(sandbox_paths, topology, "exp_000", traffic_type=TrafficClass.ICMP)
    write_run(sandbox_paths, topology, "exp_001", traffic_type=TrafficClass.VOIP_LIKE)

    bundle = build_dataset(paths=sandbox_paths)

    assert [sample.experiment_id for sample in bundle.samples] == ["exp_000", "exp_001"]
    assert [sample.label for sample in bundle.samples] == ["icmp", "voip_like"]
    assert bundle.summary["sample_count"] == 2
    assert bundle.summary["rejected_count"] == 0
    for sample in bundle.samples:
        assert list(sample.features) == list(FEATURE_WHITELIST)
        assert sample.document["schema"] == DATASET_SCHEMA
        assert sample.split in SPLITS


def test_label_never_leaks_into_the_feature_row(sandbox_paths: ProjectPaths, topology: Any) -> None:
    """Same capture, different label: the model input must stay identical."""
    write_run(sandbox_paths, topology, "exp_000", traffic_type=TrafficClass.ICMP)
    write_run(sandbox_paths, topology, "exp_001", traffic_type=TrafficClass.VOIP_LIKE)

    bundle = build_dataset(paths=sandbox_paths)
    rows = [sample.row() for sample in bundle.samples]

    assert LABEL_FIELD not in FEATURE_WHITELIST
    assert rows[0] == rows[1]  # identical captures -> identical inputs, labels are separate
    assert bundle.summary["labels_excluded_from_features"] is True


def test_dataset_features_equal_standalone_extraction(sandbox_paths: ProjectPaths, topology: Any) -> None:
    write_run(sandbox_paths, topology, "exp_000")
    bundle = build_dataset(paths=sandbox_paths)
    standalone = extract_features(sandbox_paths.raw / "exp_000" / "capture.pcap")

    assert dict(bundle.samples[0].features) == dict(standalone.features)


def test_every_row_declares_inferred_evidence(sandbox_paths: ProjectPaths, topology: Any) -> None:
    write_run(sandbox_paths, topology, "exp_000")
    bundle = build_dataset(paths=sandbox_paths)

    assert EVIDENCE_STATUS == "INFERRED"
    assert all(sample.document["evidence_status"] == EVIDENCE_STATUS for sample in bundle.samples)
    assert bundle.summary["evidence_status"] == EVIDENCE_STATUS
    assert bundle.samples[0].document["label_basis"]


def test_invalid_run_is_rejected_not_silently_dropped(
    sandbox_paths: ProjectPaths, topology: Any
) -> None:
    write_run(sandbox_paths, topology, "exp_000")
    write_run(sandbox_paths, topology, "exp_001", valid=False)

    bundle = build_dataset(paths=sandbox_paths)

    assert [sample.experiment_id for sample in bundle.samples] == ["exp_000"]
    assert bundle.summary["rejected_count"] == 1
    assert "not a valid sample" in str(bundle.rejected[0]["reason"])


def test_dry_run_artefacts_are_never_samples(sandbox_paths: ProjectPaths, topology: Any) -> None:
    write_run(sandbox_paths, topology, "exp_000", dry_run=True)

    bundle = build_dataset(paths=sandbox_paths)

    assert bundle.samples == ()
    assert "dry run" in str(bundle.rejected[0]["reason"])


def test_run_without_capture_file_is_rejected(
    sandbox_paths: ProjectPaths, topology: Any
) -> None:
    write_run(sandbox_paths, topology, "exp_000", with_pcap=False)

    bundle = build_dataset(paths=sandbox_paths)

    assert bundle.samples == ()
    assert "capture file is missing" in str(bundle.rejected[0]["reason"])


def test_label_outside_the_vocabulary_is_rejected(
    sandbox_paths: ProjectPaths, topology: Any
) -> None:
    write_run(sandbox_paths, topology, "exp_000", traffic_class_override="definitely_not_a_class")

    bundle = build_dataset(paths=sandbox_paths)

    assert bundle.samples == ()
    reason = str(bundle.rejected[0]["reason"])
    assert ErrorCode.INTERNAL_ERROR.value in reason
    assert "traffic-class vocabulary" in reason



def test_splits_are_grouped_by_experiment(sandbox_paths: ProjectPaths, topology: Any) -> None:
    for index in range(12):
        write_run(sandbox_paths, topology, f"exp_{index:03d}")

    bundle = build_dataset(paths=sandbox_paths)
    integrity = split_integrity(bundle.samples)
    groups = split_groups(bundle.samples)

    assert integrity["ok"] is True
    assert integrity["overlapping_groups"] == {}
    assert integrity["group_count"] == 12
    assert sorted(key for keys in groups.values() for key in keys) == [
        f"exp_{index:03d}" for index in range(12)
    ]
    assert bundle.summary["split_integrity"]["ok"] is True


def test_split_assignment_is_reproducible_and_seed_dependent() -> None:
    keys = [f"exp_{index:03d}" for index in range(24)]

    assert all(split_of(key, seed=3) == split_of(key, seed=3) for key in keys)
    assert {split_of(key, seed=0) for key in keys} == set(SPLITS)
    assert [split_of(key, seed=1) for key in keys] != [split_of(key, seed=0) for key in keys]


def test_extreme_split_fractions_are_honoured() -> None:
    keys = [f"exp_{index:03d}" for index in range(6)]

    assert {split_of(key, seed=0, fractions=(1.0, 0.0, 0.0)) for key in keys} == {"train"}
    assert {split_of(key, seed=0, fractions=(0.0, 0.0, 1.0)) for key in keys} == {"test"}
    with pytest.raises(FeraError):
        split_of("exp_000", seed=0, fractions=(0.0, 0.0))
    with pytest.raises(FeraError):
        split_of("exp_000", seed=0, fractions=(0.0, 0.0, 0.0))


def test_exports_round_trip_without_loss(sandbox_paths: ProjectPaths, topology: Any) -> None:
    for index in range(6):
        write_run(sandbox_paths, topology, f"exp_{index:03d}")
    bundle = build_dataset(paths=sandbox_paths)

    written = write_dataset(bundle, sandbox_paths.processed / "ml")

    assert written["jsonl"].name == DATASET_JSONL
    assert written["csv"].name == DATASET_CSV
    assert written["summary"].name == DATASET_SUMMARY
    assert [sample.to_dict() for sample in load_dataset(written["jsonl"])] == [
        sample.to_dict() for sample in bundle.samples
    ]
    with written["csv"].open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows
    assert list(rows[0]) == [*KEY_COLUMNS, *FEATURE_WHITELIST]
    for row, sample in zip(rows, bundle.samples, strict=True):
        assert row[LABEL_FIELD] == sample.label
        assert row["split"] == sample.split
        assert row["split_key"] == sample.split_key
        for name in FEATURE_WHITELIST:
            assert float(row[name]) == sample.features[name]
    summary = json.loads(written["summary"].read_text(encoding="utf-8"))
    assert summary["sample_count"] == 6
    assert sum(summary["split_counts"].values()) == 6


def test_bundle_selects_rows_per_split(sandbox_paths: ProjectPaths, topology: Any) -> None:
    for index in range(6):
        write_run(sandbox_paths, topology, f"exp_{index:03d}")
    bundle = build_dataset(paths=sandbox_paths)

    train_features, train_labels = bundle.xy("train")
    assert all(sample.split == "train" for sample in bundle.rows("train"))
    assert len(train_features) == len(train_labels) == len(bundle.rows("train"))
    assert all(len(row) == len(FEATURE_WHITELIST) for row in train_features)
    assert set(train_labels) <= {member.value for member in TrafficClass}
    with pytest.raises(FeraError):
        bundle.rows("holdout")


def test_loader_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FeraError) as excinfo:
        load_dataset(tmp_path / "absent.jsonl")
    assert excinfo.value.code is ErrorCode.IO_ERROR


def test_loader_rejects_a_foreign_row_schema(tmp_path: Path) -> None:
    target = tmp_path / "features.jsonl"
    target.write_text(json.dumps({"schema": "something_else"}) + "\n", encoding="utf-8")

    with pytest.raises(FeraError) as excinfo:
        load_dataset(target)
    assert excinfo.value.code is ErrorCode.INTERNAL_ERROR


def test_loader_rejects_a_malformed_line(tmp_path: Path) -> None:
    target = tmp_path / "features.jsonl"
    target.write_text("{not json}\n", encoding="utf-8")

    with pytest.raises(FeraError) as excinfo:
        load_dataset(target)
    assert excinfo.value.code is ErrorCode.CONFIG_VALIDATION_FAILED


def test_validation_rejects_tampered_rows(sandbox_paths: ProjectPaths, topology: Any) -> None:
    write_run(sandbox_paths, topology, "exp_000")
    base = build_dataset(paths=sandbox_paths).samples[0].to_dict()

    for mutate in (
        lambda row: row["features"].pop(FEATURE_WHITELIST[0]),
        lambda row: row["features"].__setitem__("esp_packets", float("nan")),
        lambda row: row["features"].__setitem__("unexpected", 1.0),
        lambda row: row.__setitem__(LABEL_FIELD, "not_a_class"),
        lambda row: row.__setitem__("split", "holdout"),
        lambda row: row.__setitem__("evidence_status", "OBSERVED"),
        lambda row: row.__setitem__("feature_schema", "fera_esp_features_v0"),
    ):
        tampered = json.loads(json.dumps(base))
        mutate(tampered)
        with pytest.raises(FeraError) as excinfo:
            validate_document(tampered)
        assert excinfo.value.code is ErrorCode.INTERNAL_ERROR


def test_build_sample_requires_an_experiment_id(sandbox_paths: ProjectPaths) -> None:
    pcap_path = sandbox_paths.raw / "capture.pcap"
    write_pcap(pcap_path, ike_and_esp_frames())

    with pytest.raises(FeraError) as excinfo:
        build_sample(pcap_path, {}, paths=sandbox_paths)
    assert "experiment_id" in str(excinfo.value.message)


def test_jsonl_writer_is_canonical(sandbox_paths: ProjectPaths, topology: Any) -> None:
    write_run(sandbox_paths, topology, "exp_000")
    bundle = build_dataset(paths=sandbox_paths)
    target = sandbox_paths.processed / "rows.jsonl"

    write_jsonl(bundle.samples, target)
    lines = target.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 1
    assert list(json.loads(lines[0])["features"]) == list(FEATURE_WHITELIST)
    assert target.read_text(encoding="utf-8").endswith("\n")
    assert DatasetSample(document=bundle.samples[0].to_dict()).label == "icmp"

