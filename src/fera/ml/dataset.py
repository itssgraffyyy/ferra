"""Labelled dataset: versioned features joined with ground-truth labels.

This module is the *only* place where features and labels meet.  The join is a
pure append of metadata beside the feature dict - the feature values themselves
come from :func:`fera.ml.features.extract_features`, which cannot see ground
truth at all, so a label can never leak into a model input.

Three properties make the resulting dataset defensible:

* **Honest provenance** - every row repeats the feature schema id, the label
  basis of the class and ``evidence_status = INFERRED``: an encrypted-traffic
  classifier predicts a *class*, it does not observe the application.
* **Grouped splits** - rows are grouped by ``split_key`` (the experiment id),
  so every capture of one experiment lands in exactly one split.  A random
  row-wise split would leak near-duplicate captures across the boundary and
  inflate the reported accuracy.
* **Validated round-trip** - a document is validated when it is built *and*
  when it is read back, so a hand-edited or foreign file fails loudly instead
  of silently training a model on garbage.
"""

from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..analysis.provenance import EvidenceKind
from ..common.errors import ErrorCode, FeraError
from ..common.paths import ProjectPaths, default_paths
from ..common.serialization import load_json, write_json
from ..dataset.manifest import build_manifest
from ..dataset.schema import TrafficClass
from .features import FEATURE_SCHEMA, FEATURE_WHITELIST, FeatureVector, extract_features

#: Schema identifier of one labelled dataset row.
DATASET_SCHEMA = "fera_ml_dataset_v1"
#: JSON key that carries the label of a row (never part of ``features``).
LABEL_FIELD = "traffic_class"
#: Row-level provenance: class membership of encrypted traffic is inferred.
EVIDENCE_STATUS = EvidenceKind.INFERRED.value
SPLITS: tuple[str, ...] = ("train", "val", "test")
DEFAULT_SPLIT_FRACTIONS: tuple[float, ...] = (0.7, 0.15, 0.15)
DATASET_JSONL = "features.jsonl"
DATASET_CSV = "features.csv"
DATASET_SUMMARY = "dataset_summary.json"
#: Columns written before the feature block of the CSV export.
SPLIT_COLUMN = "split"
KEY_COLUMNS: tuple[str, ...] = ("experiment_id", "capture_id", "split_key", SPLIT_COLUMN, LABEL_FIELD)

_LABEL_VALUES = frozenset(member.value for member in TrafficClass)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _contract_error(message: str, **details: Any) -> FeraError:
    """Schema violation inside the ML stage (a bug or a corrupted artefact)."""
    return FeraError(
        message,
        code=ErrorCode.INTERNAL_ERROR,
        hint="rebuild the dataset with scripts/build_dataset.py",
        details=details,
    )


def split_of(
    split_key: str,
    *,
    seed: int,
    fractions: Sequence[float] = DEFAULT_SPLIT_FRACTIONS,
) -> str:
    """Return the split of a group, deterministically and without shuffling.

    The bucket is a hash of ``seed`` and the *group key*, so every capture of
    one experiment receives the same split, the assignment is reproducible
    across machines, and changing the seed re-partitions the data.
    """
    if len(fractions) != len(SPLITS):
        raise _contract_error(
            "split fractions must have one value per split",
            splits=list(SPLITS),
            fractions=list(fractions),
        )
    total = sum(float(fraction) for fraction in fractions)
    if total <= 0:
        raise _contract_error("split fractions must sum to a positive number", fractions=list(fractions))
    digest = hashlib.sha256(f"{seed}\x00{split_key}".encode()).digest()
    bucket = int.from_bytes(digest[:8], "big") / float(1 << 64)
    cutoff = 0.0
    for name, fraction in zip(SPLITS, (float(value) / total for value in fractions), strict=True):
        cutoff += fraction
        if bucket < cutoff:
            return name
    return SPLITS[-1]


def validate_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """Return a canonical copy of one labelled row, or raise :class:`FeraError`.

    Canonical means: known schema ids, a label from the dataset vocabulary, a
    known split, and ``features`` holding exactly the whitelist - in whitelist
    order, finite and numeric (re-checked by :class:`FeatureVector`).
    """
    if document.get("schema") != DATASET_SCHEMA:
        raise _contract_error(
            "unexpected dataset row schema",
            expected=DATASET_SCHEMA,
            actual=document.get("schema"),
        )
    if document.get("feature_schema") != FEATURE_SCHEMA:
        raise _contract_error(
            "unexpected feature schema",
            expected=FEATURE_SCHEMA,
            actual=document.get("feature_schema"),
        )
    for field in KEY_COLUMNS:
        value = document.get(field)
        if not isinstance(value, str) or not value:
            raise _contract_error(f"{field} must be a non-empty string", field=field, actual=value)
    if document[SPLIT_COLUMN] not in SPLITS:
        raise _contract_error(
            "unknown split",
            allowed=list(SPLITS),
            actual=document[SPLIT_COLUMN],
            experiment_id=document.get("experiment_id"),
        )
    label = document[LABEL_FIELD]
    if label not in _LABEL_VALUES:
        raise _contract_error(
            "label is not part of the dataset traffic-class vocabulary",
            allowed=sorted(_LABEL_VALUES),
            actual=label,
            experiment_id=document.get("experiment_id"),
        )
    if document.get("evidence_status") != EVIDENCE_STATUS:
        raise _contract_error(
            "dataset rows carry inferred evidence status",
            expected=EVIDENCE_STATUS,
            actual=document.get("evidence_status"),
        )
    raw_features = document.get("features")
    if not isinstance(raw_features, Mapping):
        raise _contract_error(
            "features must be a mapping",
            actual=type(raw_features).__name__,
            experiment_id=document.get("experiment_id"),
        )
    provenance = document.get("provenance")
    pcap_path = provenance.get("pcap_path", "") if isinstance(provenance, Mapping) else ""
    FeatureVector(pcap_path=str(pcap_path), features=dict(raw_features))
    canonical = dict(document)
    canonical["features"] = {name: float(raw_features[name]) for name in FEATURE_WHITELIST}
    return canonical


@dataclass(frozen=True)
class DatasetSample:
    """One labelled feature row plus the keys that keep it attributable."""

    document: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "document", validate_document(self.document))

    @property
    def experiment_id(self) -> str:
        return str(self.document["experiment_id"])

    @property
    def capture_id(self) -> str:
        return str(self.document["capture_id"])

    @property
    def split_key(self) -> str:
        return str(self.document["split_key"])

    @property
    def split(self) -> str:
        return str(self.document[SPLIT_COLUMN])

    @property
    def label(self) -> str:
        return str(self.document[LABEL_FIELD])

    @property
    def features(self) -> Mapping[str, float]:
        return dict(self.document["features"])  # type: ignore[arg-type]

    def row(self) -> list[float]:
        """Model input row, ordered exactly like :data:`FEATURE_WHITELIST`."""
        features = self.document["features"]
        return [float(features[name]) for name in FEATURE_WHITELIST]

    def to_dict(self) -> dict[str, Any]:
        return dict(self.document)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> DatasetSample:
        return cls(document=document)


def split_groups(samples: Iterable[DatasetSample]) -> dict[str, list[str]]:
    """Map every split to the sorted group keys assigned to it."""
    groups: dict[str, set[str]] = {name: set() for name in SPLITS}
    for sample in samples:
        groups.setdefault(sample.split, set()).add(sample.split_key)
    return {name: sorted(keys) for name, keys in groups.items()}


def split_integrity(samples: Iterable[DatasetSample]) -> dict[str, Any]:
    """Prove that no group key is shared between two splits.

    A shared key means captures of the same experiment were split across the
    train/test boundary, which would silently inflate every reported score.
    """
    seen: dict[str, set[str]] = {}
    for sample in samples:
        seen.setdefault(sample.split_key, set()).add(sample.split)
    overlaps = {key: sorted(splits) for key, splits in sorted(seen.items()) if len(splits) > 1}
    return {"group_count": len(seen), "overlapping_groups": overlaps, "ok": not overlaps}


def _counts(values: Iterable[str]) -> dict[str, int]:
    """Deterministic frequency table (sorted keys, no zero-filled categories)."""
    tally: dict[str, int] = {}
    for value in values:
        tally[value] = tally.get(value, 0) + 1
    return {key: tally[key] for key in sorted(tally)}


@dataclass(frozen=True)
class DatasetBundle:
    """A built dataset: labelled rows plus the audit trail of the build."""

    samples: tuple[DatasetSample, ...]
    rejected: tuple[Mapping[str, Any], ...]
    summary: Mapping[str, Any]

    def rows(self, split: str) -> list[DatasetSample]:
        """Rows of one split, in build order."""
        if split not in SPLITS:
            raise _contract_error("unknown split", allowed=list(SPLITS), actual=split)
        return [sample for sample in self.samples if sample.split == split]

    def xy(self, split: str) -> tuple[list[list[float]], list[str]]:
        """Model-ready ``X``/``y`` of one split, whitelist ordered."""
        rows = self.rows(split)
        return [sample.row() for sample in rows], [sample.label for sample in rows]

    def to_dict(self) -> dict[str, Any]:
        return {
            **dict(self.summary),
            "rejected": [dict(item) for item in self.rejected],
        }


def _assert_labels_are_not_features() -> None:
    """Structural leakage guard: the label key must never be a feature name."""
    if LABEL_FIELD in FEATURE_WHITELIST:
        raise _contract_error(
            "the label key must never appear in the feature whitelist",
            label_field=LABEL_FIELD,
        )


def build_sample(
    pcap_path: Path | str,
    ground_truth: Mapping[str, Any],
    *,
    paths: ProjectPaths,
    seed: int = 0,
    fractions: Sequence[float] = DEFAULT_SPLIT_FRACTIONS,
) -> DatasetSample:
    """Extract features from a capture and join them with its ground truth.

    The feature vector is computed first and *independently*: ground truth only
    supplies the sibling metadata fields (label, label basis, ids) that are
    written next to it.  The split is derived from the **session id**, so all
    captures of one session always share one split.
    """
    path = Path(pcap_path)
    vector = extract_features(path)
    experiment_id = str(ground_truth.get("experiment_id") or "")
    if not experiment_id:
        raise _contract_error("ground truth has no experiment_id", pcap_path=str(path))
    # A session groups the repeats of one configuration.  Splitting on it keeps
    # every repeat of a configuration inside a single split, so a repeated
    # capture cannot appear in training and leak into the test set.  Ground truth
    # written before sessions existed has no session_id, and the experiment id is
    # then the session.
    session_id = str(ground_truth.get("session_id") or "") or experiment_id
    capture = ground_truth.get("capture")
    capture_block = capture if isinstance(capture, Mapping) else {}
    capture_id = str(capture_block.get("path") or paths.relative(path))
    document: dict[str, Any] = {
        "schema": DATASET_SCHEMA,
        "feature_schema": FEATURE_SCHEMA,
        "generated_at": _utc_now(),
        "experiment_id": experiment_id,
        "session_id": session_id,
        "capture_id": capture_id,
        "split_key": session_id,
        SPLIT_COLUMN: split_of(session_id, seed=seed, fractions=fractions),
        LABEL_FIELD: ground_truth.get("traffic_class"),
        "label_basis": ground_truth.get("traffic_label_basis"),
        "evidence_status": EVIDENCE_STATUS,
        "features": dict(vector.features),
        "provenance": {
            "pcap_path": capture_id,
            "ground_truth_source": str(ground_truth.get("ground_truth_source") or ""),
            "feature_source": "deterministic_analysis_plus_pcap_frame_headers",
            "ipsec_mode": str((ground_truth.get("ipsec") or {}).get("mode") or ""),
        },
    }
    return DatasetSample(document=document)


def build_dataset(
    *,
    paths: ProjectPaths | None = None,
    raw_dir: Path | str | None = None,
    seed: int = 0,
    fractions: Sequence[float] = DEFAULT_SPLIT_FRACTIONS,
) -> DatasetBundle:
    """Build the labelled ML dataset from the captured runs below ``raw_dir``.

    Sample selection is delegated to :func:`fera.dataset.manifest.build_manifest`
    so the ML stage cannot invent a looser validity rule than the dataset
    factory: a run that is not a valid sample never reaches the model.  Runs
    that are valid but unextractable (unreadable PCAP, unknown label) are
    reported under ``rejected`` with the reason instead of being dropped
    silently.
    """
    _assert_labels_are_not_features()
    resolved = paths if paths is not None else default_paths()
    manifest = build_manifest(paths=resolved, raw_dir=raw_dir, include_rejected=True)
    samples: list[DatasetSample] = []
    rejected: list[dict[str, Any]] = [dict(item) for item in manifest.get("rejected", [])]
    seen: set[str] = set()
    for entry in manifest["entries"]:
        experiment_id = str(entry.get("experiment_id") or "")
        if experiment_id in seen:
            rejected.append(
                {
                    "experiment_id": experiment_id,
                    "reason": "duplicate experiment_id in manifest",
                    "ground_truth_path": entry.get("ground_truth_path"),
                }
            )
            continue
        seen.add(experiment_id)
        ground_truth_file = resolved.resolve(str(entry["ground_truth_path"]))
        pcap_path = resolved.resolve(str(entry["pcap_path"]))
        try:
            document = load_json(ground_truth_file)
            samples.append(
                build_sample(pcap_path, document, paths=resolved, seed=seed, fractions=fractions)
            )
        except FeraError as error:
            rejected.append(
                {
                    "experiment_id": experiment_id,
                    "ground_truth_path": entry.get("ground_truth_path"),
                    "pcap_path": entry.get("pcap_path"),
                    "reason": f"{error.code.value}: {error.message}",
                }
            )
    samples.sort(key=lambda sample: sample.experiment_id)
    rejected.sort(key=lambda item: str(item.get("experiment_id", "")))
    return DatasetBundle(
        samples=tuple(samples),
        rejected=tuple(rejected),
        summary=_summary(
            samples,
            rejected,
            seed=seed,
            fractions=fractions,
            scanned=int(manifest.get("scanned_runs", 0)),
        ),
    )


def _summary(
    samples: Sequence[DatasetSample],
    rejected: Sequence[Mapping[str, Any]],
    *,
    seed: int,
    fractions: Sequence[float],
    scanned: int,
) -> dict[str, Any]:
    """Audit trail of one dataset build (counts, split balance, integrity)."""
    groups = split_groups(samples)
    by_split: dict[str, dict[str, int]] = {}
    for split in SPLITS:
        by_split[split] = _counts(sample.label for sample in samples if sample.split == split)
    return {
        "schema": DATASET_SCHEMA,
        "feature_schema": FEATURE_SCHEMA,
        "evidence_status": EVIDENCE_STATUS,
        "generated_at": _utc_now(),
        "seed": int(seed),
        "split_fractions": {name: float(value) for name, value in zip(SPLITS, fractions, strict=True)},
        "runs_scanned": int(scanned),
        "sample_count": len(samples),
        "rejected_count": len(rejected),
        "label_counts": _counts(sample.label for sample in samples),
        "split_counts": {split: len([s for s in samples if s.split == split]) for split in SPLITS},
        "label_counts_by_split": by_split,
        "group_counts": {split: len(keys) for split, keys in groups.items()},
        "split_integrity": split_integrity(samples),
        "labels_excluded_from_features": LABEL_FIELD not in FEATURE_WHITELIST,
        "features": list(FEATURE_WHITELIST),
        "notes": (
            "Features describe encrypted-traffic behaviour only; the label lives beside them and is "
            "never a model input.  Splits are grouped by experiment id so no two captures of one "
            "experiment can appear on both sides of a train/test boundary."
        ),
    }


def write_jsonl(samples: Iterable[DatasetSample], path: Path | str) -> Path:
    """Write one labelled row per line (canonical whitelist order, LF newlines)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(
        json.dumps(sample.to_dict(), ensure_ascii=False, sort_keys=False) + "\n" for sample in samples
    )
    target.write_text(body, encoding="utf-8", newline="\n")
    return target


def write_csv(samples: Iterable[DatasetSample], path: Path | str) -> Path:
    """Write the flat table view: key columns, then the whitelist in order."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*KEY_COLUMNS, *FEATURE_WHITELIST])
        writer.writeheader()
        for sample in samples:
            row: dict[str, Any] = {
                "experiment_id": sample.experiment_id,
                "capture_id": sample.capture_id,
                "split_key": sample.split_key,
                SPLIT_COLUMN: sample.split,
                LABEL_FIELD: sample.label,
            }
            row.update({name: repr(value) for name, value in sample.features.items()})
            writer.writerow(row)
    return target


def write_dataset(bundle: DatasetBundle, out_dir: Path | str | None = None) -> dict[str, Path]:
    """Write ``features.jsonl``, ``features.csv`` and ``dataset_summary.json``."""
    target_dir = Path(out_dir) if out_dir is not None else default_paths().processed / "ml"
    return {
        "jsonl": write_jsonl(bundle.samples, target_dir / DATASET_JSONL),
        "csv": write_csv(bundle.samples, target_dir / DATASET_CSV),
        "summary": write_json(target_dir / DATASET_SUMMARY, bundle.to_dict()),
    }


def load_dataset(path: Path | str) -> tuple[DatasetSample, ...]:
    """Read a ``features.jsonl`` back, validating every row as it is parsed."""
    target = Path(path)
    if not target.is_file():
        raise FeraError(
            f"dataset file not found: {target}",
            code=ErrorCode.IO_ERROR,
            hint="build it first with python scripts/build_dataset.py",
            details={"path": str(target)},
        )
    samples: list[DatasetSample] = []
    for number, line in enumerate(target.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except ValueError as exc:
            raise FeraError(
                f"invalid JSON on line {number} of {target}",
                code=ErrorCode.CONFIG_VALIDATION_FAILED,
                details={"path": str(target), "line": number},
            ) from exc
        if not isinstance(payload, dict):
            raise _contract_error(
                "dataset row must be a JSON object",
                path=str(target),
                line=number,
                actual=type(payload).__name__,
            )
        samples.append(DatasetSample.from_dict(payload))
    return tuple(samples)


__all__ = [
    "DATASET_CSV",
    "DATASET_JSONL",
    "DATASET_SCHEMA",
    "DATASET_SUMMARY",
    "DEFAULT_SPLIT_FRACTIONS",
    "EVIDENCE_STATUS",
    "KEY_COLUMNS",
    "LABEL_FIELD",
    "SPLITS",
    "DatasetBundle",
    "DatasetSample",
    "build_dataset",
    "build_sample",
    "load_dataset",
    "split_groups",
    "split_integrity",
    "split_of",
    "validate_document",
    "write_csv",
    "write_dataset",
    "write_jsonl",
]



