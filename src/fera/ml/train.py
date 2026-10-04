"""Training, comparison and selection of the ESP traffic classifier.

This module produces the artefact that :mod:`fera.ml.inference` loads.  It
deliberately reuses - rather than reimplements - the two contracts that make a
FERA score defensible, both owned by :mod:`fera.ml.dataset`:

* **the split assignment** is whatever the dataset recorded per *group* (one
  experiment id, one split).  Nothing here reshuffles, re-fractions or reseeds a
  split: training consumes ``train``, model selection consumes ``val``, and
  ``test`` is opened once, after the winner exists;
* **the feature contract** is :data:`fera.ml.features.FEATURE_WHITELIST`; the
  columns a candidate actually saw are persisted with it (see
  :mod:`fera.ml.feature_sets` for the named subsets an experiment may compare).

Honesty rules the code enforces rather than merely recommends:

* the held-out metrics are computed from the selected pipeline only and are never
  an input to selection, which ``selection.test_informed = false`` records;
* ground truth never reaches a model matrix - a column whose name suggests a
  label, an experiment identity or a capture filename is refused before any
  estimator is built (:data:`FORBIDDEN_FEATURE_KEYS`);
* a dataset too small to mean anything still produces a model, because the
  machinery must be testable, but its report says
  ``UNVERIFIED - INSUFFICIENT REAL LABELLED DATA`` instead of quoting an accuracy
  as though it were a capability.  Rows are never duplicated to look larger.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ..common.errors import ErrorCode, FeraError
from ..common.paths import default_paths
from ..common.versions import python_version
from .calibration import (
    calibrate_estimator,
    check_calibration_feasibility,
    compare_calibration,
    uncalibrated_metadata,
)
from .dataset import LABEL_FIELD, SPLITS, DatasetSample, load_dataset, split_groups, split_integrity
from .explain import importance_document
from .feature_sets import feature_set_name, resolve_feature_set, resolve_features
from .features import FEATURE_SCHEMA, FEATURE_WHITELIST
from .inference import (
    MODEL_SCHEMA,
    write_model,
)
from .metrics import METRIC_PRECISION, classification_metrics, macro_f1, ordered_labels
from .openworld import SOURCE_VALIDATION, RejectionPolicy, disabled_policy

#: Schema identifier of a training report.
TRAINING_SCHEMA = "fera_ml_training_v1"
#: Version stamped into every artefact this module writes; bump with the layout.
MODEL_VERSION = "1"
#: Seed used when a caller supplies none (kept explicit, never implicit).
DEFAULT_SEED = 0

#: Selection criterion, recorded verbatim so a report cannot be reinterpreted.
SELECTION_CRITERION = "macro F1 on the validation split"
#: Validation macro F1 differences below this count as a tie.
TIE_TOLERANCE = 0.01

#: Performance status vocabulary (also what a dashboard prints).
PERFORMANCE_MEASURED = "MEASURED"
PERFORMANCE_UNVERIFIED = "UNVERIFIED - INSUFFICIENT REAL LABELLED DATA"

#: Smallest row counts at which a reported metric still means something.
MIN_TRAIN_ROWS = 8
MIN_TRAIN_ROWS_PER_CLASS = 2
MIN_EVAL_ROWS = 4
MIN_ROWS_PER_CLASS = 4

#: Column names that must never reach a model matrix even if a hand-edited
#: dataset supplies them: the answer key, or anything that identifies it
#: (experiment names and capture filenames encode the label in this testbed).
FORBIDDEN_FEATURE_KEYS = frozenset(
    {
        LABEL_FIELD,
        "label",
        "traffic_label",
        "traffic_type",
        "class",
        "class_label",
        "class_name",
        "application",
        "application_label",
        "app_label",
        "ground_truth",
        "label_basis",
        "experiment",
        "experiment_id",
        "experiment_name",
        "split",
        "split_key",
        "capture",
        "capture_id",
        "capture_filename",
        "capture_path",
        "pcap",
        "pcap_path",
        "output",
        "output_path",
        "manifest",
    }
)

#: Substrings that make a column name leak-flavoured (checked case-insensitively).
LEAK_KEY_MARKERS = ("label", "ground_truth", "truth", "class", "traffic_type", "application")

#: The four lightweight scikit-learn candidates.  ``rank`` orders them from
#: simplest to most complex and is the deterministic tie-breaker; ``proba``
#: records whether the estimator can produce a real probability (all four can,
#: which is why the deployed baseline is allowed to report one).
CANDIDATE_MODELS: Mapping[str, Mapping[str, Any]] = {
    "logistic_regression": {
        "estimator": "LogisticRegression",
        "rank": 1,
        "scaling": True,
        "proba": True,
        "kwargs": {"C": 1.0, "max_iter": 2000, "class_weight": "balanced"},
    },
    "decision_tree": {
        "estimator": "DecisionTreeClassifier",
        "rank": 2,
        "scaling": False,
        "proba": True,
        "kwargs": {"class_weight": "balanced"},
    },
    "random_forest": {
        "estimator": "RandomForestClassifier",
        "rank": 3,
        "scaling": False,
        "proba": True,
        "kwargs": {"n_estimators": 300, "class_weight": "balanced_subsample"},
    },
    "hist_gradient_boosting": {
        "estimator": "HistGradientBoostingClassifier",
        "rank": 4,
        "scaling": False,
        "proba": True,
        "kwargs": {"max_iter": 200, "learning_rate": 0.1, "early_stopping": False},
    },
}

#: Selection order (also the tie-break order: simpler first).
CANDIDATE_ORDER: tuple[str, ...] = ("logistic_regression", "decision_tree", "random_forest", "hist_gradient_boosting")


class TrainingError(FeraError):
    """Training cannot produce an artefact from the dataset it was given."""


def _training_error(message: str, **details: Any) -> TrainingError:
    return TrainingError(
        message,
        code=ErrorCode.CONFIG_VALIDATION_FAILED,
        hint="inspect the dataset report; the split assignment comes from fera.ml.dataset",
        details=details,
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _count(values: Sequence[str]) -> dict[str, int]:
    """Deterministic frequency table (sorted keys, no zero-filled categories)."""
    tally: dict[str, int] = {}
    for value in values:
        tally[value] = tally.get(value, 0) + 1
    return dict(sorted(tally.items()))


@dataclass(frozen=True)
class PreparedData:
    """Model-ready matrices of one dataset, with the grouping keys kept beside them.

    ``groups`` is retained per split so a report can state how many *sessions*
    a metric rests on, not just how many rows - three repeats of one
    configuration are one piece of evidence, not three.
    """

    feature_names: tuple[str, ...]
    splits: Mapping[str, Mapping[str, Any]]
    classes: tuple[str, ...]
    integrity: Mapping[str, Any]
    fingerprint: str
    row_count: int

    def matrix(self, split: str) -> list[list[float]]:
        return [list(row) for row in (self.splits[split]["rows"] if split in self.splits else [])]

    def labels(self, split: str) -> list[str]:
        return [str(item) for item in (self.splits.get(split) or {}).get("labels", [])]

    def groups(self, split: str) -> list[str]:
        return [str(item) for item in (self.splits.get(split) or {}).get("groups", [])]


def dataset_fingerprint(samples: Sequence[DatasetSample], features: Sequence[str]) -> str:
    """Content hash of the rows and split assignment a model was trained on.

    Two artefacts with the same fingerprint were trained on the same data, which
    is what makes a re-run comparable; the hash covers the split and group keys
    precisely because a *different* split of the same rows is a different model.
    """
    digest = hashlib.sha256()
    names = tuple(features)
    digest.update("|".join(names).encode("utf-8"))
    for sample in sorted(samples, key=lambda item: (item.split_key, item.capture_id)):
        row = sample.row()
        values = ",".join(f"{row[index]!r}" for index in range(len(names)))
        digest.update(f";{sample.split}:{sample.split_key}:{sample.label}:{values}".encode())
    return digest.hexdigest()[:32]


def prepare_dataset(
    samples: Sequence[DatasetSample],
    *,
    features: Sequence[str] | None = None,
    feature_set: str | None = None,
) -> PreparedData:
    """Project dataset rows onto model-ready matrices, honouring the stored split.

    No sampling, no shuffling, no re-splitting happens here: the split column
    written by :mod:`fera.ml.dataset` is taken as authoritative, and rows are
    ordered by group key so a re-run of the trainer is bit-identical.
    """
    names = resolve_feature_set(feature_set) if feature_set else resolve_features(features)
    if not samples:
        raise _training_error("the dataset holds no rows, so there is nothing to train on")
    integrity = split_integrity(samples)
    if not integrity["ok"]:
        raise _training_error(
            "grouped split integrity violated: captures of one session straddle a split boundary",
            overlapping=integrity["overlapping_groups"],
        )
    indices = [next(index for index, candidate in enumerate(FEATURE_WHITELIST, start=0) if candidate == name) for name in names]
    ordered = sorted(samples, key=lambda item: (item.split_key, item.capture_id))
    splits: dict[str, dict[str, Any]] = {name: {"rows": [], "labels": [], "groups": []} for name in SPLITS}
    for sample in ordered:
        row = sample.row()
        bucket = splits.setdefault(sample.split, {"rows": [], "labels": [], "groups": []})
        bucket["rows"].append([row[index] for index in indices])
        bucket["labels"].append(sample.label)
        bucket["groups"].append(sample.split_key)
    classes = ordered_labels(*[bucket["labels"] for bucket in splits.values()])
    return PreparedData(
        feature_names=names,
        splits=splits,
        classes=classes,
        integrity=integrity,
        fingerprint=dataset_fingerprint(samples, FEATURE_WHITELIST),
        row_count=len(samples),
    )


def audit_features(feature_names: Sequence[str]) -> dict[str, Any]:
    """Refuse any column that is not whitelisted or that could carry the answer key.

    The whitelist check is the strong one (a non-whitelisted column cannot be
    produced by the extractor at all); the forbidden-name check exists for a
    hand-edited dataset file and for a future whitelist change, and it is written
    so that adding a feature named ``traffic_class_proxy`` fails closed.
    """
    unknown = [name for name in feature_names if name not in set(FEATURE_WHITELIST)]
    forbidden = [name for name in feature_names if name in FORBIDDEN_FEATURE_KEYS]
    leak_flavoured = [
        name
        for name in feature_names
        if name not in set(FEATURE_WHITELIST)
        and any(marker in name.lower() for marker in LEAK_KEY_MARKERS)
    ]
    if unknown or forbidden or leak_flavoured:
        raise _training_error(
            "the requested feature set is not safe to train on",
            unknown=unknown,
            forbidden=forbidden,
            leak_flavoured=leak_flavoured,
        )
    return {
        "checked": list(feature_names),
        "count": len(feature_names),
        "whitelist": FEATURE_SCHEMA,
        "forbidden_keys_checked": sorted(FORBIDDEN_FEATURE_KEYS),
        "ok": True,
    }


def audit_data(data: PreparedData) -> dict[str, Any]:
    """Validate what training is about to consume, and say how much it proves.

    Two verdicts stay apart on purpose:

    * **correctness** (hard failure): an empty split, no held-out split, fewer
      than two training classes, a non-finite number, an overlapping group, or a
      class that exists only outside training.  Training on any of those yields a
      number nobody can interpret.
    * **sufficiency** (soft): enough rows, enough groups, and every class seen
      often enough for a rate to be more than noise.  Falling short does not stop
      the run - the machinery must stay testable on a small legitimate dataset -
      but the report says ``UNVERIFIED - INSUFFICIENT REAL LABELLED DATA``
      instead of quoting an accuracy as though it were a capability.
    """
    problems: list[str] = []
    reasons: list[str] = []
    summary: dict[str, Any] = {}
    for split in data.splits:
        rows = data.matrix(split)
        labels = data.labels(split)
        groups = data.groups(split)
        if any(not all(math.isfinite(value) for value in row) for row in rows):
            problems.append(f"{split}: at least one feature value is not finite")
        if any(len(row) != len(data.feature_names) for row in rows):
            problems.append(f"{split}: a row width disagrees with the feature list")
        summary[split] = {
            "rows": len(rows),
            "groups": len(set(groups)),
            "class_count": len(set(labels)),
            "label_counts": _count(labels),
        }
    train, val, test = (summary[name] for name in SPLITS)
    if not train["rows"]:
        problems.append("the train split is empty")
    if not val["rows"]:
        problems.append("the validation split is empty, so no model could be selected honestly")
    if not test["rows"]:
        problems.append("the test split is empty, so no held-out evaluation would exist")
    if train["class_count"] < 2:
        problems.append(f"the train split holds {train['class_count']} class(es); at least two are required")
    unseen = sorted(set(data.classes) - set(train["label_counts"]))
    if unseen:
        problems.append(f"class(es) never seen in training cannot be predicted: {', '.join(unseen)}")
    if not data.integrity["ok"]:
        problems.append("grouped split integrity is violated")

    if train["rows"] < MIN_TRAIN_ROWS:
        reasons.append(f"train rows {train['rows']} < {MIN_TRAIN_ROWS}")
    if val["rows"] < MIN_EVAL_ROWS or test["rows"] < MIN_EVAL_ROWS:
        reasons.append(f"validation or test rows below {MIN_EVAL_ROWS}")
    if train["groups"] < 2:
        reasons.append("training rests on a single experiment group")
    thin = sorted(name for name, count in train["label_counts"].items() if count < MIN_TRAIN_ROWS_PER_CLASS)
    if thin:
        reasons.append(f"class(es) with fewer than {MIN_TRAIN_ROWS_PER_CLASS} training rows: {', '.join(thin)}")

    if problems:
        raise _training_error(
            "the dataset cannot support training",
            problems=sorted(set(problems)),
            split_summary=summary,
        )
    return {
        "schema": TRAINING_SCHEMA,
        "rows": int(data.row_count),
        "groups": int(data.integrity["group_count"]),
        "classes": list(data.classes),
        "class_count": len(data.classes),
        "splits": summary,
        "split_integrity": dict(data.integrity),
        "fingerprint": data.fingerprint,
        "performance_status": PERFORMANCE_MEASURED if not reasons else PERFORMANCE_UNVERIFIED,
        "reasons": reasons,
    }


def _sklearn() -> Any:
    """Import the scikit-learn pieces training needs, or fail with an install hint.

    Imported lazily and only here: inference must stay loadable on a machine that
    has ``joblib`` but no training stack, so nothing above module level touches
    ``sklearn``.
    """
    try:
        import sklearn
        from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler
        from sklearn.tree import DecisionTreeClassifier
    except Exception as exc:  # noqa: BLE001 - optional dependency at import time
        raise TrainingError(
            "scikit-learn is not installed, so a traffic model cannot be trained",
            code=ErrorCode.DEPENDENCY_MISSING,
            hint="python -m pip install scikit-learn joblib numpy (inference alone needs only joblib)",
            details={"module": "sklearn"},
        ) from exc
    return SimpleNamespace(
        version=sklearn.__version__,
        Pipeline=Pipeline,
        StandardScaler=StandardScaler,
        classes={
            "LogisticRegression": LogisticRegression,
            "DecisionTreeClassifier": DecisionTreeClassifier,
            "RandomForestClassifier": RandomForestClassifier,
            "HistGradientBoostingClassifier": HistGradientBoostingClassifier,
        },
    )


def candidate_names(requested: Sequence[str] | None = None) -> list[str]:
    """Candidate list in selection order (simplest first), filtered on request."""
    if requested is None:
        return list(CANDIDATE_ORDER)
    unknown = [name for name in requested if name not in CANDIDATE_MODELS]
    if unknown:
        raise _training_error("unknown candidate model(s) requested", unknown=unknown, available=list(CANDIDATE_ORDER))
    if not requested:
        raise _training_error("no candidate models requested")
    wanted = set(requested)
    return [name for name in CANDIDATE_ORDER if name in wanted]


def build_candidate(name: str, *, seed: int, tools: Any | None = None, parameters: Mapping[str, Any] | None = None) -> Any:
    """Build one untrained candidate pipeline (a scaler only where it matters).

    The scaler is a *pipeline step*, so ``fit`` treats it as part of the model:
    it can only be fitted on training rows, and the persisted artefact replays the
    same transform at inference.  Tree models get no scaler - it would add a step
    that cannot change their splits and one more thing to distrust.
    """
    if name not in CANDIDATE_MODELS:
        raise _training_error(f"unknown candidate model: {name}", requested=name, available=list(CANDIDATE_ORDER))
    spec = CANDIDATE_MODELS[name]
    library = tools if tools is not None else _sklearn()
    kwargs = dict(spec["kwargs"])
    kwargs.update(dict(parameters or {}))
    kwargs["random_state"] = int(seed)
    estimator = library.classes[spec["estimator"]](**kwargs)
    steps: list[tuple[str, Any]] = []
    if spec["scaling"]:
        steps.append(("scaler", library.StandardScaler()))
    steps.append(("clf", estimator))
    return library.Pipeline(steps)


def fit_pipeline(pipeline: Any, matrix: Sequence[Sequence[float]], labels: Sequence[str]) -> Any:
    """Fit one pipeline on exactly the rows it is allowed to see."""
    pipeline.fit(list(matrix), list(labels))
    return pipeline


def score_pipeline(pipeline: Any, matrix: Sequence[Sequence[float]], *, labels: Sequence[str] | None = None, groups: Sequence[str] | None = None, classes: Sequence[str] | None = None) -> dict[str, Any]:
    """Metric block of one pipeline over one split's rows."""
    predicted = [str(item) for item in pipeline.predict(list(matrix))]
    return classification_metrics(list(labels or []), predicted, labels=classes, groups=groups)


def select_candidate(reports: Sequence[Mapping[str, Any]], *, tolerance: float = TIE_TOLERANCE) -> str:
    """Pick the winner: validation macro F1, then the simpler model, then the name.

    Only the validation block of each report is read - never a test block, so
    the held-out split cannot steer its own evaluation.  The tie band exists
    because a 0.003-macro-F1 gap between a linear model and a 300-tree forest is
    not evidence that the forest is better - it is noise - and an operator
    cannot maintain a model they cannot read.  The final ``name`` tie-break
    makes the choice a pure function of the reports, so two runs never disagree.
    """
    scored = [item for item in reports if item.get("status") == "fitted"]
    if not scored:
        raise _training_error(
            "no candidate could be fitted",
            candidates=[{"name": item.get("name"), "error": item.get("error")} for item in reports],
        )
    scores = {str(item["name"]): macro_f1(dict(item.get("validation") or {})) for item in scored}
    best = max(scores.values())
    eligible = [item for item in scored if scores[str(item["name"])] >= best - tolerance]
    winner = min(eligible, key=lambda item: (int(CANDIDATE_MODELS[str(item["name"])]["rank"]), str(item["name"])))
    return str(winner["name"])


def evaluate_split(pipeline: Any, data: PreparedData, split: str) -> dict[str, Any]:
    """Metric block of one fitted pipeline over one named split of one dataset."""
    return score_pipeline(
        pipeline,
        data.matrix(split),
        labels=data.labels(split),
        groups=data.groups(split),
        classes=data.classes,
    )


def fit_candidates(
    data: PreparedData,
    requested: Sequence[str] | None = None,
    *,
    seed: int = DEFAULT_SEED,
    tolerance: float = TIE_TOLERANCE,
    parameters: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], Any, str]:
    """Fit every candidate on ``train``, score on ``val``, then pick the winner.

    Returns ``(reports, fitted_winner_pipeline, winner_name)``.  A candidate
    that fails to fit is recorded with its error instead of aborting the
    comparison - one broken estimator must not hide how the others did - but if
    *no* candidate fits, :func:`select_candidate` raises with every reason.
    """
    reports: list[dict[str, Any]] = []
    fitted: dict[str, Any] = {}
    for name in candidate_names(requested):
        entry: dict[str, Any] = {
            "name": name,
            "estimator": CANDIDATE_MODELS[name]["estimator"],
            "rank": CANDIDATE_MODELS[name]["rank"],
            "status": "fitted",
            "error": None,
            "fit_rows": len(data.labels("train")),
            "validation": None,
        }
        try:
            pipeline = build_candidate(name, seed=seed, parameters=(parameters or {}).get(name))
            fit_pipeline(pipeline, data.matrix("train"), data.labels("train"))
            entry["validation"] = evaluate_split(pipeline, data, "val")
            fitted[name] = pipeline
        except Exception as exc:  # noqa: BLE001 - a failed candidate is data, not a crash
            entry["status"] = "failed"
            entry["error"] = f"{type(exc).__name__}: {exc}"
        reports.append(entry)
    winner = select_candidate(reports, tolerance=tolerance)
    return reports, fitted[winner], winner


def _resolve_samples(dataset: Path | str | Sequence[DatasetSample]) -> tuple[DatasetSample, ...]:
    """Accept either a ``features.jsonl`` path or already-loaded samples."""
    if isinstance(dataset, (str, Path)):
        return tuple(load_dataset(dataset))
    return tuple(dataset)


def _row_probabilities(pipeline: Any, data: PreparedData, split: str) -> list[dict[str, float]]:
    """Per-row class probabilities for one split, keyed by the estimator's classes."""
    rows = data.matrix(split)
    if not rows:
        return []
    scores = pipeline.predict_proba(rows)
    declared = getattr(pipeline, "classes_", None) or data.classes
    names = [str(name) for name in declared]
    return [
        {name: round(float(value), 6) for name, value in zip(names, row, strict=True)}
        for row in scores
    ]


def train_traffic_model(
    dataset: Path | str | Sequence[DatasetSample],
    *,
    target: Path | str | None = None,
    features: Sequence[str] | None = None,
    feature_set: str | None = None,
    candidates: Sequence[str] | None = None,
    seed: int = DEFAULT_SEED,
    tolerance: float = TIE_TOLERANCE,
    parameters: Mapping[str, Mapping[str, Any]] | None = None,
    calibration_method: str | None = None,
    open_world_threshold: float | None = None,
    persist: bool = True,
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    """Run the whole classifier pipeline and (optionally) persist the artefact.

    The order of operations is the contract, not an implementation detail:

    1. load the labelled dataset and take its grouped split as authoritative;
    2. resolve and audit the feature columns (whitelist only, no leakage);
    3. fit every candidate on ``train``, score each on ``val``;
    4. select the winner on validation macro F1 (:func:`select_candidate`);
    5. open ``test`` exactly once, for the winner only;
    6. persist metadata + estimator + training report together, or return the
       report alone when ``persist=False``.

    ``target`` is the artefact directory (default: ``data/models/<model_id>``).
    Returns the JSON-safe training report; the fitted pipeline is written to
    disk when ``persist`` is set and is reloadable through
    :func:`fera.ml.inference.load_model`.
    """
    samples = _resolve_samples(dataset)
    names = resolve_feature_set(feature_set) if feature_set else resolve_features(features)
    feature_report = audit_features(names)
    data = prepare_dataset(samples, features=names)
    dataset_report = audit_data(data)
    reports, pipeline, winner = fit_candidates(
        data, candidates, seed=seed, tolerance=tolerance, parameters=parameters
    )
    # The held-out split is opened here for the first and only time: it cannot
    # have influenced selection, and nothing after it feeds back into the model.
    held_out_test = evaluate_split(pipeline, data, "test")
    importance = importance_document(pipeline, data.feature_names)
    validation = next(dict(item["validation"]) for item in reports if str(item["name"]) == winner)

    # --- calibration, fitted on validation only ---------------------------
    # Deliberately after selection and before the test split is scored, and
    # never on test: the probability map is an improvement to the shipped
    # estimator, not a new selection criterion.
    calibration_meta = uncalibrated_metadata(
        "no calibration map was requested for this model"
    )
    shipped: Any = pipeline
    baseline_report = majority_class_baseline(data)
    if calibration_method is not None:
        feasibility = check_calibration_feasibility(data.labels("val"), method=calibration_method)
        if feasibility["feasible"]:
            try:
                shipped, calibration_meta = calibrate_estimator(
                    pipeline,
                    data.matrix("val"),
                    data.labels("val"),
                    classes=data.classes,
                    method=calibration_method,
                    groups=data.groups("val"),
                    forbidden_groups=data.groups("test"),
                    forbidden_label="the held-out test split",
                )
            except FeraError as exc:
                calibration_meta = uncalibrated_metadata(f"calibration failed: {exc}")
        else:
            calibration_meta = uncalibrated_metadata(
                "the validation split could not support the requested calibration method: "
                + "; ".join(str(item) for item in feasibility["reasons"])
            )

    # --- open-world rejection policy --------------------------------------
    # A threshold supplied here is asserted by the caller to be
    # validation-derived; we record that provenance, we do not re-derive it.
    policy = (
        RejectionPolicy(
            confidence_threshold=float(open_world_threshold),
            source=SOURCE_VALIDATION,
            calibration_method=calibration_meta.get("method"),
            calibrated=bool(calibration_meta.get("calibrated")),
            notes=("threshold supplied by the operator as validation-derived",),
        )
        if open_world_threshold is not None
        else disabled_policy(
            "no open-world threshold was supplied; this model answers KNOWN only"
        )
    )

    # --- confidence quality, before and after calibration ----------------
    calibration_block: dict[str, Any] = {"metadata": dict(calibration_meta)}
    if dict(calibration_meta).get("calibrated"):
        raw_val = _row_probabilities(pipeline, data, "val")
        cal_val = _row_probabilities(shipped, data, "val")
        calibration_block["validation"] = compare_calibration(
            raw_val, cal_val, data.labels("val"), data.classes
        ).to_dict()

    set_name = feature_set_name(data.feature_names)
    model_id = f"fera-{set_name}-{winner}-{data.fingerprint[:8]}"
    trained_at = _utc_now()
    performance = str(dataset_report["performance_status"])
    selection_block = {
        "winner": winner,
        "criterion": SELECTION_CRITERION,
        "tie_tolerance": float(tolerance),
        "seed": int(seed),
        "candidates": [str(item["name"]) for item in reports],
        "scores": {
            str(item["name"]): macro_f1(dict(item.get("validation") or {}))
            for item in reports
            if item.get("status") == "fitted"
        },
        # Nothing about the test split is read before this flag is written:
        # the winner is a pure function of the validation blocks above.
        "test_informed": False,
    }
    metadata: dict[str, Any] = {
        "schema": MODEL_SCHEMA,
        "model_id": model_id,
        "model_version": MODEL_VERSION,
        "feature_schema": FEATURE_SCHEMA,
        "algorithm": CANDIDATE_MODELS[winner]["estimator"],
        "trained_at": trained_at,
        "classes": list(data.classes),
        "feature_names": list(data.feature_names),
        "feature_set": set_name,
        "calibration": dict(calibration_meta),
        "open_world": policy.to_dict(),
        "dataset": {
            "fingerprint": data.fingerprint,
            "rows": int(data.row_count),
            "groups": int(dataset_report["groups"]),
            "splits": {
                name: {"rows": block["rows"], "groups": block["groups"]}
                for name, block in dataset_report["splits"].items()
            },
            "performance_status": performance,
            "reasons": list(dataset_report["reasons"]),
        },
        "metrics": {
            "validation": validation,
            "test": held_out_test,
            "selection": selection_block,
            "performance_status": performance,
        },
        "notes": [
            *(
                [
                    "metrics are UNVERIFIED: the dataset is too small to support a performance claim",
                    *dataset_report["reasons"],
                ]
                if performance != PERFORMANCE_MEASURED
                else []
            ),
            "selection used the validation split only; the test block was computed after the winner existed",
            "a majority-class baseline is reported so the trained model's score can be read against guessing",
            *(str(item) for item in notes),
        ],
    }
    report: dict[str, Any] = {
        "schema": TRAINING_SCHEMA,
        "model_id": model_id,
        "model_version": MODEL_VERSION,
        "trained_at": trained_at,
        "seed": int(seed),
        "feature_set": set_name,
        "feature_names": list(data.feature_names),
        "features": feature_report,
        "dataset": dataset_report,
        "split_groups": split_groups(samples),
        "candidates": reports,
        "selection": selection_block,
        "validation": validation,
        "test": held_out_test,
        "importance": importance,
        "calibration": calibration_block,
        "open_world": policy.to_dict(),
        "majority_baseline": baseline_report,
        "performance_status": performance,
        "environment": {"python": python_version()},
        "notes": metadata["notes"],
    }
    artefact: dict[str, str] = {}
    if persist:
        root = Path(target) if target is not None else default_paths().models / model_id
        report["path"] = str(root)
        # The *shipped* estimator is persisted, not the raw one: if calibration
        # was fitted, inference must reload the calibrated pipeline or the
        # probabilities it emits would not match the metadata's claim.
        artefact = {
            key: str(path)
            for key, path in write_model(root, shipped, metadata, report=report).items()
        }
        report["artefact"] = dict(artefact)
    return report


#: Schema identifier of a feature-set ablation document.
ABLATION_SCHEMA = "fera_ml_ablation_v1"

#: Schema identifier of the majority-class baseline document.
BASELINE_SCHEMA = "fera_ml_baseline_v1"

#: Schema identifier of a feature-family ablation document.
FAMILY_ABLATION_SCHEMA = "fera_ml_family_ablation_v1"

#: Feature sets ablated when a caller names none: the whole whitelist against
#: the set that removes the testbed-context columns (the shortcut risk).
DEFAULT_ABLATION_SETS: tuple[str, ...] = ("all", "esp_core")

#: Feature families evaluated by :func:`ablate_feature_families`.  They select
#: from the canonical whitelist only - no family may name a column the extractor
#: cannot produce, and the import-time check in :mod:`fera.ml.feature_sets`
#: fails closed if one ever tries.
FEATURE_FAMILIES: tuple[str, ...] = ("size", "timing", "direction", "combined")

#: Family -> feature names.  ``combined`` is deliberately the whole approved
#: whitelist: it is the reference row every other family is read against, so a
#: narrower family that scores highly is informative rather than flattering.
FAMILY_FEATURES: Mapping[str, tuple[str, ...]] = {
    "size": ("avg_packet_len", "esp_avg_len", "esp_len_min", "esp_len_max", "esp_len_std"),
    "timing": ("esp_iat_mean_s", "esp_iat_std_s", "esp_iat_max_s", "esp_span_s"),
    "direction": (
        "esp_fwd_packets",
        "esp_bwd_packets",
        "esp_fwd_bytes",
        "esp_bwd_bytes",
        "esp_fwd_packet_share",
        "esp_fwd_byte_share",
    ),
    "combined": FEATURE_WHITELIST,
}


def majority_class_baseline(data: PreparedData) -> dict[str, Any]:
    """Predict the most common training class for every held-out row.

    This is not a competitor; it is the floor.  A trained classifier that cannot
    beat "always answer the most frequent class" has learned nothing about the
    traffic, and the whole point of computing it is that a good-looking macro F1
    can otherwise hide exactly that.

    The majority class is derived from **train** only and applied unchanged to
    whichever split is being scored, so the baseline never sees a label from the
    partition it is being measured on.
    """
    train_labels = data.labels("train")
    if not train_labels:
        raise _training_error("the majority baseline needs at least one training row")
    counts = _count(train_labels)
    # Ties break on the class name so the baseline is deterministic.
    majority = min(counts.items(), key=lambda item: (-item[1], item[0]))[0]

    report: dict[str, Any] = {
        "schema": BASELINE_SCHEMA,
        "classifier": "majority_class",
        "majority_class": majority,
        "majority_share": round(counts[majority] / len(train_labels), METRIC_PRECISION),
        "train_label_counts": counts,
        "splits": {},
        "notes": [
            "the majority class is computed on the train split only and reused verbatim",
            "this baseline is not expected to be competitive; it exists so a trained "
            "model's score can be shown to exceed simply guessing the commonest class",
        ],
    }
    for split in SPLITS:
        rows = data.labels(split)
        if not rows:
            continue
        predictions = [majority] * len(rows)
        metrics = classification_metrics(rows, predictions, labels=data.classes, groups=data.groups(split))
        report["splits"][split] = {
            "accuracy": metrics["accuracy"],
            "macro_f1": macro_f1(metrics),
            "sample_count": metrics["sample_count"],
        }
    return report


def ablate_feature_sets(
    dataset: Path | str | Sequence[DatasetSample],
    *,
    feature_sets: Sequence[str] | None = None,
    candidates: Sequence[str] | None = None,
    seed: int = DEFAULT_SEED,
    tolerance: float = TIE_TOLERANCE,
    parameters: Mapping[str, Mapping[str, Any]] | None = None,
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    """Train the pipeline once per named feature set and compare the results.

    This measures the shortcut risk the feature-set split exists for: a set
    built only from ESP behaviour scoring as well as the full whitelist says
    the testbed-context columns (IKE counts, harness shares) were not carrying
    the score; a full-set score far above ``esp_core`` says the model may be
    reading the harness instead of the traffic, and the report prints that as a
    caution rather than a win.

    Every set goes through :func:`train_traffic_model` unchanged - same split,
    same seed, same candidates, same selection rule - so the only variable is
    the columns.  Nothing is persisted (``persist=False``): an ablation is an
    experiment, not a deployable artefact.  A set that cannot train at all is
    recorded as ``blocked`` with its error instead of aborting the comparison,
    because "esp_core could not be fitted" is itself a result worth keeping.
    """
    requested = [str(name) for name in (feature_sets or DEFAULT_ABLATION_SETS)]
    baseline: dict[str, Any] | None = None
    results: list[dict[str, Any]] = []
    for name in requested:
        try:
            outcome = train_traffic_model(
                dataset,
                feature_set=name,
                candidates=candidates,
                seed=seed,
                tolerance=tolerance,
                parameters=parameters,
                persist=False,
                notes=notes,
            )
        except FeraError as exc:  # a blocked set is data, not a crash
            results.append(
                {
                    "feature_set": name,
                    "status": "blocked",
                    "error": exc.to_dict(),
                }
            )
            continue
        entry: dict[str, Any] = {
            "feature_set": name,
            "status": "trained",
            "error": None,
            "winner": outcome["selection"]["winner"],
            "feature_count": len(outcome["feature_names"]),
            "performance_status": outcome["performance_status"],
            "validation_macro_f1": macro_f1(dict(outcome["validation"])),
            "test_macro_f1": macro_f1(dict(outcome["test"])),
            "delta_validation_macro_f1": None,
            "delta_test_macro_f1": None,
        }
        if baseline is not None:
            entry["delta_validation_macro_f1"] = round(
                float(entry["validation_macro_f1"]) - float(baseline["validation_macro_f1"]),
                METRIC_PRECISION,
            )
            entry["delta_test_macro_f1"] = round(
                float(entry["test_macro_f1"]) - float(baseline["test_macro_f1"]),
                METRIC_PRECISION,
            )
        else:
            baseline = entry
        results.append(entry)
    trained = [item for item in results if item["status"] == "trained"]
    return {
        "schema": ABLATION_SCHEMA,
        "generated_at": _utc_now(),
        "seed": int(seed),
        "criterion": SELECTION_CRITERION,
        "baseline": requested[0] if requested else None,
        "feature_sets": requested,
        "results": results,
        "comparable": len(trained) == len(requested) and bool(trained),
        "performance_status": (
            PERFORMANCE_MEASURED
            if trained and all(item["performance_status"] == PERFORMANCE_MEASURED for item in trained)
            else PERFORMANCE_UNVERIFIED
        ),
        "notes": [
            "each row re-trained the full pipeline with only the column list changed; "
            "the grouped split, seed, candidates and selection rule were held constant",
            "a delta compares one set against the baseline set on the same data; "
            "deltas near zero mean the removed columns were not carrying the score",
            *(str(item) for item in notes),
        ],
    }


def ablate_feature_families(
    dataset: Path | str | Sequence[DatasetSample],
    *,
    families: Sequence[str] | None = None,
    candidates: Sequence[str] | None = None,
    seed: int = DEFAULT_SEED,
    tolerance: float = TIE_TOLERANCE,
    parameters: Mapping[str, Mapping[str, Any]] | None = None,
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    """Train once per feature family and report what each family is worth.

    Answers "which aspects of the encrypted-flow behaviour does the classifier
    actually depend on?" by removing whole families rather than individual
    columns.  Every run goes through :func:`train_traffic_model` unchanged - same
    grouped split, seed, candidates and selection rule - so the only variable is
    the column list, and nothing is persisted (``persist=False``): an ablation is
    an experiment, not a deployable artefact.

    A family that cannot train is recorded as ``blocked`` with its error rather
    than aborting the comparison, because "timing alone could not be fitted" is
    itself a result worth keeping.
    """
    requested = [str(name) for name in (families or FEATURE_FAMILIES)]
    unknown = [name for name in requested if name not in FAMILY_FEATURES]
    if unknown:
        raise _training_error(
            "unknown feature family",
            unknown=unknown,
            available=sorted(FAMILY_FEATURES),
        )
    results: list[dict[str, Any]] = []
    for name in requested:
        try:
            outcome = train_traffic_model(
                dataset,
                features=FAMILY_FEATURES[name],
                candidates=candidates,
                seed=seed,
                tolerance=tolerance,
                parameters=parameters,
                persist=False,
                notes=notes,
            )
        except FeraError as exc:  # a blocked family is data, not a crash
            results.append({"family": name, "status": "blocked", "error": exc.to_dict()})
            continue
        results.append(
            {
                "family": name,
                "status": "trained",
                "error": None,
                "feature_count": len(FAMILY_FEATURES[name]),
                "features": list(FAMILY_FEATURES[name]),
                "winner": outcome["selection"]["winner"],
                "performance_status": outcome["performance_status"],
                "validation_macro_f1": macro_f1(dict(outcome["validation"])),
                "test_macro_f1": macro_f1(dict(outcome["test"])),
            }
        )
    trained = [item for item in results if item["status"] == "trained"]
    return {
        "schema": FAMILY_ABLATION_SCHEMA,
        "generated_at": _utc_now(),
        "seed": int(seed),
        "criterion": SELECTION_CRITERION,
        "families": requested,
        "results": results,
        "comparable": len(trained) == len(requested) and bool(trained),
        "performance_status": (
            PERFORMANCE_MEASURED
            if trained and all(item["performance_status"] == PERFORMANCE_MEASURED for item in trained)
            else PERFORMANCE_UNVERIFIED
        ),
        "notes": [
            "each row re-trained the full pipeline with only that family's columns available",
            "'combined' is the whole approved whitelist and is the reference row",
            "a family scoring near the combined row means the removed columns were "
            "not carrying the score; a large gap means they may be",
            *(str(item) for item in notes),
        ],
    }


__all__ = [
    "ABLATION_SCHEMA",
    "BASELINE_SCHEMA",
    "CANDIDATE_MODELS",
    "CANDIDATE_ORDER",
    "DEFAULT_ABLATION_SETS",
    "DEFAULT_SEED",
    "FAMILY_ABLATION_SCHEMA",
    "FAMILY_FEATURES",
    "FEATURE_FAMILIES",
    "FORBIDDEN_FEATURE_KEYS",
    "MIN_TRAIN_ROWS",
    "MODEL_VERSION",
    "PERFORMANCE_MEASURED",
    "PERFORMANCE_UNVERIFIED",
    "SELECTION_CRITERION",
    "TIE_TOLERANCE",
    "TRAINING_SCHEMA",
    "PreparedData",
    "TrainingError",
    "ablate_feature_families",
    "ablate_feature_sets",
    "audit_data",
    "audit_features",
    "build_candidate",
    "candidate_names",
    "dataset_fingerprint",
    "evaluate_split",
    "fit_candidates",
    "fit_pipeline",
    "majority_class_baseline",
    "prepare_dataset",
    "score_pipeline",
    "select_candidate",
    "train_traffic_model",
]

