"""Leave-one-class-out open-world evaluation.

The question this answers is narrow and worth stating precisely: *if a traffic
class were absent from training, would FERA still assign it a known class
instead of rejecting it?*  That is the only honest way to measure open-world
rejection, because a rejection rate measured on classes the model has seen is
meaningless.

The procedure, and the leakage rules that make it worth anything:

1. Remove every row of one class from the dataset.  It is now genuinely unseen:
   not in training, not in validation, and not in the model's class list.
2. Train on ``train`` and select on ``val`` exactly as the normal pipeline
   does - the held-out class influences neither step.
3. Choose the rejection threshold on ``val``, using **known** rows only.  This
   is the rule that matters: tuning against the unknown pool would measure the
   policy on the very rows it is being scored on, and would let a threshold be
   picked that happens to reject exactly this class.
4. Calibrate on ``val`` where the data supports it, again without the unknown
   pool.
5. Only then apply the frozen policy to the held-out class and report what
   happened.

Grouping is preserved throughout: rows stay keyed by their experiment id, so
captures of one experiment never straddle the partitions.

Every document this module returns carries an explicit status.  A fixture-driven
run says so; a run on real strongSwan data is the only thing that may say
``MEASURED``.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from ..common.errors import ErrorCode, FeraError
from .calibration import (
    calibrate_estimator,
    check_calibration_feasibility,
    uncalibrated_metadata,
)
from .dataset import DatasetSample
from .metrics import classification_metrics, macro_f1
from .openworld import (
    RejectionPolicy,
    decide,
    open_world_metrics,
    threshold_sweep,
)

#: Schema identifier of one held-out-class experiment document.
HELD_OUT_CLASS_SCHEMA = "fera_ml_held_out_class_v1"

#: Reported when the experiment ran on data that is not real strongSwan traffic.
STATUS_FIXTURE = "MEASURED ON SYNTHETIC FIXTURE - NOT EXPERIMENTAL EVIDENCE"

#: Reported when the structure made the evaluation meaningless.
STATUS_INVALID = "NOT MEASURABLE - SEE REASONS"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _experiment_error(message: str, **details: Any) -> FeraError:
    return FeraError(
        message,
        code=ErrorCode.CONFIG_VALIDATION_FAILED,
        hint="the held-out class needs its own groups, and the rest needs at least two classes",
        details=details,
    )


def _probabilities(pipeline: Any, rows: Sequence[Sequence[float]]) -> list[dict[str, float]]:
    """Probability table per row, keyed by the estimator's own class order."""
    if not rows:
        return []
    scores = pipeline.predict_proba(list(rows))
    declared = getattr(pipeline, "classes_", None)
    if declared is None:
        names = [str(name) for name in getattr(pipeline, "classes", [])]
    else:
        names = [str(name) for name in declared]
    return [
        {name: round(float(value), 6) for name, value in zip(names, row, strict=True)}
        for row in scores
    ]


def _row_of(sample: DatasetSample, indices: Sequence[int]) -> list[float]:
    """Project one dataset row onto the selected feature columns, in order."""
    row = sample.row()
    return [row[index] for index in indices]


def held_out_class_experiment(
    samples: Sequence[DatasetSample],
    held_out_class: str,
    *,
    features: Sequence[str] | None = None,
    candidates: Sequence[str] | None = None,
    seed: int = 0,
    tolerance: float = 0.01,
    status: str = STATUS_FIXTURE,
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    """Train without ``held_out_class``, then measure how it is handled.

    Returns a JSON-safe experiment document.  The held-out class never enters
    training, selection, calibration or threshold choice; it is applied only
    after everything is frozen, which is what makes the resulting rejection rate
    mean anything.
    """
    # Imported here rather than at module scope: train imports this module's
    # siblings, and a top-level import would close the cycle.
    from .feature_sets import resolve_features
    from .features import FEATURE_WHITELIST
    from .train import fit_candidates, prepare_dataset

    if not samples:
        raise _experiment_error("the dataset is empty")
    labels = sorted({sample.label for sample in samples})
    if held_out_class not in labels:
        raise _experiment_error(
            "the held-out class does not occur in the dataset",
            held_out_class=held_out_class,
            available=labels,
        )
    remaining = [name for name in labels if name != held_out_class]
    if len(remaining) < 2:
        raise _experiment_error(
            "at least two classes must remain for training",
            held_out_class=held_out_class,
            remaining=remaining,
        )

    names = resolve_features(features) if features else tuple(FEATURE_WHITELIST)
    indices = [FEATURE_WHITELIST.index(name) for name in names]

    known = [sample for sample in samples if sample.label != held_out_class]
    unknown = [sample for sample in samples if sample.label == held_out_class]
    if not unknown:
        raise _experiment_error("no rows belong to the held-out class", held_out_class=held_out_class)

    data = prepare_dataset(known, features=names)
    if held_out_class in set(data.classes):
        raise _experiment_error(
            "the held-out class survived into the model's class list",
            held_out_class=held_out_class,
        )
    for split in ("train", "val"):
        if not data.labels(split):
            raise _experiment_error(
                f"the {split} split of the remaining classes is empty",
                held_out_class=held_out_class,
            )

    # `reasons` means the experiment is structurally invalid and its numbers must
    # not be read as a result.  `limitations` means it ran but with a caveat.
    # Conflating them would let "calibration was too small" silently invalidate a
    # perfectly sound rejection measurement.
    reasons: list[str] = []
    limitations: list[str] = []
    unknown_groups = sorted({sample.split_key for sample in unknown})
    known_groups = set(data.groups("train")) | set(data.groups("val"))
    shared = sorted(set(unknown_groups) & known_groups)
    if shared:
        reasons.append(
            f"{len(shared)} experiment group(s) appear in both the known and held-out pools, "
            "so the held-out class is not independent of training"
        )

    reports, pipeline, winner = fit_candidates(data, candidates, seed=seed, tolerance=tolerance)

    # --- calibration, fitted on validation known rows only -----------------
    val_samples = [sample for sample in known if sample.split == "val"]
    val_rows = [_row_of(sample, indices) for sample in val_samples]
    val_labels = [sample.label for sample in val_samples]
    calibration_meta = uncalibrated_metadata(
        "the validation split was too small to fit a calibration map"
    )
    estimator: Any = pipeline
    feasibility = check_calibration_feasibility(val_labels, method="sigmoid")
    if feasibility["feasible"]:
        try:
            estimator, calibration_meta = calibrate_estimator(
                pipeline,
                val_rows,
                val_labels,
                classes=data.classes,
                method="sigmoid",
                groups=[sample.split_key for sample in val_samples],
                forbidden_groups=unknown_groups,
            )
        except FeraError as exc:  # calibration is an improvement, not a gate
            limitations.append(f"calibration was skipped: {exc}")
    else:
        limitations.append(
            "no calibration map was fitted: "
            + "; ".join(str(item) for item in feasibility["reasons"])
        )

    # --- threshold chosen on validation known rows only -------------------
    raw_val = _probabilities(estimator, val_rows)
    sweep = threshold_sweep(raw_val, val_labels, RejectionPolicy(source="VALIDATION-DERIVED"))
    best = max(
        sweep["rows"],
        key=lambda row: (
            row["known_accuracy_when_accepted"],
            row["known_acceptance_rate"],
            -row["threshold"],
        ),
    )
    threshold = float(best["threshold"])
    policy = RejectionPolicy(
        confidence_threshold=threshold,
        source="VALIDATION-DERIVED",
        calibration_method=calibration_meta.get("method"),
        calibrated=bool(calibration_meta.get("calibrated")),
        notes=(
            "threshold selected on the validation split's known rows only; the held-out "
            "class was not consulted",
        ),
    )

    # --- everything frozen; only now is the unknown pool touched ----------
    def _score(
        pool: Sequence[DatasetSample],
    ) -> tuple[list[str], list[str | None]]:
        rows = [_row_of(sample, indices) for sample in pool]
        outcomes = [decide(table, policy) for table in _probabilities(estimator, rows)]
        return (
            [sample.label for sample in pool],
            [None if outcome.rejected else outcome.closest_known_class for outcome in outcomes],
        )

    val_truth, val_pred = _score(val_samples)
    test_pool = [sample for sample in known if sample.split == "test"]
    test_truth, test_pred = _score(test_pool)
    unknown_truth, unknown_pred = _score(unknown)

    # Closed-set metrics are only meaningful over rows the policy *accepted*: a
    # rejected row has no predicted class, so scoring it as one would silently
    # count a rejection as a wrong answer and make the open-world filter look
    # worse than it is.  The rejection rate is reported separately below.
    accepted_pairs = [
        (truth, predicted)
        for truth, predicted in zip(test_truth, test_pred, strict=True)
        if predicted is not None
    ]
    accepted_groups = [
        sample.split_key
        for sample, (_, predicted) in zip(test_pool, zip(test_truth, test_pred, strict=True), strict=True)
        if predicted is not None
    ]
    known_metrics = (
        classification_metrics(
            [truth for truth, _ in accepted_pairs],
            [predicted for _, predicted in accepted_pairs],
            labels=data.classes,
            groups=accepted_groups,
        )
        if accepted_pairs
        else None
    )
    return {
        "schema": HELD_OUT_CLASS_SCHEMA,
        "generated_at": _utc_now(),
        "held_out_class": held_out_class,
        "known_classes": list(data.classes),
        "winner": winner,
        "seed": int(seed),
        "features": list(names),
        "feature_count": len(names),
        "calibration": dict(calibration_meta),
        "policy": policy.to_dict(),
        "threshold": threshold,
        "threshold_source": policy.source,
        "threshold_sweep": sweep,
        "candidates": [{"name": item["name"], "status": item["status"]} for item in reports],
        "known_metrics": known_metrics,
        "known_macro_f1": macro_f1(known_metrics) if known_metrics else None,
        "open_world_metrics": open_world_metrics(test_truth, test_pred, unknown_truth, unknown_pred),
        "validation_known_metrics": open_world_metrics(val_truth, val_pred),
        "leakage_check": {
            "held_out_splits_touched_before_scoring": [],
            "unknown_groups": unknown_groups,
            "known_groups": sorted(known_groups),
            "overlapping_groups": shared,
            "held_out_class_in_model_classes": False,
        },
        "counts": {
            "known_rows": len(known),
            "unknown_rows": len(unknown),
            "test_rows": len(test_truth),
            "validation_rows": len(val_truth),
            "unknown_groups": len(unknown_groups),
        },
        "status": STATUS_INVALID if reasons else status,
        "reasons": reasons,
        "limitations": limitations,
        "notes": [
            "the held-out class was absent from training, selection, calibration and "
            "threshold choice; it was scored only after everything was frozen",
            "reported figures describe this dataset only and are not experimental "
            "evidence of real strongSwan behaviour",
            *(str(item) for item in notes),
        ],
    }


__all__ = [
    "HELD_OUT_CLASS_SCHEMA",
    "STATUS_FIXTURE",
    "STATUS_INVALID",
    "held_out_class_experiment",
]
