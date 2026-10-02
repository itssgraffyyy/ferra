"""Probability calibration and confidence-quality measurement.

A classifier's ``predict_proba`` output is **not** a calibrated confidence.  A
model can be right 90% of the time while its 0.9 predictions are only 70%
correct; FERA must not present a raw softmax score to an operator as "87% sure"
without saying whether that number has been checked.

This module owns the difference between the two:

* :func:`calibrate_estimator` fits a calibration map on data that is *not* the
  held-out test split, and refuses to run when the calibration partition is too
  small to support the method it was asked for;
* :func:`calibration_metrics` measures how good the probabilities turned out to
  be, and returns machine-readable reliability-curve data so a chart can be
  drawn without re-deriving anything.

Two deliberate design decisions, both about not leaking:

1. **Calibration never touches the test split.**  The only partition that may
   calibrate is one the caller names explicitly, and the resulting document
   records *which* split that was, so a later reader can prove the test labels
   were not consulted.
2. **Grouping is the caller's contract, and this module checks it.**  Because
   calibrating on rows of the same session as the training rows would make the
   calibration curve optimistic in exactly the way the grouped split exists to
   prevent, :func:`assert_partition_disjoint` refuses overlapping group keys.

On method choice: ``sigmoid`` (Platt scaling) is the default because it is the
defensible choice at small sample sizes - it fits two parameters per class and
degrades gracefully.  ``isotonic`` fits a free-form monotone map and needs
substantially more calibration data; asking for it without enough is an error
rather than a silently overfitted curve.

Nothing here computes a classification accuracy.  This module answers "when the
model says 0.8, how often is it right?" - a different question, owned by
:mod:`fera.ml.metrics`.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..common.errors import ErrorCode, FeraError
from .metrics import METRIC_PRECISION

#: Schema identifier of one calibration document (metadata or measurements).
CALIBRATION_SCHEMA = "fera_ml_calibration_v1"

#: Supported calibration methods, weakest-assumption first.
CALIBRATION_METHODS: tuple[str, ...] = ("sigmoid", "isotonic")

#: Calibration partitions smaller than this cannot support a sigmoid fit.
MIN_SIGMOID_CALIBRATION_ROWS = 20

#: Isotonic needs materially more data than a two-parameter map: it interpolates
#: the empirical reliability curve rather than imposing a shape on it.
MIN_ISOTONIC_CALIBRATION_ROWS = 100

#: Smallest per-class calibration count before a class may be calibrated.
MIN_CALIBRATION_ROWS_PER_CLASS = 5

#: Reliability-curve resolution (equal-width confidence bins).
RELIABILITY_BINS = 10


def _calibration_error(message: str, **details: Any) -> FeraError:
    return FeraError(
        message,
        code=ErrorCode.CONFIG_VALIDATION_FAILED,
        hint="calibrate on a larger validation partition, or use method='sigmoid'",
        details=details,
    )


def assert_partition_disjoint(
    calibration_groups: Sequence[str],
    forbidden_groups: Sequence[str],
    *,
    forbidden_label: str,
) -> None:
    """Refuse a calibration set that shares a group with ``forbidden_groups``.

    This is the machine-checked form of "calibration must not see the test
    split".  The trainer calls it with the test partition, so a future refactor
    that recalibrates on test data fails loudly instead of producing a
    flattering report.
    """
    overlap = sorted(set(map(str, calibration_groups)) & set(map(str, forbidden_groups)))
    if overlap:
        raise _calibration_error(
            f"calibration data shares {len(overlap)} group(s) with {forbidden_label}",
            overlapping_groups=overlap,
            forbidden=forbidden_label,
        )


def calibration_requirements(method: str) -> int:
    """Minimum calibration rows a method needs, or raise for an unknown method."""
    if method not in CALIBRATION_METHODS:
        raise _calibration_error(
            f"unknown calibration method: {method}",
            available=list(CALIBRATION_METHODS),
        )
    if method == "sigmoid":
        return MIN_SIGMOID_CALIBRATION_ROWS
    return MIN_ISOTONIC_CALIBRATION_ROWS
def check_calibration_feasibility(
    labels: Sequence[str],
    *,
    method: str = "sigmoid",
) -> dict[str, Any]:
    """Report whether a labelled calibration partition can support ``method``.

    Returns a *verdict document* rather than raising for insufficiency: the
    trainer records it in the report so "we could not calibrate because the
    calibration split held 14 rows" is visible instead of silently absent.  An
    unknown method still raises, because that is a programming error rather than
    a limit of the data.
    """
    required = calibration_requirements(method)
    counts: dict[str, int] = {}
    for label in labels:
        key = str(label)
        counts[key] = counts.get(key, 0) + 1
    per_class_short = sorted(
        name for name, count in counts.items() if count < MIN_CALIBRATION_ROWS_PER_CLASS
    )
    rows = len(labels)
    reasons: list[str] = []
    if rows < required:
        reasons.append(
            f"the calibration split holds {rows} row(s); {method} needs at least {required}"
        )
    if per_class_short:
        reasons.append(
            "class(es) with fewer than "
            f"{MIN_CALIBRATION_ROWS_PER_CLASS} calibration rows: {', '.join(per_class_short)}"
        )
    return {
        "method": method,
        "rows": rows,
        "classes": len(counts),
        "label_counts": dict(sorted(counts.items())),
        "min_rows_required": required,
        "min_rows_per_class": MIN_CALIBRATION_ROWS_PER_CLASS,
        "feasible": not reasons,
        "reasons": reasons,
    }


def _require_sklearn() -> None:
    """Fail with an install hint rather than an ImportError from deep inside."""
    try:
        import sklearn  # noqa: F401
    except Exception as exc:  # noqa: BLE001 - optional dependency
        raise FeraError(
            "scikit-learn is not installed, calibration cannot be fitted",
            code=ErrorCode.DEPENDENCY_MISSING,
            hint="python -m pip install scikit-learn",
            details={"module": "sklearn"},
        ) from exc


def calibrate_estimator(
    estimator: Any,
    x_calibration: Sequence[Sequence[float]],
    y_calibration: Sequence[str],
    *,
    classes: Sequence[str],
    method: str = "sigmoid",
    groups: Sequence[str] | None = None,
    forbidden_groups: Sequence[str] | None = None,
    forbidden_label: str = "the held-out test split",
) -> tuple[Any, dict[str, Any]]:
    """Wrap ``estimator`` in a calibrated clone; return ``(calibrated, metadata)``.

    The base estimator is **frozen**: ``CalibratedClassifierCV`` is used with
    ``FrozenEstimator`` so the calibration map is the only thing learned here
    and the model that won selection stays the model that ships.  Refitting
    inside the calibration step would silently re-open model selection on data
    that is meant to be held back from it.
    """
    _require_sklearn()
    from sklearn.calibration import CalibratedClassifierCV  # noqa: PLC0415
    from sklearn.frozen import FrozenEstimator  # noqa: PLC0415

    feasibility = check_calibration_feasibility(y_calibration, method=method)
    if not feasibility["feasible"]:
        raise _calibration_error(
            "cannot calibrate on this partition",
            method=method,
            rows=feasibility["rows"],
            reasons=feasibility["reasons"],
        )
    if groups is not None and forbidden_groups is not None:
        assert_partition_disjoint(groups, forbidden_groups, forbidden_label=forbidden_label)

    # sklearn >= 1.6 replaced the old ``cv="prefit"`` sentinel.  With a frozen
    # estimator, ``cv=None`` is the documented spelling meaning "calibrate this
    # estimator as-is, do not cross-validate": exactly the semantics needed
    # here, because the base model must not be refitted on the calibration rows.
    calibrated = CalibratedClassifierCV(FrozenEstimator(estimator), method=method, cv=None)
    calibrated.fit(list(x_calibration), [str(label) for label in y_calibration])

    metadata = {
        "schema": CALIBRATION_SCHEMA,
        "calibrated": True,
        "method": method,
        "classes": [str(name) for name in classes],
        "rows": int(feasibility["rows"]),
        "label_counts": feasibility["label_counts"],
        "min_rows_required": feasibility["min_rows_required"],
        "groups": sorted({str(group) for group in groups}) if groups is not None else None,
        "forbidden_partition": forbidden_label if forbidden_groups is not None else None,
        "base_estimator": type(estimator).__name__,
        "notes": [
            "the base estimator was frozen: calibration refitted the probability map only",
            "this map was fitted on a named non-test partition, never on the held-out test split",
        ],
    }
    return calibrated, metadata


def uncalibrated_metadata(reason: str) -> dict[str, Any]:
    """Metadata for an artefact that ships **without** a calibration map.

    Used instead of pretending the raw probabilities are calibrated: the
    document is explicit so the dashboard can print "UNCALIBRATED" rather than
    showing a confidence figure with no provenance behind it.
    """
    return {
        "schema": CALIBRATION_SCHEMA,
        "calibrated": False,
        "method": None,
        "reason": reason,
        "notes": [
            "probabilities are raw estimator output and are NOT calibrated confidences",
            "an open-world rejection threshold fitted on raw output is marked EXPERIMENTAL",
        ],
    }


def entropy_bits(probabilities: Sequence[float]) -> float:
    """Shannon entropy of a probability vector, in bits."""
    total = 0.0
    for value in probabilities:
        if value > 0.0:
            total -= float(value) * math.log2(float(value))
    return round(total, METRIC_PRECISION)


def top_label_confidence(probabilities: Mapping[str, float]) -> tuple[str, float]:
    """Highest-probability class and its probability (deterministic tie-break)."""
    if not probabilities:
        raise _calibration_error("cannot score an empty probability table")
    best = max(probabilities.items(), key=lambda item: (item[1], item[0]))
    return best[0], round(float(best[1]), METRIC_PRECISION)


def multiclass_brier_score(
    y_true: Sequence[str],
    probabilities: Sequence[Mapping[str, float]],
    classes: Sequence[str],
) -> float:
    """Mean squared error over the full probability vector (multiclass Brier).

    Definition: for each row, sum ``(p_k - y_k)^2`` over all declared classes
    where ``y_k`` is 1 for the true class and 0 otherwise, then average.  Range
    is ``[0, 2]`` for K classes and ``0`` is perfect.  This is the *multiclass*
    generalisation of the Brier score, not the binary top-label variant.
    """
    declared = [str(name) for name in classes]
    if not declared:
        raise _calibration_error("Brier score needs a declared class list")
    if len(y_true) != len(probabilities):
        raise _calibration_error(
            f"Brier inputs disagree: {len(y_true)} labels, {len(probabilities)} rows"
        )
    if not y_true:
        raise _calibration_error("Brier inputs are empty")
    total = 0.0
    for label, row in zip(y_true, probabilities, strict=False):
        squared = 0.0
        for name in declared:
            target = 1.0 if str(label) == name else 0.0
            squared += (float(row.get(name, 0.0)) - target) ** 2
        total += squared
    return round(total / len(y_true), METRIC_PRECISION)


def multiclass_log_loss(
    y_true: Sequence[str],
    probabilities: Sequence[Mapping[str, float]],
    classes: Sequence[str],
) -> float:
    """Mean negative log-likelihood of the true class (multiclass log loss)."""
    declared = [str(name) for name in classes]
    if not declared:
        raise _calibration_error("log loss needs a declared class list")
    if len(y_true) != len(probabilities):
        raise _calibration_error(
            f"log loss inputs disagree: {len(y_true)} labels, {len(probabilities)} rows"
        )
    if not y_true:
        raise _calibration_error("log loss inputs are empty")
    total = 0.0
    for label, row in zip(y_true, probabilities, strict=False):
        probability = float(row.get(str(label), 0.0))
        # A zero-probability truth is a certainty the model got wrong; clamp so
        # the metric stays finite and the failure shows up as a large number.
        total += -math.log(max(probability, 1e-15))
    return round(total / len(y_true), METRIC_PRECISION)


def reliability_curve(
    y_true: Sequence[str],
    probabilities: Sequence[Mapping[str, float]],
    classes: Sequence[str],
    *,
    bins: int = RELIABILITY_BINS,
) -> list[dict[str, Any]]:
    """Top-label reliability curve: confidence bin -> accuracy and sample count.

    This is the **top-label** definition: every row contributes its highest
    probability and whether that argmax was correct.  It answers "when the model
    says 0.8, how often is its top choice right?" - not a per-class curve.  A
    one-vs-rest per-class curve answers a different question and must not be
    presented as this one.

    Bins are equal-width over ``[0, 1]``; empty bins are omitted rather than
    reported with a fabricated zero accuracy.
    """
    if bins <= 0:
        raise _calibration_error(f"reliability bins must be positive (got {bins})")
    if len(y_true) != len(probabilities):
        raise _calibration_error("reliability curve inputs disagree in length")
    buckets: dict[int, dict[str, float]] = {}
    for label, row in zip(y_true, probabilities, strict=False):
        predicted, confidence = top_label_confidence(row)
        index = min(int(confidence * bins), bins - 1)
        bucket = buckets.setdefault(index, {"count": 0.0, "correct": 0.0, "confidence_sum": 0.0})
        bucket["count"] += 1.0
        bucket["confidence_sum"] += confidence
        if predicted == str(label):
            bucket["correct"] += 1.0
    curve: list[dict[str, Any]] = []
    for index in sorted(buckets):
        bucket = buckets[index]
        count = int(bucket["count"])
        curve.append(
            {
                "bin": index,
                "lower": round(index / bins, METRIC_PRECISION),
                "upper": round((index + 1) / bins, METRIC_PRECISION),
                "count": count,
                "mean_confidence": round(bucket["confidence_sum"] / count, METRIC_PRECISION),
                "accuracy": round(bucket["correct"] / count, METRIC_PRECISION),
            }
        )
    return curve


def expected_calibration_error(
    y_true: Sequence[str],
    probabilities: Sequence[Mapping[str, float]],
    classes: Sequence[str],
    *,
    bins: int = RELIABILITY_BINS,
) -> float:
    """Top-label ECE: sample-weighted gap between confidence and accuracy.

    ``ECE = sum_b (n_b / N) * |mean_confidence_b - accuracy_b|`` over non-empty
    confidence bins.  ``0`` is perfectly calibrated.  This is the top-label
    definition, matching :func:`reliability_curve`.
    """
    curve = reliability_curve(y_true, probabilities, classes, bins=bins)
    total = len(y_true)
    if not total:
        raise _calibration_error("ECE inputs are empty")
    error = sum(
        (item["count"] / total) * abs(item["mean_confidence"] - item["accuracy"])
        for item in curve
    )
    return round(error, METRIC_PRECISION)


def calibration_metrics(
    y_true: Sequence[str],
    probabilities: Sequence[Mapping[str, float]],
    classes: Sequence[str],
    *,
    bins: int = RELIABILITY_BINS,
) -> dict[str, Any]:
    """Full confidence-quality block for one labelled probability set.

    Reports the three metrics plus the curve two of them derive from, and states
    in the document that these are *top-label* / *multiclass* definitions so the
    numbers cannot be misread as their binary or one-vs-rest namesakes.
    """
    curve = reliability_curve(y_true, probabilities, classes, bins=bins)
    entropies = [
        entropy_bits([float(row.get(name, 0.0)) for name in classes]) for row in probabilities
    ]
    confidences = [top_label_confidence(row)[1] for row in probabilities]
    return {
        "schema": CALIBRATION_SCHEMA,
        "sample_count": len(y_true),
        "classes": [str(name) for name in classes],
        "definitions": {
            "brier": "multiclass: mean over rows of sum_k (p_k - y_k)^2, range [0, 2]",
            "log_loss": "multiclass: mean of -ln p(true class)",
            "ece": "top-label: sample-weighted |mean confidence - accuracy| per confidence bin",
            "reliability_curve": "top-label: argmax confidence vs whether argmax was correct",
        },
        "brier_score": multiclass_brier_score(y_true, probabilities, classes),
        "log_loss": multiclass_log_loss(y_true, probabilities, classes),
        "expected_calibration_error": expected_calibration_error(
            y_true, probabilities, classes, bins=bins
        ),
        "reliability_curve": curve,
        "reliability_bins": int(bins),
        "mean_top_label_confidence": (
            round(sum(confidences) / len(confidences), METRIC_PRECISION) if confidences else 0.0
        ),
        "mean_entropy_bits": (
            round(sum(entropies) / len(entropies), METRIC_PRECISION) if entropies else 0.0
        ),
    }


@dataclass(frozen=True)
class CalibrationComparison:
    """Before/after calibration measured on the same labelled rows.

    Produced by :func:`compare_calibration`, which scores identical data with
    the raw and the calibrated estimator so the difference is attributable to
    calibration rather than to a change of samples.
    """

    before: Mapping[str, Any]
    after: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": CALIBRATION_SCHEMA,
            "before": dict(self.before),
            "after": dict(self.after),
            "delta": {
                "brier_score": round(
                    float(self.after.get("brier_score", 0.0))
                    - float(self.before.get("brier_score", 0.0)),
                    METRIC_PRECISION,
                ),
                "log_loss": round(
                    float(self.after.get("log_loss", 0.0))
                    - float(self.before.get("log_loss", 0.0)),
                    METRIC_PRECISION,
                ),
                "expected_calibration_error": round(
                    float(self.after.get("expected_calibration_error", 0.0))
                    - float(self.before.get("expected_calibration_error", 0.0)),
                    METRIC_PRECISION,
                ),
            },
            "interpretation": (
                "negative deltas mean the calibrated probabilities are better on this data; "
                "a positive delta means calibration did not help here"
            ),
        }


def compare_calibration(
    raw_probabilities: Sequence[Mapping[str, float]],
    calibrated_probabilities: Sequence[Mapping[str, float]],
    y_true: Sequence[str],
    classes: Sequence[str],
    *,
    bins: int = RELIABILITY_BINS,
) -> CalibrationComparison:
    """Measure confidence quality before and after calibration on identical rows."""
    return CalibrationComparison(
        before=calibration_metrics(y_true, raw_probabilities, classes, bins=bins),
        after=calibration_metrics(y_true, calibrated_probabilities, classes, bins=bins),
    )


__all__ = [
    "CALIBRATION_METHODS",
    "CALIBRATION_SCHEMA",
    "MIN_CALIBRATION_ROWS_PER_CLASS",
    "MIN_ISOTONIC_CALIBRATION_ROWS",
    "MIN_SIGMOID_CALIBRATION_ROWS",
    "RELIABILITY_BINS",
    "CalibrationComparison",
    "assert_partition_disjoint",
    "calibration_metrics",
    "calibration_requirements",
    "calibrate_estimator",
    "check_calibration_feasibility",
    "compare_calibration",
    "entropy_bits",
    "expected_calibration_error",
    "multiclass_brier_score",
    "multiclass_log_loss",
    "reliability_curve",
    "top_label_confidence",
    "uncalibrated_metadata",
]
