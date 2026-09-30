"""Classification metrics for the traffic classifier.

The metric maths lives here rather than inside :mod:`fera.ml.train` for two
reasons: the validation report of a candidate model and the final held-out
report of the selected one must be computed *identically*, and the numbers a
bundle shows an operator must be reproducible without importing scikit-learn.

Every function is pure Python over sequences of class names, so a metric block
can be recomputed - and audited - from the confusion matrix alone:

* classes are ordered lexicographically everywhere, so a report is byte stable;
* a zero denominator yields ``0.0`` instead of an exception or a NaN, matching
  the ``zero_division=0`` convention, and is visible through ``support``/
  ``predicted`` beside it;
* macro averages are unweighted over the declared class list, which is what
  makes macro F1 the right selection criterion when class frequency differs.

Nothing in here knows what a traffic class *means*: a perfect score on a toy
fixture is still only a perfect score on a toy fixture, and
:func:`fera.ml.train.train_traffic_model` records how much real data produced
the number beside it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

#: Schema identifier of one metric block (per candidate, validation, final test).
METRICS_SCHEMA = "fera_ml_metrics_v1"
#: Decimal places every metric is rounded to (keeps artefacts byte stable).
METRIC_PRECISION = 6


def _ratio(numerator: float, denominator: float) -> float:
    """Return ``numerator / denominator`` rounded, or ``0.0`` for an empty side."""
    return round(numerator / denominator, METRIC_PRECISION) if denominator else 0.0


def ordered_labels(*sequences: Sequence[str]) -> tuple[str, ...]:
    """Sorted union of every class name seen in the given sequences.

    Derived from the arguments only (never from a global vocabulary), so a model
    trained on a subset of the traffic classes reports exactly its own classes.
    """
    seen: set[str] = set()
    for sequence in sequences:
        seen.update(str(value) for value in sequence)
    return tuple(sorted(seen))


def confusion_matrix(
    y_true: Sequence[str],
    y_pred: Sequence[str],
    labels: Sequence[str],
) -> dict[str, dict[str, int]]:
    """Row-styled confusion matrix keyed by *true* class, then predicted class.

    Keyed by name rather than positional so a report stays readable when two
    models declare different class orders, and so an off-by-one in the class
    mapping cannot hide inside an unnamed array.
    """
    matrix = {true: {predicted: 0 for predicted in labels} for true in labels}
    for true, predicted in zip(y_true, y_pred, strict=False):
        true_key, predicted_key = str(true), str(predicted)
        if true_key not in matrix:  # a true class outside the declared list
            matrix[true_key] = {name: 0 for name in labels}
        if predicted_key not in matrix[true_key]:  # e.g. a hand-written artefact
            matrix[true_key][predicted_key] = 0
        matrix[true_key][predicted_key] += 1
    return {true: matrix[true] for true in sorted(matrix)}


def _f1(precision: float, recall: float) -> float:
    """Harmonic mean of two rates, ``0.0`` when both are zero."""
    total = precision + recall
    return round(2.0 * precision * recall / total, METRIC_PRECISION) if total else 0.0


def per_class_metrics(
    matrix: dict[str, dict[str, int]],
    labels: Sequence[str],
) -> dict[str, dict[str, float]]:
    """Precision / recall / F1 / support / predicted count of each declared class.

    ``support`` is how often the class was the truth, ``predicted`` how often the
    model named it; a rate beside a support of one is not evidence, and those two
    counts are what let a reader notice that.
    """
    report: dict[str, dict[str, float]] = {}
    for name in labels:
        support = sum(matrix.get(name, {}).values())
        predicted = sum(row.get(name, 0) for row in matrix.values())
        correct = matrix.get(name, {}).get(name, 0)
        precision = _ratio(correct, predicted)
        recall = _ratio(correct, support)
        report[name] = {
            "support": int(support),
            "predicted": int(predicted),
            "precision": precision,
            "recall": recall,
            "f1": _f1(precision, recall),
        }
    return report


def classification_metrics(
    y_true: Sequence[str],
    y_pred: Sequence[str],
    *,
    labels: Sequence[str] | None = None,
    groups: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Accuracy, macro averages, per-class metrics and the confusion matrix.

    ``labels`` should be the classes the model declares: a class it never
    predicts still appears with ``predicted = 0`` instead of vanishing from the
    report, which is how a collapsed model becomes visible.  ``groups`` (the
    experiment keys behind the rows) only contributes a count - grouping itself
    is enforced by :mod:`fera.ml.dataset`, not here.
    """
    if len(y_true) != len(y_pred):
        raise ValueError(
            f"metric inputs disagree: {len(y_true)} truth values, {len(y_pred)} predictions"
        )
    declared = tuple(labels) if labels is not None else ordered_labels(y_true, y_pred)
    if not declared:
        raise ValueError("metric inputs are empty: there is no class to score")
    matrix = confusion_matrix(y_true, y_pred, declared)
    per_class = per_class_metrics(matrix, declared)
    sample_count = len(y_true)
    correct = sum(matrix.get(name, {}).get(name, 0) for name in declared)
    class_count = len(declared)
    return {
        "schema": METRICS_SCHEMA,
        "sample_count": int(sample_count),
        "group_count": len({str(group) for group in groups}) if groups is not None else None,
        "class_count": int(class_count),
        "classes": list(declared),
        "accuracy": _ratio(float(correct), float(sample_count)),
        "macro": {
            "precision": _ratio(sum(item["precision"] for item in per_class.values()), float(class_count)),
            "recall": _ratio(sum(item["recall"] for item in per_class.values()), float(class_count)),
            "f1": _ratio(sum(item["f1"] for item in per_class.values()), float(class_count)),
        },
        "per_class": per_class,
        "confusion_matrix": matrix,
    }


def macro_f1(metrics: dict[str, Any]) -> float:
    """The selection criterion, read defensively from a metric block."""
    return float(dict(metrics.get("macro") or {}).get("f1", 0.0))


__all__ = [
    "METRIC_PRECISION",
    "METRICS_SCHEMA",
    "classification_metrics",
    "confusion_matrix",
    "macro_f1",
    "ordered_labels",
    "per_class_metrics",
]
