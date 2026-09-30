"""Model feature importance - association, never explanation.

A tree model can say which columns its splits leaned on, and a linear model can
say which coefficients carry weight.  Neither statement is a causal claim:
"``esp_avg_len`` has the highest importance" means *this model used this column
the most on this dataset*, not "packet size causes this traffic class".  The
document produced here is therefore labelled
``association = MODEL ASSOCIATION, not causal explanation`` and carries the
method it came from, because an impurity-decrease importance and a coefficient
magnitude are not comparable quantities.

Two honest limits are stated in the document rather than hidden:

* ``HistGradientBoostingClassifier`` exposes no ``feature_importances_``; a
  permutation importance would cost a full re-scoring pass, so the method is
  reported as ``unavailable`` for such a model instead of a number being invented.
* A linear coefficient's magnitude is only meaningful after scaling; the
  candidate pipelines scale before the estimator precisely so these numbers are
  comparable across columns (see :mod:`fera.ml.train`).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .feature_sets import FALLBACK_GROUP, group_of

#: Header every importance document carries (consumers must display it).
ASSOCIATION_LABEL = "MODEL ASSOCIATION - not a causal explanation"

#: Importance kinds this module knows how to read.
METHOD_TREE = "tree_feature_importances"
METHOD_LINEAR = "linear_coefficient_magnitude"
METHOD_UNAVAILABLE = "unavailable"

#: Name of the classifier step inside a candidate pipeline.
CLASSIFIER_STEP = "clf"


def classifier_of(pipeline: Any) -> Any:
    """Return the estimator a fitted pipeline scores with (handles raw estimators)."""
    steps = getattr(pipeline, "named_steps", None)
    if isinstance(steps, Mapping) and steps:
        for name in (CLASSIFIER_STEP, *reversed(list(steps))):
            step = steps.get(name)
            if step is not None:
                return step
    return pipeline


def _vector(value: Any) -> list[float]:
    """Flatten a one- or two-dimensional numpy/array payload to plain floats."""
    if value is None:
        return []
    try:
        rows = list(value)
    except TypeError:  # pragma: no cover - scalars never carry importances
        return []
    if rows and hasattr(rows[0], "__iter__") and not isinstance(rows[0], (str, bytes)):
        per_class = [[float(item) for item in row] for row in rows]
        width = max((len(row) for row in per_class), default=0)
        summed = [0.0] * width
        for row in per_class:
            for index, item in enumerate(row):
                summed[index] += abs(item)
        return [item / len(per_class) for item in summed]
    return [float(abs(item)) for item in rows]


def importance_method(estimator: Any) -> str:
    """Which importance kind this estimator can legitimately provide."""
    if getattr(estimator, "feature_importances_", None) is not None:
        return METHOD_TREE
    if getattr(estimator, "coef_", None) is not None:
        return METHOD_LINEAR
    return METHOD_UNAVAILABLE


def importance_document(
    model: Any,
    feature_names: Sequence[str] | None = None,
    *,
    top: int | None = None,
) -> dict[str, Any]:
    """Per-feature and per-category importance of a fitted model.

    ``top`` trims the reported ``features`` list for display; the category totals
    and the ``available`` verdict always consider every column, so trimming a
    table can never hide that a category dominates.
    """
    names = tuple(feature_names) if feature_names is not None else ()
    estimator = classifier_of(model)
    method = importance_method(estimator)
    values = (
        _vector(getattr(estimator, "feature_importances_", None))
        if method == METHOD_TREE
        else _vector(getattr(estimator, "coef_", None))
        if method == METHOD_LINEAR
        else []
    )
    if names and len(values) != len(names):
        method, values = METHOD_UNAVAILABLE, []
    features = [
        {"feature": name, "importance": round(value, 8), "group": group_of(name)}
        for name, value in sorted(
            zip(names, values, strict=True), key=lambda item: (-item[1], item[0])
        )
    ]
    totals: dict[str, float] = {}
    for item in features:
        totals[str(item["group"])] = totals.get(str(item["group"]), 0.0) + float(str(item["importance"]))
    total = sum(totals.values())
    document: dict[str, Any] = {
        "association": ASSOCIATION_LABEL,
        "method": method,
        "available": bool(features),
        "total": round(total, 8),
        "groups": {
            group: {"importance": round(value, 8), "share": round(value / total, 6) if total else 0.0}
            for group, value in sorted(totals.items())
        },
        "features": features if top is None else features[: max(0, int(top))],
        "feature_count": len(features),
        "notes": [
            "Importance describes which columns this model leaned on for this dataset; "
            "it does not explain why the traffic class is what it is.",
            "Categories are named groups of whitelisted features, not independent causes.",
        ],
    }
    if method == METHOD_UNAVAILABLE:
        document["notes"].append(
            f"this model type exposes no feature_importances_ or coef_ ({METHOD_UNAVAILABLE}); "
            "no importance is reported rather than a substitute being invented"
        )
        document["unclassified_features"] = [name for name in names if group_of(name) == FALLBACK_GROUP]
    return document


__all__ = [
    "ASSOCIATION_LABEL",
    "CLASSIFIER_STEP",
    "METHOD_LINEAR",
    "METHOD_TREE",
    "METHOD_UNAVAILABLE",
    "classifier_of",
    "importance_document",
    "importance_method",
]
