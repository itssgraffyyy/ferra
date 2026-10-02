"""The contract between the ML stage and the security assessment.

Prompt 4 consumes classifier output; it never trains, tunes or evaluates a
model.  What it does need is an honest description of the prediction it is
being handed, because a metadata finding is only as trustworthy as the model
that produced it.  The schema below therefore requires the model identity, its
version and the feature schema it was fed, alongside the class and confidence.

Ground truth is refused deliberately: a document that looks like a labelled
sample (it carries a ``label`` without a ``predicted_class``) is rejected, so a
score can never be steered by the answer key.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..common.errors import ConfigValidationError, ErrorCode, FeraError
from ..ml.features import FEATURE_WHITELIST

#: Schema identifier of an accepted prediction document.
PREDICTION_SCHEMA_VERSION = "fera_ml_prediction_v1"


@dataclass(frozen=True)
class TrafficPrediction:
    """One traffic-class prediction plus the metadata needed to judge it."""

    predicted_class: str
    confidence: float
    probabilities: Mapping[str, float] = field(default_factory=dict)
    model_id: str = ""
    model_version: str = ""
    feature_schema: str = ""
    features: Mapping[str, float] = field(default_factory=dict)
    source: str = "ml.inference"
    #: Open-world decision.  ``"UNKNOWN"`` means no known class was sufficiently
    #: supported; it is an inference about traffic class and is deliberately NOT
    #: the same statement as a NOT_VERIFIABLE protocol fact.
    decision: str = "KNOWN"
    rejected: bool = False
    closest_known_class: str = ""
    rejection_reason: str | None = None
    #: Whether the confidence figure behind this prediction is calibrated.
    calibrated: bool = False

    @property
    def is_unknown(self) -> bool:
        """True when the classifier declined to assign a known traffic class."""
        return bool(self.rejected) or self.decision == "UNKNOWN"

    @property
    def effective_class(self) -> str:
        """The class to reason about.

        For a rejected sample this is the *closest* known class rather than the
        literal ``UNKNOWN`` token, so downstream text reads sensibly while the
        rejection itself stays visible through :attr:`is_unknown`.
        """
        if self.is_unknown:
            return self.closest_known_class or self.predicted_class
        return self.predicted_class

    def __post_init__(self) -> None:
        if not self.predicted_class:
            raise ConfigValidationError("a prediction needs a predicted_class")
        if not math.isfinite(self.confidence) or not 0.0 <= self.confidence <= 1.0:
            raise ConfigValidationError(
                f"confidence must be within [0, 1] (got {self.confidence})",
                details={"confidence": self.confidence},
            )
        object.__setattr__(self, "confidence", round(float(self.confidence), 6))

    @property
    def complete_metadata(self) -> bool:
        """Whether the model identity needed to interpret this prediction is known."""
        return bool(self.model_id and self.model_version and self.feature_schema)

    @property
    def cross_entropy_bits(self) -> float:
        """Surprisal of the predicted class, ``-log2(confidence)``.

        Reported instead of dressing a confidence value up as a probability of
        correctness: what an assessment can state arithmetically is how many
        bits of the class variable the model claims to have removed.
        """
        if self.confidence <= 0.0:
            return float("inf")
        return round(-math.log2(self.confidence), 4)

    @property
    def runner_up(self) -> tuple[str, float] | None:
        """Second most likely class, when a probability table was supplied."""
        ordered = sorted(
            (
                (name, value)
                for name, value in self.probabilities.items()
                if name != self.predicted_class
            ),
            key=lambda item: (-item[1], item[0]),
        )
        return ordered[0] if ordered else None

    @property
    def margin(self) -> float | None:
        """Top-1 minus top-2 probability (``None`` without a table)."""
        runner = self.runner_up
        if runner is None:
            return None
        return round(self.confidence - runner[1], 6)

    def unexpected_features(self) -> tuple[str, ...]:
        """Feature names outside the Prompt 3 whitelist (a contract violation)."""
        return tuple(name for name in sorted(self.features) if name not in FEATURE_WHITELIST)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PREDICTION_SCHEMA_VERSION,
            "predicted_class": self.predicted_class,
            "confidence": self.confidence,
            "probabilities": dict(self.probabilities),
            "model_id": self.model_id,
            "model_version": self.model_version,
            "feature_schema": self.feature_schema,
            "features": dict(self.features),
            "source": self.source,
            "decision": self.decision,
            "rejected": self.is_unknown,
            "closest_known_class": self.closest_known_class,
            "rejection_reason": self.rejection_reason,
            "calibrated": self.calibrated,
        }


def load_prediction(document: Mapping[str, Any] | str | Path) -> TrafficPrediction | None:
    """Parse one prediction document, or ``None`` when nothing was supplied.

    Accepts a mapping, a path to a JSON document, or ``None``.  Unknown keys are
    ignored, missing model metadata is tolerated but reported through
    :attr:`TrafficPrediction.complete_metadata`, and a document that carries a
    ground-truth ``label`` without a ``predicted_class`` is refused outright.
    """
    if document is None:
        return None
    payload: Mapping[str, Any]
    if isinstance(document, (str, Path)):
        path = Path(document)
        if not path.exists():
            raise FeraError(
                f"prediction document not found: {path}",
                code=ErrorCode.IO_ERROR,
                hint="run the classifier first, or point --ml-prediction at an existing JSON document",
                details={"path": str(path)},
            )
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise FeraError(
                f"could not read prediction document {path}: {exc}",
                code=ErrorCode.IO_ERROR,
                details={"path": str(path)},
            ) from exc
        if not isinstance(loaded, Mapping):
            raise ConfigValidationError(f"{path} does not contain a JSON object")
        payload = loaded
    elif isinstance(document, Mapping):
        payload = document
    else:
        raise ConfigValidationError("a prediction must be a mapping or a path to one")

    if "predicted_class" not in payload and "label" in payload:
        raise ConfigValidationError(
            "refusing a labelled sample: the assessment stage consumes predictions, "
            "never ground truth",
            details={"keys": sorted(str(key) for key in payload)},
        )
    predicted = payload.get("predicted_class")
    if not predicted:
        return None
    probabilities = payload.get("probabilities") or payload.get("class_probabilities") or {}
    if not isinstance(probabilities, Mapping):
        raise ConfigValidationError("probabilities must be an object of class -> probability")
    features = payload.get("features") or {}
    if not isinstance(features, Mapping):
        raise ConfigValidationError("features must be an object of feature -> value")
    confidence = payload.get("confidence", payload.get("max_probability"))
    if confidence is None:
        confidence = max((float(value) for value in probabilities.values()), default=0.0)
    try:
        confidence_value = float(confidence)
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            f"confidence must be a number (got {confidence!r})",
            details={"confidence": confidence},
        ) from exc
    return TrafficPrediction(
        predicted_class=str(predicted),
        confidence=confidence_value,
        probabilities={str(key): float(value) for key, value in probabilities.items()},
        model_id=str(payload.get("model_id", "")),
        model_version=str(payload.get("model_version", "")),
        decision=str(payload.get("decision") or ("UNKNOWN" if payload.get("rejected") else "KNOWN")),
        rejected=bool(payload.get("rejected", False)),
        closest_known_class=str(payload.get("closest_known_class") or ""),
        rejection_reason=(
            str(payload["rejection_reason"]) if payload.get("rejection_reason") else None
        ),
        calibrated=bool(payload.get("calibrated", False)),
        feature_schema=str(payload.get("feature_schema", "")),
        features={str(key): float(value) for key, value in features.items()},
        source=str(payload.get("source", "ml.inference")),
    )


def prediction_from_analysis(analysis: Mapping[str, Any]) -> TrafficPrediction | None:
    """Pick up a prediction embedded in an analysis document (``ml``/``traffic``)."""
    for key in ("ml", "traffic", "prediction"):
        candidate = analysis.get(key)
        if isinstance(candidate, Mapping):
            return load_prediction(candidate)
    return None


__all__ = [
    "PREDICTION_SCHEMA_VERSION",
    "TrafficPrediction",
    "load_prediction",
    "prediction_from_analysis",
]
