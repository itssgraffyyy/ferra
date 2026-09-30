"""Model discovery and inference for the traffic classifier.

The ML stage that ships with this repository extracts features
(:mod:`fera.ml.features`) and builds labelled datasets
(:mod:`fera.ml.dataset`); it deliberately does not ship pre-trained weights,
because a classifier whose training data an operator cannot inspect would make
every score that consumes it unauditable.  This module is the *bridge*: it
locates a model artefact the operator trained, verifies that the artefact was
built for the feature schema this checkout emits, and turns one
:class:`~fera.ml.features.FeatureVector` into the prediction document the
security stage is contractually allowed to consume
(:mod:`fera.security.ml_contract`).

Artefact layout (``data/models/<model_id>/``)::

    model.json    metadata: schema, classes, feature schema, metrics, provenance
    model.joblib  the fitted estimator (joblib payload)

When no artefact exists the API and dashboard must show *model unavailable* -
:func:`model_status` is the single source of truth for that statement.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..analysis.provenance import EvidenceKind
from ..common.errors import ErrorCode, FeraError
from ..common.serialization import write_json
from .features import FEATURE_SCHEMA, FEATURE_WHITELIST, FeatureVector

#: Schema identifier of a ``model.json`` metadata document.
MODEL_SCHEMA = "fera_ml_model_v1"
#: File names inside one model directory.
MODEL_METADATA_FILE = "model.json"
MODEL_ESTIMATOR_FILE = "model.joblib"
#: Directory (under ``data/``) the product layer searches for artefacts.
MODELS_DIRNAME = "models"

#: Prediction document schema, re-exported for product-layer consumers.
PREDICTION_SCHEMA = "fera_ml_prediction_v1"

#: Evidence grade of every prediction document: a classifier *infers* a class,
#: it never observes the application behind the ciphertext.
PREDICTION_EVIDENCE_STATUS = EvidenceKind.INFERRED.value

#: Confidence below which a prediction is flagged ``low_confidence``.  Callers
#: may override it per prediction; the value used is recorded in the document
#: so the flag can always be re-derived instead of trusted.
DEFAULT_CONFIDENCE_THRESHOLD = 0.5

#: Report file the trainer writes beside the artefact (documented layout).
TRAINING_REPORT_FILE = "training_report.json"


@dataclass(frozen=True)
class TrafficModel:
    """One loaded classifier artefact plus the metadata that qualifies it.

    ``metrics`` travels with the model on purpose: a prediction is only
    interpretable next to the evaluation numbers of the model that produced it,
    and the dashboard shows both side by side rather than implying that the
    confidence of one capture is the accuracy of a benchmark.
    """

    model_id: str
    model_version: str
    feature_schema: str
    classes: tuple[str, ...]
    algorithm: str
    trained_at: str
    dataset: dict[str, Any]
    metrics: dict[str, Any]
    notes: tuple[str, ...]
    path: Path
    estimator: Any
    #: Ordered columns this artefact was trained on (a whitelist subset for an
    #: ablation model; the runtime refuses to score a vector missing any of them).
    feature_names: tuple[str, ...] = FEATURE_WHITELIST

    @property
    def metadata(self) -> dict[str, Any]:
        """JSON-safe model card (never contains the estimator itself)."""
        return {
            "model_id": self.model_id,
            "model_version": self.model_version,
            "feature_schema": self.feature_schema,
            "algorithm": self.algorithm,
            "classes": list(self.classes),
            "trained_at": self.trained_at,
            "dataset": dict(self.dataset),
            "metrics": dict(self.metrics),
            "notes": list(self.notes),
            "path": str(self.path),
            "feature_names": list(self.feature_names),
        }

    def compatible(self) -> bool:
        """Whether this artefact matches the feature schema of this checkout."""
        return self.feature_schema == FEATURE_SCHEMA


    def probabilities(self, vector: FeatureVector) -> dict[str, float]:
        """Class probabilities for one feature vector, in trained-column order."""
        if not hasattr(self.estimator, "predict_proba"):
            raise FeraError(
                f"model {self.model_id} does not expose predict_proba",
                code=ErrorCode.UNSUPPORTED_FEATURE,
                hint="train the classifier with a probability-capable estimator",
                details={"model_id": self.model_id, "algorithm": self.algorithm},
            )
        missing = [name for name in self.feature_names if name not in vector.features]
        if missing:
            raise FeraError(
                f"model {self.model_id} needs columns the vector does not carry",
                code=ErrorCode.UNSUPPORTED_FEATURE,
                hint="re-extract features with this checkout's FEATURE_SCHEMA",
                details={"missing": missing, "feature_schema": self.feature_schema},
            )
        row = [vector.features[name] for name in self.feature_names]
        scores = list(self.estimator.predict_proba([row])[0])
        declared = getattr(self.estimator, "classes_", None)
        ordered = (
            tuple(str(item) for item in declared) if declared is not None and len(declared) == len(scores) else self.classes
        )
        if len(ordered) != len(scores):
            raise FeraError(
                "model class list and probability row disagree",
                code=ErrorCode.INTERNAL_ERROR,
                details={"classes": list(ordered), "probabilities": len(scores)},
            )
        return {name: round(float(score), 6) for name, score in zip(ordered, scores, strict=True)}

    def predict(
        self,
        vector: FeatureVector,
        *,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    ) -> dict[str, Any]:
        """Prediction document in ``fera_ml_prediction_v1`` shape.

        ``confidence_threshold`` (0 to 1, recorded in the document) decides the
        ``low_confidence`` flag; it never alters the class or the confidence
        themselves - downstream stages must be able to re-derive the flag from
        the recorded threshold rather than trust a boolean they cannot check.
        """
        if not self.compatible():
            raise FeraError(
                f"model {self.model_id} was trained on {self.feature_schema}, this build emits {FEATURE_SCHEMA}",
                code=ErrorCode.UNSUPPORTED_FEATURE,
                hint="retrain the model against this checkout, or pin the matching release",
                details={"model_schema": self.feature_schema, "build_schema": FEATURE_SCHEMA},
            )
        if not 0.0 <= confidence_threshold <= 1.0:
            raise FeraError(
                f"confidence_threshold must be within [0, 1] (got {confidence_threshold})",
                code=ErrorCode.CONFIG_VALIDATION_FAILED,
                details={"confidence_threshold": confidence_threshold},
            )
        probabilities = self.probabilities(vector)
        predicted, confidence = max(probabilities.items(), key=lambda item: (item[1], item[0]))
        return {
            "schema": PREDICTION_SCHEMA,
            "predicted_class": predicted,
            "confidence": confidence,
            "probabilities": probabilities,
            "evidence_status": PREDICTION_EVIDENCE_STATUS,
            "low_confidence": bool(confidence < confidence_threshold),
            "confidence_threshold": float(confidence_threshold),
            "model_id": self.model_id,
            "model_version": self.model_version,
            "feature_schema": self.feature_schema,
            "features": {name: vector.features[name] for name in FEATURE_WHITELIST},
            "source": "ml.inference",
            "model": self.metadata,
        }


def _require_joblib() -> Any:
    try:
        import joblib
    except Exception as exc:  # noqa: BLE001 - optional dependency at import time
        raise FeraError(
            "joblib is not installed, model artefacts cannot be loaded",
            code=ErrorCode.DEPENDENCY_MISSING,
            hint="python -m pip install scikit-learn joblib",
            details={"module": "joblib"},
        ) from exc
    return joblib


def read_model_metadata(directory: Path) -> dict[str, Any]:
    """Read and schema-check ``model.json`` of one artefact directory."""
    metadata_path = directory / MODEL_METADATA_FILE
    try:
        document = json.loads(metadata_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise FeraError(
            f"could not read model metadata {metadata_path}: {exc}",
            code=ErrorCode.IO_ERROR,
            details={"path": str(metadata_path)},
        ) from exc
    except ValueError as exc:
        raise FeraError(
            f"invalid model metadata in {metadata_path}: {exc}",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            details={"path": str(metadata_path)},
        ) from exc
    if not isinstance(document, dict):
        raise FeraError(
            f"{metadata_path} must contain a JSON object",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            details={"path": str(metadata_path)},
        )
    if document.get("schema") != MODEL_SCHEMA:
        raise FeraError(
            f"{metadata_path} is not a {MODEL_SCHEMA} document",
            code=ErrorCode.UNSUPPORTED_FEATURE,
            hint="models must be written by the trainer script or match its schema",
            details={"schema": document.get("schema"), "path": str(metadata_path)},
        )
    classes = document.get("classes")
    if not isinstance(classes, list) or not classes:
        raise FeraError(
            f"{metadata_path} lists no classes",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            details={"path": str(metadata_path)},
        )
    raw_features = document.get("feature_names")
    if raw_features is not None:
        if not isinstance(raw_features, list) or not raw_features:
            raise FeraError(
                f"{metadata_path} must list the ordered feature_names it was trained on",
                code=ErrorCode.CONFIG_VALIDATION_FAILED,
                details={"path": str(metadata_path)},
            )
        ordered = tuple(str(name) for name in raw_features)
        unknown = [name for name in ordered if name not in set(FEATURE_WHITELIST)]
        if unknown:
            raise FeraError(
                f"{metadata_path} names columns outside this checkout's feature whitelist",
                code=ErrorCode.UNSUPPORTED_FEATURE,
                hint="retrain the model against this checkout, or pin the matching release",
                details={"unknown": unknown, "path": str(metadata_path)},
            )
        if len(set(ordered)) != len(ordered):
            raise FeraError(
                f"{metadata_path} repeats a feature name",
                code=ErrorCode.CONFIG_VALIDATION_FAILED,
                details={"path": str(metadata_path)},
            )
        canonical = tuple(name for name in FEATURE_WHITELIST if name in set(ordered))
        if canonical != ordered:
            raise FeraError(
                f"{metadata_path} feature_names are not in whitelist order",
                code=ErrorCode.CONFIG_VALIDATION_FAILED,
                hint="order the columns exactly like FEATURE_WHITELIST",
                details={"path": str(metadata_path), "expected": list(canonical)},
            )
    return document


def load_model(directory: Path | str) -> TrafficModel:
    """Load one model artefact directory (metadata + estimator)."""
    root = Path(directory)
    document = read_model_metadata(root)
    estimator_path = root / MODEL_ESTIMATOR_FILE
    if not estimator_path.is_file():
        raise FeraError(
            f"model artefact has no estimator payload: {estimator_path}",
            code=ErrorCode.IO_ERROR,
            hint="copy the joblib payload next to model.json, or retrain the model",
            details={"path": str(estimator_path)},
        )
    estimator = _require_joblib().load(estimator_path)
    raw_features = document.get("feature_names")
    feature_names = (
        tuple(str(name) for name in raw_features) if raw_features else tuple(FEATURE_WHITELIST)
    )
    return TrafficModel(
        model_id=str(document.get("model_id") or root.name),
        model_version=str(document.get("model_version") or "unknown"),
        feature_schema=str(document.get("feature_schema") or ""),
        classes=tuple(str(item) for item in document["classes"]),
        algorithm=str(document.get("algorithm") or "unknown"),
        trained_at=str(document.get("trained_at") or ""),
        dataset=dict(document.get("dataset") or {}),
        metrics=dict(document.get("metrics") or {}),
        notes=tuple(str(item) for item in (document.get("notes") or ())),
        path=root,
        estimator=estimator,
        feature_names=feature_names,
    )


def write_model(
    directory: Path | str,
    estimator: Any,
    metadata: Mapping[str, Any],
    *,
    report: Mapping[str, Any] | None = None,
) -> dict[str, Path]:
    """Persist one artefact directory (payload first, metadata last).

    Order matters: discovery keys off ``model.json``, so writing it last means a
    crash mid-write leaves a payload without metadata (ignored by the scanner)
    rather than metadata promising a payload that never landed (which would make
    *every* status check say "broken artefact").

    The metadata is validated before a single byte is written: refusing to save
    an unloadable artefact is cheap now and expensive later.
    """
    document = dict(metadata)
    if document.get("schema") != MODEL_SCHEMA:
        raise FeraError(
            f"refusing to write a model without the {MODEL_SCHEMA} schema",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            details={"schema": document.get("schema")},
        )
    classes = document.get("classes")
    if not isinstance(classes, list) or not classes:
        raise FeraError(
            "refusing to write a model with no class list",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            details={"classes": classes},
        )
    feature_names = tuple(str(name) for name in document.get("feature_names") or FEATURE_WHITELIST)
    unknown = [name for name in feature_names if name not in set(FEATURE_WHITELIST)]
    if unknown or len(set(feature_names)) != len(feature_names):
        raise FeraError(
            "refusing to write a model with columns outside the feature whitelist",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            details={"unknown": unknown, "feature_names": list(feature_names)},
        )
    document["feature_names"] = list(feature_names)
    document.setdefault("feature_schema", FEATURE_SCHEMA)

    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    payload = target / MODEL_ESTIMATOR_FILE
    _require_joblib().dump(estimator, payload)
    written = {"estimator": payload}
    if report is not None:
        written["report"] = write_json(target / TRAINING_REPORT_FILE, dict(report))
    written["metadata"] = write_json(target / MODEL_METADATA_FILE, document)
    return written


def discover_models(models_dir: Path | str) -> list[Path]:
    """Every artefact directory under ``models_dir``, newest first."""
    root = Path(models_dir)
    if not root.is_dir():
        return []
    candidates = [child for child in root.iterdir() if child.is_dir() and (child / MODEL_METADATA_FILE).is_file()]
    return sorted(candidates, key=lambda item: (item.stat().st_mtime, item.name), reverse=True)


def _listing(directory: Path) -> dict[str, Any]:
    """Dashboard-facing description of one artefact (metadata only)."""
    document = read_model_metadata(directory)
    return {
        "directory": directory.name,
        "model_id": str(document.get("model_id") or directory.name),
        "model_version": str(document.get("model_version") or "unknown"),
        "feature_schema": str(document.get("feature_schema") or ""),
        "algorithm": str(document.get("algorithm") or "unknown"),
        "trained_at": str(document.get("trained_at") or ""),
        "classes": [str(item) for item in (document.get("classes") or ())],
        "metrics": dict(document.get("metrics") or {}),
        "compatible": document.get("feature_schema") == FEATURE_SCHEMA,
        "payload": (directory / MODEL_ESTIMATOR_FILE).is_file(),
    }



def model_status(models_dir: Path | str) -> dict[str, Any]:
    """Availability report for the dashboard, API and report footers.

    The reason always distinguishes *nothing trained* from *trained but built
    for another feature schema* from *payload unreadable*: those need different
    fixes and different wording in the UI, and collapsing them into "ml
    unavailable" would hide the actionable detail.
    """
    root = Path(models_dir)
    listed: list[dict[str, Any]] = []
    broken: list[str] = []
    usable: list[tuple[Path, dict[str, Any]]] = []
    incompatible = 0
    for directory in discover_models(root):
        try:
            entry = _listing(directory)
        except FeraError as exc:
            broken.append(f"{directory.name}: {exc.message}")
            continue
        listed.append(entry)
        if not entry["compatible"]:
            incompatible += 1
        elif not entry["payload"]:
            broken.append(f"{directory.name}: missing {MODEL_ESTIMATOR_FILE}")
        else:
            usable.append((directory, read_model_metadata(directory)))
    status: dict[str, Any] = {
        "searched": str(root),
        "artefacts": listed,
        "incompatible": incompatible,
        "errors": broken,
        "build_feature_schema": FEATURE_SCHEMA,
    }
    if not listed and not broken:
        return {"available": False, "reason": "no model artefact found; train one with scripts/train_model.py", **status}
    if not usable:
        if incompatible and not broken:
            reason = f"{incompatible} model(s) found, none built for {FEATURE_SCHEMA}"
        else:
            reason = "model artefact(s) found but none could be loaded: " + "; ".join(broken)
        return {"available": False, "reason": reason, **status}
    directory, document = usable[0]
    return {
        "available": True,
        "reason": "",
        "selected": {
            "directory": directory.name,
            "model_id": str(document.get("model_id") or directory.name),
            "model_version": str(document.get("model_version") or "unknown"),
            "algorithm": str(document.get("algorithm") or "unknown"),
            "trained_at": str(document.get("trained_at") or ""),
            "classes": [str(item) for item in (document.get("classes") or ())],
            "metrics": dict(document.get("metrics") or {}),
        },
        **status,
    }


def load_best_model(models_dir: Path | str) -> TrafficModel:
    """Load the newest usable artefact, or raise with an explicit reason."""
    status = model_status(models_dir)
    if not status["available"]:
        raise FeraError(
            f"no usable traffic model: {status['reason']}",
            code=ErrorCode.UNAVAILABLE,
            hint="train a model with scripts/train_model.py and place it under data/models",
            details={"searched": status["searched"], "errors": status["errors"]},
        )
    for directory in discover_models(models_dir):
        try:
            model = load_model(directory)
        except FeraError:
            continue
        if model.compatible():
            return model
    raise FeraError(
        "model artefact disappeared between discovery and load",
        code=ErrorCode.UNAVAILABLE,
        details={"searched": status["searched"]},
    )


def predict_capture(
    pcap_path: Path | str,
    models_dir: Path | str,
    *,
    outcome: Any = None,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> dict[str, Any]:
    """Bridge one capture to a prediction document (features, then model)."""
    from .features import extract_features

    vector = extract_features(pcap_path, outcome=outcome)
    return load_best_model(models_dir).predict(vector, confidence_threshold=confidence_threshold)


__all__ = [
    "DEFAULT_CONFIDENCE_THRESHOLD",
    "MODEL_SCHEMA",
    "MODEL_METADATA_FILE",
    "MODEL_ESTIMATOR_FILE",
    "MODELS_DIRNAME",
    "PREDICTION_EVIDENCE_STATUS",
    "PREDICTION_SCHEMA",
    "TRAINING_REPORT_FILE",
    "TrafficModel",
    "discover_models",
    "load_best_model",
    "load_model",
    "model_status",
    "predict_capture",
    "read_model_metadata",
    "write_model",
]

