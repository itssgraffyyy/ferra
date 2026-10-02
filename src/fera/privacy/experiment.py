"""The closed privacy experiment loop: baseline, mitigation, Attacker A/B.

The differentiator is not "FERA classifies encrypted traffic" - the problem
statement already requires that.  It is the *closed loop*:

    DETECT -> EXPLAIN -> MEASURE -> MITIGATE -> RE-ATTACK -> VERIFY -> COMPARE

This module implements the middle of that loop.  It answers, on whatever data it
is given:

1. which observable feature families the inference actually used;
2. what happens to a frozen attacker when the traffic is transformed;
3. what an attacker that *retrains* on the transformed traffic recovers;
4. what the transformation costs in bytes.

Two attackers, because one number cannot answer the question.  **Attacker A** is
trained on baseline traffic and then evaluated against mitigated traffic: it
measures how much the mitigation disrupts an attacker that has not seen it.
**Attacker B** retrains on mitigated traffic and is evaluated on held-out
mitigated data: it measures how much capability an adaptive attacker recovers.
A mitigation that defeats A but not B must be reported exactly that way, and
this module is built so that reporting is possible.

Every result carries its provenance, and nothing here can promote a simulated
countermeasure to a verified one.  On a host without a real IPsec testbed the
output says so.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..common.errors import ErrorCode, FeraError
from ..ml.dataset import SPLITS, DatasetSample
from ..ml.metrics import classification_metrics, macro_f1
from ..ml.train import (
    fit_candidates,
    majority_class_baseline,
    prepare_dataset,
)
from .countermeasure import (
    NOT_MEASURED,
    CountermeasureProvenance,
    PrivacyCountermeasure,
    assert_provenance_permits_claims,
)

#: Schema identifier of one privacy experiment document.
PRIVACY_EXPERIMENT_SCHEMA = "fera_privacy_experiment_v1"

#: Attacker trained on baseline traffic, evaluated against mitigated traffic.
ATTACKER_A = "ATTACKER_A_FROZEN"

#: Attacker retrained on mitigated traffic, evaluated on held-out mitigated data.
ATTACKER_B = "ATTACKER_B_ADAPTIVE"

#: Reported when the experiment ran on fixtures rather than real captures.
STATUS_SIMULATED = "SIMULATED - NOT REAL-DATA EVIDENCE"
@dataclass(frozen=True)
class AttackerResult:
    """One attacker's measurements, with the isolation it depended on recorded.

    ``trained_on`` and ``evaluated_on`` name the *datasets*, not the splits, so a
    reader can see at a glance whether a model saw the traffic it was scored on.
    For Attacker A the interesting property is ``trained_on != evaluated_on``.
    """

    name: str
    description: str
    trained_on: str
    evaluated_on: str
    winner: str
    metrics: Mapping[str, Any]
    macro_f1: float
    accuracy: float
    baseline_macro_f1: float
    delta_macro_f1: float
    delta_accuracy: float
    coverage: float
    unknown_rejection_rate: float | None
    calibration_state: str
    open_world_policy_state: str
    fingerprint: str
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "trained_on": self.trained_on,
            "evaluated_on": self.evaluated_on,
            "winner": self.winner,
            "metrics": dict(self.metrics),
            "macro_f1": self.macro_f1,
            "accuracy": self.accuracy,
            "baseline_macro_f1": self.baseline_macro_f1,
            "delta_macro_f1": self.delta_macro_f1,
            "delta_accuracy": self.delta_accuracy,
            "coverage": self.coverage,
            "unknown_rejection_rate": self.unknown_rejection_rate,
            "calibration_state": self.calibration_state,
            "open_world_policy_state": self.open_world_policy_state,
            "dataset_fingerprint": self.fingerprint,
            "notes": list(self.notes),
        }


def _mitigated_samples(
    samples: Sequence[DatasetSample],
    countermeasure: PrivacyCountermeasure,
) -> list[DatasetSample]:
    """Apply ``countermeasure`` to feature rows, preserving every other field.

    Labels, split keys and split assignments are copied verbatim: a
    countermeasure must not be able to alter the experiment's structure, only its
    observable values.  The provenance is stamped on each row so a mitigated
    dataset can never be mistaken for a captured one.
    """
    from ..ml.features import FEATURE_WHITELIST

    rows = [[float(sample.features.get(name, 0.0)) for name in FEATURE_WHITELIST] for sample in samples]
    transformed = countermeasure.apply(rows, FEATURE_WHITELIST)

    out: list[DatasetSample] = []
    for sample, new_row in zip(samples, transformed, strict=True):
        document = dict(sample.to_dict())
        document["features"] = {
            name: float(new_row[index]) for index, name in enumerate(FEATURE_WHITELIST)
        }
        document["provenance"] = {
            **dict(document.get("provenance") or {}),
            "countermeasure": countermeasure.name,
            "countermeasure_provenance": countermeasure.provenance().to_dict(),
            "mitigated": True,
            # Group keys are untouched, so lineage survives the transformation.
            "lineage_split_key": sample.split_key,
        }
        out.append(DatasetSample(document=document))
    return out


def _evaluate(
    pipeline: Any,
    data: Any,
    split: str,
) -> dict[str, Any]:
    """Classification metrics of one fitted pipeline over one split."""
    rows = data.matrix(split)
    labels = data.labels(split)
    if not rows:
        return {"sample_count": 0, "accuracy": 0.0, "macro": {"f1": 0.0}}
    predictions = [str(item) for item in pipeline.predict(rows)]
    return classification_metrics(
        labels, predictions, labels=data.classes, groups=data.groups(split)
    )

#: The only status that may describe a real, testbed-backed experiment.
STATUS_EXPERIMENTAL = "EXPERIMENTAL EVIDENCE"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _experiment_error(message: str, **details: Any) -> FeraError:
    return FeraError(
        message,
        code=ErrorCode.CONFIG_VALIDATION_FAILED,
        hint="see docs/privacy_intelligence.md for the privacy experiment contract",
        details=details,
    )


def _feature_schema() -> str:
    from ..ml.features import FEATURE_SCHEMA

    return FEATURE_SCHEMA


def _overhead(
    countermeasure: PrivacyCountermeasure,
    samples: Sequence[DatasetSample],
) -> dict[str, Any]:
    """Byte overhead of the countermeasure, plus explicitly unmeasured costs."""
    from ..ml.features import FEATURE_WHITELIST

    rows = [[float(sample.features.get(name, 0.0)) for name in FEATURE_WHITELIST] for sample in samples]
    block = countermeasure.overhead(rows, FEATURE_WHITELIST)
    block.setdefault("latency", NOT_MEASURED)
    block.setdefault("throughput", NOT_MEASURED)
    block.setdefault("jitter", NOT_MEASURED)
    return block


def _cost_block(
    attacker_a: AttackerResult,
    attacker_b: AttackerResult,
    overhead: Mapping[str, Any],
) -> dict[str, Any]:
    """The privacy/cost trade-off, with no dimension filled in by inference.

    Byte overhead is reported because it is directly computable from the
    transformation.  Latency and throughput are **not** derived from it: an
    inference from a byte count would be a fabricated measurement.
    """
    return {
        "inference_side": {
            "baseline_macro_f1": attacker_a.baseline_macro_f1,
            "attacker_a_macro_f1": attacker_a.macro_f1,
            "attacker_b_macro_f1": attacker_b.macro_f1,
            "attacker_a_delta": attacker_a.delta_macro_f1,
            "attacker_b_delta": attacker_b.delta_macro_f1,
            "coverage_attacker_a": attacker_a.coverage,
        },
        "cost_side": {
            "original_bytes": overhead.get("original_bytes"),
            "transformed_bytes": overhead.get("transformed_bytes"),
            "byte_overhead": overhead.get("byte_overhead"),
            "byte_overhead_percent": overhead.get("byte_overhead_percent"),
        },
        "not_measured": {
            "latency": NOT_MEASURED,
            "throughput": NOT_MEASURED,
            "jitter": NOT_MEASURED,
        },
        "interpretation_note": (
            "a lower attacker score is not anonymity, and byte overhead does not imply a "
            "latency or throughput cost; neither was measured"
        ),
    }


def _limitations(
    countermeasure: PrivacyCountermeasure,
    provenance: CountermeasureProvenance,
    status: str,
) -> list[str]:
    items = [
        "a mitigation that disrupts Attacker A but not Attacker B has been adapted to; "
        "reporting only Attacker A would overstate the result",
        "encryption hides payload content, not the size and timing of the packets carrying it",
        "lower inference performance is not proof of anonymity and higher confidence is not "
        "proof of leakage",
    ]
    if provenance.is_simulated:
        items.append(
            "the countermeasure was applied in software to already-captured data; it was not "
            "demonstrated on the wire by an IPsec implementation"
        )
    if status != STATUS_EXPERIMENTAL:
        items.append(
            "this run is not experimental evidence: no real testbed capture backs these numbers"
        )
    items.extend(str(item) for item in countermeasure.describe().get("does_not_model", ()))
    return items


def run_privacy_experiment(
    samples: Sequence[DatasetSample],
    countermeasure: PrivacyCountermeasure,
    *,
    experiment_id: str = "privacy-experiment",
    features: Sequence[str] | None = None,
    candidates: Sequence[str] | None = None,
    seed: int = 0,
    tolerance: float = 0.01,
    status: str = STATUS_SIMULATED,
    claiming_experimental: bool = False,
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    """Run the baseline / mitigation / Attacker A / Attacker B comparison.

    ``status`` and ``claiming_experimental`` are cross-checked against the
    countermeasure's own provenance before anything is fitted: a caller cannot
    stamp ``EXPERIMENTAL EVIDENCE`` on a simulated mechanism.
    """
    provenance = countermeasure.provenance()
    assert_provenance_permits_claims(provenance, claiming_experimental=claiming_experimental)
    if claiming_experimental and status != STATUS_EXPERIMENTAL:
        raise _experiment_error(
            "claiming experimental evidence requires the matching status", status=status
        )

    rows = list(samples)
    baseline = prepare_dataset(rows, features=features) if features else prepare_dataset(rows)
    for split in SPLITS:
        if not baseline.labels(split):
            raise _experiment_error(
                f"the {split} split is empty; a privacy comparison needs all three splits",
                split=split,
            )

    mitigated = _mitigated_samples(rows, countermeasure)
    mitigated_data = (
        prepare_dataset(mitigated, features=features)
        if features
        else prepare_dataset(mitigated)
    )
    unchanged = mitigated_data.fingerprint == baseline.fingerprint
    isolation_notes = (
        ("the countermeasure did not change any feature value",) if unchanged else ()
    )

    # ---- baseline attacker ------------------------------------------------
    reports, baseline_pipeline, baseline_winner = fit_candidates(
        baseline, candidates, seed=seed, tolerance=tolerance
    )
    baseline_test = _evaluate(baseline_pipeline, baseline, "test")
    baseline_macro = macro_f1(baseline_test)
    baseline_accuracy = float(baseline_test.get("accuracy", 0.0))
    baseline_reference = majority_class_baseline(baseline)

    # ---- Attacker A: frozen, evaluated on mitigated traffic ----------------
    a_metrics = _cross_evaluate(baseline_pipeline, mitigated_data, baseline.classes)
    attacker_a = AttackerResult(
        name=ATTACKER_A,
        description=(
            "trained and selected on baseline traffic, then evaluated unchanged against "
            "mitigated traffic; it never saw the mitigated distribution"
        ),
        trained_on="baseline",
        evaluated_on="mitigated",
        winner=baseline_winner,
        metrics=a_metrics,
        macro_f1=macro_f1(a_metrics),
        accuracy=float(a_metrics.get("accuracy", 0.0)),
        baseline_macro_f1=baseline_macro,
        delta_macro_f1=round(macro_f1(a_metrics) - baseline_macro, 6),
        delta_accuracy=round(float(a_metrics.get("accuracy", 0.0)) - baseline_accuracy, 6),
        coverage=1.0 if mitigated_data.labels("test") else 0.0,
        unknown_rejection_rate=None,
        calibration_state="as produced by the Part 1 trainer",
        open_world_policy_state="not applied (closed-set comparison)",
        fingerprint=mitigated_data.fingerprint,
        notes=(
            "the mitigated evaluation rows were never used to fit, select or calibrate this model",
            *isolation_notes,
        ),
    )

    # ---- Attacker B: retrained on mitigated traffic ------------------------
    _b_reports, b_pipeline, b_winner = fit_candidates(
        mitigated_data, candidates, seed=seed, tolerance=tolerance
    )
    b_test = _evaluate(b_pipeline, mitigated_data, "test")
    attacker_b = AttackerResult(
        name=ATTACKER_B,
        description=(
            "retrained and reselected on mitigated traffic, evaluated once on the held-out "
            "mitigated split; grouping and the train/validation/test contract are preserved"
        ),
        trained_on="mitigated",
        evaluated_on="mitigated (held-out split)",
        winner=b_winner,
        metrics=b_test,
        macro_f1=macro_f1(b_test),
        accuracy=float(b_test.get("accuracy", 0.0)),
        baseline_macro_f1=baseline_macro,
        delta_macro_f1=round(macro_f1(b_test) - baseline_macro, 6),
        delta_accuracy=round(float(b_test.get("accuracy", 0.0)) - baseline_accuracy, 6),
        coverage=1.0 if mitigated_data.labels("test") else 0.0,
        unknown_rejection_rate=None,
        calibration_state="as produced by the Part 1 trainer",
        open_world_policy_state="not applied (closed-set comparison)",
        fingerprint=mitigated_data.fingerprint,
        notes=(
            "this attacker adapted to the mitigation; a small delta here is expected and is "
            "not evidence that the mitigation failed",
        ),
    )

    overhead = _overhead(countermeasure, rows)
    return {
        "schema": PRIVACY_EXPERIMENT_SCHEMA,
        "experiment_id": experiment_id,
        "generated_at": _utc_now(),
        "status": status,
        "provenance": provenance.to_dict(),
        "dataset": {
            "baseline_fingerprint": baseline.fingerprint,
            "mitigated_fingerprint": mitigated_data.fingerprint,
            "rows": int(baseline.row_count),
            "groups": int(baseline.integrity.get("group_count", 0)),
            "classes": list(baseline.classes),
            "split_groups": baseline.integrity,
            "feature_names": list(baseline.feature_names),
            "feature_schema": _feature_schema(),
            "countermeasure_changed_data": not unchanged,
        },
        "countermeasure": countermeasure.describe(),
        "baseline": {
            "winner": baseline_winner,
            "macro_f1": baseline_macro,
            "accuracy": baseline_accuracy,
            "metrics": baseline_test,
            "majority_baseline": baseline_reference,
            "candidates": [
                {"name": item["name"], "status": item["status"]} for item in reports
            ],
        },
        "attacker_a": attacker_a.to_dict(),
        "attacker_b": attacker_b.to_dict(),
        "overhead": overhead,
        "cost": _cost_block(attacker_a, attacker_b, overhead),
        "limitations": _limitations(countermeasure, provenance, status),
        "notes": [
            "baseline and mitigation measurements use the same candidate list, seed and "
            "selection rule, so the only variable is the countermeasure",
            "no latency, throughput or jitter figure is reported; none was measured",
            *(str(item) for item in notes),
        ],
    }


def _cross_evaluate(pipeline: Any, data: Any, classes: Sequence[str]) -> dict[str, Any]:
    """Score one fitted pipeline over another dataset's held-out split."""
    rows = data.matrix("test")
    labels = data.labels("test")
    if not rows:
        return {"sample_count": 0, "accuracy": 0.0, "macro": {"f1": 0.0}}
    predictions = [str(item) for item in pipeline.predict(rows)]
    return classification_metrics(
        labels, predictions, labels=classes, groups=data.groups("test")
    )


__all__ = [
    "ATTACKER_A",
    "ATTACKER_B",
    "PRIVACY_EXPERIMENT_SCHEMA",
    "STATUS_EXPERIMENTAL",
    "STATUS_SIMULATED",
    "AttackerResult",
    "run_privacy_experiment",
]
