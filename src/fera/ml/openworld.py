"""Open-world rejection: letting FERA answer UNKNOWN instead of guessing.

A closed-set classifier answers "which known class is this?".  That question has
an answer even when the evidence does not support one, so a flow from an
application FERA has never seen still gets stamped ``web`` with whatever
probability the argmax happened to produce.  This module adds the second
question: *does the evidence justify assigning any known class at all?*

Scope, stated plainly so no downstream reader over-claims it:

* this is a **pragmatic rejection layer** built on the existing classifier's
  calibrated probabilities, not a novelty detector and not proof that FERA can
  recognise every unseen application;
* an ``UNKNOWN`` here means "FERA did not find sufficient support for a known
  class", **never** "malicious", "anomalous" or "unidentifiable forever";
* ``UNKNOWN`` remains ``INFERRED`` evidence.  It is a different statement from
  ``NOT_VERIFIABLE``, which means a protocol/security fact could not be
  determined.  The two are never substituted for one another.

Three rejection signals are supported, and they are deliberately *not* fused
into a single opaque score:

``confidence``
    the calibrated probability of the top class is below a threshold;
``margin``
    top-1 minus top-2 is below a threshold (the model is torn between two
    classes, even if it leans slightly one way);
``entropy``
    the predictive distribution is flat (bits), which catches uniform-ish
    output that a high max-probability can hide when there are many classes.

The default rule is *max-confidence OR margin*, both optional, with entropy
available but off.  A transparent rule that an operator can read off one line
is worth more here than a tuned combination whose behaviour nobody can predict.

Threshold provenance is first-class: every policy carries a
:data:`THRESHOLD_SOURCES` label saying whether its numbers came from
validation data, are an uncalibrated placeholder, or were never set.  A
threshold that has not been fitted never silently reads as authoritative.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..common.errors import ErrorCode, FeraError
from .calibration import entropy_bits

#: Schema identifier of one open-world decision document.
OPEN_WORLD_SCHEMA = "fera_ml_open_world_v1"

#: The label used when assignment to every known class is rejected.
UNKNOWN_LABEL = "UNKNOWN"

#: Decision values a sample may receive.
DECISION_KNOWN = "KNOWN"
DECISION_UNKNOWN = "UNKNOWN"

#: Stable rejection reasons.  These strings are part of the contract: a report,
#: a dashboard and a test all quote the same token.
REASON_LOW_CONFIDENCE = "LOW_CALIBRATED_CONFIDENCE"
REASON_LOW_MARGIN = "LOW_TOP1_TOP2_MARGIN"
REASON_HIGH_ENTROPY = "HIGH_PREDICTIVE_ENTROPY"
REASON_DISABLED = "OPEN_WORLD_DISABLED"

#: Where a policy's thresholds came from.  ``UNCALIBRATED_DEFAULT`` must never be
#: presented as a validated operating point.
SOURCE_VALIDATION = "VALIDATION-DERIVED"
SOURCE_PLACEHOLDER = "UNCALIBRATED_DEFAULT"
SOURCE_UNSET = "NOT_SET"

THRESHOLD_SOURCES: tuple[str, ...] = (SOURCE_VALIDATION, SOURCE_PLACEHOLDER, SOURCE_UNSET)

#: Default maximum entropy, in bits, for a two-class model.  Left ``None`` so the
#: signal is opt-in: enabling it by default on an unvalidated model would reject
#: traffic for a reason no operator asked for.
DEFAULT_MAX_ENTROPY_BITS: float | None = None
def _policy_error(message: str, **details: Any) -> FeraError:
    return FeraError(
        message,
        code=ErrorCode.CONFIG_VALIDATION_FAILED,
        hint="tune the thresholds on a validation partition, or accept the placeholder status",
        details=details,
    )


def _validate_threshold(name: str, value: float | None, *, upper: float = 1.0) -> None:
    if value is None:
        return
    if not math.isfinite(value) or not 0.0 <= value <= upper:
        raise _policy_error(
            f"{name} must be within [0, {upper}] or None (got {value})",
            threshold=name,
            value=value,
        )


@dataclass(frozen=True)
class RejectionPolicy:
    """Configurable, transparent rules for rejecting a known-class assignment.

    ``use_margin`` and ``use_entropy`` gate the two secondary signals so an
    operator can run confidence-only and see what the extra rules would change,
    rather than discovering a three-way interaction in production.

    ``source`` records provenance.  A policy whose thresholds were never fitted
    on validation data carries :data:`SOURCE_PLACEHOLDER` and the resulting
    decisions are marked ``EXPERIMENTAL``.
    """

    confidence_threshold: float = 0.5
    margin_threshold: float | None = None
    entropy_threshold: float | None = None
    use_margin: bool = False
    use_entropy: bool = False
    enabled: bool = True
    source: str = SOURCE_PLACEHOLDER
    calibration_method: str | None = None
    calibrated: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _validate_threshold("confidence_threshold", self.confidence_threshold)
        _validate_threshold("margin_threshold", self.margin_threshold)
        _validate_threshold("entropy_threshold", self.entropy_threshold)
        if self.source not in THRESHOLD_SOURCES:
            raise _policy_error(
                f"unknown threshold source: {self.source}",
                available=list(THRESHOLD_SOURCES),
            )
        if self.use_margin and self.margin_threshold is None:
            raise _policy_error("use_margin is set but margin_threshold is None")
        if self.use_entropy and self.entropy_threshold is None:
            raise _policy_error("use_entropy is set but entropy_threshold is None")

    @property
    def calibrated_status(self) -> str:
        """Human-facing calibration state of the thresholds in force."""
        if not self.calibrated:
            return "UNCALIBRATED"
        return f"CALIBRATED ({self.calibration_method})"

    @property
    def experimental(self) -> bool:
        """True when these thresholds must not be presented as validated."""
        return self.source != SOURCE_VALIDATION or not self.calibrated

    def signals(self) -> dict[str, Any]:
        """The policy as data, for an artefact or a report."""
        return {
            "enabled": bool(self.enabled),
            "confidence_threshold": self.confidence_threshold,
            "margin_threshold": self.margin_threshold,
            "entropy_threshold": self.entropy_threshold,
            "use_margin": bool(self.use_margin),
            "use_entropy": bool(self.use_entropy),
            "source": self.source,
            "calibrated": bool(self.calibrated),
            "calibration_method": self.calibration_method,
            "calibrated_status": self.calibrated_status,
            "experimental": self.experimental,
            "rule": "reject if confidence < threshold"
            + (" OR margin < threshold" if self.use_margin else "")
            + (" OR entropy > threshold" if self.use_entropy else ""),
        }

    def to_dict(self) -> dict[str, Any]:
        return {"schema": OPEN_WORLD_SCHEMA, **self.signals(), "notes": list(self.notes)}


def default_policy() -> RejectionPolicy:
    """Confidence-only policy with explicitly unvalidated thresholds.

    This is the correct default for a model that has never been calibrated on
    representative data: it degrades to the closed-set behaviour plus a low
    confidence flag, and says so rather than pretending to an operating point.
    """
    return RejectionPolicy(
        confidence_threshold=0.5,
        source=SOURCE_PLACEHOLDER,
        notes=(
            "placeholder thresholds: no representative validation data has been fitted yet",
            "decisions made with this policy are EXPERIMENTAL and must be labelled as such",
        ),
    )


def disabled_policy(reason: str) -> RejectionPolicy:
    """A policy that never rejects - the closed-set behaviour, stated explicitly."""
    return RejectionPolicy(
        enabled=False,
        source=SOURCE_UNSET,
        notes=(f"open-world rejection is disabled: {reason}",),
    )


@dataclass(frozen=True)
class OpenWorldDecision:
    """Outcome of applying a :class:`RejectionPolicy` to one probability table."""

    predicted_class: str
    decision: str
    confidence: float
    probabilities: Mapping[str, float]
    closest_known_class: str
    reason: str | None
    triggered: tuple[str, ...]
    margin: float | None
    entropy_bits: float
    policy: RejectionPolicy

    @property
    def rejected(self) -> bool:
        return self.decision == DECISION_UNKNOWN

    @property
    def top_alternatives(self) -> list[dict[str, Any]]:
        """Ranked known classes, so an UNKNOWN still says what it was torn between."""
        return [
            {"class": name, "probability": value}
            for name, value in sorted(
                self.probabilities.items(), key=lambda item: (-item[1], item[0])
            )
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": OPEN_WORLD_SCHEMA,
            "decision": self.decision,
            "rejected": self.rejected,
            "reason": self.reason,
            "triggered_signals": list(self.triggered),
            "confidence": self.confidence,
            "margin": self.margin,
            "entropy_bits": self.entropy_bits,
            "closest_known_class": self.closest_known_class,
            "threshold_source": self.policy.source,
            "calibrated": bool(self.policy.calibrated),
            "calibration_method": self.policy.calibration_method,
            "calibrated_status": self.policy.calibrated_status,
            "experimental": self.policy.experimental,
            "policy": self.policy.signals(),
            # UNKNOWN is an inference, exactly like a known-class prediction.
            "evidence_status": "INFERRED",
            "notes": [
                "UNKNOWN means no known class was sufficiently supported; it does not "
                "mean malicious, anomalous, or unidentifiable forever",
                "UNKNOWN is not NOT_VERIFIABLE: this is an inference about traffic class, "
                "not an undetermined protocol fact",
            ],
        }


def decide(
    probabilities: Mapping[str, float],
    policy: RejectionPolicy | None = None,
) -> OpenWorldDecision:
    """Apply ``policy`` to one probability table and return the KNOWN/UNKNOWN call.

    The probability table is never discarded on rejection: the closest known
    class, its calibrated probability and the ranked alternatives all survive,
    because "FERA was not sure, and here is what it was choosing between" is far
    more useful to an operator than a bare UNKNOWN.
    """
    active = policy if policy is not None else default_policy()
    if not probabilities:
        raise _policy_error("cannot decide on an empty probability table")

    ordered = sorted(probabilities.items(), key=lambda item: (-item[1], item[0]))
    closest, top = ordered[0]
    confidence = round(float(top), 6)
    runner_up = round(float(ordered[1][1]), 6) if len(ordered) > 1 else 0.0
    margin = round(confidence - runner_up, 6)
    entropy = entropy_bits([float(value) for _, value in ordered])

    triggered: list[str] = []
    if not active.enabled:
        triggered.append(REASON_DISABLED)
    else:
        if confidence < active.confidence_threshold:
            triggered.append(REASON_LOW_CONFIDENCE)
        if active.use_margin and margin < float(active.margin_threshold or 0.0):
            triggered.append(REASON_LOW_MARGIN)
        if active.use_entropy and entropy > float(active.entropy_threshold or 0.0):
            triggered.append(REASON_HIGH_ENTROPY)

    rejected = bool(triggered) and REASON_DISABLED not in triggered
    return OpenWorldDecision(
        predicted_class=UNKNOWN_LABEL if rejected else closest,
        decision=DECISION_UNKNOWN if rejected else DECISION_KNOWN,
        confidence=confidence,
        probabilities={name: round(float(value), 6) for name, value in ordered},
        closest_known_class=closest,
        reason=triggered[0] if rejected else None,
        triggered=tuple(triggered),
        margin=margin,
        entropy_bits=entropy,
        policy=active,
    )


def open_world_metrics(
    known_true: Sequence[str],
    known_predicted: Sequence[str | None],
    unknown_true: Sequence[str] | None = None,
    unknown_predicted: Sequence[str | None] | None = None,
) -> dict[str, Any]:
    """Selective-classification metrics for a rejection policy.

    Definitions, so the numbers cannot be misread:

    ``known_acceptance_rate``
        fraction of known-class rows the policy did **not** reject;
    ``known_false_rejection_rate``
        ``1 - known_acceptance_rate``, i.e. known traffic wrongly called UNKNOWN;
    ``known_accuracy_when_accepted``
        accuracy of the accepted known rows only - what the operator actually
        gets to rely on after the filter;
    ``unknown_rejection_rate``
        fraction of held-out unknown-class rows correctly rejected;
    ``coverage``
        overall fraction of *all* rows (known and unknown) that were accepted.

    ``None`` inputs are permitted for the unknown side so the function can score
    a closed-set policy honestly; the unknown metrics then report ``None``
    rather than a fabricated 0.0 or 1.0.
    """
    accepted_known = sum(1 for item in known_predicted if item is not None)
    correct_accepted = sum(
        1 for truth, predicted in zip(known_true, known_predicted, strict=False)
        if predicted is not None and predicted == truth
    )
    known_total = len(known_true)
    acceptance = accepted_known / known_total if known_total else 0.0

    block: dict[str, Any] = {
        "known_rows": known_total,
        "known_accepted": accepted_known,
        "known_accuracy_when_accepted": (
            correct_accepted / accepted_known if accepted_known else 0.0
        ),
        "known_acceptance_rate": round(acceptance, 6),
        "known_false_rejection_rate": round(1.0 - acceptance, 6),
    }

    if unknown_true is None or unknown_predicted is None:
        block.update(
            {
                "unknown_rows": 0,
                "unknown_rejected": 0,
                "unknown_rejection_rate": None,
                "coverage": None,
                "status": "UNVERIFIED - UNKNOWN VALIDATION DATA REQUIRED",
            }
        )
        return block

    unknown_total = len(unknown_true)
    unknown_rejected = sum(1 for item in unknown_predicted if item is None)
    unknown_rate = unknown_rejected / unknown_total if unknown_total else 0.0
    overall = accepted_known + (unknown_total - unknown_rejected)
    block.update(
        {
            "unknown_rows": unknown_total,
            "unknown_rejected": unknown_rejected,
            "unknown_rejection_rate": round(unknown_rate, 6),
            "coverage": round(overall / (known_total + unknown_total), 6)
            if (known_total + unknown_total)
            else 0.0,
            "status": "MEASURED",
        }
    )
    return block


def threshold_sweep(
    probabilities: Sequence[Mapping[str, float]],
    known_truth: Sequence[str],
    policy_template: RejectionPolicy,
    *,
    candidates: Sequence[float] | None = None,
) -> dict[str, Any]:
    """Evaluate a range of confidence thresholds on one (known-only) partition.

    Used to *choose* a threshold on validation data.  Deliberately takes no
    unknown-class data: selecting a threshold needs to maximise known-class
    behaviour, and tuning it against held-out unknowns would leak the very
    partition the open-world experiment later measures.
    """
    if len(probabilities) != len(known_truth):
        raise _policy_error("threshold sweep inputs disagree in length")
    grid = [float(value) for value in (candidates or (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9))]
    rows: list[dict[str, Any]] = []
    for threshold in sorted(grid):
        policy = RejectionPolicy(
            confidence_threshold=threshold,
            margin_threshold=policy_template.margin_threshold,
            entropy_threshold=policy_template.entropy_threshold,
            use_margin=policy_template.use_margin,
            use_entropy=policy_template.use_entropy,
            enabled=True,
            source=SOURCE_VALIDATION,
            calibration_method=policy_template.calibration_method,
            calibrated=policy_template.calibrated,
        )
        outcomes = [decide(row, policy) for row in probabilities]
        predicted: list[str | None] = [
            None if outcome.rejected else outcome.closest_known_class for outcome in outcomes
        ]
        rows.append(
            {
                "threshold": threshold,
                **open_world_metrics(known_truth, predicted),
            }
        )
    return {
        "schema": OPEN_WORLD_SCHEMA,
        "partition": "validation",
        "rows": rows,
        "notes": [
            "each row re-applied the policy with only the confidence threshold changed",
            "no unknown-class data is used here: choosing a threshold must not see the "
            "partition the open-world experiment later measures",
        ],
    }


__all__ = [
    "DECISION_KNOWN",
    "DECISION_UNKNOWN",
    "OPEN_WORLD_SCHEMA",
    "REASON_DISABLED",
    "REASON_HIGH_ENTROPY",
    "REASON_LOW_CONFIDENCE",
    "REASON_LOW_MARGIN",
    "SOURCE_PLACEHOLDER",
    "SOURCE_UNSET",
    "SOURCE_VALIDATION",
    "THRESHOLD_SOURCES",
    "UNKNOWN_LABEL",
    "OpenWorldDecision",
    "RejectionPolicy",
    "decide",
    "default_policy",
    "disabled_policy",
    "open_world_metrics",
    "threshold_sweep",
]
