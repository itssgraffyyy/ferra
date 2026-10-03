"""Experiment orchestration: evidence gates, manifests and the state machine.

This module exists because of a specific, previously-observed failure: strongSwan
came up, IKE negotiated, `ping` succeeded, and the payload had in fact travelled
a **direct unprotected path** while ESP carried nothing.  Every indicator FERA
had been checking was green.  The only thing that would have caught it is
checking, in order, that the XFRM state and policy existed, that the payload
matched them, and that genuine ESP appeared on the wire.

So the gates are explicit and ordered, and a run that satisfies only some of
them is **not** eligible to become real-IPsec evidence:

    1. IKE_SA established
    2. CHILD_SA established
    3. XFRM state present
    4. XFRM policy present
    5. the intended payload actually crossed the protected path
    6. genuine ESP observed in the capture

Gate 1 alone - an IKE negotiation - is explicitly *not* success.  There is a
dedicated assertion for that, because it is the mistake that would otherwise be
made again.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..common.errors import ErrorCode, FeraError

#: Schema identifier of one experiment manifest / gate document.
MANIFEST_SCHEMA = "fera_experiment_manifest_v1"


class Stage(str, Enum):
    """Where an experiment has got to.  Ordered: later requires earlier."""

    PLANNED = "PLANNED"
    PREFLIGHT_PASSED = "PREFLIGHT_PASSED"
    TESTBED_READY = "TESTBED_READY"
    IKE_VERIFIED = "IKE_VERIFIED"
    CHILD_SA_VERIFIED = "CHILD_SA_VERIFIED"
    XFRM_VERIFIED = "XFRM_VERIFIED"
    TRAFFIC_GENERATED = "TRAFFIC_GENERATED"
    ESP_VERIFIED = "ESP_VERIFIED"
    CAPTURE_VALIDATED = "CAPTURE_VALIDATED"
    MANIFEST_FINALIZED = "MANIFEST_FINALIZED"
    DATASET_ELIGIBLE = "DATASET_ELIGIBLE"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


#: The ordered evidence gates a run must clear before it may claim real ESP.
EVIDENCE_GATES: tuple[str, ...] = (
    "ike_sa_verified",
    "child_sa_verified",
    "xfrm_state_verified",
    "xfrm_policy_verified",
    "protected_payload_verified",
    "esp_verified",
)

#: Stages a run must reach before it is eligible to become dataset rows.
DATASET_ELIGIBLE_STAGE = Stage.MANIFEST_FINALIZED

#: The gate each stage depends on.  ``advance`` consults this.
GATE_FOR_STAGE: Mapping[Stage, str] = {
    Stage.IKE_VERIFIED: "ike_sa_verified",
    Stage.CHILD_SA_VERIFIED: "child_sa_verified",
    Stage.XFRM_VERIFIED: "xfrm_policy_verified",
    Stage.TRAFFIC_GENERATED: "protected_payload_verified",
    Stage.ESP_VERIFIED: "esp_verified",
}


def _gate_error(message: str, **details: Any) -> FeraError:
    return FeraError(
        message,
        code=ErrorCode.CONFIG_VALIDATION_FAILED,
        hint="see docs/linux_experiments.md for the evidence-gate contract",
        details=details,
    )


@dataclass
class ExperimentState:
    """Mutable progression of one experiment, with its evidence gates attached.

    ``advance`` refuses to move past a stage whose gate is not satisfied, so a
    failed stage cannot silently permit the real-data stages that follow it.
    """

    experiment_id: str
    session_id: str = ""
    configuration_id: str = ""
    repeat_id: int = 0
    traffic_class: str = ""
    stage: Stage = Stage.PLANNED
    gates: dict[str, bool] = field(default_factory=lambda: dict.fromkeys(EVIDENCE_GATES, False))
    #: Free-form evidence, e.g. ``{"xfrm_state_count": 2, "esp_packets": 118}``.
    evidence: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    failure_reason: str = ""

    def satisfy(self, gate: str) -> None:
        """Mark one evidence gate as verified (or explicitly not)."""
        if gate not in self.gates:
            raise _gate_error(
                f"unknown evidence gate: {gate}", known=list(EVIDENCE_GATES)
            )
        self.gates[gate] = True

    @property
    def verified_gates(self) -> list[str]:
        return [name for name in EVIDENCE_GATES if self.gates.get(name)]

    @property
    def missing_gates(self) -> list[str]:
        return [name for name in EVIDENCE_GATES if not self.gates.get(name)]

    @property
    def real_ipsec_verified(self) -> bool:
        """True only when *every* gate is satisfied.

        This is the single place the decision is made, so no caller can decide it
        more generously.
        """
        return not self.missing_gates

    def advance(self, stage: Stage) -> Stage:
        """Move to ``stage``, refusing to skip an unsatisfied gate."""
        gate = GATE_FOR_STAGE.get(stage)
        if gate is not None and not self.gates.get(gate):
            raise _gate_error(
                f"cannot enter {stage.value}: the '{gate}' gate is not verified",
                stage=stage.value,
                gate=gate,
                missing=self.missing_gates,
            )
        self.stage = stage
        return stage

    def fail(self, reason: str) -> Stage:
        self.stage = Stage.FAILED
        self.failure_reason = reason
        return self.stage

    def assert_dataset_eligible(self) -> None:
        """Refuse dataset eligibility for a run that is not fully evidenced.

        The rule this encodes: real dataset rows may only come from captures
        whose required gates passed *and* whose run did not fail.  A fixture run
        therefore cannot feed the real pipeline, and says so rather than quietly
        contributing rows.
        """
        if not self.dataset_eligible:
            raise _gate_error(
                "this run is not eligible for the real dataset: "
                + (
                    f"stage is {self.stage.value}"
                    if self.real_ipsec_verified
                    else "evidence gates are unmet"
                ),
                experiment_id=self.experiment_id,
                missing=self.missing_gates,
                stage=self.stage.value,
            )

    def assert_ike_is_not_success(self) -> None:
        """Guard the specific historical mistake.

        Separate from :attr:`real_ipsec_verified` because it is worth stating
        explicitly in code: a successful IKE negotiation, on its own, does not
        mean the payload crossed ESP.
        """
        if self.gates.get("ike_sa_verified") and not self.real_ipsec_verified:
            raise _gate_error(
                "IKE_SA is verified but the run is not real-IPsec verified; an IKE "
                "negotiation alone is not evidence that the payload crossed ESP",
                experiment_id=self.experiment_id,
                missing=self.missing_gates,
            )

    @property
    def dataset_eligible(self) -> bool:
        """Dataset rows may only come from a fully evidenced, non-failed run.

        A FAILED or BLOCKED run can still have every gate set from an earlier
        stage, so gate state alone is not enough: a run that failed during
        capture must never contribute rows to the real dataset.
        """
        return self.real_ipsec_verified and self.stage not in {
            Stage.FAILED,
            Stage.BLOCKED,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": MANIFEST_SCHEMA,
            "experiment_id": self.experiment_id,
            "session_id": self.session_id,
            "configuration_id": self.configuration_id,
            "repeat_id": int(self.repeat_id),
            "traffic_class": self.traffic_class,
            "stage": self.stage.value,
            "evidence_gates": dict(self.gates),
            "verified_gates": self.verified_gates,
            "missing_gates": self.missing_gates,
            "real_ipsec_verified": self.real_ipsec_verified,
            "dataset_eligible": self.dataset_eligible,
            "evidence": dict(self.evidence),
            "failure_reason": self.failure_reason,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ExperimentState:
        gates = dict(payload.get("evidence_gates") or {})
        return cls(
            experiment_id=str(payload.get("experiment_id") or ""),
            session_id=str(payload.get("session_id") or ""),
            configuration_id=str(payload.get("configuration_id") or ""),
            repeat_id=int(payload.get("repeat_id") or 0),
            traffic_class=str(payload.get("traffic_class") or ""),
            stage=Stage(str(payload.get("stage") or Stage.PLANNED.value)),
            gates={name: bool(gates.get(name, False)) for name in EVIDENCE_GATES},
            evidence=dict(payload.get("evidence") or {}),
            notes=[str(item) for item in (payload.get("notes") or ())],
            failure_reason=str(payload.get("failure_reason") or ""),
        )


@dataclass(frozen=True)
class GateEvidence:
    """What was actually observed about one run, gate by gate.

    Each field is an observation, never an assumption: a field is True only
    because something measured it.  ``xfrm_state``/``xfrm_policy`` are ``None``
    when the probe could not run, which is deliberately distinct from ``False``
    ("probed, and empty").  Collapsing the two would make a host that cannot
    read XFRM look identical to a host that proved no SA exists.
    """

    ike_established: bool = False
    child_installed: bool = False
    xfrm_state: bool | None = None
    xfrm_policy: bool | None = None
    protected_payload: bool = False
    esp_observed: bool = False
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ike_sa_established": self.ike_established,
            "child_sa_installed": self.child_installed,
            "xfrm_state_present": self.xfrm_state,
            "xfrm_policy_present": self.xfrm_policy,
            "protected_payload_crossed": self.protected_payload,
            "esp_observed": self.esp_observed,
            "details": dict(self.details),
        }


def _xfrm_entries(output: str) -> int:
    """Count entries in ``ip xfrm`` output.

    Every entry begins with a ``src`` line in the first column and continues with
    *indented* lines (``ip xfrm`` prints one block per SA/policy).  Matching only
    at column 0 is therefore what counts entries: stripping the line first would
    also count each entry's continuation lines and inflate the count, which
    would let a table with a single SA report several and make an empty-table
    check unreliable.
    """
    return sum(1 for line in output.splitlines() if line.startswith("src "))


def probe_xfrm(runner: Any) -> dict[str, Any]:
    """Probe the local XFRM state and policy tables through ``runner``.

    ``EVIDENCE_GATES`` demands ``xfrm_state_verified`` and
    ``xfrm_policy_verified`` before a run may claim real IPsec evidence, but
    nothing in the repository ever collected that evidence, so both gates could
    never be satisfied and the whole gate machinery was unreachable.

    A run that negotiates IKE and then sees its payload cross a cleartext path is
    exactly the failure these gates exist to catch, and ``ip xfrm state`` is the
    direct observation of whether SAs actually exist.

    A host that cannot read XFRM yields ``available=False`` with a reason rather
    than raising: a missing probe is not the same as a missing SA.
    """
    results: dict[str, Any] = {}
    reasons: list[str] = []
    for table in ("state", "policy"):
        result = runner.run(["ip", "xfrm", table], timeout=10.0, check=False)
        ok = bool(result.ok)
        entries = _xfrm_entries(result.stdout or "") if ok else 0
        results[f"{table}_entries"] = entries
        results[f"{table}_available"] = ok
        if not ok:
            detail = (result.stderr or "").strip()
            reasons.append(f"ip xfrm {table} failed (rc={result.returncode}): {detail}")
    results["available"] = not reasons
    results["reason"] = "; ".join(reasons)
    return results


def _gate_flags(evidence: GateEvidence) -> dict[str, bool]:
    """Map observed evidence onto the six evidence gates."""
    return {
        "ike_sa_verified": evidence.ike_established,
        "child_sa_verified": evidence.child_installed,
        "xfrm_state_verified": bool(evidence.xfrm_state),
        "xfrm_policy_verified": bool(evidence.xfrm_policy),
        # Traffic proves nothing about ESP on its own, so a protected payload
        # only counts when a CHILD_SA was actually installed.
        "protected_payload_verified": (
            evidence.protected_payload and evidence.child_installed
        ),
        "esp_verified": evidence.esp_observed,
    }


def derive_gate_state(
    evidence: GateEvidence,
    *,
    experiment_id: str = "",
    configuration_id: str = "",
    session_id: str = "",
    traffic_class: str = "",
    failed: bool = False,
) -> dict[str, Any]:
    """Turn observed evidence into a serialised gate state.

    The decision is made here — in the gates module that documents the contract
    — rather than being re-derived by the caller, so ``integration_verified`` can
    only ever mean *every gate was satisfied by an observation*.
    """
    state = ExperimentState(
        experiment_id=experiment_id,
        session_id=session_id,
        configuration_id=configuration_id,
        traffic_class=traffic_class,
    )
    for name, satisfied in _gate_flags(evidence).items():
        if satisfied:
            state.satisfy(name)
    state.evidence = evidence.to_dict()
    if failed:
        state.fail("run failed before the evidence gates were satisfied")
    elif state.real_ipsec_verified:
        state.advance(Stage.MANIFEST_FINALIZED)
    else:
        # Deliberately not advanced: an unmet gate must leave the run short of
        # MANIFEST_FINALIZED, which is what ``assert_dataset_eligible`` demands.
        state.notes.append("evidence gates unmet: " + ", ".join(state.missing_gates))
    return state.to_dict()


__all__ = [
    "DATASET_ELIGIBLE_STAGE",
    "EVIDENCE_GATES",
    "GATE_FOR_STAGE",
    "GateEvidence",
    "MANIFEST_SCHEMA",
    "ExperimentState",
    "Stage",
    "derive_gate_state",
    "probe_xfrm",
]
