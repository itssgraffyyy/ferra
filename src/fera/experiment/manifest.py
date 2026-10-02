"""The canonical experiment manifest: one document per run, with its lineage.

A manifest is what makes a result auditable months later.  It answers, without
needing the original shell session:

* which IPsec configuration produced this, and which traffic class;
* which **session** it was, distinct from the experiment, so grouped splitting
  has a real independence boundary;
* what the environment was, including tool versions;
* what the capture's bytes were (SHA-256), not just its filename;
* which evidence gates were actually verified, and which were not;
* what the privacy countermeasure was and **how it was applied**.

Ground truth in this document comes from the experiment configuration, never
from classifier output.  A manifest that recorded what the model predicted
would be circular, so :class:`ExperimentManifest` has no field for it.

The manifest never *infers* a gate.  It carries the state that
:mod:`fera.experiment.gates` produced and refuses to serialise a manifest whose
gates claim more than its evidence supports.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..common.errors import ErrorCode, FeraError
from ..dataset.schema import IpsecMode, TrafficClass
from .capture import CaptureEvidence
from .gates import EVIDENCE_GATES, ExperimentState, Stage

#: Schema identifier of one experiment manifest.
MANIFEST_SCHEMA = "fera_experiment_manifest_v2"

#: Terminal states of a run.
STATUS_VALID = "VALID"
STATUS_INVALID = "INVALID"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_BLOCKED = "BLOCKED"

MANIFEST_STATUSES: tuple[str, ...] = (
    STATUS_VALID,
    STATUS_INVALID,
    STATUS_INCOMPLETE,
    STATUS_BLOCKED,
)


#: Field names :class:`CaptureEvidence` owns, used to rebuild it from a document.
CAPTURE_EVIDENCE_FIELDS: tuple[str, ...] = (
    "path",
    "sha256",
    "size_bytes",
    "status",
    "packets",
    "ike_detected",
    "esp_detected",
    "ipv4_detected",
    "ipv6_detected",
    "nat_t_possible",
    "reasons",
    "checked_at",
)


def _manifest_error(message: str, **details: Any) -> FeraError:
    return FeraError(
        message,
        code=ErrorCode.CONFIG_VALIDATION_FAILED,
        hint="see docs/linux_experiments.md for the manifest contract",
        details=details,
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class IpsecGroundTruth:
    """What the experiment *configured*, read from the testbed definition.

    Every field here is CONFIGURED, not OBSERVED: it states intent from the
    experiment configuration, and whether the wire actually carried it is the
    evidence gates' business.  Keeping the two apart is what stops a
    configured-but-undelivered cipher suite from being reported as observed.
    """

    ike_version: str = "2"
    mode: str = IpsecMode.TUNNEL.value
    encryption: str = ""
    integrity: str = ""
    aead: bool = False
    dh_group: str = ""
    pfs: bool = False
    ip_version: int = 4
    nat_t: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_status": "CONFIGURED",
            "ike_version": self.ike_version,
            "mode": self.mode,
            "encryption": self.encryption,
            "integrity": self.integrity,
            "aead": self.aead,
            "dh_group": self.dh_group,
            "pfs": self.pfs,
            "ip_version": self.ip_version,
            "nat_t": self.nat_t,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> IpsecGroundTruth:
        return cls(
            ike_version=str(payload.get("ike_version") or "2"),
            mode=str(payload.get("mode") or IpsecMode.TUNNEL.value),
            encryption=str(payload.get("encryption") or ""),
            integrity=str(payload.get("integrity") or ""),
            aead=bool(payload.get("aead", False)),
            dh_group=str(payload.get("dh_group") or ""),
            pfs=bool(payload.get("pfs", False)),
            ip_version=int(payload.get("ip_version") or 4),
            nat_t=(None if payload.get("nat_t") is None else bool(payload["nat_t"])),
        )


@dataclass(frozen=True)
class NetworkCondition:
    """netem state applied to the experiment, recorded so it is reproducible."""

    condition: str = "baseline"
    loss_percent: float | None = None
    jitter_ms: float | None = None
    delay_ms: float | None = None
    applied: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "condition": self.condition,
            "loss_percent": self.loss_percent,
            "jitter_ms": self.jitter_ms,
            "delay_ms": self.delay_ms,
            "applied": self.applied,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> NetworkCondition:
        return cls(
            condition=str(payload.get("condition") or "baseline"),
            loss_percent=(
                None if payload.get("loss_percent") is None else float(payload["loss_percent"])
            ),
            jitter_ms=(None if payload.get("jitter_ms") is None else float(payload["jitter_ms"])),
            delay_ms=(None if payload.get("delay_ms") is None else float(payload["delay_ms"])),
            applied=bool(payload.get("applied", False)),
        )


@dataclass(frozen=True)
class ExperimentManifest:
    """One run: identity, lineage, ground truth, evidence and provenance."""

    state: ExperimentState
    ipsec: IpsecGroundTruth = field(default_factory=IpsecGroundTruth)
    network: NetworkCondition = field(default_factory=NetworkCondition)
    capture: CaptureEvidence | None = None
    environment: Mapping[str, Any] = field(default_factory=dict)
    countermeasure: Mapping[str, Any] = field(default_factory=dict)
    privacy_provenance: str = ""
    traffic_class: str = TrafficClass.WEB.value
    generated_at: str = ""
    notes: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        """Terminal status derived from the state, never asserted separately."""
        if self.state.stage is Stage.FAILED:
            return STATUS_INVALID
        if self.state.stage is Stage.BLOCKED:
            return STATUS_BLOCKED
        if self.state.real_ipsec_verified and self.capture is not None:
            if self.capture.supports_esp_gate:
                return STATUS_VALID
            # Gates and capture disagree: refuse to call this VALID.
            return STATUS_INCOMPLETE
        return STATUS_INCOMPLETE

    def validate(self) -> None:
        """Refuse a manifest whose gates overstate its evidence.

        This is the consistency check that stops a run from being written as
        ``VALID`` on the strength of gates alone while its capture shows no ESP.
        """
        if self.state.stage is Stage.FAILED:
            return
        if self.state.real_ipsec_verified and self.capture is None:
            raise _manifest_error(
                "the run claims every evidence gate but carries no capture",
                experiment_id=self.state.experiment_id,
            )
        if (
            self.capture is not None
            and self.state.gates.get("esp_verified")
            and not self.capture.supports_esp_gate
        ):
            raise _manifest_error(
                "the esp_verified gate is set but the capture does not evidence ESP",
                experiment_id=self.state.experiment_id,
                capture_status=self.capture.status,
                esp_detected=self.capture.esp_detected,
            )
        unknown = set(self.state.gates) - set(EVIDENCE_GATES)
        if unknown:  # pragma: no cover - ExperimentState rejects these already
            raise _manifest_error("unknown evidence gate", gates=sorted(unknown))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": MANIFEST_SCHEMA,
            "status": self.status,
            "experiment_id": self.state.experiment_id,
            "session_id": self.state.session_id,
            "configuration_id": self.state.configuration_id,
            "repeat_id": int(self.state.repeat_id),
            "traffic_class": self.traffic_class,
            "stage": self.state.stage.value,
            "lineage": {
                "experiment_id": self.state.experiment_id,
                "session_id": self.state.session_id,
                "configuration_id": self.state.configuration_id,
                "repeat_id": int(self.state.repeat_id),
            },
            "ipsec": self.ipsec.to_dict(),
            "network": self.network.to_dict(),
            "environment": dict(self.environment),
            "capture": self.capture.to_dict() if self.capture is not None else None,
            "evidence_gates": dict(self.state.gates),
            "real_ipsec_verified": self.state.real_ipsec_verified,
            "dataset_eligible": self.state.dataset_eligible,
            "countermeasure": dict(self.countermeasure),
            "privacy_provenance": self.privacy_provenance,
            "failure_reason": self.state.failure_reason,
            "notes": list(self.notes),
            "generated_at": self.generated_at or _utc_now(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ExperimentManifest:
        capture = payload.get("capture")
        capture_payload = payload.get("capture")
        capture = None
        if isinstance(capture_payload, Mapping):
            # to_dict() adds derived keys the dataclass does not own; rebuild
            # from the fields it actually holds rather than splatting the document.
            capture = CaptureEvidence(
                **{
                    name: capture_payload[name]
                    for name in CAPTURE_EVIDENCE_FIELDS
                    if name in capture_payload
                }
            )
        return cls(
            state=ExperimentState.from_dict(payload),
            ipsec=IpsecGroundTruth.from_dict(payload.get("ipsec") or {}),
            network=NetworkCondition.from_dict(payload.get("network") or {}),
            capture=capture,
            environment=dict(payload.get("environment") or {}),
            countermeasure=dict(payload.get("countermeasure") or {}),
            privacy_provenance=str(payload.get("privacy_provenance") or ""),
            traffic_class=str(payload.get("traffic_class") or TrafficClass.WEB.value),
            generated_at=str(payload.get("generated_at") or ""),
            notes=tuple(str(item) for item in (payload.get("notes") or ())),
        )


__all__ = [
    "MANIFEST_SCHEMA",
    "MANIFEST_STATUSES",
    "STATUS_BLOCKED",
    "STATUS_INCOMPLETE",
    "STATUS_INVALID",
    "STATUS_VALID",
    "ExperimentManifest",
    "IpsecGroundTruth",
    "NetworkCondition",
]
