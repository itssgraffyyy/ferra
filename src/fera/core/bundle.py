"""``fera_analysis_bundle_v1``: the single document every product surface reads.

The bundle is the *only* contract between the Python pipeline and the product
surfaces (REST API, dashboard, reports, CLI).  It exists so that no consumer
has to know that four independently built stages sit behind it, and so that a
partially available pipeline is expressed honestly instead of being hidden:

* every stage owns a :class:`StageResult` with its own status and error, so one
  broken stage can never corrupt the components that did succeed;
* ``status`` of the whole bundle is derived, never set by hand;
* the bundle is pure JSON data (``to_dict`` / ``from_dict`` round-trip), which
  is what makes it storable in the history database and replayable in the UI.

Ground truth is not part of this schema and never will be: the bundle records
what was observed on the wire, not what the experiment author intended.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..common.errors import ErrorCode, FeraError
from ..common.serialization import write_json

#: Schema identifier of the serialised bundle.  Bumped only on incompatible change.
BUNDLE_SCHEMA_VERSION = "fera_analysis_bundle_v1"

#: Component names in the order the pipeline runs them.
STAGE_ORDER: tuple[str, ...] = ("protocol", "traffic", "security", "privacy")

#: Components without which the bundle has no value to show.
REQUIRED_COMPONENTS: tuple[str, ...] = ("protocol",)


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string (second precision)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path | str, *, chunk_size: int = 1 << 20) -> str:
    """Return the streaming SHA-256 of a file (captures can be large)."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class StageStatus(str, Enum):
    """How much of one component actually ran."""

    OK = "ok"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    SKIPPED = "skipped"

    @property
    def produced_data(self) -> bool:
        """Whether a consumer may read this component's payload."""
        return self in (StageStatus.OK, StageStatus.PARTIAL)


@dataclass(frozen=True)
class StageResult:
    """Outcome of one pipeline component.

    ``error`` carries the serialised :class:`~fera.common.errors.FeraError`
    (code, message, hint, details) whenever the component did not fully
    succeed, which keeps the reason for a degraded result inside the data model
    instead of a log file nobody reads.
    """

    component: str
    status: StageStatus
    data: Any = None
    error: dict[str, Any] | None = None
    duration_ms: int = 0
    limitations: tuple[str, ...] = ()

    @property
    def available(self) -> bool:
        """Whether :attr:`data` holds usable output."""
        return self.status.produced_data and self.data is not None

    @classmethod
    def succeeded(
        cls,
        component: str,
        data: Any,
        *,
        duration_ms: int = 0,
        limitations: tuple[str, ...] = (),
    ) -> StageResult:
        """Component ran and produced a full result."""
        return cls(component, StageStatus.OK, data=data, duration_ms=duration_ms, limitations=limitations)

    @classmethod
    def degraded(cls, component: str, data: Any, *, reason: str, duration_ms: int = 0) -> StageResult:
        """Component produced output, with a caveat the UI must show."""
        return cls(component, StageStatus.PARTIAL, data=data, duration_ms=duration_ms, limitations=(reason,))

    @classmethod
    def unavailable(
        cls,
        component: str,
        error: FeraError | str,
        *,
        data: Any = None,
        duration_ms: int = 0,
    ) -> StageResult:
        """Component could not run here (missing model, tool, privilege ...).

        This is a *reported environment state*, not a pipeline bug: the API
        renders it as "unavailable" while the rest of the bundle stays valid.
        """
        payload = (
            error.to_dict()
            if isinstance(error, FeraError)
            else {"code": ErrorCode.UNAVAILABLE.value, "message": str(error), "hint": None, "details": {}}
        )
        return cls(component, StageStatus.UNAVAILABLE, data=data, error=payload, duration_ms=duration_ms)

    @classmethod
    def failed(cls, component: str, error: FeraError | Exception | str, *, duration_ms: int = 0) -> StageResult:
        """Component raised: recorded verbatim, other components unaffected."""
        if isinstance(error, FeraError):
            payload = error.to_dict()
        elif isinstance(error, Exception):
            payload = {
                "code": ErrorCode.INTERNAL_ERROR.value,
                "message": f"{type(error).__name__}: {error}",
                "hint": None,
                "details": {},
            }
        else:
            payload = {"code": ErrorCode.INTERNAL_ERROR.value, "message": str(error), "hint": None, "details": {}}
        return cls(component, StageStatus.FAILED, error=payload, duration_ms=duration_ms)

    @classmethod
    def skipped(cls, component: str, *, reason: str) -> StageResult:
        """Component was not attempted (an upstream stage was unusable)."""
        return cls(
            component,
            StageStatus.SKIPPED,
            error={"code": "SKIPPED", "message": reason, "hint": None, "details": {}},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "status": self.status.value,
            "available": self.available,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "limitations": list(self.limitations),
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> StageResult:
        status_raw = str(document.get("status", StageStatus.FAILED.value))
        try:
            status = StageStatus(status_raw)
        except ValueError:
            status = StageStatus.FAILED
        error = document.get("error")
        return cls(
            component=str(document.get("component", "")),
            status=status,
            data=document.get("data"),
            error=dict(error) if isinstance(error, Mapping) else None,
            duration_ms=int(document.get("duration_ms", 0) or 0),
            limitations=tuple(str(item) for item in (document.get("limitations") or ())),
        )


def overall_status(stages: Mapping[str, StageResult]) -> str:
    """Derive the bundle status from component statuses.

    Rules, in order: a required component without data fails the bundle;
    all-ok is ``ok``; nothing usable is ``failed``; anything else is
    ``partial`` - the product must show what worked *and* what did not.
    """
    if not stages:
        return "failed"
    for name in REQUIRED_COMPONENTS:
        stage = stages.get(name)
        if stage is None or not stage.available:
            return "failed"
    statuses = [stage.status for stage in stages.values()]
    if all(item is StageStatus.OK for item in statuses):
        return "ok"
    if not any(item.produced_data for item in statuses):
        return "failed"
    return "partial"


@dataclass
class AnalysisBundle:
    """Everything one capture produced across protocol, ML, security, privacy."""

    analysis_id: str
    created_at: str
    source: dict[str, Any] = field(default_factory=dict)
    stages: dict[str, StageResult] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)
    schema_version: str = BUNDLE_SCHEMA_VERSION

    @classmethod
    def new(cls, source: Mapping[str, Any], *, provenance: Mapping[str, Any] | None = None) -> AnalysisBundle:
        """Create an empty bundle with a fresh identifier and timestamp."""
        return cls(
            analysis_id=uuid4().hex,
            created_at=utc_now(),
            source=dict(source),
            provenance=dict(provenance or {}),
        )

    # -- component access ------------------------------------------------ #
    def set_stage(self, result: StageResult) -> None:
        """Attach (or replace) one component result."""
        self.stages[result.component] = result

    def stage(self, component: str) -> StageResult | None:
        return self.stages.get(component)

    def component(self, component: str) -> Any:
        """Payload of a component, or ``None`` when it is not usable."""
        stage = self.stages.get(component)
        return stage.data if stage is not None and stage.available else None

    @property
    def protocol(self) -> Any:
        return self.component("protocol")

    @property
    def traffic(self) -> Any:
        return self.component("traffic")

    @property
    def security(self) -> Any:
        return self.component("security")

    @property
    def privacy(self) -> Any:
        return self.component("privacy")

    @property
    def status(self) -> str:
        return overall_status(self.stages)

    @property
    def source_path(self) -> Path | None:
        """Filesystem location of the capture, when the source records one."""
        raw = self.source.get("path")
        return Path(str(raw)) if raw else None

    @property
    def limitations(self) -> list[str]:
        """Every caveat, in stage order, prefixed with its component name."""
        notes: list[str] = []
        for name in STAGE_ORDER:
            stage = self.stages.get(name)
            if stage is None:
                continue
            for note in stage.limitations:
                notes.append(f"{name}: {note}")
            if stage.error and not stage.available:
                message = str(stage.error.get("message") or stage.status.value)
                notes.append(f"{name}: {stage.status.value} ({message})")
        return notes


    # -- serialisation --------------------------------------------------- #
    def to_dict(self) -> dict[str, Any]:
        ordered = {name: self.stages[name].to_dict() for name in STAGE_ORDER if name in self.stages}
        for name, stage in sorted(self.stages.items()):
            ordered.setdefault(name, stage.to_dict())
        return {
            "schema_version": self.schema_version,
            "analysis_id": self.analysis_id,
            "created_at": self.created_at,
            "status": self.status,
            "source": dict(self.source),
            "components": ordered,
            "limitations": self.limitations,
            "provenance": dict(self.provenance),
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> AnalysisBundle:
        schema = str(document.get("schema_version", BUNDLE_SCHEMA_VERSION))
        components = document.get("components") or {}
        if not isinstance(components, Mapping):
            raise FeraError(
                "bundle components must be an object",
                code=ErrorCode.CONFIG_VALIDATION_FAILED,
                details={"schema_version": schema},
            )
        stages: dict[str, StageResult] = {}
        for name, payload in components.items():
            if isinstance(payload, Mapping):
                stages[str(name)] = StageResult.from_dict(payload)
        return cls(
            analysis_id=str(document.get("analysis_id", "")),
            created_at=str(document.get("created_at", "")),
            source=dict(document.get("source") or {}),
            stages=stages,
            provenance=dict(document.get("provenance") or {}),
            schema_version=schema,
        )

    def write_json(self, path: Path | str) -> Path:
        """Persist the full bundle as JSON (the report/export building block)."""
        return write_json(path, self.to_dict())


    # -- compact views --------------------------------------------------- #
    def summary(self) -> dict[str, Any]:
        """Row shape used by history lists and the dashboard table."""
        protocol = self.protocol if isinstance(self.protocol, Mapping) else None
        traffic = self.traffic if isinstance(self.traffic, Mapping) else None
        security = self.security if isinstance(self.security, Mapping) else None
        privacy = self.privacy if isinstance(self.privacy, Mapping) else None
        pfs_doc = protocol.get("pfs") if protocol is not None and isinstance(protocol.get("pfs"), Mapping) else {}
        return {
            "analysis_id": self.analysis_id,
            "created_at": self.created_at,
            "status": self.status,
            "schema_version": self.schema_version,
            "source": dict(self.source),
            "component_status": {name: stage.status.value for name, stage in sorted(self.stages.items())},
            "protocol": None
            if protocol is None
            else {
                "packets": protocol.get("packets"),
                "ike_packets": protocol.get("ike_packets"),
                "esp_packets": protocol.get("esp_packets"),
                "esp_flows": len(protocol.get("esp_flows") or ()),
                "ike_exchanges": len(protocol.get("ike_exchanges") or ()),
                "pfs_status": pfs_doc.get("status"),
            },
            "traffic": None
            if traffic is None
            else {
                "predicted_class": traffic.get("predicted_class"),
                "confidence": traffic.get("confidence"),
                "model_id": traffic.get("model_id"),
            },
            "security": None
            if security is None
            else {
                "security_score": security.get("security_score"),
                "risk_level": security.get("risk_level"),
                "evidence_coverage": security.get("evidence_coverage"),
                "findings": len(security.get("findings") or ()),
            },
            "privacy": None
            if privacy is None
            else {
                "privacy_risk": privacy.get("privacy_risk"),
                "top_observable": privacy.get("top_observable"),
            },
        }


def describe_capture(path: Path | str, *, kind: str = "upload", captured_at: str | None = None) -> dict[str, Any]:
    """Build the ``source`` block of a bundle for one capture file."""
    capture = Path(path)
    exists = capture.is_file()
    return {
        "kind": kind,
        "filename": capture.name,
        "path": str(capture),
        "size_bytes": capture.stat().st_size if exists else 0,
        "sha256": sha256_file(capture) if exists else None,
        "captured_at": captured_at,
    }


__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "REQUIRED_COMPONENTS",
    "STAGE_ORDER",
    "AnalysisBundle",
    "StageResult",
    "StageStatus",
    "describe_capture",
    "overall_status",
    "sha256_file",
    "utc_now",
]

