"""Aggregate models for deterministic protocol analysis."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .provenance import EvidenceKind


class PfsStatus(str, Enum):
    """PFS verdict derived only from observed CHILD_SA proposals."""

    OBSERVED = "OBSERVED"
    DISABLED = "DISABLED"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"


@dataclass(frozen=True)
class ProtocolAnalysis:
    """Structured, evidence-graded observations from one capture."""

    pcap_path: Path
    method: str = "none"
    packets: int = 0
    ike_packets: int = 0
    esp_packets: int = 0
    ike_exchanges: tuple[Any, ...] = ()
    esp_flows: tuple[Any, ...] = ()
    pfs_status: PfsStatus = PfsStatus.NOT_VERIFIABLE
    pfs_kind: EvidenceKind = EvidenceKind.NOT_VERIFIABLE
    warnings: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        def _dump(value: Any) -> Any:
            to_dict = getattr(value, "to_dict", None)
            if callable(to_dict):
                return to_dict()
            if isinstance(value, Path):
                return str(value)
            if isinstance(value, Enum):
                return value.value
            return value

        return {
            "pcap_path": str(self.pcap_path),
            "method": self.method,
            "packets": self.packets,
            "ike_packets": self.ike_packets,
            "esp_packets": self.esp_packets,
            "ike_exchanges": [_dump(item) for item in self.ike_exchanges],
            "esp_flows": [_dump(item) for item in self.esp_flows],
            "pfs": {"status": self.pfs_status.value, "kind": self.pfs_kind.value},
            "warnings": list(self.warnings),
            "details": dict(self.details),
        }

    def render_text(self) -> str:
        lines = [
            f"Capture: {self.pcap_path}",
            f"Method: {self.method}",
            f"Packets: {self.packets}",
            f"IKE packets: {self.ike_packets}",
            f"ESP packets: {self.esp_packets}",
            f"PFS: {self.pfs_status.value} ({self.pfs_kind.value})",
        ]
        for warning in self.warnings:
            lines.append(f"Warning: {warning}")
        return "\n".join(lines)

    @classmethod
    def empty(cls, pcap_path: Path | str, *, method: str, warnings: tuple[str, ...] = ()) -> ProtocolAnalysis:
        return cls(pcap_path=Path(pcap_path), method=method, warnings=warnings)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> ProtocolAnalysis:
        pfs = document.get("pfs", {}) if isinstance(document.get("pfs"), Mapping) else {}
        status_raw = str(pfs.get("status", PfsStatus.NOT_VERIFIABLE.value))
        kind_raw = str(pfs.get("kind", EvidenceKind.NOT_VERIFIABLE.value))
        try:
            status = PfsStatus(status_raw)
        except ValueError:
            status = PfsStatus.NOT_VERIFIABLE
        try:
            kind = EvidenceKind(kind_raw)
        except ValueError:
            kind = EvidenceKind.NOT_VERIFIABLE
        details = document.get("details")
        return cls(
            pcap_path=Path(str(document.get("pcap_path", ""))),
            method=str(document.get("method", "none")),
            packets=int(document.get("packets", 0) or 0),
            ike_packets=int(document.get("ike_packets", 0) or 0),
            esp_packets=int(document.get("esp_packets", 0) or 0),
            ike_exchanges=tuple(document.get("ike_exchanges", ()) or ()),
            esp_flows=tuple(document.get("esp_flows", ()) or ()),
            pfs_status=status,
            pfs_kind=kind,
            warnings=tuple(document.get("warnings", ()) or ()),
            details=dict(details) if isinstance(details, Mapping) else {},
        )


__all__ = ["PfsStatus", "ProtocolAnalysis"]
