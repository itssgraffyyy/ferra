"""SA correlation: link IKE proposals to ESP flows; PFS verdict."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .constants import PROTOCOL_AH, PROTOCOL_ESP
from .esp import EspFlowRecord
from .ike import IkeExchangeRecord
from .models import PfsStatus
from .provenance import EvidenceKind


@dataclass(frozen=True)
class PfsAnalysis:
    """PFS verdict derived only from observed CHILD_SA proposals."""

    status: PfsStatus
    kind: EvidenceKind
    child_sa_dh_groups: tuple[int, ...] = ()
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "kind": self.kind.value,
            "child_sa_dh_groups": list(self.child_sa_dh_groups),
            "reason": self.reason,
        }


def correlate_sa(
    exchanges: list[IkeExchangeRecord],
    flows: list[EspFlowRecord],
) -> PfsAnalysis:
    """Decide PFS status from observed ESP/AH proposals only."""
    groups: set[int] = set()
    saw_child_proposal = False
    for exchange in exchanges:
        for proposal in exchange.proposals:
            if proposal.protocol_id in {PROTOCOL_ESP, PROTOCOL_AH}:
                saw_child_proposal = True
                groups.update(proposal.dh_groups)
    ordered = tuple(sorted(groups))
    if ordered:
        return PfsAnalysis(
            status=PfsStatus.OBSERVED,
            kind=EvidenceKind.OBSERVED,
            child_sa_dh_groups=ordered,
            reason=f"DH group(s) {list(ordered)} in CHILD_SA proposal",
        )
    if saw_child_proposal:
        return PfsAnalysis(
            status=PfsStatus.DISABLED,
            kind=EvidenceKind.OBSERVED,
            child_sa_dh_groups=(),
            reason="CHILD_SA proposals carry no DH group",
        )
    if flows:
        return PfsAnalysis(
            status=PfsStatus.NOT_VERIFIABLE,
            kind=EvidenceKind.NOT_VERIFIABLE,
            child_sa_dh_groups=(),
            reason="ESP seen but no CHILD_SA proposal in clear",
        )
    return PfsAnalysis(
        status=PfsStatus.NOT_VERIFIABLE,
        kind=EvidenceKind.NOT_VERIFIABLE,
        child_sa_dh_groups=(),
        reason="no CHILD_SA proposal observed",
    )


__all__ = ["PfsAnalysis", "correlate_sa"]
