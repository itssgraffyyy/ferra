"""Evidence grading for the security assessment stage.

The assessment stage inherits the provenance vocabulary of the deterministic
protocol analysis (:class:`fera.analysis.provenance.EvidenceKind`) and extends
it with one additional, deliberately separate category:

* ``OBSERVED``        - the property is present in clear text in the capture
  (an IKE SA payload, an ESP header, a sequence number).
* ``CONFIGURED``      - the property comes from the *testbed* definition of the
  run, not from the wire.  It is trustworthy for questions about what was
  configured, and it must never be presented as an observation.
* ``INFERRED``        - the property was produced by the ML stage; it carries a
  model confidence and is always labelled as model-derived downstream.
* ``NOT_VERIFIABLE``  - a passive capture cannot prove the property at all
  (e.g. whether the receiver actually enforces anti-replay).

The split between ``OBSERVED`` and ``CONFIGURED`` is the reason Prompt 4 has
its own enum: Prompt 2 only ever describes what a capture shows, while a
security assessment also consumes operator supplied configuration.  Keeping the
two apart is what stops "the testbed configured PFS" from being reported as
"PFS was observed on the wire".
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..analysis.provenance import EvidenceKind


class EvidenceStatus(str, Enum):
    """Provenance of one assessed security property."""

    OBSERVED = "OBSERVED"
    CONFIGURED = "CONFIGURED"
    INFERRED = "INFERRED"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"

    @property
    def rank(self) -> int:
        """Position in the evidence hierarchy (0 is the strongest)."""
        return EVIDENCE_RANK[self]

    @property
    def contributes_to_score(self) -> bool:
        """Whether a verdict based on this evidence may change the score.

        ``NOT_VERIFIABLE`` never does: absence of evidence must not look like
        either a strength or a weakness.
        """
        return self is not EvidenceStatus.NOT_VERIFIABLE


#: Strongest first.  Single source of truth for the evidence hierarchy that the
#: whole :mod:`fera.security` package applies.
EVIDENCE_PRECEDENCE: tuple[EvidenceStatus, ...] = (
    EvidenceStatus.OBSERVED,
    EvidenceStatus.CONFIGURED,
    EvidenceStatus.INFERRED,
    EvidenceStatus.NOT_VERIFIABLE,
)

#: ``status -> precedence index`` (derived, never hand-edited).
EVIDENCE_RANK: dict[EvidenceStatus, int] = {status: index for index, status in enumerate(EVIDENCE_PRECEDENCE)}


def strongest(*statuses: EvidenceStatus | None) -> EvidenceStatus:
    """Return the strongest of ``statuses`` (``NOT_VERIFIABLE`` when empty)."""
    present = [status for status in statuses if status is not None]
    if not present:
        return EvidenceStatus.NOT_VERIFIABLE
    return min(present, key=lambda status: status.rank)


def status_from_evidence_kind(kind: EvidenceKind | str | None) -> EvidenceStatus:
    """Map Prompt 2 provenance onto the assessment vocabulary.

    Prompt 2 has no notion of ``CONFIGURED``; what it reports as ``OBSERVED``
    stays ``OBSERVED`` here and what it cannot prove stays ``NOT_VERIFIABLE``.
    Unknown values degrade to ``NOT_VERIFIABLE`` instead of being upgraded.
    """
    if kind is None:
        return EvidenceStatus.NOT_VERIFIABLE
    raw = kind.value if isinstance(kind, EvidenceKind) else str(kind).strip().upper()
    try:
        return EvidenceStatus(raw)
    except ValueError:
        return EvidenceStatus.NOT_VERIFIABLE



@dataclass(frozen=True)
class EvidenceRef:
    """One citable piece of evidence attached to a finding.

    ``source`` names where the evidence came from (``analysis.esp_flows``,
    ``testbed.experiment_config``, ``ml.inference``), ``detail`` states what was
    actually seen, and ``details`` carries the structured values a reader needs
    to verify the claim by hand.
    """

    status: EvidenceStatus
    source: str
    detail: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "source": self.source,
            "detail": self.detail,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> EvidenceRef:
        details = document.get("details")
        return cls(
            status=status_from_evidence_kind(document.get("status")),
            source=str(document.get("source", "")),
            detail=str(document.get("detail", "")),
            details=dict(details) if isinstance(details, Mapping) else {},
        )

    @classmethod
    def observed(cls, source: str, detail: str = "", **details: Any) -> EvidenceRef:
        return cls(EvidenceStatus.OBSERVED, source, detail, details)

    @classmethod
    def configured(cls, source: str, detail: str = "", **details: Any) -> EvidenceRef:
        return cls(EvidenceStatus.CONFIGURED, source, detail, details)

    @classmethod
    def inferred(cls, source: str, detail: str = "", **details: Any) -> EvidenceRef:
        return cls(EvidenceStatus.INFERRED, source, detail, details)

    @classmethod
    def not_verifiable(cls, source: str, detail: str = "", **details: Any) -> EvidenceRef:
        return cls(EvidenceStatus.NOT_VERIFIABLE, source, detail, details)


def count_evidence(refs: Iterable[EvidenceRef]) -> dict[str, int]:
    """Tally evidence references per status (always all four keys, §28)."""
    counts = {status.value: 0 for status in EVIDENCE_PRECEDENCE}
    for ref in refs:
        counts[ref.status.value] += 1
    return counts


__all__ = [
    "EVIDENCE_PRECEDENCE",
    "EVIDENCE_RANK",
    "EvidenceRef",
    "EvidenceStatus",
    "count_evidence",
    "status_from_evidence_kind",
    "strongest",
]
