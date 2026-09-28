"""Evidence provenance tracking for protocol analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class EvidenceKind(str, Enum):
    """Provenance category for an analytical finding."""

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"


@dataclass(frozen=True)
class Evidence(Generic[T]):
    """A typed value paired with its observational provenance."""

    value: T
    kind: EvidenceKind
    source: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "kind": self.kind.value,
            "source": self.source,
            "details": self.details,
        }

    @classmethod
    def observed(cls, value: T, source: str, **details: Any) -> Evidence[T]:
        return cls(value=value, kind=EvidenceKind.OBSERVED, source=source, details=details)

    @classmethod
    def inferred(cls, value: T, source: str, **details: Any) -> Evidence[T]:
        return cls(value=value, kind=EvidenceKind.INFERRED, source=source, details=details)

    @classmethod
    def not_verifiable(cls, value: T, source: str, **details: Any) -> Evidence[T]:
        return cls(value=value, kind=EvidenceKind.NOT_VERIFIABLE, source=source, details=details)


__all__ = [
    "Evidence",
    "EvidenceKind",
]
