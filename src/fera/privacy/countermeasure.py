"""Traffic-shaping countermeasures and their provenance.

A *countermeasure* here is anything that changes what a passive observer can
measure.  The interface is deliberately narrow so that a future TFC
implementation, a dummy-traffic generator, a timing shaper or an IP-TFS model
can be added without the privacy experiment pipeline being rewritten around the
one mechanism that happens to exist today.

The single most important property of this module is **provenance**.

A packet-size transformation applied in software is *not* the same thing as a
packet-size transformation performed by a real IPsec implementation on the
wire.  One approximates the other; only the other is evidence about a deployed
system.  Conflating them would let a fixture produce the appearance of a
validated mitigation, which is precisely the failure this module exists to
prevent.  :class:`CountermeasureProvenance` encodes that distinction and
:func:`assert_provenance_permits_claims` fails closed when a document claims
testbed verification without the evidence to support it.

What is *not* claimed here:

* that padding eliminates traffic-analysis leakage - it removes at most the size
  component, and timing and direction remain;
* that RFC 4303 Traffic Flow Confidentiality (TFC) has been implemented or
  deployed.  The simulated mechanism below approximates one *aspect* of the
  padding problem.  It is not TFC, and no document it produces may be read as a
  TFC conformance claim.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..common.errors import ErrorCode, FeraError

#: Schema identifier of one countermeasure provenance document.
COUNTERMEASURE_SCHEMA = "fera_privacy_countermeasure_v1"

#: The transformation was applied in software to data FERA already had.  It is a
#: methodology probe or a counterfactual, NOT evidence about a deployed system.
SIMULATED = "SIMULATED_COUNTERMEASURE"

#: The transformation was declared by a trusted testbed configuration but no
#: capture demonstrates it on the wire.
CONFIGURED_NOT_VERIFIED = "CONFIGURED_NOT_VERIFIED"

#: The transformation was genuinely applied in a real testbed and the resulting
#: traffic was observed and verified.  Only a real experiment may set this.
TESTBED_VERIFIED = "TESTBED_VERIFIED_COUNTERMEASURE"

PROVENANCE_STATES: tuple[str, ...] = (SIMULATED, CONFIGURED_NOT_VERIFIED, TESTBED_VERIFIED)

#: Only this state may appear in a document that claims experimental evidence.
EXPERIMENTAL_PROVENANCE = TESTBED_VERIFIED

#: Value used for every cost dimension that no measurement supports.  Deliberately
#: a string rather than 0.0 or None, so a reader cannot mistake "not measured"
#: for "measured as zero".
NOT_MEASURED = "NOT_MEASURED"


def _countermeasure_error(message: str, **details: Any) -> FeraError:
    return FeraError(
        message,
        code=ErrorCode.CONFIG_VALIDATION_FAILED,
        hint="see docs/privacy_intelligence.md for the countermeasure contract",
        details=details,
    )


@dataclass(frozen=True)
class CountermeasureProvenance:
    """How a countermeasure reached the data, and what that permits claiming.

    ``evidence_capture`` is the machine-checkable part: a document may only claim
    :data:`TESTBED_VERIFIED` when it names a real capture that demonstrated the
    transformation.  :func:`assert_provenance_permits_claims` enforces this, so a
    fixture run cannot quietly present itself as a validated mitigation.
    """

    state: str = SIMULATED
    #: Path of a capture that demonstrated the countermeasure on the wire.
    evidence_capture: str | None = None
    #: SHA-256 of that capture, so the evidence is addressable rather than claimed.
    evidence_sha256: str | None = None
    #: Identifier of the testbed/configuration that applied it.
    testbed_id: str | None = None
    reason: str = ""
    notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.state not in PROVENANCE_STATES:
            raise _countermeasure_error(
                f"unknown countermeasure provenance: {self.state}",
                available=list(PROVENANCE_STATES),
            )
        if self.state == TESTBED_VERIFIED and not self.evidence_capture:
            raise _countermeasure_error(
                "testbed verification requires a capture demonstrating the countermeasure",
                state=self.state,
            )

    @property
    def is_simulated(self) -> bool:
        return self.state == SIMULATED

    @property
    def permits_experimental_claims(self) -> bool:
        """Whether documents built on this may be called experimental evidence."""
        return self.state == EXPERIMENTAL_PROVENANCE

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": COUNTERMEASURE_SCHEMA,
            "state": self.state,
            "evidence_capture": self.evidence_capture,
            "evidence_sha256": self.evidence_sha256,
            "testbed_id": self.testbed_id,
            "reason": self.reason,
            "permits_experimental_claims": self.permits_experimental_claims,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CountermeasureProvenance:
        return cls(
            state=str(payload.get("state") or SIMULATED),
            evidence_capture=(
                str(payload["evidence_capture"]) if payload.get("evidence_capture") else None
            ),
            evidence_sha256=(
                str(payload["evidence_sha256"]) if payload.get("evidence_sha256") else None
            ),
            testbed_id=(str(payload["testbed_id"]) if payload.get("testbed_id") else None),
            reason=str(payload.get("reason") or ""),
            notes=tuple(str(item) for item in (payload.get("notes") or ())),
        )


def assert_provenance_permits_claims(
    provenance: CountermeasureProvenance,
    *,
    claiming_experimental: bool,
) -> None:
    """Refuse an experimental claim the provenance does not support.

    This is the machine-checkable guard behind "never automatically upgrade
    simulated to verified".  The current Windows host cannot satisfy it, and no
    amount of fixture execution changes that.
    """
    if claiming_experimental and not provenance.permits_experimental_claims:
        raise _countermeasure_error(
            "a simulated countermeasure cannot be reported as experimental evidence",
            provenance=provenance.state,
            permits_experimental_claims=provenance.permits_experimental_claims,
        )


#: How a countermeasure maps an original length onto a transmitted length.
SIZE_MODES: tuple[str, ...] = ("fixed", "bucket")


@dataclass(frozen=True)
class SizeNormalizationParameters:
    """Configuration of the simulated size-normalization mechanism.

    ``mode='fixed'`` pads every packet up to ``target_size``.  ``mode='bucket'``
    rounds each packet up to the next multiple of ``bucket_size`` - a weaker
    mechanism that leaks far less than the original distribution but is not
    constant-size, and is therefore a more realistic thing to evaluate.

    Both are deterministic functions of the input, which is what makes the
    resulting dataset reproducible and the comparison fair.
    """

    mode: str = "bucket"
    target_size: int = 1400
    bucket_size: int = 256
    #: Packets at or above this size are transmitted unchanged - padding them
    #: would be a lie, since ESP cannot shrink a datagram.
    max_pad_size: int = 1400

    def __post_init__(self) -> None:
        if self.mode not in SIZE_MODES:
            raise _countermeasure_error(
                f"unknown size-normalization mode: {self.mode}",
                available=list(SIZE_MODES),
            )
        for name in ("target_size", "bucket_size", "max_pad_size"):
            value = int(getattr(self, name))
            if value <= 0:
                raise _countermeasure_error(
                    f"{name} must be a positive number of bytes (got {value})", field=name
                )
        if self.mode == "bucket" and self.bucket_size <= 1:
            raise _countermeasure_error(
                "bucket_size must exceed 1 byte, otherwise every packet is unchanged",
                bucket_size=self.bucket_size,
            )
        if self.mode == "fixed" and self.target_size < self.max_pad_size:
            raise _countermeasure_error(
                "fixed mode with target_size below max_pad_size would leave large packets "
                "unpadded while claiming a constant size",
                target_size=self.target_size,
                max_pad_size=self.max_pad_size,
            )

    def transmit_length(self, original: int) -> int:
        """Transmitted length for one packet.  Never shrinks the payload."""
        if original <= 0:
            raise _countermeasure_error(
                "packet length must be positive", length=original
            )
        if original >= self.max_pad_size:
            return original
        if self.mode == "fixed":
            return int(self.target_size)
        padded = -(-original // int(self.bucket_size)) * int(self.bucket_size)
        return int(padded)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "target_size": int(self.target_size),
            "bucket_size": int(self.bucket_size),
            "max_pad_size": int(self.max_pad_size),
        }


class PrivacyCountermeasure(ABC):
    """A transformation an observer's traffic would undergo if it were mitigated.

    Deliberately abstract over *what* is mitigated.  The privacy experiment
    pipeline talks to this interface only, so adding a real TFC implementation
    later means adding a subclass rather than restructuring the experiment.
    """

    #: Stable identifier recorded in every experiment document.
    name: str = "unnamed"

    @abstractmethod
    def describe(self) -> dict[str, Any]:
        """Machine-readable description of the mechanism and its parameters."""

    @abstractmethod
    def apply(self, rows: Sequence[Sequence[float]], features: Sequence[str]) -> list[list[float]]:
        """Return transformed feature rows.  Must be deterministic."""

    def overhead(self, rows: Sequence[Sequence[float]], features: Sequence[str]) -> dict[str, Any]:
        """Byte cost of applying this countermeasure to ``rows``."""
        raise _countermeasure_error(
            f"countermeasure {self.name} does not report overhead",
            countermeasure=self.name,
        )

    def provenance(self) -> CountermeasureProvenance:
        """How this countermeasure reached the data.

        A software transformation is :data:`SIMULATED` by construction.  Only a
        countermeasure backed by a real testbed run may override this.
        """
        return CountermeasureProvenance(
            state=SIMULATED,
            reason=f"{self.name} was applied in software to already-captured data",
        )
class SizeNormalizationCountermeasure(PrivacyCountermeasure):
    """Simulated packet-size normalisation over the ESP size feature family.

    Only the length columns named by the caller are rewritten; every other column
    is passed through **unchanged**, and labels, groups and split assignments are
    untouched because this class never sees them.  That is deliberate: a
    countermeasure must not be able to quietly alter the experiment's structure.

    What this models: an endpoint that pads outbound packets so their lengths
    carry less information about the inner traffic.

    What this does *not* model: ESP Traffic Flow Confidentiality, a real
    implementation's padding boundary behaviour, dummy traffic, or any timing
    effect.  It is a **counterfactual probe of the size channel only**, and every
    document it contributes to is stamped
    :data:`~fera.privacy.countermeasure.SIMULATED`.
    """

    name = "simulated_size_normalization"

    #: Feature columns this mechanism is defined over.  Taken from the Part 1
    #: family definition so the privacy analysis and the ablation cannot drift.
    SIZE_FEATURES: tuple[str, ...] = (
        "avg_packet_len",
        "esp_avg_len",
        "esp_len_min",
        "esp_len_max",
        "esp_len_std",
    )

    def __init__(self, parameters: SizeNormalizationParameters | None = None) -> None:
        self.parameters = parameters or SizeNormalizationParameters()

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": "packet_size_normalization",
            "parameters": self.parameters.to_dict(),
            "affected_features": list(self.SIZE_FEATURES),
            "models": (
                "an endpoint padding outbound packets so their lengths reveal less about the "
                "inner traffic"
            ),
            "does_not_model": [
                "RFC 4303 Traffic Flow Confidentiality (this is not TFC)",
                "a real implementation's padding boundary behaviour",
                "dummy traffic or cover packets",
                "any timing or direction effect",
            ],
            "provenance": self.provenance().to_dict(),
        }

    def apply(self, rows: Sequence[Sequence[float]], features: Sequence[str]) -> list[list[float]]:
        """Rewrite the size columns; pass everything else through verbatim."""
        index_of = {name: index for index, name in enumerate(features)}
        targets = [index_of[name] for name in self.SIZE_FEATURES if name in index_of]
        if not targets:
            raise _countermeasure_error(
                "none of the size features are present, so this countermeasure would be a no-op",
                available=list(features),
                expected=list(self.SIZE_FEATURES),
            )
        out: list[list[float]] = []
        for row in rows:
            if len(row) != len(features):
                raise _countermeasure_error(
                    "row width disagrees with the feature list",
                    expected=len(features),
                    actual=len(row),
                )
            new_row = list(row)
            for index in targets:
                new_row[index] = float(self.parameters.transmit_length(int(row[index])))
            out.append(new_row)
        return out

    def overhead(self, rows: Sequence[Sequence[float]], features: Sequence[str]) -> dict[str, Any]:
        """Byte cost of padding, measured on the mean ESP packet length.

        Only the byte-overhead component is computed.  Latency and throughput are
        deliberately left ``NOT_MEASURED``: inferring them from a byte count
        would be fabricating a measurement.
        """
        index_of = {name: index for index, name in enumerate(features)}
        key = "esp_avg_len"
        if key not in index_of:
            raise _countermeasure_error(
                f"overhead needs the {key} feature", available=list(features)
            )
        column = index_of[key]
        original = [float(row[column]) for row in rows]
        if not original:
            raise _countermeasure_error("overhead needs at least one row")
        transmitted = [float(self.parameters.transmit_length(int(value))) for value in original]
        original_bytes = int(round(sum(original)))
        transformed_bytes = int(round(sum(transmitted)))
        overhead = transformed_bytes - original_bytes
        return {
            "basis": f"mean {key} across {len(rows)} row(s)",
            "original_bytes": original_bytes,
            "transformed_bytes": transformed_bytes,
            "byte_overhead": overhead,
            "byte_overhead_percent": round(100.0 * overhead / original_bytes, 6)
            if original_bytes
            else 0.0,
            "mean_original_len": round(sum(original) / len(original), 6),
            "mean_transformed_len": round(sum(transmitted) / len(transmitted), 6),
            "latency": NOT_MEASURED,
            "throughput": NOT_MEASURED,
            "jitter": NOT_MEASURED,
        }


__all__ = [
    "CONFIGURED_NOT_VERIFIED",
    "COUNTERMEASURE_SCHEMA",
    "EXPERIMENTAL_PROVENANCE",
    "NOT_MEASURED",
    "PROVENANCE_STATES",
    "SIMULATED",
    "SIZE_MODES",
    "TESTBED_VERIFIED",
    "CountermeasureProvenance",
    "PrivacyCountermeasure",
    "SizeNormalizationCountermeasure",
    "SizeNormalizationParameters",
    "assert_provenance_permits_claims",
]
