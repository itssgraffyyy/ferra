"""IKE payload parsing and proposal normalisation.

Only clear-text SA payloads (IKE_SA_INIT / CREATE_CHILD_SA with an SA payload)
are interpreted.  Encrypted IKE_AUTH payloads are counted as present but never
fabricated into proposals -- see ``docs/ipsec_correctness.md`` section 6.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from ..common.logging_utils import get_logger
from .constants import (
    DH_GROUPS_IANA,
    ENCRYPTION_ALGORITHMS,
    INTEGRITY_ALGORITHMS,
    PRF_ALGORITHMS,
    PROTOCOL_AH,
    PROTOCOL_ESP,
    PROTOCOL_IKE,
    PROTOCOL_NAMES,
    IkeExchangeType,
    IkeTransformType,
)

logger = get_logger(__name__)

IKE_HEADER_LEN = 28
IKEV2_MAJOR = 2
IKEV1_MAJOR = 1
PAYLOAD_SA = 33
PAYLOAD_NONE = 0

#: IANA-assigned IKEv2 exchange types (RFC 7296 s3.10 and the IANA registry).
#: An exchange type outside this set means the bytes are not a real IKEv2
#: header - most often ESP-encrypted IKE arriving on UDP/4500, where the first
#: encrypted byte run can imitate the version/exchange-type nibbles.
_IKEV2_ASSIGNED_EXCHANGES = frozenset(range(34, 42))


def _u16(data: bytes, offset: int) -> int | None:
    if len(data) < offset + 2:
        return None
    return struct.unpack_from("!H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int | None:
    if len(data) < offset + 4:
        return None
    return struct.unpack_from("!I", data, offset)[0]


@dataclass(frozen=True)
class TransformRecord:
    """One IKE transform (type + id) with registry names attached."""

    transform_type: int
    transform_id: int
    type_name: str
    name: str
    key_bits: int | None = None
    aead: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "transform_type": self.transform_type,
            "type_name": self.type_name,
            "transform_id": self.transform_id,
            "name": self.name,
            "key_bits": self.key_bits,
            "aead": self.aead,
        }


@dataclass(frozen=True)
class ProposalRecord:
    """One SA proposal (protocol + SPI + transforms)."""

    proposal_number: int
    protocol_id: int
    protocol_name: str
    spi: str
    transforms: tuple[TransformRecord, ...] = ()
    dh_groups: tuple[int, ...] = ()
    encryption: tuple[str, ...] = ()
    integrity: tuple[str, ...] = ()
    prf: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_number": self.proposal_number,
            "protocol_id": self.protocol_id,
            "protocol_name": self.protocol_name,
            "spi": self.spi,
            "transforms": [item.to_dict() for item in self.transforms],
            "dh_groups": list(self.dh_groups),
            "encryption": list(self.encryption),
            "integrity": list(self.integrity),
            "prf": list(self.prf),
        }


@dataclass(frozen=True)
class IkeExchangeRecord:
    """One decoded IKE message with any inline SA proposals."""

    frame_index: int
    ike_version: int
    exchange_type: int
    exchange_name: str
    initiator: bool
    response: bool
    message_id: int
    initiator_spi: str
    responder_spi: str
    proposals: tuple[ProposalRecord, ...] = ()
    payload_types: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "frame_index": self.frame_index,
            "ike_version": self.ike_version,
            "exchange_type": self.exchange_type,
            "exchange_name": self.exchange_name,
            "initiator": self.initiator,
            "response": self.response,
            "message_id": self.message_id,
            "initiator_spi": self.initiator_spi,
            "responder_spi": self.responder_spi,
            "proposals": [item.to_dict() for item in self.proposals],
            "payload_types": list(self.payload_types),
        }


def describe_transform(transform_type: int, transform_id: int) -> TransformRecord:
    """Map numeric transform identifiers to registry names (never raises)."""
    try:
        type_name = IkeTransformType(transform_type).name
    except ValueError:
        type_name = f"UNKNOWN_TRANSFORM_TYPE_{transform_type}"
    if transform_type == IkeTransformType.ENCRYPTION_ALGORITHM:
        entry = ENCRYPTION_ALGORITHMS.get(transform_id, {})
        return TransformRecord(
            transform_type=transform_type,
            transform_id=transform_id,
            type_name=type_name,
            name=str(entry.get("name", f"ENCR_{transform_id}")),
            key_bits=entry.get("key_bits"),  # type: ignore[arg-type]
            aead=bool(entry.get("aead", False)),
        )
    if transform_type == IkeTransformType.PSEUDORANDOM_FUNCTION:
        return TransformRecord(
            transform_type=transform_type,
            transform_id=transform_id,
            type_name=type_name,
            name=PRF_ALGORITHMS.get(transform_id, f"PRF_{transform_id}"),
        )
    if transform_type == IkeTransformType.INTEGRITY_ALGORITHM:
        entry = INTEGRITY_ALGORITHMS.get(transform_id, {})
        return TransformRecord(
            transform_type=transform_type,
            transform_id=transform_id,
            type_name=type_name,
            name=str(entry.get("name", f"AUTH_{transform_id}")),
        )
    if transform_type == IkeTransformType.DIFFIE_HELLMAN_GROUP:
        entry = DH_GROUPS_IANA.get(transform_id, {})
        return TransformRecord(
            transform_type=transform_type,
            transform_id=transform_id,
            type_name=type_name,
            name=str(entry.get("name", f"DH_{transform_id}")),
            key_bits=entry.get("bits"),  # type: ignore[arg-type]
        )
    return TransformRecord(
        transform_type=transform_type,
        transform_id=transform_id,
        type_name=type_name,
        name=f"TRANSFORM_{transform_type}_{transform_id}",
    )


def _parse_transforms(payload: bytes) -> list[TransformRecord]:
    """Parse IKEv2 transform substructures (next/reserved/len/type/reserved/id)."""
    records: list[TransformRecord] = []
    offset = 0
    guard = 0
    while offset + 8 <= len(payload) and guard < 64:
        guard += 1
        total = _u16(payload, offset + 2)
        transform_type = payload[offset + 4]
        transform_id = _u16(payload, offset + 6)
        if transform_id is None:
            break
        records.append(describe_transform(transform_type, transform_id))
        if total is None or total < 8:
            offset += 8
        else:
            offset += total
    return records


def _parse_proposals(sa_body: bytes) -> list[ProposalRecord]:
    """Parse concatenated proposals inside one SA payload body."""
    proposals: list[ProposalRecord] = []
    offset = 0
    guard = 0
    while offset + 8 <= len(sa_body) and guard < 32:
        guard += 1
        length = _u16(sa_body, offset + 2)
        if length is None or length < 8 or offset + length > len(sa_body):
            break
        proposal_no = sa_body[offset + 4]
        protocol_id = sa_body[offset + 5]
        spi_size = sa_body[offset + 6]
        header_len = 8 + spi_size
        if header_len > length:
            break
        spi = sa_body[offset + 8 : offset + 8 + spi_size].hex() if spi_size else ""
        transforms = _parse_transforms(sa_body[offset + header_len : offset + length])
        dh = tuple(sorted({t.transform_id for t in transforms if t.transform_type == 4}))
        enc = tuple(t.name for t in transforms if t.transform_type == 1)
        integ = tuple(t.name for t in transforms if t.transform_type == 3)
        prf = tuple(t.name for t in transforms if t.transform_type == 2)
        proposals.append(
            ProposalRecord(
                proposal_number=proposal_no,
                protocol_id=protocol_id,
                protocol_name=PROTOCOL_NAMES.get(protocol_id, f"PROTO_{protocol_id}"),
                spi=spi,
                transforms=tuple(transforms),
                dh_groups=dh,
                encryption=enc,
                integrity=integ,
                prf=prf,
            )
        )
        offset += length
    return proposals


def _walk_payloads(first_type: int, body: bytes) -> tuple[tuple[int, ...], list[ProposalRecord]]:
    """Walk generic payload chain; collect SA proposals when present."""
    payloads: list[int] = []
    proposals: list[ProposalRecord] = []
    payload_type = first_type
    offset = 0
    guard = 0
    while payload_type != PAYLOAD_NONE and guard < 32:
        guard += 1
        if offset + 4 > len(body):
            break
        payloads.append(payload_type)
        next_payload = body[offset]
        length = _u16(body, offset + 2)
        if length is None or length < 4 or offset + length > len(body):
            break
        content = body[offset + 4 : offset + length]
        if payload_type == PAYLOAD_SA:
            proposals.extend(_parse_proposals(content))
        payload_type = next_payload
        offset += length
    return tuple(payloads), proposals


def parse_ike_message(frame_index: int, udp_payload: bytes) -> IkeExchangeRecord | None:
    """Parse one UDP payload as IKE; None when not parseable.

    A payload that merely *looks* like an IKEv2 header is not enough.  On
    UDP/4500 the bytes after the NON-ESP marker are usually ESP-encrypted, and
    any random 4-byte run has a 1-in-16 chance of carrying major version 2 in
    the right nibble.  Treating that as a decoded exchange invents a message id
    and an exchange type that never existed, so a real strongSwan capture
    reported fabricated ``UNKNOWN_EXCHANGE_177`` rows.

    Reject anything whose exchange type is not an IANA-assigned IKEv2 value
    (34-41) or which is an IKEv2 message with a non-zero responder SPI outside
    IKE_SA_INIT.  Returning None means "not decodable", which is honest.
    """
    if len(udp_payload) < IKE_HEADER_LEN:
        return None
    initiator_spi = udp_payload[0:8]
    responder_spi = udp_payload[8:16]
    next_payload = udp_payload[16]
    major = udp_payload[17] >> 4
    exchange_type = udp_payload[18]
    flags = udp_payload[19]
    message_id = _u32(udp_payload, 20)
    length = _u32(udp_payload, 24)
    if message_id is None or length is None:
        return None
    if major == IKEV2_MAJOR:
        if exchange_type not in _IKEV2_ASSIGNED_EXCHANGES:
            return None
        # RFC 7296: only IKE_SA_INIT carries a zero responder SPI.
        if exchange_type != int(IkeExchangeType.IKE_SA_INIT) and not any(responder_spi):
            return None
        exchange_name = IkeExchangeType.describe(exchange_type)
    elif major == IKEV1_MAJOR:
        exchange_name = f"IKEV1_EXCHANGE_{exchange_type}"
    else:
        return None
    if length >= IKE_HEADER_LEN and length <= len(udp_payload):
        body = udp_payload[IKE_HEADER_LEN:length]
    else:
        body = udp_payload[IKE_HEADER_LEN:]
    payload_types, proposals = _walk_payloads(next_payload, body)
    return IkeExchangeRecord(
        frame_index=frame_index,
        ike_version=major,
        exchange_type=exchange_type,
        exchange_name=exchange_name,
        initiator=bool(flags & 0x08),
        response=bool(flags & 0x20),
        message_id=message_id,
        initiator_spi=initiator_spi.hex(),
        responder_spi=responder_spi.hex(),
        proposals=tuple(proposals),
        payload_types=payload_types,
    )


@dataclass
class IkeSummary:
    """Aggregate view over decoded IKE messages."""

    exchanges: list[IkeExchangeRecord] = field(default_factory=list)
    proposals: list[ProposalRecord] = field(default_factory=list)

    def child_sa_dh_groups(self) -> list[int]:
        """Distinct DH groups in ESP/AH (CHILD_SA) proposals."""
        groups: set[int] = set()
        for proposal in self.proposals:
            if proposal.protocol_id in {PROTOCOL_ESP, PROTOCOL_AH}:
                groups.update(proposal.dh_groups)
        return sorted(groups)

    def ike_sa_dh_groups(self) -> list[int]:
        """Distinct DH groups in IKE proposals."""
        groups: set[int] = set()
        for proposal in self.proposals:
            if proposal.protocol_id == PROTOCOL_IKE:
                groups.update(proposal.dh_groups)
        return sorted(groups)


def summarise_ike(records: list[IkeExchangeRecord]) -> IkeSummary:
    """Collect proposals across exchanges (pure aggregation)."""
    summary = IkeSummary(exchanges=list(records))
    for record in records:
        summary.proposals.extend(record.proposals)
    return summary


__all__ = [
    "IKE_HEADER_LEN",
    "IkeExchangeRecord",
    "IkeSummary",
    "ProposalRecord",
    "TransformRecord",
    "describe_transform",
    "parse_ike_message",
    "summarise_ike",
]



