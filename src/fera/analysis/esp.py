"""ESP flow correlation (SPI grouping and sequence tracking)."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from .provenance import EvidenceKind

ESP_HEADER_LEN = 8


@dataclass(frozen=True)
class EspPacketRecord:
    """One decoded ESP header (SPI + sequence number only)."""

    frame_index: int
    spi: str
    spi_int: int
    sequence_number: int
    src: str = ""
    dst: str = ""
    length: int = 0
    udp_encapsulated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "frame_index": self.frame_index,
            "spi": self.spi,
            "spi_int": self.spi_int,
            "sequence_number": self.sequence_number,
            "src": self.src,
            "dst": self.dst,
            "length": self.length,
            "udp_encapsulated": self.udp_encapsulated,
        }


@dataclass(frozen=True)
class EspFlowRecord:
    """All packets sharing one SPI."""

    spi: str
    packets: int
    bytes_total: int
    src: str = ""
    dst: str = ""
    first_frame: int = 0
    last_frame: int = 0
    sequence_numbers: tuple[int, ...] = ()
    udp_encapsulated: bool = False
    sequence_gaps: int = 0
    sequence_replays: int = 0
    sequence_monotonic: bool = True
    encapsulation: str = "unknown"
    encapsulation_kind: str = EvidenceKind.NOT_VERIFIABLE.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "spi": self.spi,
            "packets": self.packets,
            "bytes_total": self.bytes_total,
            "src": self.src,
            "dst": self.dst,
            "first_frame": self.first_frame,
            "last_frame": self.last_frame,
            "sequence_numbers": list(self.sequence_numbers),
            "udp_encapsulated": self.udp_encapsulated,
            "sequence_gaps": self.sequence_gaps,
            "sequence_replays": self.sequence_replays,
            "sequence_monotonic": self.sequence_monotonic,
            "encapsulation": self.encapsulation,
            "encapsulation_kind": self.encapsulation_kind,
        }


def parse_esp_header(frame_index: int, ip_payload: bytes, **kw: Any) -> EspPacketRecord | None:
    """Parse 8-byte ESP header; None when too short."""
    if len(ip_payload) < ESP_HEADER_LEN:
        return None
    spi_int = struct.unpack_from("!I", ip_payload, 0)[0]
    seq = struct.unpack_from("!I", ip_payload, 4)[0]
    return EspPacketRecord(
        frame_index=frame_index,
        spi=f"{spi_int:08x}",
        spi_int=spi_int,
        sequence_number=seq,
        src=str(kw.get("src", "")),
        dst=str(kw.get("dst", "")),
        length=int(kw.get("length", 0)),
        udp_encapsulated=bool(kw.get("udp_encapsulated", False)),
    )


def _seq_stats(seqs: list[int]) -> tuple[int, int, bool]:
    gaps = 0
    replays = 0
    mono = True
    seen: set[int] = set()
    prev: int | None = None
    for value in seqs:
        if value in seen:
            replays += 1
        seen.add(value)
        if prev is not None:
            if value < prev:
                mono = False
            elif value > prev + 1:
                gaps += value - prev - 1
        prev = value
    return gaps, replays, mono


def summarise_esp_flows(packets: list[EspPacketRecord]) -> list[EspFlowRecord]:
    """Group ESP packets by SPI in deterministic order."""
    grouped: dict[str, list[EspPacketRecord]] = {}
    for packet in packets:
        grouped.setdefault(packet.spi, []).append(packet)
    flows: list[EspFlowRecord] = []
    for spi in sorted(grouped):
        members = sorted(grouped[spi], key=lambda item: item.frame_index)
        seqs = [item.sequence_number for item in members]
        gaps, replays, mono = _seq_stats(seqs)
        udp = any(item.udp_encapsulated for item in members)
        if udp:
            enc, kind = "esp-in-udp", EvidenceKind.OBSERVED
        else:
            enc, kind = "unknown", EvidenceKind.NOT_VERIFIABLE
        first = members[0]
        flows.append(
            EspFlowRecord(
                spi=spi,
                packets=len(members),
                bytes_total=sum(item.length for item in members),
                src=first.src,
                dst=first.dst,
                first_frame=first.frame_index,
                last_frame=members[-1].frame_index,
                sequence_numbers=tuple(seqs),
                udp_encapsulated=udp,
                sequence_gaps=gaps,
                sequence_replays=replays,
                sequence_monotonic=mono,
                encapsulation=enc,
                encapsulation_kind=kind.value,
            )
        )
    return flows


__all__ = ["ESP_HEADER_LEN", "EspFlowRecord", "EspPacketRecord", "parse_esp_header", "summarise_esp_flows"]
