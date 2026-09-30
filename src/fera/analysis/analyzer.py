"""Top-level deterministic PCAP analyser."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..capture.pcap_scan import (
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    ETHERTYPE_QINQ,
    ETHERTYPE_VLAN,
    LINKTYPE_ETHERNET,
    LINKTYPE_RAW,
    _ipv6_payload_offset_and_protocol,
    scan_pcap,
)
from .esp import EspPacketRecord, parse_esp_header, summarise_esp_flows
from .ike import IkeExchangeRecord, parse_ike_message
from .models import ProtocolAnalysis
from .sa import correlate_sa

IKE_PORTS = {500, 4500}
IPPROTO_ESP = 50
IPPROTO_UDP = 17
IPPROTO_AH = 51

ETHERTYPE_VLAN_IP = ETHERTYPE_VLAN
ETHERTYPE_QINQ_IP = ETHERTYPE_QINQ

#: Fixed IPv6 header length (RFC 8200): 40 bytes, no IHL field and no options.
IPV6_HEADER_BYTES = 40


@dataclass
class AnalysisOutcome:
    """Result of analysing one capture file."""

    analysis: ProtocolAnalysis
    ike_exchanges: list[IkeExchangeRecord] = field(default_factory=list)
    esp_packets: list[EspPacketRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"analysis": self.analysis.to_dict(), "warnings": list(self.warnings)}


def _ipv4_parse(packet: bytes) -> tuple[int, int, bytes, str, str] | None:
    if len(packet) < 20 or (packet[0] >> 4) != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if len(packet) < ihl:
        return None
    proto = packet[9]
    total = struct.unpack_from("!H", packet, 2)[0]
    body = packet[ihl:total] if total > ihl else packet[ihl:]
    src = ".".join(str(b) for b in packet[12:16])
    dst = ".".join(str(b) for b in packet[16:20])
    return proto, ihl, body, src, dst


def _ipv6_parse(packet: bytes) -> tuple[int, bytes, str, str] | None:
    """Return ``(next_header, payload, src, dst)`` for an IPv6 packet.

    The fixed 40-byte header has no IHL field and no options, so the payload
    always starts at :data:`IPV6_HEADER_BYTES`.  Extension headers are walked by
    :func:`fera.capture.pcap_scan._ipv6_payload_offset_and_protocol`, which is
    bounded (8 headers) and returns ``None`` on a truncated or malformed chain
    rather than guessing - a packet we cannot decode becomes "unknown", never a
    fabricated protocol.

    ``payload_length`` is honoured: a jumbo or zero-length payload must not make
    the slice run past the captured bytes.
    """
    if len(packet) < IPV6_HEADER_BYTES or (packet[0] >> 4) != 6:
        return None
    walked = _ipv6_payload_offset_and_protocol(packet)
    if walked is None:
        return None
    offset, next_header = walked
    payload_length = struct.unpack_from("!H", packet, 4)[0]
    end = IPV6_HEADER_BYTES + payload_length
    # A truncated capture must not read past what was actually captured.
    end = min(end, len(packet)) if payload_length else len(packet)
    payload = packet[offset:end] if offset < end else b""
    src = _ipv6_address(packet[8:24])
    dst = _ipv6_address(packet[24:40])
    return next_header, payload, src, dst


def _ipv6_address(raw: bytes) -> str:
    """Render 16 bytes as a compressed IPv6 address.

    Falls back to hex when the address carries an IPv4-mapped prefix, which is
    what a NAT64 or dual-stack tunnel endpoint often looks like on the wire.
    """
    if len(raw) != 16:
        return ""
    if raw[:12] == b"\x00" * 10 + b"\xff\xff":
        return f"::ffff:{'.'.join(str(b) for b in raw[12:])}"
    groups = [f"{int.from_bytes(raw[i : i + 2], 'big'):x}" for i in range(0, 16, 2)]
    head = ":".join(groups)
    best_start = best_len = -1
    run_start = -1
    for index in range(8):
        if groups[index] == "0":
            if run_start < 0:
                run_start = index
            if index - run_start + 1 > best_len:
                best_start, best_len = run_start, index - run_start + 1
        else:
            run_start = -1
    if best_len < 2:
        return head
    prefix = ":".join(groups[:best_start])
    suffix = ":".join(groups[best_start + best_len :])
    return f"{prefix}::{suffix}" if prefix and suffix else f"{prefix}::" if prefix else f"::{suffix}"


def _ip_parse(packet: bytes) -> tuple[int, bytes, str, str, int] | None:
    """Dispatch one IP packet to the IPv4 or IPv6 parser.

    Returns ``(protocol, payload, src, dst, ip_version)``.  Both families hand
    back the same shape so the IKE/ESP logic below is written once and runs
    unchanged over IPv4 and IPv6.
    """
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 6:
        parsed = _ipv6_parse(packet)
        if parsed is None:
            return None
        next_header, payload, src, dst = parsed
        return next_header, payload, src, dst, 6
    if version == 4:
        parsed4 = _ipv4_parse(packet)
        if parsed4 is None:
            return None
        proto, _ihl, body, src, dst = parsed4
        return proto, body, src, dst, 4
    return None


def _udp_parse(segment: bytes) -> tuple[int, int, bytes] | None:
    if len(segment) < 8:
        return None
    sport, dport = struct.unpack_from("!HH", segment, 0)
    length = struct.unpack_from("!H", segment, 4)[0]
    payload = segment[8:length] if length >= 8 else segment[8:]
    return sport, dport, payload


def _frame_ip(frame: bytes, linktype: int | None) -> bytes | None:
    """Return the IP payload of one link-layer frame.

    Both ethertypes are accepted here.  IPv6 must not be filtered out at the
    link layer: dropping 0x86DD here made every IPv6 capture look like a
    capture with no IPsec in it, which reads as "no tunnel" rather than
    "not analysed".
    """
    if linktype == LINKTYPE_RAW:
        return frame
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        if ethertype in (ETHERTYPE_VLAN_IP, ETHERTYPE_QINQ_IP) and len(frame) >= 18:
            ethertype = struct.unpack_from("!H", frame, 16)[0]
            return frame[18:] if ethertype in (ETHERTYPE_IPV4, ETHERTYPE_IPV6) else None
        return frame[14:] if ethertype in (ETHERTYPE_IPV4, ETHERTYPE_IPV6) else None
    if frame and (frame[0] >> 4) in (4, 6):
        return frame
    return frame[14:] if len(frame) >= 14 else frame


def _iter_frames(pcap: Path) -> tuple[list[bytes], int | None]:
    from ..capture.pcap_scan import PCAPNG_MAGIC

    raw = pcap.read_bytes()
    if raw[:8] == PCAPNG_MAGIC:
        return [], None
    magic = raw[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        return [], -1
    linktype = struct.unpack(f"{endian}I", raw[20:24])[0]
    frames: list[bytes] = []
    offset = 24
    while offset + 16 <= len(raw):
        _a, _b, incl, _c = struct.unpack(f"{endian}IIII", raw[offset : offset + 16])
        offset += 16
        frames.append(raw[offset : offset + incl])
        offset += incl
    return frames, linktype


def analyze_pcap(pcap_path: str | Path, *, use_tshark: bool = False) -> AnalysisOutcome:
    """Deterministically analyse ``pcap_path`` without ML or guessing."""
    path = Path(pcap_path)
    warnings: list[str] = []
    ike_records: list[IkeExchangeRecord] = []
    esp_records: list[EspPacketRecord] = []
    method = "pcap_scan"
    if use_tshark:
        from .tshark import TsharkWrapper

        wrapper = TsharkWrapper()
        if wrapper.available:
            method = "tshark"
            warnings.append("tshark active: counts via pcap_scan")
        else:
            warnings.append("tshark unavailable; fell back to pcap_scan")
    scan = scan_pcap(path)
    frames, linktype = _iter_frames(path)
    if linktype is None:
        warnings.append("pcapng input: per-packet decode skipped")
    ipv4_esp = 0
    ipv6_esp = 0
    for index, frame in enumerate(frames):
        ip = _frame_ip(frame, linktype)
        if not ip:
            continue
        parsed = _ip_parse(ip)
        if parsed is None:
            continue
        proto, body, src, dst, ip_version = parsed
        if proto == IPPROTO_UDP:
            udp = _udp_parse(body)
            if udp is None:
                continue
            sport, dport, upayload = udp
            on_500 = sport == 500 or dport == 500
            on_4500 = sport == 4500 or dport == 4500
            if on_500:
                rec = parse_ike_message(index, upayload)
                if rec is not None:
                    ike_records.append(rec)
            elif on_4500:
                # RFC 3948: a zero first-4-bytes marker means an IKE header
                # (SPI==0); any other value starts an ESP header.  This rule is
                # protocol-level, so it holds identically for IPv4 and IPv6 -
                # NAT-T is not inferred from the outer address family.
                if upayload[:4] == b"\x00\x00\x00\x00":
                    rec = parse_ike_message(index, upayload)
                    if rec is not None:
                        ike_records.append(rec)
                elif len(upayload) >= 12:
                    esp = parse_esp_header(
                        index,
                        upayload,
                        src=src,
                        dst=dst,
                        length=len(frame),
                        udp_encapsulated=True,
                    )
                    if esp is not None:
                        esp_records.append(esp)
        elif proto == IPPROTO_ESP:
            esp = parse_esp_header(index, body, src=src, dst=dst, length=len(frame))
            if esp is not None:
                esp_records.append(esp)
                if ip_version == 6:
                    ipv6_esp += 1
                else:
                    ipv4_esp += 1
    flows = summarise_esp_flows(esp_records)
    pfs = correlate_sa(ike_records, flows)
    analysis = ProtocolAnalysis(
        pcap_path=path,
        method=method,
        packets=scan.packets,
        ike_packets=len(ike_records),
        esp_packets=len(esp_records),
        ike_exchanges=tuple(r.to_dict() for r in ike_records),
        esp_flows=tuple(f.to_dict() for f in flows),
        pfs_status=pfs.status,
        pfs_kind=pfs.kind,
        warnings=tuple(warnings),
        details={
            "pfs": pfs.to_dict(),
            "scan": scan.to_dict(),
            "outer_ip_versions": {"ipv4_esp": ipv4_esp, "ipv6_esp": ipv6_esp},
        },
    )
    return AnalysisOutcome(
        analysis=analysis,
        ike_exchanges=ike_records,
        esp_packets=esp_records,
        warnings=warnings,
    )


__all__ = ["AnalysisOutcome", "analyze_pcap"]


