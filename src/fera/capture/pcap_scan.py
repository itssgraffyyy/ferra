"""Minimal PCAP scanner used when tshark is not available.

This is intentionally *not* a protocol analyser: it reads the link layer just
deep enough to count what a dataset sample must contain (IKE, ESP, IPv4, IPv6,
ICMP).  Deep interpretation belongs to the later protocol-analysis stage.

Supported inputs:

* classic PCAP (``0xa1b2c3d4`` magic, either byte order), link types Ethernet,
  raw IP and Linux cooked capture (SLL/SLL2),
* PCAPNG files are *not* parsed here; the caller should use tshark for those
  (the scanner reports the format instead of guessing).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from ..common.errors import ErrorCode, FeraError

PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

#: Size of the classic PCAP global header (bytes).
PCAP_HEADER_BYTES = 24

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
LINKTYPE_NULL = 0

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_AH = 51
IPPROTO_ESP = 50
IPPROTO_ICMPV6 = 58
IPV6_EXTENSION_HEADERS = {0, 43, 60, 135, 139, 140}


@dataclass(frozen=True)
class PcapScanResult:
    """Counts observed in a capture file."""

    path: Path
    file_format: str
    linktype: int | None
    linktype_name: str
    packets: int = 0
    captured_bytes: int = 0
    ipv4_packets: int = 0
    ipv6_packets: int = 0
    esp_packets: int = 0
    ah_packets: int = 0
    ike_packets: int = 0
    icmp_packets: int = 0
    icmpv6_packets: int = 0
    truncated_frames: int = 0
    notes: tuple[str, ...] = ()

    @property
    def ike_detected(self) -> bool:
        return self.ike_packets > 0

    @property
    def esp_detected(self) -> bool:
        return self.esp_packets > 0

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "file_format": self.file_format,
            "linktype": self.linktype,
            "linktype_name": self.linktype_name,
            "packets": self.packets,
            "captured_bytes": self.captured_bytes,
            "ipv4_packets": self.ipv4_packets,
            "ipv6_packets": self.ipv6_packets,
            "esp_packets": self.esp_packets,
            "ah_packets": self.ah_packets,
            "ike_packets": self.ike_packets,
            "icmp_packets": self.icmp_packets,
            "icmpv6_packets": self.icmpv6_packets,
            "truncated_frames": self.truncated_frames,
            "notes": list(self.notes),
        }


def _strip_ethernet(frame: bytes) -> bytes | None:
    """Return the IP payload of an Ethernet frame (handles one VLAN tag)."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    if ethertype in {ETHERTYPE_VLAN, ETHERTYPE_QINQ} and len(frame) >= 18:
        ethertype = struct.unpack_from("!H", frame, 16)[0]
        offset = 18
    if ethertype not in {ETHERTYPE_IPV4, ETHERTYPE_IPV6}:
        return None
    return frame[offset:]


def _ipv4_offset_and_protocol(frame: bytes) -> tuple[int, int] | None:
    """Return ``(payload_offset, protocol)`` for an IPv4 packet."""
    if len(frame) < 20 or frame[0] >> 4 != 4:
        return None
    ihl = (frame[0] & 0x0F) * 4
    if len(frame) < ihl:
        return None
    return ihl, frame[9]


def _ipv6_payload_offset_and_protocol(frame: bytes) -> tuple[int, int] | None:
    """Return ``(payload_offset, next_header)``, walking IPv6 extension headers."""
    if len(frame) < 40 or frame[0] >> 4 != 6:
        return None
    next_header = frame[6]
    offset = 40
    guard = 0
    while next_header in IPV6_EXTENSION_HEADERS and guard < 8:
        if len(frame) < offset + 2:
            return None
        if next_header == 44:  # fragment header has a fixed size of 8 bytes
            length = 8
        else:
            length = (frame[offset + 1] + 1) * 8
        next_header = frame[offset]
        offset += length
        guard += 1
    if len(frame) < offset:
        return None
    return offset, next_header


def _udp_ports(frame: bytes, offset: int) -> tuple[int, int] | None:
    if len(frame) < offset + 4:
        return None
    return struct.unpack_from("!HH", frame, offset)


def _account_transport(counts: dict[str, int], payload: bytes, offset: int, protocol: int) -> None:
    """Increase the counters for one decoded IP payload."""
    if protocol == IPPROTO_ESP:
        counts["esp"] += 1
        return
    if protocol == IPPROTO_AH:
        counts["ah"] += 1
        return
    if protocol == IPPROTO_ICMP:
        counts["icmp"] += 1
        return
    if protocol == IPPROTO_ICMPV6:
        counts["icmpv6"] += 1
        return
    if protocol == IPPROTO_UDP:
        ports = _udp_ports(payload, offset)
        if ports and (500 in ports or 4500 in ports):
            counts["ike"] += 1


def open_pcap(path: str | Path) -> BinaryIO:
    """Open a PCAP file for scanning, raising an explicit error otherwise."""
    candidate = Path(path)
    if not candidate.is_file():
        raise FeraError(
            f"capture file not found: {candidate}",
            code=ErrorCode.CAPTURE_EMPTY,
            details={"path": str(candidate)},
        )
    size = candidate.stat().st_size
    if size <= PCAP_HEADER_BYTES:
        raise FeraError(
            f"capture file is empty or truncated: {candidate} ({size} bytes)",
            code=ErrorCode.CAPTURE_EMPTY,
            details={"path": str(candidate), "size": size},
        )
    return candidate.open("rb")


def scan_pcap(pcap_path: str | Path) -> PcapScanResult:
    """Scan a capture file and count the traffic classes a dataset sample needs."""
    path = Path(pcap_path)
    counters = {
        "packets": 0,
        "bytes": 0,
        "ipv4": 0,
        "ipv6": 0,
        "esp": 0,
        "ah": 0,
        "ike": 0,
        "icmp": 0,
        "icmpv6": 0,
        "truncated": 0,
    }
    notes: list[str] = []
    linktype: int | None = None
    linktype_name = "UNKNOWN"
    with open_pcap(path) as handle:
        header = handle.read(16)
        if header[:4] == PCAPNG_MAGIC:
            raise FeraError(
                f"{path} is a PCAPNG file; FERA's built-in scanner only reads classic PCAP",
                code=ErrorCode.UNSUPPORTED_FEATURE,
                hint="install tshark for PCAPNG support, or record with tcpdump (classic PCAP)",
                details={"path": str(path)},
            )
        magic = header[:4]
        if magic == PCAP_MAGIC_LE:
            endian = "<"
        elif magic == PCAP_MAGIC_BE:
            endian = ">"
        else:
            raise FeraError(
                f"{path} is not a classic PCAP file (magic {magic.hex()})",
                code=ErrorCode.CAPTURE_VALIDATION_FAILED,
                details={"path": str(path), "magic": magic.hex()},
            )
        _vmajor, _vminor, _tz, _sigfigs, snaplen, linktype = (*struct.unpack(f"{endian}HHii", header[4:16]), *struct.unpack(f"{endian}II", handle.read(8)))
        linktype_name = {
            LINKTYPE_ETHERNET: "ETHERNET",
            LINKTYPE_RAW: "RAW_IP",
            LINKTYPE_LINUX_SLL: "LINUX_SLL",
            LINKTYPE_LINUX_SLL2: "LINUX_SLL2",
            LINKTYPE_NULL: "NULL_LOOPBACK",
        }.get(linktype, f"UNKNOWN_{linktype}")
        parsed_link = linktype in {
            LINKTYPE_ETHERNET,
            LINKTYPE_RAW,
            LINKTYPE_LINUX_SLL,
            LINKTYPE_LINUX_SLL2,
            LINKTYPE_NULL,
        }
        if not parsed_link:
            notes.append(f"link type {linktype} ({linktype_name}) is not parsed by this scanner")
        if snaplen and snaplen < 512:
            notes.append(f"snap length is small ({snaplen} bytes): payload analysis will be limited")

        while True:
            frame_header = handle.read(16)
            if len(frame_header) < 16:
                break
            _ts_sec, _ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", frame_header)
            if incl_len > 262_144:  # guard against corrupted length fields
                notes.append("stopped scanning after an implausible frame length")
                break
            data = handle.read(incl_len)
            if len(data) < incl_len:
                notes.append("file ends inside a frame (capture was interrupted)")
                break
            counters["packets"] += 1
            counters["bytes"] += incl_len
            if incl_len < orig_len:
                counters["truncated"] += 1
            if not parsed_link:
                continue
            if linktype == LINKTYPE_ETHERNET:
                payload = _strip_ethernet(data)
            elif linktype == LINKTYPE_LINUX_SLL:
                payload = data[16:]
            elif linktype == LINKTYPE_LINUX_SLL2:
                payload = data[20:]
            elif linktype == LINKTYPE_NULL:
                payload = data[4:]
            else:
                payload = data
            if not payload:
                continue
            version = payload[0] >> 4
            if version == 4:
                parsed = _ipv4_offset_and_protocol(payload)
                if parsed is None:
                    continue
                offset, protocol = parsed
                counters["ipv4"] += 1
                _account_transport(counters, payload, offset, protocol)
            elif version == 6:
                parsed6 = _ipv6_payload_offset_and_protocol(payload)
                if parsed6 is None:
                    continue
                offset6, protocol6 = parsed6
                counters["ipv6"] += 1
                _account_transport(counters, payload, offset6, protocol6)

    return PcapScanResult(
        path=path,
        file_format="pcap",
        linktype=linktype,
        linktype_name=linktype_name,
        packets=counters["packets"],
        captured_bytes=counters["bytes"],
        ipv4_packets=counters["ipv4"],
        ipv6_packets=counters["ipv6"],
        esp_packets=counters["esp"],
        ah_packets=counters["ah"],
        ike_packets=counters["ike"],
        icmp_packets=counters["icmp"],
        icmpv6_packets=counters["icmpv6"],
        truncated_frames=counters["truncated"],
        notes=tuple(notes),
    )


__all__ = [
    "PCAPNG_MAGIC",
    "PCAP_HEADER_BYTES",
    "PCAP_MAGIC_BE",
    "PCAP_MAGIC_LE",
    "PcapScanResult",
    "open_pcap",
    "scan_pcap",
]


