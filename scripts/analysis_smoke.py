"""Dev smoke: build a realistic synthetic IPsec capture and inspect the analysis.

Not a product entry point and not a unit test - it exists so the analysis,
privacy and API layers can be exercised with one command on a machine with no
real captures:

    python scripts/analysis_smoke.py            # prints the document outline
    python scripts/analysis_smoke.py --full     # prints the whole JSON document
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fera.analysis import analyze_pcap  # noqa: E402

PCAP_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
ETH_V4 = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
ETH_V6 = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x86\xdd"
HOST = bytes([10, 10, 10, 1])
PEER = bytes([10, 10, 10, 2])


def udp_v4(port_src: int, port_dst: int, payload: bytes, *, src: bytes = HOST, dst: bytes = PEER) -> bytes:
    transport = struct.pack("!HHHH", port_src, port_dst, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 0, 0, 64, 17, 0, src, dst)
    return ETH_V4 + ip + transport


def tcp_v4(port_src: int, port_dst: int, payload: bytes, *, src: bytes = HOST, dst: bytes = PEER) -> bytes:
    transport = struct.pack("!HHIIBBHHH", port_src, port_dst, 0, 0, 0x50, 0x18, 65535, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 0, 0, 64, 6, 0, src, dst)
    return ETH_V4 + ip + transport


def icmp_v4(payload: bytes = b"\x08\x00\x00\x00" + b"\x00" * 8) -> bytes:
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, 1, 0, HOST, PEER)
    return ETH_V4 + ip + payload


def esp(spi_int: int, sequence: int, size: int, *, src: bytes = HOST, dst: bytes = PEER) -> bytes:
    body = struct.pack("!II", spi_int, sequence) + bytes(size)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, 50, 0, src, dst)
    return ETH_V4 + ip + body


def sa_payload(protocol_id: int, spi: bytes, transforms: list[tuple[int, int]]) -> bytes:
    blob = b""
    for index, (kind, identifier) in enumerate(transforms):
        nxt = 0 if index == len(transforms) - 1 else 3
        blob += struct.pack("!BBHBBH", nxt, 0, 8, kind, 0, identifier)
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(spi) + len(blob), 1, protocol_id, len(spi), 0)
    return struct.pack("!BBH", 0, 0, 4 + 8 + len(spi) + len(blob)) + proposal + spi + blob


def ike_v2(exchange: int, flags: int, message_id: int, body: bytes = b"", spi: str = "1" * 16 + "2" * 16) -> bytes:
    header = struct.pack(
        "!16sBBBBII", bytes.fromhex(spi), 33 if body else 0, 0x21, exchange, flags, message_id, 28 + len(body)
    )
    return header + body


def frames() -> list[tuple[bytes, int, int]]:
    """Frames as (bytes, ts_sec, ts_usec) tuples: IKEv2 SA up, ESP data, cleartext."""
    proposal = [(1, 12), (2, 2), (4, 19)]  # AES-GCM-128, PRF_SHA2_256, DH19
    out: list[tuple[bytes, int, int]] = [
        (udp_v4(500, 500, ike_v2(34, 0x01, 0, sa_payload(3, bytes.fromhex("aabbccdd"), proposal))), 1700000000, 0),
        (udp_v4(500, 500, ike_v2(34, 0x20, 0, sa_payload(3, bytes.fromhex("ddeeff00"), proposal))), 1700000000, 40000),
        (udp_v4(500, 500, ike_v2(35, 0x01, 1)), 1700000000, 90000),
        (udp_v4(500, 500, ike_v2(35, 0x20, 1)), 1700000000, 150000),
    ]
    sizes = [24, 24, 60, 92, 1444, 1444, 900, 120, 24, 76, 76, 1448, 60, 92]
    for index, size in enumerate(sizes):
        stamp = 1700000001 + index // 5
        micro = (index % 5) * 200000
        out.append((esp(0x11223344, index + 1, size), stamp, micro))
    for index in range(3):
        out.append((esp(0x55667788, index + 1, 84), 1700000003 + index, 500000))
    out += [
        (udp_v4(4500, 4500, b"\x00" * 4 + bytes(60)), 1700000004, 0),
        (udp_v4(53, 51000, b"\x00" * 24), 1700000004, 100000),  # cleartext DNS response
        (udp_v4(51000, 53, b"\x00" * 46), 1700000004, 120000),  # cleartext DNS query
        (tcp_v4(80, 51001, b"HTTP/1.1 200 OK\r\n" + bytes(40)), 1700000004, 200000),
        (icmp_v4(), 1700000004, 300000),
        (ETH_V4[:12] + b"\x08\x06" + bytes(28), 1700000004, 400000),  # ARP
    ]
    return out


def build(path: Path) -> Path:
    body = bytearray(PCAP_HEADER)
    for data, second, micro in frames():
        body += struct.pack("<IIII", second, micro, len(data), len(data))
        body += data
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(body))
    return path


def outline(document: dict, prefix: str = "") -> None:
    for key, value in document.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            print(f"{name}: dict({len(value)})")
            outline(value, f"{name}.")
        elif isinstance(value, list):
            print(f"{name}: list({len(value)})")
            if value and isinstance(value[0], dict):
                print(f"{name}[0] keys: {sorted(value[0])}")
        else:
            rendered = str(value)
            print(f"{name} = {rendered if len(rendered) < 90 else rendered[:87] + '...'}")


def main(argv: list[str]) -> int:
    capture = build(ROOT / "data" / "tmp" / "smoke_ipsec.pcap")
    outcome = analyze_pcap(capture)
    document = outcome.analysis.to_dict()
    print(f"capture: {capture} ({capture.stat().st_size} bytes)")
    print("warnings:", outcome.warnings)
    if "--full" in argv:
        print(json.dumps(document, indent=2, sort_keys=True, default=str))
    else:
        outline(document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
