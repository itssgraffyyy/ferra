"""IPv6 IPsec analysis tests (PS closure, phase 1).

Before this module existed, ``analyze_pcap`` dropped every Ethernet frame with
ethertype 0x86DD at the link layer and then only ever called the IPv4 parser, so
an IPv6 capture analysed to zero IKE and zero ESP.  That reads exactly like "no
tunnel in this capture", which is the dangerous kind of wrong: the honest answer
was "not analysed", and the report said "nothing there".

These tests pin that IPv6 now converges into the *same* parsers as IPv4:
IKE on UDP/500 and UDP/4500, native ESP, ESP behind extension headers, and safe
refusal on truncated or malformed input.  Synthetic frames prove parser
behaviour only - they are not evidence of real strongSwan behaviour.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from conftest import ethernet_ipv4, ethernet_ipv6, write_pcap
from fera.analysis import analyze_pcap
from fera.analysis.analyzer import _ip_parse, _ipv6_address
from fera.analysis.ike import parse_ike_message

ESP_OPAQUE = b"\xAA" * 16
IPV6_ETHERTYPE = 0x86DD


def _esp_payload(spi_int: int, sequence: int) -> bytes:
    return struct.pack("!II", spi_int, sequence) + ESP_OPAQUE


def _ike_v2(exchange_type: int = 34, flags: int = 0x01, message_id: int = 0) -> bytes:
    """A minimal but structurally valid IKEv2 header."""
    return struct.pack(
        "!16sBBBBII",
        bytes.fromhex("11111111111111112222222222222222"),
        33,
        0x20,
        exchange_type,
        flags,
        message_id,
        28,
    )


def _ipv6_base(next_header: int, payload: bytes) -> bytes:
    """Build a bare (link-layer-free) IPv6 packet."""
    header = struct.pack("!IHBB", 0x60000000, len(payload), next_header, 64)
    addresses = bytes.fromhex("fd001010000000000000000000000001") + bytes.fromhex(
        "fd001010000000000000000000000002"
    )
    return header + addresses + payload


def _ipv6_frame(next_header: int, payload: bytes) -> bytes:
    return ethernet_ipv6(next_header, payload=payload)


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _analyze(tmp_path: Path, frames: list[bytes]):
    return analyze_pcap(write_pcap(tmp_path / "cap.pcap", frames))
# --- A. IPv6 + UDP/500 + IKE ---------------------------------------------------

def test_ipv6_udp_500_reaches_the_ike_parser(tmp_path: Path) -> None:
    outcome = _analyze(tmp_path, [ethernet_ipv6(17, src_port=500, dst_port=500,
                                               payload=_ike_v2())])
    assert outcome.analysis.ike_packets == 1
    assert outcome.analysis.ike_exchanges[0]["exchange_name"] == "IKE_SA_INIT"


# --- B. IPv6 + UDP/4500 + IKE (NON-ESP marker) --------------------------------

def test_ipv6_udp_4500_nonesp_marker_is_ike_not_esp(tmp_path: Path) -> None:
    """RFC 3948: the four zero bytes mean IKE, whatever the address family."""
    payload = b"\x00\x00\x00\x00" + _ike_v2()
    outcome = _analyze(tmp_path, [ethernet_ipv6(17, src_port=4500, dst_port=4500,
                                               payload=payload)])
    assert outcome.analysis.ike_packets == 1
    assert outcome.analysis.esp_packets == 0


# --- C. IPv6 + UDP/4500 + ESP -------------------------------------------------

def test_ipv6_udp_4500_non_marker_is_encapsulated_esp(tmp_path: Path) -> None:
    payload = struct.pack("!I", 0xDEADBEEF) + _esp_payload(0xCAFEBABE, 7)
    outcome = _analyze(tmp_path, [ethernet_ipv6(17, src_port=4500, dst_port=4500,
                                               payload=payload)])
    assert outcome.analysis.esp_packets == 1
    assert outcome.analysis.ike_packets == 0
    flow = outcome.analysis.esp_flows[0]
    assert flow["encapsulation"] == "esp-in-udp"
    assert flow["udp_encapsulated"] is True


# --- D. IPv6 + native ESP -----------------------------------------------------

def test_ipv6_native_esp_is_decoded(tmp_path: Path) -> None:
    outcome = _analyze(tmp_path, [ethernet_ipv6(50, payload=_esp_payload(0xABCD1234, 3))])
    assert outcome.analysis.esp_packets == 1
    flow = outcome.analysis.esp_flows[0]
    assert flow["spi"] == "abcd1234"
    assert flow["src"].startswith("fd00:1010")


def test_ipv6_addresses_are_rendered_compressed() -> None:
    assert _ipv6_address(bytes.fromhex("fd001010000000000000000000000001")) == "fd00:1010::1"
    assert _ipv6_address(bytes.fromhex("00000000000000000000ffff0a0a0a01")) == "::ffff:10.10.10.1"
# --- E/F. extension headers ----------------------------------------------------

def _extension(next_header: int, upper: bytes) -> bytes:
    """One IPv6 extension header (8 bytes) chaining to ``upper``."""
    return struct.pack("!BB", next_header, 0) + b"\x00" * 6 + upper


def test_ipv6_extension_header_then_esp_is_decoded(tmp_path: Path) -> None:
    frame = _ipv6_frame(60, _extension(50, _esp_payload(0x11112222, 1)))
    outcome = _analyze(tmp_path, [frame])
    assert outcome.analysis.esp_packets == 1
    assert outcome.analysis.esp_flows[0]["spi"] == "11112222"


def test_ipv6_extension_header_then_ike_is_decoded(tmp_path: Path) -> None:
    frame = _ipv6_frame(0, _extension(17, _udp(500, 500, _ike_v2())))
    outcome = _analyze(tmp_path, [frame])
    assert outcome.analysis.ike_packets == 1


def test_ipv6_fragment_header_then_esp_is_decoded(tmp_path: Path) -> None:
    fragment = struct.pack("!BBHI", 50, 0, 0, 0x00000001)  # next=ESP, fixed 8 bytes
    frame = _ipv6_frame(44, fragment + _esp_payload(0x22223333, 2))
    outcome = _analyze(tmp_path, [frame])
    assert outcome.analysis.esp_packets == 1
    assert outcome.analysis.esp_flows[0]["spi"] == "22223333"


# --- G/H. malformed and truncated ---------------------------------------------

def test_truncated_ipv6_packet_is_skipped_without_raising(tmp_path: Path) -> None:
    outcome = _analyze(tmp_path, [_ipv6_base(50, _esp_payload(1, 1))[:20]])
    assert outcome.analysis.esp_packets == 0


def test_malformed_extension_chain_does_not_crash(tmp_path: Path) -> None:
    """A chain claiming a huge length must be refused, not followed."""
    bogus = struct.pack("!BB", 60, 255) + b"\x00" * 6  # claims 2048 bytes
    outcome = _analyze(tmp_path, [_ipv6_frame(60, bogus),
                                  ethernet_ipv6(50, payload=_esp_payload(9, 9))])
    # The bad frame is dropped; the good frame in the same file still analyses.
    assert outcome.analysis.esp_packets == 1


def test_extension_header_loop_terminates(tmp_path: Path) -> None:
    """A chain that points at itself must hit the bounded-walk guard."""
    looping = struct.pack("!BB", 60, 0) + b"\x00" * 6
    outcome = _analyze(tmp_path, [_ipv6_frame(60, looping)])
    assert outcome.analysis.esp_packets == 0


# --- I/J/K. features, mixed, regression ---------------------------------------

def test_ipv6_capture_reaches_ml_feature_extraction(tmp_path: Path) -> None:
    from fera.ml import extract_features

    pcap = write_pcap(tmp_path / "v6.pcap", [ethernet_ipv6(50, payload=_esp_payload(5, 1))] * 4)
    vector = extract_features(pcap)
    assert vector.features["ipv6_packet_share"] == 1.0
    assert vector.features["esp_packets"] == 4


def test_mixed_ipv4_ipv6_capture_analyses_both_families(tmp_path: Path) -> None:
    outcome = _analyze(tmp_path, [ethernet_ipv4(50, payload=_esp_payload(1, 1)),
                                  ethernet_ipv6(50, payload=_esp_payload(2, 2))])
    assert outcome.analysis.esp_packets == 2
    assert outcome.analysis.details["outer_ip_versions"] == {"ipv4_esp": 1, "ipv6_esp": 1}


def test_ipv4_analysis_is_unchanged(tmp_path: Path) -> None:
    """Regression guard: the IPv4 path must behave exactly as before."""
    outcome = _analyze(tmp_path, [ethernet_ipv4(17, src_port=500, dst_port=500,
                                               payload=_ike_v2()),
                                  ethernet_ipv4(50, payload=_esp_payload(0x1111, 1))])
    assert outcome.analysis.ike_packets == 1
    assert outcome.analysis.esp_packets == 1
    assert outcome.analysis.details["outer_ip_versions"]["ipv4_esp"] == 1


def test_ethernet_ipv6_ethertype_is_not_dropped() -> None:
    """The link layer must hand 0x86DD frames to the IP parser."""
    frame = ethernet_ipv6(50, payload=_esp_payload(3, 3))
    assert struct.unpack_from("!H", frame, 12)[0] == IPV6_ETHERTYPE


@pytest.mark.parametrize("length", [0, 1, 20, 39])
def test_ipv6_shorter_than_fixed_header_is_undecodable(length: int) -> None:
    assert _ip_parse(_ipv6_base(50, b"")[:length]) is None



# --- Linux cooked captures (linktype), found via a real strongSwan pcap -------

def _write_pcap_linktype(path: Path, frames: list[bytes], linktype: int) -> Path:
    """Write a classic PCAP with an explicit link type."""
    body = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
    for index, frame in enumerate(frames):
        body += struct.pack("<IIII", 1700000000 + index, 0, len(frame), len(frame))
        body += frame
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(body))
    return path


def _sll2(ethertype: int, ip_packet: bytes) -> bytes:
    """Linux SLL2 header (linktype 276): protocol first, 20-byte header."""
    return struct.pack("!HHIHBB", ethertype, 0, 1, 1, 0, 6) + b"\x00" * 8 + ip_packet


def _sll(ethertype: int, ip_packet: bytes) -> bytes:
    """Linux SLL header (linktype 113): 16 bytes, protocol at offset 14."""
    return struct.pack("!HHH", 0, 1, 6) + b"\x00" * 8 + struct.pack("!H", ethertype) + ip_packet


def _ipv6_packet(next_header: int, payload: bytes) -> bytes:
    header = struct.pack("!IHBB", 0x60000000, len(payload), next_header, 64)
    addresses = bytes.fromhex("fd001010000000000000000000000001") + bytes.fromhex(
        "fd001010000000000000000000000002"
    )
    return header + addresses + payload


def test_sll2_capture_ike_is_decoded(tmp_path: Path) -> None:
    """Regression: a real strongSwan pcap is linktype 276, and analysed as empty.

    ``tcpdump -i any`` on the tunnel host writes Linux SLL2, which has no
    ethertype at offset 12.  The analyser used to strip a 14-byte Ethernet
    header from a 20-byte SLL2 one, failed to parse, and reported zero IKE for
    a capture that plainly contained it.
    """
    ip_packet = _ipv6_packet(17, _udp(500, 500, _ike_v2()))
    pcap = _write_pcap_linktype(tmp_path / "sll2.pcap", [_sll2(0x86DD, ip_packet)], 276)
    outcome = analyze_pcap(pcap)
    assert outcome.analysis.ike_packets == 1
    assert outcome.analysis.ike_exchanges[0]["exchange_name"] == "IKE_SA_INIT"


def test_sll_capture_ipv4_esp_is_decoded(tmp_path: Path) -> None:
    ip_packet = ethernet_ipv4(50, payload=_esp_payload(0x11223344, 1))[14:]
    pcap = _write_pcap_linktype(tmp_path / "sll.pcap", [_sll(0x0800, ip_packet)], 113)
    outcome = analyze_pcap(pcap)
    assert outcome.analysis.esp_packets == 1
    assert outcome.analysis.esp_flows[0]["spi"] == "11223344"


def test_sll2_non_ip_ethertype_is_skipped(tmp_path: Path) -> None:
    """ARP over SLL2 must not be mistaken for IP."""
    pcap = _write_pcap_linktype(tmp_path / "arp.pcap", [_sll2(0x0806, b"\x00" * 28)], 276)
    outcome = analyze_pcap(pcap)
    assert outcome.analysis.ike_packets == 0
    assert outcome.analysis.esp_packets == 0


def test_sll2_truncated_header_is_skipped(tmp_path: Path) -> None:
    pcap = _write_pcap_linktype(tmp_path / "short.pcap", [_sll2(0x86DD, b"\x00" * 8)], 276)
    assert analyze_pcap(pcap).analysis.ike_packets == 0


def test_encrypted_natt_payload_is_not_reported_as_a_fake_exchange() -> None:
    """Regression: ciphertext on 4500 must not invent an IKE exchange.

    On a real capture the ESP-encrypted IKE messages on UDP/4500 were decoded as
    ``UNKNOWN_EXCHANGE_177`` with nonsense message ids, because a random 4-byte
    run carries major version 2 in the right nibble one time in sixteen.
    """
    cipher = struct.pack("!16sBBBBII", bytes.fromhex("aa" * 8 + "bb" * 8), 0, 0x20, 177, 0x08, 773858056, 528)
    assert parse_ike_message(0, cipher) is None


def test_ike_auth_with_zero_responder_spi_is_rejected() -> None:
    """Only IKE_SA_INIT may carry a zero responder SPI (RFC 7296)."""
    bogus = struct.pack("!16sBBBBII", bytes.fromhex("11" * 8 + "00" * 8), 33, 0x20, 35, 0x08, 1, 28)
    assert parse_ike_message(0, bogus) is None


def test_valid_ike_sa_init_still_parses() -> None:
    record = parse_ike_message(0, _ike_v2())
    assert record is not None
    assert record.exchange_name == "IKE_SA_INIT"
    assert record.ike_version == 2


def test_valid_ike_auth_with_responder_spi_parses() -> None:
    message = struct.pack(
        "!16sBBBBII", bytes.fromhex("11" * 8 + "22" * 8), 33, 0x20, 35, 0x08, 1, 28
    )
    record = parse_ike_message(0, message)
    assert record is not None
    assert record.exchange_name == "IKE_AUTH"
