"""Deterministic protocol analyser tests using synthetic PCAPs.

The frames below are byte-exact IKEv2/ESP constructions so every expectation
(counts, SPI grouping, sequence stats, PFS verdicts, evidence kinds) is
checkable without tshark, a kernel, or a VPN.
"""

from __future__ import annotations

import struct
from pathlib import Path

from conftest import ethernet_ipv4, write_pcap
from fera.analysis import analyze_pcap
from fera.analysis.models import PfsStatus
from fera.analysis.provenance import EvidenceKind

ESP_OPAQUE = b"\xAA" * 16


def _esp_payload(spi_int: int, sequence: int) -> bytes:
    return struct.pack("!II", spi_int, sequence) + ESP_OPAQUE


def _sa_payload(protocol_id: int, spi: bytes, transforms: list[tuple[int, int]]) -> bytes:
    """Build an IKEv2 SA payload with one proposal and the given transforms."""
    t_blob = b""
    for index, (t_type, t_id) in enumerate(transforms):
        nxt = 0 if index == len(transforms) - 1 else 3
        t_blob += struct.pack("!BBHBBH", nxt, 0, 8, t_type, 0, t_id)
    proposal_len = 8 + len(spi) + len(t_blob)
    proposal = struct.pack("!BBHBBBB", 0, 0, proposal_len, 1, protocol_id, len(spi), 0)
    proposal += spi + t_blob
    return struct.pack("!BBH", 0, 0, 4 + len(proposal)) + proposal


def _ike_v2(exchange_type: int, flags: int, message_id: int, sa_payload: bytes = b"") -> bytes:
    body = sa_payload
    header = struct.pack(
        "!16sBBBBII",
        bytes.fromhex("11111111111111112222222222222222"),
        33 if body else 0,
        0x20,
        exchange_type,
        flags,
        message_id,
        28 + len(body),
    )
    return header + body


def _ike_sa_init_with_child_proposal(dh_group: int | None) -> bytes:
    transforms = [(1, 12), (2, 2)]  # ENCR_AES_GCM_16 (128), PRF_HMAC_SHA2_256
    if dh_group is not None:
        transforms.append((4, dh_group))  # DH transform
    return _ike_v2(34, 0x01, 0, _sa_payload(3, bytes.fromhex("c0a81401"), transforms))


# --- full pipeline ------------------------------------------------------------
def test_analyze_pcap_ikes_esp_and_natt_flows(tmp_path: Path) -> None:
    frames = [
        ethernet_ipv4(17, src_port=500, dst_port=500, payload=_ike_sa_init_with_child_proposal(19)),
        ethernet_ipv4(50, payload=_esp_payload(0xAABBCCDD, 1)),
        ethernet_ipv4(50, payload=_esp_payload(0xAABBCCDD, 2)),
        ethernet_ipv4(50, payload=_esp_payload(0xAABBCCDD, 4)),  # gap of one
        ethernet_ipv4(17, src_port=4500, dst_port=4500, payload=_esp_payload(0x11223344, 5)),
        ethernet_ipv4(17, src_port=4500, dst_port=4500, payload=_esp_payload(0x11223344, 5)),  # replay
    ]
    pcap = write_pcap(tmp_path / "mixed.pcap", frames)
    outcome = analyze_pcap(pcap)
    analysis = outcome.analysis

    assert analysis.method == "pcap_scan"
    assert analysis.packets == 6
    assert analysis.ike_packets == 1
    assert analysis.esp_packets == 5  # 3 plain ESP + 2 ESP-in-UDP

    assert len(analysis.ike_exchanges) == 1
    exchange = analysis.ike_exchanges[0]
    assert exchange["ike_version"] == 2
    assert exchange["exchange_name"] == "IKE_SA_INIT"
    proposal = exchange["proposals"][0]
    assert proposal["protocol_name"] == "ESP"
    assert proposal["dh_groups"] == [19]
    assert proposal["spi"] == "c0a81401"

    flows = {flow["spi"]: flow for flow in analysis.esp_flows}
    assert set(flows) == {"aabbccdd", "11223344"}
    plain = flows["aabbccdd"]
    assert plain["packets"] == 3
    assert plain["sequence_gaps"] == 1
    assert plain["sequence_replays"] == 0
    assert plain["sequence_monotonic"] is True
    assert plain["encapsulation"] == "unknown"
    assert plain["encapsulation_kind"] == EvidenceKind.NOT_VERIFIABLE.value
    natt = flows["11223344"]
    assert natt["packets"] == 2
    assert natt["sequence_replays"] == 1
    assert natt["udp_encapsulated"] is True
    assert natt["encapsulation"] == "esp-in-udp"
    assert natt["encapsulation_kind"] == EvidenceKind.OBSERVED.value

    assert analysis.pfs_status is PfsStatus.OBSERVED
    assert analysis.pfs_kind is EvidenceKind.OBSERVED
    assert analysis.details["pfs"]["child_sa_dh_groups"] == [19]

    document = analysis.to_dict()
    assert document["pfs"] == {"status": "OBSERVED", "kind": "OBSERVED"}
    assert document["esp_flows"][0]["spi"] in {"11223344", "aabbccdd"}


def test_pfs_disabled_when_child_proposal_has_no_dh(tmp_path: Path) -> None:
    frames = [
        ethernet_ipv4(17, src_port=500, dst_port=500, payload=_ike_sa_init_with_child_proposal(None)),
        ethernet_ipv4(50, payload=_esp_payload(0x0A0B0C0D, 1)),
    ]
    outcome = analyze_pcap(write_pcap(tmp_path / "nopfs.pcap", frames))
    assert outcome.analysis.pfs_status is PfsStatus.DISABLED
    assert outcome.analysis.pfs_kind is EvidenceKind.OBSERVED


def test_pfs_not_verifiable_without_clear_proposals(tmp_path: Path) -> None:
    frames = [ethernet_ipv4(50, payload=_esp_payload(0x0A0B0C0D, 7))]
    outcome = analyze_pcap(write_pcap(tmp_path / "esponly.pcap", frames))
    assert outcome.analysis.pfs_status is PfsStatus.NOT_VERIFIABLE
    assert outcome.analysis.pfs_kind is EvidenceKind.NOT_VERIFIABLE
    assert outcome.analysis.esp_packets == 1


def test_zero_marker_on_4500_is_ike_not_esp(tmp_path: Path) -> None:
    init = _ike_v2(34, 0x01, 0)
    zeroed = b"\x00" * 8 + init[8:]  # initiator SPI must be zero for the marker
    frames = [ethernet_ipv4(17, src_port=4500, dst_port=4500, payload=zeroed)]
    outcome = analyze_pcap(write_pcap(tmp_path / "natt-ike.pcap", frames))
    assert outcome.analysis.ike_packets == 1
    assert outcome.analysis.esp_packets == 0


