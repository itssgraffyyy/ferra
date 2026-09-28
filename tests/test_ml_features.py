"""Checkpoint 3A: versioned ESP feature extraction tests.

These tests lock the ``fera_esp_features_v1`` contract (schema id + whitelist
order), prove the leakage guards (no label inputs, finite numeric outputs),
and verify direction normalisation, timing and sequence-health features on
byte-exact synthetic captures - no tshark, no VPN, no real data required.
"""

from __future__ import annotations

import inspect
import math
import struct
from pathlib import Path

import pytest

from conftest import ethernet_ipv4, write_pcap
from fera.analysis import analyze_pcap
from fera.common.errors import ErrorCode, FeraError
from fera.ml import FEATURE_SCHEMA, FEATURE_WHITELIST, FeatureVector, extract_features

ESP_OPAQUE = b"\xAA" * 16

#: Exact whitelist as shipped in schema v1.  Any drift here means the schema
#: changed: update this tuple *and* bump FEATURE_SCHEMA together.
EXPECTED_WHITELIST = (
    "capture_packets",
    "capture_bytes",
    "capture_duration_s",
    "packet_rate_pps",
    "byte_rate_bps",
    "avg_packet_len",
    "esp_packet_share",
    "ike_packet_share",
    "icmp_packet_share",
    "ipv6_packet_share",
    "truncated_packet_share",
    "esp_packets",
    "esp_bytes",
    "esp_flow_count",
    "esp_avg_len",
    "esp_len_min",
    "esp_len_max",
    "esp_len_std",
    "esp_avg_packets_per_flow",
    "esp_avg_bytes_per_flow",
    "esp_largest_flow_share",
    "esp_fwd_packets",
    "esp_bwd_packets",
    "esp_fwd_bytes",
    "esp_bwd_bytes",
    "esp_fwd_packet_share",
    "esp_fwd_byte_share",
    "esp_iat_mean_s",
    "esp_iat_std_s",
    "esp_iat_max_s",
    "esp_span_s",
    "esp_seq_gap_total",
    "esp_seq_replay_total",
    "esp_nonmonotonic_flow_share",
    "esp_udp_encap_share",
    "ike_packet_count",
    "ike_exchange_count",
)


def _esp_payload(spi_int: int, sequence: int, opaque: bytes = ESP_OPAQUE) -> bytes:
    return struct.pack("!II", spi_int, sequence) + opaque


def _ipv4_frame(
    src: tuple[int, int, int, int],
    dst: tuple[int, int, int, int],
    protocol: int,
    payload: bytes,
    *,
    src_port: int = 0,
    dst_port: int = 0,
) -> bytes:
    """Ethernet/IPv4 frame with explicit addresses (direction tests need both)."""
    if protocol == 17:
        transport = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    elif protocol == 1:
        transport = b"\x08\x00\x00\x00" + payload
    else:
        transport = payload
    total_length = 20 + len(transport)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        protocol,
        0,
        bytes(src),
        bytes(dst),
    )
    ethernet = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
    return ethernet + ip_header + transport


HOST_A = (10, 10, 10, 1)
HOST_B = (10, 10, 10, 2)


def _ike_sa_init_frame() -> bytes:
    """Minimal valid IKEv2 IKE_SA_INIT header on UDP/500."""
    header = struct.pack(
        "!16sBBBBII",
        bytes.fromhex("11111111111111112222222222222222"),
        0,
        0x20,
        34,
        0x01,
        0,
        28,
    )
    return ethernet_ipv4(17, src_port=500, dst_port=500, payload=header)


def test_feature_schema_and_whitelist_are_locked() -> None:
    """Schema id and whitelist order are the versioned cross-stage contract."""
    assert FEATURE_SCHEMA == "fera_esp_features_v1"
    assert FEATURE_WHITELIST == EXPECTED_WHITELIST
    assert len(set(FEATURE_WHITELIST)) == len(FEATURE_WHITELIST)
    # labels/ground truth must never become model input features
    forbidden = ("label", "truth", "class", "target", "experiment_id", "traffic_type")
    assert not any(token in name for name in FEATURE_WHITELIST for token in forbidden)


def test_extract_features_matches_contract(tmp_path: Path) -> None:
    """The vector carries exactly the whitelist, ordered, finite floats."""
    frames = [
        ethernet_ipv4(50, payload=_esp_payload(0xAABBCCDD, 1)),
        ethernet_ipv4(50, payload=_esp_payload(0xAABBCCDD, 2)),
        ethernet_ipv4(50, payload=_esp_payload(0xAABBCCDD, 4)),
        ethernet_ipv4(1),
    ]
    vector = extract_features(write_pcap(tmp_path / "contract.pcap", frames))

    assert vector.schema == FEATURE_SCHEMA
    assert list(vector.features) == list(FEATURE_WHITELIST)
    assert len(vector.row()) == len(FEATURE_WHITELIST)
    assert all(type(value) is float for value in vector.row())  # noqa: E721 - exact type lock
    assert all(math.isfinite(value) for value in vector.row())
    assert vector.features["capture_packets"] == 4.0
    assert vector.features["esp_packets"] == 3.0
    assert vector.features["esp_flow_count"] == 1.0
    assert vector.features["esp_seq_gap_total"] == 1.0  # sequence 1, 2, 4 skips 3
    assert vector.features["esp_fwd_packets"] == 3.0  # single sender -> all forward
    assert vector.features["icmp_packet_share"] == 0.25
    assert vector.features["esp_packet_share"] == 0.75
    document = vector.to_dict()
    assert document["schema"] == FEATURE_SCHEMA
    assert set(document) == {"schema", "pcap_path", "features"}


def test_extract_features_is_deterministic(tmp_path: Path) -> None:
    """Same capture -> byte-identical feature values."""
    frames = [ethernet_ipv4(50, payload=_esp_payload(0x01020304, seq)) for seq in range(1, 5)]
    pcap = write_pcap(tmp_path / "det.pcap", frames)
    first = extract_features(pcap)
    second = extract_features(pcap)
    assert first.features == second.features
    assert first.row() == second.row()


def test_analysis_outcome_can_be_reused(tmp_path: Path) -> None:
    """Passing a precomputed Prompt 2 outcome yields the same vector."""
    frames = [ethernet_ipv4(50, payload=_esp_payload(0x11223344, 1))]
    pcap = write_pcap(tmp_path / "reuse.pcap", frames)
    outcome = analyze_pcap(pcap)
    assert extract_features(pcap, outcome=outcome).features == extract_features(pcap).features


def test_direction_features_follow_initiator_not_addresses(tmp_path: Path) -> None:
    """The first observed ESP sender defines forward, regardless of who it is."""
    a_to_b = _ipv4_frame(HOST_A, HOST_B, 50, _esp_payload(0xA0A0A0A0, 1))
    b_to_a = _ipv4_frame(HOST_B, HOST_A, 50, _esp_payload(0xB0B0B0B0, 1))
    b_to_a_again = _ipv4_frame(HOST_B, HOST_A, 50, _esp_payload(0xB0B0B0B0, 2))
    # first ESP packet is from B -> B is the initiator, B->A is "forward"
    vector = extract_features(write_pcap(tmp_path / "dir.pcap", [b_to_a, a_to_b, b_to_a_again]))
    assert vector.features["esp_fwd_packets"] == 2.0
    assert vector.features["esp_bwd_packets"] == 1.0
    assert vector.features["esp_fwd_packet_share"] == pytest.approx(2.0 / 3.0)


def test_direction_features_are_mirror_invariant(tmp_path: Path) -> None:
    """Swapping every src/dst pair yields identical features (normalisation)."""
    forward = [
        _ipv4_frame(HOST_A, HOST_B, 50, _esp_payload(0xC0C0C0C0, 1)),
        _ipv4_frame(HOST_B, HOST_A, 50, _esp_payload(0xD0D0D0D0, 1)),
        _ipv4_frame(HOST_A, HOST_B, 50, _esp_payload(0xC0C0C0C0, 2)),
    ]
    mirrored = [
        _ipv4_frame(HOST_B, HOST_A, 50, _esp_payload(0xC0C0C0C0, 1)),
        _ipv4_frame(HOST_A, HOST_B, 50, _esp_payload(0xD0D0D0D0, 1)),
        _ipv4_frame(HOST_B, HOST_A, 50, _esp_payload(0xC0C0C0C0, 2)),
    ]
    original = extract_features(write_pcap(tmp_path / "orig.pcap", forward))
    flipped = extract_features(write_pcap(tmp_path / "mirror.pcap", mirrored))
    assert original.features == flipped.features


def test_timing_features_from_frame_timestamps(tmp_path: Path) -> None:
    """Duration and IATs come from PCAP frame headers (1s spacing in fixture)."""
    frames = [ethernet_ipv4(50, payload=_esp_payload(0x0A0B0C0D, seq)) for seq in (1, 2, 3)]
    vector = extract_features(write_pcap(tmp_path / "timing.pcap", frames))
    # write_pcap stamps frames at 1700000000 + index seconds
    assert vector.features["capture_duration_s"] == pytest.approx(2.0)
    assert vector.features["esp_span_s"] == pytest.approx(2.0)
    assert vector.features["esp_iat_mean_s"] == pytest.approx(1.0)
    assert vector.features["esp_iat_max_s"] == pytest.approx(1.0)
    assert vector.features["esp_iat_std_s"] == pytest.approx(0.0)
    assert vector.features["packet_rate_pps"] == pytest.approx(1.5)  # 3 packets / 2 s


def test_zero_esp_capture_yields_zeroed_esp_features(tmp_path: Path) -> None:
    """A capture without ESP still produces a valid, fully finite vector."""
    vector = extract_features(write_pcap(tmp_path / "noesp.pcap", [ethernet_ipv4(1), ethernet_ipv4(1)]))
    assert vector.features["esp_packets"] == 0.0
    assert vector.features["esp_flow_count"] == 0.0
    assert vector.features["esp_fwd_packet_share"] == 0.0
    assert vector.features["esp_iat_mean_s"] == 0.0
    assert vector.features["icmp_packet_share"] == 1.0
    assert vector.features["esp_packet_share"] == 0.0
    assert all(math.isfinite(value) for value in vector.row())  # no NaN from divisions


def test_sequence_health_features(tmp_path: Path) -> None:
    """Gaps, replays and monotonicity flow through from Prompt 2 flow stats."""
    frames = [
        ethernet_ipv4(50, payload=_esp_payload(0xAABBCCDD, 1)),
        ethernet_ipv4(50, payload=_esp_payload(0xAABBCCDD, 2)),
        ethernet_ipv4(50, payload=_esp_payload(0xAABBCCDD, 4)),  # gap of 1
        ethernet_ipv4(50, payload=_esp_payload(0xAABBCCDD, 4)),  # replay
        ethernet_ipv4(17, src_port=4500, dst_port=4500, payload=_esp_payload(0x11223344, 1)),
        ethernet_ipv4(17, src_port=4500, dst_port=4500, payload=_esp_payload(0x11223344, 1)),
    ]
    vector = extract_features(write_pcap(tmp_path / "health.pcap", frames))
    assert vector.features["esp_packets"] == 6.0
    assert vector.features["esp_flow_count"] == 2.0
    assert vector.features["esp_seq_gap_total"] == 1.0
    assert vector.features["esp_seq_replay_total"] == 2.0  # seq 4 twice + seq 1 twice
    assert vector.features["esp_nonmonotonic_flow_share"] == 0.0
    assert vector.features["esp_udp_encap_share"] == pytest.approx(2.0 / 6.0)
    assert vector.features["esp_largest_flow_share"] == pytest.approx(4.0 / 6.0)


def test_ike_context_features(tmp_path: Path) -> None:
    """IKE packets and decoded exchanges are visible as context features."""
    frames = [
        _ike_sa_init_frame(),
        ethernet_ipv4(50, payload=_esp_payload(0xAABBCCDD, 1)),
    ]
    vector = extract_features(write_pcap(tmp_path / "ike.pcap", frames))
    assert vector.features["ike_packet_count"] == 1.0
    assert vector.features["ike_exchange_count"] == 1.0
    assert vector.features["ike_packet_share"] == pytest.approx(0.5)


def test_extraction_has_no_label_inputs(tmp_path: Path) -> None:
    """Ground truth / labels are structurally impossible to pass in."""
    signature = inspect.signature(extract_features)
    assert set(signature.parameters) == {"pcap_path", "outcome"}
    frames = [ethernet_ipv4(50, payload=_esp_payload(0xDEADBEEF, 1))]
    document = extract_features(write_pcap(tmp_path / "nolabel.pcap", frames)).to_dict()
    assert "traffic_type" not in document
    assert "label" not in document
    assert set(document) == {"schema", "pcap_path", "features"}


def test_vector_rejects_whitelist_drift(tmp_path: Path) -> None:
    """A vector missing or carrying extra keys cannot be constructed."""
    frames = [ethernet_ipv4(50, payload=_esp_payload(0xABCD1234, 1))]
    good = extract_features(write_pcap(tmp_path / "drift.pcap", frames))

    missing = dict(good.features)
    missing.pop(next(iter(missing)))
    with pytest.raises(FeraError) as missing_info:
        FeatureVector(pcap_path="x.pcap", features=missing)
    assert missing_info.value.code is ErrorCode.INTERNAL_ERROR
    assert missing_info.value.details["missing"]

    extra = dict(good.features)
    extra["ground_truth_label"] = "web"
    with pytest.raises(FeraError) as extra_info:
        FeatureVector(pcap_path="x.pcap", features=extra)
    assert extra_info.value.details["extra"] == ["ground_truth_label"]


def test_vector_rejects_non_finite_values(tmp_path: Path) -> None:
    """NaN / inf / non-numeric values never reach training or inference."""
    frames = [ethernet_ipv4(50, payload=_esp_payload(0xABCD1234, 1))]
    good = extract_features(write_pcap(tmp_path / "finite.pcap", frames))

    for bad_value in (float("nan"), float("inf"), float("-inf"), "0.5", None, True):
        broken = dict(good.features)
        broken["esp_packets"] = bad_value
        with pytest.raises(FeraError):
            FeatureVector(pcap_path="x.pcap", features=broken)


def test_empty_capture_raises_structured_error(tmp_path: Path) -> None:
    """A truncated/empty file fails with the shared FeraError contract."""
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    with pytest.raises(FeraError) as error_info:
        extract_features(empty)
    assert error_info.value.code is ErrorCode.CAPTURE_EMPTY

