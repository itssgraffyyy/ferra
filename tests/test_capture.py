"""Capture orchestration, PCAP scanning, filter and sanity-check tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import (
    TSHARK_PHS,
    ScriptedRunner,
    command_contains,
    ethernet_ipv4,
    ike_and_esp_frames,
    write_pcap,
)
from fera.capture.capture import (
    CaptureSession,
    build_capture_command,
    capture_file_stats,
    select_capture_tool,
)
from fera.capture.filters import default_capture_filter, validate_bpf_filter
from fera.capture.pcap_scan import scan_pcap
from fera.capture.sanity import (
    ValidationStatus,
    parse_tshark_protocol_hierarchy,
    validate_capture,
)
from fera.common.errors import ConfigValidationError, ErrorCode, FeraError


# --- command construction ---------------------------------------------------
def test_tcpdump_command_is_built_safely(tmp_path: Path) -> None:
    command = build_capture_command(
        "tcpdump",
        interface="fera-va",
        output_path=tmp_path / "capture.pcap",
        bpf_filter="esp or (udp port 500)",
        snaplen=0,
    )
    assert command[:7] == ["tcpdump", "-i", "fera-va", "-n", "-s", "0", "-U"]
    assert command[7] == "-w"
    assert command[-1] == "esp or (udp port 500)"
    assert all(isinstance(part, str) for part in command)


def test_dumpcap_command_uses_filter_option(tmp_path: Path) -> None:
    command = build_capture_command(
        "dumpcap",
        interface="eth0",
        output_path=tmp_path / "capture.pcap",
        bpf_filter="esp",
    )
    assert command[:2] == ["dumpcap", "-i"]
    assert "-f" in command
    assert command[command.index("-f") + 1] == "esp"


def test_unknown_capture_tool_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(FeraError) as error:
        build_capture_command("wireshark", interface="eth0", output_path=tmp_path / "x.pcap")
    assert error.value.code is ErrorCode.CAPTURE_TOOL_NOT_AVAILABLE


def test_missing_capture_tool_is_reported() -> None:
    runner = ScriptedRunner(available_tools=("swanctl",))
    with pytest.raises(FeraError) as error:
        select_capture_tool(runner)
    assert error.value.code is ErrorCode.CAPTURE_TOOL_NOT_AVAILABLE


# --- filter validation -----------------------------------------------------
def test_filter_validation_rejects_shell_metacharacters() -> None:
    for bad in ("esp; rm -rf /", "esp `id`", "esp $(id)", "esp\nrm"):
        with pytest.raises(ConfigValidationError):
            validate_bpf_filter(bad)


def test_filter_validation_accepts_normal_expressions() -> None:
    expression = "esp or (udp port 500) or (udp port 4500) or icmp"
    assert validate_bpf_filter(expression) == expression
    assert "esp" in default_capture_filter(ip_version=4)
    assert "ip6 proto 58" in default_capture_filter(ip_version=6)


# --- session behaviour -----------------------------------------------------
def test_capture_session_prefixes_command_and_validates_output(tmp_path: Path) -> None:
    runner = ScriptedRunner()
    session = CaptureSession(
        output_path=tmp_path / "capture.pcap",
        interface="fera-va",
        bpf_filter="esp",
        runner=runner,
        log_path=tmp_path / "capture.log",
        command_prefix=("ip", "netns", "exec", "fera-a"),
        require_privileges=False,
    )
    plan = session.start()
    assert plan.command[:4] == ("ip", "netns", "exec", "fera-a")
    assert command_contains(plan.command, "tcpdump", "-w")
    result = session.stop()
    assert result.usable is True
    assert result.error_code is None
    assert result.exists and result.size_bytes > 24
    assert runner.spawned and runner.spawned[0] == plan.command


def test_capture_session_flags_an_empty_capture(tmp_path: Path) -> None:
    runner = ScriptedRunner(capture_frames=[])
    session = CaptureSession(
        output_path=tmp_path / "capture.pcap",
        interface="any",
        runner=runner,
        log_path=tmp_path / "capture.log",
        require_privileges=False,
    )
    session.start()
    result = session.stop()
    assert result.error_code is ErrorCode.CAPTURE_EMPTY
    assert result.usable is False


def test_capture_file_stats() -> None:
    assert capture_file_stats("does-not-exist.pcap") == (False, 0)


# --- pcap scanning ---------------------------------------------------------
def test_scan_pcap_counts_ike_esp_and_ip_versions(tmp_path: Path) -> None:
    path = write_pcap(tmp_path / "capture.pcap", ike_and_esp_frames())
    scan = scan_pcap(path)
    assert scan.packets == 7
    assert scan.ike_packets == 3  # two IPv4 + one IPv6 frame on UDP 500/4500
    assert scan.esp_packets == 3
    assert scan.ipv4_packets == 5
    assert scan.ipv6_packets == 2
    assert scan.icmp_packets == 1
    assert scan.file_format == "pcap"


def test_scan_pcap_rejects_a_corrupt_file(tmp_path: Path) -> None:
    corrupt = tmp_path / "capture.pcap"
    corrupt.write_bytes(b"not a pcap file at all........")
    with pytest.raises(FeraError) as error:
        scan_pcap(corrupt)
    assert error.value.code in {ErrorCode.CAPTURE_VALIDATION_FAILED, ErrorCode.CAPTURE_EMPTY}


def test_scan_pcap_reports_pcapng_as_unsupported(tmp_path: Path) -> None:
    pcapng = tmp_path / "capture.pcapng"
    pcapng.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 64)
    with pytest.raises(FeraError) as error:
        scan_pcap(pcapng)
    assert error.value.code is ErrorCode.UNSUPPORTED_FEATURE


def test_scan_pcap_handles_raw_ip_link_type(tmp_path: Path) -> None:
    import struct

    from fera.capture.pcap_scan import PCAP_MAGIC_LE

    frame = ethernet_ipv4(50, payload=b"\x00" * 32)[14:]
    body = bytearray(
        struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 101)  # LINKTYPE_RAW
    )
    body += struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)) + frame
    path = tmp_path / "raw.pcap"
    path.write_bytes(bytes(body))
    assert PCAP_MAGIC_LE  # sanity: magic constant is exported
    scan = scan_pcap(path)
    assert scan.esp_packets == 1
    assert scan.linktype_name == "RAW_IP"


# --- validation ------------------------------------------------------------
def test_validate_capture_accepts_expected_content(tmp_path: Path) -> None:
    path = write_pcap(tmp_path / "capture.pcap", ike_and_esp_frames())
    result = validate_capture(path, expected_ip_version=4, use_tshark=False)
    assert result.status is ValidationStatus.VALID
    assert result.ike_detected and result.esp_detected
    assert result.method == "pcap_scan"
    assert any("tshark is not installed" in reason for reason in result.reasons)


def test_validate_capture_rejects_wrong_ip_version(tmp_path: Path) -> None:
    path = write_pcap(tmp_path / "capture.pcap", [ethernet_ipv4(50, payload=b"\x00" * 32)])
    result = validate_capture(path, expected_ip_version=6, use_tshark=False)
    assert result.status is ValidationStatus.INVALID
    assert any("IPv6" in reason for reason in result.reasons)


def test_validate_capture_rejects_a_capture_without_esp(tmp_path: Path) -> None:
    path = write_pcap(tmp_path / "capture.pcap", [ethernet_ipv4(17, src_port=500, dst_port=500)])
    result = validate_capture(path, expected_ip_version=4, use_tshark=False)
    assert result.status is ValidationStatus.INVALID
    assert result.ike_detected and not result.esp_detected


def test_validate_capture_rejects_an_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"\x00" * 8)
    result = validate_capture(path, use_tshark=False)
    assert result.status is ValidationStatus.INVALID
    assert "empty" in result.reasons[0]


def test_validate_capture_reports_missing_file(tmp_path: Path) -> None:
    result = validate_capture(tmp_path / "nope.pcap", use_tshark=False)
    assert result.status is ValidationStatus.INVALID
    assert "does not exist" in result.reasons[0]


def test_tshark_evidence_is_used_when_available(tmp_path: Path) -> None:
    path = write_pcap(tmp_path / "capture.pcap", ike_and_esp_frames())
    runner = ScriptedRunner(responses=[("tshark", 0, TSHARK_PHS)])
    result = validate_capture(path, expected_ip_version=4, runner=runner)
    assert "tshark" in result.method
    assert result.details["tshark_protocol_frames"]["isakmp"] == 2
    assert result.status is ValidationStatus.VALID
    assert result.render_text().count("IKE detected: YES") == 1


def test_parse_tshark_protocol_hierarchy() -> None:
    counts = parse_tshark_protocol_hierarchy(TSHARK_PHS)
    assert counts["isakmp"] == 2
    assert counts["esp"] == 2
    assert counts["ip"] == 5
    assert counts["ipv6"] == 2


def test_validation_result_serialises(tmp_path: Path) -> None:
    result = validate_capture(
        write_pcap(tmp_path / "capture.pcap", ike_and_esp_frames()), use_tshark=False
    )
    payload = result.to_dict()
    assert payload["status"] == "VALID"
    assert payload["valid"] is True
    assert payload["packets"] == 7

