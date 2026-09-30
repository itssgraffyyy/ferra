"""Bounded live capture: validation, command shape and failure mapping.

The subprocess boundary is mocked (a real capture needs root and a Linux
capture tool).  What these tests pin down is everything FERA controls: the
argument array, the bounds, and the specific error each environment failure
produces.  No test here asserts that a real packet capture succeeded.
"""

from __future__ import annotations

import pytest

from fera.capture.live import (
    CAPTURE_TOOLS,
    DEFAULT_DURATION_S,
    MAX_DURATION_S,
    MAX_PACKET_COUNT,
    MIN_DURATION_S,
    build_command,
    capture_live,
    classify_failure,
    find_capture_tool,
    live_capture_available,
    validate_duration,
    validate_filter,
    validate_interface,
)
from fera.common.errors import ErrorCode, FeraError
from fera.common.process import CommandResult, RecordingRunner


class _CaptureRunner(RecordingRunner):
    """Runner that writes a real PCAP where the capture tool would write one."""

    def __init__(self, frames, *, returncode=0, stderr="", timed_out=False, tools=("tcpdump",)):
        super().__init__(available_tools=tools)
        self._frames = frames
        self._result = (returncode, stderr, timed_out)

    def run(self, command, *, timeout=60.0, check=False, **kwargs):  # noqa: ARG002
        cmd = tuple(str(part) for part in command)
        self.commands.append(cmd)
        target = cmd[cmd.index("-w") + 1]
        with open(target, "wb") as handle:
            handle.write(self._frames)
        returncode, stderr, timed_out = self._result
        return CommandResult(cmd, returncode, "", stderr, 0.01, timed_out=timed_out)


# --- validation ------------------------------------------------------------


@pytest.mark.parametrize("name", ["eth0", "wlan0", "any", "lo", "enp3s0", "veth-test"])
def test_valid_interfaces_are_accepted(name):
    assert validate_interface(name) == name


@pytest.mark.parametrize(
    "name",
    ["", "   ", "eth0; rm -rf /", "../../etc/passwd", "eth 0", "a" * 40, "$(id)", "eth0|cat"],
)
def test_hostile_or_invalid_interfaces_are_refused(name):
    with pytest.raises(FeraError) as excinfo:
        validate_interface(name)
    assert excinfo.value.code is ErrorCode.CONFIG_VALIDATION_FAILED


def test_duration_bounds():
    assert validate_duration(MIN_DURATION_S) == MIN_DURATION_S
    assert validate_duration(MAX_DURATION_S) == MAX_DURATION_S
    assert validate_duration(DEFAULT_DURATION_S) == DEFAULT_DURATION_S


@pytest.mark.parametrize("value", [0, -1, MAX_DURATION_S + 1, 3600, "abc", None])
def test_out_of_range_durations_are_refused(value):
    with pytest.raises(FeraError) as excinfo:
        validate_duration(value)
    assert excinfo.value.code is ErrorCode.CONFIG_VALIDATION_FAILED


def test_capture_filter_is_validated():
    assert validate_filter(None) is None
    assert validate_filter("  ") is None
    assert validate_filter("udp port 500 or ip proto 50") == "udp port 500 or ip proto 50"
    with pytest.raises(FeraError):
        validate_filter("tcp; rm -rf /")


# --- command construction --------------------------------------------------


def test_command_is_an_argument_array_with_a_stop_condition(tmp_path):
    command = build_command("/usr/bin/tcpdump", "eth0", tmp_path / "out.pcap", duration_s=10)
    assert command[0] == "/usr/bin/tcpdump"
    assert command[command.index("-i") + 1] == "eth0"
    assert command[command.index("-c") + 1] == str(MAX_PACKET_COUNT)
    assert "-G" in command, "tcpdump needs a rotation bound to stop on its own"
    assert all(isinstance(part, str) for part in command), "no part may be a shell string"


def test_dumpcap_uses_its_own_stop_flag(tmp_path):
    assert "duration:7" in build_command("/usr/bin/dumpcap", "eth0", tmp_path / "o.pcap", duration_s=7)


def test_filter_is_appended_as_one_argument(tmp_path):
    command = build_command("/usr/bin/tcpdump", "eth0", tmp_path / "o.pcap", duration_s=5, capture_filter="ip proto 50")
    assert command[-1] == "ip proto 50"




# --- failure mapping -------------------------------------------------------


@pytest.mark.parametrize(
    ("stderr", "timed_out", "expected"),
    [
        ("tcpdump: You don't have permission", False, ErrorCode.INSUFFICIENT_PRIVILEGES),
        ("Operation not permitted", False, ErrorCode.INSUFFICIENT_PRIVILEGES),
        ("", True, ErrorCode.TIMEOUT),
        ("no such device exists", False, ErrorCode.CAPTURE_START_FAILED),
    ],
)
def test_failures_map_to_specific_codes(stderr, timed_out, expected):
    result = CommandResult(("tcpdump",), 1, "", stderr, 0.1, timed_out=timed_out)
    assert classify_failure(result, tool="tcpdump", duration_s=5).code is expected


# --- end to end (mocked subprocess) ----------------------------------------


def test_capture_produces_a_file(tmp_path):
    from conftest import ike_and_esp_frames, write_pcap

    seed = tmp_path / "seed.pcap"
    write_pcap(seed, ike_and_esp_frames())
    capture = capture_live("eth0", duration_s=3, target_dir=tmp_path / "out", runner=_CaptureRunner(seed.read_bytes()))
    assert capture.path.is_file()
    assert capture.size_bytes > 0
    assert (capture.interface, capture.duration_s, capture.tool) == ("eth0", 3, "tcpdump")


def test_failed_capture_leaves_no_file_behind(tmp_path):
    with pytest.raises(FeraError):
        capture_live(
            "eth0",
            duration_s=3,
            target_dir=tmp_path,
            runner=_CaptureRunner(b"\x00" * 32, returncode=1, stderr="no such device"),
        )
    assert list(tmp_path.glob("live_*")) == []


def test_empty_capture_is_refused_and_cleaned(tmp_path):
    """An empty PCAP would look like 'nothing happened'; it is an error instead."""
    with pytest.raises(FeraError) as excinfo:
        capture_live("eth0", duration_s=3, target_dir=tmp_path, runner=_CaptureRunner(b""))
    assert excinfo.value.code is ErrorCode.CAPTURE_EMPTY
    assert list(tmp_path.glob("live_*")) == []


def test_invalid_arguments_fail_before_any_process_starts(tmp_path):
    runner = _CaptureRunner(b"")
    with pytest.raises(FeraError):
        capture_live("bad;iface", duration_s=3, target_dir=tmp_path, runner=runner)
    with pytest.raises(FeraError):
        capture_live("eth0", duration_s=9999, target_dir=tmp_path, runner=runner)
    assert runner.commands == [], "no capture tool may run with rejected arguments"

# --- tool discovery --------------------------------------------------------


def test_missing_tool_is_reported_with_what_was_searched():
    runner = RecordingRunner(available_tools=())
    available, reason = live_capture_available(runner)
    assert available is False
    assert reason
    with pytest.raises(FeraError) as excinfo:
        find_capture_tool(runner)
    assert excinfo.value.code is ErrorCode.TOOL_NOT_AVAILABLE
    assert excinfo.value.details["searched"] == list(CAPTURE_TOOLS)


def test_present_tool_is_found():
    assert find_capture_tool(RecordingRunner(available_tools=("tcpdump",)))
