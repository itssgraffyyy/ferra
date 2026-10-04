"""Environment detection and safe-subprocess tests."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from conftest import ScriptedRunner
from fera.common.errors import ErrorCode, FeraError
from fera.common.process import (
    CommandResult,
    RecordingRunner,
    SubprocessRunner,
    format_command,
    run_command,
)
from fera.common.versions import parse_version
from fera.testbed.environment import (
    CheckStatus,
    EnvironmentReport,
    _check_charon,
    check_environment,
    is_wsl,
    list_interfaces,
    write_environment_report,
)


# --- safe subprocess handling ----------------------------------------------
def test_format_command_quotes_arguments_for_display() -> None:
    assert format_command(["tcpdump", "-i", "any", "esp or icmp"]) == "tcpdump -i any 'esp or icmp'"


def test_run_command_executes_a_real_process() -> None:
    result = run_command([sys.executable, "-c", "print('hello')"], timeout=30)
    assert result.ok
    assert "hello" in result.stdout
    assert result.executed is True


def test_run_command_reports_a_nonzero_exit_code() -> None:
    result = run_command([sys.executable, "-c", "raise SystemExit(3)"], timeout=30)
    assert result.ok is False
    assert result.returncode == 3


def test_run_command_timeout_is_explicit() -> None:
    result = run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
    assert result.timed_out is True
    assert result.ok is False


def test_missing_tool_raises_with_error_code() -> None:
    with pytest.raises(FeraError) as error:
        SubprocessRunner().run(["definitely-not-a-real-tool-xyz"], timeout=5)
    assert error.value.code is ErrorCode.TOOL_NOT_AVAILABLE


def test_recording_runner_does_not_execute_anything() -> None:
    runner = RecordingRunner()
    result = runner.run(["tcpdump", "-i", "any"])
    assert result.executed is False
    assert result.ok is False  # a command that was not executed is not "ok"
    assert runner.commands == [("tcpdump", "-i", "any")]


def test_recording_runner_raises_when_check_is_requested() -> None:
    runner = RecordingRunner(
        result_factory=lambda command: CommandResult(command, 1, "", "boom", 0.0, executed=False)
    )
    with pytest.raises(FeraError):
        runner.run(["swanctl", "--list-sas"], check=True)


# --- charon / VICI probing --------------------------------------------------


class _ViciRunner:
    """Runner returning a scripted ``swanctl --stats`` outcome."""

    name = "vici"

    def __init__(self, *, tools=("swanctl",), returncode=0, timed_out=False, stderr="") -> None:
        self._tools = tuple(tools)
        self._returncode = returncode
        self._timed_out = timed_out
        self._stderr = stderr

    def which(self, tool):
        return f"/usr/bin/{tool}" if tool in self._tools else None

    def run(self, command, **_kwargs):
        return CommandResult(
            tuple(str(part) for part in command),
            self._returncode,
            "",
            self._stderr,
            15.0,
            executed=True,
            timed_out=self._timed_out,
        )


def test_charon_is_available_when_the_daemon_answers() -> None:
    result = _check_charon(_ViciRunner())
    assert result.status is CheckStatus.AVAILABLE
    assert "reachable" in result.detail


def test_charon_is_missing_when_swanctl_is_absent() -> None:
    result = _check_charon(_ViciRunner(tools=()))
    assert result.status is CheckStatus.MISSING
    assert "swanctl is missing" in result.detail


def test_charon_is_missing_when_no_daemon_answers() -> None:
    result = _check_charon(_ViciRunner(returncode=1, stderr="no such file or directory"))
    assert result.status is CheckStatus.MISSING
    assert "no daemon" in result.detail


def test_an_unresponsive_daemon_is_unverified_not_missing() -> None:
    """A daemon that never answers is not the same as no daemon at all.

    Both look like a failed ``swanctl --stats``, but they need different fixes.
    Reporting MISSING for a hung daemon names a cause that is not the cause and
    sends the operator to install or start strongSwan for no reason.
    """
    result = _check_charon(_ViciRunner(timed_out=True))
    assert result.status is CheckStatus.UNVERIFIED
    assert "unresponsive" in result.detail
    assert "not the same as no daemon" in result.detail
    assert "no daemon on the default vici socket" not in result.detail


def test_command_result_serialisation_keeps_tails() -> None:
    result = CommandResult(("swanctl", "--stats"), 0, "x" * 5000, "", 1.5)
    payload = result.to_dict()
    assert payload["ok"] is True
    assert len(payload["stdout_tail"]) == 2000
    assert payload["display"] == "swanctl --stats"


# --- version parsing --------------------------------------------------------
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("tcpdump version 4.99.4\nlibpcap version 1.10.4", "4.99.4"),
        ("TShark (Wireshark) 4.2.2 (Git v4.2.2)", "4.2.2"),
        ("iperf 3.16 (cJSON 1.7.15)", "3.16"),
        ("", None),
        (None, None),
    ],
)
def test_parse_version(raw: str | None, expected: str | None) -> None:
    assert parse_version(raw) == expected


def test_environment_report_marks_windows_platform_unsupported(repo_paths) -> None:
    report = check_environment(repo_paths, ScriptedRunner(), include_tool_versions=False)
    platform_check = report.check("platform")
    assert platform_check is not None
    if os.name == "nt":
        assert platform_check.status is CheckStatus.UNSUPPORTED
        assert platform_check.blocking is True
    else:
        assert platform_check.status is CheckStatus.AVAILABLE

def test_report_has_explicit_statuses_and_summary(repo_paths) -> None:
    report = check_environment(repo_paths, ScriptedRunner(), include_tool_versions=False)
    assert isinstance(report, EnvironmentReport)
    assert report.checks
    for check in report.checks:
        assert isinstance(check.status, CheckStatus)
        assert check.detail
    counts = report.summary()
    assert counts["blocking"] == len(report.blocking_checks)
    assert set(counts) >= {"AVAILABLE", "MISSING", "UNVERIFIED", "UNSUPPORTED", "NOT_APPLICABLE", "blocking"}


def test_report_is_serialisable_and_renderable(repo_paths) -> None:
    report = check_environment(repo_paths, ScriptedRunner(), include_tool_versions=True)
    payload = report.to_dict()
    assert payload["schema_version"] == 1
    assert isinstance(payload["checks"], list) and payload["checks"]
    assert "host" in payload and "tool_versions" in payload
    rendered = report.render_text()
    assert "FERA environment report" in rendered
    assert "summary:" in rendered
    assert ("READY" in rendered) or ("NOT READY" in rendered)


def test_blocking_environment_cannot_pass_require_ready(repo_paths) -> None:
    """An unknown capture interface must block, on every platform."""
    report = check_environment(
        repo_paths,
        ScriptedRunner(),
        capture_interface="definitely-not-a-real-interface",
        include_tool_versions=False,
    )
    assert report.ready is False
    assert report.blocker_reason()
    with pytest.raises(FeraError) as error:
        report.require_ready()
    assert error.value.code is not None
    assert error.value.details["blocking_checks"]


def test_missing_strongswan_is_reported_as_such(repo_paths) -> None:
    report = check_environment(repo_paths, ScriptedRunner(available_tools=()), include_tool_versions=False)
    swanctl = report.check("swanctl")
    assert swanctl is not None
    assert swanctl.status is CheckStatus.MISSING
    assert swanctl.required is True
    assert "strongSwan" in (swanctl.remediation or "")


def test_capture_tool_fallback_to_dumpcap(repo_paths) -> None:
    report = check_environment(
        repo_paths, ScriptedRunner(available_tools=("dumpcap",)), include_tool_versions=False
    )
    capture = report.check("capture_tool")
    assert capture is not None
    assert capture.status is CheckStatus.AVAILABLE
    assert "dumpcap" in capture.detail


def test_ipv6_can_be_required_or_optional(repo_paths) -> None:
    optional = check_environment(repo_paths, ScriptedRunner(), include_tool_versions=False)
    required = check_environment(
        repo_paths, ScriptedRunner(), expected_ip_version=6, include_tool_versions=False
    )
    assert optional.check("ipv6").required is False
    assert required.check("ipv6").required is True


def test_wsl_detection_does_not_crash() -> None:
    assert isinstance(is_wsl(), bool)


def test_interface_listing_returns_names_on_linux() -> None:
    names = list_interfaces()
    assert isinstance(names, list)
    if sys.platform.startswith("linux"):
        assert "lo" not in names


def test_write_environment_report(tmp_path: Path, repo_paths) -> None:
    report = check_environment(repo_paths, ScriptedRunner(), include_tool_versions=False)
    target = write_environment_report(report, tmp_path / "environment.json")
    assert target.is_file()
    assert '"schema_version"' in target.read_text(encoding="utf-8")
