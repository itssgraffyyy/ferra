"""strongSwan control plane (``swanctl``) command construction tests."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from fera.common.process import CommandResult, RecordingRunner
from fera.testbed.ipsec_control import IpsecController

URI = "unix:///run/fera-testbed/charon-a.vici"


def _executed_ok(command: tuple[str, ...]) -> CommandResult:
    """A recorded command that counts as successfully executed."""
    return CommandResult(command, 0, "", "", 0.0, executed=True)


def make_controller(
    *, uri: str | None = URI, prefix: tuple[str, ...] = ()
) -> tuple[RecordingRunner, IpsecController]:
    runner = RecordingRunner(result_factory=_executed_ok)
    controller = IpsecController(
        runner,
        endpoint_label="a",
        command_prefix=prefix,
        uri=uri,
    )
    return runner, controller


def test_uri_is_placed_after_the_subcommand() -> None:
    """swanctl only parses its general options after the subcommand.

    ``swanctl --uri <uri> --stats`` exits with ``unrecognized option '--uri'``,
    so a leading ``--uri`` makes every control call fail and the daemon look
    unreachable even though it is running.
    """
    runner, controller = make_controller()
    assert controller.command("--stats") == ["swanctl", "--stats", "--uri", URI]
    assert runner.commands == []


def test_command_without_a_uri_has_no_uri_flag() -> None:
    _, controller = make_controller(uri=None)
    assert controller.command("--stats") == ["swanctl", "--stats"]


def test_command_prefix_precedes_swansctl_and_uri_stays_last() -> None:
    _, controller = make_controller(prefix=("ip", "netns", "exec", "fera-a"))
    command = controller.command("--list-sas")
    assert command[:5] == ["ip", "netns", "exec", "fera-a", "swanctl"]
    assert command[-2:] == ["--uri", URI]


def test_load_connections_keeps_the_file_flag_before_the_uri() -> None:
    runner, controller = make_controller()
    controller.load_connections(Path("/tmp/fera-conn.conf"))
    command = list(runner.commands[-1])
    assert command[:4] == ["swanctl", "--load-conns", "--file", "/tmp/fera-conn.conf"]
    assert command[-2:] == ["--uri", URI]


def test_initiate_places_the_uri_after_the_child_name() -> None:
    runner, controller = make_controller()
    controller.initiate(child="fera-child")
    assert list(runner.commands[-1]) == [
        "swanctl",
        "--initiate",
        "--child",
        "fera-child",
        "--uri",
        URI,
    ]


@pytest.mark.skipif(shutil.which("swanctl") is None, reason="swanctl is not installed")
def test_swansctl_accepts_the_generated_option_order() -> None:
    """Let swanctl itself check the order: only it knows its option grammar.

    ``--uri`` is a *subcommand* option, so it only parses after the subcommand.
    The probe uses ``--list-sas`` because ``--version`` returns before option
    parsing and would accept anything, proving nothing.

    ``--list-sas`` on a socket that does not exist still proves the point: the
    error must be a *connection* error, never an *option* error.
    """
    result = subprocess.run(
        ["swanctl", "--list-sas", "--uri", "unix:///tmp/fera-does-not-exist.vici"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    output = (result.stdout or "") + (result.stderr or "")
    assert "unrecognized option" not in output, output
    assert "fera-does-not-exist.vici" in output, output


@pytest.mark.skipif(shutil.which("swanctl") is None, reason="swanctl is not installed")
def test_uri_before_the_subcommand_is_rejected() -> None:
    """The ordering FERA uses is the only ordering swanctl accepts."""
    result = subprocess.run(
        ["swanctl", "--uri", "unix:///tmp/fera-does-not-exist.vici", "--list-sas"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    output = (result.stdout or "") + (result.stderr or "")
    assert "unrecognized option '--uri'" in output, output

