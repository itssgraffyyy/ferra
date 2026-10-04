"""Unit tests for remote (two-VM / SSH) endpoint preflight.

Every SSH interaction here is fake.  Nothing in this file opens a socket, and no
test can make an experiment look successful: the fakes only prove that FERA
*asks* the right questions and refuses to invent answers.
"""

from __future__ import annotations

import pytest

from fera.common.errors import ErrorCode, FeraError
from fera.common.process import CommandResult
from fera.testbed.remote_preflight import (
    PASS,
    REQUIRED_COMMANDS,
    preflight_endpoint,
    require_remote_endpoints_ready,
)
from fera.testbed.topology import endpoint_from_dict, topology_from_dict

_LINK = (
    "2: enp0s8: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state UP\n"
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
)
_ADDR = "2: enp0s8    inet 10.10.10.1/24 brd 10.10.10.255 scope global enp0s8\n"


def _endpoint(**overrides):
    data = {
        "name": "endpoint-a",
        "role": "initiator",
        "kind": "ssh",
        "ssh_host": "10.0.2.15",
        "ssh_user": "fera",
        "ssh_port": 2221,
        "capture_interface": "enp0s8",
        "outer_ipv4": "10.10.10.1/24",
    }
    data.update(overrides)
    return endpoint_from_dict(data)


class _FakeRunner:
    """Answers by matching substrings of the joined command."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.commands: list[tuple[str, ...]] = []

    def run(self, command, *, timeout=60.0, check=False, **kwargs):  # noqa: ANN001, ANN201, ARG002
        cmd = tuple(str(part) for part in command)
        self.commands.append(cmd)
        joined = " ".join(cmd)
        for needle, rc, stdout, stderr in self.responses:
            if needle in joined:
                return CommandResult(cmd, rc, stdout, stderr, 0.01, executed=True)
        return CommandResult(cmd, 0, "", "", 0.01, executed=True)


def _all_good(*, peer_ok: bool = True):
    return _FakeRunner(
        [
            ("command -v", 0, "", ""),
            ("swanctl --version", 0, "5.9.13", ""),
            ("swanctl --list-sas", 0, "", ""),
            ("-o link show", 0, _LINK, ""),
            ("-o addr show", 0, _ADDR, ""),
            ("tcpdump --version", 0, "tcpdump 4.99", ""),
            ("ping", 0 if peer_ok else 1, "", ""),
        ]
    )
def test_preflight_passes_when_the_endpoint_is_reachable_and_capable() -> None:
    result = preflight_endpoint(_endpoint(), _all_good(), peer="10.10.10.2")
    assert result.reachable is True
    assert result.ready is True
    names = {c["name"] for c in result.checks}
    assert {"ssh", "commands", "swanctl", "vici", "interface", "address", "capture", "peer"} <= names


def test_every_probe_runs_through_the_ssh_prefix() -> None:
    runner = _all_good()
    preflight_endpoint(_endpoint(), runner, peer="10.10.10.2")
    assert runner.commands
    for cmd in runner.commands:
        assert cmd[0] == "ssh", f"a probe escaped the endpoint: {cmd}"
        assert "BatchMode=yes" in cmd, f"a probe could block on a prompt: {cmd}"


def test_unreachable_ssh_fails_loudly_and_stops_probing() -> None:
    runner = _FakeRunner([("ssh", 255, "", "ssh: connect to port 2221: Connection refused")])
    result = preflight_endpoint(_endpoint(), runner)
    assert result.reachable is False
    assert result.ready is False
    assert "cannot reach" in result.detail
    # Nothing beyond the ssh probe: a dead endpoint is not probed further.
    assert len(runner.commands) == 1


def test_missing_required_command_is_reported_by_name() -> None:
    runner = _FakeRunner([("command -v tcpdump", 1, "", "")])
    result = preflight_endpoint(_endpoint(), runner)
    commands = next(c for c in result.checks if c["name"] == "commands")
    assert commands["status"] == "fail"
    assert "tcpdump" in commands["detail"]


def test_swanctl_not_answering_is_a_failure_not_a_pass() -> None:
    runner = _FakeRunner([("swanctl --list-sas", 2, "", "Error: connecting to default URI failed")])
    result = preflight_endpoint(_endpoint(), runner)
    assert next(c for c in result.checks if c["name"] == "vici")["status"] == "fail"
    assert result.ready is False


def test_absent_interface_is_a_failure() -> None:
    runner = _FakeRunner([("-o link show", 0, "1: lo: <LOOPBACK> mtu 65536\n", "")])
    result = preflight_endpoint(_endpoint(), runner)
    assert next(c for c in result.checks if c["name"] == "interface")["status"] == "fail"


def test_absent_address_is_a_failure() -> None:
    runner = _FakeRunner([("-o addr show", 0, "1: lo inet 127.0.0.1/8\n", "")])
    result = preflight_endpoint(_endpoint(), runner)
    assert next(c for c in result.checks if c["name"] == "address")["status"] == "fail"


def test_unanswered_ping_is_not_fatal() -> None:
    """IKE uses UDP 500/4500; a filtered ping proves nothing either way."""
    result = preflight_endpoint(_endpoint(), _all_good(peer_ok=False), peer="10.10.10.2")
    peer_check = next(c for c in result.checks if c["name"] == "peer")
    assert peer_check["status"] in {PASS, "unknown"}
    assert result.ready is True


def test_preflight_refuses_a_non_remote_endpoint() -> None:
    local = endpoint_from_dict({"name": "a", "role": "initiator", "outer_ipv4": "10.0.0.1/24"})
    with pytest.raises(FeraError) as error:
        preflight_endpoint(local, _FakeRunner([]))
    assert error.value.code is ErrorCode.CONFIG_VALIDATION_FAILED


def test_required_commands_cover_what_an_experiment_needs() -> None:
    assert set(REQUIRED_COMMANDS) == {"swanctl", "ip", "tcpdump"}
def _two_vm_topology():
    return topology_from_dict(
        {
            "name": "ssh_two_vm",
            "runner": "ssh",
            "endpoints": {
                "a": {
                    "name": "endpoint-a", "role": "initiator", "kind": "ssh",
                    "ssh_host": "10.0.2.15", "ssh_port": 2221,
                    "outer_ipv4": "10.10.10.1/24",
                },
                "b": {
                    "name": "endpoint-b", "role": "responder", "kind": "ssh",
                    "ssh_host": "10.0.2.15", "ssh_port": 2222,
                    "outer_ipv4": "10.10.10.2/24",
                },
            },
        }
    )


def test_require_remote_endpoints_ready_raises_when_an_endpoint_is_down() -> None:
    runner = _FakeRunner([("ssh", 255, "", "Connection refused")])
    with pytest.raises(FeraError) as error:
        require_remote_endpoints_ready(_two_vm_topology(), runner)
    assert error.value.code is ErrorCode.REMOTE_PREFLIGHT_FAILED
    assert error.value.details["results"]


def test_require_remote_endpoints_ready_reports_both_endpoints_when_up() -> None:
    results = require_remote_endpoints_ready(_two_vm_topology(), _all_good())
    assert {r.endpoint for r in results} == {"endpoint-a", "endpoint-b"}


def test_require_remote_endpoints_ready_skips_local_endpoints() -> None:
    """A namespace endpoint has no ssh_host, so it must not be preflighted."""
    topology = topology_from_dict(
        {
            "name": "mixed",
            "endpoints": {
                "a": {
                    "name": "endpoint-a", "role": "initiator", "kind": "ssh",
                    "ssh_host": "10.0.2.15", "ssh_port": 2221,
                    "outer_ipv4": "10.10.10.1/24",
                },
                "b": {
                    "name": "endpoint-b", "role": "responder", "netns": "fera-b",
                    "outer_ipv4": "10.10.10.2/24",
                },
            },
        }
    )
    results = require_remote_endpoints_ready(topology, _all_good())
    assert [r.endpoint for r in results] == ["endpoint-a"]
