"""Topology model, template mirroring and addressing tests."""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import pytest

from conftest import REPO_ROOT
from fera.common.errors import ConfigValidationError
from fera.testbed.namespaces import (
    DEFAULT_SOCKET_DIR,
    ROOT_SOCKET_DIR,
    charon_command,
    default_socket_dir,
    netns_launcher,
    netns_prefix,
)
from fera.testbed.topology import (
    DEFAULT_TOPOLOGY_DOCUMENT,
    SSH,
    Endpoint,
    TestbedTopology,
    default_topology,
    endpoint_from_dict,
    host_cidr,
    is_host_selector,
    load_topology,
    network_cidr,
    topology_from_dict,
)


def test_shipped_yaml_matches_builtin_document(repo_paths) -> None:
    """The template file and the code constant must never drift apart."""
    yaml_topology = load_topology(repo_paths.topology_file)
    builtin = default_topology()
    assert yaml_topology.to_dict() == builtin.to_dict()


def test_default_topology_addressing() -> None:
    topology = default_topology()
    assert topology.endpoint_a.outer_address(4) == "10.10.10.1/24"
    assert topology.endpoint_b.protected_address(4) == "10.30.0.1/24"
    assert topology.supports_ip_version(4) and topology.supports_ip_version(6)


def test_tunnel_selectors_are_networks_and_transport_selectors_are_hosts() -> None:
    topology = default_topology()
    tunnel = topology.selectors("tunnel", 4)
    transport = topology.selectors("transport", 4)
    assert (tunnel.local_ts, tunnel.remote_ts) == ("10.20.0.0/24", "10.30.0.0/24")
    assert tunnel.host_to_host is False
    assert (transport.local_ts, transport.remote_ts) == ("10.10.10.1/32", "10.10.10.2/32")
    assert transport.host_to_host is True


def test_ipv6_selectors_use_ula_space() -> None:
    topology = default_topology()
    tunnel = topology.selectors("tunnel", 6)
    transport = topology.selectors("transport", 6)
    assert tunnel.local_ts == "fd00:20::/64"
    assert transport.local_ts == "fd00:10:10::1/128"
    assert is_host_selector(transport.remote_ts)


def test_reverse_direction_swaps_selectors() -> None:
    topology = default_topology()
    forward = topology.selectors("tunnel", 4, direction="a_to_b")
    backward = topology.selectors("tunnel", 4, direction="b_to_a")
    assert forward.local_ts == backward.remote_ts
    assert forward.remote_ts == backward.local_ts


def test_traffic_source_and_target_follow_the_mode() -> None:
    topology = default_topology()
    assert topology.traffic_target("tunnel", 4) == "10.30.0.1"
    assert topology.traffic_source("tunnel", 4) == "10.20.0.1"
    assert topology.traffic_target("transport", 4) == "10.10.10.2"
    assert topology.traffic_source("transport", 4) == "10.10.10.1"


def test_tunnel_route_pins_the_protected_source() -> None:
    route = default_topology().route_to_peer("tunnel", 4)
    assert route == {"destination": "10.30.0.0/24", "gateway": "10.10.10.2", "source": "10.20.0.1"}
    assert default_topology().route_to_peer("transport", 4) is None


def test_capture_interface_is_the_endpoint_veth(topology) -> None:
    assert topology.capture_interface("a") == topology.veth_a
    assert topology.capture_interface("b") == topology.veth_b


def test_command_prefix_wraps_for_netns() -> None:
    endpoint = default_topology().endpoint_a
    assert endpoint.wrap_command(["swanctl", "--list-sas"])[:4] == [
        "ip",
        "netns",
        "exec",
        "fera-a",
    ]


def test_remote_endpoint_uses_ssh_prefix() -> None:
    endpoint = Endpoint(
        name="endpoint-b",
        role="responder",
        outer_ipv4="192.0.2.10/32",
        command_prefix=("ssh", "-o", "BatchMode=yes", "fera@192.0.2.10"),
    )
    assert endpoint.wrap_command(["swanctl", "--list-sas"])[:4] == [
        "ssh",
        "-o",
        "BatchMode=yes",
        "fera@192.0.2.10",
    ]


def test_endpoint_requires_an_outer_address() -> None:
    with pytest.raises(ConfigValidationError):
        Endpoint(name="a", role="initiator")


def test_roles_are_validated() -> None:
    with pytest.raises(ConfigValidationError):
        Endpoint(name="a", role="client", outer_ipv4="10.0.0.1/24")


def test_topology_rejects_unknown_fields() -> None:
    document = dict(DEFAULT_TOPOLOGY_DOCUMENT)
    document["mystery"] = True
    with pytest.raises(ConfigValidationError):
        topology_from_dict(document)


def test_endpoint_rejects_string_command_prefix() -> None:
    document = dict(DEFAULT_TOPOLOGY_DOCUMENT)
    document = {**document, "endpoints": dict(document["endpoints"])}
    document["endpoints"]["a"] = dict(document["endpoints"]["a"], command_prefix="ip netns exec")
    with pytest.raises(ConfigValidationError):
        topology_from_dict(document)


def test_network_and_host_helpers() -> None:
    assert network_cidr("10.20.0.1/24") == "10.20.0.0/24"
    assert network_cidr("fd00:20::1/64") == "fd00:20::/64"
    assert host_cidr("10.10.10.1/24", 4) == "10.10.10.1/32"
    assert host_cidr("fd00:10:10::1/64", 6) == "fd00:10:10::1/128"


def test_missing_template_falls_back_to_builtin(tmp_path: Path) -> None:
    missing = tmp_path / "nope.yaml"
    assert missing.is_file() is False
    assert default_topology().name == "netns_dualstack"


def test_swapped_initiator_roles_are_rejected() -> None:
    document = dict(DEFAULT_TOPOLOGY_DOCUMENT)
    endpoints = {key: dict(value) for key, value in document["endpoints"].items()}
    endpoints["a"]["role"] = "responder"
    endpoints["b"]["role"] = "initiator"
    with pytest.raises(ConfigValidationError):
        topology_from_dict({**document, "endpoints": endpoints})


def test_charon_command_gives_each_instance_a_private_runtime_dir() -> None:
    """Two charons cannot share a runtime directory.

    ``/var/run/charon.pid`` is a string constant in the binary (there is no
    ``charon.pidfile`` setting), so the second daemon aborts with *charon
    already running* and never opens its VICI socket: the endpoint looks
    configured, but every ``swanctl`` call to it fails.
    """
    script = charon_command(default_topology(), "a", strongswan_conf="/tmp/a.conf")[-1]
    assert "mount -t tmpfs -o rw tmpfs /var/run" in script
    assert "exec env STRONGSWAN_CONF=/tmp/a.conf /usr/lib/ipsec/charon" in script


def test_charon_command_starts_the_daemon_even_if_the_mount_is_refused() -> None:
    script = charon_command(default_topology(), "b", strongswan_conf="/tmp/b.conf")[-1]
    assert "|| true;" in script, "a refused mount must not stop charon from starting"



def test_charon_command_creates_the_vici_socket_dir_inside_the_private_tmpfs() -> None:
    """The socket directory must exist where charon will look for it.

    On a normal host ``/var/run`` is a symlink to ``/run``, so the tmpfs mount
    over ``/var/run`` shadows ``/run`` itself inside charon's mount namespace.
    The socket is configured as ``unix://<socket_dir>/charon-<key>.vici``; if
    that directory does not exist charon binds **no** VICI socket at all, and
    every ``swanctl`` call fails while the daemon still looks healthy.  This only
    happens when the mount really succeeds, i.e. when FERA runs as root.
    """
    script = charon_command(default_topology(), "a", strongswan_conf="/tmp/a.conf")[-1]
    socket_dir = default_socket_dir()
    assert f"mkdir -p {socket_dir}" in script
    # The directory must be created *after* the mount and *before* charon is exec'd.
    assert script.index("mount -t tmpfs") < script.index(f"mkdir -p {socket_dir}")
    assert script.index(f"mkdir -p {socket_dir}") < script.index("exec env STRONGSWAN_CONF")


def test_charon_command_honours_an_explicit_socket_dir() -> None:
    script = charon_command(
        default_topology(), "b", strongswan_conf="/tmp/b.conf", socket_dir="/tmp/ferab"
    )[-1]
    assert "mkdir -p /tmp/ferab" in script


def test_root_socket_dir_lives_outside_the_shadowed_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """As root the socket may not live under /run: the tmpfs shadows it.

    The private-runtime tmpfs is mounted over ``/var/run``, which is a symlink to
    ``/run``, so ``/run`` disappears inside charon's mount namespace while
    ``ip netns exec ... swanctl`` still sees the real one.  A socket under
    ``/run`` is therefore unreachable from the client that must drive the daemon.
    """
    monkeypatch.delenv("FERA_SOCKET_DIR", raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert default_socket_dir() == Path(ROOT_SOCKET_DIR)
    assert not str(default_socket_dir()).startswith("/run")


def test_unprivileged_socket_dir_stays_under_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without root the mount is refused, so /run is intact and stays correct."""
    monkeypatch.delenv("FERA_SOCKET_DIR", raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert default_socket_dir() == Path(DEFAULT_SOCKET_DIR)


def test_socket_dir_override_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FERA_SOCKET_DIR", "/tmp/custom-sockets")
    assert default_socket_dir() == Path("/tmp/custom-sockets")


# --- SSH / two-VM endpoints -------------------------------------------------
# The other half of the testbed story: endpoints that are separate machines
# reached over SSH, where almost every namespace assumption is false.


def _ssh_topology_document() -> dict:
    return {
        "schema_version": 1,
        "name": "ssh_two_vm",
        "runner": "ssh",
        "link": {"ipv4": "10.10.10.0/24"},
        "endpoints": {
            "a": {
                "name": "endpoint-a", "role": "initiator", "kind": "ssh",
                "ssh_host": "10.0.2.15", "ssh_user": "fera", "ssh_port": 2221,
                "capture_interface": "enp0s8", "outer_ipv4": "10.10.10.1/24",
            },
            "b": {
                "name": "endpoint-b", "role": "responder", "kind": "ssh",
                "ssh_host": "10.0.2.15", "ssh_user": "fera", "ssh_port": 2222,
                "capture_interface": "enp0s8", "outer_ipv4": "10.10.10.2/24",
            },
        },
    }


def _ssh_topology() -> TestbedTopology:
    return topology_from_dict(_ssh_topology_document())



def test_charon_command_is_wrapped_for_its_endpoint() -> None:
    command = charon_command(default_topology(), "b", strongswan_conf="/tmp/b.conf")
    assert command[:4] == ["ip", "netns", "exec", "fera-b"]
    assert command[4] == "sh" and command[5] == "-c"


# --- namespace launcher -----------------------------------------------------
# `ip netns exec` does not only switch network namespaces: it also creates a
# mount namespace and bind-remounts /sys for the target namespace.  That side
# effect is easy to confuse with a property of the network namespace, so the two
# are selectable independently and each is pinned here.


def test_default_launcher_is_ip_netns_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FERA_NETNS_LAUNCHER", raising=False)
    assert netns_prefix("fera-a") == ["ip", "netns", "exec", "fera-a"]
    assert default_topology().endpoint_a.wrap_command(["ip", "addr"]) == [
        "ip", "netns", "exec", "fera-a", "ip", "addr",
    ]


def test_nsenter_launcher_enters_only_the_network_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FERA_NETNS_LAUNCHER", "nsenter")
    assert netns_prefix("fera-a") == ["nsenter", "--net=/run/netns/fera-a"]
    assert default_topology().endpoint_b.wrap_command(["swanctl"]) == [
        "nsenter", "--net=/run/netns/fera-b", "swanctl",
    ]


def test_unknown_launcher_falls_back_to_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FERA_NETNS_LAUNCHER", "sudo-sandwich")
    assert netns_launcher() == "ip"
    assert netns_prefix("fera-a") == ["ip", "netns", "exec", "fera-a"]


def test_explicit_command_prefix_beats_the_launcher(monkeypatch: pytest.MonkeyPatch) -> None:
    """A topology that names its own prefix is used verbatim, launcher or not."""
    monkeypatch.setenv("FERA_NETNS_LAUNCHER", "nsenter")
    endpoint = default_topology().endpoint_a
    # A copy, not a mutation: object.__setattr__ on the shared topology would
    # leak into every later test, and monkeypatch cannot undo it.
    custom = dataclasses.replace(endpoint, command_prefix=("docker", "exec", "ep-a"))
    assert custom.wrap_command(["ping", "-c1"]) == ["docker", "exec", "ep-a", "ping", "-c1"]

def test_ssh_endpoint_is_explicitly_remote_and_not_namespace() -> None:
    topology = _ssh_topology()
    assert topology.is_remote is True
    for key in ("a", "b"):
        endpoint = topology.endpoint(key)
        assert endpoint.is_remote is True
        assert endpoint.uses_private_vici is False, "a VM uses its own default VICI socket"
        assert endpoint.netns is None


def test_netns_endpoints_are_still_not_remote() -> None:
    topology = default_topology()
    assert topology.is_remote is False
    for key in ("a", "b"):
        endpoint = topology.endpoint(key)
        assert endpoint.is_remote is False
        assert endpoint.uses_private_vici is True, "namespace endpoints keep a private socket"


def test_ssh_wraps_commands_as_a_separated_argument_array() -> None:
    command = _ssh_topology().endpoint("a").wrap_command(["swanctl", "--list-sas"])
    assert command[:6] == ["ssh", "-o", "BatchMode=yes", "-p", "2221", "fera@10.0.2.15"]
    assert command[6:] == ["swanctl", "--list-sas"]
    # Every element is its own argument: no shell string is ever built.
    assert all(" " not in part for part in command)


def test_ssh_targets_differ_per_endpoint() -> None:
    topology = _ssh_topology()
    prefix_a = topology.endpoint("a").wrap_command(["ip"])[:-1]
    prefix_b = topology.endpoint("b").wrap_command(["ip"])[:-1]
    assert prefix_a != prefix_b
    assert "2221" in prefix_a and "2222" in prefix_b


def test_ssh_prefix_is_noninteractive() -> None:
    """BatchMode stops a preflight hanging on a password or host-key prompt."""
    assert tuple(_ssh_topology().endpoint("a").ssh_command_prefix()[:3]) == (
        "ssh",
        "-o",
        "BatchMode=yes",
    )


def test_ssh_identity_is_a_separate_argument() -> None:
    endpoint = dataclasses.replace(
        _ssh_topology().endpoint("a"), ssh_identity="/home/me/.ssh/id_fera"
    )
    prefix = endpoint.ssh_command_prefix()
    assert prefix[prefix.index("-i") + 1] == "/home/me/.ssh/id_fera"


def test_explicit_command_prefix_wins_over_ssh() -> None:
    endpoint = dataclasses.replace(
        _ssh_topology().endpoint("a"), command_prefix=("docker", "exec", "ep-a")
    )
    assert endpoint.wrap_command(["ip", "addr"]) == ["docker", "exec", "ep-a", "ip", "addr"]


def test_ssh_capture_interface_comes_from_the_endpoint_not_a_veth() -> None:
    topology = _ssh_topology()
    assert topology.capture_interface("a") == "enp0s8"
    assert topology.capture_interface("b") == "enp0s8"


def test_ssh_kind_requires_a_host() -> None:
    with pytest.raises(ConfigValidationError, match="ssh_host"):
        endpoint_from_dict(
            {"name": "x", "role": "initiator", "kind": "ssh", "outer_ipv4": "10.0.0.1/24"}
        )


def test_ssh_host_without_ssh_kind_is_rejected() -> None:
    """A remote address on a local endpoint would silently do the wrong thing."""
    with pytest.raises(ConfigValidationError, match="ssh_host"):
        endpoint_from_dict(
            {
                "name": "x", "role": "initiator", "kind": "local",
                "ssh_host": "10.0.2.15", "outer_ipv4": "10.0.0.1/24",
            }
        )


def test_unknown_kind_is_rejected() -> None:
    with pytest.raises(ConfigValidationError, match="kind"):
        endpoint_from_dict(
            {"name": "x", "role": "initiator", "kind": "telepathy", "outer_ipv4": "10.0.0.1/24"}
        )


def test_ssh_fields_round_trip_through_to_dict() -> None:
    original = _ssh_topology().endpoint("a")
    restored = endpoint_from_dict(original.to_dict())
    assert restored.kind == SSH
    assert restored.ssh_host == original.ssh_host
    assert restored.ssh_port == original.ssh_port
    assert restored.capture_interface == original.capture_interface


def test_shipped_ssh_template_parses_and_is_remote() -> None:
    topology = load_topology(str(REPO_ROOT / "configs" / "templates" / "testbed_topology_ssh.yaml"))
    assert topology.is_remote is True
    assert topology.capture_interface("a") == "enp0s8"
    assert topology.endpoint_a.outer_ipv4 == "10.10.10.1/24"
    assert topology.endpoint_b.outer_ipv4 == "10.10.10.2/24"


def test_shipped_netns_template_is_unchanged_by_the_ssh_work() -> None:
    """The namespace topology must remain the shipped default."""
    topology = load_topology(str(REPO_ROOT / "configs" / "templates" / "testbed_topology.yaml"))
    assert topology.is_remote is False
    assert topology.endpoint_a.netns == "fera-a"
    assert topology.capture_interface("a") == topology.veth_a
