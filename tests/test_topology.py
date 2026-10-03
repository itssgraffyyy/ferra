"""Topology model, template mirroring and addressing tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from fera.common.errors import ConfigValidationError
from fera.testbed.namespaces import charon_command
from fera.testbed.topology import (
    DEFAULT_TOPOLOGY_DOCUMENT,
    Endpoint,
    default_topology,
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


def test_charon_command_is_wrapped_for_its_endpoint() -> None:
    command = charon_command(default_topology(), "b", strongswan_conf="/tmp/b.conf")
    assert command[:4] == ["ip", "netns", "exec", "fera-b"]
    assert command[4] == "sh" and command[5] == "-c"
