"""Linux network namespace testbed: script and command generation.

The recommended local testbed is two Linux network namespaces joined by a veth
pair (see ``docs/testbed.md``).  This module *generates* the setup/teardown
shell scripts and the per endpoint charon commands, so the topology in
``configs/templates/testbed_topology.yaml`` stays the single source of truth::

    Endpoint A (ns fera-a)                  Endpoint B (ns fera-b)
    10.10.10.1/24 fera-va <--- veth ---> 10.10.10.2/24 fera-vb
    10.20.0.1/24 (protected A)             10.30.0.1/24 (protected B)

Tunnel mode protects ``10.20.0.0/24 <-> 10.30.0.0/24``; transport mode protects
the host pair ``10.10.10.1/32 <-> 10.10.10.2/32``.
"""

from __future__ import annotations

import os
import shlex
import tempfile
from pathlib import Path
from typing import Any

from .topology import TestbedTopology

#: Directory for the per endpoint VICI sockets.  Unix sockets must live on a
#: local Linux filesystem: the repository is often a mounted Windows volume
#: under WSL, which does not support them reliably.
DEFAULT_SOCKET_DIR = "/run/fera-testbed"


def default_socket_dir() -> Path:
    """Return the default VICI socket directory for this platform."""
    override = os.environ.get("FERA_SOCKET_DIR")
    if override:
        return Path(override)
    if os.name == "posix":
        return Path(DEFAULT_SOCKET_DIR)
    return Path(tempfile.gettempdir()) / "fera-testbed"


SCRIPT_HEADER = """#!/usr/bin/env bash
# FERA generated script - do not edit by hand.
# source of truth: configs/templates/testbed_topology.yaml ({topology})
# regenerate with : python scripts/setup_netns_testbed.py --print-only
set -euo pipefail
"""


def render_netns_setup_script(topology: TestbedTopology, *, mtu: int | None = None) -> str:
    """Render the bash script that creates the whole namespace testbed.

    The script is idempotent: existing namespaces are deleted first, so a broken
    previous run can never poison the next experiment.
    """
    link_mtu = int(mtu or topology.mtu)
    lines = [SCRIPT_HEADER.format(topology=topology.name)]
    namespaces = {
        "a": topology.endpoint_a.netns or "fera-a",
        "b": topology.endpoint_b.netns or "fera-b",
    }
    veths = {"a": topology.veth_a, "b": topology.veth_b}

    for key in ("a", "b"):
        lines.append(f"ip netns del {namespaces[key]} 2>/dev/null || true")
    lines.append("")
    for key in ("a", "b"):
        lines.append(f"ip netns add {namespaces[key]}")
    lines.append("")
    lines.append(f"ip link add {veths['a']} type veth peer name {veths['b']}")
    lines.append("")

    for key in ("a", "b"):
        endpoint = topology.endpoint(key)
        namespace = namespaces[key]
        link = veths[key]
        lines.append(f"ip link set {link} netns {namespace}")
        lines.append(f"ip netns exec {namespace} ip link set lo up")
        lines.append(f"ip netns exec {namespace} ip link set {link} mtu {link_mtu} up")
        for ip_version in (4, 6):
            if not endpoint.supports(ip_version):
                continue
            flag = " -6" if ip_version == 6 else ""
            lines.append(
                f"ip netns exec {namespace} ip{flag} addr add "
                f"{endpoint.outer_network(ip_version)} dev {link}"
            )
            protected = endpoint.protected_network(ip_version)
            if protected:
                nodev = " nodad" if ip_version == 6 else ""
                lines.append(
                    f"ip netns exec {namespace} ip{flag} addr add {protected} dev {link}{nodev}"
                )
        lines.append("")

    lines.append("# protect the peer network and pin the source address to the protected address")
    for ip_version in (4, 6):
        if not topology.supports_ip_version(ip_version):
            continue
        flag = " -6" if ip_version == 6 else ""
        for key in ("a", "b"):
            route = _route_for(topology, key, ip_version)
            if not route:
                continue
            lines.append(
                f"ip netns exec {namespaces[key]} ip{flag} route replace {route['destination']} "
                f"via {route['gateway']} src {route['source']}"
            )
    lines.append("")
    lines.append('echo "FERA namespace testbed is up:"')
    for key in ("a", "b"):
        lines.append(f"ip netns exec {namespaces[key]} ip -brief addr show")
    return "\n".join(lines) + "\n"


def _route_for(topology: TestbedTopology, key: str, ip_version: int) -> dict[str, str] | None:
    """Route that the given namespace needs so its traffic is protected.

    Endpoint B needs the mirrored route (its own protected address as source,
    endpoint A's network as destination); the route is built directly instead
    of constructing a swapped topology object.
    """
    from .topology import host_address, network_cidr

    local = topology.endpoint(key)
    peer = topology.peer_of(key)
    local_protected = local.protected_network(ip_version)
    peer_protected = peer.protected_network(ip_version)
    if local_protected is None or peer_protected is None:
        return None
    return {
        "destination": network_cidr(peer_protected),
        "gateway": host_address(str(peer.outer_address(ip_version))),
        "source": host_address(local_protected),
    }


def render_netns_teardown_script(topology: TestbedTopology) -> str:
    """Render the bash script that removes the namespace testbed."""
    lines = [SCRIPT_HEADER.format(topology=topology.name)]
    for key in ("a", "b"):
        namespace = topology.endpoint(key).netns or f"fera-{key}"
        lines.append(f"ip netns del {namespace} 2>/dev/null || true")
    lines.append('echo "FERA namespace testbed removed"')
    return "\n".join(lines) + "\n"


def vici_socket_path(runtime_dir: Path | str, key: str) -> Path:
    """Path of the per endpoint VICI socket."""
    return Path(runtime_dir) / f"charon-{key}.vici"


CHARON_RUNTIME_DIR = "/var/run"


def charon_command(
    topology: TestbedTopology,
    key: str,
    *,
    strongswan_conf: Path | str,
    charon_binary: str = "/usr/lib/ipsec/charon",
    runtime_dir: str = CHARON_RUNTIME_DIR,
) -> list[str]:
    """Full command that starts a dedicated charon instance for an endpoint.

    Each instance is given a private ``/var/run`` before charon starts.  The
    daemon hard-codes ``/var/run/charon.pid`` -- there is no ``charon.pidfile``
    setting, the path is a string constant in the binary -- and it also binds
    ``charon.ctl``, ``charon.lkp`` and ``charon.enfy`` there.  Two daemons that
    share one runtime directory cannot both run: the second aborts with *charon
    already running ('/var/run/charon.pid' exists)*, never opens its VICI
    socket, and that endpoint is left with a socket file nobody listens on, so
    every ``swanctl`` call to it fails while the testbed still reports success.
    ``ip netns exec`` already gives the instance its own mount namespace, so a
    tmpfs over the runtime directory is private to that daemon and disappears
    with it.

    The mount is best effort: if it is not permitted the daemon still starts,
    exactly as before, instead of never starting at all.
    """
    endpoint = topology.endpoint(key)
    return [
        *endpoint.wrap_command([]),
        "sh",
        "-c",
        (
            f"mount -t tmpfs -o rw tmpfs {shlex.quote(runtime_dir)} 2>/dev/null || true; "
            f"exec env STRONGSWAN_CONF={shlex.quote(str(strongswan_conf))} "
            f"{shlex.quote(charon_binary)}"
        ),
    ]


def topology_summary_lines(topology: TestbedTopology) -> list[str]:
    """Human readable description of the addressing (used by docs and CLI)."""
    lines = [f"topology: {topology.name} (runner: {topology.runner})"]
    for key in ("a", "b"):
        endpoint = topology.endpoint(key)
        for ip_version in (4, 6):
            if not endpoint.supports(ip_version):
                continue
            lines.append(
                f"  {endpoint.name:<12} IPv{ip_version}: outer {endpoint.outer_network(ip_version)}"
                f"   protected {endpoint.protected_network(ip_version)}"
            )
    for mode in ("tunnel", "transport"):
        for ip_version in (4, 6):
            if not topology.supports_ip_version(ip_version):
                continue
            selectors = topology.selectors(mode, ip_version)
            lines.append(
                f"  {mode:<12} IPv{ip_version}: local_ts {selectors.local_ts}  "
                f"remote_ts {selectors.remote_ts}  traffic target {topology.traffic_target(mode, ip_version)}"
            )
    return lines


def netns_script_document(topology: TestbedTopology) -> dict[str, Any]:
    """Metadata block describing the generated testbed (for reports)."""
    return {
        "topology": topology.name,
        "runner": topology.runner,
        "namespaces": {"a": topology.endpoint_a.netns, "b": topology.endpoint_b.netns},
        "veth": {"a": topology.veth_a, "b": topology.veth_b},
        "mtu": topology.mtu,
        "sockets": {"a": str(vici_socket_path(".", "a")), "b": str(vici_socket_path(".", "b"))},
        "summary": topology_summary_lines(topology),
    }


__all__ = [
    "SCRIPT_HEADER",
    "charon_command",
    "netns_script_document",
    "render_netns_setup_script",
    "render_netns_teardown_script",
    "topology_summary_lines",
    "vici_socket_path",
]

