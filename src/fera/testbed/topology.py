"""Testbed topology model.

The topology describes the two IPsec endpoints, their outer (transport) and
protected (tunnel) addresses, and how the runner reaches each endpoint
(``ip netns exec`` locally, or ``ssh`` to a remote host).  It is the single
source of truth for:

* address selection per experiment (IPv4/IPv6, tunnel/transport),
* the traffic source/target of an experiment,
* the interface that packet capture must listen on,
* the shell script that creates the isolated Linux network namespace testbed.

Recommended execution environment: two Linux network namespaces (or two Linux
VMs) as described in ``docs/testbed.md``.  WSL2 works only when its kernel
provides XFRM support - the environment checker reports that explicitly.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..common.errors import ConfigValidationError

INITIATOR = "initiator"
RESPONDER = "responder"
SUPPORTED_ROLES = (INITIATOR, RESPONDER)


def split_cidr(value: str) -> tuple[str, int]:
    """Split ``10.0.0.1/24`` into ``("10.0.0.1", 24)``; bare addresses get a host prefix."""
    if "/" in value:
        address, _, prefix = value.partition("/")
        if not prefix.isdigit():
            raise ConfigValidationError(
                f"invalid CIDR prefix in {value!r}",
                hint="use address/prefix notation, e.g. 10.20.0.1/24",
            )
        return address.strip(), int(prefix)
    return value.strip(), (128 if ":" in value else 32)


def host_address(value: str) -> str:
    """Return the address part of a CIDR string."""
    return split_cidr(value)[0]


def is_host_selector(value: str) -> bool:
    """True when the CIDR denotes a single host (``/32`` or ``/128``)."""
    address, prefix = split_cidr(value)
    return prefix == (128 if ":" in address else 32)


@dataclass(frozen=True)
class TrafficSelectors:
    """The IPsec traffic selectors (TS) of one CHILD_SA direction."""

    local_ts: str
    remote_ts: str

    @property
    def host_to_host(self) -> bool:
        return is_host_selector(self.local_ts) and is_host_selector(self.remote_ts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "local_ts": self.local_ts,
            "remote_ts": self.remote_ts,
            "host_to_host": self.host_to_host,
        }


@dataclass(frozen=True)
class Endpoint:
    """One IPsec endpoint of the testbed."""

    name: str
    role: str
    outer_ipv4: str | None = None
    outer_ipv6: str | None = None
    protected_ipv4: str | None = None
    protected_ipv6: str | None = None
    ike_id: str = ""
    netns: str | None = None
    command_prefix: tuple[str, ...] = ()
    sudo: bool = False

    def __post_init__(self) -> None:
        if self.role not in SUPPORTED_ROLES:
            raise ConfigValidationError(
                f"endpoint {self.name!r} has invalid role {self.role!r}",
                hint=f"supported roles: {', '.join(SUPPORTED_ROLES)}",
            )
        if not (self.outer_ipv4 or self.outer_ipv6):
            raise ConfigValidationError(f"endpoint {self.name!r} needs at least one outer address")
        if not self.ike_id:
            object.__setattr__(self, "ike_id", f"{self.name}.fera.test")

    # -- addressing ----------------------------------------------------
    def outer_address(self, ip_version: int) -> str | None:
        """Transport address (the address IKE/ESP is exchanged between)."""
        if ip_version == 4:
            return self.outer_ipv4
        if ip_version == 6:
            return self.outer_ipv6
        raise ConfigValidationError(f"unsupported IP version: {ip_version!r}")

    def protected_address(self, ip_version: int) -> str | None:
        """Address behind the endpoint (tunnel mode selector/target)."""
        if ip_version == 4:
            return self.protected_ipv4
        if ip_version == 6:
            return self.protected_ipv6
        raise ConfigValidationError(f"unsupported IP version: {ip_version!r}")

    def outer_network(self, ip_version: int) -> str | None:
        """Outer address in CIDR notation (an ``ip addr add`` argument)."""
        address = self.outer_address(ip_version)
        if address is None:
            return None
        return address if "/" in address else f"{address}/{'32' if ip_version == 4 else '128'}"

    def protected_network(self, ip_version: int) -> str | None:
        """Protected address in CIDR notation."""
        address = self.protected_address(ip_version)
        if address is None:
            return None
        return address if "/" in address else f"{address}/{'32' if ip_version == 4 else '128'}"

    def supports(self, ip_version: int) -> bool:
        """True when the endpoint has addresses for this IP version."""
        return ip_version in (4, 6) and self.outer_address(ip_version) is not None

    # -- process invocation -------------------------------------------
    def wrap_command(self, command: list[str]) -> list[str]:
        """Prefix ``command`` so that it executes on this endpoint.

        * local execution: unchanged
        * network namespace: ``ip netns exec <ns> ...``
        * remote endpoint: ``ssh <host> ...``

        ``command_prefix`` is used verbatim as an argument array - the runner
        never builds shell strings, so this cannot be abused for injection.

        The namespace launcher is selectable because ``ip netns exec`` does more
        than enter the network namespace: it also creates a *mount* namespace and
        bind-remounts ``/sys`` for the target namespace, so anything it starts
        sees a different ``/sys`` from the rest of the system.  Set
        ``FERA_NETNS_LAUNCHER=nsenter`` to enter only the network namespace and
        leave ``/sys`` alone, which keeps the two effects separable.  Unlike
        ``ip netns exec``, ``nsenter`` keeps the caller's mount namespace, so a
        per-endpoint runtime directory must be created explicitly by the caller.
        """
        prefix = list(self.command_prefix)
        if not prefix and self.netns:
            # Imported here, not at module scope: namespaces imports this module.
            from .namespaces import netns_prefix  # noqa: PLC0415 - avoids a cycle

            prefix = netns_prefix(self.netns)
        return [*prefix, *command]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "ike_id": self.ike_id,
            "outer_ipv4": self.outer_ipv4,
            "outer_ipv6": self.outer_ipv6,
            "protected_ipv4": self.protected_ipv4,
            "protected_ipv6": self.protected_ipv6,
            "netns": self.netns,
            "command_prefix": list(self.command_prefix),
            "sudo": self.sudo,
        }

    def describe(self) -> str:
        """Short public label used in metadata (no sensitive information)."""
        return f"{self.name} ({self.role})"


def network_cidr(address: str) -> str:
    """Return the network part of a host CIDR, e.g. ``10.20.0.1/24`` -> ``10.20.0.0/24``."""
    import ipaddress

    text = address if "/" in address else f"{address}/{'128' if ':' in address else '32'}"
    return str(ipaddress.ip_interface(text).network)


def host_cidr(address: str, ip_version: int) -> str:
    """Return ``address`` as a host selector (``/32`` or ``/128``)."""
    return f"{host_address(address)}/{32 if ip_version == 4 else 128}"


@dataclass(frozen=True)
class TestbedTopology:
    """A two endpoint IPsec testbed."""

    #: Keep pytest from treating the class as a test case (it starts with "Test").
    __test__ = False

    name: str
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    description: str = ""
    runner: str = "netns"
    link_ipv4: str | None = None
    link_ipv6: str | None = None
    veth_a: str = "fera-va"
    veth_b: str = "fera-vb"
    lan_interface_a: str = "fera-lana"
    lan_interface_b: str = "fera-lanb"
    mtu: int = 1400
    ike_port: int = 500
    nat_t_port: int = 4500
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.endpoint_a.name == self.endpoint_b.name:
            raise ConfigValidationError("testbed endpoints must have distinct names")
        if self.endpoint_a.role != INITIATOR:
            raise ConfigValidationError(
                "endpoint A must be the initiator",
                hint="swap the roles or use topology endpoint_b as initiator",
            )
        if self.endpoint_b.role != RESPONDER:
            raise ConfigValidationError("endpoint B must be the responder")
        if not any(
            self.endpoint_a.supports(version) and self.endpoint_b.supports(version) for version in (4, 6)
        ):
            raise ConfigValidationError(
                "the two endpoints have no IP version in common",
                hint="give both endpoints an outer IPv4 and/or IPv6 address",
            )
        if self.mtu < 576:
            raise ConfigValidationError(f"link MTU {self.mtu} is too small for IPsec")

    # -- endpoints ------------------------------------------------------
    @property
    def initiator(self) -> Endpoint:
        return self.endpoint_a

    @property
    def responder(self) -> Endpoint:
        return self.endpoint_b

    def endpoint(self, which: str) -> Endpoint:
        """Return an endpoint by ``"a"``/``"b"``/``"initiator"``/``"responder"``."""
        key = str(which).strip().lower()
        if key in {"a", "initiator", self.endpoint_a.name.lower()}:
            return self.endpoint_a
        if key in {"b", "responder", self.endpoint_b.name.lower()}:
            return self.endpoint_b
        raise ConfigValidationError(f"unknown endpoint reference: {which!r}", hint="use a|b|initiator|responder")

    def peer_of(self, which: str) -> Endpoint:
        return self.endpoint_b if self.endpoint(which).role == INITIATOR else self.endpoint_a

    def supports_ip_version(self, ip_version: int) -> bool:
        return self.endpoint_a.supports(ip_version) and self.endpoint_b.supports(ip_version)

    # -- selectors ------------------------------------------------------
    def selectors(self, mode: str, ip_version: int, *, direction: str = "a_to_b") -> TrafficSelectors:
        """Traffic selectors for the CHILD_SA of ``direction``.

        Tunnel mode protects the networks behind the endpoints, transport mode
        protects the endpoints themselves (host selectors only).
        """
        source = self.endpoint_a if direction == "a_to_b" else self.endpoint_b
        target = self.endpoint_b if direction == "a_to_b" else self.endpoint_a
        if mode == "transport":
            return TrafficSelectors(
                local_ts=host_cidr(str(source.outer_address(ip_version)), ip_version),
                remote_ts=host_cidr(str(target.outer_address(ip_version)), ip_version),
            )
        if mode == "tunnel":
            local_address = source.protected_network(ip_version)
            remote_address = target.protected_network(ip_version)
            if local_address is None or remote_address is None:
                raise ConfigValidationError(
                    f"endpoint {source.name!r} or {target.name!r} has no protected IPv{ip_version} address",
                    hint="tunnel mode needs protected_ipv4/protected_ipv6 on both endpoints",
                )
            return TrafficSelectors(
                local_ts=network_cidr(local_address),
                remote_ts=network_cidr(remote_address),
            )
        raise ConfigValidationError(
            f"unsupported IPsec mode: {mode!r}",
            hint="supported modes: tunnel, transport",
        )


    # -- traffic addressing ---------------------------------------------
    def traffic_source(self, mode: str, ip_version: int) -> str:
        """Source address the traffic generator should use on endpoint A."""
        endpoint = self.endpoint_a
        if mode == "transport":
            return host_address(str(endpoint.outer_address(ip_version)))
        address = endpoint.protected_network(ip_version)
        if address is None:
            raise ConfigValidationError(f"{endpoint.name} has no protected IPv{ip_version} address")
        return host_address(address)

    def traffic_target(self, mode: str, ip_version: int) -> str:
        """Target address the traffic generator should send to (on endpoint B)."""
        endpoint = self.endpoint_b
        if mode == "transport":
            return host_address(str(endpoint.outer_address(ip_version)))
        address = endpoint.protected_network(ip_version)
        if address is None:
            raise ConfigValidationError(f"{endpoint.name} has no protected IPv{ip_version} address")
        return host_address(address)

    def route_to_peer(self, mode: str, ip_version: int) -> dict[str, str] | None:
        """Route needed on endpoint A so that traffic to B's side is protected.

        For tunnel mode this routes B's protected network through the IPsec
        peer while pinning the source address to A's protected address - which
        is what makes the packet match ``local_ts``.  Transport mode needs no
        extra route.
        """
        if mode != "tunnel":
            return None
        peer_network = self.endpoint_b.protected_network(ip_version)
        if peer_network is None:
            return None
        return {
            "destination": network_cidr(peer_network),
            "gateway": host_address(str(self.endpoint_b.outer_address(ip_version))),
            "source": host_address(str(self.endpoint_a.protected_network(ip_version))),
        }

    def capture_interface(self, endpoint: str = "a") -> str | None:
        """Interface to capture on, *inside* the given endpoint.

        The outer veth end of the endpoint carries IKE, ESP and (for transport
        mode) the protected traffic, so it is the right vantage point.
        """
        target = self.endpoint(endpoint)
        if target.netns is None and not target.command_prefix:
            return None
        return self.veth_a if target.role == INITIATOR else self.veth_b

    # -- metadata --------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "description": self.description,
            "runner": self.runner,
            "link": {"ipv4": self.link_ipv4, "ipv6": self.link_ipv6, "mtu": self.mtu},
            "interfaces": {
                "veth_a": self.veth_a,
                "veth_b": self.veth_b,
                "lan_a": self.lan_interface_a,
                "lan_b": self.lan_interface_b,
            },
            "ike": {"port": self.ike_port, "nat_t_port": self.nat_t_port},
            "endpoints": {"a": self.endpoint_a.to_dict(), "b": self.endpoint_b.to_dict()},
        }

    def metadata_block(self, mode: str, ip_version: int) -> dict[str, Any]:
        """Public, non-sensitive description of the testbed used by ground truth."""
        selectors = self.selectors(mode, ip_version)
        return {
            "topology": self.name,
            "runner": self.runner,
            "initiator": self.endpoint_a.describe(),
            "responder": self.endpoint_b.describe(),
            "initiator_ike_id": self.endpoint_a.ike_id,
            "responder_ike_id": self.endpoint_b.ike_id,
            "initiator_outer_address": self.endpoint_a.outer_address(ip_version),
            "responder_outer_address": self.endpoint_b.outer_address(ip_version),
            "traffic_source": self.traffic_source(mode, ip_version),
            "traffic_target": self.traffic_target(mode, ip_version),
            "selectors": selectors.to_dict(),
        }


_TOPOLOGY_KEYS = {"schema_version", "name", "description", "runner", "link", "interfaces", "ike", "endpoints"}
_ENDPOINT_KEYS = {
    "name",
    "role",
    "ike_id",
    "outer_ipv4",
    "outer_ipv6",
    "protected_ipv4",
    "protected_ipv6",
    "netns",
    "command_prefix",
    "sudo",
}


def _reject_unknown_keys(data: Mapping[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigValidationError(
            f"{context} contains unknown field(s): {', '.join(unknown)}",
            hint=f"allowed fields: {', '.join(sorted(allowed))}",
            details={"unknown": unknown, "allowed": sorted(allowed)},
        )


def endpoint_from_dict(data: Mapping[str, Any]) -> Endpoint:
    """Build an :class:`Endpoint` from a mapping, rejecting unknown fields."""
    if not isinstance(data, Mapping):
        raise ConfigValidationError("endpoint definition must be a mapping")
    _reject_unknown_keys(data, _ENDPOINT_KEYS, "endpoint definition")
    for required in ("name", "role"):
        if not data.get(required):
            raise ConfigValidationError(f"endpoint definition is missing {required!r}")
    prefix = data.get("command_prefix") or ()
    if isinstance(prefix, str):
        raise ConfigValidationError(
            "command_prefix must be a list of arguments, not a string",
            hint='use e.g. ["ip", "netns", "exec", "fera-a"]',
        )
    return Endpoint(
        name=str(data["name"]),
        role=str(data["role"]),
        outer_ipv4=data.get("outer_ipv4"),
        outer_ipv6=data.get("outer_ipv6"),
        protected_ipv4=data.get("protected_ipv4"),
        protected_ipv6=data.get("protected_ipv6"),
        ike_id=str(data.get("ike_id") or ""),
        netns=data.get("netns"),
        command_prefix=tuple(str(part) for part in prefix),
        sudo=bool(data.get("sudo", False)),
    )


def topology_from_dict(data: Mapping[str, Any]) -> TestbedTopology:
    """Build a :class:`TestbedTopology` from a mapping (e.g. parsed YAML)."""
    if not isinstance(data, Mapping):
        raise ConfigValidationError("topology document must be a mapping")
    _reject_unknown_keys(data, _TOPOLOGY_KEYS, "topology document")
    endpoints = data.get("endpoints")
    if not isinstance(endpoints, Mapping) or "a" not in endpoints or "b" not in endpoints:
        raise ConfigValidationError(
            "topology document needs an 'endpoints' mapping with keys 'a' and 'b'",
            details={"found": sorted(endpoints) if isinstance(endpoints, Mapping) else None},
        )
    link = data.get("link") or {}
    interfaces = data.get("interfaces") or {}
    ike = data.get("ike") or {}
    return TestbedTopology(
        name=str(data.get("name") or "unnamed"),
        description=str(data.get("description") or ""),
        runner=str(data.get("runner") or "netns"),
        link_ipv4=link.get("ipv4"),
        link_ipv6=link.get("ipv6"),
        mtu=int(link.get("mtu", 1400)),
        veth_a=str(interfaces.get("veth_a", "fera-va")),
        veth_b=str(interfaces.get("veth_b", "fera-vb")),
        lan_interface_a=str(interfaces.get("lan_a", "fera-lana")),
        lan_interface_b=str(interfaces.get("lan_b", "fera-lanb")),
        ike_port=int(ike.get("port", 500)),
        nat_t_port=int(ike.get("nat_t_port", 4500)),
        schema_version=int(data.get("schema_version", 1)),
        endpoint_a=endpoint_from_dict(endpoints["a"]),
        endpoint_b=endpoint_from_dict(endpoints["b"]),
    )


#: Shipped default topology.  ``configs/templates/testbed_topology.yaml`` is a
#: mirror of this document and ``tests/test_topology.py`` fails if the two ever
#: drift apart.
DEFAULT_TOPOLOGY_DOCUMENT: dict[str, Any] = {
    "schema_version": 1,
    "name": "netns_dualstack",
    "description": (
        "Two Linux network namespaces joined by a veth pair.  Each namespace is one "
        "IPsec endpoint with an additional protected address behind it (tunnel mode)."
    ),
    "runner": "netns",
    "link": {"ipv4": "10.10.10.0/24", "ipv6": "fd00:10:10::/64", "mtu": 1400},
    "interfaces": {
        "veth_a": "fera-va",
        "veth_b": "fera-vb",
        "lan_a": "fera-lana",
        "lan_b": "fera-lanb",
    },
    "ike": {"port": 500, "nat_t_port": 4500},
    "endpoints": {
        "a": {
            "name": "endpoint-a",
            "role": "initiator",
            "ike_id": "endpoint-a.fera.test",
            "netns": "fera-a",
            "outer_ipv4": "10.10.10.1/24",
            "outer_ipv6": "fd00:10:10::1/64",
            "protected_ipv4": "10.20.0.1/24",
            "protected_ipv6": "fd00:20::1/64",
        },
        "b": {
            "name": "endpoint-b",
            "role": "responder",
            "ike_id": "endpoint-b.fera.test",
            "netns": "fera-b",
            "outer_ipv4": "10.10.10.2/24",
            "outer_ipv6": "fd00:10:10::2/64",
            "protected_ipv4": "10.30.0.1/24",
            "protected_ipv6": "fd00:30::1/64",
        },
    },
}


def default_topology() -> TestbedTopology:
    """Return the built-in testbed topology."""
    return topology_from_dict(DEFAULT_TOPOLOGY_DOCUMENT)


def load_topology(path: str | None = None) -> TestbedTopology:
    """Load a topology from ``path``, falling back to the shipped default.

    A missing default template file is not an error - the built-in document is
    used instead, so the pipeline works in a fresh checkout.
    """
    if path is None:
        from ..common.paths import default_paths

        candidate = default_paths().topology_file
        if not candidate.is_file():
            return default_topology()
        path = str(candidate)
    from ..common.serialization import load_document

    data = load_document(path)
    return topology_from_dict(data)


__all__ = [
    "DEFAULT_TOPOLOGY_DOCUMENT",
    "INITIATOR",
    "RESPONDER",
    "SUPPORTED_ROLES",
    "Endpoint",
    "TestbedTopology",
    "TrafficSelectors",
    "default_topology",
    "endpoint_from_dict",
    "host_address",
    "host_cidr",
    "is_host_selector",
    "load_topology",
    "network_cidr",
    "split_cidr",
    "topology_from_dict",
]





