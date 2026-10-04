"""Preflight verification for endpoints that live on another machine.

A two-VM testbed driven from a laptop or WSL has a property the namespace
testbed never had: most of what must work lives somewhere FERA cannot see, over
a link that may be a VirtualBox forwarded port that only resolves *inside*
Windows.  ``127.0.0.1:2221`` being reachable from Windows is no evidence that
it is reachable from WSL.

So before an experiment starts, every remote endpoint is verified on its own
terms.  Passing preflight proves the machine is *reachable and capable*; it
proves nothing about the experiment.  No probe here reports success unless it
actually saw the command succeed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..common.errors import ErrorCode, FeraError
from ..common.process import BaseRunner
from .topology import Endpoint

#: Commands an endpoint must provide before FERA can drive an experiment on it.
REQUIRED_COMMANDS = ("swanctl", "ip", "tcpdump")

PASS = "pass"
FAIL = "fail"
UNKNOWN = "unknown"


@dataclass
class PreflightResult:
    """Outcome of preflighting one remote endpoint."""

    endpoint: str
    target: str
    reachable: bool
    checks: list[dict[str, Any]] = field(default_factory=list)
    detail: str = ""

    @property
    def ready(self) -> bool:
        return self.reachable and all(c["status"] != FAIL for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "ssh_target": self.target,
            "reachable": self.reachable,
            "ready": self.ready,
            "detail": self.detail,
            "checks": self.checks,
        }

    def render_text(self) -> str:
        mark = {"pass": "PASS", "fail": "FAIL", "unknown": "?   "}
        lines = [f"{self.endpoint} via {self.target}"]
        for check in self.checks:
            lines.append(f"  [{mark[check['status']]}] {check['name']:<22} {check['detail']}")
        lines.append("  -> " + ("ready for an experiment" if self.ready else "NOT ready"))
        return "\n".join(lines)


def _check(name: str, ok: bool | None, detail: str, **extra: Any) -> dict[str, Any]:
    status = PASS if ok else (UNKNOWN if ok is None else FAIL)
    return {"name": name, "status": status, "detail": detail, **extra}


def preflight_endpoint(
    endpoint: Endpoint,
    runner: BaseRunner,
    *,
    peer: str | None = None,
    timeout: float = 30.0,
) -> PreflightResult:
    """Verify that ``endpoint`` is reachable over SSH and able to run FERA.

    Every probe is a real command executed through the endpoint's SSH prefix.
    A probe that cannot run is reported ``unknown`` or ``fail``, never a pass.
    """
    if not endpoint.is_remote:
        raise FeraError(
            f"preflight_endpoint expects a remote endpoint, got kind={endpoint.kind!r}",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
        )
    prefix = endpoint.ssh_command_prefix()
    result = PreflightResult(endpoint=endpoint.name, target=endpoint.ssh_target, reachable=False)

    # 1. SSH itself, non-interactively.  BatchMode=yes is in the prefix precisely
    #    so this cannot hang waiting for a password or a host-key prompt.
    probe = runner.run([*prefix, "true"], timeout=timeout, check=False)
    if not probe.executed:
        result.checks.append(_check("ssh", None, "not executed (dry run)"))
        result.detail = "dry run: remote preflight was not executed"
        return result
    if not probe.ok:
        result.checks.append(
            _check("ssh", False, f"rc={probe.returncode}: {(probe.stderr or '').strip()[:160]}")
        )
        result.detail = (
            f"cannot reach {endpoint.ssh_target} non-interactively; check the forwarded "
            "port, the key, and that the VM accepts this user"
        )
        return result
    result.reachable = True
    result.checks.append(_check("ssh", True, "non-interactive ssh works"))

    # 2. Required commands must actually exist on that machine.
    missing = [
        command
        for command in REQUIRED_COMMANDS
        if not runner.run([*prefix, "command", "-v", command], timeout=timeout, check=False).ok
    ]
    result.checks.append(
        _check(
            "commands",
            not missing,
            "all required commands present" if not missing else f"missing: {', '.join(missing)}",
        )
    )

    # 3. strongSwan usable, and swanctl answering on the VM's own socket.
    version = runner.run([*prefix, "swanctl", "--version"], timeout=timeout, check=False)
    result.checks.append(
        _check("swanctl", version.ok, "swanctl --version" + ("" if version.ok else " failed"))
    )
    sas = runner.run([*prefix, "swanctl", "--list-sas"], timeout=timeout, check=False)
    result.checks.append(
        _check(
            "vici",
            sas.ok,
            "swanctl reaches the endpoint's default VICI socket"
            if sas.ok
            else "swanctl could not query the endpoint's default VICI socket",
        )
    )

    # 4. The interface and address the topology claims, checked on that machine.
    interface = endpoint.capture_interface
    if interface:
        links = runner.run([*prefix, "ip", "-o", "link", "show"], timeout=timeout, check=False)
        names = {
            line.split(":", 2)[1].strip().split("@", 1)[0]
            for line in (links.stdout or "").splitlines()
            if line.count(":") >= 2
        }
        result.checks.append(
            _check(
                "interface",
                interface in names,
                f"{interface} present" if interface in names else f"{interface} not found",
                interfaces=sorted(names),
            )
        )
    else:
        result.checks.append(_check("interface", None, "no capture interface configured"))

    address = endpoint.outer_address(4) or endpoint.outer_address(6)
    if address:
        bare = address.split("/")[0]
        addrs = runner.run([*prefix, "ip", "-o", "addr", "show"], timeout=timeout, check=False)
        present = bare in (addrs.stdout or "")
        result.checks.append(
            _check(
                "address",
                present,
                f"{bare} present" if present else f"{bare} not configured",
            )
        )

    # 5. Capture capability: what makes a run able to produce a real pcap.  This
    #    is a capability check, never evidence that a capture happened.
    capture = runner.run([*prefix, "tcpdump", "--version"], timeout=timeout, check=False)
    result.checks.append(
        _check("capture", capture.ok, "tcpdump is usable" if capture.ok else "tcpdump is unusable")
    )

    # 6. Peer reachability, deliberately *inconclusive* rather than pass/fail:
    #    IKE runs on UDP 500/4500 and a host may filter ICMP entirely, so a
    #    silent ping must not block an experiment that is otherwise ready.
    if peer:
        ping = runner.run([*prefix, "ping", "-c", "1", "-W", "2", peer], timeout=timeout + 10, check=False)
        result.checks.append(
            _check(
                "peer",
                None if not ping.ok else True,
                (
                    f"{peer} answered ping"
                    if ping.ok
                    else f"{peer} did not answer ping; inconclusive (IKE runs on UDP 500/4500)"
                ),
            )
        )
    else:
        result.checks.append(_check("peer", None, "no peer address known"))

    result.detail = "preflight passed" if result.ready else "preflight found problems"
    return result
def require_remote_endpoints_ready(
    topology: Any,
    runner: BaseRunner,
    *,
    timeout: float = 30.0,
) -> list[PreflightResult]:
    """Preflight every remote endpoint; raise when any is unusable.

    Raises rather than returning a report: an experiment must not start against a
    machine it cannot reach, and the caller asked to be stopped, not warned.
    Local and namespace endpoints are skipped - they are covered by the local
    environment report.
    """
    results: list[PreflightResult] = []
    failures: list[str] = []
    for key in ("a", "b"):
        endpoint = topology.endpoint(key)
        if not endpoint.is_remote:
            continue
        peer_endpoint = topology.endpoint("b" if key == "a" else "a")
        peer_address = peer_endpoint.outer_address(4) or peer_endpoint.outer_address(6)
        outcome = preflight_endpoint(
            endpoint,
            runner,
            peer=peer_address.split("/")[0] if peer_address else None,
            timeout=timeout,
        )
        results.append(outcome)
        if not outcome.ready:
            failures.append(f"{endpoint.name}: {outcome.detail}")
    if failures:
        raise FeraError(
            "remote endpoint preflight failed",
            code=ErrorCode.REMOTE_PREFLIGHT_FAILED,
            hint="; ".join(failures),
            details={"results": [r.to_dict() for r in results]},
        )
    return results


__all__ = [
    "PASS",
    "FAIL",
    "UNKNOWN",
    "REQUIRED_COMMANDS",
    "PreflightResult",
    "preflight_endpoint",
    "require_remote_endpoints_ready",
]
