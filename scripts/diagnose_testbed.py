#!/usr/bin/env python3
"""Diagnose the live FERA testbed: is every layer actually working?

    python scripts/diagnose_testbed.py            # human readable
    python scripts/diagnose_testbed.py --json     # machine readable
    sudo python scripts/diagnose_testbed.py       # needed for netns/XFRM detail

This exists because "the experiment failed" is rarely the useful error.  The
same underlying fault was reported four different ways depending on which layer
noticed it last: a capture interface that "does not exist" (it existed, in
another namespace), a VICI socket that was bound but never answered (the daemon
accepted the connection and never serviced it), and a configuration apply error
that was really a dead control plane.

Each layer is probed on its own terms and reported with the evidence that
produced the verdict, so a failure names the layer that broke rather than the
step that tripped over it.

This script is strictly read-only.  It never mounts, unmounts, starts, stops or
edits anything.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import _bootstrap  # noqa: E402
from fera.testbed.namespaces import default_socket_dir, vici_socket_path  # noqa: E402
from fera.testbed.topology import load_topology  # noqa: E402

OK = "ok"
BAD = "bad"
UNKNOWN = "unknown"


@dataclass
class Probe:
    """One layer of the testbed and the verdict reached about it."""

    name: str
    status: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "evidence": self.evidence,
        }


def _run(command: list[str], timeout: float = 20.0) -> tuple[int, str, str]:
    """Run a command, returning (rc, stdout, stderr). Never raises."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout:g}s"
    except (OSError, ValueError) as exc:  # pragma: no cover - environment dependent
        return 127, "", str(exc)
    return result.returncode, result.stdout or "", result.stderr or ""


def _socket_lines(text: str) -> set[str]:
    """Interface names from ``ip -o link show`` output."""
    names: set[str] = set()
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        names.add(parts[1].strip().split("@", 1)[0].split(":", 1)[0])
    return names


def probe_namespaces(topology: Any) -> Probe:
    rc, out, _ = _run(["ip", "netns", "list"])
    if rc != 0:
        return Probe("namespaces", BAD, "`ip netns list` failed")
    present = {line.split()[0] for line in out.splitlines() if line.strip()}
    wanted = {topology.endpoint_a.netns, topology.endpoint_b.netns}
    missing = sorted(wanted - present)
    if missing:
        return Probe(
            "namespaces",
            BAD,
            f"missing namespace(s): {', '.join(missing)}",
            {"present": sorted(present),
             "remediation": "sudo python scripts/setup_netns_testbed.py --apply"},
        )
    return Probe("namespaces", OK, f"{len(wanted)} namespaces present", {"present": sorted(wanted)})


def probe_interfaces(topology: Any) -> Probe:
    evidence: dict[str, Any] = {}
    ok = True
    details: list[str] = []
    for key in ("a", "b"):
        endpoint = topology.endpoint(key)
        rc, out, err = _run(["ip", "netns", "exec", endpoint.netns, "ip", "-o", "link", "show"])
        name = getattr(endpoint, "veth", None) or endpoint.netns
        if rc != 0:
            ok = False
            details.append(f"{key}: probe failed ({err.strip() or 'rc=' + str(rc)})")
            continue
        names = _socket_lines(out)
        evidence[key] = sorted(names)
        if name not in names:
            ok = False
            details.append(f"{key}: {name!r} absent")
    if not ok:
        return Probe(
            "interfaces",
            BAD,
            "; ".join(details),
            {**evidence, "remediation": "sudo python scripts/setup_netns_testbed.py --apply"},
        )
    return Probe("interfaces", OK, "both endpoint interfaces present", evidence)


def probe_vici(topology: Any, socket_dir: Path, timeout: float) -> Probe:
    """Round-trip every endpoint daemon on its private VICI socket.

    A bound socket is not a working one.  charon can create and listen on the
    socket, accept the connection (the kernel backlog drops to zero) and then
    never service the request - which is why this sends an actual command
    instead of checking that the file exists.
    """
    evidence: dict[str, Any] = {}
    bad: list[str] = []
    for key in ("a", "b"):
        path = Path(vici_socket_path(socket_dir, key))
        uri = f"unix://{path}"
        if not path.exists():
            bad.append(f"{key}: socket missing ({path})")
            evidence[key] = "socket missing"
            continue
        rc, out, err = _run(["swanctl", "--list-sas", "--uri", uri], timeout=timeout)
        combined = out + err
        if rc == 0:
            evidence[key] = "answering"
        elif "No such file or directory" in combined:
            bad.append(f"{key}: socket missing ({path})")
            evidence[key] = "socket missing"
        elif rc == 124:
            bad.append(f"{key}: no reply within {timeout:g}s (accepted, never serviced)")
            evidence[key] = "stalled"
        else:
            bad.append(f"{key}: rc={rc} {combined.strip().splitlines()[:1]}")
            evidence[key] = f"failed (rc={rc})"
    if bad:
        return Probe(
            "vici",
            BAD,
            "; ".join(bad),
            {
                "results": evidence,
                "remediation": (
                    "restart with 'sudo python scripts/setup_netns_testbed.py --apply "
                    "--start-charon'; a stalled endpoint means charon accepts VICI but "
                    "never services it"
                ),
            },
        )
    return Probe("vici", OK, "both endpoint daemons answer on VICI", {"results": evidence})


def probe_run_mount() -> Probe:
    """Is ``/run`` mounted?

    Worth checking explicitly: ``/var/run`` is a symlink to ``/run`` on most
    distributions, so any tmpfs mounted over the charon runtime directory
    shadows ``/run`` itself.  A daemon started that way in a *host* mount
    namespace takes the host's control socket with it.
    """
    try:
        mounts = Path("/proc/mounts").read_text(encoding="utf-8")
    except OSError as exc:
        return Probe("run_mount", UNKNOWN, f"cannot read /proc/mounts: {exc}")
    mounted = any(
        len(line.split()) > 1 and line.split()[1] == "/run" for line in mounts.splitlines()
    )
    if not mounted:
        return Probe(
            "run_mount",
            BAD,
            "/run is not a mountpoint; the host runtime filesystem is missing",
            {"remediation": "sudo mount -t tmpfs -o rw,nosuid,nodev,mode=755 tmpfs /run"},
        )
    return Probe("run_mount", OK, "/run is mounted")


def probe_xfrm(topology: Any) -> Probe:
    """Does the kernel hold any IPsec state/policy in either endpoint?"""
    evidence: dict[str, Any] = {}
    counts: dict[str, int] = {}
    for key in ("a", "b"):
        endpoint = topology.endpoint(key)
        rc_s, out_s, _ = _run(["ip", "netns", "exec", endpoint.netns, "ip", "-s", "xfrm", "state"])
        rc_p, out_p, _ = _run(["ip", "netns", "exec", endpoint.netns, "ip", "-s", "xfrm", "policy"])
        states = len([ln for ln in out_s.splitlines() if ln.startswith("src ")]) if rc_s == 0 else -1
        policies = len([ln for ln in out_p.splitlines() if ln.startswith("src ")]) if rc_p == 0 else -1
        evidence[key] = {"states": states, "policies": policies}
        counts[key] = states + policies
    if not any(counts.values()):
        return Probe("xfrm", UNKNOWN, "no XFRM state or policy yet (expected before a run)", evidence)
    return Probe("xfrm", OK, f"XFRM present: {counts}", evidence)


def probe_capture_tool() -> Probe:
    for tool in ("tcpdump", "dumpcap", "tshark"):
        path = shutil.which(tool)
        if path:
            return Probe("capture_tool", OK, f"{tool} -> {path}")
    return Probe("capture_tool", BAD, "no capture tool found (tcpdump, dumpcap, tshark)")


def build_report(
    topology: Any,
    *,
    socket_dir: Path | None = None,
    vici_timeout: float = 30.0,
    root_required: bool = False,
) -> list[Probe]:
    resolved = socket_dir or default_socket_dir()
    probes = [
        probe_run_mount(),
        probe_capture_tool(),
        probe_namespaces(topology),
        probe_interfaces(topology),
        probe_vici(topology, resolved, vici_timeout),
        probe_xfrm(topology),
    ]
    if root_required:
        probes.append(
            Probe(
                "privileges",
                OK if os.geteuid() == 0 else UNKNOWN,
                "running as root" if os.geteuid() == 0 else "not root: some probes are incomplete",
                {"euid": os.geteuid()},
            )
        )
    return probes


def render(report: list[Probe]) -> str:
    lines = ["FERA testbed diagnosis", "=" * 46]
    for probe in report:
        mark = {OK: "PASS", BAD: "FAIL", UNKNOWN: "?   "}[probe.status]
        lines.append(f"[{mark}] {probe.name:<14} {probe.detail}")
        remediation = probe.evidence.get("remediation")
        if remediation and probe.status == BAD:
            lines.append(f"        -> {remediation}")
    failing = [p for p in report if p.status == BAD]
    lines.append("=" * 46)
    if failing:
        lines.append(f"{len(failing)} failing layer(s): {', '.join(p.name for p in failing)}")
        lines.append("No experiment can succeed until these are fixed.")
    else:
        lines.append("All probed layers healthy.")
    return "\n".join(lines)



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Diagnose the live FERA testbed (read-only).")
    parser.add_argument("--topology", default=None, help="topology YAML (default: configs/templates/...)")
    parser.add_argument("--socket-dir", default=None, help="directory holding the per endpoint VICI sockets")
    parser.add_argument("--vici-timeout", type=float, default=30.0, help="seconds to wait for a VICI reply")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging("WARNING")
    topology = load_topology(args.topology)
    socket_dir = Path(args.socket_dir) if args.socket_dir else None
    report = build_report(
        topology,
        socket_dir=socket_dir,
        vici_timeout=args.vici_timeout,
        root_required=os.geteuid() == 0,
    )
    if args.json:
        print(json.dumps({"probes": [p.to_dict() for p in report]}, indent=2))
    else:
        print(render(report))
    return 1 if any(p.status == BAD for p in report) else 0


if __name__ == "__main__":
    raise SystemExit(main())

