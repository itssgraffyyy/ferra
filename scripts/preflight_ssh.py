#!/usr/bin/env python3
"""Verify that the SSH endpoints of a FERA topology are reachable and capable.

    python scripts/preflight_ssh.py --topology configs/templates/testbed_topology_ssh.yaml
    python scripts/preflight_ssh.py --topology ... --json

Run this from the machine that will run FERA *before* any experiment.  A
VirtualBox forwarded port that answers on the Windows host is no evidence that
it answers from WSL, and that is precisely the assumption this script exists to
falsify.

Passing means the endpoint is reachable and able to run FERA.  It says nothing
about whether an experiment will succeed: no IKE_SA, CHILD_SA, ESP or capture is
attempted here, and this script cannot report one.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import _bootstrap  # noqa: E402
from fera.common.errors import FeraError  # noqa: E402
from fera.common.process import SubprocessRunner  # noqa: E402
from fera.testbed.remote_preflight import preflight_endpoint  # noqa: E402
from fera.testbed.topology import load_topology  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight the SSH endpoints of a FERA topology (read-only)."
    )
    parser.add_argument("--topology", required=True, help="topology YAML to check")
    parser.add_argument("--timeout", type=float, default=45.0, help="seconds per probe")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging("WARNING")
    topology = load_topology(args.topology)
    if not topology.is_remote:
        print(
            "This topology has no remote endpoints; nothing to preflight.\n"
            "Set kind: ssh and ssh_host on an endpoint to check it over SSH."
        )
        return 1

    runner = SubprocessRunner()
    results = []
    for key in ("a", "b"):
        endpoint = topology.endpoint(key)
        if not endpoint.is_remote:
            print(f"{endpoint.name}: kind={endpoint.kind!r}, not remote - skipped")
            continue
        peer = topology.endpoint("b" if key == "a" else "a")
        peer_address = peer.outer_address(4) or peer.outer_address(6)
        try:
            outcome = preflight_endpoint(
                endpoint,
                runner,
                peer=peer_address.split("/")[0] if peer_address else None,
                timeout=args.timeout,
            )
        except FeraError as exc:
            print(f"{endpoint.name}: {exc.message}")
            return 1
        results.append(outcome.to_dict())
        if not args.json:
            print(outcome.render_text())

    if args.json:
        print(json.dumps({"endpoints": results}, indent=2))
    ready = all(r["ready"] for r in results) if results else False
    if not ready:
        print("\nNOT ready. Fix the reported problems before running an experiment.")
    else:
        print("\nAll remote endpoints reachable and capable.")
        print("This says nothing about whether an experiment will succeed.")
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
