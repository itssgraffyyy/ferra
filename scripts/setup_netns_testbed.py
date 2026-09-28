#!/usr/bin/env python3
"""Create (or remove) the Linux network namespace IPsec testbed.

    python scripts/setup_netns_testbed.py --print-only          # show the script
    sudo python scripts/setup_netns_testbed.py --apply --start-charon
    sudo python scripts/setup_netns_testbed.py --stop-charon --teardown

Requires Linux with root (CAP_NET_ADMIN).  The topology comes from
``configs/templates/testbed_topology.yaml``; nothing here is hard-coded.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import _bootstrap  # noqa: E402
from fera.common.errors import ErrorCode, FeraError  # noqa: E402
from fera.common.logging_utils import get_logger  # noqa: E402
from fera.common.paths import default_paths  # noqa: E402
from fera.common.serialization import write_json, write_text_file  # noqa: E402
from fera.testbed.namespaces import (  # noqa: E402
    charon_command,
    default_socket_dir,
    netns_script_document,
    render_netns_setup_script,
    render_netns_teardown_script,
    topology_summary_lines,
    vici_socket_path,
)
from fera.testbed.swanctl_config import render_strongswan_conf  # noqa: E402
from fera.testbed.topology import load_topology  # noqa: E402

logger = get_logger("scripts.setup_netns_testbed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage the FERA namespace testbed.")
    parser.add_argument("--topology", default=None, help="topology YAML (default: configs/templates/...)")
    parser.add_argument("--apply", action="store_true", help="create the namespaces and addressing")
    parser.add_argument("--teardown", action="store_true", help="delete the namespaces")
    parser.add_argument("--print-only", action="store_true", help="print the generated script and exit")
    parser.add_argument("--start-charon", action="store_true",
                        help="start one charon instance per endpoint with its own vici socket")
    parser.add_argument("--stop-charon", action="store_true", help="stop the FERA charon instances")
    parser.add_argument("--charon-binary", default="/usr/lib/ipsec/charon")
    parser.add_argument("--socket-dir", default=None,
                        help="directory for the per endpoint VICI sockets (default: /run/fera-testbed)")
    parser.add_argument("--log-dir", default=None,
                        help="directory for charon logs and strongswan.conf files (default: data/logs/netns)")
    parser.add_argument("--log-level", default="INFO")
    return parser


def _require_linux_root() -> None:
    if platform.system() != "Linux":
        raise FeraError(
            "the namespace testbed requires Linux",
            code=ErrorCode.UNSUPPORTED_PLATFORM,
            hint="run this inside the Linux testbed (VM, bare metal, or a WSL2 distribution with XFRM support)",
        )
    if os.geteuid() != 0:
        raise FeraError(
            "the namespace testbed requires root (CAP_NET_ADMIN)",
            code=ErrorCode.INSUFFICIENT_PRIVILEGES,
            hint="re-run with sudo",
        )


def _run_script(script: str, description: str) -> int:
    logger.info("running generated script: %s", description)
    completed = subprocess.run(  # noqa: S603 - generated script, no user data interpolated
        ["bash", "-s"],
        input=script,
        text=True,
        check=False,
    )
    return completed.returncode


def _start_charon(topology, socket_dir: Path, log_dir: Path, binary: str) -> list[dict]:
    """Write per endpoint strongswan.conf files and start the daemons."""
    socket_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    started: list[dict] = []
    for key in ("a", "b"):
        socket_path = vici_socket_path(socket_dir, key)
        log_file = log_dir / f"charon-{key}.log"
        conf_file = log_dir / f"strongswan-{key}.conf"
        write_text_file(
            conf_file,
            render_strongswan_conf(vici_socket=str(socket_path), log_file=str(log_file)),
        )
        socket_path.unlink(missing_ok=True)
        command = charon_command(topology, key, strongswan_conf=conf_file, charon_binary=binary)
        log_handle = log_file.open("ab")
        process = subprocess.Popen(  # noqa: S603 - argument array, no shell
            command,
            stdout=log_handle,
            stderr=log_handle,
            stdin=subprocess.DEVNULL,
        )
        started.append(
            {
                "endpoint": key,
                "namespace": topology.endpoint(key).netns,
                "pid": process.pid,
                "vici_socket": str(socket_path),
                "strongswan_conf": str(conf_file),
                "log_file": str(log_file),
            }
        )
        logger.info("started charon for endpoint %s (pid %s, socket %s)", key, process.pid, socket_path)
    write_json(log_dir / "charon-instances.json", {"instances": started})
    return started


def _stop_charon(log_dir: Path) -> int:
    """Stop the charon instances started by a previous --start-charon run."""
    import json
    import signal

    record = log_dir / "charon-instances.json"
    if not record.is_file():
        logger.warning("no charon instance record found at %s", record)
        return 0
    stopped = 0
    for instance in json.loads(record.read_text(encoding="utf-8")).get("instances", []):
        pid = instance.get("pid")
        if not pid:
            continue
        try:
            os.kill(int(pid), signal.SIGTERM)
            stopped += 1
            logger.info("stopped charon pid %s (endpoint %s)", pid, instance.get("endpoint"))
        except (ProcessLookupError, PermissionError) as exc:
            logger.warning("could not stop charon pid %s: %s", pid, exc)
    return stopped


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging(args.log_level)
    paths = default_paths()
    topology = load_topology(args.topology)

    setup_script = render_netns_setup_script(topology)
    teardown_script = render_netns_teardown_script(topology)
    log_dir = Path(args.log_dir) if args.log_dir else paths.logs / "netns"
    socket_dir = Path(args.socket_dir) if args.socket_dir else default_socket_dir()

    if args.print_only:
        print("\n".join(topology_summary_lines(topology)))
        print()
        print(setup_script)
        return 0

    _require_linux_root()
    if shutil.which("ip") is None:
        raise FeraError(
            "the `ip` utility (iproute2) is required",
            code=ErrorCode.TOOL_NOT_AVAILABLE,
            hint="apt-get install iproute2",
        )

    exit_code = 0
    if args.apply:
        exit_code = _run_script(setup_script, "namespace testbed setup")
        if exit_code != 0:
            print("failed to create the namespace testbed", file=sys.stderr)
            return exit_code
        write_json(
            paths.manifests / "testbed.json",
            netns_script_document(topology) | {"log_dir": str(log_dir), "socket_dir": str(socket_dir)},
        )
        print("namespace testbed is up")
    if args.start_charon:
        if shutil.which(args.charon_binary) is None and not Path(args.charon_binary).is_file():
            raise FeraError(
                f"charon binary not found: {args.charon_binary}",
                code=ErrorCode.STRONGSWAN_NOT_INSTALLED,
                hint="install strongSwan (apt-get install strongswan strongswan-swanctl)",
            )
        _start_charon(topology, socket_dir, log_dir, args.charon_binary)
        print(f"started charon instances in {topology.endpoint_a.netns} and {topology.endpoint_b.netns}")
    if args.stop_charon:
        stopped = _stop_charon(log_dir)
        print(f"stopped {stopped} charon instance(s)")
    if args.teardown:
        exit_code = _run_script(teardown_script, "namespace testbed teardown")
        print("namespace testbed removed" if exit_code == 0 else "teardown failed")
    if not any((args.apply, args.start_charon, args.stop_charon, args.teardown)):
        print("nothing to do: pass --apply, --start-charon, --stop-charon, --teardown or --print-only")
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FeraError as error:  # pragma: no cover - CLI error path
        print(f"ERROR [{error.code.value}]: {error.message}", file=sys.stderr)
        if error.hint:
            print(f"hint: {error.hint}", file=sys.stderr)
        sys.exit(1)

