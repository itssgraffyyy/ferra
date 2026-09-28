#!/usr/bin/env python3
"""Check whether this machine can run FERA IPsec experiments.

Reports every capability with an explicit status (AVAILABLE / MISSING /
UNVERIFIED / UNSUPPORTED / NOT_APPLICABLE) and never claims a testbed works
without having probed it::

    python scripts/check_environment.py
    python scripts/check_environment.py --json                 # write data/manifests/environment.json
    python scripts/check_environment.py --strict                # non-zero exit when not ready
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import _bootstrap  # noqa: E402  (inserts src/ into sys.path)
from fera.common.paths import default_paths  # noqa: E402
from fera.testbed.environment import check_environment  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report the capabilities FERA needs (strongSwan, XFRM, capture tools, IPv6, ...)."
    )
    parser.add_argument("--json", nargs="?", const="", default=None,
                        help="write the report as JSON (optionally to a path)")
    parser.add_argument("--strict", action="store_true",
                        help="exit with status 1 when the environment is not ready")
    parser.add_argument("--expected-ip-version", type=int, choices=(4, 6), default=None,
                        help="treat IPv6 as mandatory (use with IPv6 experiments)")
    parser.add_argument("--capture-interface", default=None,
                        help="also verify that this capture interface exists")
    parser.add_argument("--quiet", action="store_true", help="only print the JSON path / exit status")
    parser.add_argument("--log-level", default="WARNING")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging(args.log_level)
    paths = default_paths()

    report = check_environment(
        paths,
        expected_ip_version=args.expected_ip_version,
        capture_interface=args.capture_interface,
    )
    if not args.quiet:
        print(report.render_text())

    if args.json is not None:
        target = Path(args.json) if args.json else paths.environment_report_file
        _bootstrap.write_json_output(target, report.to_dict())
        print(f"\nJSON report written to {target}")
    if args.quiet:
        print(f"ready={report.ready} blocking={len(report.blocking_checks)}")

    if not report.ready and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
