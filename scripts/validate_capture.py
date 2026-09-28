#!/usr/bin/env python3
"""Sanity check a capture file (IKE / ESP / IP version / packets).

    python scripts/validate_capture.py --pcap data/raw/exp_000_.../capture.pcap
    python scripts/validate_capture.py --pcap capture.pcap --expected-ip-version 6 --json

This is a *dataset* check, not protocol analysis (that is Prompt 2's job).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import _bootstrap  # noqa: E402
from fera.capture.sanity import validate_capture  # noqa: E402
from fera.common.errors import FeraError  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate that a capture contains IKE/ESP as expected.")
    parser.add_argument("--pcap", required=True, help="capture file to validate")
    parser.add_argument("--expected-ip-version", type=int, choices=(4, 6), default=None)
    parser.add_argument("--no-tshark", action="store_true", help="use only FERA's built-in scanner")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("--log-level", default="WARNING")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging(args.log_level)
    try:
        result = validate_capture(
            Path(args.pcap),
            expected_ip_version=args.expected_ip_version,
            use_tshark=not args.no_tshark,
        )
    except FeraError as error:
        print(f"ERROR [{error.code.value}]: {error.message}", file=sys.stderr)
        return 1
    if args.json:
        _bootstrap.print_json(result.to_dict())
    else:
        print(result.render_text())
    return 0 if result.valid else 1


if __name__ == "__main__":
    sys.exit(main())
