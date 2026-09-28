#!/usr/bin/env python3
"""Build the dataset manifest from the captured runs.

    python scripts/build_manifest.py
    python scripts/build_manifest.py --with-coverage --print-entries
    python scripts/build_manifest.py --raw data/raw --out data/manifests/dataset.json

Only captures whose sanity check passed are listed as samples; everything else
is reported under ``rejected`` with the reason.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import _bootstrap  # noqa: E402
from fera.common.errors import FeraError  # noqa: E402
from fera.common.paths import default_paths  # noqa: E402
from fera.dataset.manifest import build_manifest, write_manifest  # noqa: E402
from fera.dataset.matrix import build_matrix, check_coverage, coverage_report  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build data/manifests/dataset.json from data/raw.")
    parser.add_argument("--raw", default=None, help="raw data directory (default: data/raw)")
    parser.add_argument("--out", default=None, help="manifest path (default: data/manifests/dataset.json)")
    parser.add_argument("--with-coverage", action="store_true",
                        help="also embed the PS coverage report of the generated matrix")
    parser.add_argument("--print-entries", action="store_true", help="print one line per sample")
    parser.add_argument("--json", action="store_true", help="print the manifest to stdout")
    parser.add_argument("--log-level", default="WARNING")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging(args.log_level)
    paths = default_paths()

    manifest = build_manifest(
        paths=paths,
        raw_dir=Path(args.raw) if args.raw else None,
    )
    if args.with_coverage:
        configs = build_matrix()
        manifest["matrix_coverage"] = coverage_report(check_coverage(configs), configs=configs)

    _bootstrap.print_section("Dataset manifest")
    print(f"samples         : {manifest['sample_count']}")
    print(f"rejected        : {manifest['rejected_count']}")
    print(f"runs scanned    : {manifest['scanned_runs']}")
    for dimension, counts in manifest["summary"].items():
        rendered = ", ".join(f"{key}={value}" for key, value in counts.items()) or "none"
        print(f"{dimension:<16}: {rendered}")

    if args.print_entries:
        print()
        for entry in manifest["entries"]:
            print(
                f"  {entry['experiment_id']}: {entry['mode']}/{entry['encryption']}+{entry['integrity']} "
                f"{entry['dh_group']} pfs={'on' if entry['pfs'] else 'off'} IPv{entry['ip_version']} "
                f"{entry['traffic_type']} -> {entry['pcap_path']}"
            )
    if manifest["rejected_count"] and not args.json:
        print()
        print("rejected runs:")
        for rejected in manifest.get("rejected", []):
            print(f"  {rejected['experiment_id']}: {rejected['reason']}")

    target = write_manifest(manifest, Path(args.out) if args.out else None)
    print(f"\nmanifest written to {target} (relative paths, no packet data duplicated)")

    if args.json:
        _bootstrap.print_json(manifest)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FeraError as error:  # pragma: no cover - CLI error path
        print(f"ERROR [{error.code.value}]: {error.message}", file=sys.stderr)
        sys.exit(1)
