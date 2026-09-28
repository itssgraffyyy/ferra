#!/usr/bin/env python3
"""Check which problem statement dimensions the experiment matrix covers.

Every PASS/FAIL is computed from the configurations in ``configs/experiments``
(or from the built-in matrix with ``--from-matrix``) - nothing is hard-coded::

    python scripts/check_matrix_coverage.py
    python scripts/check_matrix_coverage.py --from-matrix --json coverage.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import _bootstrap  # noqa: E402
from fera.common.errors import FeraError  # noqa: E402
from fera.common.paths import default_paths  # noqa: E402
from fera.dataset.matrix import build_matrix, check_coverage, coverage_report, render_coverage  # noqa: E402
from fera.dataset.schema import find_experiment_configs, load_experiment  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify that the experiment matrix covers every required PS dimension."
    )
    parser.add_argument("--experiments", default=None,
                        help="directory of generated experiment files (default: configs/experiments)")
    parser.add_argument("--from-matrix", action="store_true",
                        help="ignore the files on disk and evaluate the built-in matrix")
    parser.add_argument("--json", nargs="?", const="", default=None, help="write the report as JSON")
    parser.add_argument("--quiet", action="store_true", help="only print the summary line")
    parser.add_argument("--log-level", default="WARNING")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging(args.log_level)
    paths = default_paths()

    if args.from_matrix:
        configs = build_matrix()
        source = "built-in matrix"
    else:
        directory = Path(args.experiments) if args.experiments else paths.experiments_dir
        files = find_experiment_configs(directory)
        if not files:
            print(
                f"No experiment files found in {directory}.\n"
                "Run: python scripts/generate_experiment_matrix.py",
                file=sys.stderr,
            )
            return 2
        configs = [load_experiment(path) for path in files]
        source = str(directory)

    checks = check_coverage(configs)
    report = coverage_report(checks, configs=configs)
    report["source"] = source

    if not args.quiet:
        _bootstrap.print_section(f"PS coverage ({len(configs)} experiment(s) from {source})")
    print(render_coverage(checks))

    if args.json is not None:
        target = Path(args.json) if args.json else paths.manifests / "matrix_coverage.json"
        _bootstrap.write_json_output(target, report)
        print(f"coverage report written to {target}")

    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FeraError as error:  # pragma: no cover - CLI error path
        print(f"ERROR [{error.code.value}]: {error.message}", file=sys.stderr)
        print(f"hint: {error.hint}", file=sys.stderr)
        sys.exit(1)
