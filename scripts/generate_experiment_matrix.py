#!/usr/bin/env python3
"""Generate the representative experiment matrix.

Writes one validated YAML file per experiment into ``configs/experiments`` and
an index that records the fingerprints, so a regeneration is a no-op::

    python scripts/generate_experiment_matrix.py                 # write YAML files
    python scripts/generate_experiment_matrix.py --force         # replace existing files
    python scripts/generate_experiment_matrix.py --print-only    # show what would be written
    python scripts/generate_experiment_matrix.py --clean --force # remove stale files first
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import _bootstrap  # noqa: E402
from fera.common.errors import FeraError  # noqa: E402
from fera.common.paths import default_paths  # noqa: E402
from fera.common.serialization import write_json  # noqa: E402
from fera.dataset.matrix import (  # noqa: E402
    build_matrix,
    check_coverage,
    coverage_report,
    render_coverage,
)
from fera.dataset.schema import save_experiment  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate the representative FERA experiment matrix.")
    parser.add_argument("--out", default=None, help="output directory (default: configs/experiments)")
    parser.add_argument("--force", action="store_true", help="overwrite existing experiment files")
    parser.add_argument("--clean", action="store_true", help="delete generated files that are no longer in the matrix")
    parser.add_argument("--id-style", choices=("ordinal", "hash"), default="ordinal")
    parser.add_argument("--capture-duration", type=float, default=None,
                        help="override the capture duration of every experiment (seconds)")
    parser.add_argument("--tag", default=None, help="additional tag applied to every experiment")
    parser.add_argument("--print-only", action="store_true", help="do not write anything")
    parser.add_argument("--json", nargs="?", const="", default=None, help="write a summary JSON document")
    parser.add_argument("--log-level", default="INFO")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging(args.log_level)
    paths = default_paths()
    out_dir = Path(args.out) if args.out else paths.experiments_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    configs = build_matrix(
        id_style=args.id_style,
        capture_duration_s=args.capture_duration,
        tag=args.tag,
    )
    checks = check_coverage(configs)
    report = coverage_report(checks, configs=configs)

    _bootstrap.print_section(f"Experiment matrix ({len(configs)} experiments)")
    for config in configs:
        print("  " + config.summary())
    print()
    print(render_coverage(checks))

    written: list[str] = []
    if not args.print_only:
        wanted: set[str] = set()
        for config in configs:
            target = out_dir / f"{config.experiment_id}.yaml"
            wanted.add(target.name)
            if target.exists() and not args.force:
                print(f"keep   {target.name} (exists, use --force to overwrite)")
                continue
            save_experiment(config, target)
            written.append(target.name)
        index = {
            "schema_version": 1,
            "generated_by": "scripts/generate_experiment_matrix.py",
            "id_style": args.id_style,
            "experiment_count": len(configs),
            "experiments": [
                {
                    "experiment_id": config.experiment_id,
                    "file": f"{config.experiment_id}.yaml",
                    "fingerprint": config.fingerprint,
                    "mode": config.mode.value,
                    "encryption": config.encryption.value,
                    "integrity": config.integrity.value,
                    "dh_group": config.dh_group.value,
                    "pfs": config.pfs,
                    "ip_version": config.ip_version,
                    "traffic_type": config.traffic_type.value,
                }
                for config in configs
            ],
        }
        write_json(out_dir / "_matrix_index.json", index)
        if args.clean:
            for stale in sorted(out_dir.glob("exp_*.yaml")):
                if stale.name not in wanted:
                    stale.unlink()
                    print(f"remove {stale.name} (no longer part of the matrix)")
        print()
        print(f"wrote {len(written)} file(s) to {out_dir}")

    if args.json is not None:
        target = Path(args.json) if args.json else out_dir / "_matrix_summary.json"
        write_json(target, report)
        print(f"summary written to {target}")

    if not report["all_passed"]:
        print("\nERROR: the generated matrix does not satisfy every required dimension", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FeraError as error:  # pragma: no cover - CLI error path
        print(f"ERROR [{error.code.value}]: {error.message}", file=sys.stderr)
        print(f"hint: {error.hint}", file=sys.stderr)
        sys.exit(1)
