#!/usr/bin/env python3
"""One entry point for the whole dataset pipeline.

    python scripts/run_pipeline.py --dry-run
    sudo python scripts/run_pipeline.py --repeats 3 --capture-interface veth-a

Runs the five stages in the order they depend on each other:

    matrix -> experiments -> manifest -> dataset -> verify

Running them by hand means knowing that order and the flags each one wants; this
composes them and stops where it is sensible to stop.

Failure policy, stated rather than implied:

* a stage that cannot produce its inputs (the matrix) stops the pipeline, because
  everything after it would fail for the same uninformative reason;
* a run in which **some** experiments failed still builds the manifest and the
  dataset, so the successful captures are not thrown away - the manifest records
  what was rejected - but the pipeline still exits non-zero, so a partial run is
  never reported as a complete one.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[0]))

import build_dataset as stage_dataset  # noqa: E402
import build_manifest as stage_manifest  # noqa: E402
import generate_experiment_matrix as stage_matrix  # noqa: E402
import run_experiment as stage_experiment  # noqa: E402
import verify_dataset as stage_verify  # noqa: E402
from _bootstrap import bootstrap_logging  # noqa: E402
from fera.common.errors import FeraError  # noqa: E402

STAGES = ("matrix", "experiments", "manifest", "dataset", "verify")


@dataclass(frozen=True)
class StageResult:
    name: str
    status: int

    @property
    def ok(self) -> bool:
        return self.status == 0


def _matrix_args(args: argparse.Namespace) -> list[str]:
    # Deliberately NOT --print-only in a dry run: the matrix stage writes the
    # experiment *specifications*, which are plans rather than results, and the
    # experiment stage needs them to exist.  A dry run therefore plans every
    # experiment and still executes none of them.
    argv = ["--out", args.experiments_dir]
    if args.force_matrix:
        argv.append("--force")
    return argv


def _experiment_args(args: argparse.Namespace) -> list[str]:
    argv = ["--config", args.experiments_dir]
    # --raw-dir must be forwarded or the flag lies: the experiments would write
    # into the repository's data/raw while the later stages read from the
    # directory the operator asked for.
    argv += ["--raw-dir", args.raw_dir]
    if args.dry_run:
        argv.append("--dry-run")
    if args.repeats > 1:
        argv += ["--repeats", str(args.repeats)]
    if args.continue_on_error:
        argv.append("--continue-on-error")
    if args.capture_interface:
        argv += ["--capture-interface", args.capture_interface]
    if args.network_condition != "baseline":
        argv += ["--network-condition", args.network_condition]
    argv.append("--update-manifest")
    return argv


def _output_dirs(raw_dir: str) -> tuple[str, str]:
    """Where the manifest and the dataset belong for a given ``--raw-dir``.

    Derived from ``raw_dir`` rather than left to each script's default, so that
    ``--raw-dir`` actually relocates the whole pipeline.  Otherwise the manifest
    is written under the repository while the verify stage looks for it beside
    the raw data, and the run fails at the last step for a path reason.
    """
    parent = Path(raw_dir).parent
    return (
        str(parent / "manifests" / "dataset.json"),
        str(parent / "processed" / "ml"),
    )


def _manifest_args(args: argparse.Namespace) -> list[str]:
    manifest_path, _ = _output_dirs(args.raw_dir)
    argv = ["--raw", args.raw_dir, "--out", manifest_path]
    if args.dry_run:
        # Nothing was captured, so there is no dataset to describe yet.
        argv.append("--print-entries")
    return argv


def _dataset_args(args: argparse.Namespace) -> list[str]:
    _, dataset_out = _output_dirs(args.raw_dir)
    argv = ["--raw", args.raw_dir, "--out", dataset_out]
    if args.dry_run:
        argv.append("--print-samples")
    return argv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the FERA dataset pipeline: matrix -> experiments -> manifest -> dataset -> verify."
    )
    parser.add_argument("--experiments-dir", default="configs/experiments")
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--capture-interface", default=None)
    parser.add_argument(
        "--network-condition",
        default="baseline",
        choices=("baseline", "loss", "jitter", "latency"),
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="plan everything and execute nothing"
    )
    parser.add_argument(
        "--continue-on-error", action="store_true", help="keep running experiments after one fails"
    )
    parser.add_argument(
        "--force-matrix", action="store_true", help="overwrite existing experiment files"
    )
    parser.add_argument(
        "--skip", action="append", default=[], choices=STAGES, help="skip a stage (repeatable)"
    )
    parser.add_argument("--log-level", default="INFO")
    return parser


def run_pipeline(args: argparse.Namespace) -> list[StageResult]:
    """Execute the stages in order and report what each one did."""
    manifest_path, _ = _output_dirs(args.raw_dir)
    plan: list[tuple[str, list[str]]] = [
        ("matrix", _matrix_args(args)),
        ("experiments", _experiment_args(args)),
        ("manifest", _manifest_args(args)),
        ("dataset", _dataset_args(args)),
        ("verify", ["--manifest", str(manifest_path)]),
    ]
    modules = {
        "matrix": stage_matrix,
        "experiments": stage_experiment,
        "manifest": stage_manifest,
        "dataset": stage_dataset,
        "verify": stage_verify,
    }
    results: list[StageResult] = []
    for name, argv in plan:
        if name in args.skip:
            print(f"\n=== {name}: SKIPPED ===")
            results.append(StageResult(name, 0))
            continue
        print(f"\n=== {name}: {' '.join(argv)} ===")
        try:
            status = modules[name].main(argv)
        except FeraError as error:
            # A stage that cannot even start is a failed stage, not a traceback:
            # the summary has to name it so the pipeline can report it honestly.
            print(f"  {name} could not run: {error}", file=sys.stderr)
            status = 2
        results.append(StageResult(name, status))
        if not results[-1].ok and name == "matrix":
            # Everything downstream would fail for the same reason, and a second
            # failure adds noise rather than information.
            print("\nmatrix generation failed; skipping every dependent stage")
            for remaining in STAGES[1:]:
                results.append(StageResult(remaining, 0))
                print(f"=== {remaining}: SKIPPED ===")
            break
    return results


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    bootstrap_logging(args.log_level)
    results = run_pipeline(args)

    print("\n" + "=" * 60)
    print("pipeline summary")
    print("=" * 60)
    worst = 0
    for result in results:
        state = "ok" if result.ok else f"FAILED ({result.status})"
        print(f"  {result.name:<14} {state}")
        worst = max(worst, result.status)
    if worst:
        # Never report a partial run as a complete one.
        print("\nsome stages failed: the artefacts above are incomplete")
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
