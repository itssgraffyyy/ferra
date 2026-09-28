#!/usr/bin/env python3
"""Build the labelled ML dataset from the captured runs.

    python scripts/build_dataset.py
    python scripts/build_dataset.py --seed 7 --fractions 0.8,0.1,0.1
    python scripts/build_dataset.py --raw data/raw --out data/processed/ml

Each row is a feature vector joined with its ground-truth label.  The label
lives beside the features and is never one of them, and splits are assigned per
experiment id so no two captures of one run can straddle a train/test boundary.

Paths inside the artefacts stay relative to the repository root, so ``--raw``
and ``--out`` are interpreted against it (set ``FERA_ROOT`` to relocate the
whole tree, exactly like the other pipeline scripts).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import _bootstrap  # noqa: E402
from fera.common.errors import FeraError  # noqa: E402
from fera.common.paths import default_paths  # noqa: E402
from fera.ml.dataset import SPLITS, build_dataset, write_dataset  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the labelled ML dataset from data/raw.")
    parser.add_argument("--raw", default=None, help="raw data directory (default: data/raw)")
    parser.add_argument("--out", default=None, help="output directory (default: data/processed/ml)")
    parser.add_argument("--seed", type=int, default=0, help="split seed (default: 0)")
    parser.add_argument(
        "--fractions",
        default="0.7,0.15,0.15",
        help="train,val,test split fractions (default: 0.7,0.15,0.15)",
    )
    parser.add_argument("--print-samples", action="store_true", help="print one line per row")
    parser.add_argument("--json", action="store_true", help="print the dataset summary to stdout")
    parser.add_argument("--log-level", default="WARNING")
    return parser


def parse_fractions(value: str) -> tuple[float, ...]:
    try:
        fractions = tuple(float(part) for part in value.split(","))
    except ValueError as exc:
        raise SystemExit(f"--fractions must be comma separated numbers, got {value!r}") from exc
    if len(fractions) != len(SPLITS):
        raise SystemExit(f"--fractions must hold exactly {len(SPLITS)} values (train,val,test)")
    return fractions


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging(args.log_level)
    paths = default_paths()

    bundle = build_dataset(
        paths=paths,
        raw_dir=Path(args.raw) if args.raw else None,
        seed=args.seed,
        fractions=parse_fractions(args.fractions),
    )
    written = write_dataset(bundle, Path(args.out) if args.out else None)
    summary = bundle.summary

    _bootstrap.print_section("ML dataset")
    print(f"samples         : {summary['sample_count']}")
    print(f"rejected        : {summary['rejected_count']}")
    print(f"runs scanned    : {summary['runs_scanned']}")
    print(f"feature schema  : {summary['feature_schema']}")
    print(f"evidence status : {summary['evidence_status']}")
    print(f"split seed      : {summary['seed']}")
    for split in SPLITS:
        counts = summary["label_counts_by_split"][split]
        rendered = ", ".join(f"{key}={value}" for key, value in counts.items()) or "none"
        print(
            f"{split:<16}: {summary['split_counts'][split]:>4} row(s), "
            f"{summary['group_counts'][split]:>3} group(s)  {rendered}"
        )
    integrity = summary["split_integrity"]
    verdict = "ok" if integrity["ok"] else "OVERLAPPING GROUPS"
    print(f"split integrity : {verdict} ({integrity['group_count']} group(s))")

    if args.print_samples:
        print()
        for sample in bundle.samples:
            print(f"  {sample.experiment_id}: {sample.label} -> {sample.split} ({sample.capture_id})")
    if bundle.rejected and not args.json:
        print()
        print("rejected runs:")
        for rejected in bundle.rejected:
            print(f"  {rejected.get('experiment_id', '?')}: {rejected.get('reason', 'rejected')}")

    print()
    print(f"rows            : {written['jsonl']}")
    print(f"table           : {written['csv']}")
    print(f"summary         : {written['summary']}")
    if not bundle.samples:
        print("\nno valid captures found - run experiments first (scripts/run_experiment.py)")

    if args.json:
        _bootstrap.print_json(bundle.to_dict())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FeraError as error:  # pragma: no cover - CLI error path
        print(f"ERROR [{error.code.value}]: {error.message}", file=sys.stderr)
        sys.exit(1)
