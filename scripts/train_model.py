#!/usr/bin/env python3
"""Train the traffic classifier, or run a feature-set ablation.

    python scripts/train_model.py
    python scripts/train_model.py --dataset data/processed/ml
    python scripts/train_model.py --feature-set esp_core --seed 7
    python scripts/train_model.py --ablate

Training writes a deployable artefact (estimator + metadata + training report)
under ``data/models/<model_id>``, which is exactly where the product API looks
for it.  ``--ablate`` writes nothing: an ablation is an experiment that measures
shortcut risk across feature sets, not an artefact to serve.

The printed result is the training report itself, including the selected
candidate, the held-out test metrics, and - when the run could not be measured -
an explicit ``performance_status`` saying so.  Nothing here invents a score.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import _bootstrap  # noqa: E402
from fera.common.errors import FeraError  # noqa: E402
from fera.common.paths import default_paths  # noqa: E402
from fera.ml.feature_sets import FEATURE_SETS  # noqa: E402
from fera.ml.train import CANDIDATE_ORDER, ablate_feature_sets, train_traffic_model  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train the FERA traffic classifier.")
    parser.add_argument("--dataset", default=None, help="labelled dataset (default: data/processed/ml)")
    parser.add_argument("--target", default=None, help="artefact directory (default: data/models/<model_id>)")
    parser.add_argument(
        "--feature-set",
        default=None,
        choices=sorted(FEATURE_SETS),
        help="restrict training to a named feature set (default: the whole whitelist)",
    )
    parser.add_argument(
        "--candidates",
        default=None,
        help=f"comma separated subset of {','.join(CANDIDATE_ORDER)} (default: all)",
    )
    parser.add_argument("--seed", type=int, default=None, help="random seed")
    parser.add_argument("--note", action="append", default=[], help="note recorded in the report (repeatable)")
    parser.add_argument(
        "--ablate",
        action="store_true",
        help="run the feature-set ablation instead of training a deployable model",
    )
    parser.add_argument("--json", action="store_true", help="print the raw report to stdout")
    parser.add_argument("--log-level", default="WARNING")
    return parser


def _summarise(report: dict) -> None:
    """Print the few numbers a human needs, without inventing any of them."""
    print(f"model_id           : {report.get('model_id')}")
    print(f"performance_status : {report.get('performance_status')}")
    selection = report.get("selection") or {}
    if selection:
        print(f"selected           : {selection.get('selected')} ({selection.get('criterion')})")
    test = report.get("test") or {}
    if test:
        print(f"test macro_f1      : {test.get('macro_f1')}")
        print(f"test accuracy      : {test.get('accuracy')}")
    for note in report.get("notes") or ():
        print(f"note               : {note}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging(args.log_level)
    paths = default_paths()

    dataset = Path(args.dataset) if args.dataset else paths.processed / "ml"
    if not dataset.exists():
        raise FeraError(
            f"no labelled dataset at {dataset}",
            hint="run scripts/build_dataset.py first",
        )

    candidates = [name.strip() for name in args.candidates.split(",")] if args.candidates else None
    if candidates:
        unknown = [name for name in candidates if name not in CANDIDATE_ORDER]
        if unknown:
            raise SystemExit(f"unknown candidate(s): {', '.join(unknown)}; known: {', '.join(CANDIDATE_ORDER)}")

    try:
        kwargs: dict = {"dataset": dataset, "candidates": candidates, "notes": args.note}
        if args.seed is not None:
            kwargs["seed"] = args.seed
        if args.ablate:
            report = ablate_feature_sets(**kwargs)
        else:
            if args.target:
                kwargs["target"] = args.target
            if args.feature_set:
                kwargs["feature_set"] = args.feature_set
            report = train_traffic_model(**kwargs)
    except FeraError:
        raise
    except Exception as exc:  # sklearn/IO failures are not Fera protocol errors
        raise SystemExit(f"training failed: {exc}") from exc

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif args.ablate:
        for row in report.get("results") or ():
            print(f"{row.get('feature_set'):<12} {row.get('status'):<10} {row.get('test', {}).get('macro_f1')}")
    else:
        _summarise(report)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FeraError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
