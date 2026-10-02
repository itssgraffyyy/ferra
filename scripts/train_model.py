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
from fera.ml.calibration import CALIBRATION_METHODS  # noqa: E402
from fera.ml.feature_sets import FEATURE_SETS  # noqa: E402
from fera.ml.train import (  # noqa: E402
    CANDIDATE_ORDER,
    ablate_feature_families,
    ablate_feature_sets,
    train_traffic_model,
)


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
    parser.add_argument(
        "--feature-families",
        action="store_true",
        help="ablate the size / timing / direction / combined feature families",
    )
    parser.add_argument(
        "--held-out-config",
        action="store_true",
        help="evaluate generalisation to configurations never seen in training",
    )
    parser.add_argument(
        "--held-out-class",
        default=None,
        metavar="CLASS",
        help="leave this traffic class out of training and measure UNKNOWN rejection of it",
    )
    parser.add_argument(
        "--held-out-configs",
        default=None,
        metavar="IDS",
        help="comma separated configuration ids to hold out (default: the last quarter)",
    )
    parser.add_argument(
        "--calibration-method",
        default=None,
        choices=sorted(CALIBRATION_METHODS),
        help="fit a calibration map on the validation split and persist it with the model",
    )
    parser.add_argument(
        "--open-world-threshold",
        type=float,
        default=None,
        help="enable open-world rejection at this confidence threshold (validation-derived)",
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


def _held_out_class_report(dataset: Path, class_name: str, kwargs: dict) -> dict:
    """Run the leave-one-class-out experiment from the command line."""
    from fera.ml.dataset import load_dataset  # noqa: PLC0415
    from fera.ml.heldout import held_out_class_experiment  # noqa: PLC0415

    kwargs.pop("notes", None)
    return held_out_class_experiment(
        load_dataset(dataset),
        class_name,
        candidates=kwargs.get("candidates"),
        seed=int(kwargs.get("seed", 0)),
    )


def _held_out_config_report(dataset: Path, configs: str | None, kwargs: dict) -> dict:
    """Run the held-out-configuration evaluation from the command line.

    Configuration identity is read from the dataset manifest next to the
    samples.  It is used to partition the evaluation only and never becomes a
    feature; if the manifest is absent the run is refused rather than guessed,
    because a fabricated configuration grouping would silently invalidate the
    result it claims to measure.
    """
    import json  # noqa: PLC0415

    from fera.common.paths import default_paths  # noqa: PLC0415
    from fera.ml.dataset import load_dataset  # noqa: PLC0415
    from fera.ml.heldout import evaluate_held_out_configurations  # noqa: PLC0415

    kwargs.pop("notes", None)
    manifest_path = dataset / "dataset_summary.json"
    if not manifest_path.is_file():
        manifest_path = dataset.parent / "manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(
            f"no manifest beside {dataset}: held-out-configuration evaluation needs the "
            "experiment metadata that identifies each capture's configuration"
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest.get("entries") or manifest.get("samples") or []
    config_of = {
        str(item.get("experiment_id")): str(item.get("configuration_hash") or item.get("experiment_id"))
        for item in entries
        if isinstance(item, dict) and item.get("experiment_id")
    }
    if not config_of:
        raise SystemExit(f"{manifest_path} lists no usable configuration identifiers")
    named = [name.strip() for name in (configs or "").split(",") if name.strip()]
    if not named:
        # Default to the last quarter of the configurations, so the split is
        # derived from the data rather than from a number typed on the CLI.
        unique = sorted(set(config_of.values()))
        named = unique[max(1, (len(unique) * 3) // 4) :]
    _ = default_paths()
    return evaluate_held_out_configurations(
        load_dataset(dataset),
        config_of,
        named,
        candidates=kwargs.get("candidates"),
        seed=int(kwargs.get("seed", 0)),
    )


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
        if args.calibration_method:
            kwargs["calibration_method"] = args.calibration_method
        if args.open_world_threshold is not None:
            kwargs["open_world_threshold"] = args.open_world_threshold
        if args.feature_families:
            report = ablate_feature_families(**kwargs)
        elif args.ablate:
            report = ablate_feature_sets(**kwargs)
        elif args.held_out_class:
            report = _held_out_class_report(dataset, args.held_out_class, kwargs)
        elif args.held_out_config:
            report = _held_out_config_report(dataset, args.held_out_configs, kwargs)
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
    elif args.feature_families:
        for row in report.get("results") or ():
            print(
                f"{row.get('family'):<12} {row.get('status'):<10} "
                f"val={row.get('validation_macro_f1')} test={row.get('test_macro_f1')}"
            )
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
