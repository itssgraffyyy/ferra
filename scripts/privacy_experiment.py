#!/usr/bin/env python3
"""Run the encrypted-traffic privacy experiment loop.

    python scripts/privacy_experiment.py --dataset data/processed/ml
    python scripts/privacy_experiment.py --dataset data/processed/ml --mode fixed
    python scripts/privacy_experiment.py --dataset data/processed/ml --json

This executes the *closed loop* FERA is built around:

    BASELINE -> COUNTERMEASURE -> ATTACKER A -> ATTACKER B -> COMPARE -> OVERHEAD

Two attackers, because one number cannot answer the question.  Attacker A is
frozen and never saw the mitigated traffic; Attacker B retrained on it.  A
mitigation that defeats A but not B is reported exactly that way.

The countermeasure implemented here is a **simulated** packet-size
normalisation.  It is applied in software to already-captured feature rows; it
was not produced by an IPsec implementation on the wire, and it is not RFC 4303
Traffic Flow Confidentiality.  Every document this writes is stamped
``SIMULATED_COUNTERMEASURE`` and the run status says it is not experimental
evidence.  Nothing in this script can promote that state, and asking it to try
is an error rather than a warning.

Byte overhead is reported because it is computable.  Latency, throughput and
jitter are reported as ``NOT_MEASURED`` because nothing here measures them.
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
from fera.common.serialization import write_json  # noqa: E402
from fera.privacy.countermeasure import (  # noqa: E402
    SIZE_MODES,
    SizeNormalizationCountermeasure,
    SizeNormalizationParameters,
)
from fera.privacy.experiment import (  # noqa: E402
    PRIVACY_EXPERIMENT_SCHEMA,
    run_privacy_experiment,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the FERA privacy experiment loop (baseline / mitigation / Attacker A+B)."
    )
    parser.add_argument("--dataset", default=None, help="labelled dataset (default: data/processed/ml)")
    parser.add_argument(
        "--mode",
        default="bucket",
        choices=sorted(SIZE_MODES),
        help="packet-size normalisation mode (default: bucket)",
    )
    parser.add_argument("--bucket-size", type=int, default=256, help="bucket mode quantum in bytes")
    parser.add_argument("--target-size", type=int, default=1400, help="fixed mode target size in bytes")
    parser.add_argument("--max-pad-size", type=int, default=1400, help="largest packet that may be padded")
    parser.add_argument("--experiment-id", default="privacy-experiment")
    parser.add_argument("--candidates", default=None, help="comma separated candidate models")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--output", default=None, help="write the experiment JSON here")
    parser.add_argument(
        "--features",
        default=None,
        help="comma separated feature subset to train on (default: the whole whitelist)",
    )
    parser.add_argument("--json", action="store_true", help="print the raw report to stdout")
    parser.add_argument("--log-level", default="WARNING")
    return parser


def _summarise(report: dict) -> None:
    """Print the numbers a reader needs, with their provenance attached."""
    baseline = report["baseline"]["macro_f1"]
    print(f"experiment_id      : {report['experiment_id']}")
    print(f"status             : {report['status']}")
    print(f"countermeasure     : {report['countermeasure']['name']} ({report['provenance']['state']})")
    print(f"baseline macro F1  : {baseline}")
    print(f"attacker A macro F1: {report['attacker_a']['macro_f1']} (delta {report['attacker_a']['delta_macro_f1']})")
    print(f"attacker B macro F1: {report['attacker_b']['macro_f1']} (delta {report['attacker_b']['delta_macro_f1']})")
    cost = report["cost"]["cost_side"]
    print(f"byte overhead      : {cost['byte_overhead']} ({cost['byte_overhead_percent']}%)")
    print(f"latency/throughput : {report['cost']['not_measured']['latency']}")
    for note in report["limitations"][:4]:
        print(f"limitation         : {note}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging(args.log_level)
    paths = default_paths()

    from fera.ml.dataset import load_dataset  # noqa: PLC0415

    dataset = Path(args.dataset) if args.dataset else paths.processed / "ml"
    if not dataset.exists():
        raise FeraError(
            f"no labelled dataset at {dataset}",
            hint="run scripts/build_dataset.py first",
        )
    samples = list(load_dataset(dataset))
    if not samples:
        raise FeraError(f"{dataset} holds no labelled rows", hint="rebuild the dataset")

    countermeasure = SizeNormalizationCountermeasure(
        SizeNormalizationParameters(
            mode=args.mode,
            target_size=args.target_size,
            bucket_size=args.bucket_size,
            max_pad_size=args.max_pad_size,
        )
    )
    features = (
        [name.strip() for name in args.features.split(",") if name.strip()]
        if args.features
        else None
    )
    candidates = (
        [name.strip() for name in args.candidates.split(",") if name.strip()]
        if args.candidates
        else None
    )
    try:
        report = run_privacy_experiment(
            samples,
            countermeasure,
            experiment_id=args.experiment_id,
            features=features,
            candidates=candidates,
            seed=int(args.seed),
        )
    except FeraError:
        raise
    except Exception as exc:  # sklearn/IO failures are not Fera protocol errors
        raise SystemExit(f"privacy experiment failed: {exc}") from exc

    if report["schema"] != PRIVACY_EXPERIMENT_SCHEMA:  # pragma: no cover - guard
        raise SystemExit("unexpected experiment schema")

    if args.output:
        write_json(args.output, report)
        print(f"experiment written to {args.output}")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _summarise(report)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FeraError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
