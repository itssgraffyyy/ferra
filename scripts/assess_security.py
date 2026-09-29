#!/usr/bin/env python3
"""Assess one capture and publish the security report.

    python scripts/assess_security.py --pcap data/raw/exp_004/capture.pcap
    python scripts/assess_security.py --analysis data/processed/analysis/exp_004.json \\
        --config configs/experiments/exp_004.yaml --ml-prediction ml/prediction.json
    python scripts/assess_security.py --pcap capture.pcap --json --fail-under 85

The report is written as JSON beside the other processed artefacts
(``data/processed/security/<analysis id>.json``) and printed as text.

Ground truth is never an input.  ``--config`` is the testbed's own configuration
(graded ``CONFIGURED``) and ``--ml-prediction`` a classifier result (graded
``INFERRED``); a labelled sample handed to either one is refused outright, so a
score can never be steered by the answer key.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import _bootstrap  # noqa: E402
from fera.analysis import ProtocolAnalysis, analyze_pcap  # noqa: E402
from fera.common.errors import ConfigValidationError, FeraError  # noqa: E402
from fera.common.paths import default_paths  # noqa: E402
from fera.common.serialization import load_document, load_json, write_json  # noqa: E402
from fera.security import assess_security, load_prediction  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Assess an IKE/IPsec capture and publish a security report.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", help="capture to analyse first (Prompt 2 runs inside this script)")
    source.add_argument("--analysis", help="existing analysis JSON document to assess")
    parser.add_argument("--config", default=None, help="testbed experiment configuration (YAML or JSON)")
    parser.add_argument("--ml-prediction", default=None, help="classifier prediction JSON document")
    parser.add_argument("--out", default=None, help="report path (default: data/processed/security/<id>.json)")
    parser.add_argument("--json", action="store_true", help="print the report document instead of the text report")
    parser.add_argument("--fail-under", type=float, default=None, help="exit 1 when the score is below this")
    parser.add_argument("--no-tshark", action="store_true", help="use only FERA's built-in scanner")
    parser.add_argument("--log-level", default="WARNING")
    return parser


def load_analysis_document(path: Path) -> dict:
    """Read an analysis document, refusing anything that is not a JSON object."""
    document = load_json(path)
    if not isinstance(document, dict):
        raise ConfigValidationError(
            f"{path} does not contain a JSON object", details={"path": str(path)}
        )
    return document


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging(args.log_level)
    paths = default_paths()

    if args.analysis:
        analysis: ProtocolAnalysis | dict = load_analysis_document(paths.resolve(args.analysis))
        source = paths.relative(paths.resolve(args.analysis))
    else:
        analysis = analyze_pcap(paths.resolve(args.pcap), use_tshark=not args.no_tshark).analysis
        source = f"analyze_pcap({paths.relative(paths.resolve(args.pcap))})"

    configured = paths.resolve(args.config) if args.config else None
    configured_document = load_document(configured) if configured else None
    prediction_document = load_prediction(args.ml_prediction) if args.ml_prediction else None
    assessment = assess_security(
        analysis,
        configured=configured_document if configured_document else None,
        traffic=prediction_document,
        inputs={
            "analysis_source": source,
            "configuration": paths.relative(configured) if configured else "",
            "ml_prediction": paths.relative(paths.resolve(args.ml_prediction)) if args.ml_prediction else "",
            "report_generator": "scripts/assess_security.py",
        },
    )

    target = Path(args.out) if args.out else paths.processed / "security" / f"{assessment.analysis_id}.json"
    write_json(target, assessment.to_dict())

    if args.json:
        _bootstrap.print_json(assessment.to_dict())
    else:
        print(assessment.render_text())
        _bootstrap.print_section("artefacts")
        print(f"report          : {paths.relative(target)}")
        print(f"policy          : {assessment.policy['policy_id']} {assessment.policy['policy_version']}")

    if args.fail_under is not None and assessment.security_score < args.fail_under:
        print(
            f"FAIL: security score {assessment.security_score} is below --fail-under {args.fail_under}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FeraError as error:  # pragma: no cover - CLI error path
        print(f"ERROR [{error.code.value}]: {error.message}", file=sys.stderr)
        sys.exit(1)
