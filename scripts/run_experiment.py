#!/usr/bin/env python3
"""Run one experiment (or a whole directory of experiments) end to end.

    python scripts/run_experiment.py --config configs/experiments/exp_000_....yaml
    python scripts/run_experiment.py --experiment-id exp_000_...
    python scripts/run_experiment.py --config configs/experiments --limit 3 --continue-on-error
    python scripts/run_experiment.py --config configs/experiments/exp_000_....yaml --dry-run

Exit codes: ``0`` success, ``1`` failure, ``3`` environment blocker.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import _bootstrap  # noqa: E402
from fera.common.errors import ErrorCode, FeraError  # noqa: E402
from fera.common.paths import default_paths  # noqa: E402
from fera.dataset.runner import ExperimentRunner, RunnerSettings, RunStatus  # noqa: E402
from fera.dataset.schema import find_experiment_configs, load_experiment  # noqa: E402
from fera.experiment.netem import CONDITION_NAMES  # noqa: E402
from fera.testbed.topology import load_topology  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run FERA IPsec experiments and build dataset samples.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--config", help="experiment YAML file, or a directory of them")
    source.add_argument("--experiment-id", help="experiment id inside configs/experiments")
    parser.add_argument("--topology", default=None, help="testbed topology YAML")
    parser.add_argument("--raw-dir", default=None, help="override the output directory (default: data/raw)")
    parser.add_argument("--dry-run", action="store_true",
                        help="generate everything and write the plan, but execute nothing")
    parser.add_argument("--overwrite", action="store_true", help="replace an existing experiment directory")
    parser.add_argument("--keep-sa", action="store_true", help="do not terminate the SA at the end")
    parser.add_argument("--update-manifest", action="store_true", help="refresh data/manifests/dataset.json")
    parser.add_argument("--no-responder", action="store_true",
                        help="do not start the FERA responder on endpoint B")
    parser.add_argument("--capture-interface", default=None)
    parser.add_argument("--capture-filter", default=None)
    parser.add_argument("--capture-tool", default=None, choices=(None, "tcpdump", "dumpcap"))
    parser.add_argument("--capture-snaplen", type=int, default=0)
    parser.add_argument("--sa-wait-timeout", type=float, default=30.0)
    parser.add_argument("--network-condition", default="baseline", choices=CONDITION_NAMES,
                        help="netem condition applied to the capture interface during the run")
    parser.add_argument("--network-interface", default=None,
                        help="interface for the netem qdisc (default: the capture interface)")
    parser.add_argument("--limit", type=int, default=None, help="run at most N experiments of a directory")
    parser.add_argument("--continue-on-error", action="store_true",
                        help="keep going when one experiment fails (batch mode)")
    parser.add_argument("--json", nargs="?", const="", default=None, help="write the outcome(s) as JSON")
    parser.add_argument("--log-level", default="INFO")
    return parser


def _collect_configs(args: argparse.Namespace, paths) -> list[Path]:
    if args.experiment_id:
        candidate = paths.experiment_config_path(args.experiment_id)
        if not candidate.is_file():
            raise FeraError(
                f"experiment file not found: {candidate}",
                code=ErrorCode.IO_ERROR,
                hint="run python scripts/generate_experiment_matrix.py first",
            )
        return [candidate]
    target = Path(args.config)
    if target.is_dir():
        files = find_experiment_configs(target)
        if not files:
            raise FeraError(
                f"no experiment files in {target}",
                code=ErrorCode.IO_ERROR,
                hint="run python scripts/generate_experiment_matrix.py",
            )
        return files[: args.limit] if args.limit else files
    return [target]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging(args.log_level)
    paths = default_paths()

    files = _collect_configs(args, paths)
    topology = load_topology(args.topology)
    settings = RunnerSettings(
        dry_run=args.dry_run,
        overwrite=args.overwrite,
        keep_sa=args.keep_sa,
        update_manifest=args.update_manifest,
        responder=not args.no_responder,
        capture_interface=args.capture_interface,
        capture_filter=args.capture_filter,
        capture_tool=args.capture_tool,
        capture_snaplen=args.capture_snaplen,
        sa_wait_timeout_s=args.sa_wait_timeout,
        network_condition=args.network_condition,
        network_interface=args.network_interface,
        topology_path=args.topology,
        raw_dir=Path(args.raw_dir) if args.raw_dir else None,
        log_level=args.log_level,
    )

    outcomes: list[dict] = []
    worst_status = 0
    for index, config_file in enumerate(files, start=1):
        print()
        print(f"[{index}/{len(files)}] {config_file}")
        try:
            config = load_experiment(config_file)
        except FeraError as error:
            print(f"  FAILED to load configuration: {error}", file=sys.stderr)
            worst_status = max(worst_status, 1)
            if not args.continue_on_error:
                return worst_status
            continue
        outcome = ExperimentRunner(config, paths=paths, settings=settings, topology=topology).run()
        outcomes.append(outcome.to_dict())
        print(f"  status : {outcome.status.value}")
        if outcome.error_code:
            print(f"  error  : {outcome.error_code.value} - {outcome.message}")
        if outcome.pcap_path:
            print(f"  pcap   : {paths.relative(outcome.pcap_path)}")
        if outcome.ground_truth_path:
            print(f"  truth  : {paths.relative(outcome.ground_truth_path)}")
        if outcome.status is RunStatus.SUCCESS:
            print("  result : VALID dataset sample")
        elif outcome.status is RunStatus.DRY_RUN:
            print("  result : dry run (nothing executed, not a dataset sample)")
        elif outcome.status is RunStatus.UNSUPPORTED_ENVIRONMENT:
            worst_status = max(worst_status, 3)
        else:
            worst_status = max(worst_status, 1)
        if outcome.status in {RunStatus.FAILED, RunStatus.UNSUPPORTED_ENVIRONMENT} and not args.continue_on_error:
            break

    if args.json is not None:
        target = Path(args.json) if args.json else paths.manifests / "last_run.json"
        _bootstrap.write_json_output(target, {"runs": outcomes})
        print(f"\noutcomes written to {target}")

    print()
    print(f"summary: {len(outcomes)} run(s), worst exit status {worst_status}")
    return worst_status


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FeraError as error:  # pragma: no cover - CLI error path
        print(f"ERROR [{error.code.value}]: {error.message}", file=sys.stderr)
        if error.hint:
            print(f"hint: {error.hint}", file=sys.stderr)
        sys.exit(1)

