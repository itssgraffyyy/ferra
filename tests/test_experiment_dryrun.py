"""Dry-run planning tests.

The single most important assertion here is negative: **a dry run must never
mark an evidence gate**.  A dry run produces no IKE_SA, no XFRM state, no
capture and no ESP.  A plan that marked a gate would be the exact mechanism by
which fabricated evidence entered the pipeline, so the plan carries a
``marked_verified`` list and it must always be empty.

The rest covers what makes a dry run useful from a non-Linux host: it describes
the workflow, labels which stages need Linux/root, and still refuses to claim
the host could execute anything.
"""

from __future__ import annotations

import pytest

from fera.common.errors import FeraError
from fera.experiment.dryrun import (
    DRY_RUN_BANNER,
    LINUX_ONLY_STAGES,
    PLANNED_STAGES,
    plan_experiments,
    render_text,
)
from fera.experiment.gates import EVIDENCE_GATES, ExperimentState, Stage
from fera.experiment.preflight import REQUIRED_CAPABILITIES, run_preflight
from fera.testbed.environment import CheckResult, CheckStatus, EnvironmentReport


def _blocked_preflight():
    statuses = dict.fromkeys(REQUIRED_CAPABILITIES, "AVAILABLE")
    statuses["xfrm"] = "UNSUPPORTED"
    return run_preflight(
        require_real_experiments=True,
        environment=EnvironmentReport(
            checks=tuple(
                CheckResult(key=k, label=k, status=CheckStatus(v), detail="test")
                for k, v in statuses.items()
            ),
            host={},
            tool_versions={},
            generated_at="2026-01-01T00:00:00Z",
        ),
    )


def test_dry_run_never_marks_an_evidence_gate() -> None:
    plan = plan_experiments(repeats=1, preflight=_blocked_preflight())

    assert plan["executed"] is False
    assert plan["evidence_gates"]["marked_verified"] == []
    for gate in EVIDENCE_GATES:
        assert gate not in plan["evidence_gates"]["marked_verified"]


def test_dry_run_reports_no_experiment_executed() -> None:
    plan = plan_experiments(repeats=1)
    assert plan["banner"] == DRY_RUN_BANNER
    assert plan["executed"] is False
    assert DRY_RUN_BANNER in render_text(plan)


def test_dry_run_cannot_make_a_blocked_host_executable() -> None:
    plan = plan_experiments(repeats=1, preflight=_blocked_preflight())
    assert plan["experiments"], "the plan must still describe the work"
    assert all(item["executable_here"] is False for item in plan["experiments"])
    assert all(item["blocked_reason"] for item in plan["experiments"])


def test_dry_run_labels_linux_only_stages() -> None:
    plan = plan_experiments(repeats=1)
    stages = {item["stage"]: item for item in plan["stages"]}

    assert set(stages) == set(PLANNED_STAGES)
    for name in LINUX_ONLY_STAGES:
        assert stages[name]["requires_linux"] is True
        assert stages[name]["executable_here"] is False
    assert "dataset_eligibility" in stages
    assert stages["dataset_eligibility"]["requires_linux"] is False


def test_repeats_produce_distinct_session_ids() -> None:
    single = plan_experiments(repeats=1)
    triple = plan_experiments(repeats=3)

    assert triple["counts"]["planned_sessions"] == single["counts"]["planned_sessions"] * 3
    assert triple["counts"]["distinct_session_ids"] == triple["counts"]["planned_sessions"]
    ids = [item["session_id"] for item in triple["experiments"]]
    assert len(set(ids)) == len(ids)


def test_configuration_id_is_independent_of_traffic_class() -> None:
    """The grouping key must not change when the traffic class does.

    The id is built from the IPsec parameters only.  Whether two *entries* ever
    share one is a property of the curated matrix, not of this function - see
    test_the_curated_matrix_confounds_configuration_with_traffic_class.
    """
    plan = plan_experiments(repeats=1)
    for item in plan["experiments"]:
        assert item["traffic_class"] not in item["configuration_id"]
        assert item["session_id"].endswith(f"--r{item['repeat_id']:02d}")


def test_the_curated_matrix_confounds_configuration_with_traffic_class() -> None:
    """A known limitation of the shipped matrix, pinned so it cannot drift.

    Every one of the matrix's 15 configurations carries exactly one traffic
    class.  Configuration and class are therefore *perfectly confounded*: a
    classifier could score well by recognising the configuration rather than
    the traffic, and no held-out-configuration evaluation on this matrix could
    separate the two.

    This is a property of the existing curated matrix, not of the planner.  It
    is pinned here rather than silently assumed away because the problem
    statement explicitly warns against exactly this design ("all web = GCM, all
    video = CBC" style confounding).  Fixing it means changing the matrix, which
    is a separate decision.
    """
    plan = plan_experiments(repeats=1)
    by_config: dict[str, set[str]] = {}
    for item in plan["experiments"]:
        by_config.setdefault(item["configuration_id"], set()).add(item["traffic_class"])
    counts = sorted(len(classes) for classes in by_config.values())

    # Assert the truth of today so a future matrix change is visible here.
    assert counts, "the matrix produced no configurations"
    assert max(counts) == 1, (
        f"the matrix now has a configuration with several classes {counts}; "
        "update this test and the known-limitation note together"
    )


def test_plan_reports_distinct_configuration_count() -> None:
    plan = plan_experiments(repeats=2)
    counts = plan["counts"]
    assert counts["distinct_configurations"] == len(plan["configurations"])
    assert counts["planned_sessions"] == counts["distinct_configurations"] * 2


def test_plan_includes_coverage_of_the_matrix() -> None:
    plan = plan_experiments(repeats=1)
    assert plan["coverage"]
    # The plan reuses the curated matrix, so its coverage must be computed,
    # not asserted.
    assert any(key in plan["coverage"] for key in ("checks", "summary"))


def test_plan_is_deterministic() -> None:
    first = plan_experiments(repeats=2)
    second = plan_experiments(repeats=2)
    assert [item["session_id"] for item in first["experiments"]] == [
        item["session_id"] for item in second["experiments"]
    ]
    assert first["configurations"] == second["configurations"]


def test_invalid_plan_arguments_are_refused() -> None:
    with pytest.raises(FeraError):
        plan_experiments(repeats=0)
    with pytest.raises(FeraError):
        plan_experiments(entries=())


def test_planning_never_advances_the_experiment_state_machine() -> None:
    """A plan and an ExperimentState are separate objects on purpose."""
    state = ExperimentState(experiment_id="exp-000")
    plan = plan_experiments(repeats=1)

    assert plan["executed"] is False
    assert state.stage is Stage.PLANNED
    assert state.missing_gates == list(EVIDENCE_GATES)
    assert "experiment_state" not in plan


def test_render_text_states_no_execution_and_names_blocking() -> None:
    text = render_text(plan_experiments(repeats=1, preflight=_blocked_preflight()))
    assert DRY_RUN_BANNER in text
    assert "executed           : False" in text
    assert "BLOCKED" in text
    assert "verified by this plan : 0" in text
