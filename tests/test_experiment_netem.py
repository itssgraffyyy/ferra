"""Network-condition (netem) planning tests.

Two properties matter here and neither is "did tc succeed":

* the **planned command is correct**, because it is what a reviewer inspects
  before anyone touches a real host, and a wrong qdisc that silently does
  nothing would waste a full experiment matrix;
* **planning never claims an impairment was applied**, so a manifest cannot
  record loss and jitter that never happened.

Nothing here executes `tc`. On Windows every `executable_here()` is False, and
that is asserted rather than assumed.
"""

from __future__ import annotations

import sys

import pytest

from fera.common.errors import FeraError
from fera.experiment.netem import (
    CONDITION_NAMES,
    NETEM_SCHEMA,
    NetworkCondition,
    plan_condition,
    plan_matrix,
)


def test_unknown_condition_is_refused() -> None:
    with pytest.raises(FeraError):
        plan_condition("tornado")
    with pytest.raises(FeraError):
        NetworkCondition(name="tornado")


def test_baseline_produces_no_apply_command() -> None:
    """A 'no impairment' run must not replace a leftover qdisc."""
    condition = plan_condition("baseline", interface="veth-a")
    assert condition.apply_command() is None
    assert condition.is_baseline is True


def test_loss_condition_plans_the_expected_command() -> None:
    condition = plan_condition("loss", interface="veth-a")
    command = condition.apply_command()

    assert command == [
        "tc", "qdisc", "replace", "dev", "veth-a", "root", "netem", "loss", "1.0%",
    ]


def test_latency_condition_plans_delay() -> None:
    command = plan_condition("latency", interface="veth-a").apply_command()
    assert command is not None
    assert command[-2:] == ["delay", "50.0ms"]


def test_jitter_includes_the_delay_it_requires() -> None:
    """netem silently ignores jitter without a delay; carry one."""
    command = plan_condition("jitter", interface="veth-a").apply_command()
    assert command is not None
    assert "delay" in command
    assert "10.0ms" in command
    assert "distribution" in command


def test_jitter_without_delay_is_refused() -> None:
    condition = NetworkCondition(name="latency", jitter_ms=5.0, delay_ms=None)
    with pytest.raises(FeraError):
        condition.qdisc_arguments()


def test_cleanup_command_is_planned_and_idempotent_in_shape() -> None:
    condition = plan_condition("loss", interface="veth-a")
    assert condition.cleanup_command() == ["tc", "qdisc", "del", "dev", "veth-a", "root"]
    # Deleting a root qdisc that does not exist is harmless, which is what makes
    # cleanup safe to run unconditionally.
    assert condition.cleanup_command()[1] == "qdisc"


def test_planning_never_marks_a_condition_applied() -> None:
    for name in CONDITION_NAMES:
        condition = plan_condition(name, interface="veth-a")
        assert condition.applied is False
        assert condition.to_dict()["applied"] is False


def test_windows_host_cannot_execute_any_condition() -> None:
    conditions = [plan_condition(name, interface="veth-a") for name in CONDITION_NAMES]
    if sys.platform.startswith("linux"):  # pragma: no cover - platform dependent
        pytest.skip("this assertion describes the non-Linux case")
    assert all(item.executable_here() is False for item in conditions)


def test_condition_without_an_interface_is_not_executable() -> None:
    assert plan_condition("loss", interface="").executable_here() is False
    assert plan_condition("loss", interface="").apply_command() is None


def test_invalid_numeric_settings_are_refused() -> None:
    with pytest.raises(FeraError):
        NetworkCondition(name="loss", loss_percent=-1.0)
    with pytest.raises(FeraError):
        NetworkCondition(name="loss", loss_percent=150.0)
    with pytest.raises(FeraError):
        NetworkCondition(name="loss", delay_ms="fast")  # type: ignore[arg-type]


def test_matrix_plans_every_condition_with_both_commands() -> None:
    planned = plan_matrix(interface="veth-a")

    assert [item["name"] for item in planned] == list(CONDITION_NAMES)
    for item in planned:
        assert item["schema"] == NETEM_SCHEMA
        assert item["cleanup_command"] is not None
        assert item["applied"] is False
    impaired = [item for item in planned if item["apply_command"]]
    assert impaired, "at least the impaired conditions should plan a command"


def test_condition_round_trips_through_a_document() -> None:
    condition = plan_condition("jitter", interface="veth-a")
    restored = NetworkCondition.from_dict(condition.to_dict())

    assert restored.name == "jitter"
    assert restored.interface == "veth-a"
    assert restored.qdisc_arguments() == condition.qdisc_arguments()
    assert restored.applied is False
