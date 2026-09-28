"""Traffic generator tests (plans, execution, determinism, honest labels)."""

from __future__ import annotations

from pathlib import Path

import pytest

from fera.common.errors import ErrorCode, FeraError
from fera.common.process import CommandResult, RecordingRunner
from fera.dataset.schema import TrafficClass
from fera.traffic.base import CommandStep, NativeStats, NativeStep, TrafficContext, execute_plan
from fera.traffic.icmp import ping_command
from fera.traffic.native import deterministic_payload
from fera.traffic.profiles import TRAFFIC_PROFILE_DOCUMENT, default_profiles, load_profiles, profile_for
from fera.traffic.registry import (
    describe_traffic_types,
    generate_traffic,
    get_generator,
    resolve_traffic_type,
)
from fera.traffic.web import WebTrafficGenerator


def context(traffic_type: TrafficClass, *, target: str = "10.30.0.1", **kwargs) -> TrafficContext:
    return TrafficContext(
        traffic_type=traffic_type,
        target=target,
        ip_version=6 if ":" in target else 4,
        duration_s=kwargs.pop("duration_s", 5.0),
        seed=kwargs.pop("seed", 1234),
        **kwargs,
    )


# --- ICMP -------------------------------------------------------------------
def test_icmp_plan_uses_ping_with_bounded_probe_count() -> None:
    plan = get_generator(TrafficClass.ICMP).build_plan(context(TrafficClass.ICMP, duration_s=5.0))
    assert len(plan.steps) == 1
    step = plan.steps[0]
    assert isinstance(step, CommandStep)
    assert step.command[0] == "ping"
    assert int(step.command[step.command.index("-c") + 1]) == 10  # 5 s / 500 ms default


def test_icmp_plan_marks_ipv6_and_source_address() -> None:
    v6 = context(TrafficClass.ICMP, target="fd00:30::1", source="fd00:20::1", options={"interval_ms": 1000})
    command = ping_command(v6, count=3, interval_s=1.0, payload_bytes=64)
    assert "-6" in command
    assert command[command.index("-I") + 1] == "fd00:20::1"
    assert command[-1] == "fd00:30::1"


def test_icmp_plan_is_deterministic() -> None:
    generator = get_generator(TrafficClass.ICMP)
    assert generator.build_plan(context(TrafficClass.ICMP)).to_dict() == generator.build_plan(
        context(TrafficClass.ICMP)
    ).to_dict()


# --- web --------------------------------------------------------------------
def test_web_plan_targets_the_controlled_endpoint() -> None:
    plan = WebTrafficGenerator().build_plan(
        context(TrafficClass.WEB, options={"request_count": 3, "port": 8080, "payload_bytes": 1024})
    )
    urls = [step.command[-1] for step in plan.steps if isinstance(step, CommandStep)]
    assert all(url.startswith("http://10.30.0.1:8080") for url in urls)
    assert any("/payload?bytes=1024" in url for url in urls)
    assert plan.uses_server is True and plan.server_hint


def test_web_plan_uses_brackets_for_ipv6_targets() -> None:
    plan = WebTrafficGenerator().build_plan(context(TrafficClass.WEB, target="fd00:30::1"))
    first = next(step for step in plan.steps if isinstance(step, CommandStep))
    assert "http://[fd00:30::1]:8080" in first.command[-1]


# --- native classes ---------------------------------------------------------
@pytest.mark.parametrize(
    ("traffic_type", "expected_kind"),
    [
        (TrafficClass.VOIP_LIKE, "udp_pattern"),
        (TrafficClass.MESSAGING_LIKE, "udp_bursts"),
        (TrafficClass.EMAIL_LIKE, "tcp_request_response"),
        (TrafficClass.VIDEO_LIKE, "tcp_stream"),
    ],
)
def test_analogue_classes_use_native_patterns(traffic_type: TrafficClass, expected_kind: str) -> None:
    plan = get_generator(traffic_type).build_plan(context(traffic_type))
    assert [step.kind for step in plan.steps if isinstance(step, NativeStep)] == [expected_kind]
    # one-way VoIP-like traffic needs no responder, the request/response
    # classes do - the plan states that explicitly instead of hiding it
    expects_server = traffic_type is not TrafficClass.VOIP_LIKE
    assert plan.uses_server is expects_server
    if expects_server:
        assert plan.server_hint is not None


def test_voip_like_bidirectional_requires_a_responder() -> None:
    plan = get_generator(TrafficClass.VOIP_LIKE).build_plan(
        context(TrafficClass.VOIP_LIKE, options={"bidirectional": True})
    )
    assert plan.uses_server is True
    assert "udp" in (plan.server_hint or "")


def test_voip_default_profile_is_g711_shaped() -> None:
    plan = get_generator(TrafficClass.VOIP_LIKE).build_plan(context(TrafficClass.VOIP_LIKE))
    step = plan.steps[0]
    assert isinstance(step, NativeStep)
    assert step.parameters["packet_size"] == 160
    assert step.parameters["interval_ms"] == 20


def test_video_plan_can_switch_to_iperf3() -> None:
    plan = get_generator(TrafficClass.VIDEO_LIKE).build_plan(
        context(TrafficClass.VIDEO_LIKE, options={"use_iperf3": True})
    )
    step = plan.steps[0]
    assert isinstance(step, CommandStep)
    assert step.command[0] == "iperf3"
    assert "--bitrate" in step.command


# --- control ----------------------------------------------------------------
def test_control_class_generates_no_traffic() -> None:
    result = generate_traffic(
        TrafficClass.CONTROL, target="10.30.0.1", duration_s=1.0, ip_version=4, runner=RecordingRunner()
    )
    assert result.generated is True
    assert result.packets_sent == 0
    assert result.executed_commands == ()


# --- execution --------------------------------------------------------------
def test_execute_plan_reports_command_failure() -> None:
    def factory(command: tuple[str, ...]) -> CommandResult:
        return CommandResult(command, 1, "", "ping: unknown host", 0.01)

    runner = RecordingRunner(result_factory=factory)
    plan = get_generator(TrafficClass.ICMP).build_plan(context(TrafficClass.ICMP))
    result = execute_plan(plan, context(TrafficClass.ICMP), runner)
    assert result.generated is False
    assert result.error_code is ErrorCode.TRAFFIC_GENERATION_FAILED
    assert "unknown host" in (result.message or "")


def test_execute_plan_runs_native_steps_with_injected_executor() -> None:
    calls: list[int] = []

    def fake_executor(parameters, ctx) -> NativeStats:  # noqa: ARG001
        calls.append(parameters["port"])
        return NativeStats(bytes_sent=100, packets_sent=2)

    plan = get_generator(TrafficClass.MESSAGING_LIKE).build_plan(context(TrafficClass.MESSAGING_LIKE))
    result = execute_plan(
        plan,
        context(TrafficClass.MESSAGING_LIKE),
        RecordingRunner(),
        native_executors={"udp_bursts": fake_executor},
    )
    assert result.generated is True
    assert result.bytes_sent == 100
    assert calls == [plan.steps[0].parameters["port"]]


def test_execute_plan_reports_native_errors() -> None:
    def failing_executor(parameters, ctx) -> NativeStats:  # noqa: ARG001
        return NativeStats(errors=("no responder answered",))

    plan = get_generator(TrafficClass.EMAIL_LIKE).build_plan(context(TrafficClass.EMAIL_LIKE))
    result = execute_plan(
        plan,
        context(TrafficClass.EMAIL_LIKE),
        RecordingRunner(),
        native_executors={"tcp_request_response": failing_executor},
    )
    assert result.generated is False
    assert "no responder answered" in (result.message or "")


def test_missing_tool_produces_explicit_error() -> None:
    runner = RecordingRunner(available_tools=("curl",))
    result = generate_traffic(
        TrafficClass.ICMP, target="10.30.0.1", duration_s=1.0, ip_version=4, runner=runner
    )
    assert result.generated is False
    assert result.error_code is ErrorCode.TOOL_NOT_AVAILABLE
    assert "ping" in (result.message or "")


def test_unknown_native_step_kind_is_an_internal_error() -> None:
    from fera.traffic.base import TrafficPlan

    plan = TrafficPlan(traffic_type=TrafficClass.VOIP_LIKE, steps=(NativeStep(kind="bogus", parameters={}),))
    result = execute_plan(plan, context(TrafficClass.VOIP_LIKE), RecordingRunner())
    assert result.error_code is ErrorCode.INTERNAL_ERROR


# --- registry / profiles ----------------------------------------------------
def test_traffic_aliases_resolve_and_brand_names_do_not() -> None:
    assert resolve_traffic_type("ping") is TrafficClass.ICMP
    assert resolve_traffic_type("voice_like") is TrafficClass.VOIP_LIKE
    with pytest.raises(FeraError):
        resolve_traffic_type("whatsapp")


def test_every_traffic_class_has_a_generator() -> None:
    described = describe_traffic_types()
    assert {entry["traffic_type"] for entry in described} == {item.value for item in TrafficClass}
    assert all(entry["label"] for entry in described)


def test_shipped_profile_template_matches_builtin_document(repo_paths) -> None:
    assert load_profiles(repo_paths.traffic_profiles_file) == default_profiles()
    assert TRAFFIC_PROFILE_DOCUMENT["responder"]["echo_port"] == 9099


def test_profile_defaults_are_merged_into_plan() -> None:
    assert profile_for("voip_like", default_profiles())["packet_size"] == 160
    plan = get_generator(TrafficClass.VOIP_LIKE).build_plan(
        context(TrafficClass.VOIP_LIKE, options={"packet_size": 96, "interval_ms": 30})
    )
    step = plan.steps[0]
    assert isinstance(step, NativeStep)
    assert step.parameters["packet_size"] == 96
    assert step.parameters["interval_ms"] == 30


def test_deterministic_payload_is_reproducible() -> None:
    assert deterministic_payload(42, 32) == deterministic_payload(42, 32)
    assert deterministic_payload(42, 32) != deterministic_payload(43, 32)
    assert deterministic_payload(1, 0) == b""


def test_generate_traffic_dry_run_executes_nothing() -> None:
    result = generate_traffic(
        TrafficClass.ICMP,
        target="10.30.0.1",
        duration_s=2.0,
        ip_version=4,
        runner=RecordingRunner(),
        dry_run=True,
    )
    assert result.status.value == "DRY_RUN"
    assert result.generated is False


def test_responder_command_uses_env_for_pythonpath(tmp_path: Path) -> None:
    from fera.traffic.servers import responder_command

    command = responder_command("udp", host="10.30.0.1", pythonpath=tmp_path / "src")
    assert command[0] == "env"
    assert command[1].startswith("PYTHONPATH=")
    assert "fera.traffic.servers" in command
    assert "udp" in command

