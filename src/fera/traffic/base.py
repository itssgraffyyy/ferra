"""Traffic generation framework.

Design goals:

* one small generator per traffic class (``icmp``, ``web``, ``email_like``,
  ``voip_like``, ``video_like``, ``messaging_like``, plus a ``control`` class
  that generates no application traffic at all),
* *plans* are pure data: building a plan never touches the network, so it can be
  unit tested and shown to the user before execution,
* execution is separate and injection friendly: external tools (``ping``,
  ``curl``, ``iperf3``) run through :class:`~fera.common.process.BaseRunner`,
  native flows (UDP/TCP patterns) use small, injectable senders,
* everything is deterministic given the experiment seed, so the same experiment
  produces the same traffic pattern.

Honest labelling: the analogue classes model the *shape* of an application
class (message sizes, intervals, burstiness).  They are never labelled as the
real application - see :class:`~fera.dataset.schema.TrafficClass`.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar, Protocol, runtime_checkable

from ..common.errors import ErrorCode, FeraError, ToolUnavailableError
from ..common.logging_utils import get_logger
from ..common.process import BaseRunner
from ..dataset.schema import TrafficClass

logger = get_logger(__name__)


class TrafficStatus(str, Enum):
    """Outcome of a traffic generation attempt."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    DRY_RUN = "DRY_RUN"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class TrafficContext:
    """Everything a generator needs to build a plan."""

    traffic_type: TrafficClass
    target: str
    ip_version: int
    duration_s: float
    seed: int
    source: str | None = None
    port: int | None = None
    command_prefix: tuple[str, ...] = ()
    platform: str = "linux"
    options: Mapping[str, Any] = field(default_factory=dict)
    notes: str = ""

    @property
    def target_is_ipv6(self) -> bool:
        return ":" in self.target

    def option(self, key: str, default: Any = None) -> Any:
        """Return a generator specific option with a default."""
        value = self.options.get(key, default)
        return default if value is None else value

    def require(self, key: str) -> Any:
        """Return a mandatory generator option."""
        if key not in self.options:
            raise FeraError(
                f"traffic option {key!r} is required for {self.traffic_type.value}",
                code=ErrorCode.CONFIG_VALIDATION_FAILED,
                details={"traffic_type": self.traffic_type.value, "missing_option": key},
            )
        return self.options[key]


@dataclass(frozen=True)
class CommandStep:
    """A plan step that executes an external tool."""

    command: tuple[str, ...]
    description: str = ""
    timeout_s: float = 120.0

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "command", "command": list(self.command), "description": self.description}


@dataclass(frozen=True)
class NativeStep:
    """A plan step executed in-process (deterministic UDP/TCP pattern)."""

    kind: str
    parameters: Mapping[str, Any]
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"kind": f"native:{self.kind}", "parameters": dict(self.parameters), "description": self.description}


PlanStep = CommandStep | NativeStep


@dataclass(frozen=True)
class TrafficPlan:
    """A deterministic description of the traffic to generate."""

    traffic_type: TrafficClass
    steps: tuple[PlanStep, ...]
    description: str = ""
    uses_server: bool = False
    server_hint: str | None = None
    expected_flow_count: int | None = None
    required_tools: tuple[str, ...] = ()

    @property
    def commands(self) -> tuple[tuple[str, ...], ...]:
        return tuple(step.command for step in self.steps if isinstance(step, CommandStep))

    def to_dict(self) -> dict[str, Any]:
        return {
            "traffic_type": self.traffic_type.value,
            "description": self.description,
            "steps": [step.to_dict() for step in self.steps],
            "uses_server": self.uses_server,
            "server_hint": self.server_hint,
            "expected_flow_count": self.expected_flow_count,
            "required_tools": list(self.required_tools),
        }


@dataclass(frozen=True)
class TrafficResult:
    """Outcome of executing a traffic plan."""

    traffic_type: TrafficClass
    status: TrafficStatus
    generated: bool
    bytes_sent: int = 0
    packets_sent: int = 0
    duration_s: float = 0.0
    tool: str | None = None
    error_code: ErrorCode | None = None
    message: str | None = None
    executed_commands: tuple[tuple[str, ...], ...] = ()
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "traffic_type": self.traffic_type.value,
            "status": self.status.value,
            "generated": self.generated,
            "bytes_sent": self.bytes_sent,
            "packets_sent": self.packets_sent,
            "duration_s": round(self.duration_s, 3),
            "tool": self.tool,
            "error_code": self.error_code.value if self.error_code else None,
            "message": self.message,
            "executed_commands": [list(command) for command in self.executed_commands],
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class NativeStats:
    """Accounting of a native (in-process) traffic pattern."""

    bytes_sent: int = 0
    packets_sent: int = 0
    duration_s: float = 0.0
    errors: tuple[str, ...] = ()

    def merge(self, other: NativeStats) -> NativeStats:
        return NativeStats(
            bytes_sent=self.bytes_sent + other.bytes_sent,
            packets_sent=self.packets_sent + other.packets_sent,
            duration_s=self.duration_s + other.duration_s,
            errors=(*self.errors, *other.errors),
        )


NativeExecutor = Callable[[Mapping[str, Any], TrafficContext], NativeStats]


@runtime_checkable
class TrafficGenerator(Protocol):
    """Interface implemented by every traffic generator."""

    traffic_type: ClassVar[TrafficClass]
    display_name: ClassVar[str]
    required_tools: ClassVar[tuple[str, ...]]
    label: ClassVar[str]

    def build_plan(self, context: TrafficContext) -> TrafficPlan:
        """Return a deterministic plan (must not touch the network)."""
        ...


def _default_native_executors() -> Mapping[str, NativeExecutor]:
    from .native import NATIVE_EXECUTORS

    return NATIVE_EXECUTORS


class BaseTrafficGenerator:
    """Shared behaviour: tool checking and plan execution."""

    traffic_type: ClassVar[TrafficClass]
    display_name: ClassVar[str] = "traffic"
    required_tools: ClassVar[tuple[str, ...]] = ()
    #: ``True`` when the pattern needs a responder running on the target side.
    needs_responder: ClassVar[bool] = False
    label: ClassVar[str] = "synthetic traffic"

    def build_plan(self, context: TrafficContext) -> TrafficPlan:  # pragma: no cover - interface
        raise NotImplementedError

    def missing_tools(self, runner: BaseRunner) -> tuple[str, ...]:
        """Return the required tools that are not available."""
        return tuple(tool for tool in self.required_tools if runner.which(tool) is None)

    def ensure_tools(self, runner: BaseRunner) -> None:
        """Raise :class:`ToolUnavailableError` when a required tool is missing."""
        missing = self.missing_tools(runner)
        if missing:
            raise ToolUnavailableError(
                f"{self.display_name} traffic needs tool(s) that are not installed: {', '.join(missing)}",
                hint=f"install {', '.join(missing)} on the traffic generating endpoint",
                details={"traffic_type": self.traffic_type.value, "missing_tools": list(missing)},
            )

    def generate(
        self,
        context: TrafficContext,
        runner: BaseRunner,
        *,
        dry_run: bool = False,
    ) -> TrafficResult:
        """Build and execute the plan for ``context``."""
        return execute_plan(self.build_plan(context), context, runner, dry_run=dry_run)


def ping_count(duration_s: float, interval_s: float, *, max_count: int = 10000) -> int:
    """Number of probes for a duration/interval pair (at least one)."""
    if interval_s <= 0:
        return 1
    return max(1, min(max_count, int(math.ceil(max(0.0, duration_s) / interval_s))))


def execute_plan(
    plan: TrafficPlan,
    context: TrafficContext,
    runner: BaseRunner,
    *,
    dry_run: bool = False,
    native_executors: Mapping[str, NativeExecutor] | None = None,
) -> TrafficResult:
    """Execute a plan, turning every failure into an explicit result.

    Exceptions are converted into a ``FAILED`` :class:`TrafficResult` (instead
    of propagating) so the experiment runner can always stop the capture and
    record why generation failed.  A failed traffic generation never yields a
    valid dataset sample.
    """
    executors = native_executors if native_executors is not None else _default_native_executors()
    started = time.monotonic()
    executed: list[tuple[str, ...]] = []
    stats = NativeStats()
    tool_used: str | None = None
    notes: list[str] = [context.notes] if context.notes else []
    if plan.uses_server and plan.server_hint:
        notes.append(plan.server_hint)

    for step in plan.steps:
        if isinstance(step, CommandStep):
            command = (*context.command_prefix, *step.command)
            if dry_run:
                executed.append(command)
                continue
            tool_used = step.command[0] if step.command else tool_used
            try:
                result = runner.run(list(command), timeout=step.timeout_s)
            except FeraError as exc:
                return TrafficResult(
                    traffic_type=plan.traffic_type,
                    status=TrafficStatus.FAILED,
                    generated=False,
                    error_code=exc.code,
                    message=f"{step.description or 'command'} failed: {exc.message}",
                    executed_commands=tuple(executed),
                    duration_s=time.monotonic() - started,
                    notes=tuple(notes),
                )
            executed.append(command)
            if not result.ok:
                detail = (result.stderr or result.stdout or "").strip()[-400:]
                return TrafficResult(
                    traffic_type=plan.traffic_type,
                    status=TrafficStatus.FAILED,
                    generated=False,
                    error_code=ErrorCode.TRAFFIC_GENERATION_FAILED,
                    message=f"{step.description or 'command'} exited with {result.returncode}: {detail}",
                    executed_commands=tuple(executed),
                    tool=tool_used,
                    duration_s=time.monotonic() - started,
                    notes=tuple(notes),
                )
            continue

        if dry_run:
            executed.append(("native", step.kind))
            continue
        executor = executors.get(step.kind)
        if executor is None:
            return TrafficResult(
                traffic_type=plan.traffic_type,
                status=TrafficStatus.FAILED,
                generated=False,
                error_code=ErrorCode.INTERNAL_ERROR,
                message=f"no native executor registered for step kind {step.kind!r}",
                executed_commands=tuple(executed),
                duration_s=time.monotonic() - started,
            )
        try:
            step_stats = executor(step.parameters, context)
        except FeraError as exc:
            return TrafficResult(
                traffic_type=plan.traffic_type,
                status=TrafficStatus.FAILED,
                generated=False,
                error_code=exc.code,
                message=f"{step.description or step.kind} failed: {exc.message}",
                executed_commands=tuple(executed),
                duration_s=time.monotonic() - started,
                notes=tuple(notes),
            )
        stats = stats.merge(step_stats)
        executed.append((step.kind,))
        if step_stats.errors:
            return TrafficResult(
                traffic_type=plan.traffic_type,
                status=TrafficStatus.FAILED,
                generated=False,
                error_code=ErrorCode.TRAFFIC_GENERATION_FAILED,
                bytes_sent=stats.bytes_sent,
                packets_sent=stats.packets_sent,
                message=f"{step.description or step.kind} reported errors: {'; '.join(step_stats.errors)}",
                executed_commands=tuple(executed),
                duration_s=time.monotonic() - started,
                notes=tuple(notes),
            )

    if dry_run:
        return TrafficResult(
            traffic_type=plan.traffic_type,
            status=TrafficStatus.DRY_RUN,
            generated=False,
            executed_commands=tuple(executed),
            duration_s=time.monotonic() - started,
            notes=tuple(notes),
        )
    return TrafficResult(
        traffic_type=plan.traffic_type,
        status=TrafficStatus.SUCCESS,
        generated=True,
        bytes_sent=stats.bytes_sent,
        packets_sent=stats.packets_sent,
        duration_s=time.monotonic() - started,
        tool=tool_used,
        executed_commands=tuple(executed),
        notes=tuple(notes),
    )


__all__ = [
    "BaseTrafficGenerator",
    "CommandStep",
    "NativeExecutor",
    "NativeStats",
    "NativeStep",
    "PlanStep",
    "TrafficContext",
    "TrafficGenerator",
    "TrafficPlan",
    "TrafficResult",
    "TrafficStatus",
    "execute_plan",
    "ping_count",
]


