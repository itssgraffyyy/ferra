"""Traffic generator registry and the ``generate_traffic()`` facade.

This is the single entry point the experiment runner uses::

    result = generate_traffic(
        "icmp",
        target="10.30.0.1",
        duration_s=20,
        ip_version=4,
        runner=runner,
        seed=experiment.effective_seed,
    )

The registry owns one generator instance per traffic class, merges the traffic
profile defaults with experiment specific options, and checks tool availability
*before* generating, so a missing ``curl`` produces an explicit
``TOOL_NOT_AVAILABLE`` result instead of a half-executed plan.
"""

from __future__ import annotations

import platform as platform_module
from collections.abc import Mapping, Sequence
from typing import Any

from ..common.errors import ErrorCode, FeraError
from ..common.logging_utils import get_logger
from ..common.process import BaseRunner, SubprocessRunner
from ..dataset.schema import TrafficClass
from .base import BaseTrafficGenerator, TrafficContext, TrafficResult, TrafficStatus
from .control import ControlTrafficGenerator
from .email_like import EmailLikeTrafficGenerator
from .icmp import IcmpTrafficGenerator
from .messaging_like import MessagingLikeTrafficGenerator
from .profiles import profile_for
from .video_like import VideoLikeTrafficGenerator
from .voip_like import VoipLikeTrafficGenerator
from .web import WebTrafficGenerator

logger = get_logger(__name__)

#: One generator per traffic class.
GENERATORS: Mapping[TrafficClass, BaseTrafficGenerator] = {
    TrafficClass.ICMP: IcmpTrafficGenerator(),
    TrafficClass.WEB: WebTrafficGenerator(),
    TrafficClass.EMAIL_LIKE: EmailLikeTrafficGenerator(),
    TrafficClass.VOIP_LIKE: VoipLikeTrafficGenerator(),
    TrafficClass.VIDEO_LIKE: VideoLikeTrafficGenerator(),
    TrafficClass.MESSAGING_LIKE: MessagingLikeTrafficGenerator(),
    TrafficClass.CONTROL: ControlTrafficGenerator(),
}

#: Convenience aliases.  Note that no *application brand* is ever mapped here:
#: mapping "whatsapp" to a synthetic generator would be a false label.
TRAFFIC_ALIASES: Mapping[str, TrafficClass] = {
    "none": TrafficClass.CONTROL,
    "no_traffic": TrafficClass.CONTROL,
    "ping": TrafficClass.ICMP,
    "icmp_echo": TrafficClass.ICMP,
    "http": TrafficClass.WEB,
    "https": TrafficClass.WEB,
    "web_browsing": TrafficClass.WEB,
    "email": TrafficClass.EMAIL_LIKE,
    "mail_like": TrafficClass.EMAIL_LIKE,
    "voip": TrafficClass.VOIP_LIKE,
    "voice_like": TrafficClass.VOIP_LIKE,
    "video": TrafficClass.VIDEO_LIKE,
    "streaming_like": TrafficClass.VIDEO_LIKE,
    "messaging": TrafficClass.MESSAGING_LIKE,
    "chat_like": TrafficClass.MESSAGING_LIKE,
}


def resolve_traffic_type(value: TrafficClass | str) -> TrafficClass:
    """Resolve a traffic class name (including aliases) to :class:`TrafficClass`."""
    if isinstance(value, TrafficClass):
        return value
    text = str(value).strip().lower()
    if text in TRAFFIC_ALIASES:
        return TRAFFIC_ALIASES[text]
    for traffic_type in TrafficClass:
        if text == traffic_type.value:
            return traffic_type
    raise FeraError(
        f"unknown traffic type: {value!r}",
        code=ErrorCode.CONFIG_VALIDATION_FAILED,
        hint=f"supported traffic types: {', '.join(available_traffic_types())}",
        details={"requested": str(value), "supported": list(available_traffic_types())},
    )


def get_generator(traffic_type: TrafficClass | str) -> BaseTrafficGenerator:
    """Return the generator instance for a traffic class."""
    return GENERATORS[resolve_traffic_type(traffic_type)]


def available_traffic_types() -> tuple[str, ...]:
    """All traffic classes with a registered generator."""
    return tuple(traffic.value for traffic in GENERATORS)


def describe_traffic_types(runner: BaseRunner | None = None) -> list[dict[str, Any]]:
    """Describe every traffic class, including tool availability when a runner is given."""
    descriptions: list[dict[str, Any]] = []
    for traffic_type, generator in GENERATORS.items():
        entry: dict[str, Any] = {
            "traffic_type": traffic_type.value,
            "display_name": generator.display_name,
            "label": generator.label,
            "required_tools": list(generator.required_tools),
            "needs_responder": generator.needs_responder,
        }
        if runner is not None:
            missing = generator.missing_tools(runner)
            entry["missing_tools"] = list(missing)
            entry["usable"] = not missing
        descriptions.append(entry)
    return descriptions


# ---8<--- APPEND MARKER ---8<---

def build_context(
    traffic_type: TrafficClass | str,
    *,
    target: str,
    duration_s: float,
    ip_version: int,
    source: str | None = None,
    port: int | None = None,
    seed: int = 0,
    options: Mapping[str, Any] | None = None,
    command_prefix: Sequence[str] = (),
    platform: str | None = None,
    profiles: Mapping[str, Mapping[str, Any]] | None = None,
    runner: BaseRunner | None = None,
) -> TrafficContext:
    """Merge profile defaults with explicit options into a :class:`TrafficContext`."""
    resolved = resolve_traffic_type(traffic_type)
    profile_values = profile_for(resolved, profiles)
    merged: dict[str, Any] = dict(profile_values)
    explicit = dict(options or {})
    merged.update(explicit)
    if runner is not None and resolved is TrafficClass.VIDEO_LIKE and "use_iperf3" not in explicit:
        merged["use_iperf3"] = runner.which("iperf3") is not None
    return TrafficContext(
        traffic_type=resolved,
        target=target,
        ip_version=ip_version,
        duration_s=float(duration_s),
        seed=int(seed),
        source=source,
        port=port,
        command_prefix=tuple(str(part) for part in command_prefix),
        platform=platform or platform_module.system().lower(),
        options=merged,
    )


def generate_traffic(
    traffic_type: TrafficClass | str,
    *,
    target: str,
    duration_s: float,
    ip_version: int,
    source: str | None = None,
    port: int | None = None,
    seed: int = 0,
    options: Mapping[str, Any] | None = None,
    runner: BaseRunner | None = None,
    command_prefix: Sequence[str] = (),
    profiles: Mapping[str, Mapping[str, Any]] | None = None,
    dry_run: bool = False,
) -> TrafficResult:
    """Generate traffic of ``traffic_type`` and return an explicit result.

    Tool availability is checked first, so a missing ``curl``/``ping`` yields a
    ``TOOL_NOT_AVAILABLE`` result instead of a partially executed plan.  The
    function never raises for expected failures - the runner decides what to do
    with the result.
    """
    active_runner = runner if runner is not None else SubprocessRunner()
    generator = get_generator(traffic_type)
    context = build_context(
        traffic_type,
        target=target,
        duration_s=duration_s,
        ip_version=ip_version,
        source=source,
        port=port,
        seed=seed,
        options=options,
        command_prefix=command_prefix,
        profiles=profiles,
        runner=active_runner,
    )
    missing = generator.missing_tools(active_runner)
    if missing:
        message = (
            f"{generator.display_name} traffic requires tool(s) that are not installed: "
            f"{', '.join(missing)}"
        )
        logger.error("%s", message)
        return TrafficResult(
            traffic_type=context.traffic_type,
            status=TrafficStatus.FAILED,
            generated=False,
            error_code=ErrorCode.TOOL_NOT_AVAILABLE,
            message=message,
        )
    logger.info(
        "generating %s traffic towards %s for %.1fs",
        context.traffic_type.value,
        context.target,
        context.duration_s,
    )
    return generator.generate(context, active_runner, dry_run=dry_run)

