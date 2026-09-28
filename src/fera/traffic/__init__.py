"""Traffic generation: generators, profiles, responders."""

from __future__ import annotations

from .base import (
    BaseTrafficGenerator,
    CommandStep,
    NativeStep,
    TrafficContext,
    TrafficGenerator,
    TrafficPlan,
    TrafficResult,
    TrafficStatus,
    execute_plan,
    ping_count,
)
from .control import ControlTrafficGenerator
from .email_like import EmailLikeTrafficGenerator
from .icmp import IcmpTrafficGenerator
from .messaging_like import MessagingLikeTrafficGenerator
from .native import (
    NATIVE_EXECUTORS,
    UdpSender,
    deterministic_payload,
    send_tcp_request_response,
    send_tcp_stream,
    send_udp_bursts,
    send_udp_pattern,
)
from .profiles import default_profiles, load_profiles, profile_for
from .registry import (
    GENERATORS,
    TRAFFIC_ALIASES,
    available_traffic_types,
    describe_traffic_types,
    generate_traffic,
    get_generator,
    resolve_traffic_type,
)
from .servers import responder_command, serve_http, serve_tcp_echo, serve_udp_echo
from .video_like import VideoLikeTrafficGenerator
from .voip_like import VoipLikeTrafficGenerator
from .web import WebTrafficGenerator

__all__ = [
    "GENERATORS",
    "NATIVE_EXECUTORS",
    "TRAFFIC_ALIASES",
    "BaseTrafficGenerator",
    "CommandStep",
    "ControlTrafficGenerator",
    "EmailLikeTrafficGenerator",
    "IcmpTrafficGenerator",
    "MessagingLikeTrafficGenerator",
    "NativeStep",
    "TrafficContext",
    "TrafficGenerator",
    "TrafficPlan",
    "TrafficResult",
    "TrafficStatus",
    "UdpSender",
    "VideoLikeTrafficGenerator",
    "VoipLikeTrafficGenerator",
    "WebTrafficGenerator",
    "available_traffic_types",
    "default_profiles",
    "describe_traffic_types",
    "deterministic_payload",
    "execute_plan",
    "generate_traffic",
    "get_generator",
    "load_profiles",
    "ping_count",
    "profile_for",
    "resolve_traffic_type",
    "responder_command",
    "send_tcp_request_response",
    "send_tcp_stream",
    "send_udp_bursts",
    "send_udp_pattern",
    "serve_http",
    "serve_tcp_echo",
    "serve_udp_echo",
]
