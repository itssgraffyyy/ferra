"""Messaging-like traffic (small bidirectional bursts).

Models chat traffic: short bursts of a few small messages, separated by pauses
that represent typing.  Labelled ``messaging_like`` - it is **not** captured
WhatsApp/Signal traffic.
"""

from __future__ import annotations

from ..dataset.schema import TrafficClass
from .base import BaseTrafficGenerator, NativeStep, TrafficContext, TrafficPlan
from .native import DEFAULT_ECHO_PORT


class MessagingLikeTrafficGenerator(BaseTrafficGenerator):
    """Generate bursty small-message UDP traffic."""

    traffic_type = TrafficClass.MESSAGING_LIKE
    display_name = "messaging-like bursts"
    required_tools = ()
    needs_responder = True
    label = "synthetic small-message bursts (chat-shaped, not real messenger traffic)"

    def build_plan(self, context: TrafficContext) -> TrafficPlan:
        bursts = int(context.option("bursts", 6))
        messages_per_burst = int(context.option("messages_per_burst", 3))
        parameters = {
            "port": int(context.port or context.option("port", DEFAULT_ECHO_PORT)),
            "bursts": bursts,
            "messages_per_burst": messages_per_burst,
            "message_size": int(context.option("message_size", 320)),
            "burst_gap_ms": int(context.option("burst_gap_ms", 1200)),
            "message_gap_ms": int(context.option("message_gap_ms", 250)),
            "read_responses": True,
            "response_timeout_ms": int(context.option("response_timeout_ms", 400)),
            "duration_s": context.duration_s,
        }
        return TrafficPlan(
            traffic_type=self.traffic_type,
            steps=(
                NativeStep(
                    kind="udp_bursts",
                    parameters=parameters,
                    description=(
                        f"{bursts} bursts of {messages_per_burst} messages "
                        f"({parameters['message_size']} byte base size, echoing responder)"
                    ),
                ),
            ),
            description=(
                f"messaging-like: {bursts} bursts x {messages_per_burst} messages, "
                f"{parameters['burst_gap_ms']} ms between bursts"
            ),
            uses_server=True,
            server_hint=(
                "requires the UDP echo responder on the responder endpoint "
                "(python -m fera.traffic.servers --proto udp)"
            ),
            expected_flow_count=1,
        )


__all__ = ["MessagingLikeTrafficGenerator"]
