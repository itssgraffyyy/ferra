"""VoIP-like traffic (configurable UDP flow: packet size, interval, duration).

Defaults model a G.711 style stream: 160 byte payloads every 20 ms, which is
the classic constant bit rate voice profile.  The class is labelled
``voip_like``; it is a synthetic model of a voice flow, not a captured call.
"""

from __future__ import annotations

from ..dataset.schema import TrafficClass
from .base import BaseTrafficGenerator, NativeStep, TrafficContext, TrafficPlan
from .native import DEFAULT_ECHO_PORT


class VoipLikeTrafficGenerator(BaseTrafficGenerator):
    """Generate a constant bit rate UDP flow."""

    traffic_type = TrafficClass.VOIP_LIKE
    display_name = "voip-like UDP flow"
    required_tools = ()
    needs_responder = False
    label = "synthetic constant bit rate UDP flow with voice-like packet size and interval"

    def build_plan(self, context: TrafficContext) -> TrafficPlan:
        packet_size = int(context.option("packet_size", 160))
        interval_ms = int(context.option("interval_ms", 20))
        bidirectional = bool(context.option("bidirectional", False))
        parameters = {
            "port": int(context.port or context.option("port", DEFAULT_ECHO_PORT)),
            "packet_size": packet_size,
            "interval_ms": interval_ms,
            "duration_s": context.duration_s,
            "read_responses": bidirectional,
            "response_timeout_ms": int(context.option("response_timeout_ms", 500)),
        }
        expected_packets = int(max(1, context.duration_s) * 1000 / max(1, interval_ms))
        return TrafficPlan(
            traffic_type=self.traffic_type,
            steps=(
                NativeStep(
                    kind="udp_pattern",
                    parameters=parameters,
                    description=(
                        f"UDP flow: {packet_size} byte payloads every {interval_ms} ms for "
                        f"{context.duration_s:g} s"
                    ),
                ),
            ),
            description=(
                f"voip-like: {packet_size} byte payloads every {interval_ms} ms "
                f"(~{expected_packets} packets, one direction={not bidirectional})"
            ),
            uses_server=bidirectional,
            server_hint=(
                "bidirectional mode requires the UDP responder "
                "(python -m fera.traffic.servers --proto udp)"
                if bidirectional
                else None
            ),
            expected_flow_count=1,
        )


__all__ = ["VoipLikeTrafficGenerator"]
