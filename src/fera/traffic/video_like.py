"""Video-like traffic (sustained or bursty high throughput flow).

Two implementations are available:

* ``iperf3`` when it is installed (mature tool, accurate throughput control),
* a native TCP stream otherwise (paced to a target bitrate, optionally with
  adaptive-streaming-like bursts).

The class is labelled ``video_like`` - it is a throughput model, not captured
YouTube/Netflix traffic.
"""

from __future__ import annotations

from ..dataset.schema import TrafficClass
from .base import BaseTrafficGenerator, CommandStep, NativeStep, TrafficContext, TrafficPlan
from .native import DEFAULT_ECHO_PORT

DEFAULT_IPERF_PORT = 5201


class VideoLikeTrafficGenerator(BaseTrafficGenerator):
    """Generate a sustained or bursty high throughput flow."""

    traffic_type = TrafficClass.VIDEO_LIKE
    display_name = "video-like stream"
    #: iperf3 is optional: the native TCP stream is used when it is missing.
    required_tools = ()
    needs_responder = True
    label = "synthetic high throughput stream (video-shaped, not real streaming traffic)"

    def build_plan(self, context: TrafficContext) -> TrafficPlan:
        target_mbps = float(context.option("target_mbps", 4.0))
        duration_s = float(context.option("duration_s", context.duration_s))
        if context.option("use_iperf3", False):
            port = int(context.port or context.option("port", DEFAULT_IPERF_PORT))
            command = [
                "iperf3",
                "--client",
                context.target,
                "--time",
                f"{max(1.0, duration_s):.0f}",
                "--bitrate",
                f"{max(0.1, target_mbps):g}M",
                "--port",
                str(port),
                "--json",
            ]
            return TrafficPlan(
                traffic_type=self.traffic_type,
                steps=(
                    CommandStep(
                        command=tuple(command),
                        description=f"iperf3 TCP stream at {target_mbps:g} Mbit/s for {duration_s:g} s",
                        timeout_s=max(30.0, duration_s + 30.0),
                    ),
                ),
                description=f"video-like (iperf3): {target_mbps:g} Mbit/s for {duration_s:g} s",
                uses_server=True,
                server_hint=(
                    f"requires `iperf3 --server --port {port}` on the responder endpoint"
                ),
                expected_flow_count=1,
            )
        parameters = {
            "port": int(context.port or context.option("port", DEFAULT_ECHO_PORT)),
            "duration_s": duration_s,
            "chunk_bytes": int(context.option("chunk_bytes", 16384)),
            "target_mbps": target_mbps,
            "burst_on_ms": int(context.option("burst_on_ms", 0)),
            "burst_off_ms": int(context.option("burst_off_ms", 0)),
        }
        burst_note = (
            f", bursts {parameters['burst_on_ms']} ms on / {parameters['burst_off_ms']} ms off"
            if parameters["burst_on_ms"] and parameters["burst_off_ms"]
            else ", continuous"
        )
        return TrafficPlan(
            traffic_type=self.traffic_type,
            steps=(
                NativeStep(
                    kind="tcp_stream",
                    parameters=parameters,
                    description=f"native TCP stream at {target_mbps:g} Mbit/s for {duration_s:g} s",
                ),
            ),
            description=f"video-like (native TCP): {target_mbps:g} Mbit/s for {duration_s:g} s{burst_note}",
            uses_server=True,
            server_hint=(
                "requires the FERA TCP responder on the responder endpoint "
                "(python -m fera.traffic.servers --proto tcp)"
            ),
            expected_flow_count=1,
        )


__all__ = ["DEFAULT_IPERF_PORT", "VideoLikeTrafficGenerator"]
