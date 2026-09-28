"""ICMP traffic generation (controlled ping traffic).

The ICMP class is the control measurement of the dataset: it is cheap, has a
known packet count, and exercises the SA in both directions through echo
request/reply.  It needs no responder software because the peer kernel answers
ICMP echo requests itself - which is also why ICMP cannot be used to prove that
*application* traffic is protected.
"""

from __future__ import annotations

from ..dataset.schema import TrafficClass
from .base import BaseTrafficGenerator, CommandStep, TrafficContext, TrafficPlan, ping_count


def ping_command(
    context: TrafficContext,
    *,
    count: int,
    interval_s: float,
    payload_bytes: int,
) -> list[str]:
    """Build the platform appropriate ``ping`` command."""
    if context.platform == "windows":
        command = ["ping", "-n", str(count), "-w", "2000"]
        if context.target_is_ipv6:
            command.append("-6")
        command.append(context.target)
        return command
    # Linux (iputils-ping): -n = numeric output, -c count, -i interval,
    # -W timeout, -s payload size.  IPv6 needs -6 and stays below the
    # minimum MTU so the probes are not fragmented.
    size = min(payload_bytes, 1200) if context.target_is_ipv6 else payload_bytes
    command = [
        "ping",
        "-n",
        "-c",
        str(count),
        "-i",
        f"{max(interval_s, 0.2):.2f}",
        "-W",
        "2",
        "-s",
        str(size),
    ]
    if context.target_is_ipv6:
        command.append("-6")
    if context.source:
        command += ["-I", context.source]
    command.append(context.target)
    return command


class IcmpTrafficGenerator(BaseTrafficGenerator):
    """Generate controlled ICMP echo traffic."""

    traffic_type = TrafficClass.ICMP
    display_name = "ICMP echo"
    required_tools = ("ping",)
    label = "synthetic ICMP echo request/reply traffic"

    def build_plan(self, context: TrafficContext) -> TrafficPlan:
        interval_s = float(context.option("interval_ms", 500)) / 1000.0
        payload_bytes = int(context.option("payload_bytes", 56))
        count = ping_count(context.duration_s, interval_s)
        command = ping_command(context, count=count, interval_s=interval_s, payload_bytes=payload_bytes)
        return TrafficPlan(
            traffic_type=self.traffic_type,
            steps=(
                CommandStep(
                    command=tuple(command),
                    description=f"{count} ICMP echo requests to {context.target}",
                    timeout_s=max(30.0, context.duration_s + 30.0),
                ),
            ),
            description=(
                f"ICMP echo, {count} probes, interval {interval_s * 1000:.0f} ms, "
                f"payload {payload_bytes} bytes"
            ),
            expected_flow_count=1,
            required_tools=self.required_tools,
        )


__all__ = ["IcmpTrafficGenerator", "ping_command"]
