"""Web traffic generation (HTTP requests against a controlled endpoint).

Traffic is generated with ``curl`` against the HTTP endpoint the topology
provides on the responder side (the FERA responder can serve a deterministic
``/payload`` object).  This is *web-shaped* traffic - it is never labelled as a
specific website.
"""

from __future__ import annotations

import random

from ..dataset.schema import TrafficClass
from .base import BaseTrafficGenerator, CommandStep, TrafficContext, TrafficPlan

DEFAULT_PATHS = ("/", "/index.html", "/assets/style.css", "/assets/app.js", "/assets/logo.png")
DEFAULT_HTTP_PORT = 8080


def curl_command(
    context: TrafficContext,
    *,
    url: str,
    max_time_s: float,
    extra: tuple[str, ...] = (),
) -> list[str]:
    """Build a quiet, time limited ``curl`` request."""
    devnull = "NUL" if context.platform == "windows" else "/dev/null"
    return [
        "curl",
        "--silent",
        "--show-error",
        "--output",
        devnull,
        "--max-time",
        f"{max_time_s:.0f}",
        *extra,
        url,
    ]


def http_base_url(context: TrafficContext, *, port: int, scheme: str = "http") -> str:
    """Build the base URL for the responder's HTTP endpoint."""
    host = f"[{context.target}]" if context.target_is_ipv6 else context.target
    return f"{scheme}://{host}:{port}"


class WebTrafficGenerator(BaseTrafficGenerator):
    """Generate HTTP requests against a controlled endpoint."""

    traffic_type = TrafficClass.WEB
    display_name = "HTTP requests"
    required_tools = ("curl",)
    needs_responder = True
    label = "synthetic HTTP request/response traffic against the controlled testbed endpoint"

    def build_plan(self, context: TrafficContext) -> TrafficPlan:
        port = int(context.port or context.option("port", DEFAULT_HTTP_PORT))
        scheme = str(context.option("scheme", "http"))
        paths = tuple(context.option("paths", DEFAULT_PATHS))
        request_count = int(context.option("request_count", 10))
        payload_bytes = int(context.option("payload_bytes", 2_000_000))
        base = http_base_url(context, port=port, scheme=scheme)
        rng = random.Random(context.seed)

        steps: list[CommandStep] = []
        for _index in range(max(1, request_count)):
            path = paths[rng.randrange(len(paths))]
            steps.append(
                CommandStep(
                    command=tuple(curl_command(context, url=f"{base}{path}", max_time_s=10)),
                    description=f"HTTP GET {path}",
                    timeout_s=15.0,
                )
            )
        steps.append(
            CommandStep(
                command=tuple(
                    curl_command(
                        context,
                        url=f"{base}/payload?bytes={payload_bytes}",
                        max_time_s=max(10.0, min(context.duration_s, 120.0)),
                    )
                ),
                description=f"HTTP GET /payload ({payload_bytes} bytes)",
                timeout_s=max(20.0, min(context.duration_s, 120.0) + 10.0),
            )
        )
        return TrafficPlan(
            traffic_type=self.traffic_type,
            steps=tuple(steps),
            description=f"HTTP: {request_count} object requests + one {payload_bytes} byte transfer",
            uses_server=True,
            server_hint=(
                f"an HTTP endpoint must be reachable at {base} "
                "(python -m fera.traffic.servers --proto http)"
            ),
            expected_flow_count=request_count + 1,
            required_tools=self.required_tools,
        )


__all__ = ["DEFAULT_HTTP_PORT", "DEFAULT_PATHS", "WebTrafficGenerator", "curl_command", "http_base_url"]
