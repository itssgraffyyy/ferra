"""Email-like traffic (repeatable request/response exchange patterns).

The class models the *shape* of mail retrieval: a client opens a connection,
uploads a request of a few tens of kilobytes and reads an answer.  It is
deliberately protocol agnostic (plain TCP against the FERA responder) and is
labelled ``email_like`` - it is **not** captured Gmail/IMAP/SMTP traffic.  Real
mail captures can be added later under their own label without changing this
interface.
"""

from __future__ import annotations

from ..dataset.schema import TrafficClass
from .base import BaseTrafficGenerator, NativeStep, TrafficContext, TrafficPlan
from .native import DEFAULT_ECHO_PORT


class EmailLikeTrafficGenerator(BaseTrafficGenerator):
    """Generate mail-like request/response sessions."""

    traffic_type = TrafficClass.EMAIL_LIKE
    display_name = "email-like request/response"
    required_tools = ()
    needs_responder = True
    label = "synthetic request/response sessions with mail-like message sizes (not real mail traffic)"

    def build_plan(self, context: TrafficContext) -> TrafficPlan:
        sessions = int(context.option("sessions", 4))
        request_bytes = int(context.option("request_bytes", 65536))
        parameters = {
            "port": int(context.port or context.option("port", DEFAULT_ECHO_PORT)),
            "sessions": sessions,
            "request_bytes": request_bytes,
            "chunk_bytes": int(context.option("chunk_bytes", 8192)),
            "pause_ms": int(context.option("pause_ms", 500)),
            "response_timeout_ms": int(context.option("response_timeout_ms", 3000)),
            "duration_s": context.duration_s,
        }
        return TrafficPlan(
            traffic_type=self.traffic_type,
            steps=(
                NativeStep(
                    kind="tcp_request_response",
                    parameters=parameters,
                    description=f"{sessions} request/response sessions of ~{request_bytes} bytes",
                ),
            ),
            description=(
                f"email-like: {sessions} sessions, ~{request_bytes} byte requests, "
                "answer read back from the responder"
            ),
            uses_server=True,
            server_hint=(
                "requires the FERA responder on the responder endpoint "
                "(python -m fera.traffic.servers --proto tcp)"
            ),
            expected_flow_count=sessions,
        )


__all__ = ["EmailLikeTrafficGenerator"]
