"""Control class: capture IKE/ESP control traffic only.

An experiment with ``traffic_type: control`` generates no application traffic.
It exists because several later questions ("how does IKE/PFS look on the wire?",
"how much metadata leaks without payload?") need a capture without payload as a
reference point.  The class is explicitly *not* part of the data classes
required by the problem statement.
"""

from __future__ import annotations

from ..dataset.schema import TrafficClass
from .base import BaseTrafficGenerator, TrafficContext, TrafficPlan


class ControlTrafficGenerator(BaseTrafficGenerator):
    """Generate no application traffic at all."""

    traffic_type = TrafficClass.CONTROL
    display_name = "control (no application traffic)"
    required_tools = ()
    label = "no application traffic: IKE/ESP control traffic only"

    def build_plan(self, context: TrafficContext) -> TrafficPlan:
        return TrafficPlan(
            traffic_type=self.traffic_type,
            steps=(),
            description="no application traffic generated (control capture)",
            expected_flow_count=0,
        )


__all__ = ["ControlTrafficGenerator"]
