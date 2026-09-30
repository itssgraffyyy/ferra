"""Metadata-exposure view: what an off-path observer can still learn.

The security answer measures how well the tunnel is protected.  This package asks
the complementary question - what is visible *around* the tunnel - because
"your data is encrypted" and "an observer can still tell who you talk to, when,
and roughly how much" are both true at once, and the second one is what privacy
reviews care about.
"""

from .models import (
    EXPOSURE_POINTS,
    PRIVACY_SCHEMA_VERSION,
    Observation,
    PrivacyReport,
    exposure_band,
)
from .observer import observe_privacy

__all__ = [
    "EXPOSURE_POINTS",
    "PRIVACY_SCHEMA_VERSION",
    "Observation",
    "PrivacyReport",
    "exposure_band",
    "observe_privacy",
]
