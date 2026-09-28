"""AI stage: encrypted ESP traffic classification.

Modules:

* :mod:`fera.ml.features` - versioned statistical features extracted from the
  deterministic Prompt 2 analysis output (no protocol re-parsing, no labels).
"""

from __future__ import annotations

from .features import FEATURE_SCHEMA, FEATURE_WHITELIST, FeatureVector, extract_features

__all__ = [
    "FEATURE_SCHEMA",
    "FEATURE_WHITELIST",
    "FeatureVector",
    "extract_features",
]
