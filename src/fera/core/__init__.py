"""Product layer: the unified analysis surface consumed by API and dashboard.

This package is an *integrating* layer.  It never re-implements protocol
decoding, feature extraction, classification or security scoring; it calls the
stages that already exist and combines their output into one document:

===========================  =========================================  ===================
Stage                        Consumed from                              Bundle component
===========================  =========================================  ===================
Prompt 2 protocol analysis   :func:`fera.analysis.analyze_pcap`          ``protocol``
Prompt 3 ML traffic          :func:`fera.ml.extract_features` + model     ``traffic``
Prompt 4 security scoring    :func:`fera.security.assess_security`        ``security``
Privacy intelligence         :mod:`fera.privacy`                          ``privacy``
===========================  =========================================  ===================

The contract is :data:`BUNDLE_SCHEMA_VERSION` (:class:`AnalysisBundle`).  Every
component is optional and carries its own :class:`StageResult`, so a missing
model or an unavailable capture tool downgrades *one* component instead of
failing the whole analysis (see :mod:`fera.core.orchestrator`).
"""

from __future__ import annotations

from .bundle import (
    BUNDLE_SCHEMA_VERSION,
    STAGE_ORDER,
    AnalysisBundle,
    StageResult,
    StageStatus,
    overall_status,
)
from .orchestrator import CaptureSource, SourceKind, run_analysis

__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "STAGE_ORDER",
    "AnalysisBundle",
    "CaptureSource",
    "SourceKind",
    "StageResult",
    "StageStatus",
    "overall_status",
    "run_analysis",
]
