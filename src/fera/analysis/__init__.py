"""Deterministic IKEv2 / IPsec protocol analysis.

The analyser converts a PCAP capture into structured, evidence-graded
observations (never predictions).  Every finding carries an
:class:`~fera.analysis.provenance.EvidenceKind`:

* ``OBSERVED``      - bytes/fields literally present in the capture.
* ``INFERRED``      - deterministically derived from observed values.
* ``NOT_VERIFIABLE`` - cannot be proven from a passive capture alone
  (e.g. which proposal the peer *selected* when the relevant IKE_AUTH
  payload is encrypted).
"""

from __future__ import annotations

from .analyzer import AnalysisOutcome, analyze_pcap
from .constants import (
    DH_GROUPS_IANA,
    ENCRYPTION_ALGORITHMS,
    INTEGRITY_ALGORITHMS,
    PRF_ALGORITHMS,
    IkeExchangeType,
    IkeTransformType,
)
from .esp import EspFlowRecord, summarise_esp_flows
from .ike import IkeExchangeRecord, ProposalRecord, TransformRecord, summarise_ike
from .models import PfsStatus, ProtocolAnalysis
from .provenance import Evidence, EvidenceKind
from .sa import PfsAnalysis, correlate_sa
from .tshark import TsharkError, TsharkWrapper, find_tshark

__all__ = [
    "AnalysisOutcome",
    "DH_GROUPS_IANA",
    "ENCRYPTION_ALGORITHMS",
    "INTEGRITY_ALGORITHMS",
    "EspFlowRecord",
    "Evidence",
    "EvidenceKind",
    "IkeExchangeRecord",
    "IkeExchangeType",
    "IkeTransformType",
    "PRF_ALGORITHMS",
    "PfsAnalysis",
    "PfsStatus",
    "ProposalRecord",
    "ProtocolAnalysis",
    "TsharkError",
    "TsharkWrapper",
    "TransformRecord",
    "analyze_pcap",
    "correlate_sa",
    "find_tshark",
    "summarise_esp_flows",
    "summarise_ike",
]
