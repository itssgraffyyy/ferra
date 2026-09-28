"""FERA - IPsec VPN protocol analysis and security assessment platform.

This package implements *stage 1* of the platform: the reproducible data
foundation.

    experiment configuration -> strongSwan IPsec configuration -> VPN session
    -> labelled traffic generation -> packet capture -> dataset (PCAP +
    ground truth + manifest)

Later stages (protocol parsing, ML classification, security scoring, API and
dashboard) consume the artefacts produced here and are intentionally **not**
implemented in this package yet.
"""

from __future__ import annotations

__all__ = ["__version__", "SCHEMA_VERSION"]

__version__ = "0.1.0"

#: Version of the on-disk artefact schemas (experiment YAML, ground truth,
#: dataset manifest).  Bump when a backwards incompatible field change happens.
SCHEMA_VERSION = 1
