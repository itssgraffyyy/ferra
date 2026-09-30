"""Local persistence for the product layer.

Only the analysis history lives here.  The canonical bundle documents
themselves stay on disk as JSON, so a stored result can always be re-opened and
diffed exactly as the pipeline produced it.
"""

from __future__ import annotations

from .history import (
    FILTER_FIELDS,
    HISTORY_SCHEMA_VERSION,
    AnalysisRecord,
    HistoryRepository,
    record_from_bundle,
)

__all__ = [
    "FILTER_FIELDS",
    "HISTORY_SCHEMA_VERSION",
    "AnalysisRecord",
    "HistoryRepository",
    "record_from_bundle",
]
