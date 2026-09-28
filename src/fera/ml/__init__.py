"""AI stage: encrypted ESP traffic classification.

Modules:

* :mod:`fera.ml.features` - versioned statistical features extracted from the
  deterministic Prompt 2 analysis output (no protocol re-parsing, no labels).
* :mod:`fera.ml.dataset` - joins those features with ground-truth labels and
  assigns grouped train/val/test splits (the only place labels and features
  are combined).
"""

from __future__ import annotations

from .dataset import (
    DATASET_SCHEMA,
    EVIDENCE_STATUS,
    LABEL_FIELD,
    SPLITS,
    DatasetBundle,
    DatasetSample,
    build_dataset,
    build_sample,
    load_dataset,
    split_of,
    write_dataset,
)
from .features import FEATURE_SCHEMA, FEATURE_WHITELIST, FeatureVector, extract_features

__all__ = [
    "DATASET_SCHEMA",
    "EVIDENCE_STATUS",
    "FEATURE_SCHEMA",
    "FEATURE_WHITELIST",
    "LABEL_FIELD",
    "SPLITS",
    "DatasetBundle",
    "DatasetSample",
    "FeatureVector",
    "build_dataset",
    "build_sample",
    "extract_features",
    "load_dataset",
    "split_of",
    "write_dataset",
]

