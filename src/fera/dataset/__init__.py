"""Dataset factory: schema, matrix, ground truth, manifest, experiment runner."""

from __future__ import annotations

from .ground_truth import (
    GroundTruth,
    build_ground_truth,
    ground_truth_path,
    load_ground_truth,
)
from .manifest import ManifestEntry, build_manifest, entry_from_ground_truth, write_manifest
from .matrix import (
    MATRIX_ENTRIES,
    CoverageCheck,
    MatrixEntry,
    build_matrix,
    check_coverage,
    coverage_report,
    render_coverage,
)
from .schema import (
    MAX_CAPTURE_DURATION_S,
    REQUIRED_TRAFFIC_CLASSES,
    SCHEMA_VERSION,
    SUPPORTED_IKE_VERSIONS,
    SUPPORTED_IP_VERSIONS,
    ExperimentConfig,
    IpsecMode,
    TrafficClass,
    build_experiment_id,
    check_topology_compatibility,
    experiment_from_dict,
    find_experiment_configs,
    load_experiment,
    require_topology_compatibility,
    save_experiment,
)

__all__ = [
    "MATRIX_ENTRIES",
    "MAX_CAPTURE_DURATION_S",
    "REQUIRED_TRAFFIC_CLASSES",
    "SCHEMA_VERSION",
    "SUPPORTED_IKE_VERSIONS",
    "SUPPORTED_IP_VERSIONS",
    "CoverageCheck",
    "ExperimentConfig",
    "GroundTruth",
    "IpsecMode",
    "ManifestEntry",
    "MatrixEntry",
    "TrafficClass",
    "build_experiment_id",
    "build_ground_truth",
    "build_manifest",
    "build_matrix",
    "check_coverage",
    "check_topology_compatibility",
    "coverage_report",
    "entry_from_ground_truth",
    "experiment_from_dict",
    "find_experiment_configs",
    "ground_truth_path",
    "load_experiment",
    "load_ground_truth",
    "render_coverage",
    "require_topology_compatibility",
    "save_experiment",
    "write_manifest",
]
