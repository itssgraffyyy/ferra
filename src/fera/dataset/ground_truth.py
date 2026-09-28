"""Ground truth metadata.

Ground truth is the contract between this dataset factory and every later
stage: it states what was *configured*, what the toolchain *reported* and
whether the run is a usable sample.  It never contains model predictions -
predictions are produced by later stages and must stay separable from the
ground truth (that separation is what makes the dataset defensible).

Configured vs. observed: passive capture cannot prove which algorithms were
negotiated, so ground truth records:

* ``configured_*`` - what the experiment asked strongSwan for,
* ``local_endpoint_reported_*`` - what the endpoint's own ``swanctl --list-sas``
  reported after the SA was established (runtime evidence from the endpoint,
  clearly attributed - not a passive-observation claim).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..common.paths import ProjectPaths
from ..common.serialization import write_json
from ..testbed.topology import TestbedTopology
from .schema import ExperimentConfig

GROUND_TRUTH_SOURCE = "experiment_configuration_and_runtime"
#: Placeholder for prediction fields owned by later prompt stages.
MODEL_PREDICTIONS_SLOT: None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class GroundTruth:
    """Ground truth document of one experiment run."""

    experiment_id: str
    document: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return self.document

    def write(self, path: Path | str) -> Path:
        return write_json(Path(path), self.document)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> GroundTruth:
        return cls(experiment_id=str(document.get("experiment_id", "")), document=dict(document))


def ground_truth_path(paths: ProjectPaths, experiment_id: str) -> Path:
    """Canonical ground-truth location of an experiment."""
    return paths.experiment_dir(experiment_id) / "ground_truth.json"


def build_ground_truth(
    config: ExperimentConfig,
    topology: TestbedTopology,
    *,
    execution_status: str,
    dry_run: bool = False,
    valid_capture: bool = False,
    integration_verified: bool = False,
    error_code: str | None = None,
    error_message: str | None = None,
    pcap_path: str | None = None,
    pcap_relative_path: str | None = None,
    capture_details: Mapping[str, Any] | None = None,
    validation: Mapping[str, Any] | None = None,
    sa_details: Mapping[str, Any] | None = None,
    tool_versions: Mapping[str, str | None] | None = None,
    host: Mapping[str, Any] | None = None,
    timing: Mapping[str, Any] | None = None,
    experiment_config_path: str | None = None,
    generated_config: Mapping[str, Any] | None = None,
    notes: str | None = None,
) -> GroundTruth:
    """Build the ground-truth document of one experiment run.

    ``valid_capture`` must already reflect the capture sanity check: the runner
    is responsible for never marking a broken run as a valid sample.
    """
    transforms = config.transforms
    document: dict[str, Any] = {
        "schema_version": 1,
        "ground_truth_source": GROUND_TRUTH_SOURCE,
        "experiment_id": config.experiment_id,
        "configuration_hash": config.fingerprint,
        "generated_at": _utc_now(),
        "execution": {
            "status": execution_status,
            "dry_run": bool(dry_run),
            "valid_capture": bool(valid_capture),
            "integration_verified": bool(integration_verified),
            "error_code": error_code,
            "error_message": error_message,
            "reusable_as_dataset_sample": bool(valid_capture and not dry_run),
        },
        "ipsec": {
            "mode": config.mode.value,
            "ike_version": config.ike_version,
            "configured_encryption": config.encryption.value,
            "configured_encryption_key_bits": transforms.encryption_info.key_bits,
            "configured_encryption_strongswan_keyword": transforms.encryption_info.strongswan_keyword,
            "aead": transforms.aead,
            "configured_integrity": config.integrity.value,
            "configured_integrity_strongswan_keyword": transforms.esp_integrity_keyword,
            "configured_integrity_source": transforms.to_dict()["integrity_source"],
            "configured_ike_prf": transforms.effective_prf,
            "configured_ike_prf_source": transforms.prf_source,
            "configured_dh_group": config.dh_group.value,
            "configured_dh_group_number": config.dh_group.info.iana_group_number,
            "configured_pfs": bool(config.pfs),
            "configured_pfs_child_dh_group": (
                config.pfs_dh_group.value
                if config.pfs_dh_group
                else (config.dh_group.value if config.pfs else None)
            ),
            "pfs_semantics": transforms.pfs_description,
            "esp_proposal_contains_dh_group": bool(config.pfs),
            "configured_ike_proposal": transforms.ike_proposal,
            "configured_esp_proposal": transforms.esp_proposal,
            "configured_ike_sa_lifetime_s": int(config.ike_sa_lifetime_s),
            "configured_child_sa_rekey_time_s": int(config.child_sa_lifetime_s),
            "configured_child_sa_life_time_s": int(config.child_sa_life_time_s()),
        },
        "ip_version": config.ip_version,
        "traffic_class": config.traffic_type.value,
        "traffic_label_basis": (
            "synthetic analogue of the named application class (not a capture of the real application)"
            if config.traffic_type.is_labelled_analogue
            else "synthetic control/measurement traffic"
        ),
        "capture": {
            "filename": Path(pcap_path).name if pcap_path else "capture.pcap",
            "path": pcap_relative_path or (str(pcap_path) if pcap_path else None),
            "details": dict(capture_details or {}),
        },
        "capture_validation": dict(validation or {}),
        "testbed": topology.metadata_block(config.mode.value, config.ip_version),
        "local_endpoint_reported": dict(sa_details or {}),
        "runtime": {
            "tool_versions": dict(tool_versions or {}),
            "host": dict(host or {}),
            "timing": dict(timing or {}),
        },
        "reproducibility": {
            "seed": config.seed,
            "effective_seed": config.effective_seed,
            "experiment_config_path": experiment_config_path,
            "generated_config": dict(generated_config or {}),
            "regenerate_command": f"python scripts/run_experiment.py --config {experiment_config_path}",
        },
        "model_predictions": MODEL_PREDICTIONS_SLOT,
        "notes": notes if notes is not None else config.notes,
    }
    return GroundTruth(experiment_id=config.experiment_id, document=document)


def load_ground_truth(path: Path | str) -> GroundTruth:
    """Load a ground-truth document from disk."""
    from ..common.serialization import load_json

    return GroundTruth.from_dict(load_json(Path(path)))


__all__ = [
    "GROUND_TRUTH_SOURCE",
    "GroundTruth",
    "build_ground_truth",
    "ground_truth_path",
    "load_ground_truth",
]

