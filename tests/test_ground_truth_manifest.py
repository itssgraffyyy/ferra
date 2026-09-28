"""Ground truth and dataset manifest tests."""

from __future__ import annotations

from pathlib import Path

from conftest import ike_and_esp_frames, make_config, write_pcap
from fera.common.serialization import write_json
from fera.dataset.ground_truth import build_ground_truth, ground_truth_path, load_ground_truth
from fera.dataset.manifest import build_manifest, entry_from_ground_truth, write_manifest
from fera.testbed.swanctl_config import generate_psk


def ground_truth_for(tmp_path: Path, topology, *, status: str = "SUCCESS", valid: bool = True, pcap: bool = True):
    config = make_config()
    pcap_path = tmp_path / config.experiment_id / "capture.pcap"
    if pcap:
        write_pcap(pcap_path, ike_and_esp_frames())
    validation = {
        "status": "VALID" if valid else "INVALID",
        "valid": valid,
        "method": "pcap_scan",
        "packets": 7,
        "bytes_on_disk": pcap_path.stat().st_size if pcap else 0,
        "ike_detected": True,
        "esp_detected": valid,
        "reasons": [] if valid else ["no ESP (IP protocol 50) found in the capture"],
    }
    document = build_ground_truth(
        config,
        topology,
        execution_status=status,
        valid_capture=valid,
        integration_verified=valid,
        error_code=None if valid else "CAPTURE_VALIDATION_FAILED",
        error_message=None if valid else "capture validation failed",
        pcap_path=str(pcap_path),
        pcap_relative_path=f"data/raw/{config.experiment_id}/capture.pcap",
        capture_details={"tool": "tcpdump", "size_bytes": validation["bytes_on_disk"], "sha256": "abc123"},
        validation=validation,
        sa_details={"endpoint_a": {"ike_state": "ESTABLISHED"}},
        tool_versions={"swanctl": "5.9.13", "tcpdump": "4.99.4", "iperf3": None},
        host={"system": "Linux"},
        timing={"run_duration_s": 21.0},
        experiment_config_path=f"data/raw/{config.experiment_id}/experiment.yaml",
        generated_config={"connection_name": "fera-exp"},
    )
    return config, pcap_path, document


def test_ground_truth_records_configured_not_predicted_values(tmp_path: Path, topology) -> None:
    config, _pcap, document = ground_truth_for(tmp_path, topology, status="SUCCESS")
    payload = document.to_dict()

    assert payload["ground_truth_source"] == "experiment_configuration_and_runtime"
    assert payload["experiment_id"] == config.experiment_id
    assert payload["ipsec"]["configured_encryption"] == "aes128_gcm"
    assert payload["ipsec"]["configured_integrity"] == "aead"
    assert payload["ipsec"]["configured_pfs"] is True
    assert payload["ipsec"]["configured_dh_group"] == "ecp256"
    assert payload["ipsec"]["configured_ike_proposal"] == "aes128gcm16-prfsha256-ecp256"
    assert payload["ipsec"]["esp_proposal_contains_dh_group"] is True
    assert payload["ipsec"]["configured_integrity_source"].startswith("AEAD")
    assert payload["model_predictions"] is None
    assert payload["execution"]["reusable_as_dataset_sample"] is True
    assert payload["runtime"]["tool_versions"]["iperf3"] is None
    assert payload["local_endpoint_reported"]["endpoint_a"]["ike_state"] == "ESTABLISHED"


def test_ground_truth_never_contains_credentials(tmp_path: Path, topology) -> None:
    psk = generate_psk(16)
    _config, _pcap, document = ground_truth_for(tmp_path, topology)
    assert psk not in str(document.to_dict())


def test_ground_truth_round_trips_through_disk(tmp_path: Path, topology) -> None:
    _config, _pcap, document = ground_truth_for(tmp_path, topology)
    target = tmp_path / "ground_truth.json"
    document.write(target)
    reloaded = load_ground_truth(target)
    assert reloaded.to_dict() == document.to_dict()
    assert reloaded.experiment_id == document.experiment_id


def test_ground_truth_path_helper(sandbox_paths) -> None:
    path = ground_truth_path(sandbox_paths, "exp_000_tunnel_aes128gcm_ecp256_pfson_ipv4_icmp")
    assert path.name == "ground_truth.json"
    assert path.parent.name.startswith("exp_000")


def test_manifest_entry_requires_a_valid_capture(tmp_path: Path, repo_paths, topology) -> None:
    _config, _pcap, document = ground_truth_for(tmp_path, topology, valid=False, status="FAILED")
    entry, rejection = entry_from_ground_truth(
        document.to_dict(),
        paths=repo_paths,
        ground_truth_file=tmp_path / "ground_truth.json",
    )
    assert entry is None
    assert rejection is not None and "not a valid sample" in rejection


def test_manifest_excludes_failed_runs(tmp_path: Path, sandbox_paths, topology) -> None:
    raw = sandbox_paths.raw
    for name, valid, status in (("exp_000_good", True, "SUCCESS"), ("exp_001_bad", False, "FAILED")):
        experiment_dir = raw / name
        experiment_dir.mkdir(parents=True, exist_ok=True)
        _config, _pcap, document = ground_truth_for(tmp_path, topology, status=status, valid=valid)
        payload = document.to_dict()
        payload["experiment_id"] = name
        payload["capture"]["path"] = f"data/raw/{name}/capture.pcap"
        write_pcap(experiment_dir / "capture.pcap", ike_and_esp_frames())
        write_json(experiment_dir / "ground_truth.json", payload)

    manifest = build_manifest(paths=sandbox_paths)
    assert manifest["sample_count"] == 1
    assert manifest["rejected_count"] == 1
    assert manifest["entries"][0]["experiment_id"] == "exp_000_good"
    assert manifest["rejected"][0]["experiment_id"] == "exp_001_bad"
    assert manifest["entries"][0]["pcap_path"].startswith("data/raw/")
    assert manifest["entries"][0]["ground_truth_path"].endswith("ground_truth.json")
    assert manifest["summary"]["mode"] == {"tunnel": 1}
    assert manifest["summary"]["ip_version"] == {"IPv4": 1}
    assert manifest["summary"]["pfs"] == {"on": 1}
    assert "packet data" in manifest["notes"].lower()


def test_manifest_marks_missing_capture_as_rejected(tmp_path: Path, sandbox_paths, topology) -> None:
    experiment_dir = sandbox_paths.raw / "exp_002_missing"
    experiment_dir.mkdir(parents=True, exist_ok=True)
    _config, _pcap, document = ground_truth_for(tmp_path, topology, pcap=False)
    payload = document.to_dict()
    payload["experiment_id"] = "exp_002_missing"
    payload["capture"]["path"] = "data/raw/exp_002_missing/capture.pcap"
    write_json(experiment_dir / "ground_truth.json", payload)

    manifest = build_manifest(paths=sandbox_paths)
    assert manifest["sample_count"] == 0
    assert "missing" in manifest["rejected"][0]["reason"]


def test_manifest_writer_is_atomic(tmp_path: Path, repo_paths) -> None:
    manifest = build_manifest(paths=repo_paths)
    target = write_manifest(manifest, tmp_path / "nested" / "dataset.json")
    assert target.is_file()
    assert not (tmp_path / "nested" / "dataset.json.tmp").exists()


def test_manifest_without_runs_is_empty_but_valid(tmp_path: Path) -> None:
    from fera.common.paths import ProjectPaths

    manifest = build_manifest(paths=ProjectPaths(tmp_path))
    assert manifest["sample_count"] == 0
    assert manifest["rejected_count"] == 0
    assert manifest["entries"] == []


def test_unreadable_ground_truth_is_rejected_not_fatal(tmp_path: Path, sandbox_paths) -> None:
    experiment_dir = sandbox_paths.raw / "exp_003_broken"
    experiment_dir.mkdir(parents=True, exist_ok=True)
    (experiment_dir / "ground_truth.json").write_text("{not json", encoding="utf-8")
    manifest = build_manifest(paths=sandbox_paths)
    assert manifest["sample_count"] == 0
    assert "unreadable ground truth" in manifest["rejected"][0]["reason"]

