"""Dataset manifest generation.

The manifest is the index of the dataset: it points at PCAPs and ground truth
files and repeats only the *small* classification fields a consumer needs to
select samples.  Packet data is never duplicated in the manifest.

Only captures whose sanity check passed end up in ``entries``; everything else
lands in ``rejected`` with the reason, so a broken run is visible (and auditable)
without ever being usable as a training sample.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..common.logging_utils import get_logger
from ..common.paths import ProjectPaths, default_paths
from ..common.serialization import load_json, write_json

logger = get_logger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class ManifestEntry:
    """One dataset sample in the manifest."""

    experiment_id: str
    pcap_path: str
    ground_truth_path: str
    traffic_type: str
    mode: str
    encryption: str
    integrity: str
    dh_group: str
    pfs: bool
    ip_version: int
    valid_capture: bool
    timestamp: str
    extra: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        entry = {
            "experiment_id": self.experiment_id,
            "pcap_path": self.pcap_path,
            "ground_truth_path": self.ground_truth_path,
            "traffic_type": self.traffic_type,
            "mode": self.mode,
            "encryption": self.encryption,
            "integrity": self.integrity,
            "dh_group": self.dh_group,
            "pfs": self.pfs,
            "ip_version": self.ip_version,
            "valid_capture": self.valid_capture,
            "timestamp": self.timestamp,
        }
        entry.update(self.extra)
        return entry


def _relative(paths: ProjectPaths, path: Path | str | None) -> str | None:
    if path is None:
        return None
    return paths.relative(path)


def entry_from_ground_truth(
    ground_truth: Mapping[str, Any],
    *,
    paths: ProjectPaths,
    ground_truth_file: Path,
) -> tuple[ManifestEntry | None, str | None]:
    """Build a manifest entry from a ground truth document.

    Returns ``(entry, rejection_reason)`` - exactly one of both is set.
    """
    experiment_id = str(ground_truth.get("experiment_id") or "")
    if not experiment_id:
        return None, "ground truth document has no experiment_id"
    execution = ground_truth.get("execution") or {}
    ipsec = ground_truth.get("ipsec") or {}
    capture = ground_truth.get("capture") or {}
    validation = ground_truth.get("capture_validation") or {}
    pcap_path = capture.get("path")
    if not pcap_path:
        return None, "ground truth document has no capture path"
    # validity is judged first: an invalid run is rejected for that reason even
    # when its capture file is missing (which is itself part of the failure).
    valid_capture = bool(execution.get("valid_capture"))
    if not valid_capture:
        reason = execution.get("error_code") or "capture was not validated"
        if validation.get("reasons"):
            reason = f"{reason}: {'; '.join(validation['reasons'])}"
        return None, f"not a valid sample ({reason})"
    if execution.get("dry_run"):
        return None, "dry run artefacts are never part of the dataset"
    pcap_file = paths.resolve(str(pcap_path))
    if not pcap_file.is_file():
        return None, f"capture file is missing: {pcap_path}"

    extra: dict[str, Any] = {
        "bytes": validation.get("bytes_on_disk") or capture.get("details", {}).get("size_bytes"),
        "packets": validation.get("packets"),
        "validation_method": validation.get("method"),
        "ike_detected": validation.get("ike_detected"),
        "esp_detected": validation.get("esp_detected"),
        "traffic_class_is_synthetic_analogue": bool(
            ground_truth.get("traffic_label_basis", "").startswith("synthetic analogue")
        ),
        "integration_verified": bool(execution.get("integration_verified")),
        "execution_status": execution.get("status"),
        "configuration_hash": ground_truth.get("configuration_hash"),
        "capture_sha256": capture.get("details", {}).get("sha256"),
    }
    return (
        ManifestEntry(
            experiment_id=experiment_id,
            pcap_path=str(_relative(paths, pcap_file)),
            ground_truth_path=str(_relative(paths, ground_truth_file)),
            traffic_type=str(ground_truth.get("traffic_class") or ""),
            mode=str(ipsec.get("mode") or ""),
            encryption=str(ipsec.get("configured_encryption") or ""),
            integrity=str(ipsec.get("configured_integrity") or ""),
            dh_group=str(ipsec.get("configured_dh_group") or ""),
            pfs=bool(ipsec.get("configured_pfs")),
            ip_version=int(ground_truth.get("ip_version") or 0),
            valid_capture=True,
            timestamp=str(ground_truth.get("generated_at") or ""),
            extra={key: value for key, value in extra.items() if value is not None},
        ),
        None,
    )


def _counts(values: Iterable[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def build_manifest(
    *,
    paths: ProjectPaths | None = None,
    raw_dir: Path | str | None = None,
    include_rejected: bool = True,
) -> dict[str, Any]:
    """Scan the raw data tree and build the dataset manifest document."""
    resolved = paths if paths is not None else default_paths()
    base = Path(raw_dir) if raw_dir is not None else resolved.raw
    entries: list[ManifestEntry] = []
    rejected: list[dict[str, Any]] = []
    scanned = 0
    if base.is_dir():
        for experiment_dir in sorted(p for p in base.iterdir() if p.is_dir()):
            ground_truth_file = experiment_dir / "ground_truth.json"
            if not ground_truth_file.is_file():
                continue
            scanned += 1
            try:
                document = load_json(ground_truth_file)
            except Exception as exc:  # noqa: BLE001 - a broken file must not abort the manifest
                rejected.append(
                    {
                        "experiment_id": experiment_dir.name,
                        "ground_truth_path": resolved.relative(ground_truth_file),
                        "reason": f"unreadable ground truth: {exc}",
                    }
                )
                continue
            entry, rejection = entry_from_ground_truth(
                document, paths=resolved, ground_truth_file=ground_truth_file
            )
            if entry is not None:
                entries.append(entry)
            elif rejection:
                rejected.append(
                    {
                        "experiment_id": str(document.get("experiment_id") or experiment_dir.name),
                        "ground_truth_path": resolved.relative(ground_truth_file),
                        "reason": rejection,
                    }
                )
    entries.sort(key=lambda item: item.experiment_id)
    rejected.sort(key=lambda item: str(item.get("experiment_id", "")))
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "raw_dir": resolved.relative(base),
        "scanned_runs": scanned,
        "sample_count": len(entries),
        "rejected_count": len(rejected),
        "entries": [entry.to_dict() for entry in entries],
        "summary": {
            "traffic_type": _counts(entry.traffic_type for entry in entries),
            "mode": _counts(entry.mode for entry in entries),
            "encryption": _counts(entry.encryption for entry in entries),
            "integrity": _counts(entry.integrity for entry in entries),
            "dh_group": _counts(entry.dh_group for entry in entries),
            "pfs": _counts("on" if entry.pfs else "off" for entry in entries),
            "ip_version": _counts(f"IPv{entry.ip_version}" for entry in entries),
        },
        "notes": (
            "Only captures whose sanity check passed are listed as samples.  Paths are relative to "
            "the repository root.  Packet data lives in the referenced PCAP files, never here."
        ),
    }
    if include_rejected:
        manifest["rejected"] = rejected
    logger.info("manifest: %d sample(s), %d rejected, %d run(s) scanned", len(entries), len(rejected), scanned)
    return manifest


def write_manifest(document: Mapping[str, Any], path: Path | str | None = None) -> Path:
    """Write the manifest atomically (temporary file + replace)."""
    target = Path(path) if path is not None else default_paths().default_manifest_file
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    write_json(temporary, document)
    temporary.replace(target)
    return target


__all__ = [
    "ManifestEntry",
    "build_manifest",
    "entry_from_ground_truth",
    "write_manifest",
]

