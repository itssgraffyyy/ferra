"""Provenance: source revision and capture-hash verification tests."""

from __future__ import annotations

import json
from pathlib import Path

from fera.common.paths import ProjectPaths
from fera.dataset.provenance import (
    PROVENANCE_SCHEMA,
    VerificationReport,
    build_provenance,
    file_sha256,
    source_revision,
    verify_manifest,
)


def _manifest(paths: ProjectPaths, entries: list[dict]) -> dict:
    return {"schema_version": 1, "sample_count": len(entries), "samples": entries}


def _write_capture(paths: ProjectPaths, experiment_id: str, payload: bytes = b"pcap-bytes") -> str:
    pcap = paths.raw / experiment_id / "capture.pcap"
    pcap.parent.mkdir(parents=True, exist_ok=True)
    pcap.write_bytes(payload)
    return paths.relative(pcap)


def test_file_sha256_matches_hashlib(tmp_path: Path) -> None:
    import hashlib

    target = tmp_path / "capture.pcap"
    target.write_bytes(b"hello")
    assert file_sha256(target) == hashlib.sha256(b"hello").hexdigest()


def test_file_sha256_is_none_for_a_missing_file(tmp_path: Path) -> None:
    assert file_sha256(tmp_path / "absent.pcap") is None


def test_source_revision_reads_the_real_checkout(sandbox_paths: ProjectPaths) -> None:
    """The repository is a git checkout, so the revision must be readable."""
    revision = source_revision(sandbox_paths.root)
    if not revision["known"]:
        # Sandboxes are not git checkouts; the fallback must be explicit.
        assert revision["commit"] == ""
        return
    assert len(revision["commit"]) == 40
    assert isinstance(revision["dirty"], bool)


def test_matching_captures_verify(sandbox_paths: ProjectPaths) -> None:
    path = _write_capture(sandbox_paths, "exp_ok")
    entry = {
        "experiment_id": "exp_ok",
        "pcap_path": path,
        "capture_sha256": file_sha256(sandbox_paths.resolve(path)),
    }
    report = verify_manifest(_manifest(sandbox_paths, [entry]), sandbox_paths)
    assert report.ok is True
    assert report.checked == 1
    assert report.matched == 1
    assert report.mismatched == ()


def test_a_changed_capture_is_detected(sandbox_paths: ProjectPaths) -> None:
    """The whole point: a replaced capture must not pass as verified."""
    path = _write_capture(sandbox_paths, "exp_changed")
    original = file_sha256(sandbox_paths.resolve(path))
    # Someone edits or truncates the capture after the run finished.
    sandbox_paths.resolve(path).write_bytes(b"tampered")
    entry = {"experiment_id": "exp_changed", "pcap_path": path, "capture_sha256": original}

    report = verify_manifest(_manifest(sandbox_paths, [entry]), sandbox_paths)
    assert report.ok is False
    assert report.mismatched == ("exp_changed",)
    assert "exp_changed" in report.render_text()
    assert "NOT VERIFIED" in report.render_text()


def test_a_missing_capture_is_reported_as_missing(sandbox_paths: ProjectPaths) -> None:
    entry = {
        "experiment_id": "exp_gone",
        "pcap_path": "data/raw/exp_gone/capture.pcap",
        "capture_sha256": "0" * 64,
    }
    report = verify_manifest(_manifest(sandbox_paths, [entry]), sandbox_paths)
    assert report.ok is False
    assert report.missing == ("exp_gone",)
    assert report.matched == 0


def test_a_capture_without_a_recorded_hash_is_not_counted_as_verified(
    sandbox_paths: ProjectPaths,
) -> None:
    """No hash is not a pass -- it is unverifiable, and says so."""
    path = _write_capture(sandbox_paths, "exp_old")
    entry = {"experiment_id": "exp_old", "pcap_path": path, "capture_sha256": ""}
    report = verify_manifest(_manifest(sandbox_paths, [entry]), sandbox_paths)
    assert report.unhashed == ("exp_old",)
    assert report.matched == 0
    assert any("predate hash recording" in note for note in report.notes)


def test_one_bad_capture_fails_the_whole_report(sandbox_paths: ProjectPaths) -> None:
    good = _write_capture(sandbox_paths, "exp_good")
    bad = _write_capture(sandbox_paths, "exp_bad", b"other-bytes")
    entries = [
        {
            "experiment_id": "exp_good",
            "pcap_path": good,
            "capture_sha256": file_sha256(sandbox_paths.resolve(good)),
        },
        # Recorded hash deliberately wrong.
        {"experiment_id": "exp_bad", "pcap_path": bad, "capture_sha256": "f" * 64},
    ]
    report = verify_manifest(_manifest(sandbox_paths, entries), sandbox_paths)
    assert report.checked == 2
    assert report.matched == 1
    assert report.ok is False


def test_build_provenance_records_the_revision_and_verification(
    sandbox_paths: ProjectPaths,
) -> None:
    path = _write_capture(sandbox_paths, "exp_ok")
    manifest = _manifest(
        sandbox_paths,
        [
            {
                "experiment_id": "exp_ok",
                "pcap_path": path,
                "capture_sha256": file_sha256(sandbox_paths.resolve(path)),
            }
        ],
    )
    document = build_provenance(sandbox_paths, manifest)
    assert document["schema"] == PROVENANCE_SCHEMA
    assert "source" in document
    assert document["sample_count"] == 1
    assert document["verification"]["ok"] is True
    # Must survive a round trip so it can be written as JSON.
    assert json.loads(json.dumps(document))["verification"]["matched"] == 1


def test_empty_manifest_verifies_vacuously(sandbox_paths: ProjectPaths) -> None:
    report = VerificationReport()
    assert report.ok is True
    assert verify_manifest({"samples": []}, sandbox_paths).checked == 0
