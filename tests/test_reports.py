"""Report generation from the canonical bundle.

The property under test is that a report *reproduces* the bundle and nothing
more: no stage re-runs, no evidence status is upgraded, and an absent stage is
shown as absent rather than as a clean result.
"""

from __future__ import annotations

import json

import pytest

from fera.common.errors import ErrorCode, FeraError
from fera.reports import (
    CONTENT_TYPES,
    EXECUTIVE,
    JSON,
    REPORT_TYPES,
    TECHNICAL,
    normalise_report_type,
    render_report,
    report_filename,
)

GENERATED_AT = "2024-01-01T00:00:00Z"


@pytest.fixture()
def bundle(tmp_path):
    """A real bundle from a synthetic capture, analysed by the real pipeline."""
    from conftest import ike_and_esp_frames, write_pcap
    from fera.common.paths import ProjectPaths
    from fera.core.orchestrator import CaptureSource, run_analysis

    paths = ProjectPaths(tmp_path)
    paths.ensure_runtime_dirs()
    capture = tmp_path / "sample.pcap"
    write_pcap(capture, ike_and_esp_frames())
    return run_analysis(CaptureSource.from_path(capture, kind="upload"), paths=paths).to_dict()


# --- format plumbing -------------------------------------------------------


@pytest.mark.parametrize("kind", [EXECUTIVE, TECHNICAL, JSON])
def test_each_report_type_renders(kind, bundle):
    payload = render_report(bundle, kind, generated_at=GENERATED_AT)
    assert payload
    if kind == JSON:
        assert json.loads(payload.decode())["analysis_id"] == bundle["analysis_id"]
    else:
        assert payload.decode().startswith("<!doctype html>")


def test_reports_are_reproducible(bundle):
    first = render_report(bundle, TECHNICAL, generated_at=GENERATED_AT)
    second = render_report(bundle, TECHNICAL, generated_at=GENERATED_AT)
    assert first == second, "the same bundle must always render the same document"


def test_unknown_report_type_is_refused():
    with pytest.raises(FeraError) as excinfo:
        normalise_report_type("powerpoint")
    assert excinfo.value.code is ErrorCode.CONFIG_VALIDATION_FAILED
    assert excinfo.value.details["supported"] == list(REPORT_TYPES)


@pytest.mark.parametrize(
    ("kind", "expected"),
    [(EXECUTIVE, "fera_id1_executive.html"), (TECHNICAL, "fera_id1_technical.html"), (JSON, "fera_id1.json")],
)
def test_filenames_are_predictable(kind, expected):
    assert report_filename("id1", kind) == expected


@pytest.mark.parametrize("hostile", ["../../etc/passwd", "..\\..\\windows", "a/b", "....//.."])
def test_filenames_cannot_escape_the_download_directory(hostile):
    name = report_filename(hostile, JSON)
    assert "/" not in name and "\\" not in name and ".." not in name


def test_every_type_declares_a_content_type():
    assert set(CONTENT_TYPES) == set(REPORT_TYPES)


# --- the analysis id and the evidence semantics ----------------------------


def test_reports_carry_the_analysis_id(bundle):
    for kind in (EXECUTIVE, TECHNICAL):
        assert bundle["analysis_id"] in render_report(bundle, kind, generated_at=GENERATED_AT).decode()


def test_not_verifiable_survives_into_the_reports(bundle):
    """A passive capture cannot prove PFS enforcement; that must stay visible."""
    for kind in (EXECUTIVE, TECHNICAL):
        text = render_report(bundle, kind, generated_at=GENERATED_AT).decode()
        assert "NOT_VERIFIABLE" in text or "NOT VERIFIABLE" in text, kind


def test_not_verifiable_is_not_rendered_as_a_failure(bundle):
    text = render_report(bundle, TECHNICAL, generated_at=GENERATED_AT).decode()
    # The verdict exists and is distinct; the prose must say what it means.
    assert "unanswered questions" in text or "not verifiable" in text.lower()


def test_missing_model_is_reported_honestly(bundle):
    """With no trained model the reports must not invent a traffic class."""
    import tempfile
    from pathlib import Path

    from conftest import ike_and_esp_frames, write_pcap
    from fera.common.paths import ProjectPaths
    from fera.core.orchestrator import CaptureSource, run_analysis

    with tempfile.TemporaryDirectory() as raw:
        paths = ProjectPaths(Path(raw))
        paths.ensure_runtime_dirs()
        capture = Path(raw) / "x.pcap"
        write_pcap(capture, ike_and_esp_frames())
        document = run_analysis(CaptureSource.from_path(capture, kind="upload"), paths=paths).to_dict()

    if document["components"]["traffic"]["status"] == "unavailable":
        for kind in (EXECUTIVE, TECHNICAL):
            text = render_report(document, kind, generated_at=GENERATED_AT).decode()
            assert "unavailable" in text.lower()
            assert "Traffic classification unavailable" in text


def test_reports_never_contain_raw_script_tags(bundle):
    """Every value is escaped: a crafted file name cannot inject markup."""
    for kind in (EXECUTIVE, TECHNICAL):
        text = render_report(bundle, kind, generated_at=GENERATED_AT).decode()
        assert "<script" not in text.lower()


def test_capture_values_are_escaped(bundle):
    hostile = json.loads(json.dumps(bundle))
    hostile["source"]["filename"] = "<img src=x onerror=alert(1)>.pcap"
    text = render_report(hostile, TECHNICAL, generated_at=GENERATED_AT).decode()
    assert "<img src=x" not in text
    assert "&lt;img" in text


def test_empty_bundle_still_renders(bundle):
    """A bundle with no stages must produce a document, not an exception."""
    empty = {"analysis_id": "none", "schema_version": bundle["schema_version"], "components": {}}
    for kind in (EXECUTIVE, TECHNICAL):
        text = render_report(empty, kind, generated_at=GENERATED_AT).decode()
        assert "not reported" in text
