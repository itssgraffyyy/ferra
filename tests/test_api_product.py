"""The product HTTP surface, exercised end to end over a real capture.

Every test here runs the actual orchestrator against a synthetic PCAP and then
checks what the API returns, so a passing test means the whole path - capture,
analysis, persistence, retrieval, report - worked.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from fera.api.main import ApiConfig, create_app


@pytest.fixture()
def capture_bytes():
    """Bytes of a synthetic PCAP containing IKE and ESP frames."""
    import tempfile
    from pathlib import Path

    from conftest import ike_and_esp_frames, write_pcap

    with tempfile.TemporaryDirectory() as raw:
        target = Path(raw) / "sample.pcap"
        write_pcap(target, ike_and_esp_frames())
        return target.read_bytes()


@pytest.fixture()
def client(sandbox_paths, capture_bytes):
    """A test client whose storage is a throw-away directory."""
    app = create_app(ApiConfig(paths=sandbox_paths, max_upload_bytes=4 * 1024 * 1024))
    with TestClient(app) as instance:
        yield instance


def _upload(client, data, name="sample.pcap"):
    return client.post("/analyze", files={"file": (name, data, "application/vnd.tcpdump.pcap")})


# --- health, version, capabilities -----------------------------------------


def test_health_reports_the_process_not_its_dependencies(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert "max_upload_bytes" in body["limits"]


def test_version_lists_the_schemas(client):
    body = client.get("/version").json()
    assert body["bundle_schema"]
    assert body["security_schema"]
    assert body["history_schema"]


def test_capabilities_are_measured_not_assumed(client):
    body = client.get("/capabilities").json()["capabilities"]
    assert set(body) >= {
        "protocol_analysis",
        "tshark",
        "ml_model",
        "security_assessment",
        "privacy_analysis",
        "live_capture",
        "report_generation",
        "history",
    }
    for name, entry in body.items():
        assert entry["status"] in {"available", "unavailable"}, name
        if entry["status"] == "unavailable":
            assert entry.get("reason"), f"{name} is unavailable and must say why"


def test_model_status_does_not_leak_filesystem_paths(client):
    body = client.get("/models/status").json()
    assert "available" in body
    assert "path" not in body and "directory" not in body


# --- analysis --------------------------------------------------------------


def test_analyze_returns_a_bundle(client, capture_bytes):
    response = _upload(client, capture_bytes)
    assert response.status_code == 200
    body = response.json()
    assert body["analysis_id"]
    assert body["schema_version"]
    assert set(body["components"]) == {"protocol", "traffic", "security", "privacy"}


def test_analyze_stores_the_result(client, capture_bytes):
    analysis_id = _upload(client, capture_bytes).json()["analysis_id"]
    assert client.get(f"/analyses/{analysis_id}").status_code == 200
    assert analysis_id in [row["analysis_id"] for row in client.get("/analyses").json()["analyses"]]


def test_partial_status_when_a_stage_is_unavailable(client, capture_bytes):
    """No trained model here, so the run is partial - and must say so."""
    body = _upload(client, capture_bytes).json()
    if body["components"]["traffic"]["status"] == "unavailable":
        assert body["status"] == "partial"
        assert body["components"]["traffic"]["error"]["code"] == "UNAVAILABLE"


# --- upload hardening ------------------------------------------------------


def test_traversal_filename_cannot_escape_the_upload_directory(client, sandbox_paths, capture_bytes):
    response = _upload(client, capture_bytes, name="../../../evil.pcap")
    assert response.status_code == 200
    for stored in sandbox_paths.uploads.iterdir():
        assert stored.parent == sandbox_paths.uploads
        assert ".." not in stored.name


def test_empty_upload_is_rejected(client):
    response = _upload(client, b"")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "CAPTURE_EMPTY"


def test_oversized_upload_is_rejected(client):
    response = _upload(client, b"\xd4\xc3\xb2\xa1" + b"\x00" * (5 * 1024 * 1024))
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_non_pcap_content_is_rejected(client):
    response = _upload(client, b"this is definitely not a capture" * 10, name="notes.txt")
    assert response.status_code == 415
    assert response.json()["error"]["code"] == "UNSUPPORTED_CONTENT"


def test_corrupt_capture_fails_cleanly(client):
    """Truncated PCAP data must not surface a stack trace to the caller."""
    response = _upload(client, b"\xd4\xc3\xb2\xa1" + b"\xff" * 40)
    assert response.status_code in {200, 422}
    if response.status_code != 200:
        assert "Traceback" not in response.json()["error"]["message"]


def test_failed_upload_is_not_left_on_disk(client, sandbox_paths):
    _upload(client, b"not a pcap at all", name="bad.pcap")
    assert not list(sandbox_paths.uploads.glob("*.pcap"))


# --- history ---------------------------------------------------------------


def test_history_lists_then_reopens(client, capture_bytes):
    analysis_id = _upload(client, capture_bytes).json()["analysis_id"]
    listing = client.get("/analyses").json()
    assert listing["count"] == 1
    row = listing["analyses"][0]
    assert row["analysis_id"] == analysis_id
    # the stored name is prefixed to avoid collisions, but it keeps the original
    assert row["display_filename"].endswith("sample.pcap")
    assert ".." not in row["display_filename"]
    assert client.get(f"/analyses/{analysis_id}").json()["analysis_id"] == analysis_id


def test_history_survives_a_new_application(client, sandbox_paths, capture_bytes):
    """A restarted service reads the same database, not a fresh one."""
    analysis_id = _upload(client, capture_bytes).json()["analysis_id"]

    restarted = TestClient(create_app(ApiConfig(paths=sandbox_paths)))
    assert restarted.get(f"/analyses/{analysis_id}").status_code == 200
    assert restarted.get("/analyses").json()["count"] == 1
    assert restarted.get("/capabilities").json()["capabilities"]["history"]["status"] == "available"


# --- export and reports ----------------------------------------------------


def test_export_returns_the_canonical_bundle(client, capture_bytes):
    analysis_id = _upload(client, capture_bytes).json()["analysis_id"]
    response = client.get(f"/analyses/{analysis_id}/export")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert analysis_id in response.headers["content-disposition"]
    assert json.loads(response.text)["analysis_id"] == analysis_id


@pytest.mark.parametrize(
    ("kind", "prefix"),
    [("executive", "text/html"), ("technical", "text/html"), ("json", "application/json")],
)
def test_each_report_type_is_served(client, capture_bytes, kind, prefix):
    analysis_id = _upload(client, capture_bytes).json()["analysis_id"]
    response = client.get(f"/analyses/{analysis_id}/report", params={"type": kind})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(prefix)
    assert response.content


def test_report_preserves_not_verifiable_semantics(client, capture_bytes):
    analysis_id = _upload(client, capture_bytes).json()["analysis_id"]
    text = client.get(f"/analyses/{analysis_id}/report", params={"type": "technical"}).text
    assert "NOT_VERIFIABLE" in text or "NOT VERIFIABLE" in text


def test_report_of_a_missing_analysis_is_404(client):
    assert client.get("/analyses/nope/report", params={"type": "executive"}).status_code == 404


def test_unknown_report_type_is_422(client, capture_bytes):
    analysis_id = _upload(client, capture_bytes).json()["analysis_id"]
    response = client.get(f"/analyses/{analysis_id}/report", params={"type": "powerpoint"})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "CONFIG_VALIDATION_FAILED"


# --- live capture ----------------------------------------------------------


def test_live_capture_reports_an_environment_blocker_honestly(client):
    """No capture tool here: the endpoint must refuse, not fake a result."""
    response = client.post("/live/analyze", json={"interface": "eth0", "duration_s": 5})
    if response.status_code == 200:
        pytest.skip("a real capture tool is installed in this environment")
    assert response.status_code == 503
    assert response.json()["error"]["code"] in {"TOOL_NOT_AVAILABLE", "INSUFFICIENT_PRIVILEGES"}


def test_live_capture_rejects_an_out_of_range_duration(client):
    assert client.post("/live/analyze", json={"interface": "eth0", "duration_s": 9999}).status_code == 422


def test_live_capture_rejects_a_hostile_interface(client):
    assert client.post("/live/analyze", json={"interface": "eth0; rm -rf /"}).status_code in {422, 503}

def test_history_is_newest_first(client, capture_bytes):
    for _ in range(3):
        _upload(client, capture_bytes)
    stamps = [row["created_at"] for row in client.get("/analyses").json()["analyses"]]
    assert stamps == sorted(stamps, reverse=True)


def test_missing_analysis_id_is_404(client):
    response = client.get("/analyses/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


def test_delete_removes_the_analysis(client, capture_bytes):
    analysis_id = _upload(client, capture_bytes).json()["analysis_id"]
    assert client.delete(f"/analyses/{analysis_id}").status_code == 200
    assert client.get(f"/analyses/{analysis_id}").status_code == 404
    assert client.delete(f"/analyses/{analysis_id}").status_code == 404

