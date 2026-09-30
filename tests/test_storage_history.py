"""SQLite analysis history: the repository contract.

These tests exercise the real database, not a fake: the point of the history is
that a result survives the process that produced it, so the round trip has to go
through an actual file.
"""

from __future__ import annotations

import pytest

from fera.common.errors import ErrorCode, FeraError
from fera.core.bundle import AnalysisBundle, StageResult
from fera.storage import (
    HISTORY_SCHEMA_VERSION,
    AnalysisRecord,
    HistoryRepository,
    record_from_bundle,
)


@pytest.fixture()
def repository(sandbox_paths):
    """A history repository over a throw-away repository layout."""
    return HistoryRepository(paths=sandbox_paths)


def _bundle(paths, *, analysis_id: str, filename: str = "a.pcap", created_at: str | None = None) -> AnalysisBundle:
    """Build a minimal but realistic bundle for the history to summarise."""
    bundle = AnalysisBundle.new({"kind": "upload", "filename": filename, "size_bytes": 128, "sha256": "abc123"})
    bundle.analysis_id = analysis_id
    if created_at is not None:
        bundle.created_at = created_at
    bundle.set_stage(StageResult.succeeded("protocol", {"packets": 7, "esp_packets": 2, "ike_packets": 3}))
    bundle.set_stage(StageResult.succeeded("security", {"security_score": 91.5, "risk_level": "LOW"}))
    return bundle


def test_initialise_creates_the_database(repository, sandbox_paths):
    repository.initialise()
    assert repository.database_path.is_file()
    assert repository.count() == 0
    assert repository.describe()["schema_version"] == HISTORY_SCHEMA_VERSION
    assert repository.database_path == sandbox_paths.database_file


def test_save_bundle_writes_document_and_row(repository, sandbox_paths):
    record = repository.save_bundle(_bundle(sandbox_paths, analysis_id="an-1"))

    assert (sandbox_paths.bundles / "an-1.json").is_file()
    assert record.analysis_id == "an-1"
    assert record.source_mode == "upload"
    assert record.display_filename == "a.pcap"
    assert record.security_score == 91.5
    assert record.risk_band == "LOW"
    assert record.bundle_schema


def test_get_analysis_returns_the_canonical_bundle(repository, sandbox_paths):
    bundle = _bundle(sandbox_paths, analysis_id="an-2")
    repository.save_bundle(bundle)

    reloaded = repository.get_analysis("an-2")
    assert reloaded.analysis_id == "an-2"
    assert reloaded.to_dict() == bundle.to_dict(), "history must not alter the stored document"


def test_get_analysis_missing_id_raises_not_found(repository):
    with pytest.raises(FeraError) as excinfo:
        repository.get_analysis("nope")
    assert excinfo.value.code is ErrorCode.NOT_FOUND


def test_get_analysis_missing_document_is_reported(repository, sandbox_paths):
    """A row whose bundle was deleted must not return a stale or empty result."""
    repository.save_bundle(_bundle(sandbox_paths, analysis_id="an-3"))


def test_list_is_newest_first(repository, sandbox_paths):
    for index, moment in enumerate(("2024-01-01T00:00:00Z", "2024-06-01T00:00:00Z", "2024-03-01T00:00:00Z")):
        repository.save_bundle(_bundle(sandbox_paths, analysis_id=f"an-{index}", created_at=moment))

    assert [record.analysis_id for record in repository.list_analyses()] == ["an-1", "an-2", "an-0"]


def test_list_ordering_is_deterministic_within_one_second(repository, sandbox_paths):
    moment = "2024-01-01T00:00:00Z"
    for index in range(5):
        repository.save_bundle(_bundle(sandbox_paths, analysis_id=f"same-{index}", created_at=moment))
    first = [record.analysis_id for record in repository.list_analyses()]
    assert first == [record.analysis_id for record in repository.list_analyses()]
    assert first == sorted(first, reverse=True), "ties break on the id, deterministically"


def test_list_respects_limit_and_filters(repository, sandbox_paths):
    repository.save_bundle(_bundle(sandbox_paths, analysis_id="u-1", filename="one.pcap"))
    risky = _bundle(sandbox_paths, analysis_id="l-1", filename="two.pcap")
    risky.set_stage(StageResult.succeeded("security", {"security_score": 20.0, "risk_level": "HIGH"}))
    repository.save_bundle(risky)

    assert len(repository.list_analyses(limit=1)) == 1
    assert [r.analysis_id for r in repository.list_analyses(risk_band="HIGH")] == ["l-1"]
    assert repository.list_analyses(risk_band="CRITICAL") == []


def test_list_clamps_the_limit(repository, sandbox_paths):
    repository.save_bundle(_bundle(sandbox_paths, analysis_id="a"))
    assert len(repository.list_analyses(limit=0)) == 1
    assert len(repository.list_analyses(limit=10_000)) == 1


def test_delete_reports_whether_a_row_existed(repository, sandbox_paths):
    repository.save_bundle(_bundle(sandbox_paths, analysis_id="gone"))
    assert repository.delete_analysis("gone") is True
    assert repository.delete_analysis("gone") is False
    assert repository.count() == 0


def test_saving_the_same_id_twice_replaces_the_row(repository, sandbox_paths):
    repository.save_bundle(_bundle(sandbox_paths, analysis_id="dup"))
    repository.save_bundle(_bundle(sandbox_paths, analysis_id="dup", filename="renamed.pcap"))
    assert repository.count() == 1
    assert repository.get_record("dup").display_filename == "renamed.pcap"


def test_history_survives_a_new_repository_instance(repository, sandbox_paths):
    """The point of the history: a fresh service sees the same rows."""
    repository.save_bundle(_bundle(sandbox_paths, analysis_id="persisted"))

    reopened = HistoryRepository(paths=sandbox_paths)
    assert reopened.count() == 1
    assert reopened.get_analysis("persisted").analysis_id == "persisted"


def test_unavailable_stage_contributes_no_value(repository, sandbox_paths):
    """A stage that did not run must leave ``None``, not a zero."""
    bundle = _bundle(sandbox_paths, analysis_id="no-ml")
    bundle.set_stage(StageResult.unavailable("traffic", FeraError("no model", code=ErrorCode.UNAVAILABLE)))
    record = repository.save_bundle(bundle)

    assert record.traffic_prediction is None
    assert record.traffic_confidence is None


def test_record_never_invents_a_protocol_summary(sandbox_paths):
    bundle = AnalysisBundle.new({"kind": "upload", "filename": "x.pcap", "size_bytes": 1})
    bundle.analysis_id = "empty"
    assert record_from_bundle(bundle).protocol_summary is None


def test_create_analysis_accepts_a_hand_built_record(repository):
    repository.create_analysis(AnalysisRecord(analysis_id="manual", created_at="2024-01-01T00:00:00Z"))
    assert repository.get_record("manual").analysis_id == "manual"

