"""SQLite-backed history of past analyses.

The history exists so a decision maker can reopen a result without re-running
the pipeline, and so the dashboard has something to list.  It is deliberately
*not* a second source of truth:

* the full canonical bundle stays authoritative and is stored as JSON on disk
  (``data/bundles/<id>.json``); this table keeps only a handful of summary
  columns for listing and filtering;
* :meth:`HistoryRepository.get_analysis` re-reads the bundle file, so a row can
  never disagree with the document the stages actually produced;
* no PCAP bytes and no capture blobs are stored here - the capture stays on
  disk where the operator put it, and only its hash and display name are kept.

Ordering is deterministic (``created_at DESC, analysis_id DESC``) so that two
analyses created inside the same second still list in a stable order.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..common.errors import ErrorCode, FeraError
from ..common.paths import ProjectPaths, default_paths
from ..common.serialization import load_json, write_json
from ..core.bundle import AnalysisBundle

#: Schema identifier of the history database.
HISTORY_SCHEMA_VERSION = "fera_history_v1"

#: Columns of the ``analyses`` table, in insert order.
_COLUMNS: tuple[str, ...] = (
    "analysis_id",
    "created_at",
    "source_mode",
    "display_filename",
    "capture_size",
    "capture_hash",
    "bundle_schema",
    "bundle_path",
    "protocol_summary",
    "traffic_prediction",
    "traffic_confidence",
    "security_score",
    "risk_band",
    "privacy_band",
    "analysis_state",
)

#: Every filterable field a caller may narrow a listing by.
FILTER_FIELDS: tuple[str, ...] = (
    "source_mode",
    "risk_band",
    "traffic_prediction",
    "analysis_state",
)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id         TEXT PRIMARY KEY,
    created_at          TEXT NOT NULL,
    source_mode         TEXT,
    display_filename    TEXT,
    capture_size        INTEGER,
    capture_hash        TEXT,
    bundle_schema       TEXT,
    bundle_path         TEXT,
    protocol_summary    TEXT,
    traffic_prediction  TEXT,
    traffic_confidence  REAL,
    security_score      REAL,
    risk_band           TEXT,
    privacy_band        TEXT,
    analysis_state      TEXT
)
"""

_CREATE_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses (created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_analyses_risk ON analyses (risk_band)",
    "CREATE INDEX IF NOT EXISTS idx_analyses_source ON analyses (source_mode)",
    "CREATE INDEX IF NOT EXISTS idx_analyses_traffic ON analyses (traffic_prediction)",
)

_CREATE_META = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
"""



@dataclass(frozen=True)
class AnalysisRecord:
    """One row of the history table."""

    analysis_id: str
    created_at: str
    source_mode: str | None = None
    display_filename: str | None = None
    capture_size: int | None = None
    capture_hash: str | None = None
    bundle_schema: str | None = None
    bundle_path: str | None = None
    protocol_summary: str | None = None
    traffic_prediction: str | None = None
    traffic_confidence: float | None = None
    security_score: float | None = None
    risk_band: str | None = None
    privacy_band: str | None = None
    analysis_state: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in _COLUMNS}


def _protocol_summary(bundle: AnalysisBundle) -> str | None:
    """One short human readable line describing what was found on the wire.

    Built from the bundle only; the history never re-derives a protocol fact.
    """
    protocol = bundle.protocol
    if not isinstance(protocol, Mapping):
        return None
    parts: list[str] = []
    if protocol.get("ipsec_detected"):
        parts.append("IPsec")
    ike_version = protocol.get("ike_version")
    if ike_version:
        parts.append(f"IKEv{ike_version}" if str(ike_version).isdigit() else str(ike_version))
    if protocol.get("esp_packets"):
        parts.append(f"{protocol['esp_packets']} ESP")
    if protocol.get("esp_flows"):
        parts.append(f"{len(protocol['esp_flows'])} flow(s)")
    return ", ".join(parts) if parts else None


def record_from_bundle(bundle: AnalysisBundle, *, bundle_path: Path | str | None = None) -> AnalysisRecord:
    """Derive one history row from a canonical bundle.

    Every field is read straight out of the bundle, so the row can never claim
    something the analysis did not produce.  A stage that was unavailable
    contributes ``None`` rather than a placeholder.
    """
    summary = bundle.summary()
    source = dict(bundle.source)
    traffic = summary.get("traffic") or {}
    security = summary.get("security") or {}
    privacy = summary.get("privacy") or {}
    return AnalysisRecord(
        analysis_id=bundle.analysis_id,
        created_at=bundle.created_at,
        source_mode=str(source.get("kind") or ""),
        display_filename=str(source.get("filename") or ""),
        capture_size=int(source.get("size_bytes") or 0),
        capture_hash=str(source.get("sha256") or "") or None,
        bundle_schema=bundle.schema_version,
        bundle_path=str(bundle_path) if bundle_path is not None else None,
        protocol_summary=_protocol_summary(bundle),
        traffic_prediction=str(traffic.get("predicted_class")) if traffic.get("predicted_class") else None,
        traffic_confidence=float(traffic["confidence"]) if traffic.get("confidence") is not None else None,
        security_score=float(security["security_score"]) if security.get("security_score") is not None else None,
        risk_band=str(security.get("risk_level")) if security.get("risk_level") else None,
        privacy_band=str(privacy.get("privacy_risk")) if privacy.get("privacy_risk") is not None else None,
        analysis_state=bundle.status,
    )




class HistoryRepository:
    """Create, read, list and delete rows of the analysis history.

    The database is initialised on first use, so a caller never has to run a
    migration step: opening the repository on a fresh checkout produces a
    usable (empty) history.  Every value is bound as a SQL parameter; the only
    identifiers ever interpolated are column names taken from the frozen
    :data:`FILTER_FIELDS` tuple after a membership check.
    """

    def __init__(self, database: Path | str | None = None, *, paths: ProjectPaths | None = None) -> None:
        resolved_paths = paths if paths is not None else default_paths()
        self._paths = resolved_paths
        self._database = Path(database) if database is not None else resolved_paths.database_file
        self._initialised = False

    # -- lifecycle --------------------------------------------------------
    @property
    def database_path(self) -> Path:
        """Location of the SQLite file backing this repository."""
        return self._database

    @property
    def bundles_dir(self) -> Path:
        """Directory the canonical bundle documents are written to."""
        return self._paths.bundles

    def initialise(self) -> None:
        """Create the schema if it is missing (idempotent)."""
        self._database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(_CREATE_TABLE)
            connection.execute(_CREATE_META)
            for statement in _CREATE_INDEXES:
                connection.execute(statement)
            connection.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                ("schema_version", HISTORY_SCHEMA_VERSION),
            )
        self._initialised = True

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open a connection with row access by name, committing on success."""
        connection = sqlite3.connect(self._database)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _ensure_ready(self) -> None:
        if not self._initialised:
            self.initialise()

    # -- writes -----------------------------------------------------------
    def save_bundle(self, bundle: AnalysisBundle, *, bundle_path: Path | str | None = None) -> AnalysisRecord:
        """Persist the bundle document and its history row in one step.

        The bundle JSON is written first: if that write fails we never advertise
        a history row pointing at a document that does not exist.
        """
        self._ensure_ready()
        target = Path(bundle_path) if bundle_path is not None else self._paths.bundles / f"{bundle.analysis_id}.json"
        write_json(target, bundle.to_dict())
        record = record_from_bundle(bundle, bundle_path=target)
        self._insert(record)
        return record

    def _insert(self, record: AnalysisRecord) -> None:
        placeholders = ", ".join("?" for _ in _COLUMNS)
        columns = ", ".join(_COLUMNS)
        values = [getattr(record, name) for name in _COLUMNS]
        with self._connect() as connection:
            connection.execute(f"INSERT OR REPLACE INTO analyses ({columns}) VALUES ({placeholders})", values)

    def create_analysis(self, record: AnalysisRecord) -> AnalysisRecord:
        """Insert a record built by hand (used by tests and by importers)."""
        self._ensure_ready()
        self._insert(record)
        return record

    def delete_analysis(self, analysis_id: str) -> bool:
        """Delete one row.  Returns ``False`` when the id was unknown."""
        self._ensure_ready()
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM analyses WHERE analysis_id = ?", (str(analysis_id),))
            return cursor.rowcount > 0

    # -- reads ------------------------------------------------------------
    def get_record(self, analysis_id: str) -> AnalysisRecord | None:
        """Return the history row for ``analysis_id`` (``None`` when absent)."""
        self._ensure_ready()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM analyses WHERE analysis_id = ?",
                (str(analysis_id),),
            ).fetchone()
        return _row_to_record(row) if row is not None else None

    def get_analysis(self, analysis_id: str) -> AnalysisBundle:
        """Return the canonical bundle for ``analysis_id``.

        Raises :class:`~fera.common.errors.FeraError` with ``NOT_FOUND`` when
        either the row or the stored document is missing, so the API can answer
        404 without inspecting two places.
        """
        record = self.get_record(analysis_id)
        if record is None:
            raise FeraError(
                f"no analysis stored for id {analysis_id}",
                code=ErrorCode.NOT_FOUND,
                hint="run an analysis first, or check the id returned by an earlier request",
                details={"analysis_id": str(analysis_id)},
            )
        path = Path(record.bundle_path) if record.bundle_path else self._paths.bundles / f"{record.analysis_id}.json"
        if not path.is_file():
            raise FeraError(
                f"the stored bundle for {analysis_id} is missing from disk",
                code=ErrorCode.NOT_FOUND,
                hint="the history row points at a bundle that was deleted; re-run the analysis",
                details={"analysis_id": str(analysis_id), "expected_path": str(path)},
            )
        return AnalysisBundle.from_dict(load_json(path))

    def list_analyses(
        self,
        *,
        limit: int = 50,
        source_mode: str | None = None,
        risk_band: str | None = None,
        traffic_class: str | None = None,
        analysis_state: str | None = None,
    ) -> list[AnalysisRecord]:
        """List stored analyses, newest first.

        ``limit`` is clamped to ``1..500`` so a caller cannot ask the database
        for an unbounded result set.
        """
        self._ensure_ready()
        bounded = max(1, min(int(limit), 500))
        clauses: list[str] = []
        values: list[Any] = []
        for column, value in (
            ("source_mode", source_mode),
            ("risk_band", risk_band),
            ("traffic_prediction", traffic_class),
            ("analysis_state", analysis_state),
        ):
            if value is not None:
                if column not in FILTER_FIELDS:  # pragma: no cover - defensive
                    raise FeraError(
                        f"unknown history filter {column}",
                        code=ErrorCode.CONFIG_VALIDATION_FAILED,
                        details={"allowed": list(FILTER_FIELDS)},
                    )
                clauses.append(f"{column} = ?")
                values.append(str(value))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(bounded)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM analyses{where} ORDER BY created_at DESC, analysis_id DESC LIMIT ?",
                values,
            ).fetchall()
        return [_row_to_record(row) for row in rows]

    def count(self) -> int:
        """Total number of stored analyses."""
        self._ensure_ready()
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS total FROM analyses").fetchone()
        return int(row["total"]) if row is not None else 0

    def describe(self) -> dict[str, Any]:
        """Schema version and row count (surfaced by ``GET /capabilities``)."""
        self._ensure_ready()
        with self._connect() as connection:
            row = connection.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        return {
            "schema_version": str(row["value"]) if row is not None else HISTORY_SCHEMA_VERSION,
            "analyses": self.count(),
        }


def _row_to_record(row: sqlite3.Row) -> AnalysisRecord:
    """Convert a result row into an :class:`AnalysisRecord`."""
    return AnalysisRecord(**{name: row[name] for name in _COLUMNS})  # type: ignore[arg-type]


__all__ = [
    "FILTER_FIELDS",
    "HISTORY_SCHEMA_VERSION",
    "AnalysisRecord",
    "HistoryRepository",
    "record_from_bundle",
]

