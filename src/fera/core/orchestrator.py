"""Run every stage over one capture and assemble an :class:`AnalysisBundle`.

The pipeline is a *sequential* composition of the existing stages; nothing here
decodes packets, computes features, classifies traffic or scores findings.  What
this module owns is the part no single stage can own:

* **pre-flight validation** - reject missing, oversized or non-PCAP input with a
  specific :class:`~fera.common.errors.ErrorCode` before any stage runs, so the
  API can answer ``404`` / ``413`` / ``415`` instead of a stack trace;
* **graceful degradation** - each stage is wrapped on its own.  A missing
  classifier model makes ``traffic`` ``unavailable`` and costs coverage in the
  security score; it never discards the protocol or security results, and it
  never pretends to be a zero;
* **honest skipping** - a capture with no ESP traffic cannot be classified, so
  the traffic stage reports ``skipped`` with the reason instead of feeding the
  model an all-zero feature row;
* **provenance** - tool availability, model identity and schema versions travel
  with the bundle, because a number whose provenance is unknown is not evidence.

Stage dependency is one-directional and mirrors the order in
:data:`~fera.core.bundle.STAGE_ORDER`: protocol -> traffic -> security ->
privacy.  ``security`` consumes the traffic prediction *only* through the
contract in :mod:`fera.security.ml_contract`, so a model that emits an
unrecognised document is refused rather than trusted.
"""

from __future__ import annotations

import platform
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ..analysis import analyze_pcap, find_tshark
from ..capture.pcap_scan import PCAP_HEADER_BYTES
from ..common.errors import ErrorCode, FeraError
from ..common.paths import ProjectPaths, default_paths
from ..ml.features import extract_features
from ..ml.inference import load_best_model, model_status
from ..privacy import observe_privacy
from ..security import SECURITY_SCHEMA_VERSION, assess_security
from .bundle import (
    BUNDLE_SCHEMA_VERSION,
    AnalysisBundle,
    StageResult,
    describe_capture,
    utc_now,
)

SourceKind = Literal["upload", "path", "live", "archive"]

#: Capture extensions the product accepts.  PCAPNG is analysed with the built-in
#: scanner (which degrades to metadata-only features), classic PCAP fully.
ALLOWED_SUFFIXES: tuple[str, ...] = (".pcap", ".pcapng", ".cap")

#: Refuse larger uploads: a 2 GiB capture is a benchmark job, not an API request.
DEFAULT_MAX_BYTES = 256 * 1024 * 1024

_PCAPNG_MAGIC = 0x0A0D0D0A


def _magic(path: Path) -> int | None:
    """First four file bytes as a big-endian integer (format sniffing)."""
    try:
        with path.open("rb") as handle:
            header = handle.read(4)
    except OSError:
        return None
    if len(header) < 4:
        return None
    return int.from_bytes(header, "big")


def _is_pcap_magic(value: int | None) -> bool:
    if value is None:
        return False
    return value in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1, _PCAPNG_MAGIC)


@dataclass(frozen=True)
class CaptureSource:
    """Where one analysis started from, and how much of it we may trust."""

    kind: SourceKind
    path: Path
    captured_at: str | None = None
    max_bytes: int = DEFAULT_MAX_BYTES

    @classmethod
    def from_path(
        cls,
        path: Path | str,
        *,
        kind: SourceKind = "path",
        captured_at: str | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> CaptureSource:
        """Source for a capture already on disk (CLI, live capture, archive)."""
        return cls(kind=kind, path=Path(path), captured_at=captured_at, max_bytes=max_bytes)

    def validate(self) -> Path:
        """Check the capture exists, is a PCAP, and fits the size budget.

        Raises :class:`FeraError` with ``NOT_FOUND``, ``UNSUPPORTED_CONTENT`` or
        ``PAYLOAD_TOO_LARGE`` - the codes the HTTP layer maps onto ``404``,
        ``415`` and ``413``.
        """
        capture = self.path
        if not capture.is_file():
            raise FeraError(
                f"capture not found: {capture}",
                code=ErrorCode.NOT_FOUND,
                hint="upload a capture, or start a live capture before analysing it",
                details={"path": str(capture)},
            )
        size = capture.stat().st_size
        if size == 0:
            # An empty upload is a caller mistake, not an unsupported format;
            # saying "unsupported content" would point at the wrong fix.
            raise FeraError(
                f"{capture.name} is empty",
                code=ErrorCode.CAPTURE_EMPTY,
                hint="record with tcpdump/dumpcap or upload a capture saved by Wireshark",
                details={"path": str(capture), "size_bytes": 0},
            )
        if size < PCAP_HEADER_BYTES:
            raise FeraError(
                f"{capture.name} is too small to be a PCAP file ({size} bytes)",
                code=ErrorCode.UNSUPPORTED_CONTENT,
                hint="record with tcpdump/dumpcap or upload a file saved by Wireshark",
                details={"path": str(capture), "size_bytes": size},
            )
        if size > self.max_bytes:
            raise FeraError(
                f"{capture.name} is {size} bytes, above the {self.max_bytes} byte limit",
                code=ErrorCode.PAYLOAD_TOO_LARGE,
                hint="trim the capture (BPF filter or ring buffer) and retry",
                details={"path": str(capture), "size_bytes": size, "limit_bytes": self.max_bytes},
            )
        if capture.suffix.lower() not in ALLOWED_SUFFIXES or not _is_pcap_magic(_magic(capture)):
            raise FeraError(
                f"{capture.name} is not a PCAP/PCAPNG capture",
                code=ErrorCode.UNSUPPORTED_CONTENT,
                hint=f"accepted extensions: {', '.join(ALLOWED_SUFFIXES)}",
                details={"path": str(capture), "suffix": capture.suffix},
            )
        return capture

    def describe(self) -> dict[str, Any]:
        """Serialised ``source`` block of the bundle."""
        return describe_capture(self.path, kind=self.kind, captured_at=self.captured_at)


#: Error codes that describe the environment rather than a pipeline defect.
UNAVAILABLE_CODES: frozenset[ErrorCode] = frozenset(
    {
        ErrorCode.UNAVAILABLE,
        ErrorCode.DEPENDENCY_MISSING,
        ErrorCode.TOOL_NOT_AVAILABLE,
        ErrorCode.CAPTURE_TOOL_NOT_AVAILABLE,
        ErrorCode.INSUFFICIENT_PRIVILEGES,
        ErrorCode.UNSUPPORTED_FEATURE,
    }
)


def _attempt(component: str, action: Callable[[], StageResult]) -> StageResult:
    """Run one stage, converting every escape into a :class:`StageResult`.

    The distinction that matters here is between *unavailable* (this machine
    cannot run the stage: no model, no tshark, no privileges) and *failed* (the
    stage broke).  Both are recorded, neither aborts the run.
    """
    started = time.perf_counter()
    try:
        result = action()
    except FeraError as exc:
        elapsed = round((time.perf_counter() - started) * 1000)
        if exc.code in UNAVAILABLE_CODES:
            return StageResult.unavailable(component, exc, duration_ms=elapsed)
        return StageResult.failed(component, exc, duration_ms=elapsed)
    except Exception as exc:  # noqa: BLE001 - one stage must never abort the run
        elapsed = round((time.perf_counter() - started) * 1000)
        return StageResult.failed(component, exc, duration_ms=elapsed)
    if not result.duration_ms:
        result = StageResult(
            result.component, result.status, data=result.data, error=result.error,
            duration_ms=round((time.perf_counter() - started) * 1000), limitations=result.limitations,
        )
    return result


@dataclass
class _Run:
    """Mutable state shared by the stages of a single pipeline execution."""

    bundle: AnalysisBundle
    capture: Path
    paths: ProjectPaths
    models_dir: Path
    configured: Mapping[str, Any] | None = None
    use_tshark: bool = False
    outcome: Any = None
    analysis: dict[str, Any] | None = None
    prediction: dict[str, Any] | None = None
    model: Any = None
    notes: list[str] = field(default_factory=list)

    def limitation(self, note: str) -> None:
        """Remember a cross-stage caveat for the provenance block."""
        if note not in self.notes:
            self.notes.append(note)


def build_provenance(paths: ProjectPaths, models_dir: Path, *, use_tshark: bool) -> dict[str, Any]:
    """Environment identity recorded with every bundle (answers "with what?")."""
    import fera

    return {
        "fera_version": getattr(fera, "__version__", "unknown"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "bundle_schema": BUNDLE_SCHEMA_VERSION,
        "security_schema": SECURITY_SCHEMA_VERSION,
        "capture_dir": str(paths.raw),
        "bundle_dir": str(paths.bundles),
        "tshark": find_tshark(),
        "tshark_requested": use_tshark,
        "models": model_status(models_dir),
        "started_at": utc_now(),
    }


def _stage_protocol(run: _Run) -> StageResult:
    """Prompt 2: deterministic protocol analysis of the capture."""
    outcome = analyze_pcap(run.capture, use_tshark=run.use_tshark)
    document = outcome.analysis.to_dict()
    run.outcome, run.analysis = outcome, document
    warnings = tuple(str(item) for item in outcome.warnings)
    packets = int(document.get("packets", 0) or 0)
    if packets == 0:
        return StageResult.degraded("protocol", document, reason="capture contains no decodable packets")
    return StageResult.succeeded("protocol", document, limitations=warnings)


def _esp_packets(document: Mapping[str, Any]) -> int:
    return int(document.get("esp_packets", 0) or 0)


def _stage_traffic(run: _Run) -> StageResult:
    """Prompt 3: statistical classification of the encrypted traffic."""
    if _esp_packets(run.analysis or {}) == 0:
        return StageResult.skipped(
            "traffic",
            reason="capture carries no ESP traffic, so the encrypted-traffic classifier does not apply",
        )
    status = model_status(run.models_dir)
    if not status["available"]:
        raise FeraError(
            f"traffic classifier unavailable: {status['reason']}",
            code=ErrorCode.UNAVAILABLE,
            hint="train a model with scripts/train_traffic_model.py, then restart the API",
            details={"searched": status["searched"], "artefacts": status["artefacts"]},
        )
    vector = extract_features(run.capture, outcome=run.outcome)
    model = load_best_model(run.models_dir)
    run.model = model
    prediction = model.predict(vector)
    run.prediction = prediction
    return StageResult.succeeded("traffic", prediction)


def _stage_security(run: _Run) -> StageResult:
    """Prompt 4: evidence-graded security assessment."""
    if run.analysis is None:  # pragma: no cover - protocol stage skipped first
        return StageResult.skipped("security", reason="protocol analysis produced nothing to assess")
    assessment = assess_security(
        run.analysis,
        configured=run.configured,
        traffic=run.prediction,
        analysis_id=run.bundle.analysis_id,
        inputs={"capture": run.bundle.source, "model": run.model.metadata if run.model is not None else None},
    )
    document = assessment.to_dict()
    limitations = tuple(str(item) for item in (document.get("limitations") or ()))
    if run.prediction is None:
        limitations += ("no ML prediction: inference-dependent rules reported NOT_VERIFIABLE",)
    return StageResult.succeeded("security", document, limitations=limitations)


def _stage_privacy(run: _Run) -> StageResult:
    """Metadata-exposure assessment of the same capture."""
    if run.analysis is None:  # pragma: no cover - protocol stage skipped first
        return StageResult.skipped("privacy", reason="protocol analysis produced nothing to observe")
    report = observe_privacy(run.capture, run.analysis, prediction=run.prediction)
    return StageResult.succeeded("privacy", report.to_dict(), limitations=report.limitations)


STAGES: tuple[tuple[str, Callable[[_Run], StageResult]], ...] = (
    ("protocol", _stage_protocol),
    ("traffic", _stage_traffic),
    ("security", _stage_security),
    ("privacy", _stage_privacy),
)


def run_analysis(
    source: CaptureSource | Path | str,
    *,
    paths: ProjectPaths | None = None,
    configured: Mapping[str, Any] | None = None,
    use_tshark: bool = False,
    models_dir: Path | str | None = None,
    analysis_id: str | None = None,
    persist: bool = True,
) -> AnalysisBundle:
    """Analyse one capture with every stage and return the assembled bundle.

    ``source`` accepts a :class:`CaptureSource`, or a path (treated as
    ``kind="path"``).  Validation problems (missing file, wrong format, oversize)
    raise: they are the caller's input error, not a stage failure.  Everything
    downstream of validation is captured per stage.

    ``configured`` is the optional testbed configuration the security stage grades
    as ``CONFIGURED`` evidence; ``use_tshark`` asks the analyser to prefer an
    external dissector when one is installed.  ``persist`` writes the bundle under
    ``data/bundles`` so a run is replayable after the capture is gone.
    """
    resolved_paths = paths if paths is not None else default_paths()
    capture_source = (
        source
        if isinstance(source, CaptureSource)
        else CaptureSource.from_path(source, kind="path")
    )
    capture = capture_source.validate()
    bundle_dir = Path(models_dir) if models_dir is not None else resolved_paths.models
    bundle = AnalysisBundle.new(
        capture_source.describe(),
        provenance=build_provenance(resolved_paths, bundle_dir, use_tshark=use_tshark),
    )
    if analysis_id:
        bundle.analysis_id = str(analysis_id)
    run = _Run(
        bundle=bundle,
        capture=capture,
        paths=resolved_paths,
        models_dir=bundle_dir,
        configured=configured,
        use_tshark=use_tshark,
    )
    for name, stage in STAGES:
        result = _attempt(name, lambda stage=stage: stage(run))
        bundle.set_stage(result)
        if not result.available and result.component == "protocol":
            for downstream in ("traffic", "security", "privacy"):
                if downstream not in bundle.stages:
                    bundle.set_stage(StageResult.skipped(downstream, reason="protocol analysis produced no data"))
    bundle.provenance["finished_at"] = utc_now()
    bundle.provenance["notes"] = list(run.notes)
    if persist:
        resolved_paths.ensure_runtime_dirs()
        written = bundle.write_json(resolved_paths.bundles / f"{bundle.analysis_id}.json")
        bundle.provenance["bundle_path"] = str(written)
    return bundle


__all__ = [
    "ALLOWED_SUFFIXES",
    "DEFAULT_MAX_BYTES",
    "STAGES",
    "UNAVAILABLE_CODES",
    "AnalysisBundle",
    "CaptureSource",
    "SourceKind",
    "build_provenance",
    "run_analysis",
]
