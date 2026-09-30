"""FastAPI service: upload a capture, get the whole bundle back.

The HTTP layer is deliberately thin - it validates the upload, calls
:func:`fera.core.orchestrator.run_analysis`, and translates the error codes the
orchestrator already uses into HTTP statuses:

================================  ======  =========================================
Error code                        HTTP    Meaning for the caller
================================  ======  =========================================
``NOT_FOUND``                     404     capture or bundle is not on the server
``CAPTURE_VALIDATION_FAILED``     422     malformed request body / file name
``PAYLOAD_TOO_LARGE``             413     upload above the configured budget
``UNSUPPORTED_CONTENT``           415     not a PCAP/PCAPNG file
``UNAVAILABLE``                   200     stage could not run here (see its status)
``INTERNAL_ERROR``                500     pipeline defect, never a caller error
================================  ======  =========================================

A stage failure is *not* an HTTP error: ``traffic: unavailable`` because no model
has been trained yet is a valid answer, and the response still carries the
protocol, security and privacy components.

Run it with::

    python -m fera.api.main          # http://127.0.0.1:8000/docs
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, cast

from fastapi import FastAPI, File, Form, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..capture.live import (
    DEFAULT_DURATION_S as LIVE_DEFAULT_DURATION_S,
)
from ..capture.live import (
    MAX_DURATION_S as LIVE_MAX_DURATION_S,
)
from ..capture.live import (
    capture_live,
    live_capture_available,
)
from ..common.errors import ErrorCode, FeraError
from ..common.paths import ProjectPaths, default_paths
from ..core.orchestrator import DEFAULT_MAX_BYTES, CaptureSource, run_analysis
from ..reports import (
    CONTENT_TYPES as REPORT_CONTENT_TYPES,
)
from ..reports import (
    REPORT_TYPES,
    normalise_report_type,
    render_report,
    report_filename,
)
from ..storage import HISTORY_SCHEMA_VERSION, HistoryRepository

#: FERA's own error code -> HTTP status.  Everything not listed here is 500:
#: an unmapped code is a defect, and pretending otherwise would hide it.
STATUS_BY_CODE: dict[ErrorCode, int] = {
    ErrorCode.CAPTURE_VALIDATION_FAILED: 422,
    ErrorCode.CONFIG_VALIDATION_FAILED: 422,
    ErrorCode.CAPTURE_EMPTY: 422,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.IO_ERROR: 400,
    ErrorCode.PAYLOAD_TOO_LARGE: 413,
    ErrorCode.UNSUPPORTED_CONTENT: 415,
    # A missing tool or a missing privilege is an environment condition, not a
    # server defect: 503 says "this cannot work here, try elsewhere or install
    # something", which is exactly the remediation the error message carries.
    ErrorCode.TOOL_NOT_AVAILABLE: 503,
    ErrorCode.CAPTURE_TOOL_NOT_AVAILABLE: 503,
    ErrorCode.DEPENDENCY_MISSING: 503,
    ErrorCode.INSUFFICIENT_PRIVILEGES: 503,
    ErrorCode.TIMEOUT: 504,
}

#: Only these characters survive in an uploaded file name; anything else is
#: replaced so the stored name can never escape the uploads directory.
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class ApiConfig:
    """Runtime knobs for one API process, read from the environment."""

    paths: ProjectPaths
    max_upload_bytes: int = DEFAULT_MAX_BYTES
    use_tshark: bool = False
    models_dir: Path | None = None

    @classmethod
    def from_env(cls) -> ApiConfig:
        """Build the config from ``FERA_*`` environment variables."""

        def flag(name: str, default: bool = False) -> bool:
            return os.environ.get(name, "1" if default else "0").strip().lower() in {"1", "true", "yes", "on"}

        paths = default_paths()
        raw_models = os.environ.get("FERA_MODELS_DIR")
        return cls(
            paths=paths,
            max_upload_bytes=int(os.environ.get("FERA_MAX_UPLOAD_BYTES", DEFAULT_MAX_BYTES)),
            use_tshark=flag("FERA_USE_TSHARK"),
            models_dir=paths.resolve(raw_models) if raw_models else paths.models,
        )


def _problem(status: int, code: str, message: str, *, hint: str | None = None, details: Any = None) -> JSONResponse:
    """Return the one error shape the API uses, matching the CLI's error output."""
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "code": code,
                "message": message,
                "hint": hint,
                "details": details or {},
            }
        },
    )


def _stored_name(filename: str | None) -> str:
    """Return a safe file name for one upload (never trust the client's)."""
    stem = _SAFE_NAME.sub("_", Path(filename or "capture.pcap").name).strip("._") or "capture.pcap"
    return f"{uuid.uuid4().hex[:8]}-{stem}"


def _configured_document(raw: str | None) -> dict[str, Any] | None:
    """Parse the optional ``configured`` form field as a JSON object."""
    if not raw or not raw.strip():
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FeraError(
            "configured must be a JSON object describing the operator settings",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            hint='for example {"encryption": "AES_GCM", "dh_group": 19, "pfs": true}',
            details={"error": str(exc)},
        ) from exc
    if not isinstance(parsed, dict):
        raise FeraError(
            "configured must be a JSON object",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            details={"received": type(parsed).__name__},
        )
    return parsed


class LiveAnalyzeRequest(BaseModel):
    """Body of ``POST /live/analyze``."""

    interface: str = Field(
        default="any",
        description="Capture interface, e.g. eth0, wlan0, any or lo.",
    )
    duration_s: int = Field(
        default=LIVE_DEFAULT_DURATION_S,
        ge=1,
        le=LIVE_MAX_DURATION_S,
        description=f"Seconds to record ({LIVE_DEFAULT_DURATION_S} by default, at most {LIVE_MAX_DURATION_S}).",
    )
    capture_filter: str | None = Field(
        default=None,
        description="Optional BPF filter, e.g. 'udp port 500 or ip proto 50'.",
    )
    configured: dict[str, Any] | None = Field(
        default=None,
        description="Optional operator configuration the security stage grades as CONFIGURED evidence.",
    )


def create_app(config: ApiConfig | None = None) -> FastAPI:
    """Build the application; ``config`` is injectable so tests can redirect storage."""
    settings = config or ApiConfig.from_env()
    settings.paths.ensure_runtime_dirs()
    history = HistoryRepository(paths=settings.paths)
    history.initialise()
    app = FastAPI(
        title="FERA API",
        summary="Encrypted-traffic analysis for IPsec captures",
        version="0.1.0",
        description=(
            "Upload a PCAP of IPsec traffic and receive the assembled analysis bundle: protocol, "
            "traffic classifier, security assessment and privacy exposure, each with its own status."
        ),
    )
    app.state.config = settings
    app.state.history = history

    @app.exception_handler(FeraError)
    async def _handle_fera_error(request: Request, exc: FeraError) -> JSONResponse:
        status = STATUS_BY_CODE.get(exc.code, 500)
        return _problem(status, exc.code.value, exc.message, hint=exc.hint, details=exc.details)

    @app.exception_handler(RequestValidationError)
    async def _handle_request_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _problem(
            422,
            ErrorCode.CAPTURE_VALIDATION_FAILED.value,
            "request did not validate",
            hint="POST a multipart form with a 'file' part and an optional JSON 'configured' object",
            details={"errors": [dict(error) for error in exc.errors()]},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _handle_http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _problem(exc.status_code, ErrorCode.CAPTURE_VALIDATION_FAILED.value, str(exc.detail), hint="see /docs")

    @app.exception_handler(Exception)
    async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        return _problem(
            500,
            ErrorCode.INTERNAL_ERROR.value,
            f"{type(exc).__name__}: {exc}",
            hint="the analysis did not expect this input; check the server log",
        )

    @app.get("/health")
    def health() -> dict[str, Any]:
        """What this process can do right now, and why it might not do more."""
        from fera import SCHEMA_VERSION

        from ..ml.inference import model_status

        models = model_status(settings.models_dir or settings.paths.models)
        return {
            "status": "ok",
            "schema_version": SCHEMA_VERSION,
            "storage": {
                "root": str(settings.paths.root),
                "uploads": str(settings.paths.uploads),
                "bundles": str(settings.paths.bundles),
            },
            "limits": {"max_upload_bytes": settings.max_upload_bytes},
            "analysis": {
                "use_tshark": settings.use_tshark,
                "models_dir": str(settings.models_dir or settings.paths.models),
                "model_available": bool(models["available"]),
                "model_reason": models.get("reason"),
            },
        }

    @app.get("/version")
    def version() -> dict[str, Any]:
        """Version and schema identifiers of the running product."""
        from fera import SCHEMA_VERSION

        from ..core.bundle import BUNDLE_SCHEMA_VERSION
        from ..security import SECURITY_SCHEMA_VERSION

        return {
            "name": "fera",
            "api_version": "0.1.0",
            "schema_version": SCHEMA_VERSION,
            "bundle_schema": BUNDLE_SCHEMA_VERSION,
            "security_schema": SECURITY_SCHEMA_VERSION,
            "history_schema": HISTORY_SCHEMA_VERSION,
        }

    @app.get("/capabilities")
    def capabilities() -> dict[str, Any]:
        """What this installation can actually do right now.

        Every entry is measured, never assumed.  A capability that cannot run
        here says so and carries the reason, so a client can hide the matching
        control instead of offering something that will fail.
        """
        from fera import SCHEMA_VERSION

        from ..analysis import find_tshark
        from ..ml.inference import model_status
        from ..reports.pdf import reportlab_available

        models = model_status(settings.models_dir or settings.paths.models)
        tshark_path = find_tshark()
        live_ok, live_reason = live_capture_available()
        pdf_ok = reportlab_available()
        return {
            "schema_version": SCHEMA_VERSION,
            "capabilities": {
                "protocol_analysis": {
                    "status": "available",
                    "detail": "built-in pcap scanner; tshark is used when installed",
                },
                "tshark": {
                    "status": "available" if tshark_path else "unavailable",
                    "reason": None if tshark_path else "tshark is not installed; the built-in scanner is used instead",
                },
                "ml_model": {
                    "status": "available" if models.get("available") else "unavailable",
                    "model_id": models.get("model_id"),
                    "feature_schema": models.get("feature_schema"),
                    "reason": models.get("reason"),
                },
                "security_assessment": {"status": "available"},
                "privacy_analysis": {"status": "available"},
                "live_capture": {
                    "status": "available" if live_ok else "unavailable",
                    "reason": live_reason,
                    "bounds": {
                        "default_duration_s": LIVE_DEFAULT_DURATION_S,
                        "max_duration_s": LIVE_MAX_DURATION_S,
                    },
                },
                "report_generation": {
                    "status": "available",
                    "formats": ["executive", "technical", "json"] + (["pdf"] if pdf_ok else []),
                    "pdf_reason": None if pdf_ok else "install the optional 'reportlab' package for PDF export",
                },
                "history": {"status": "available", **history.describe()},
            },
        }

    @app.get("/models/status")
    def models_status() -> dict[str, Any]:
        """Identity and verification status of the traffic classifier.

        Only what a caller needs to interpret a prediction is exposed; the
        artefact's filesystem path is deliberately omitted.
        """
        from ..ml.inference import model_status as status_of

        info = dict(status_of(settings.models_dir or settings.paths.models))
        info.pop("path", None)
        info.pop("directory", None)
        return info

    @app.post("/analyze")
    async def analyze(
        file: Annotated[UploadFile, File(description="PCAP or PCAPNG capture of IPsec traffic")],
        configured: Annotated[
            str | None, Form(description="JSON object of operator-configured parameters")
        ] = None,
    ) -> dict[str, Any]:
        """Analyse an uploaded capture and return the assembled bundle document."""
        capture = settings.paths.uploads / _stored_name(file.filename)
        try:
            written = 0
            with capture.open("wb") as handle:
                while chunk := await file.read(1 << 20):
                    written += len(chunk)
                    if written > settings.max_upload_bytes:
                        raise FeraError(
                            f"upload exceeds the {settings.max_upload_bytes} byte limit",
                            code=ErrorCode.PAYLOAD_TOO_LARGE,
                            hint="trim the capture with a BPF filter and retry",
                            details={"limit_bytes": settings.max_upload_bytes},
                        )
                    handle.write(chunk)
            source = CaptureSource.from_path(capture, kind="upload", max_bytes=settings.max_upload_bytes)
            bundle = run_analysis(
                source,
                paths=settings.paths,
                configured=_configured_document(configured),
                use_tshark=settings.use_tshark,
                models_dir=settings.models_dir,
            )
        except Exception:
            # A capture we refused is not one we keep: uploads are sensitive data.
            capture.unlink(missing_ok=True)
            raise
        finally:
            await file.close()
        history.save_bundle(bundle)
        return bundle.to_dict()

    @app.get("/analyses")
    def list_analyses(
        limit: Annotated[int, Query(ge=1, le=500, description="Maximum number of rows to return")] = 50,
        source_mode: Annotated[str | None, Query(description="Filter by capture source mode")] = None,
        risk_band: Annotated[str | None, Query(description="Filter by risk band, e.g. HIGH")] = None,
        traffic_class: Annotated[str | None, Query(description="Filter by predicted traffic class")] = None,
    ) -> dict[str, Any]:
        """List stored analyses, newest first.

        Only summary columns are returned: reopening a record is a separate call
        to ``GET /analyses/{id}``, so a long history never ships every bundle.
        """
        records = history.list_analyses(
            limit=limit,
            source_mode=source_mode,
            risk_band=risk_band,
            traffic_class=traffic_class,
        )
        return {"count": len(records), "analyses": [record.to_dict() for record in records]}

    @app.get("/analyses/{analysis_id}")
    def get_analysis(analysis_id: str) -> dict[str, Any]:
        """Return a previously stored bundle by analysis id."""
        return history.get_analysis(analysis_id).to_dict()

    @app.delete("/analyses/{analysis_id}")
    def delete_analysis(analysis_id: str) -> dict[str, Any]:
        """Delete one stored analysis row and its bundle document."""
        if not history.delete_analysis(analysis_id):
            raise FeraError(
                f"no analysis stored for id {analysis_id}",
                code=ErrorCode.NOT_FOUND,
                hint="list /analyses to see what is stored",
                details={"analysis_id": analysis_id},
            )
        name = _SAFE_NAME.sub("_", analysis_id)
        (settings.paths.bundles / f"{name}.json").unlink(missing_ok=True)
        return {"deleted": analysis_id}

    @app.get("/analyses/{analysis_id}/export")
    def export_analysis(analysis_id: str) -> Response:
        """Download the canonical bundle as JSON.

        The bytes are the stored document verbatim: no stage re-runs, so an
        export always matches what the analysis produced at the time.
        """
        document = history.get_analysis(analysis_id).to_dict()
        filename = report_filename(analysis_id, "json")
        return Response(
            content=json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/analyses/{analysis_id}/report")
    def analysis_report(
        analysis_id: str,
        type: Annotated[str, Query(description=f"One of: {', '.join(REPORT_TYPES)}")] = "executive",
        format: Annotated[str, Query(description="'html' or 'pdf' (ignored when type=json)")] = "html",
    ) -> Response:
        """Render a report from the stored bundle.

        ``type=json`` returns the raw export; ``format=pdf`` needs the optional
        ``reportlab`` package and says so explicitly when it is absent rather
        than returning an empty file.
        """
        kind = normalise_report_type(type)
        bundle = history.get_analysis(analysis_id)
        if kind == "json":
            return Response(
                content=json.dumps(bundle.to_dict(), indent=2, ensure_ascii=False) + "\n",
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="{report_filename(analysis_id, "json")}"'},
            )
        wanted = "pdf" if format.lower() == "pdf" else kind
        payload = render_report(bundle.to_dict(), wanted, generated_at=bundle.created_at)
        return Response(
            content=payload,
            media_type=REPORT_CONTENT_TYPES[wanted],
            headers={"Content-Disposition": f'inline; filename="{report_filename(analysis_id, wanted)}"'},
        )

    @app.post("/live/analyze")
    def live_analyze(request: LiveAnalyzeRequest) -> dict[str, Any]:
        """Record a bounded live capture and analyse it through the same pipeline.

        The capture is the only thing this endpoint does itself: the resulting
        file is handed to the ordinary orchestrator, so a live analysis and an
        uploaded capture produce the same bundle shape.  Environment problems
        (no capture tool, no privileges) surface as a structured error rather
        than a fabricated result.
        """
        available, reason = live_capture_available()
        if not available:
            raise FeraError(
                reason or "live capture is unavailable in this environment",
                code=ErrorCode.TOOL_NOT_AVAILABLE,
                hint="install tcpdump or dumpcap, then retry; uploaded captures work without them",
                details={"capability": "live_capture"},
            )
        capture = capture_live(
            request.interface,
            duration_s=request.duration_s,
            target_dir=settings.paths.uploads,
            capture_filter=request.capture_filter,
        )
        try:
            bundle = run_analysis(
                CaptureSource("live", capture.path, captured_at=capture.captured_at),
                paths=settings.paths,
                configured=request.configured,
                use_tshark=settings.use_tshark,
                models_dir=settings.models_dir,
            )
        except Exception:
            capture.path.unlink(missing_ok=True)
            raise
        history.save_bundle(bundle)
        document = bundle.to_dict()
        document["live_capture"] = capture.to_dict()
        return document

    return app




app = create_app()


def main() -> int:
    """Serve the API (``python -m fera.api.main``)."""
    import uvicorn

    settings = cast("ApiConfig", app.state.config)
    host = os.environ.get("FERA_HOST", "127.0.0.1")
    port = int(os.environ.get("FERA_PORT", "8000"))
    print(  # noqa: T201 - deliberate startup banner for the CLI entry point
        f"FERA API on http://{host}:{port} (docs at /docs, uploads in {settings.paths.uploads})"
    )
    uvicorn.run(cast("Any", app), host=host, port=port)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
