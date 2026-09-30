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

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..common.errors import ErrorCode, FeraError
from ..common.paths import ProjectPaths, default_paths
from ..core.orchestrator import DEFAULT_MAX_BYTES, CaptureSource, run_analysis

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


def create_app(config: ApiConfig | None = None) -> FastAPI:
    """Build the application; ``config`` is injectable so tests can redirect storage."""
    settings = config or ApiConfig.from_env()
    settings.paths.ensure_runtime_dirs()
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
        return bundle.to_dict()

    @app.get("/analyses/{analysis_id}")
    def analyses(analysis_id: str) -> dict[str, Any]:
        """Return a previously stored bundle by analysis id."""
        name = _SAFE_NAME.sub("_", analysis_id)
        stored = settings.paths.bundles / f"{name}.json"
        if not stored.is_file():
            raise FeraError(
                f"no bundle stored for analysis id {analysis_id}",
                code=ErrorCode.NOT_FOUND,
                hint="POST /analyze first, or check the id returned by an earlier upload",
                details={"looked_for": str(stored)},
            )
        return json.loads(stored.read_text(encoding="utf-8"))

    return app


app = create_app()


def main() -> int:
    """Serve the API (``python -m fera.api.main``)."""
    import uvicorn

    settings = cast("ApiConfig", app.state.config)
    host = os.environ.get("FERA_HOST", "127.0.0.1")
    port = int(os.environ.get("FERA_PORT", "8000"))
    print(f"FERA API on http://{host}:{port} (docs at /docs, uploads in {settings.paths.uploads})")
    uvicorn.run(cast("Any", app), host=host, port=port)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
