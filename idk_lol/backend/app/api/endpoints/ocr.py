"""OCR processing endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status

from app.api.deps import get_current_user, get_db, require_permission
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.crud.document import document as document_crud
from app.crud.ocr_job import ocr_job as ocr_job_crud
from app.models.document import Document
from app.schemas.ocr_job import OcrJobRead
from app.services.ocr_service import run_ocr

logger = get_logger("app.api.endpoints.ocr")

router = APIRouter(tags=["ocr"])


@router.post("/documents/{document_id}/ocr", status_code=status.HTTP_202_ACCEPTED)
def trigger_ocr(
    document_id: str,
    db=Depends(get_db),
    current_user=Depends(require_permission("ocr:trigger")),
):
    doc = document_crud.get(db, document_id)
    if not doc:
        raise NotFoundError("document", document_id)
    result = run_ocr(db, document_id=document_id)
    return {"status": "accepted", "result": result}


@router.get("/documents/{document_id}/ocr", response_model=OcrJobRead)
def ocr_status(
    document_id: str,
    db=Depends(get_db),
    current_user=Depends(require_permission("ocr:read")),
):
    job = (
        db.query(OcrJob)
        .filter(OcrJob.document_id == document_id)
        .order_by(OcrJob.created_at.desc())
        .first()
    )
    if not job:
        raise NotFoundError("ocr_job", document_id)
    return job