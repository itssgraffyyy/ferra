"""Document upload and retrieval endpoints."""

from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_permission, require_institution_access
from app.core.config import get_settings
from app.core.exceptions import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.crud.document import document as document_crud
from app.models.document import Document
from app.schemas.document import DocumentRead
from app.services.document_service import save_document, validate_upload

logger = get_logger("app.api.endpoints.documents")
settings = get_settings()

router = APIRouter(tags=["documents"])


@router.post("/instruments/{instrument_id}/documents", status_code=status.HTTP_201_CREATED)
def upload_document(
    instrument_id: str,
    file: UploadFile = File(...),
    change_reason: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("document:write")),
):
    validate_upload(file)
    try:
        doc = save_document(
            db,
            instrument_id=instrument_id,
            uploaded_by=current_user.id,
            file=file,
            change_reason=change_reason,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.message)
    return {"id": doc.id, "sha256": doc.sha256, "processing_status": doc.processing_status}


@router.get("/documents/{document_id}")
def get_document(
    document_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("document:read")),
):
    from app.services.document_service import get_document_bytes

    doc = document_crud.get(db, document_id)
    if not doc:
        raise NotFoundError("document", document_id)
    result = get_document_bytes(db, document_id)
    if not result:
        raise NotFoundError("document_file", document_id)
    data, content_type, filename = result
    return Response(content=data, media_type=content_type, headers={"X-Document-SHA256": doc.sha256})


@router.get("/documents/{document_id}/meta", response_model=DocumentRead)
def get_document_meta(
    document_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("document:read")),
):
    doc = document_crud.get(db, document_id)
    if not doc:
        raise NotFoundError("document", document_id)
    return doc


@router.get("/documents", response_model=list[DocumentRead])
def list_documents(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("document:read")),
    instrument_id: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
):
    if instrument_id:
        return document_crud.get_by_instrument(db, instrument_id=instrument_id, skip=skip, limit=limit)
    return document_crud.get_multi(db, skip=skip, limit=limit)