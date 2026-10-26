"""Document storage and management service.

Documents are stored content-addressed (SHA-256). Originals are never
silently overwritten; replacements create a new version.
"""

from __future__ import annotations

import hashlib
import os
from typing import Optional

from fastapi import UploadFile
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import ValidationError
from app.core.logging import get_logger
from app.crud.document import document as document_crud, document_version as version_crud
from app.models.document import Document, DocumentProcessingStatus
from app.models.extraction import ExtractedField, ExtractionMethod, ExtractionStatus
from app.schemas.document import DocumentCreate

logger = get_logger("app.services.document_service")

MAX_UPLOAD_BYTES = int(get_settings().MAX_UPLOAD_BYTES)
ALLOWED_CONTENT_TYPES = set(get_settings().ALLOWED_CONTENT_TYPES)
LOCAL_STORAGE_PATH = get_settings().LOCAL_STORAGE_PATH


def validate_upload(file: UploadFile) -> None:
    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise ValidationError(f"Unsupported content type: {file.content_type}")
    # size enforced at read time below


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def storage_path_for(instrument_id: str, version: int, filename: str) -> str:
    return f"documents/{instrument_id}/v{version}/{filename}"


def save_document(
    db: Session,
    *,
    instrument_id: str,
    uploaded_by: Optional[str],
    file: UploadFile,
    change_reason: Optional[str] = None,
) -> Document:
    settings = get_settings()
    os.makedirs(LOCAL_STORAGE_PATH, exist_ok=True)

    data = file.file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValidationError(f"File exceeds maximum size of {MAX_UPLOAD_BYTES} bytes")
    sha256 = compute_sha256(data)

    # Determine document (existing by instrument + sha256 check for dedupe)
    existing = document_crud.get_by_sha256(db, sha256=sha256)
    if existing:
        raise ValidationError("A document with identical content already exists")

    # Determine next version number
    docs = document_crud.get_by_instrument(db, instrument_id=instrument_id)
    version_number = 1
    if docs:
        # find max version among versions of the latest document
        latest = docs[-1]
        versions = version_crud.get_multi(db)  # crude; filter below
        max_ver = 0
        for v in versions:
            if v.document_id == latest.id and v.version_number > max_ver:
                max_ver = v.version_number
        version_number = max_ver + 1

    stored_path = storage_path_for(instrument_id, version_number, file.filename or "upload.bin")
    full_path = os.path.join(LOCAL_STORAGE_PATH, stored_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "wb") as f:
        f.write(data)

    doc_in = DocumentCreate(
        instrument_id=instrument_id,
        original_filename=file.filename or "upload.bin",
        stored_path=stored_path,
        content_type=file.content_type or "application/octet-stream",
        size_bytes=len(data),
        sha256=sha256,
        processing_status=DocumentProcessingStatus.PENDING,
    )
    doc = document_crud.create(db, obj_in=doc_in, uploaded_by=uploaded_by)

    # create version record
    version_crud.create(
        db,
        obj_in=__import__("app.schemas.document", fromlist=["DocumentVersionCreate"]).DocumentVersionCreate(
            document_id=doc.id,
            version_number=version_number,
            stored_path=stored_path,
            sha256=sha256,
            uploaded_by=uploaded_by,
            change_reason=change_reason or "Initial upload",
        ),
    )

    # seed a pending extracted-field placeholder? No; extraction creates fields.
    logger.info(
        "document.uploaded",
        extra={
            "action": "document.upload",
            "user_id": uploaded_by,
            "target_type": "document",
            "target_id": doc.id,
            "institution_id": None,
        },
    )
    return doc


def get_document_bytes(db: Session, document_id: str) -> Optional[tuple[bytes, str, str]]:
    """Return (bytes, content_type, filename) if document exists."""
    doc = document_crud.get(db, document_id)
    if not doc:
        return None
    full_path = os.path.join(LOCAL_STORAGE_PATH, doc.stored_path)
    if not os.path.exists(full_path):
        return None
    with open(full_path, "rb") as f:
        data = f.read()
    return data, doc.content_type, doc.original_filename