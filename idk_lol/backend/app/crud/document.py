"""CRUD operations for documents and document versions."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.document import Document, DocumentVersion
from app.schemas.document import DocumentCreate, DocumentUpdate, DocumentVersionCreate


class CRUDDocument(CRUDBase[Document, DocumentCreate, DocumentUpdate]):
    def get_by_instrument(self, db: Session, *, instrument_id: str, skip: int = 0, limit: int = 100):
        return (
            db.query(Document)
            .filter(Document.instrument_id == instrument_id)
            .offset(skip)
            .limit(limit)
            .all()
        )

    def get_by_sha256(self, db: Session, *, sha256: str) -> Document | None:
        return db.query(Document).filter(Document.sha256 == sha256).first()


class CRUDDocumentVersion(CRUDBase[DocumentVersion, DocumentVersionCreate, Any]):
    pass


document = CRUDDocument(Document)
document_version = CRUDDocumentVersion(DocumentVersion)