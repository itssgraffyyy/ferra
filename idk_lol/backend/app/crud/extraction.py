"""CRUD operations for extracted fields."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.extraction import ExtractedField
from app.schemas.extraction import ExtractedFieldCreate, ExtractedFieldUpdate


class CRUDExtractedField(CRUDBase[ExtractedField, ExtractedFieldCreate, ExtractedFieldUpdate]):
    def get_by_document(self, db: Session, *, document_id: str, skip: int = 0, limit: int = 100):
        return (
            db.query(ExtractedField)
            .filter(ExtractedField.document_id == document_id)
            .offset(skip)
            .limit(limit)
            .all()
        )


extracted_field = CRUDExtractedField(ExtractedField)