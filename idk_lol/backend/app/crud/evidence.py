"""CRUD operations for evidence sources and external verification records."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.evidence import EvidenceSource, ExternalVerificationRecord
from app.schemas.evidence import EvidenceSourceCreate, EvidenceSourceUpdate, ExternalVerificationRecordCreate


class CRUDEvidenceSource(CRUDBase[EvidenceSource, EvidenceSourceCreate, EvidenceSourceUpdate]):
    def get_by_instrument(self, db: Session, *, instrument_id: str, skip: int = 0, limit: int = 100):
        return (
            db.query(EvidenceSource)
            .filter(EvidenceSource.instrument_id == instrument_id)
            .offset(skip)
            .limit(limit)
            .all()
        )


class CRUDExternalVerificationRecord(CRUDBase[ExternalVerificationRecord, ExternalVerificationRecordCreate, Any]):
    pass


evidence_source = CRUDEvidenceSource(EvidenceSource)
external_verification_record = CRUDExternalVerificationRecord(ExternalVerificationRecord)