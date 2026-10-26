"""CRUD operations for compliance findings."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.finding import ComplianceFinding
from app.schemas.finding import ComplianceFindingCreate, ComplianceFindingUpdate


class CRUDComplianceFinding(CRUDBase[ComplianceFinding, ComplianceFindingCreate, ComplianceFindingUpdate]):
    def get_by_instrument(self, db: Session, *, instrument_id: str, skip: int = 0, limit: int = 100):
        return (
            db.query(ComplianceFinding)
            .filter(ComplianceFinding.instrument_id == instrument_id)
            .offset(skip)
            .limit(limit)
            .all()
        )


compliance_finding = CRUDComplianceFinding(ComplianceFinding)