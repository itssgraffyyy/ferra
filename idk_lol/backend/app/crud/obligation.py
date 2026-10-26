"""CRUD operations for security obligations."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.obligation import SecurityObligation
from app.schemas.obligation import SecurityObligationCreate, SecurityObligationUpdate


class CRUDSecurityObligation(CRUDBase[SecurityObligation, SecurityObligationCreate, SecurityObligationUpdate]):
    def get_by_reference(self, db: Session, *, reference: str, institution_id: str) -> SecurityObligation | None:
        return (
            db.query(SecurityObligation)
            .filter(SecurityObligation.reference == reference, SecurityObligation.institution_id == institution_id)
            .first()
        )

    def get_by_institution(self, db: Session, *, institution_id: str, skip: int = 0, limit: int = 100):
        return (
            db.query(SecurityObligation)
            .filter(SecurityObligation.institution_id == institution_id)
            .offset(skip)
            .limit(limit)
            .all()
        )


security_obligation = CRUDSecurityObligation(SecurityObligation)