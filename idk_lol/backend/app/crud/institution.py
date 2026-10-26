"""CRUD operations for institutions."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.institution import Institution
from app.schemas.institution import InstitutionCreate, InstitutionUpdate


class CRUDInstitution(CRUDBase[Institution, InstitutionCreate, InstitutionUpdate]):
    def get_by_code(self, db: Session, *, code: str) -> Institution | None:
        return db.query(Institution).filter(Institution.code == code).first()


institution = CRUDInstitution(Institution)