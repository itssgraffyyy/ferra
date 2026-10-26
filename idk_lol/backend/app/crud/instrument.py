"""CRUD operations for financial instruments."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.instrument import FinancialInstrument
from app.schemas.instrument import FinancialInstrumentCreate, FinancialInstrumentUpdate


class CRUDFinancialInstrument(CRUDBase[FinancialInstrument, FinancialInstrumentCreate, FinancialInstrumentUpdate]):
    def get_by_reference(self, db: Session, *, reference_number: str) -> FinancialInstrument | None:
        return db.query(FinancialInstrument).filter(FinancialInstrument.reference_number == reference_number).first()

    def get_by_obligation(self, db: Session, *, obligation_id: str, skip: int = 0, limit: int = 100):
        return (
            db.query(FinancialInstrument)
            .filter(FinancialInstrument.obligation_id == obligation_id)
            .offset(skip)
            .limit(limit)
            .all()
        )


financial_instrument = CRUDFinancialInstrument(FinancialInstrument)