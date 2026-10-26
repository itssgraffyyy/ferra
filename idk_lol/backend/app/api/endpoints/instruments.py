"""Financial instrument endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_permission
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.crud.instrument import financial_instrument as instrument_crud
from app.models.instrument import FinancialInstrument
from app.schemas.instrument import FinancialInstrumentCreate, FinancialInstrumentRead, FinancialInstrumentUpdate

logger = get_logger("app.api.endpoints.instruments")

router = APIRouter(tags=["instruments"])


@router.post("/instruments", response_model=FinancialInstrumentRead, status_code=status.HTTP_201_CREATED)
def create_instrument(
    instrument_in: FinancialInstrumentCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("instrument:write")),
):
    return instrument_crud.create(db, obj_in=instrument_in)


@router.get("/instruments", response_model=list[FinancialInstrumentRead])
def list_instruments(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("instrument:read")),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    obligation_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    q = db.query(FinancialInstrument)
    if obligation_id:
        q = q.filter(FinancialInstrument.obligation_id == obligation_id)
    if status:
        q = q.filter(FinancialInstrument.status == status)
    return q.offset(skip).limit(limit).all()


@router.get("/instruments/{instrument_id}", response_model=FinancialInstrumentRead)
def get_instrument(
    instrument_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("instrument:read")),
):
    inst = instrument_crud.get(db, instrument_id)
    if not inst:
        raise NotFoundError("financial_instrument", instrument_id)
    return inst


@router.put("/instruments/{instrument_id}", response_model=FinancialInstrumentRead)
def update_instrument(
    instrument_id: str,
    instrument_in: FinancialInstrumentUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("instrument:write")),
):
    inst = instrument_crud.get(db, instrument_id)
    if not inst:
        raise NotFoundError("financial_instrument", instrument_id)
    return instrument_crud.update(db, db_obj=inst, obj_in=instrument_in)