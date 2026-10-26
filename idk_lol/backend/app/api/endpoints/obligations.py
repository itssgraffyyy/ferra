"""Security obligation endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_permission, require_institution_access
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.crud.obligation import security_obligation as obligation_crud
from app.models.obligation import SecurityObligation
from app.schemas.obligation import SecurityObligationCreate, SecurityObligationRead, SecurityObligationUpdate

logger = get_logger("app.api.endpoints.obligations")

router = APIRouter(tags=["obligations"])


@router.post("/obligations", response_model=SecurityObligationRead, status_code=status.HTTP_201_CREATED)
def create_obligation(
    obligation_in: SecurityObligationCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("obligation:write")),
):
    return obligation_crud.create(db, obj_in=obligation_in)


@router.get("/obligations", response_model=list[SecurityObligationRead])
def list_obligations(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("obligation:read")),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    institution_id: str | None = Query(None),
):
    q = db.query(SecurityObligation)
    if institution_id:
        q = q.filter(SecurityObligation.institution_id == institution_id)
    return q.offset(skip).limit(limit).all()


@router.get("/obligations/{obligation_id}", response_model=SecurityObligationRead)
def get_obligation(
    obligation_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("obligation:read")),
):
    obl = obligation_crud.get(db, obligation_id)
    if not obl:
        raise NotFoundError("security_obligation", obligation_id)
    return obl


@router.put("/obligations/{obligation_id}", response_model=SecurityObligationRead)
def update_obligation(
    obligation_id: str,
    obligation_in: SecurityObligationUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("obligation:write")),
):
    obl = obligation_crud.get(db, obligation_id)
    if not obl:
        raise NotFoundError("security_obligation", obligation_id)
    return obligation_crud.update(db, db_obj=obl, obj_in=obligation_in)