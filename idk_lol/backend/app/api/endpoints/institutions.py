"""Institution endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_permission
from app.core.logging import get_logger
from app.crud.institution import institution as institution_crud
from app.schemas.institution import InstitutionCreate, InstitutionRead, InstitutionUpdate

logger = get_logger("app.api.endpoints.institutions")

router = APIRouter(tags=["institutions"])


@router.post("/institutions", response_model=InstitutionRead, status_code=status.HTTP_201_CREATED)
def create_institution(
    institution_in: InstitutionCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("institution:write")),
):
    existing = institution_crud.get_by_code(db, code=institution_in.code)
    if existing:
        from app.core.exceptions import ConflictError

        raise ConflictError("Institution code already exists")
    inst = institution_crud.create(db, obj_in=institution_in)
    return inst


@router.get("/institutions", response_model=list[InstitutionRead])
def list_institutions(
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("institution:read_all")),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
):
    return institution_crud.get_multi(db, skip=skip, limit=limit)


@router.get("/institutions/{institution_id}", response_model=InstitutionRead)
def get_institution(
    institution_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("institution:read")),
):
    from app.core.exceptions import NotFoundError

    inst = institution_crud.get(db, institution_id)
    if not inst:
        raise NotFoundError("institution", institution_id)
    return inst


@router.put("/institutions/{institution_id}", response_model=InstitutionRead)
def update_institution(
    institution_id: str,
    institution_in: InstitutionUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("institution:write")),
):
    from app.core.exceptions import NotFoundError

    inst = institution_crud.get(db, institution_id)
    if not inst:
        raise NotFoundError("institution", institution_id)
    return institution_crud.update(db, db_obj=inst, obj_in=institution_in)