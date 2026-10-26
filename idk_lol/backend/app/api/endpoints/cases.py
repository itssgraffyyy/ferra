"""Exception / resolution case endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import get_current_user, get_db, require_permission
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.crud.case import exception_resolution_case as case_crud
from app.models.case import ExceptionResolutionCase
from app.schemas.case import (
    ExceptionResolutionCaseCreate,
    ExceptionResolutionCaseRead,
    ExceptionResolutionCaseUpdate,
)

logger = get_logger("app.api.endpoints.cases")

router = APIRouter(tags=["cases"])


@router.post("/cases", response_model=ExceptionResolutionCaseRead, status_code=status.HTTP_201_CREATED)
def create_case(
    case_in: ExceptionResolutionCaseCreate,
    db=Depends(get_db),
    current_user=Depends(require_permission("case:write")),
):
    return case_crud.create(db, obj_in=case_in)


@router.get("/cases", response_model=list[ExceptionResolutionCaseRead])
def list_cases(
    db=Depends(get_db),
    current_user=Depends(require_permission("case:read")),
    instrument_id: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
):
    if instrument_id:
        return case_crud.get_by_instrument(db, instrument_id=instrument_id, skip=skip, limit=limit)
    return db.query(ExceptionResolutionCase).offset(skip).limit(limit).all()


@router.put("/cases/{case_id}/resolve", response_model=ExceptionResolutionCaseRead)
def resolve_case(
    case_id: str,
    resolution_summary: str,
    db=Depends(get_db),
    current_user=Depends(require_permission("case:write")),
):
    case = case_crud.get(db, case_id)
    if not case:
        raise NotFoundError("exception_resolution_case", case_id)
    from datetime import datetime, timezone
    return case_crud.update(
        db,
        db_obj=case,
        obj_in=ExceptionResolutionCaseUpdate(
            status="resolved",
            resolution_summary=resolution_summary,
            resolved_by=current_user.id,
            resolved_at=datetime.now(timezone.utc).isoformat(),
        ),
    )