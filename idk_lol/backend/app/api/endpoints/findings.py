"""Compliance finding endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_current_user, get_db, require_permission
from app.core.logging import get_logger
from app.crud.finding import compliance_finding as finding_crud
from app.models.finding import ComplianceFinding
from app.schemas.finding import ComplianceFindingRead

logger = get_logger("app.api.endpoints.findings")

router = APIRouter(tags=["findings"])


@router.get("/findings", response_model=list[ComplianceFindingRead])
def list_findings(
    db=Depends(get_db),
    current_user=Depends(require_permission("finding:read")),
    instrument_id: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
):
    if instrument_id:
        return finding_crud.get_by_instrument(db, instrument_id=instrument_id, skip=skip, limit=limit)
    return db.query(ComplianceFinding).offset(skip).limit(limit).all()