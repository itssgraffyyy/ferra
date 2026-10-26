"""Audit event endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_current_user, get_db, require_permission
from app.core.logging import get_logger
from app.crud.audit import audit_event as audit_crud
from app.schemas.audit import AuditEventRead

logger = get_logger("app.api.endpoints.audit")

router = APIRouter(tags=["audit"])


@router.get("/audit-events", response_model=list[AuditEventRead])
def list_audit_events(
    db=Depends(get_db),
    current_user=Depends(require_permission("audit:read")),
    actor_user_id: Optional[str] = Query(None),
    institution_id: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
):
    if actor_user_id:
        return audit_crud.get_by_actor(db, actor_user_id=actor_user_id, skip=skip, limit=limit)
    if institution_id:
        return audit_crud.get_by_institution(db, institution_id=institution_id, skip=skip, limit=limit)
    return audit_crud.get_multi(db, skip=skip, limit=limit)