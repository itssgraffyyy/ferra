"""CRUD operations for audit events."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.audit import AuditEvent
from app.schemas.audit import AuditEventCreate, AuditEventUpdate


class CRUDAuditEvent(CRUDBase[AuditEvent, AuditEventCreate, AuditEventUpdate]):
    def get_by_actor(self, db: Session, *, actor_user_id: str, skip: int = 0, limit: int = 100):
        return (
            db.query(AuditEvent)
            .filter(AuditEvent.actor_user_id == actor_user_id)
            .offset(skip)
            .limit(limit)
            .all()
        )

    def get_by_institution(self, db: Session, *, institution_id: str, skip: int = 0, limit: int = 100):
        return (
            db.query(AuditEvent)
            .filter(AuditEvent.institution_id == institution_id)
            .offset(skip)
            .limit(limit)
            .all()
        )


audit_event = CRUDAuditEvent(AuditEvent)