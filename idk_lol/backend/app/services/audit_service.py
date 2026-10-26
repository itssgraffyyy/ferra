"""Audit service for recording immutable audit events."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.crud.audit import audit_event as audit_crud
from app.schemas.audit import AuditEventCreate

logger = get_logger("app.services.audit_service")


class AuditService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def log(
        self,
        *,
        actor_user_id: str | None,
        action: str,
        target_type: str,
        target_id: str | None = None,
        institution_id: str | None = None,
        metadata: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        try:
            audit_crud.create(
                self.db,
                obj_in=AuditEventCreate(
                    actor_user_id=actor_user_id,
                    institution_id=institution_id,
                    action=action,
                    target_type=target_type,
                    target_id=target_id,
                    metadata=metadata,
                    ip_address=ip_address,
                    user_agent=user_agent,
                ),
            )
        except Exception as exc:  # audit must never break the primary request
            logger.error("audit.log_failed", extra={"action": "audit_log", "message": str(exc)})
