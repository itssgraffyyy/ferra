"""Audit event schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AuditEventBase(BaseModel):
    actor_user_id: str | None = None
    institution_id: str | None = None
    action: str = Field(min_length=1, max_length=100)
    target_type: str = Field(min_length=1, max_length=100)
    target_id: str | None = Field(default=None, max_length=255)
    metadata: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None


class AuditEventCreate(AuditEventBase):
    pass


class AuditEventUpdate(BaseModel):
    action: str | None = None
    metadata: str | None = None


class AuditEventRead(AuditEventBase):
    id: str

    class Config:
        from_attributes = True