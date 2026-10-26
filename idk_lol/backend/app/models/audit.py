"""Audit event model.

Immutable record of sensitive actions. Never contains sensitive financial
values in metadata -- only ids and safe descriptors.
"""

from __future__ import annotations

from typing import Optional
from enum import Enum as PyEnum

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin


class AuditEvent(Base, IdMixin, TimestampMixin):
    __tablename__ = "audit_events"

    actor_user_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    institution_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("institutions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    metadata: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string (safe fields only)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)