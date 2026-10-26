"""Exception / resolution case model."""

from __future__ import annotations

from typing import Optional
from enum import Enum as PyEnum

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin


class CaseStatus(str, PyEnum):
    OPEN = "open"
    IN_REVIEW = "in_review"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    CLOSED = "closed"


class ExceptionResolutionCase(Base, IdMixin, TimestampMixin):
    __tablename__ = "exception_resolution_cases"

    instrument_id: Mapped[str] = mapped_column(
        ForeignKey("financial_instruments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default=CaseStatus.OPEN, nullable=False, index=True)
    resolution_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resolved_by: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    instrument: Mapped["FinancialInstrument"] = relationship()