"""Security obligation model.

An obligation is an AICTE-mandated security deposit requirement registered
against an institution. One obligation can relate to one or more financial
instruments (FDRs).
"""

from __future__ import annotations

from typing import List, Optional
from enum import Enum as PyEnum

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin


class ObligationStatus(str, PyEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    FULFILLED = "fulfilled"
    RELEASED = "released"
    ARCHIVED = "archived"


class SecurityObligation(Base, IdMixin, TimestampMixin):
    __tablename__ = "security_obligations"

    institution_id: Mapped[str] = mapped_column(
        ForeignKey("institutions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    reference: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    programme_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    programme_level: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    deposit_amount_required: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # minor units (paise)
    currency: Mapped[str] = mapped_column(String(10), default="INR", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default=ObligationStatus.ACTIVE, nullable=False, index=True)
    regulation_source: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    institution: Mapped["Institution"] = relationship(back_populates="obligations")
    instruments: Mapped[List["FinancialInstrument"]] = relationship(back_populates="obligation")

    __table_args__ = (
        # One active obligation per reference per institution
    )