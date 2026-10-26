"""Financial instrument (FDR) model."""

from __future__ import annotations

from typing import List, Optional
from enum import Enum as PyEnum

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin


class InstrumentStatus(str, PyEnum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    RETURNED_FOR_CORRECTION = "returned_for_correction"
    CLOSED = "closed"


class MaturityStatus(str, PyEnum):
    NOT_MATURE = "not_mature"
    MATURE = "mature"
    LIEN_RELEASED = "lien_released"
    UNKNOWN = "unknown"


class FinancialInstrument(Base, IdMixin, TimestampMixin):
    __tablename__ = "financial_instruments"

    obligation_id: Mapped[str] = mapped_column(
        ForeignKey("security_obligations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    instrument_type: Mapped[str] = mapped_column(String(50), default="FDR", nullable=False)
    reference_number: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    bank_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    branch: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ifsc: Mapped[Optional[str]] = mapped_column(String(11), nullable=True, index=True)
    principal_amount: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # minor units
    currency: Mapped[str] = mapped_column(String(10), default="INR", nullable=False)
    issue_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    maturity_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    depositor_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    status: Mapped[str] = mapped_column(
        String(50), default=InstrumentStatus.DRAFT, nullable=False, index=True
    )
    # Independent of instrument.status: bank-side maturity state
    maturity_status: Mapped[str] = mapped_column(
        String(50), default=MaturityStatus.UNKNOWN, nullable=False
    )
    # Independent authorization lifecycle
    release_authorization_status: Mapped[str] = mapped_column(
        String(50), default="not_requested", nullable=False
    )

    obligation: Mapped["SecurityObligation"] = relationship(back_populates="instruments")
    documents: Mapped[List["Document"]] = relationship(back_populates="instrument", cascade="all, delete-orphan")

    __table_args__ = (
        # Unique reference within an obligation
    )