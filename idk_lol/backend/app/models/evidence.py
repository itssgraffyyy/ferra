"""Evidence source and external verification models.

The four evidence columns are: institution declaration, document extraction,
regulatory requirement, and external financial evidence. Each source carries an
explicit trust classification and provenance record -- never a bare "verified"
boolean.
"""

from __future__ import annotations

from typing import List, Optional
from enum import Enum as PyEnum

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin


class EvidenceSourceType(str, PyEnum):
    DECLARATION = "declaration"       # institution-declared information
    EXTRACTION = "extraction"         # document extraction
    REGULATORY = "regulatory"         # requirement derived from AICTE regulations
    EXTERNAL = "external"             # externally sourced financial evidence


class TrustClassification(str, PyEnum):
    UNVERIFIED = "unverified"
    TRUSTED = "trusted"
    SANDBOX = "sandbox"               # explicitly simulated / mock data
    PROVISIONAL = "provisional"       # not yet validated


class EvidenceStatus(str, PyEnum):
    SUBMITTED = "submitted"
    EXTRACTED = "extracted"
    MATCHED = "matched"
    CONFLICTING = "conflicting"
    UNCONFIRMED = "unconfirmed"
    EXTERNALLY_CONFIRMED = "externally_confirmed"
    UNAVAILABLE = "unavailable"
    REQUIRES_HUMAN_REVIEW = "requires_human_review"


class EvidenceSource(Base, IdMixin, TimestampMixin):
    __tablename__ = "evidence_sources"

    instrument_id: Mapped[str] = mapped_column(
        ForeignKey("financial_instruments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    source_name: Mapped[str] = mapped_column(String(255), nullable=False)
    trust_classification: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default=EvidenceStatus.SUBMITTED, nullable=False, index=True)
    value_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    provenance: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # how the evidence was obtained
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    instrument: Mapped["FinancialInstrument"] = relationship()


class ExternalVerificationStatus(str, PyEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    CONFLICTING = "conflicting"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    SANDBOX_MOCK = "sandbox_mock"


class ExternalVerificationRecord(Base, IdMixin, TimestampMixin):
    __tablename__ = "external_verification_records"

    instrument_id: Mapped[str] = mapped_column(
        ForeignKey("financial_instruments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    adapter_name: Mapped[str] = mapped_column(String(100), nullable=False)
    reference_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    consent_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    response_status: Mapped[str] = mapped_column(String(50), nullable=False)
    response_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verified_at: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # ISO timestamp

    instrument: Mapped["FinancialInstrument"] = relationship()