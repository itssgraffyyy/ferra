"""Extracted financial field model.

Every extracted field is tied to its source document/page and carries its own
processing status. Extracted values are institution-declared-or-extracted
evidence, not confirmation of a bank deposit.
"""

from __future__ import annotations

from typing import List, Optional
from enum import Enum as PyEnum

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin


class ExtractionStatus(str, PyEnum):
    PENDING = "pending"
    EXTRACTED = "extracted"
    LOW_CONFIDENCE = "low_confidence"
    FAILED = "failed"
    CORRECTED = "corrected"


class ExtractionMethod(str, PyEnum):
    PDF_TEXT = "pdf_text"
    OCR = "ocr"
    MANUAL_CORRECTION = "manual_correction"
    SIMULATED_DEV_FIXTURE = "simulated_dev_fixture"


class ExtractedField(Base, IdMixin, TimestampMixin):
    __tablename__ = "extracted_fields"

    document_id: Mapped[str] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    field_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    extracted_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    normalized_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(nullable=True)
    source_page: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    bbox: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    extraction_method: Mapped[str] = mapped_column(String(50), nullable=False)
    processing_status: Mapped[str] = mapped_column(
        String(50), default=ExtractionStatus.PENDING, nullable=False, index=True
    )
    warnings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string

    # Manual corrections preserve the original extracted values
    corrected_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    corrected_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    corrected_at: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # ISO timestamp

    document: Mapped["Document"] = relationship(back_populates="extracted_fields")