"""Document and document-version models.

Original documents are never silently overwritten: every replacement creates a
new DocumentVersion with its own SHA-256 hash.
"""

from __future__ import annotations

from typing import List, Optional
from enum import Enum as PyEnum

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin


class DocumentProcessingStatus(str, PyEnum):
    PENDING = "pending"
    EXTRACTING = "extracting"
    EXTRACTED = "extracted"
    EXTRACTION_FAILED = "extraction_failed"
    REVIEWED = "reviewed"


class Document(Base, IdMixin, TimestampMixin):
    __tablename__ = "documents"

    instrument_id: Mapped[str] = mapped_column(
        ForeignKey("financial_instruments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    uploaded_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    original_filename: Mapped[str] = mapped_column(String(500), nullable=False)
    stored_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    processing_status: Mapped[str] = mapped_column(
        String(50), default=DocumentProcessingStatus.PENDING, nullable=False, index=True
    )

    instrument: Mapped["FinancialInstrument"] = relationship(back_populates="documents")
    uploader: Mapped[Optional["User"]] = relationship()
    versions: Mapped[List["DocumentVersion"]] = relationship(back_populates="document", cascade="all, delete-orphan")
    extracted_fields: Mapped[List["ExtractedField"]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )


class DocumentVersion(Base, IdMixin, TimestampMixin):
    __tablename__ = "document_versions"

    document_id: Mapped[str] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    stored_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    uploaded_by: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    change_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    document: Mapped["Document"] = relationship(back_populates="versions")

    __table_args__ = (
        # One version number per document
    )