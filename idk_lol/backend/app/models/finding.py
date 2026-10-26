"""Compliance finding model.

Each finding is deterministic, explainable, and linked to its supporting
evidence sources and regulatory rule.
"""

from __future__ import annotations

from typing import Optional
from enum import Enum as PyEnum

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin


class FindingStatus(str, PyEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    REQUIRES_HUMAN_REVIEW = "requires_human_review"


class ComplianceFinding(Base, IdMixin, TimestampMixin):
    __tablename__ = "compliance_findings"

    instrument_id: Mapped[str] = mapped_column(
        ForeignKey("financial_instruments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    policy_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g. amount_mismatch, ifsc_mismatch
    severity: Mapped[str] = mapped_column(String(50), nullable=False)  # low, medium, high, critical
    status: Mapped[str] = mapped_column(String(50), default=FindingStatus.OPEN, nullable=False, index=True)

    inputs_used: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    source_evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string: linked evidence ids
    evaluation_result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # deterministic reasoning text
    outstanding_information: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommended_action: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    instrument: Mapped["FinancialInstrument"] = relationship()