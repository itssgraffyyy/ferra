"""Versioned AICTE regulatory rule models.

Rules are deterministic and explainable. Rules not yet validated against an
official source are marked provisional and route cases for human review.
"""

from __future__ import annotations

from typing import List, Optional
from enum import Enum as PyEnum

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin


class ValidationStatus(str, PyEnum):
    PROVISIONAL = "provisional"       # not validated against an official source
    VALIDATED = "validated"           # checked against official AICTE handbook/amendment
    UNSUPPORTED = "unsupported"       # interpretation not supported


class RegulatoryPolicyVersion(Base, IdMixin, TimestampMixin):
    __tablename__ = "regulatory_policy_versions"

    code: Mapped[str] = mapped_column(String(100), nullable=False, index=True)  # e.g. "APH-2025-26"
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    effective_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # ISO date
    source_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_current: Mapped[bool] = mapped_column(default=False, nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    rules: Mapped[List["RegulatoryRule"]] = relationship(back_populates="policy_version", cascade="all, delete-orphan")


class RegulatoryRule(Base, IdMixin, TimestampMixin):
    __tablename__ = "regulatory_rules"

    policy_version_id: Mapped[str] = mapped_column(
        ForeignKey("regulatory_policy_versions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    official_source: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    applicability_conditions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    institution_category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    programme_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    programme_level: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    deposit_amount_required: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    currency: Mapped[str] = mapped_column(String(10), default="INR", nullable=False)
    exemptions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    adjustments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    evidence_requirements: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    evaluation_logic: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string: deterministic conditions
    rule_version: Mapped[str] = mapped_column(String(50), default="1.0", nullable=False)
    validation_status: Mapped[str] = mapped_column(
        String(50), default=ValidationStatus.PROVISIONAL, nullable=False
    )

    policy_version: Mapped["RegulatoryPolicyVersion"] = relationship(back_populates="rules")