"""Institution model."""

from __future__ import annotations

from typing import List, Optional
from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin


class Institution(Base, IdMixin, TimestampMixin):
    __tablename__ = "institutions"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    code: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # Government / Private / ...
    address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    contact_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    contact_phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="active", nullable=False)

    users: Mapped[List["User"]] = relationship(back_populates="institution")
    obligations: Mapped[List["SecurityObligation"]] = relationship(back_populates="institution")