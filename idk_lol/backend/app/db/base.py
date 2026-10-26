"""SQLAlchemy declarative base with shared columns."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class IdMixin:
    """Stable opaque identifier: UUID4 string."""

    id: Mapped[str] = mapped_column(
        primary_key=True, default=lambda: str(uuid.uuid4()), nullable=False
    )