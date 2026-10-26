"""Exception/resolution case schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ExceptionResolutionCaseBase(BaseModel):
    instrument_id: str
    title: str = Field(min_length=1, max_length=255)
    description: str | None = None
    status: str = "open"
    resolution_summary: str | None = None


class ExceptionResolutionCaseCreate(ExceptionResolutionCaseBase):
    pass


class ExceptionResolutionCaseUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    resolution_summary: str | None = None
    resolved_by: str | None = None


class ExceptionResolutionCaseRead(ExceptionResolutionCaseBase):
    id: str
    resolved_by: str | None = None
    resolved_at: str | None = None

    class Config:
        from_attributes = True