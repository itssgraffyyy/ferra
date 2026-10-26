"""Security obligation schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SecurityObligationBase(BaseModel):
    reference: str = Field(min_length=1, max_length=100)
    programme_type: str | None = None
    programme_level: str | None = None
    deposit_amount_required: int | None = Field(default=None, ge=0)
    currency: str = "INR"
    status: str = "active"
    regulation_source: str | None = None
    notes: str | None = None


class SecurityObligationCreate(SecurityObligationBase):
    pass


class SecurityObligationUpdate(BaseModel):
    reference: str | None = None
    programme_type: str | None = None
    programme_level: str | None = None
    deposit_amount_required: int | None = Field(default=None, ge=0)
    currency: str | None = None
    status: str | None = None
    regulation_source: str | None = None
    notes: str | None = None


class SecurityObligationRead(SecurityObligationBase):
    id: str
    institution_id: str

    class Config:
        from_attributes = True