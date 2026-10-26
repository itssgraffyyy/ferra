"""Institution schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class InstitutionBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    code: str = Field(min_length=1, max_length=50)
    category: str | None = None
    address: str | None = None
    contact_email: str | None = None
    contact_phone: str | None = None
    status: str = "active"


class InstitutionCreate(InstitutionBase):
    pass


class InstitutionUpdate(BaseModel):
    name: str | None = None
    code: str | None = None
    category: str | None = None
    address: str | None = None
    contact_email: str | None = None
    contact_phone: str | None = None
    status: str | None = None


class InstitutionRead(InstitutionBase):
    id: str

    class Config:
        from_attributes = True