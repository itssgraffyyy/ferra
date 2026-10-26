"""Financial instrument schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FinancialInstrumentBase(BaseModel):
    instrument_type: str = "FDR"
    reference_number: str = Field(min_length=1, max_length=100)
    bank_name: str | None = None
    branch: str | None = None
    ifsc: str | None = Field(default=None, max_length=11)
    principal_amount: int | None = Field(default=None, ge=0)
    currency: str = "INR"
    issue_date: str | None = None
    maturity_date: str | None = None
    depositor_name: str | None = None
    status: str = "draft"
    maturity_status: str = "unknown"
    release_authorization_status: str = "not_requested"


class FinancialInstrumentCreate(FinancialInstrumentBase):
    obligation_id: str


class FinancialInstrumentUpdate(BaseModel):
    bank_name: str | None = None
    branch: str | None = None
    ifsc: str | None = Field(default=None, max_length=11)
    principal_amount: int | None = Field(default=None, ge=0)
    currency: str | None = None
    issue_date: str | None = None
    maturity_date: str | None = None
    depositor_name: str | None = None
    status: str | None = None
    maturity_status: str | None = None
    release_authorization_status: str | None = None


class FinancialInstrumentRead(FinancialInstrumentBase):
    id: str
    obligation_id: str

    class Config:
        from_attributes = True