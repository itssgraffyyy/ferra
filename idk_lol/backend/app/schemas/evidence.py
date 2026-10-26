"""Evidence source schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class EvidenceSourceBase(BaseModel):
    instrument_id: str
    source_type: str
    source_name: str = Field(min_length=1, max_length=255)
    trust_classification: str
    status: str = "submitted"
    value_summary: str | None = None
    provenance: str | None = None
    notes: str | None = None


class EvidenceSourceCreate(EvidenceSourceBase):
    pass


class EvidenceSourceUpdate(BaseModel):
    source_type: str | None = None
    source_name: str | None = None
    trust_classification: str | None = None
    status: str | None = None
    value_summary: str | None = None
    provenance: str | None = None
    notes: str | None = None


class EvidenceSourceRead(EvidenceSourceBase):
    id: str

    class Config:
        from_attributes = True


class ExternalVerificationRecordBase(BaseModel):
    instrument_id: str
    adapter_name: str = Field(min_length=1, max_length=100)
    reference_id: str | None = None
    consent_id: str | None = None
    response_status: str
    response_data: str | None = None
    error_message: str | None = None


class ExternalVerificationRecordCreate(ExternalVerificationRecordBase):
    pass


class ExternalVerificationRecordRead(ExternalVerificationRecordBase):
    id: str
    verified_at: str | None = None

    class Config:
        from_attributes = True