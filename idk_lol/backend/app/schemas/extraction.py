"""Extracted field schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ExtractedFieldBase(BaseModel):
    document_id: str
    field_name: str = Field(min_length=1, max_length=100)
    extracted_value: str | None = None
    normalized_value: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    source_page: int | None = Field(default=None, ge=1)
    bbox: str | None = None
    extraction_method: str
    processing_status: str = "pending"
    warnings: str | None = None
    corrected_value: str | None = None


class ExtractedFieldCreate(ExtractedFieldBase):
    pass


class ExtractedFieldUpdate(BaseModel):
    extracted_value: str | None = None
    normalized_value: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    processing_status: str | None = None
    warnings: str | None = None
    corrected_value: str | None = None
    corrected_by: str | None = None


class ExtractedFieldRead(ExtractedFieldBase):
    id: str
    corrected_by: str | None = None
    corrected_at: str | None = None

    class Config:
        from_attributes = True