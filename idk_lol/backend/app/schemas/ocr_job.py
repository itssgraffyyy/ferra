"""OCR job schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class OcrJobBase(BaseModel):
    document_id: str
    status: str = "queued"
    engine: str
    error_message: str | None = None


class OcrJobCreate(OcrJobBase):
    pass


class OcrJobUpdate(BaseModel):
    status: str | None = None
    error_message: str | None = None
    engine: str | None = None


class OcrJobRead(OcrJobBase):
    id: str

    class Config:
        from_attributes = True