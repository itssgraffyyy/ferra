"""Document schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DocumentBase(BaseModel):
    instrument_id: str
    original_filename: str = Field(min_length=1, max_length=500)
    stored_path: str = Field(min_length=1, max_length=1000)
    content_type: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(min_length=64, max_length=64)
    processing_status: str = "pending"


class DocumentCreate(DocumentBase):
    uploaded_by: str | None = None


class DocumentUpdate(BaseModel):
    processing_status: str | None = None


class DocumentRead(DocumentBase):
    id: str
    uploaded_by: str | None = None

    class Config:
        from_attributes = True


class DocumentVersionBase(BaseModel):
    document_id: str
    version_number: int = Field(ge=1)
    stored_path: str = Field(min_length=1, max_length=1000)
    sha256: str = Field(min_length=64, max_length=64)
    change_reason: str | None = None


class DocumentVersionCreate(DocumentVersionBase):
    uploaded_by: str | None = None


class DocumentVersionRead(DocumentVersionBase):
    id: str

    class Config:
        from_attributes = True