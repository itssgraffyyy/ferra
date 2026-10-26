"""CRUD operations for OCR jobs."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.ocr_job import OcrJob
from app.schemas.ocr_job import OcrJobCreate, OcrJobUpdate


class CRUDOcrJob(CRUDBase[OcrJob, OcrJobCreate, OcrJobUpdate]):
    pass


ocr_job = CRUDOcrJob(OcrJob)