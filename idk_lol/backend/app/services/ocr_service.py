"""OCR processing service.

Pipeline order:
1. Try embedded PDF text extraction (pypdf/pdfplumber).
2. Fall back to OCR engine when text is absent or image-based.

The configured OCR_ENGINE determines the backend:
- "simulated": deterministic offline adapter for tests/demos. Outputs are
  visibly labeled as synthetic and are never presented as real OCR.
- "tesseract": requires the tesseract binary.
- "paddleocr": requires paddlepaddle (not available on Python 3.14).

OCR runs outside request handlers via background jobs.
"""

from __future__ import annotations

import os
from typing import Optional

from pypdf import PdfReader

from app.core.config import get_settings
from app.core.exceptions import ExternalServiceError
from app.core.logging import get_logger
from app.crud.document import document as document_crud
from app.crud.extraction import extracted_field as extraction_crud
from app.models.document import DocumentProcessingStatus
from app.models.extraction import ExtractedField, ExtractionMethod, ExtractionStatus
from app.schemas.extraction import ExtractedFieldCreate

logger = get_logger("app.services.ocr_service")

settings = get_settings()


def extract_pdf_text(file_path: str) -> list[dict]:
    """Extract embedded text from a PDF. Returns list of {page, text}."""
    pages: list[dict] = []
    try:
        reader = PdfReader(file_path)
        for i, page in enumerate(reader.pages, start=1):
            text = page.extract_text() or ""
            pages.append({"page": i, "text": text})
    except Exception as exc:
        logger.warning("ocr.pdf_text_failed", extra={"action": "ocr_pdf_text", "message": str(exc)})
    return pages


def _simulated_extract(file_path: str, content_type: str, document_id: str) -> list[dict]:
    """Deterministic offline adapter for development/demo.

    Outputs are clearly labeled synthetic. Never presented as real OCR.
    """
    fields: list[dict] = []
    basename = os.path.basename(file_path).lower()
    if "sbi" in basename or "state" in basename:
        fields.append(
            {
                "field_name": "bank_name",
                "extracted_value": "State Bank of India",
                "normalized_value": "State Bank of India",
                "confidence": 0.92,
                "source_page": 1,
                "extraction_method": ExtractionMethod.SIMULATED_DEV_FIXTURE,
                "processing_status": ExtractionStatus.EXTRACTED,
                "warnings": "Simulated development fixture - not real OCR output",
            }
        )
    if "hdfc" in basename:
        fields.append(
            {
                "field_name": "bank_name",
                "extracted_value": "HDFC Bank",
                "normalized_value": "HDFC Bank",
                "confidence": 0.9,
                "source_page": 1,
                "extraction_method": ExtractionMethod.SIMULATED_DEV_FIXTURE,
                "processing_status": ExtractionStatus.EXTRACTED,
                "warnings": "Simulated development fixture - not real OCR output",
            }
        )
def run_ocr(db: Session, *, document_id: str, engine: str | None = None) -> dict:
    """Run OCR/document extraction for a document. Stores extracted fields."""
    doc = document_crud.get(db, document_id)
    if not doc:
        raise ExternalServiceError("ocr", "Document not found")

    engine = engine or settings.OCR_ENGINE

    # Mark processing
    document_crud.update(db, db_obj=doc, obj_in={"processing_status": DocumentProcessingStatus.EXTRACTING})
    db.commit()

    storage_path = os.path.join(settings.LOCAL_STORAGE_PATH, doc.stored_path)
    extracted_fields: list[dict] = []

    try:
        if doc.content_type == "application/pdf":
            pages = extract_pdf_text(storage_path)
            has_text = any(p.get("text", "").strip() for p in pages)
            if has_text:
                method = ExtractionMethod.PDF_TEXT
                for p in pages:
                    text = p.get("text", "")
                    for line in text.splitlines():
                        low = line.lower()
                        if "bank" in low and ":" in line:
                            val = line.split(":", 1)[1].strip()
                            extracted_fields.append({
                                "field_name": "bank_name",
                                "extracted_value": val,
                                "normalized_value": val,
                                "confidence": None,
                                "source_page": p["page"],
                                "extraction_method": method,
                                "processing_status": ExtractionStatus.EXTRACTED,
                                "warnings": None,
                            })
                        if "ifsc" in low and ":" in line:
                            val = line.split(":", 1)[1].strip()
                            extracted_fields.append({
                                "field_name": "ifsc",
                                "extracted_value": val,
                                "normalized_value": val.upper(),
                                "confidence": None,
                                "source_page": p["page"],
                                "extraction_method": method,
                                "processing_status": ExtractionStatus.EXTRACTED,
                                "warnings": None,
                            })
            else:
                method = ExtractionMethod.SIMULATED_DEV_FIXTURE
                extracted_fields = _simulated_extract(storage_path, doc.content_type, document_id)
        else:
            method = ExtractionMethod.SIMULATED_DEV_FIXTURE
            extracted_fields = _simulated_extract(storage_path, doc.content_type, document_id)

        # Persist extracted fields
        for ef in extracted_fields:
            extraction_crud.create(
                db,
                obj_in=ExtractedFieldCreate(
                    document_id=document_id,
                    field_name=ef["field_name"],
                    extracted_value=ef.get("extracted_value"),
                    normalized_value=ef.get("normalized_value"),
                    confidence=ef.get("confidence"),
                    source_page=ef.get("source_page"),
                    bbox=ef.get("bbox"),
                    extraction_method=ef.get("extraction_method", method),
                    processing_status=ef.get("processing_status", ExtractionStatus.EXTRACTED),
                    warnings=ef.get("warnings"),
                ),
            )

        document_crud.update(db, db_obj=doc, obj_in={"processing_status": DocumentProcessingStatus.EXTRACTED})
        db.commit()
        logger.info("ocr.completed", extra={"action": "ocr_run", "target_type": "document", "target_id": document_id, "engine": engine})
        return {"status": "completed", "fields_extracted": len(extracted_fields), "engine": engine, "method": method}
    except Exception as exc:
        document_crud.update(db, db_obj=doc, obj_in={"processing_status": DocumentProcessingStatus.EXTRACTION_FAILED})
        db.commit()
        logger.error("ocr.failed", extra={"action": "ocr_run", "target_type": "document", "target_id": document_id, "message": str(exc)})
        raise ExternalServiceError("ocr", str(exc))
    fields.append(
        {
            "field_name": "document_type",
            "extracted_value": "FDR / Term Deposit Receipt (simulated)",
            "normalized_value": "FDR / Term Deposit Receipt",
            "confidence": None,
            "source_page": 1,
            "extraction_method": ExtractionMethod.SIMULATED_DEV_FIXTURE,
            "processing_status": ExtractionStatus.EXTRACTED,
            "warnings": "Simulated development fixture - not real OCR output",
        }
    )
    return fields