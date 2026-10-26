"""Four-source evidence reconciliation engine.

The four evidence columns:
1. Institution declaration (instrument record)
2. Document extraction (extracted fields)
3. Regulatory requirement (policy rules)
4. External financial evidence (AA adapter / IFSC lookup)

Each source carries an explicit trust classification and provenance record --
never a bare "verified" boolean.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Optional

from app.core.logging import get_logger
from app.crud.evidence import evidence_source as evidence_crud
from app.crud.extraction import extracted_field as extraction_crud
from app.crud.instrument import financial_instrument as instrument_crud
from app.models.evidence import EvidenceSourceType, EvidenceStatus, TrustClassification
from app.models.extraction import ExtractedField
from app.services.aa_adapter import get_adapter
from app.services.ifsc_service import compare_ifsc_with_declared

logger = get_logger("app.services.reconciliation_service")


def _to_amount(value) -> Optional[Decimal]:
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None


class ReconciliationResult:
    def __init__(self, instrument_id: str) -> None:
        self.instrument_id = instrument_id
        self.sources: dict = {}
        self.comparisons: dict = {}
        self.findings: list[dict] = []
        self.overall_status: str = "unconfirmed"

    def to_dict(self) -> dict:
        return {
            "instrument_id": self.instrument_id,
            "sources": self.sources,
            "comparisons": self.comparisons,
            "findings": self.findings,
            "overall_status": self.overall_status,
        }


def reconcile_instrument(db, instrument_id: str) -> ReconciliationResult:
    """Run four-source reconciliation for a financial instrument."""
    instrument = instrument_crud.get(db, instrument_id)
    if not instrument:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("financial_instrument", instrument_id)

    result = ReconciliationResult(instrument_id)

    # --- Source 1: Institution declaration ---
    declaration = {
        "source_type": EvidenceSourceType.DECLARATION,
        "source_name": "Institution declaration (instrument record)",
        "trust_classification": TrustClassification.UNVERIFIED,
        "status": EvidenceStatus.SUBMITTED,
        "value_summary": {
            "reference_number": instrument.reference_number,
            "bank_name": instrument.bank_name,
            "branch": instrument.branch,
            "ifsc": instrument.ifsc,
            "principal_amount": instrument.principal_amount,
            "currency": instrument.currency,
            "issue_date": instrument.issue_date,
            "maturity_date": instrument.maturity_date,
            "depositor_name": instrument.depositor_name,
        },
        "provenance": "Declared by institution user via instrument submission",
    }
    result.sources["declaration"] = declaration

    # --- Source 2: Document extraction ---
    from app.crud.document import document as document_crud
    docs = document_crud.get_by_instrument(db, instrument_id=instrument_id)
    latest_doc = docs[-1] if docs else None
    extraction = {
        "source_type": EvidenceSourceType.EXTRACTION,
        "source_name": "Document extraction (OCR / PDF text)",
        "trust_classification": TrustClassification.PROVISIONAL,
        "status": EvidenceStatus.UNCONFIRMED,
        "value_summary": {},
        "provenance": "Extracted from uploaded document",
    }
    fields_map: dict[str, ExtractedField] = {}
    if latest_doc:
        fields = extraction_crud.get_by_document(db, document_id=latest_doc.id)
        for f in fields:
            fields_map[f.field_name] = f
        extraction["value_summary"] = {
            f.field_name: {
                "extracted_value": f.extracted_value,
                "normalized_value": f.normalized_value,
                "confidence": f.confidence,
                "source_page": f.source_page,
                "method": f.extraction_method,
                "status": f.processing_status,
            }
            for f in fields
        }
        extraction["status"] = EvidenceStatus.EXTRACTED if fields else EvidenceStatus.UNAVAILABLE
    result.sources["extraction"] = extraction

    # --- Source 3: Regulatory requirement ---
    from app.models.policy import RegulatoryRule
    obligation = instrument.obligation
    rules = []
    if obligation:
        all_rules = db.query(RegulatoryRule).all()
        for r in all_rules:
            rules.append({
                "rule_id": r.rule_id,
                "title": r.title,
                "deposit_amount_required": r.deposit_amount_required,
                "programme_type": r.programme_type,
                "programme_level": r.programme_level,
                "institution_category": r.institution_category,
                "validation_status": r.validation_status,
            })
    regulatory = {
        "source_type": EvidenceSourceType.REGULATORY,
        "source_name": "AICTE regulatory requirement (versioned rules)",
        "trust_classification": TrustClassification.PROVISIONAL,
        "status": EvidenceStatus.SUBMITTED,
        "value_summary": {
            "required_amount": obligation.deposit_amount_required if obligation else None,
            "currency": obligation.currency if obligation else None,
            "programme_type": obligation.programme_type if obligation else None,
            "programme_level": obligation.programme_level if obligation else None,
            "applicable_rules": rules,
        },
        "provenance": "Derived from versioned AICTE regulatory policy engine",
    }
    result.sources["regulatory"] = regulatory

    # --- Source 4: External financial evidence ---
    external = {
        "source_type": EvidenceSourceType.EXTERNAL,
        "source_name": "External financial evidence (term-deposit adapter)",
        "trust_classification": TrustClassification.SANDBOX,
        "status": EvidenceStatus.UNAVAILABLE,
        "value_summary": {},
        "provenance": "Sourced via AA-compatible term-deposit adapter",
    }
    external_record = None
    try:
        import asyncio
        adapter = get_adapter("local_mock")
        record = asyncio.run(adapter.fetch_term_deposit(deposit_reference=instrument.reference_number))
        external_record = record
        external["value_summary"] = record.to_dict()
        external["trust_classification"] = TrustClassification.SANDBOX
        external["status"] = EvidenceStatus.UNCONFIRMED
    except Exception as exc:
        external["value_summary"] = {"error": str(exc)}
        external["status"] = EvidenceStatus.UNAVAILABLE
        logger.warning("aa.fetch_failed", extra={"action": "aa_fetch", "reference": instrument.reference_number, "message": str(exc)})
    result.sources["external"] = external

    return _finalize(result, instrument, fields_map, external_record, external)


def _finalize(result, instrument, fields_map, external_record, external) -> ReconciliationResult:
    """Build comparisons and findings from gathered sources."""
    declared_amount = _to_amount(instrument.principal_amount)
    extracted_field = fields_map.get("principal_amount")
    extracted_amount = _to_amount(extracted_field.normalized_value if extracted_field else None)
    external_amount = _to_amount(external_record.principal_amount if external_record else None)

    comp_amount_declared_vs_extracted = {
        "compared_fields": ["principal_amount"],
        "declared": instrument.principal_amount,
        "extracted": fields_map.get("principal_amount").normalized_value if fields_map.get("principal_amount") else None,
        "match": declared_amount == extracted_amount if declared_amount is not None and extracted_amount is not None else None,
        "status": "matched" if (declared_amount == extracted_amount) else ("conflicting" if (declared_amount is not None and extracted_amount is not None) else "unconfirmed"),
    }
    result.comparisons["amount_declared_vs_extracted"] = comp_amount_declared_vs_extracted

    comp_amount_extracted_vs_external = {
        "compared_fields": ["principal_amount"],
        "extracted": fields_map.get("principal_amount").normalized_value if fields_map.get("principal_amount") else None,
        "external": external_record.principal_amount if external_record else None,
        "match": extracted_amount == external_amount if extracted_amount is not None and external_amount is not None else None,
        "status": "matched" if (extracted_amount == external_amount) else ("conflicting" if (extracted_amount is not None and external_amount is not None) else "unconfirmed"),
        "external_trust": external["trust_classification"],
    }
    result.comparisons["amount_extracted_vs_external"] = comp_amount_extracted_vs_external

    ifsc_check = compare_ifsc_with_declared(instrument.ifsc or "", instrument.bank_name, instrument.branch)
    result.comparisons["ifsc_bank_branch"] = {
        "ifsc": instrument.ifsc,
        "format_valid": ifsc_check["format_valid"],
        "exists": ifsc_check["exists"],
        "bank": ifsc_check.get("bank"),
        "branch": ifsc_check.get("branch"),
        "declared_bank": instrument.bank_name,
        "declared_branch": instrument.branch,
        "conflicts": ifsc_check.get("conflicts", []),
        "note": "IFSC validation does not authenticate the underlying FDR",
    }

    result.comparisons["dates"] = {
        "declared_issue_date": instrument.issue_date,
        "declared_maturity_date": instrument.maturity_date,
        "extracted_issue_date": fields_map.get("issue_date").normalized_value if fields_map.get("issue_date") else None,
        "extracted_maturity_date": fields_map.get("maturity_date").normalized_value if fields_map.get("maturity_date") else None,
        "external_issue_date": external_record.issue_date if external_record else None,
        "external_maturity_date": external_record.maturity_date if external_record else None,
    }

    # --- Findings ---
    findings: list[dict] = []

    if comp_amount_declared_vs_extracted["status"] == "conflicting":
        findings.append({
            "finding_type": "amount_mismatch_declared_vs_extracted",
            "severity": "high",
            "reasoning": "Declared principal amount conflicts with extracted amount from document",
            "source_evidence": ["declaration", "extraction"],
            "recommended_action": "Requires human review",
        })
    elif comp_amount_declared_vs_extracted["status"] == "unconfirmed":
        findings.append({
            "finding_type": "amount_unconfirmed",
            "severity": "medium",
            "reasoning": "Principal amount could not be compared across sources",
            "source_evidence": ["declaration", "extraction"],
            "recommended_action": "Verify document extraction",
        })

    if comp_amount_extracted_vs_external["status"] == "conflicting":
        findings.append({
            "finding_type": "amount_mismatch_extracted_vs_external",
            "severity": "high",
            "reasoning": "Extracted amount conflicts with external financial evidence",
            "source_evidence": ["extraction", "external"],
            "recommended_action": "Requires human review",
        })
    elif external["status"] == EvidenceStatus.UNAVAILABLE:
        findings.append({
            "finding_type": "external_evidence_unavailable",
            "severity": "medium",
            "reasoning": "External financial evidence is unavailable for this instrument",
            "source_evidence": ["external"],
            "recommended_action": "Proceed with declaration + extraction only",
        })

    if ifsc_check.get("conflicts"):
        findings.append({
            "finding_type": "ifsc_mismatch",
            "severity": "medium",
            "reasoning": "; ".join(ifsc_check["conflicts"]),
            "source_evidence": ["declaration", "external"],
            "recommended_action": "Verify IFSC and bank details",
        })
    if not ifsc_check["format_valid"]:
        findings.append({
            "finding_type": "ifsc_invalid_format",
            "severity": "high",
            "reasoning": f"IFSC '{instrument.ifsc}' has invalid format",
            "source_evidence": ["declaration"],
            "recommended_action": "Correct IFSC before submission",
        })

    result.findings = findings
    if any(f["severity"] == "high" for f in findings):
        result.overall_status = "conflicting"
    elif findings:
        result.overall_status = "requires_human_review"
    elif external["status"] == EvidenceStatus.UNAVAILABLE:
        result.overall_status = "unconfirmed"
    else:
        result.overall_status = "matched"

    return result
