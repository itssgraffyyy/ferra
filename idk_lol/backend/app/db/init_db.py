"""Database initialization and development seed data.

Seed data is only loaded when SEED_DATA=true and the tables are empty.
It exists so a fresh local instance is immediately usable for demo/testing.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.session import get_engine
from app.models.user import RoleName, User
from app.models.institution import Institution
from app.models.obligation import SecurityObligation
from app.models.instrument import FinancialInstrument
from app.models.document import Document
from app.models.extraction import ExtractedField
from app.models.policy import RegulatoryPolicyVersion, RegulatoryRule
from app.core.security import hash_password

logger = get_logger("app.db.init_db")


def _seed(db: Session) -> None:
    from app.models.audit import AuditEvent
    from app.models.evidence import EvidenceSource

    if db.query(User).first():
        logger.info("Seed data already present, skipping")
        return

    inst_a = Institution(
        name="Government Model Engineering College",
        code="GMEC01",
        category="Government",
        address="Thrissur, Kerala",
        contact_email="registrar@gmec.example.in",
        status="active",
    )
    inst_b = Institution(
        name="Private Institute of Technology",
        code="PIT02",
        category="Private",
        address="Coimbatore, Tamil Nadu",
        contact_email="registrar@pit.example.in",
        status="active",
    )
    db.add_all([inst_a, inst_b])
    db.flush()

    admin = User(
        email="admin@aictedemo.example.in",
        password_hash=hash_password("AdminPass123!"),
        full_name="AICTE Administrator",
        role=RoleName.AICTE_ADMIN,
        institution_id=None,
        is_active=True,
    )
    officer = User(
        email="officer@aictedemo.example.in",
        password_hash=hash_password("OfficerPass123!"),
        full_name="AICTE Reviewing Officer",
        role=RoleName.AICTE_REVIEWING_OFFICER,
        institution_id=None,
        is_active=True,
    )
    auditor = User(
        email="auditor@aictedemo.example.in",
        password_hash=hash_password("AuditorPass123!"),
        full_name="Security / Audit Reviewer",
        role=RoleName.SECURITY_AUDIT_REVIEWER,
        institution_id=None,
        is_active=True,
    )
    college_user = User(
        email="registrar@gmec.example.in",
        password_hash=hash_password("CollegePass123!"),
        full_name="College Registrar",
        role=RoleName.INSTITUTION_USER,
        institution_id=inst_a.id,
        is_active=True,
    )
    db.add_all([admin, officer, auditor, college_user])
    db.flush()

    obligation = SecurityObligation(
        institution_id=inst_a.id,
        reference="OBL-GMEC-2025-001",
        programme_type="Engineering & Technology",
        programme_level="Undergraduate",
        deposit_amount_required=500000,
        currency="INR",
        status="active",
        regulation_source="AICTE Approval Process Handbook 2025-26 (provisional - pending verification)",
    )
    db.add(obligation)
    db.flush()

    instrument = FinancialInstrument(
        obligation_id=obligation.id,
        instrument_type="FDR",
        reference_number="FDR-2025-GMEC-001",
        bank_name="State Bank of India",
        branch="Thrissur Main Branch",
        ifsc="SBIN0001234",
        principal_amount=500000,
        currency="INR",
        issue_date="2025-06-15",
        maturity_date="2026-06-15",
        depositor_name="Government Model Engineering College",
        status="submitted",
    )
    db.add(instrument)
    db.flush()

    document = Document(
        instrument_id=instrument.id,
        uploaded_by=college_user.id,
        original_filename="fdr_sbin_2025_001.pdf",
        stored_path=f"documents/{instrument.id}/v1/fdr_sbin_2025_001.pdf",
        content_type="application/pdf",
        size_bytes=0,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        processing_status="pending",
    )
    db.add(document)
    db.flush()

    extracted = ExtractedField(
        document_id=document.id,
        field_name="bank_name",
        extracted_value="State Bank of India",
        normalized_value="State Bank of India",
        confidence=None,
        source_page=1,
        extraction_method="simulated-dev-fixture",
        processing_status="extracted",
        warnings=["Development fixture - not real OCR output"],
    )
    db.add(extracted)
    db.flush()

    audit = AuditEvent(
        actor_user_id=college_user.id,
        institution_id=inst_a.id,
        action="instrument.submitted",
        target_type="financial_instrument",
        target_id=instrument.id,
        metadata={"instrument_reference": instrument.reference_number},
    )
    db.add(audit)

    db.commit()
    logger.info("Seed data loaded")


def init_db() -> None:
    from app.db.base import Base

    engine = get_engine()
    Base.metadata.create_all(engine)
    from sqlalchemy.orm import Session

    with Session(engine) as db:
        settings = get_settings()
        if settings.SEED_DATA:
            _seed(db)