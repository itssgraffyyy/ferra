# FDR Sentinel domain models

# Import all models so SQLAlchemy metadata is fully populated (needed for
# Alembic autogenerate and `Base.metadata.create_all`).
from app.models.audit import AuditEvent  # noqa: F401
from app.models.case import ExceptionResolutionCase  # noqa: F401
from app.models.document import Document  # noqa: F401
from app.models.evidence import EvidenceSource  # noqa: F401
from app.models.extraction import ExtractedField  # noqa: F401
from app.models.finding import ComplianceFinding  # noqa: F401
from app.models.institution import Institution  # noqa: F401
from app.models.instrument import FinancialInstrument  # noqa: F401
from app.models.obligation import SecurityObligation  # noqa: F401
from app.models.ocr_job import OcrJob  # noqa: F401
from app.models.policy import RegulatoryPolicyVersion, RegulatoryRule  # noqa: F401
from app.models.user import Role, RolePermission, User, UserRole  # noqa: F401