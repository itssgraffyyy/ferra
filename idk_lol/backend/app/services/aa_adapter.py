"""Account Aggregator (AA) compatible term-deposit adapter interface.

Defines a clean interface for fetching term-deposit financial evidence.
Implements a deterministic local mock adapter for offline testing/demos.
Mock data is visibly labeled and never presented as independent proof of FDR
authenticity or AICTE lien status.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.core.exceptions import ExternalServiceError
from app.core.logging import get_logger

logger = get_logger("app.services.aa_adapter")


class TermDepositRecord:
    """Normalized term-deposit response model."""

    def __init__(
        self,
        *,
        deposit_reference: str,
        bank_name: str,
        ifsc: str,
        principal_amount: int,
        currency: str,
        issue_date: str,
        maturity_date: str,
        depositor_name: str,
        status: str,
        data_source: str,
        consent_id: Optional[str] = None,
        lien_registered: bool = False,
        lien_holder: Optional[str] = None,
        raw_response: Optional[dict] = None,
    ) -> None:
        self.deposit_reference = deposit_reference
        self.bank_name = bank_name
        self.ifsc = ifsc
        self.principal_amount = principal_amount
        self.currency = currency
        self.issue_date = issue_date
        self.maturity_date = maturity_date
        self.depositor_name = depositor_name
        self.status = status
        self.data_source = data_source
        self.consent_id = consent_id
        self.lien_registered = lien_registered
        self.lien_holder = lien_holder
        self.raw_response = raw_response or {}
        self.fetched_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "deposit_reference": self.deposit_reference,
            "bank_name": self.bank_name,
            "ifsc": self.ifsc,
            "principal_amount": self.principal_amount,
            "currency": self.currency,
            "issue_date": self.issue_date,
            "maturity_date": self.maturity_date,
            "depositor_name": self.depositor_name,
            "status": self.status,
            "data_source": self.data_source,
            "consent_id": self.consent_id,
            "lien_registered": self.lien_registered,
            "lien_holder": self.lien_holder,
            "fetched_at": self.fetched_at,
            "raw_response": self.raw_response,
        }


class TermDepositAdapter:
    """Abstract interface for term-deposit financial evidence."""

    name: str = "base"

    async def fetch_term_deposit(
        self,
        *,
        deposit_reference: str,
        consent_id: Optional[str] = None,
        customer_id: Optional[str] = None,
    ) -> TermDepositRecord:
        raise NotImplementedError


class LocalMockTermDepositAdapter(TermDepositAdapter):
    """Deterministic local mock adapter. Offline; clearly labeled sandbox data."""

    name = "local_mock"

    FIXTURES: dict[str, dict] = {
        "FDR-2025-GMEC-001": {
            "bank_name": "State Bank of India",
            "ifsc": "SBIN0001234",
            "principal_amount": 500000,
            "currency": "INR",
            "issue_date": "2025-06-15",
            "maturity_date": "2026-06-15",
            "depositor_name": "Government Model Engineering College",
            "status": "active",
            "lien_registered": True,
            "lien_holder": "AICTE",
        },
        "FDR-2025-GMEC-002": {
            "bank_name": "HDFC Bank",
            "ifsc": "HDFC0001234",
            "principal_amount": 300000,
            "currency": "INR",
            "issue_date": "2025-01-10",
            "maturity_date": "2026-01-10",
            "depositor_name": "Government Model Engineering College",
            "status": "active",
            "lien_registered": False,
            "lien_holder": None,
        },
    }

    async def fetch_term_deposit(
        self,
        *,
        deposit_reference: str,
        consent_id: Optional[str] = None,
        customer_id: Optional[str] = None,
    ) -> TermDepositRecord:
        logger.info("aa.mock_fetch", extra={"action": "aa_fetch", "reference": deposit_reference, "adapter": "local_mock"})
        fixture = self.FIXTURES.get(deposit_reference)
        if fixture is None:
            raise ExternalServiceError("local_mock", f"No mock record for deposit reference {deposit_reference}")
        return TermDepositRecord(
            deposit_reference=deposit_reference,
            data_source="local_mock",
            consent_id=consent_id,
            raw_response={"mock": True, "note": "deterministic local fixture"},
            **fixture,
        )


class SetuSandboxTermDepositAdapter(TermDepositAdapter):
    """Setu AA-compatible sandbox adapter (when credentials/onboarding available).

    Never fabricates a successful live sandbox connection.
    """

    name = "setu_sandbox"

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None) -> None:
        self.api_key = api_key
        self.base_url = base_url

    async def fetch_term_deposit(
        self,
        *,
        deposit_reference: str,
        consent_id: Optional[str] = None,
        customer_id: Optional[str] = None,
    ) -> TermDepositRecord:
        if not self.api_key or not self.base_url:
            raise ExternalServiceError("setu_sandbox", "Setu sandbox credentials not configured")
        raise ExternalServiceError("setu_sandbox", "Setu sandbox integration not yet implemented")


def get_adapter(adapter_name: str = "local_mock", **kwargs) -> TermDepositAdapter:
    if adapter_name == "local_mock":
        return LocalMockTermDepositAdapter()
    if adapter_name == "setu_sandbox":
        return SetuSandboxTermDepositAdapter(**kwargs)
    raise ExternalServiceError(adapter_name, "Unknown term-deposit adapter")