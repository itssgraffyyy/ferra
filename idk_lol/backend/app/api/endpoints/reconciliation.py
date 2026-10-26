"""Four-source reconciliation endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status

from app.api.deps import get_current_user, get_db, require_permission
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.crud.instrument import financial_instrument as instrument_crud
from app.services.reconciliation_service import reconcile_instrument

logger = get_logger("app.api.endpoints.reconciliation")

router = APIRouter(tags=["reconciliation"])


@router.get("/instruments/{instrument_id}/reconciliation")
def get_reconciliation(
    instrument_id: str,
    db=Depends(get_db),
    current_user=Depends(require_permission("reconciliation:read")),
):
    instrument = instrument_crud.get(db, instrument_id)
    if not instrument:
        raise NotFoundError("financial_instrument", instrument_id)
    result = reconcile_instrument(db, instrument_id)
    return result.to_dict()