"""Regulatory policy evaluation endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status

from app.api.deps import get_current_user, get_db, require_permission
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.crud.instrument import financial_instrument as instrument_crud
from app.services.policy_service import evaluate_instrument

logger = get_logger("app.api.endpoints.policy")

router = APIRouter(tags=["policy"])


@router.get("/instruments/{instrument_id}/policy-evaluation")
def get_policy_evaluation(
    instrument_id: str,
    db=Depends(get_db),
    current_user=Depends(require_permission("policy:read")),
):
    from app.core.exceptions import NotFoundError as _NFE

    instrument = instrument_crud.get(db, instrument_id)
    if not instrument:
        raise _NFE("financial_instrument", instrument_id)
    results = evaluate_instrument(db, instrument)
    return [r.to_dict() for r in results]