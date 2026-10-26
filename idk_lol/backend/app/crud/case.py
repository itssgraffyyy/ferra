"""CRUD operations for exception/resolution cases."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.case import ExceptionResolutionCase
from app.schemas.case import ExceptionResolutionCaseCreate, ExceptionResolutionCaseUpdate


class CRUDExceptionResolutionCase(CRUDBase[ExceptionResolutionCase, ExceptionResolutionCaseCreate, ExceptionResolutionCaseUpdate]):
    pass


exception_resolution_case = CRUDExceptionResolutionCase(ExceptionResolutionCase)