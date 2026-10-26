"""CRUD operations for regulatory policies and rules."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.policy import RegulatoryPolicyVersion, RegulatoryRule
from app.schemas.policy import RegulatoryPolicyVersionCreate, RegulatoryPolicyVersionUpdate, RegulatoryRuleCreate, RegulatoryRuleUpdate


class CRUDRegulatoryPolicyVersion(CRUDBase[RegulatoryPolicyVersion, RegulatoryPolicyVersionCreate, RegulatoryPolicyVersionUpdate]):
    pass


class CRUDRegulatoryRule(CRUDBase[RegulatoryRule, RegulatoryRuleCreate, RegulatoryRuleUpdate]):
    def get_by_rule_id(self, db: Session, *, rule_id: str) -> RegulatoryRule | None:
        return db.query(RegulatoryRule).filter(RegulatoryRule.rule_id == rule_id).first()


regulatory_policy_version = CRUDRegulatoryPolicyVersion(RegulatoryPolicyVersion)
regulatory_rule = CRUDRegulatoryRule(RegulatoryRule)