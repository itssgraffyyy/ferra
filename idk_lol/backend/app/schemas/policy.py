"""Regulatory policy and rule schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RegulatoryPolicyVersionBase(BaseModel):
    code: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=50)
    effective_date: str | None = None
    source_reference: str | None = None
    is_current: bool = False
    notes: str | None = None


class RegulatoryPolicyVersionCreate(RegulatoryPolicyVersionBase):
    pass


class RegulatoryPolicyVersionUpdate(BaseModel):
    code: str | None = None
    version: str | None = None
    effective_date: str | None = None
    source_reference: str | None = None
    is_current: bool | None = None
    notes: str | None = None


class RegulatoryPolicyVersionRead(RegulatoryPolicyVersionBase):
    id: str

    class Config:
        from_attributes = True


class RegulatoryRuleBase(BaseModel):
    rule_id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=255)
    official_source: str | None = None
    applicability_conditions: str | None = None
    institution_category: str | None = None
    programme_type: str | None = None
    programme_level: str | None = None
    deposit_amount_required: int | None = Field(default=None, ge=0)
    currency: str = "INR"
    exemptions: str | None = None
    adjustments: str | None = None
    evidence_requirements: str | None = None
    evaluation_logic: str | None = None
    rule_version: str = "1.0"
    validation_status: str = "provisional"


class RegulatoryRuleCreate(RegulatoryRuleBase):
    policy_version_id: str


class RegulatoryRuleUpdate(BaseModel):
    rule_id: str | None = None
    title: str | None = None
    official_source: str | None = None
    applicability_conditions: str | None = None
    institution_category: str | None = None
    programme_type: str | None = None
    programme_level: str | None = None
    deposit_amount_required: int | None = Field(default=None, ge=0)
    currency: str | None = None
    exemptions: str | None = None
    adjustments: str | None = None
    evidence_requirements: str | None = None
    evaluation_logic: str | None = None
    rule_version: str | None = None
    validation_status: str | None = None


class RegulatoryRuleRead(RegulatoryRuleBase):
    id: str
    policy_version_id: str

    class Config:
        from_attributes = True