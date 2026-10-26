"""Compliance finding schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ComplianceFindingBase(BaseModel):
    instrument_id: str
    rule_id: str | None = None
    policy_version: str | None = None
    finding_type: str = Field(min_length=1, max_length=100)
    severity: str = Field(min_length=1, max_length=50)
    status: str = "open"
    inputs_used: str | None = None
    source_evidence: str | None = None
    evaluation_result: str | None = None
    reasoning: str | None = None
    outstanding_information: str | None = None
    recommended_action: str | None = None


class ComplianceFindingCreate(ComplianceFindingBase):
    pass


class ComplianceFindingUpdate(BaseModel):
    rule_id: str | None = None
    policy_version: str | None = None
    finding_type: str | None = None
    severity: str | None = None
    status: str | None = None
    inputs_used: str | None = None
    source_evidence: str | None = None
    evaluation_result: str | None = None
    reasoning: str | None = None
    outstanding_information: str | None = None
    recommended_action: str | None = None


class ComplianceFindingRead(ComplianceFindingBase):
    id: str

    class Config:
        from_attributes = True