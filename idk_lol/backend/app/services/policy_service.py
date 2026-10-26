"""Versioned AICTE regulatory policy engine.

Deterministic and explainable. Rules are NOT decided by an LLM. Each rule
carries a validation_status; provisional/unsupported rules route for human
review.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Optional

from app.core.exceptions import ExternalServiceError
from app.core.logging import get_logger
from app.crud.policy import regulatory_policy_version as policy_crud, regulatory_rule as rule_crud
from app.models.policy import RegulatoryPolicyVersion, RegulatoryRule, ValidationStatus

logger = get_logger("app.services.policy_service")


def _to_amount(value) -> Optional[Decimal]:
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None


def _parse_json(text: Optional[str]) -> dict:
    if not text:
        return {}
    import json
    try:
        return json.loads(text)
    except Exception:
        return {}


class PolicyEvaluationResult:
    def __init__(self) -> None:
        self.rule_id: Optional[str] = None
        self.policy_version: Optional[str] = None
        self.applicable: bool = False
        self.passed: bool = False
        self.reasoning: str = ""
        self.inputs_used: dict = {}
        self.outstanding_information: list[str] = []
        self.recommended_action: str = ""
        self.validation_status: str = "provisional"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "policy_version": self.policy_version,
            "applicable": self.applicable,
            "passed": self.passed,
            "reasoning": self.reasoning,
            "inputs_used": self.inputs_used,
            "outstanding_information": self.outstanding_information,
            "recommended_action": self.recommended_action,
            "validation_status": self.validation_status,
        }


def evaluate_instrument(db, instrument) -> list[PolicyEvaluationResult]:
    """Evaluate all applicable regulatory rules for an instrument. Returns results."""
    results: list[PolicyEvaluationResult] = []

    obligation = instrument.obligation
    if not obligation:
        res = PolicyEvaluationResult()
        res.rule_id = "NO_OBLIGATION"
        res.policy_version = None
        res.applicable = True
        res.passed = False
        res.reasoning = "No security obligation registered for this instrument's institution/context"
        res.outstanding_information = ["Register a security obligation"]
        res.recommended_action = "Register security obligation before compliance evaluation"
        res.validation_status = ValidationStatus.VALIDATED
        results.append(res)
        return results

    # Get current policy version
    policy = (
        db.query(RegulatoryPolicyVersion)
        .filter(RegulatoryPolicyVersion.is_current == True)  # noqa: E712
        .first()
    )
    if not policy:
        policy = db.query(RegulatoryPolicyVersion).first()
    if not policy:
        res = PolicyEvaluationResult()
        res.rule_id = "NO_POLICY"
        res.applicable = True
        res.passed = False
        res.reasoning = "No regulatory policy version loaded"
        res.recommended_action = "Load AICTE regulatory policy version"
        results.append(res)
        return results

    rules = rule_crud.get_multi(db)
    rules = [r for r in rules if r.policy_version_id == policy.id]

    for rule in rules:
        res = _evaluate_single_rule(rule, policy, obligation, instrument)
        results.append(res)

    return results


def _evaluate_single_rule(rule: RegulatoryRule, policy: RegulatoryPolicyVersion, obligation, instrument) -> PolicyEvaluationResult:
    res = PolicyEvaluationResult()
    res.rule_id = rule.rule_id
    res.policy_version = f"{policy.code} v{policy.version}"
    res.validation_status = rule.validation_status

    app_cond = _parse_json(rule.applicability_conditions)
    applicable = True
    if app_cond.get("programme_type") and obligation.programme_type != app_cond["programme_type"]:
        applicable = False
    if app_cond.get("programme_level") and obligation.programme_level != app_cond["programme_level"]:
        applicable = False
    if app_cond.get("institution_category"):
        inst = obligation.institution
        cat = inst.category if inst else None
        if cat != app_cond["institution_category"]:
            applicable = False
    res.applicable = applicable
    res.inputs_used = {
        "programme_type": obligation.programme_type,
        "programme_level": obligation.programme_level,
        "institution_category": obligation.institution.category if obligation.institution else None,
        "deposit_amount_required": obligation.deposit_amount_required,
        "instrument_amount": instrument.principal_amount,
    }

    if not applicable:
        res.passed = False
        res.reasoning = "Rule not applicable to this institution/programme context"
        res.recommended_action = "No action required"
        return res

    required = _to_amount(rule.deposit_amount_required or obligation.deposit_amount_required)
    instrument_amount = _to_amount(instrument.principal_amount)

    exemptions = _parse_json(rule.exemptions)
    adjustments = _parse_json(rule.adjustments)

    is_exempt = False
    if exemptions.get("eligible_existing_institution") and obligation.institution:
        is_exempt = False

    if is_exempt:
        res.passed = True
        res.reasoning = "Institution is exempt from deposit obligation under this rule"
        res.recommended_action = "Document exemption evidence"
        return res

    if required is None:
        res.passed = False
        res.reasoning = "Rule has no deposit amount defined"
        res.outstanding_information = ["Define deposit amount in rule"]
        res.recommended_action = "Route for human review"
        return res

    if instrument_amount is None:
        res.passed = False
        res.reasoning = "Instrument principal amount not declared"
        res.outstanding_information = ["Declare instrument principal amount"]
        res.recommended_action = "Complete instrument declaration"
        return res

    adjusted_required = required
    if adjustments.get("private_leased_property") and obligation.institution and obligation.institution.category == "Private":
        adj_pct = Decimal(str(adjustments.get("private_leased_property_percent", 0)))
        adjusted_required = required * (1 - adj_pct / 100)
        res.reasoning += f"Applied private leased-property adjustment of {adj_pct}%. "

    if instrument_amount >= adjusted_required:
        res.passed = True
        res.reasoning += f"Instrument amount {instrument_amount} meets required {adjusted_required}."
    else:
        res.passed = False
        res.reasoning += f"Instrument amount {instrument_amount} is below required {adjusted_required}."

    if res.validation_status in (ValidationStatus.PROVISIONAL, ValidationStatus.UNSUPPORTED):
        res.recommended_action = "Route for human review (rule not validated against official source)"
    else:
        res.recommended_action = "No action required" if res.passed else "Correct deposit amount"

    return res
