"""How verdicts become numbers, and how they are not allowed to.

The score is a bounded subtraction from 100.  Nothing else in the package is
allowed to touch it, which is what keeps three overlapping observations of the
same weakness from paying for it three times:

1. each rule returns at most one verdict per ``property_key``;
2. verdicts about the same property are reduced to the strongest one, and the
   losers stay in the report as ``PASS`` entries that name the winner;
3. duplicates of the same ``(rule_id, dedup_key)`` collapse to their worst
   member;
4. the surviving deduction of one category can never exceed that category's
   weight, so no single area can wipe out the whole score.

::

    base_points            rule x status        (policy.TIER_BASE_POINTS / rule table)
      x STATUS_FACTORS[status]                  FAIL 1.0, WARNING 0.4
      x evidence_factor(status, confidence)     OBSERVED 1.0, CONFIGURED 0.85,
                                                INFERRED 0.5 x confidence, NOT_VERIFIABLE 0.0
      = points_deducted, capped at category weight x 100

    security_score = 100 - sum(capped category deductions)
    risk_score     = 100 - security_score

``NOT_VERIFIABLE`` appears twice in that formula and still cannot move the
number: its status factor is 0 and its evidence factor is 0.  It lowers
``evidence_coverage`` instead, which is the only honest place for it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any

from .context import AssessmentContext
from .evidence import EvidenceStatus, count_evidence, strongest
from .models import CategoryScore, FindingStatus, RiskLevel, SecurityCategory, SecurityFinding, Severity
from .policy import (
    CATEGORY_WEIGHTS,
    COVERAGE_WEIGHTS,
    EVIDENCE_FACTORS,
    RISK_BANDS,
    STATUS_FACTORS,
    TIER_BASE_POINTS,
    evidence_factor,
    risk_level,
)
from .rules import Rule, RuleVerdict


@dataclass(frozen=True)
class ScoredFinding:
    """One rule's contribution, with the arithmetic that produced it.

    ``property_key`` is the fact the rule decided (``"child_encryption"``), and
    ``property_status`` is how well that fact could be established: it is what
    ``evidence_coverage`` averages over, so a rule that had to give up lowers the
    coverage of the assessment instead of its score.
    """

    finding: SecurityFinding
    property_key: str
    property_status: FindingStatus
    base_points: float
    status_factor: float
    evidence_weight: float
    suppressed_by: str = ""

    @property
    def suppressed(self) -> bool:
        return bool(self.suppressed_by)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding.to_dict(),
            "property_key": self.property_key,
            "property_status": self.property_status.value,
            "base_points": self.base_points,
            "status_factor": self.status_factor,
            "evidence_weight": self.evidence_weight,
            "suppressed_by": self.suppressed_by,
        }


@dataclass(frozen=True)
class ScoringResult:
    """Everything the engine needs to publish a score."""

    security_score: float
    risk_score: float
    risk_level: RiskLevel
    findings: tuple[SecurityFinding, ...]
    categories: tuple[CategoryScore, ...]
    evidence_counts: dict[str, int]
    evidence_coverage: float
    scored: tuple[ScoredFinding, ...]

    def rule_ledger(self) -> list[dict[str, Any]]:
        """One row per rule, including the rules that were overruled.

        The ledger exists so a reader can reconcile the score by hand: every rule
        appears with the property it decided, the status it claimed, the points it
        cost and, when it was overruled, the rule that won.
        """
        rows: list[dict[str, Any]] = []
        for entry in self.scored:
            finding = entry.finding
            rows.append(
                {
                    "rule_id": finding.rule_id,
                    "category": finding.category.value,
                    "property_key": entry.property_key,
                    "verdict": finding.status.value,
                    "property_status": entry.property_status.value,
                    "severity": finding.severity.value,
                    "evidence_status": finding.evidence_status.value,
                    "base_points": entry.base_points,
                    "status_factor": entry.status_factor,
                    "evidence_weight": entry.evidence_weight,
                    "points_deducted": finding.points_deducted,
                    "suppressed_by": entry.suppressed_by,
                    "dedup_key": finding.dedup_key,
                }
            )
        return rows


def verdict_evidence_status(verdict: RuleVerdict) -> EvidenceStatus:
    """Provenance of a verdict: the strongest reference it carries.

    A verdict that cites both the capture and the configuration is treated as
    observed, because the capture alone would support it.
    """
    return strongest(*(ref.status for ref in verdict.evidence))


def base_points_for(rule: Rule, verdict: RuleVerdict) -> float:
    """Unweighted cost of a verdict, before status and provenance factors.

    A verdict that names a policy tier costs what that tier costs everywhere in
    the report, so a deprecated cipher is not cheaper in the key-exchange section
    than in the cryptography section.  Structural verdicts (no PFS at all, a
    lifetime nobody stated) carry their own table on the rule.
    """
    if verdict.tier is not None:
        return TIER_BASE_POINTS[verdict.tier]
    return rule.points.get(verdict.status, 0.0)


#: Which verdict settles a property.  The weakest observation about one fact is
#: the one that has to be reported: a tunnel that is "configured with PFS" and
#: "observed without PFS" does not have PFS.
PROPERTY_STRENGTH: dict[FindingStatus, int] = {
    FindingStatus.PASS: 0,
    FindingStatus.NOT_VERIFIABLE: 1,
    FindingStatus.WARNING: 2,
    FindingStatus.FAIL: 3,
}


def apply_rule(rule: Rule, context: AssessmentContext) -> ScoredFinding:
    """Run one rule and price its verdict.

    Points only exist here: ``rule.evaluate`` says what it was, and the
    multiplication below decides what it is worth.  A verdict that cites no
    evidence lands on ``NOT_VERIFIABLE`` and costs nothing whichever status it
    claimed, so rules cannot manufacture a deduction by asserting one.
    """
    verdict = rule.evaluate(context)
    evidence_status = verdict_evidence_status(verdict)
    base = base_points_for(rule, verdict)
    status_factor = STATUS_FACTORS[verdict.status]
    weight = evidence_factor(evidence_status, verdict.confidence)
    points = 0.0 if status_factor == 0.0 or weight == 0.0 else round(base * status_factor * weight, 2)
    confidence = max(0.0, min(1.0, verdict.confidence))
    finding = SecurityFinding(
        rule_id=rule.rule_id,
        category=rule.category,
        title=rule.title,
        status=verdict.status,
        severity=verdict.severity,
        evidence_status=evidence_status,
        confidence=round(confidence, 4),
        explanation=verdict.explanation,
        points_deducted=points,
        recommendation=verdict.recommendation,
        dedup_key=verdict.dedup_key or rule.rule_id,
        evidence=verdict.evidence,
        references=tuple(rule.references) + tuple(verdict.references),
        details=verdict.details,
    )
    return ScoredFinding(
        finding=finding,
        property_key=verdict.property_key or rule.property_key,
        property_status=verdict.property_status or verdict.status,
        base_points=round(base, 2),
        status_factor=status_factor,
        evidence_weight=round(weight, 4),
    )


def _collapse_duplicates(entries: Sequence[ScoredFinding]) -> list[ScoredFinding]:
    """Keep one entry per ``(rule_id, dedup_key)``: the most expensive one.

    A rule that reports the same weakness on four SAs (``dedup_key`` left at its
    default) found one weakness, not four: an attacker does not have to break four
    tunnels that all use the same cipher.  A rule that reports the same *kind* of
    weakness on four distinguishable subjects (``dedup_key`` naming each SPI) keeps
    all four, because each one is separately observable.
    """
    best: dict[tuple[str, str], ScoredFinding] = {}
    for entry in entries:
        key = (entry.finding.rule_id, entry.finding.dedup_key)
        current = best.get(key)
        if current is None or entry.finding.points_deducted > current.finding.points_deducted:
            best[key] = entry
    return list(best.values())


def _suppress(entry: ScoredFinding, winner_rule_id: str) -> ScoredFinding:
    """Demote a losing duplicate to an informational trace entry.

    The finding is not deleted: an auditor comparing the rule catalogue with the
    report should see that the rule fired and why its points were not counted.
    """
    finding = entry.finding
    note = f"not counted separately: {winner_rule_id} settles the same property more pessimistically"
    return ScoredFinding(
        finding=replace(
            finding,
            status=FindingStatus.PASS,
            severity=Severity.INFO,
            points_deducted=0.0,
            explanation=f"{finding.explanation} ({note})",
        ),
        property_key=entry.property_key,
        property_status=entry.property_status,
        base_points=entry.base_points,
        status_factor=entry.status_factor,
        evidence_weight=entry.evidence_weight,
        suppressed_by=winner_rule_id,
    )


def _settle_properties(entries: Sequence[ScoredFinding]) -> list[ScoredFinding]:
    """Let exactly one rule per property cost points, keeping catalogue order.

    This is what stops ``CRYPTO-002`` (a CBC cipher offers no integrity on its
    own) and ``CRYPTO-003`` (the child SA cipher is weak) from charging twice for
    one bad cipher: they decide the same property, so the more severe verdict is
    kept, the other becomes a trace entry, and the reader can follow the choice.
    """
    deduped = _collapse_duplicates(entries)
    winners: dict[str, ScoredFinding] = {}
    for entry in deduped:
        current = winners.get(entry.property_key)
        if current is None or PROPERTY_STRENGTH[entry.finding.status] > PROPERTY_STRENGTH[current.finding.status]:
            winners[entry.property_key] = entry
    settled: list[ScoredFinding] = []
    for entry in deduped:
        winner = winners[entry.property_key]
        settled.append(
            entry
            if winner.finding.rule_id == entry.finding.rule_id
            else _suppress(entry, winner.finding.rule_id)
        )
    return settled


def _category_scores(entries: Sequence[ScoredFinding]) -> tuple[CategoryScore, ...]:
    """Per-category totals, each capped at its weight so one area cannot dominate.

    The cap is per category and never per finding, so the ledger still shows what
    the rules added up before the model decided how much of it to charge.
    """
    scores: list[CategoryScore] = []
    for category in SecurityCategory:
        weight = CATEGORY_WEIGHTS[category]
        ceiling = round(weight * 100.0, 2)
        mine = tuple(entry for entry in entries if entry.finding.category is category)
        raw = round(sum(entry.finding.points_deducted for entry in mine), 2)
        deducted = min(raw, ceiling)
        status_counts: dict[str, int] = {}
        for entry in mine:
            key = entry.finding.status.value
            status_counts[key] = status_counts.get(key, 0) + 1
        scores.append(
            CategoryScore(
                category=category,
                weight=weight,
                max_score=ceiling,
                deducted=round(deducted, 2),
                score=round(ceiling - deducted, 2),
                status_counts=status_counts,
                assessed_rules=sum(1 for entry in mine if entry.finding.status is not FindingStatus.NOT_VERIFIABLE),
                unverified_rules=sum(1 for entry in mine if entry.finding.status is FindingStatus.NOT_VERIFIABLE),
                coverage=round(
                    sum(COVERAGE_WEIGHTS[entry.finding.evidence_status] for entry in mine) / max(1, len(mine)),
                    4,
                ),
                findings=tuple(entry.finding for entry in mine),
            )
        )
    return tuple(scores)


def score_rules(context: AssessmentContext, rules: Sequence[Rule]) -> ScoringResult:
    """Apply ``rules`` to ``context`` and turn the verdicts into a score.

    The only function in the package that produces a number, which is what makes
    the whole scoring model auditable: read this function and you have read every
    rule about how a capture becomes a score.
    """
    settled = _settle_properties([apply_rule(rule, context) for rule in rules])
    categories = _category_scores(settled)
    deducted = round(sum(category.deducted for category in categories), 2)
    security_score = round(max(0.0, min(100.0, 100.0 - deducted)), 2)
    settled_count = max(1, len(settled))
    return ScoringResult(
        security_score=security_score,
        risk_score=round(100.0 - security_score, 2),
        risk_level=risk_level(security_score),
        findings=tuple(entry.finding for entry in settled),
        categories=categories,
        evidence_counts=count_evidence(ref for entry in settled for ref in entry.finding.evidence),
        evidence_coverage=round(
            sum(COVERAGE_WEIGHTS[entry.finding.evidence_status] for entry in settled) / settled_count, 4
        ),
        scored=tuple(settled),
    )


def deduction_model() -> dict[str, Any]:
    """The arithmetic, as data, for the generated reference and for tests."""
    return {
        "formula": "100 - sum(min(category_total, weight * 100))",
        "point_formula": "base_points * status_factor * evidence_factor",
        "category_weights": {category.value: weight for category, weight in CATEGORY_WEIGHTS.items()},
        "status_factors": {status.value: factor for status, factor in STATUS_FACTORS.items()},
        "evidence_factors": {status.value: factor for status, factor in EVIDENCE_FACTORS.items()},
        "tier_base_points": {tier.value: points for tier, points in TIER_BASE_POINTS.items()},
        "coverage_weights": {status.value: weight for status, weight in COVERAGE_WEIGHTS.items()},
        "risk_bands": [{"min_score": floor, "risk": level.value} for floor, level in RISK_BANDS],
        "rules": [
            "one finding per (rule_id, dedup_key): the most expensive one",
            "one finding per property_key pays: the most severe one decides",
            "a category deduction is capped at weight * 100",
            "NOT_VERIFIABLE never deducts and never counts as coverage",
        ],
    }



