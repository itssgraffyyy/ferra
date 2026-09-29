"""The rules: one question about the capture, one verdict, one piece of evidence.

Nothing in this module computes a score, reads a file, or looks at raw JSON.  A
rule receives an :class:`~fera.security.context.AssessmentContext`, answers one
question about it, and hands back a :class:`RuleVerdict` saying what it found,
how sure it is and - crucially - *how it knows*.  What a verdict costs is decided
in :mod:`fera.security.scoring`, which is what keeps two rules that notice the
same weakness from charging for it twice.

Three conventions run through the catalogue:

* **A rule states its limits.**  If the capture cannot answer the question the
  verdict is ``NOT_VERIFIABLE`` with a reason, not a guess dressed up as a pass.
* **Offered is not negotiated.**  An algorithm merely present in an offer is a
  downgrade surface (``WARNING``); only what a peer actually selected is a
  failure.  A passive capture usually cannot see the selection, because IKEv2
  returns it encrypted, and the finding says so.
* **Severity comes from the policy table.**  A rule does not invent how bad 3DES
  is; it looks the algorithm up and reports the tier the baseline assigned.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from .context import AlgorithmUse, AssessmentContext
from .evidence import EvidenceRef, EvidenceStatus
from .models import SEVERITY_RANK, FindingStatus, SecurityCategory, Severity
from .policy import (
    CHILD_LIFETIME,
    IKE_LIFETIME,
    METADATA_THRESHOLDS,
    MIN_PACKETS_FOR_SEQUENCE_ANALYSIS,
    POLICY_ID,
    TIER_SEVERITY,
    AlgorithmPolicy,
    PolicyTier,
    aead_tag_bits,
    dh_policy,
    encryption_policy,
    integrity_policy,
    is_aead,
    prf_policy,
    requires_separate_integrity,
)

#: A rule's decision function.
Check = Callable[[AssessmentContext], "RuleVerdict"]
#: Whether a rule is meaningful for a given capture at all.
Applicability = Callable[[AssessmentContext], bool]

#: Cost of a structural verdict where no algorithm tier applies: a missing
#: property is not the same weakness as a weak one, so it carries its own numbers.
#: Only :mod:`fera.security.scoring` reads this table.
STANDARD_POINTS: Mapping[FindingStatus, float] = {
    FindingStatus.FAIL: 14.0,
    FindingStatus.WARNING: 5.0,
    FindingStatus.PASS: 0.0,
    FindingStatus.NOT_VERIFIABLE: 0.0,
}

#: Verdicts that exist to be reported and never to be charged for.
INFORMATIONAL_POINTS: Mapping[FindingStatus, float] = {
    FindingStatus.FAIL: 0.0,
    FindingStatus.WARNING: 0.0,
    FindingStatus.PASS: 0.0,
    FindingStatus.NOT_VERIFIABLE: 0.0,
}

#: A failure is never merely informational: a rule that forgets to pick a
#: severity gets this floor instead of a report that reads "critical, info".
FAIL_SEVERITY_FLOOR = Severity.MEDIUM

#: Order of weakness of the tiers, so "worst of these policies" is defined.
TIER_RANK: dict[PolicyTier, int] = {
    PolicyTier.RECOMMENDED: 0,
    PolicyTier.ACCEPTABLE: 1,
    PolicyTier.UNKNOWN: 2,
    PolicyTier.DEPRECATED: 3,
    PolicyTier.FORBIDDEN: 4,
}


@dataclass(frozen=True)
class RuleVerdict:
    """What a rule found, with no notion of what the finding is worth.

    ``tier`` lets a verdict borrow its cost from the shared tier table so that a
    deprecated cipher costs the same wherever it appears.  ``property_key`` names
    the fact the rule decided; when two rules name the same fact, scoring keeps
    the more severe verdict and reports the other as covered by it.  Set
    ``property_status`` when the verdict's own status is not a statement about how
    well the property was established: an unknown algorithm cites an observed
    name and still leaves the property unassessed.
    """

    status: FindingStatus
    explanation: str
    severity: Severity = Severity.INFO
    evidence: tuple[EvidenceRef, ...] = ()
    recommendation: str = ""
    tier: PolicyTier | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    references: tuple[str, ...] = ()
    property_key: str | None = None
    property_status: FindingStatus | None = None
    dedup_key: str = ""
    confidence: float = 1.0


def _always(_context: AssessmentContext) -> bool:
    return True



@dataclass(frozen=True)
class Rule:
    """One check, its identity, and the vocabulary it reports in."""

    rule_id: str
    category: SecurityCategory
    title: str
    summary: str
    check: Check
    property_key: str = ""
    #: A dict default is rejected by ``dataclass``, hence the factory: the
    #: catalogue shares one immutable table per point class.
    points: Mapping[FindingStatus, float] = field(default_factory=lambda: STANDARD_POINTS)
    references: tuple[str, ...] = ()
    applies: Applicability = _always

    def evaluate(self, context: AssessmentContext) -> RuleVerdict:
        """Run the check and stamp in the rule's identity defaults."""
        verdict = self.check(context)
        severity = verdict.severity
        if verdict.status is FindingStatus.FAIL and SEVERITY_RANK[severity] < SEVERITY_RANK[FAIL_SEVERITY_FLOOR]:
            severity = FAIL_SEVERITY_FLOOR
        return replace(
            verdict,
            severity=severity,
            property_key=verdict.property_key or self.property_key,
        )

    def applies_to(self, context: AssessmentContext) -> bool:
        """Whether this rule says anything meaningful about ``context``."""
        return self.applies(context)

    def describe(self) -> dict[str, Any]:
        """Catalogue entry, consumed by the generated policy reference."""
        return {
            "rule_id": self.rule_id,
            "category": self.category.value,
            "title": self.title,
            "summary": self.summary,
            "property_key": self.property_key,
            "points": {status.value: points for status, points in self.points.items()},
            "references": list(self.references),
        }


def _worst(policies: Iterable[AlgorithmPolicy]) -> AlgorithmPolicy:
    """The weakest of a set of judged algorithms - the one that decides."""
    return max(policies, key=lambda item: (TIER_RANK[item.tier], item.name))


def _names(uses: Sequence[AlgorithmUse]) -> str:
    """Readable list of the algorithms a verdict is about."""
    return ", ".join(use.name for use in uses) or "none observed"


def _ref(status: EvidenceStatus, source: str, detail: str, **details: Any) -> tuple[EvidenceRef, ...]:
    """One-element evidence tuple, spelled the same way in every rule."""
    return (EvidenceRef(status=status, source=source, detail=detail, details=details),)


#: Argument names :func:`_ref` already owns.  A rule that spreads a summary into
#: the keyword arguments must not collide with them (``metadata_summary`` has a
#: ``source`` key of its own, for instance).
_REF_RESERVED = frozenset({"status", "source", "detail", "details"})


def _unassessed(subject: str, reason: str) -> RuleVerdict:
    """The verdict for "this capture cannot answer the question"."""
    return RuleVerdict(
        status=FindingStatus.NOT_VERIFIABLE,
        severity=Severity.INFO,
        explanation=f"{subject} could not be assessed: {reason}",
        evidence=_ref(EvidenceStatus.NOT_VERIFIABLE, "assessment.evidence", reason),
        property_status=FindingStatus.NOT_VERIFIABLE,
    )


def _settled(context: AssessmentContext, candidates: int) -> bool:
    """Whether what we see is the negotiated choice rather than an offer set.

    One proposal means the peer had nothing else to choose from, so what we saw is
    what was used.  Several proposals plus an observable selection (an unprotected
    exchange carrying a reply) is the other case.  Anything else is an offer, and
    an offer only proves that a weaker option was *available*.
    """
    return candidates <= 1 or context.selection_observable


# ---------------------------------------------------------------------------
# Algorithm strength (the policy tables do the judging, the rules only look up)
# ---------------------------------------------------------------------------
def _strength_verdict(
    context: AssessmentContext,
    *,
    subject: str,
    uses: Sequence[AlgorithmUse],
    evidence: EvidenceStatus,
    source: str,
    judge: Callable[[str], AlgorithmPolicy],
    missing_reason: str,
    recommendation: str,
) -> RuleVerdict:
    """Judge the algorithms in effect for one property against the policy tables.

    ``judge`` is the lookup that assigns a tier (encryption, integrity, PRF or DH
    group).  When several algorithms are in play the weakest one decides, because
    an offer that contains a weak option is exactly the option a downgrade attack
    reaches for.
    """
    if not uses:
        return _unassessed(subject, missing_reason)
    policies = [judge(use.name) for use in uses]
    worst = _worst(policies)
    refs = _ref(evidence, source, f"{subject}: {_names(uses)}", algorithms=[use.name for use in uses])
    details = {
        "algorithms": [use.to_dict() for use in uses],
        "tier": worst.tier.value,
        "selection_observable": context.selection_observable,
    }
    if worst.tier is PolicyTier.UNKNOWN:
        return RuleVerdict(
            status=FindingStatus.NOT_VERIFIABLE,
            explanation=(
                f"{subject} offered {worst.name}, which has no entry in the {POLICY_ID} baseline; the name is "
                "reported as seen and deliberately not judged"
            ),
            evidence=refs,
            tier=worst.tier,
            details=details,
            property_status=FindingStatus.NOT_VERIFIABLE,
        )
    if worst.tier.is_weakness:
        settled = _settled(context, len({use.name for use in uses}))
        note = (
            ", the only option on the table"
            if settled
            else "; the selection is not visible in this capture, so this is reported as an offered weakness "
            "rather than a negotiated one"
        )
        return RuleVerdict(
            status=FindingStatus.FAIL if settled else FindingStatus.WARNING,
            severity=TIER_SEVERITY[worst.tier],
            explanation=(
                f"{subject} uses {worst.name}, which the baseline rates {worst.tier.value}: {worst.reason}"
                f"{note}"
            ),
            evidence=refs,
            recommendation=recommendation,
            tier=worst.tier,
            details=details,
            references=worst.references,
        )
    quality = "is what this baseline would configure" if worst.tier is PolicyTier.RECOMMENDED else "meets the floor"
    return RuleVerdict(
        status=FindingStatus.PASS,
        explanation=f"{subject} uses {_names(uses)}, which {quality}: {worst.reason}",
        evidence=refs,
        details=details,
        references=worst.references,
    )


def _encryption_verdict(context: AssessmentContext, *, child: bool) -> RuleVerdict:
    """Judge the confidentiality algorithm of one SA scope."""
    subject = "CHILD_SA encryption" if child else "IKE_SA encryption"
    source = "analysis.child_proposals" if child else "analysis.ike_proposals"
    uses, evidence = context.effective_encryption(child=child)
    return _strength_verdict(
        context,
        subject=subject,
        uses=uses,
        evidence=evidence,
        source=source,
        judge=encryption_policy,
        missing_reason="no encryption transform was readable in any proposal and the configuration states none",
        recommendation=(
            "restrict the proposal set to an AEAD cipher such as AES-GCM with a 128-bit tag and drop every "
            "cipher below it"
        ),
    )

def _integrity_verdict(context: AssessmentContext, *, child: bool) -> RuleVerdict:
    """Judge the authentication of one SA scope, without false alarms on AEAD.

    The trap is that an AEAD cipher needs no separate integrity transform, so "no
    ICV offered" is only a finding when the cipher in use does not authenticate by
    itself.  Reporting a missing ICV next to AES-GCM would be a false positive, so
    the rule asks the policy table what the cipher provides before it complains.
    """
    subject = "CHILD_SA integrity" if child else "IKE_SA integrity"
    source = "analysis.child_proposals" if child else "analysis.ike_proposals"
    uses, evidence = context.effective_integrity(child=child)
    if uses:
        return _strength_verdict(
            context,
            subject=subject,
            uses=uses,
            evidence=evidence,
            source=source,
            judge=integrity_policy,
            missing_reason="no integrity transform was readable",
            recommendation="offer HMAC-SHA2-256 or stronger, or rely on an AEAD cipher's own tag",
        )
    enc_uses, _enc_evidence = context.effective_encryption(child=child)
    refs = _ref(EvidenceStatus.OBSERVED, source, f"{subject}: implied by {_names(enc_uses)}")
    if enc_uses and all(is_aead(use.name) for use in enc_uses):
        tag = aead_tag_bits(enc_uses[0].name)
        return RuleVerdict(
            status=FindingStatus.PASS,
            explanation=(
                f"{subject} shows no separate integrity transform because {enc_uses[0].name} authenticates every "
                f"packet itself ({tag}-bit tag): an absent ICV is the correct shape here, not a weakness"
            ),
            evidence=refs,
            details={"aead": True, "tag_bits": tag},
            references=("RFC 5116 section 4 (AEAD transforms for IKEv2 include integrity)",),
        )
    if enc_uses and any(requires_separate_integrity(use.name) for use in enc_uses):
        return RuleVerdict(
            status=FindingStatus.FAIL,
            severity=Severity.CRITICAL,
            explanation=(
                f"{subject} relies on {_names(enc_uses)}, which does not authenticate packets, and no integrity "
                "transform was offered at all: an on-path attacker can modify tunnel traffic undetected"
            ),
            evidence=refs,
            recommendation="add HMAC-SHA2-256 to every proposal, or move the SA to an AEAD cipher",
            details={"cipher": enc_uses[0].name, "separate_integrity_required": True},
            references=("RFC 4306 section 2.2 (ESP integrity is mandatory unless the cipher is AEAD)",),
        )
    if enc_uses:
        return RuleVerdict(
            status=FindingStatus.PASS,
            explanation=(
                f"{subject} shows no integrity transform and none is expected: {_names(enc_uses)} provides no "
                "confidentiality either, which the encryption rule reports directly"
            ),
            evidence=refs,
            details={"null_encryption": True},
        )
    return _unassessed(
        subject,
        "no integrity transform was readable, no readable encryption algorithm implies one, and the "
        "configuration states none",
    )


def _prf_verdict(context: AssessmentContext) -> RuleVerdict:
    """Judge the pseudorandom function that derives the key material."""
    uses, evidence = context.effective_prf()
    return _strength_verdict(
        context,
        subject="IKE PRF",
        uses=uses,
        evidence=evidence,
        source="analysis.ike_proposals",
        judge=prf_policy,
        missing_reason="no PRF transform was readable in any IKE proposal and the configuration states none",
        recommendation="offer PRF_HMAC_SHA2_256 or PRF_HMAC_SHA2_384 and remove PRF_HMAC_MD5/SHA1",
    )


def _dh_verdict(context: AssessmentContext, *, child: bool) -> RuleVerdict:
    """Judge the Diffie-Hellman group used for one SA scope."""
    subject = "CHILD_SA Diffie-Hellman group" if child else "IKE_SA Diffie-Hellman group"
    source = "analysis.child_proposals" if child else "analysis.ike_proposals"
    groups, evidence = context.effective_dh_groups(child=child)
    if not groups:
        reason = context.pfs_reason or "no KE payload was readable in any proposal and the configuration states none"
        return _unassessed(subject, reason)
    uses = [AlgorithmUse(name=str(group)) for group in groups]
    return _strength_verdict(
        context,
        subject=subject,
        uses=uses,
        evidence=evidence,
        source=source,
        judge=dh_policy,
        missing_reason="no KE payload was readable",
        recommendation="restrict the group list to MODP-3072 or an ECC group of at least 256 bits",
    )


# ---------------------------------------------------------------------------
# Key exchange: how the keys were made, and whether anyone said for how long
# ---------------------------------------------------------------------------
#: IKEv2 payload type 3 (Authentication) - RFC 7296 section 3.6.
PAYLOAD_AUTH = 3
#: IKEv2 payload types 35/37 (IDi/IDr) - RFC 7296 sections 3.4 and 3.5.
PAYLOAD_IDENTITIES = (35, 37)
#: Exchanges in which a peer proves its identity (IKEv2 and the IKEv1 equivalents).
AUTHENTICATING_EXCHANGES = ("IKE_AUTH", "IKEV1_EXCHANGE_3", "IKEV1_EXCHANGE_5", "IKEV1_EXCHANGE_6")


def _pfs_verdict(context: AssessmentContext) -> RuleVerdict:
    """Whether child-SA keys come from a fresh key exchange.

    Perfect forward secrecy is a property of the rekey, not of the cipher suite, so
    this rule reads what Prompt 2 could establish from the child-SA creations and
    never infers it from a strong DH group in the initial exchange - that group
    built the IKE keys, not the child keys.
    """
    pfs, evidence = context.effective_pfs()
    if pfs is None:
        return _unassessed(
            "Perfect forward secrecy",
            context.pfs_reason or "no child SA creation was observed and the configuration states no PFS setting",
        )
    groups = ", ".join(str(group) for group in context.pfs_child_dh_groups)
    if pfs:
        detail = "child SA creations carried a KE payload"
        if groups:
            detail = f"{detail} (groups {groups})"
        return RuleVerdict(
            status=FindingStatus.PASS,
            explanation=(
                "CHILD_SA keys are refreshed by a fresh key exchange, so compromising the IKE SA key material "
                "later does not hand over traffic keyed before the rekey"
            ),
            evidence=_ref(evidence, "analysis.pfs", detail, child_dh_groups=list(context.pfs_child_dh_groups)),
            details={"child_dh_groups": list(context.pfs_child_dh_groups)},
            references=("RFC 7296 section 1.3.2 (PFS achieved by a KE payload inside CREATE_CHILD_SA)",),
        )
    return RuleVerdict(
        status=FindingStatus.FAIL,
        severity=Severity.HIGH,
        explanation=(
            "child SA keys are derived from the IKE SA's key material without a fresh key exchange, so one later "
            "compromise of the IKE keys decrypts every child SA ever created from it"
        ),
        evidence=_ref(evidence, "analysis.pfs", context.pfs_reason or "child SA creations carried no KE payload"),
        recommendation="enable PFS on the child SA with at least a 256-bit ECC group (group 19 or 31)",
        details={"configured_pfs": (context.configured.pfs if context.configured else None)},
        references=("RFC 7296 section 3.8 (CREATE_CHILD_SA and its optional KE payload)",),
    )


def _pfs_claim_verdict(context: AssessmentContext) -> RuleVerdict:
    """Whether the configuration's PFS claim survives contact with the wire.

    This rule exists to be overruled: it decides the same property as the PFS rule
    and costs nothing when the two agree.  When they do not, scoring keeps the worse
    verdict and the report shows the contradiction, because a file that says
    ``pfs=yes`` next to a capture with no KE payload is a finding about the
    configuration as well as about the tunnel.
    """
    configured = context.configured
    if configured is None or configured.pfs is None:
        return _unassessed("The PFS configuration", "no testbed configuration was supplied")
    claimed = EvidenceRef(status=EvidenceStatus.CONFIGURED, source=configured.source, detail=f"pfs={configured.pfs}")
    observed = EvidenceRef(status=EvidenceStatus.OBSERVED, source="analysis.pfs", detail=context.pfs_reason)
    if context.pfs_status == "NOT_VERIFIABLE":
        return RuleVerdict(
            status=FindingStatus.PASS,
            explanation=(
                f"the configuration states pfs={configured.pfs} and nothing observed contradicts it, but no child "
                "SA creation was captured, so the claim stands unverified"
            ),
            evidence=(claimed,),
            property_status=FindingStatus.NOT_VERIFIABLE,
        )
    if configured.pfs and context.pfs_status == "DISABLED":
        return RuleVerdict(
            status=FindingStatus.FAIL,
            severity=Severity.HIGH,
            explanation=(
                f"the configuration claims pfs=true but the captured child SA creations carry no KE payload, so "
                f"{configured.source} does not describe the tunnel that is actually running"
            ),
            evidence=(observed, claimed),
            recommendation="find the peer or connection definition really in effect and enable PFS there",
            details={"claimed": True, "observed": context.pfs_status},
        )
    if not configured.pfs and context.pfs_status == "OBSERVED":
        return RuleVerdict(
            status=FindingStatus.WARNING,
            severity=Severity.LOW,
            explanation=(
                "the configuration states pfs=false yet the captured child SA creations carried a KE payload: the "
                "stronger behaviour is running and the stated configuration is stale"
            ),
            evidence=(observed, claimed),
            recommendation="update the stored configuration so it describes the tunnel that is running",
            details={"claimed": False, "observed": context.pfs_status},
        )
    return RuleVerdict(
        status=FindingStatus.PASS,
        explanation=f"the configuration (pfs={configured.pfs}) and the observed child SAs agree",
        evidence=(observed, claimed),
    )


def _lifetime_verdict(context: AssessmentContext, *, scope: str) -> RuleVerdict:
    """Judge a rekey lifetime against the baseline's ceilings.

    Lifetimes are the clearest example of why evidence status matters: a passive
    capture cannot contain one, so with no configuration the honest answer is
    ``NOT_VERIFIABLE`` rather than a guess inferred from packet counts, and with a
    configuration the answer is only as good as that file (``CONFIGURED``).
    """
    subject = "CHILD_SA lifetime" if scope == "child" else "IKE_SA lifetime"
    ceilings = CHILD_LIFETIME if scope == "child" else IKE_LIFETIME
    seconds, evidence = context.effective_lifetime(scope)
    if seconds is None:
        return _unassessed(
            subject,
            "a passive capture contains no lifetime information and the testbed configuration states none; "
            "rekey behaviour can only be judged from an endpoint, not from packets",
        )
    tier = ceilings.tier_for(float(seconds))
    source = context.configured.source if context.configured else "testbed"
    refs = _ref(
        evidence,
        source,
        f"{subject} = {seconds}s (preferred <= {ceilings.preferred_s}s, maximum <= {ceilings.maximum_s}s)",
        seconds=seconds,
    )
    details = {
        "seconds": seconds,
        "tier": tier.value,
        "preferred_s": ceilings.preferred_s,
        "acceptable_s": ceilings.acceptable_s,
        "maximum_s": ceilings.maximum_s,
    }
    if tier.is_weakness:
        boundary = (
            f"maximum of {ceilings.maximum_s}s"
            if float(seconds) > ceilings.maximum_s
            else f"acceptable value of {ceilings.acceptable_s}s"
        )
        return RuleVerdict(
            status=FindingStatus.WARNING if tier is PolicyTier.DEPRECATED else FindingStatus.FAIL,
            severity=TIER_SEVERITY[tier],
            explanation=(
                f"{subject} is {seconds}s, above this baseline's {boundary}: {ceilings.rationale}"
            ),
            evidence=refs,
            recommendation=f"rekey at most every {ceilings.acceptable_s}s",
            tier=tier,
            details=details,
            references=("RFC 7296 section 2.4 (rekeying must be possible; lifetime choice is operational)",),
        )
    return RuleVerdict(
        status=FindingStatus.PASS,
        explanation=(
            f"{subject} is {seconds}s, within this baseline's target of {ceilings.acceptable_s}s"
        ),
        evidence=refs,
        details=details,
    )


def _authentication_verdict(context: AssessmentContext) -> RuleVerdict:
    """Whether the peers proved who they are - and whether we could see them do it.

    A passive capture shows that an IKE_AUTH exchange happened, not that it
    succeeded: the ID and AUTH payloads live inside the encrypted body, and verifying
    a signature needs the certificate chain.  The tempting shortcut - treating the
    presence of an encrypted payload as proof of authentication - is exactly the
    conflation this rule refuses to make, so the default answer is ``NOT_VERIFIABLE``
    with the reason spelled out.
    """
    if not context.exchanges:
        return _unassessed("Peer authentication", "no IKE exchange was captured")
    authenticated = [item for item in context.exchanges if item.exchange in AUTHENTICATING_EXCHANGES]
    if not authenticated:
        return _unassessed(
            "Peer authentication",
            "the capture contains no IKE_AUTH (or IKEv1 identity-protection) exchange, so the part of the "
            "handshake that proves identity was never recorded",
        )
    plain = [item for item in authenticated if not item.carries_encryption]
    if plain:
        return RuleVerdict(
            status=FindingStatus.WARNING,
            severity=Severity.HIGH,
            explanation=(
                f"{len(plain)} authenticating exchange(s) carry no encrypted payload, so the identity and "
                "authentication payloads were exchanged in the clear and an on-path observer holds the material "
                "to attack them offline"
            ),
            evidence=_ref(
                EvidenceStatus.OBSERVED,
                "analysis.ike_exchanges",
                f"exchange {plain[0].exchange} at frame {plain[0].frame_index} without an encrypted payload",
                frames=[item.frame_index for item in plain],
            ),
            recommendation="check that the peers negotiate encryption for IKE_AUTH rather than falling back to plaintext",
            details={"frames": [item.frame_index for item in plain]},
            references=("RFC 7296 section 2.2 (IKE_AUTH is encrypted once the IKE SA is established)",),
        )
    return RuleVerdict(
        status=FindingStatus.NOT_VERIFIABLE,
        severity=Severity.INFO,
        explanation=(
            f"{len(authenticated)} authenticating exchange(s) were captured inside an encrypted body: their "
            "identity and authentication payloads were not readable, so the engine can state that an "
            "authenticated exchange took place but not that the peers' identities were verified"
        ),
        evidence=_ref(
            EvidenceStatus.NOT_VERIFIABLE,
            "analysis.ike_exchanges",
            f"{len(authenticated)} IKE_AUTH exchange(s) recorded as encrypted payloads only",
            exchanges=[item.exchange for item in authenticated],
        ),
        property_status=FindingStatus.NOT_VERIFIABLE,
        details={"authenticating_exchanges": [item.exchange for item in authenticated]},
        references=("RFC 7296 section 3.6 (the AUTH payload carries the proof that is not visible here)",),
    )


#: IKEv1 payload type 5 (ID) in the clear is the signature of aggressive mode.
PAYLOAD_IKEV1_ID = 5


def _ike_version_verdict(context: AssessmentContext) -> RuleVerdict:
    """Judge the IKE major version actually seen on the wire."""
    version, evidence = context.effective_ike_version()
    if version is None:
        return _unassessed("The IKE version", "no IKE message was decoded")
    source = "analysis.ike_exchanges" if evidence is EvidenceStatus.OBSERVED else "testbed"
    refs = _ref(evidence, source, f"IKE version observed: {version}")
    if version != 1:
        return RuleVerdict(
            status=FindingStatus.PASS,
            explanation="the exchange runs IKEv2, the current version of the protocol",
            evidence=refs,
            details={"version": version},
            references=("RFC 7296 (IKEv2)",),
        )
    aggressive = any(
        item.ike_version == 1 and PAYLOAD_IKEV1_ID in item.payload_types and not item.carries_encryption
        for item in context.exchanges
    )
    if aggressive:
        return RuleVerdict(
            status=FindingStatus.FAIL,
            severity=Severity.HIGH,
            explanation=(
                "IKEv1 was observed with a cleartext ID payload, the shape of aggressive mode: the responder "
                "identity is exposed to anyone on path and the exchange is the classic offline password target"
            ),
            evidence=refs,
            recommendation=(
                "move the peer to IKEv2; if IKEv1 must stay, require main mode with a certificate-based method"
            ),
            details={"version": version, "aggressive_mode_shape": True},
            references=(
                "RFC 6189 (moving IKEv1 to historic status)",
                "RFC 2409 section 5.2 (IKEv1 aggressive mode)",
            ),
        )
    mixed = len(context.ike_versions) > 1
    return RuleVerdict(
        status=FindingStatus.WARNING if mixed else FindingStatus.FAIL,
        severity=Severity.HIGH if not mixed else Severity.MEDIUM,
        explanation=(
            "IKEv1 traffic was observed: IKEv1 is historic, offers no protected identity exchange, and its mode "
            "cannot be told apart from the payload types available in this capture"
        ),
        evidence=refs,
        recommendation="migrate the peer to IKEv2 and disable IKEv1 on both ends",
        details={"version": version, "aggressive_mode_shape": False},
        references=("RFC 6189 (moving IKEv1 to historic status)",),
    )


# ---------------------------------------------------------------------------
# SA security: is anything protected, and can its packets be identified
# ---------------------------------------------------------------------------
def _protection_coverage_verdict(context: AssessmentContext) -> RuleVerdict:
    """Whether the capture contains protected traffic at all.

    An IKE handshake with no ESP behind it is neither a secure tunnel nor a broken
    one: it is no tunnel.  Saying so keeps a sample that never reached the data phase
    from reading as a clean bill of health, since every rule above it has nothing to
    say when no child SA exists.
    """
    if not context.has_ike and not context.has_esp:
        return _unassessed("ESP protection coverage", "the capture contains neither IKE nor ESP traffic")
    if context.has_esp:
        return RuleVerdict(
            status=FindingStatus.PASS,
            explanation=(
                f"{context.esp_packets} ESP packet(s) across {context.spi_count} security association(s) were "
                "captured, so the sample does contain traffic protected by the negotiated parameters"
            ),
            evidence=_ref(
                EvidenceStatus.OBSERVED,
                "analysis.esp_flows",
                f"{context.esp_packets} ESP packets, {context.spi_count} distinct SPIs",
                esp_packets=context.esp_packets,
                spi_count=context.spi_count,
            ),
            details={"esp_packets": context.esp_packets, "spi_count": context.spi_count},
        )
    return RuleVerdict(
        status=FindingStatus.FAIL,
        severity=Severity.HIGH,
        explanation=(
            f"{context.ike_packets} IKE packet(s) were captured and no ESP traffic at all: no child SA carried "
            "data in this sample, so nothing in it demonstrates a working protected tunnel"
        ),
        evidence=_ref(
            EvidenceStatus.OBSERVED,
            "analysis.details.scan",
            f"{context.ike_packets} IKE packets, 0 ESP packets",
            ike_packets=context.ike_packets,
        ),
        recommendation="capture the data phase as well as the handshake, or find out why the child SA never came up",
        details={"ike_packets": context.ike_packets, "esp_packets": 0},
    )


#: SPI values that cannot have come from a random generator.
DEGENERATE_SPIS = frozenset({"00000000", "ffffffff", "11111111", "22222222", "aaaaaaaa", "cccccccc"})


def _spi_entropy_verdict(context: AssessmentContext) -> RuleVerdict:
    """Whether the observed SPIs look like the random values the standard requires.

    SPIs are not secret, so this is not a confidentiality question.  It matters
    because receivers and middleboxes key their state off this 32-bit value: a pinned
    SPI lets an observer aim state-exhaustion or lookup attacks at one known
    association instead of guessing, and usually betrays a hand-rolled stack.
    """
    if not context.esp_flows:
        return _unassessed("SPI selection", "no ESP security association was observed, so no SPI can be inspected")
    spis = sorted({flow.spi for flow in context.esp_flows})
    refs = _ref(EvidenceStatus.OBSERVED, "analysis.esp_flows", f"SPIs observed: {', '.join(spis)}")
    degenerate = sorted(item for item in spis if item.lower() in DEGENERATE_SPIS)
    if degenerate:
        return RuleVerdict(
            status=FindingStatus.WARNING,
            severity=Severity.MEDIUM,
            explanation=(
                f"SPI {', '.join(degenerate)} carries no entropy: RFC 4303 requires the SPI to be chosen at "
                "random, and a fixed value lets anyone on path target one known association instead of guessing"
            ),
            evidence=refs,
            recommendation="let the IPsec stack choose SPIs at random instead of pinning them",
            details={"degenerate_spis": degenerate, "spis": spis},
            references=("RFC 4303 section 2.1 (SPI selection must be random; 0 and all-ones are reserved)",),
        )
    return RuleVerdict(
        status=FindingStatus.PASS,
        explanation=f"all {len(spis)} observed SPI(s) look like random 32-bit values",
        evidence=refs,
        details={"spis": spis},
    )


def _encapsulation_verdict(context: AssessmentContext) -> RuleVerdict:
    """Report UDP-encapsulated ESP as the availability dependency that it is."""
    if not context.esp_flows:
        return _unassessed("ESP encapsulation", "no ESP traffic was observed")
    encapsulated = [flow for flow in context.esp_flows if flow.udp_encapsulated]
    details = {
        "flows": len(context.esp_flows),
        "udp_encapsulated": len(encapsulated),
        "encapsulations": sorted({flow.encapsulation for flow in context.esp_flows}),
    }
    refs = _ref(
        EvidenceStatus.OBSERVED,
        "analysis.esp_flows",
        f"{len(encapsulated)} of {len(context.esp_flows)} flow(s) run ESP over UDP",
    )
    if not encapsulated:
        return RuleVerdict(
            status=FindingStatus.PASS,
            explanation="ESP runs directly over IP protocol 50, so no NAT binding has to stay alive for the tunnel",
            evidence=refs,
            details=details,
        )
    partial = len(encapsulated) < len(context.esp_flows)
    return RuleVerdict(
        status=FindingStatus.WARNING,
        severity=Severity.LOW,
        explanation=(
            f"{len(encapsulated)} of {len(context.esp_flows)} ESP flow(s) are UDP-encapsulated, so a NAT binding "
            "sits in the path: an idle tunnel survives only as long as its keepalive beats the binding's idle "
            "timeout"
            + (", and part of this traffic crosses the NAT while part of it does not" if partial else "")
        ),
        evidence=refs,
        recommendation="check the NAT idle timeout against the keepalive interval; the tunnel breaks silently otherwise",
        details=details,
        references=("RFC 3948 section 2.1 (UDP encapsulation of ESP for NAT traversal)",),
    )


# ---------------------------------------------------------------------------
# Replay protection: what the sender sent, and what the receiver will tolerate
# ---------------------------------------------------------------------------
def _sender_sequence_verdict(context: AssessmentContext) -> RuleVerdict:
    """Judge the ESP sequence numbers the sender actually produced.

    Sequence numbers travel in the clear, so this is one of the few replay facts a
    passive capture can show.  The limit that matters: gaps and reordering are also
    exactly what loss looks like, so the rule warns instead of failing, and declines
    to answer at all when too few packets were captured for the counts to mean
    anything.
    """
    sequence = context.sequence
    refs = _ref(
        sequence.evidence,
        "analysis.esp_flows",
        f"{sequence.packets} ESP packet(s) over {sequence.flows} flow(s): {sequence.replays} replay(s), "
        f"{sequence.gaps} gap(s)",
        **sequence.to_dict(),
    )
    if sequence.packets < MIN_PACKETS_FOR_SEQUENCE_ANALYSIS:
        return RuleVerdict(
            status=FindingStatus.NOT_VERIFIABLE,
            severity=Severity.INFO,
            explanation=(
                f"only {sequence.packets} ESP packet(s) were captured, below the "
                f"{MIN_PACKETS_FOR_SEQUENCE_ANALYSIS} this baseline requires before sequence behaviour means "
                "anything: a handful of packets cannot tell a replay window from a coincidence"
            ),
            evidence=refs,
            property_status=FindingStatus.NOT_VERIFIABLE,
            details=sequence.to_dict(),
        )
    if sequence.replays:
        return RuleVerdict(
            status=FindingStatus.WARNING,
            severity=Severity.MEDIUM,
            explanation=(
                f"{sequence.replays} packet(s) reused a sequence number already seen on the same SPI: a receiver "
                "with a replay window drops these and a receiver without one accepts them, and this capture "
                "cannot show which end is receiving them"
            ),
            evidence=refs,
            recommendation="confirm the receiver keeps replay protection on, and look for a middlebox duplicating packets",
            details=sequence.to_dict(),
            references=("RFC 4303 section 3.4.3 (the replay window and its sequence arithmetic)",),
        )
    if sequence.gaps or sequence.non_monotonic_flows:
        return RuleVerdict(
            status=FindingStatus.WARNING,
            severity=Severity.LOW,
            explanation=(
                f"sequence numbers skip ({sequence.gaps}) or arrive out of order ({sequence.non_monotonic_flows} "
                "flow(s)), which cannot be told apart here from ordinary loss and is reported as a note"
            ),
            evidence=refs,
            details=sequence.to_dict(),
        )
    return RuleVerdict(
        status=FindingStatus.PASS,
        explanation=(
            f"sequence numbers increase without gaps across all {sequence.flows} flow(s), which is what a "
            "functioning sender side of replay protection looks like"
        ),
        evidence=refs,
        details=sequence.to_dict(),
    )


def _replay_window_verdict(context: AssessmentContext) -> RuleVerdict:
    """Judge the replay window as the configuration states it."""
    enabled, evidence = context.effective_replay_protection()
    if enabled is None:
        return _unassessed(
            "The replay window",
            "replay protection is a receiver-side setting that never appears on the wire, and no configuration "
            "was supplied that states it",
        )
    source = context.configured.source if context.configured else "testbed"
    refs = _ref(evidence, source, f"replay_protection={enabled}")
    if enabled:
        return RuleVerdict(
            status=FindingStatus.PASS,
            explanation="the configuration keeps the replay window enabled, so captured packets cannot be replayed",
            evidence=refs,
            references=("RFC 4303 section 3.4.3 (replay forwarding based on the window)",),
        )
    return RuleVerdict(
        status=FindingStatus.FAIL,
        severity=Severity.HIGH,
        explanation=(
            "the configuration disables replay protection: anyone who records one valid tunnel packet can inject "
            "it again and the receiver will accept it as fresh traffic"
        ),
        evidence=refs,
        recommendation="re-enable the replay window; if a legitimate sender reuses sequence numbers, fix the sender",
        references=("RFC 4303 section 3.4.3 (replay forwarding based on the window)",),
    )


def _sequence_space_verdict(context: AssessmentContext) -> RuleVerdict:
    """State what cannot be known about the size of the sequence-number space.

    Whether the sender runs with extended sequence numbers is decided inside the
    child SA, whose parameters are encrypted, and the ESP header does not reveal the
    counter width.  The wrap point still matters: past 2**32 packets under a single
    SPI the counter reuses values and the replay window starts rejecting live traffic
    (or accepting replays, with ESN disabled), so the rule records the limit and the
    only defence that is verifiable from an endpoint - rekeying first.
    """
    sequence = context.sequence
    return RuleVerdict(
        status=FindingStatus.NOT_VERIFIABLE,
        severity=Severity.INFO,
        explanation=(
            f"the counter width in use cannot be read from {sequence.packets} captured ESP packet(s): ESP "
            "headers do not say whether extended sequence numbers are enabled, and the child SA that negotiated "
            "them is encrypted"
        ),
        evidence=_ref(
            EvidenceStatus.NOT_VERIFIABLE,
            "analysis.esp_flows",
            f"{sequence.packets} packet(s) observed per {sequence.flows} flow(s)",
            packets=sequence.packets,
        ),
        property_status=FindingStatus.NOT_VERIFIABLE,
        recommendation=(
            "rekey each child SA well before 2**32 packets under one SPI, or turn on extended sequence numbers "
            "and size the lifetime against the flow rate"
        ),
        details={"observed_packets": sequence.packets, "wrap_at_packets": 2**32},
        references=("RFC 4303 appendix A (extended sequence numbers)", "RFC 3735 (the rekey interval problem)"),
    )


def _receiver_policy_verdict(context: AssessmentContext) -> RuleVerdict:
    """Say plainly that the receiver's decision is invisible from the outside."""
    return RuleVerdict(
        status=FindingStatus.NOT_VERIFIABLE,
        severity=Severity.INFO,
        explanation=(
            "whether the receiver drops out-of-window packets is a decision taken inside the endpoint: a passive "
            "capture sees the sender's numbers, never the receiver's verdict, and the testbed records no "
            "receiver-side counters"
        ),
        evidence=_ref(
            EvidenceStatus.NOT_VERIFIABLE,
            "assessment.evidence",
            "no receiver-side counters in the supplied inputs",
        ),
        property_status=FindingStatus.NOT_VERIFIABLE,
        recommendation="collect the receiver's anti-replay counters (or a host log) if this must be verified",
        references=("RFC 4303 section 3.4.3 (the window is a receiver-side construct)",),
    )


# ---------------------------------------------------------------------------
# Configuration: what the file claims, and what the wire contradicts
# ---------------------------------------------------------------------------
def _judge_any(name: object) -> AlgorithmPolicy:
    """Judge a name whose vocabulary (cipher, ICV, PRF or group) is not known.

    Offered sets mix the four transform kinds and a proposal record does not always
    keep them apart, so each table is tried in turn.  Returning ``UNKNOWN`` instead of
    a best guess is deliberate: an unrecognised name must not inherit some other
    transform's verdict.
    """
    verdict = encryption_policy(name)
    for judge in (integrity_policy, prf_policy, dh_policy):
        if verdict.tier is not PolicyTier.UNKNOWN:
            return verdict
        verdict = judge(name)
    return verdict


def _effective_names(context: AssessmentContext) -> set[str]:
    """Names of the algorithms the resolvers treat as in effect for any scope."""
    names: set[str] = set()
    for child in (False, True):
        names.update(use.name for use in context.effective_encryption(child=child)[0])
        names.update(use.name for use in context.effective_integrity(child=child)[0])
        names.update(str(group) for group in context.effective_dh_groups(child=child)[0])
    names.update(use.name for use in context.effective_prf()[0])
    return names


def _weak_offered_verdict(context: AssessmentContext) -> RuleVerdict:
    """Report weak algorithms that were offered but are not the effective choice.

    This is the downgrade surface: an offer of ``AES-GCM, 3DES`` usually means the
    tunnel runs AES-GCM today and that a peer willing to take 3DES can be talked into
    it tomorrow.  The effective choice is already judged by the algorithm rules, so
    this rule subtracts it and reports only what is *available* - and stays
    informational, because an offer is a policy decision, not a breach.
    """
    if not context.proposals:
        return _unassessed("The downgrade surface", "no SA payload was readable, so the offered set is unknown")
    effective = _effective_names(context)
    offered: dict[str, int] = {}
    for proposal in context.proposals:
        names = [use.name for use in proposal.encryption + proposal.integrity + proposal.prf]
        names += [str(group) for group in proposal.dh_groups]
        for name in names:
            if name and name not in effective:
                offered[name] = offered.get(name, 0) + 1
    weak = sorted(name for name in offered if _judge_any(name).tier.is_weakness)
    summary = sorted(offered)
    refs = _ref(
        EvidenceStatus.OBSERVED,
        "analysis.proposals",
        f"{len(context.proposals)} proposal(s) offering {len(summary)} algorithm(s) beyond the effective set",
        offered=summary,
    )
    if not weak:
        return RuleVerdict(
            status=FindingStatus.PASS,
            explanation=(
                "no algorithm outside the effective set falls below the baseline, so a downgrade inside this "
                "offer set cannot reach a weak cipher"
            ),
            evidence=refs,
            details={"offered_otherwise": summary},
        )
    tiers = ", ".join(f"{name} ({_judge_any(name).tier.value})" for name in weak)
    return RuleVerdict(
        status=FindingStatus.WARNING,
        severity=Severity.MEDIUM,
        explanation=(
            f"the proposal set still offers {tiers} without {'them' if len(weak) > 1 else 'it'} being what this "
            "tunnel runs on, so an attacker who can influence the negotiation has a weak target to aim at"
        ),
        evidence=refs,
        recommendation="delete the weak proposals instead of leaving them as fallbacks",
        details={"weak_offered": weak, "offered_otherwise": summary},
    )


def _config_provenance_verdict(context: AssessmentContext) -> RuleVerdict:
    """Record how much of this assessment had to lean on a configuration file.

    Not a weakness check: it is the assessment admitting which of its answers came
    from an operator-supplied file rather than from packets, so a reader never
    mistakes a well-documented testbed for an observed network.
    """
    configured = context.configured
    if configured is None:
        return RuleVerdict(
            status=FindingStatus.NOT_VERIFIABLE,
            severity=Severity.INFO,
            explanation=(
                "no operational configuration was supplied, so every parameter a passive capture cannot show "
                "(lifetimes, replay window, selected proposal) is reported as unverifiable instead of assumed"
            ),
            evidence=_ref(EvidenceStatus.NOT_VERIFIABLE, "assessment.inputs", "no configuration input"),
            property_status=FindingStatus.NOT_VERIFIABLE,
        )
    stated = sorted(
        key
        for key, value in (
            ("encryption", configured.encryption),
            ("integrity", configured.integrity),
            ("prf", configured.prf),
            ("dh_group", configured.dh_group),
            ("pfs", configured.pfs),
            ("ike_version", configured.ike_version),
            ("replay_protection", configured.replay_protection),
            ("ike_sa_lifetime_s", configured.ike_sa_lifetime_s),
            ("child_sa_lifetime_s", configured.child_sa_lifetime_s),
        )
        if value is not None
    )
    return RuleVerdict(
        status=FindingStatus.PASS,
        explanation=(
            f"{configured.source} supplied {len(stated)} operational parameter(s) ({', '.join(stated)}); findings "
            "that rest on them are labelled CONFIGURED, never OBSERVED"
        ),
        evidence=_ref(EvidenceStatus.CONFIGURED, configured.source, ", ".join(stated)),
        details={"stated": stated, "source": configured.source},
    )


def _config_contradiction_verdict(context: AssessmentContext) -> RuleVerdict:
    """Whether the stated configuration describes the tunnel in the capture.

    A config file is evidence about intent, not about behaviour, so it is only ever a
    ``CONFIGURED`` finding on its own.  Compared against the wire it becomes much
    stronger: not "the operator meant X" but "the operator believes X while the
    tunnel negotiates Y", which is the kind of drift that survives every review.
    """
    configured = context.configured
    if configured is None:
        return _unassessed("The configuration's agreement with the wire", "no configuration was supplied")
    observed_encryption = {encryption_policy(use.name).name for proposal in context.proposals for use in proposal.encryption}
    observed_integrity = {integrity_policy(use.name).name for proposal in context.proposals for use in proposal.integrity}
    observed_prf = {prf_policy(use.name).name for proposal in context.proposals for use in proposal.prf}
    observed_groups = {dh_policy(group).name for proposal in context.proposals for group in proposal.dh_groups}
    checks = (
        ("encryption", configured.encryption, observed_encryption),
        ("integrity", configured.integrity, observed_integrity),
        ("prf", configured.prf, observed_prf),
    )
    conflicts = []
    for parameter, stated, observed in checks:
        if stated is None or not observed:
            continue
        judged = _judge_any(stated)
        if judged.name not in observed:
            conflicts.append({"parameter": parameter, "configured": judged.name, "observed": sorted(observed)})
    if configured.dh_group is not None and observed_groups and dh_policy(configured.dh_group).name not in observed_groups:
        conflicts.append(
            {"parameter": "dh_group", "configured": dh_policy(configured.dh_group).name, "observed": sorted(observed_groups)}
        )
    refs = _ref(
        EvidenceStatus.OBSERVED,
        "analysis.proposals",
        f"{len(context.proposals)} proposal(s) compared against {configured.source}",
        conflicts=conflicts,
    )
    if conflicts:
        listed = "; ".join(
            f"{item['parameter']} configured as {item['configured']} while the wire shows {', '.join(item['observed'])}"
            for item in conflicts
        )
        return RuleVerdict(
            status=FindingStatus.WARNING,
            severity=Severity.MEDIUM,
            explanation=(
                f"{configured.source} disagrees with the capture: {listed}. Every finding that relied on the file "
                "is labelled CONFIGURED, and this one is the reason"
            ),
            evidence=(
                refs[0],
                EvidenceRef(status=EvidenceStatus.CONFIGURED, source=configured.source, detail=configured.proposal),
            ),
            recommendation="bring the stored configuration in line with what the peers actually negotiate",
            details={"conflicts": conflicts},
        )
    return RuleVerdict(
        status=FindingStatus.PASS,
        explanation=f"every algorithm named by {configured.source} also appears in the captured proposals",
        evidence=(
            refs[0],
            EvidenceRef(status=EvidenceStatus.CONFIGURED, source=configured.source, detail=configured.proposal),
        ),
        details={"conflicts": []},
    )


# ---------------------------------------------------------------------------
# Metadata privacy: what an observer learns without breaking anything
# ---------------------------------------------------------------------------
def _spi_visibility_verdict(context: AssessmentContext) -> RuleVerdict:
    """Report the association identifiers that anyone on path can see.

    SPIs are designed to be public, so this is not a weakness in the tunnel - it is
    the price of the protocol, and it belongs in the report because it is what makes
    the volume findings meaningful: an observer who can split traffic by SPI can
    measure each tunnel separately.
    """
    if not context.has_esp:
        return _unassessed("SPI visibility", "no ESP security association was observed")
    return RuleVerdict(
        status=FindingStatus.WARNING,
        severity=Severity.LOW,
        explanation=(
            f"{context.spi_count} SPI(s) and their peer addresses travel in the clear, so an observer can split "
            "this tunnel's traffic per association and count packets and bytes against each one: the baseline "
            "cost of ESP rather than a misconfiguration, but the reason packet counts are worth reporting"
        ),
        evidence=_ref(
            EvidenceStatus.OBSERVED,
            "analysis.esp_flows",
            f"{context.spi_count} distinct SPI(s), {len(context.esp_flows)} flow(s)",
            spi_count=context.spi_count,
        ),
        recommendation="if per-tunnel traffic analysis matters, mix the tunnels together or pad them uniformly",
        details={"spi_count": context.spi_count, "flows": len(context.esp_flows)},
        references=("RFC 4303 section 2.1 (the SPI is clear-text and must not be treated as a secret)",),
    )


def _traffic_volume_verdict(context: AssessmentContext) -> RuleVerdict:
    """Report the volume and shape of the encrypted exchange."""
    summary = context.metadata_summary()
    packets = int(summary.get("esp_packets", 0))
    refs = _ref(
        EvidenceStatus.OBSERVED,
        "analysis.esp_flows",
        f"{packets} ESP packet(s), {summary.get('esp_bytes', 0)} byte(s) over {summary.get('esp_flows', 0)} flow(s)",
        **{
            key: value
            for key, value in summary.items()
            if not isinstance(value, dict) and key not in _REF_RESERVED
        },
    )
    if packets < MIN_PACKETS_FOR_SEQUENCE_ANALYSIS:
        return RuleVerdict(
            status=FindingStatus.NOT_VERIFIABLE,
            severity=Severity.INFO,
            explanation=(
                f"the sample holds {packets} ESP packet(s), too few for any statement about its size or timing "
                "profile: a burst this short fits a ping as well as a file transfer"
            ),
            evidence=refs,
            property_status=FindingStatus.NOT_VERIFIABLE,
            details=dict(summary),
        )
    return RuleVerdict(
        status=FindingStatus.WARNING,
        severity=Severity.LOW,
        explanation=(
            f"an observer sees {packets} ESP packet(s) totalling {summary.get('esp_bytes', 0)} byte(s), largest "
            f"flow {summary.get('largest_flow_packets', 0)} packet(s): the contents stay private, how much was "
            "sent and in how many bursts does not"
        ),
        evidence=refs,
        recommendation="enable traffic-flow confidentiality padding if packet counts are themselves sensitive",
        details=dict(summary),
        references=("RFC 4303 section 2.7 (traffic analysis is outside ESP's scope)",),
    )


def _class_inference_verdict(context: AssessmentContext) -> RuleVerdict:
    """Report what a model can infer from the metadata, at the model's own confidence.

    This is the only rule whose evidence is ``INFERRED``, and it is written so the
    inference cannot launder itself into a measurement: the finding's confidence is
    the model's confidence, scoring discounts it again on top of that, and a
    prediction with no model identity is refused outright, because a confidence
    number means nothing without knowing what produced it.
    """
    prediction = context.traffic
    if prediction is None:
        return _unassessed(
            "Metadata inference",
            "no traffic-class prediction was supplied, so nothing was inferred beyond what was counted",
        )
    source = prediction.model_id or prediction.source
    details = {
        "predicted_class": prediction.predicted_class,
        "confidence": prediction.confidence,
        "cross_entropy_bits": prediction.cross_entropy_bits,
        "margin": prediction.margin,
        "model": f"{prediction.model_id}@{prediction.model_version}",
    }
    if not prediction.complete_metadata:
        return RuleVerdict(
            status=FindingStatus.NOT_VERIFIABLE,
            severity=Severity.INFO,
            explanation=(
                f"a model labelled this traffic {prediction.predicted_class} at {prediction.confidence:.2f}, but "
                "the prediction carries no model id, version or feature schema, so that number cannot be "
                "interpreted and no exposure is claimed"
            ),
            evidence=_ref(EvidenceStatus.NOT_VERIFIABLE, source, "prediction without model metadata", **details),
            property_status=FindingStatus.NOT_VERIFIABLE,
            details=details,
        )
    refs = _ref(
        EvidenceStatus.INFERRED,
        source,
        f"class {prediction.predicted_class} at confidence {prediction.confidence:.3f}",
        **details,
    )
    inconclusive = (
        prediction.confidence < METADATA_THRESHOLDS.prediction_confidence_min
        or prediction.cross_entropy_bits > METADATA_THRESHOLDS.prediction_surprisal_max_bits
    )
    if inconclusive:
        return RuleVerdict(
            status=FindingStatus.WARNING,
            severity=Severity.LOW,
            explanation=(
                f"the model's best guess is {prediction.predicted_class} at {prediction.confidence:.2f} "
                f"({prediction.cross_entropy_bits:.2f} bits removed), barely better than chance: the exposure is "
                "stated as unproven rather than dismissed"
            ),
            evidence=refs,
            confidence=prediction.confidence,
            details=details,
        )
    runner = prediction.runner_up
    margin = f", against runner-up {runner[0]} at {runner[1]:.2f}" if runner else ""
    return RuleVerdict(
        status=FindingStatus.WARNING,
        severity=Severity.MEDIUM,
        explanation=(
            f"metadata alone let {prediction.model_id} classify this traffic as {prediction.predicted_class} at "
            f"{prediction.confidence:.2f}{margin}: anyone with this capture and a similarly trained model can "
            "label the traffic without decrypting a byte of it"
        ),
        evidence=refs,
        recommendation="pad payloads to fixed sizes and jitter timings if the traffic class is itself sensitive",
        confidence=prediction.confidence,
        details=details,
        references=("RFC 4303 section 2.7 (ESP does not protect traffic-analysis metadata)",),
    )













# ---------------------------------------------------------------------------
# The catalogue
# ---------------------------------------------------------------------------
#: A structural gap where a whole protection is missing (no authentication at all,
#: no child SA, no forward secrecy) rather than a weak-but-present choice.
GAP_POINTS: Mapping[FindingStatus, float] = {
    FindingStatus.FAIL: 20.0,
    FindingStatus.WARNING: 6.0,
    FindingStatus.PASS: 0.0,
    FindingStatus.NOT_VERIFIABLE: 0.0,
}

#: A cost the protocol charges everyone (visible SPIs, measurable volume): real,
#: small, and never a failure.
EXPOSURE_POINTS: Mapping[FindingStatus, float] = {
    FindingStatus.FAIL: 8.0,
    FindingStatus.WARNING: 3.0,
    FindingStatus.PASS: 0.0,
    FindingStatus.NOT_VERIFIABLE: 0.0,
}

#: Modelled exposure: scoring scales this by the model's own confidence.
INFERENCE_POINTS: Mapping[FindingStatus, float] = {
    FindingStatus.FAIL: 10.0,
    FindingStatus.WARNING: 6.0,
    FindingStatus.PASS: 0.0,
    FindingStatus.NOT_VERIFIABLE: 0.0,
}

CRYPTO = SecurityCategory.CRYPTOGRAPHY
KEYX = SecurityCategory.KEY_EXCHANGE
SA = SecurityCategory.SA_SECURITY
REPLAY = SecurityCategory.REPLAY_PROTECTION
CONFIG = SecurityCategory.CONFIGURATION
METADATA = SecurityCategory.METADATA_PRIVACY

#: Every rule the engine runs, in the order it runs them.  The order matters twice:
#: it is the order the report reads in, and it breaks ties when two rules reach the
#: same verdict about the same property (the first one keeps the finding).
RULES: tuple[Rule, ...] = (
    Rule(
        "CRYPTO-001",
        CRYPTO,
        "IKE SA cipher",
        "Judges the encryption algorithm protecting the IKE SA itself.",
        lambda ctx: _encryption_verdict(ctx, child=False),
        property_key="ike_encryption",
    ),
    Rule(
        "CRYPTO-002",
        CRYPTO,
        "IKE SA integrity",
        "Checks that IKE packets are authenticated, without charging AEAD ciphers for an absent ICV.",
        lambda ctx: _integrity_verdict(ctx, child=False),
        property_key="ike_integrity",
        points=GAP_POINTS,
    ),
    Rule(
        "CRYPTO-003",
        CRYPTO,
        "Key derivation function",
        "Judges the PRF that turns the shared secret into the tunnel's key material.",
        _prf_verdict,
        property_key="ike_prf",
    ),
    Rule(
        "CRYPTO-004",
        CRYPTO,
        "Child SA cipher",
        "Judges the cipher protecting the tunnel's data traffic.",
        lambda ctx: _encryption_verdict(ctx, child=True),
        property_key="child_encryption",
    ),
    Rule(
        "CRYPTO-005",
        CRYPTO,
        "Child SA integrity",
        "Checks that tunnel packets are authenticated, so undetected tampering is not possible.",
        lambda ctx: _integrity_verdict(ctx, child=True),
        property_key="child_integrity",
        points=GAP_POINTS,
    ),
    Rule(
        "KEYX-001",
        KEYX,
        "IKE Diffie-Hellman group",
        "Judges the group in which the IKE shared secret was agreed.",
        lambda ctx: _dh_verdict(ctx, child=False),
        property_key="ike_dh_group",
    ),
    Rule(
        "KEYX-002",
        KEYX,
        "Child SA Diffie-Hellman group",
        "Judges the group used when child keys are refreshed.",
        lambda ctx: _dh_verdict(ctx, child=True),
        property_key="child_dh_group",
    ),
    Rule(
        "KEYX-003",
        KEYX,
        "Forward secrecy of child keys",
        "Asks whether child keys come from a fresh exchange or from long-lived IKE key material.",
        _pfs_verdict,
        property_key="pfs",
        points=GAP_POINTS,
    ),
    Rule(
        "KEYX-004",
        KEYX,
        "PFS claim versus observation",
        "Compares the configured PFS setting with what the captured child SA creations show.",
        _pfs_claim_verdict,
        property_key="pfs",
        points=GAP_POINTS,
    ),
    Rule(
        "KEYX-005",
        KEYX,
        "IKE SA lifetime",
        "Judges how long one IKE key is allowed to protect every child SA below it.",
        lambda ctx: _lifetime_verdict(ctx, scope="ike"),
        property_key="ike_lifetime",
    ),
    Rule(
        "KEYX-006",
        KEYX,
        "Child SA lifetime",
        "Judges how long one leaked tunnel key keeps decrypting recorded traffic.",
        lambda ctx: _lifetime_verdict(ctx, scope="child"),
        property_key="child_lifetime",
    ),
    Rule(
        "KEYX-007",
        KEYX,
        "Peer authentication",
        "Reports whether the identity exchange was visible at all, and refuses to call encryption proof.",
        _authentication_verdict,
        property_key="authentication",
        points=GAP_POINTS,
    ),
    Rule(
        "KEYX-008",
        KEYX,
        "Protocol version",
        "Reports IKEv1, whose unprotected identity exchange has been historic since 2011.",
        _ike_version_verdict,
        property_key="ike_version",
        points={FindingStatus.FAIL: 14.0, FindingStatus.WARNING: 8.0, FindingStatus.PASS: 0.0},
    ),
    Rule(
        "SA-001",
        SA,
        "Protection coverage",
        "Checks that the sample contains protected traffic rather than a handshake that went nowhere.",
        _protection_coverage_verdict,
        property_key="protection_coverage",
        points={FindingStatus.FAIL: 14.0, FindingStatus.WARNING: 5.0, FindingStatus.PASS: 0.0},
    ),
    Rule(
        "SA-002",
        SA,
        "SPI selection",
        "Looks for pinned or reserved SPIs, which make association-targeted attacks guessable.",
        _spi_entropy_verdict,
        property_key="spi_entropy",
        points={FindingStatus.FAIL: 8.0, FindingStatus.WARNING: 6.0, FindingStatus.PASS: 0.0},
    ),
    Rule(
        "SA-003",
        SA,
        "ESP encapsulation",
        "Reports UDP-encapsulated ESP, whose tunnel depends on a NAT binding staying alive.",
        _encapsulation_verdict,
        property_key="encapsulation",
        points={FindingStatus.WARNING: 2.0, FindingStatus.PASS: 0.0},
    ),
    Rule(
        "REPLAY-001",
        REPLAY,
        "Sender sequence behaviour",
        "Reads the clear-text ESP sequence numbers for reuse, gaps and reordering.",
        _sender_sequence_verdict,
        property_key="sender_sequence",
        points={FindingStatus.WARNING: 6.0, FindingStatus.PASS: 0.0},
    ),
    Rule(
        "REPLAY-002",
        REPLAY,
        "Replay window",
        "Checks the configured replay window, without which one recorded packet can be injected again.",
        _replay_window_verdict,
        property_key="replay_window",
        points={FindingStatus.FAIL: 12.0, FindingStatus.WARNING: 4.0, FindingStatus.PASS: 0.0},
    ),
    Rule(
        "REPLAY-003",
        REPLAY,
        "Sequence-number space",
        "States the counter wrap limit and that the counter width itself is not observable.",
        _sequence_space_verdict,
        property_key="sequence_space",
        points=INFORMATIONAL_POINTS,
    ),
    Rule(
        "REPLAY-004",
        REPLAY,
        "Receiver replay policy",
        "States that the receiver's accept-or-drop decision cannot be seen from a passive capture.",
        _receiver_policy_verdict,
        property_key="receiver_policy",
        points=INFORMATIONAL_POINTS,
    ),
    Rule(
        "CONFIG-001",
        CONFIG,
        "Configuration provenance",
        "Records how many answers came from an operator file rather than from packets.",
        _config_provenance_verdict,
        property_key="config_provenance",
        points=INFORMATIONAL_POINTS,
    ),
    Rule(
        "CONFIG-002",
        CONFIG,
        "Downgrade surface",
        "Lists weak algorithms still on offer even when the tunnel does not use them.",
        _weak_offered_verdict,
        property_key="downgrade_surface",
        points={FindingStatus.WARNING: 6.0, FindingStatus.PASS: 0.0},
    ),
    Rule(
        "CONFIG-003",
        CONFIG,
        "Configuration versus wire",
        "Reports parameters the configuration states that the captured proposals contradict.",
        _config_contradiction_verdict,
        property_key="config_agreement",
        points={FindingStatus.WARNING: 6.0, FindingStatus.PASS: 0.0},
    ),
    Rule(
        "META-001",
        METADATA,
        "Association visibility",
        "Reports the clear-text SPIs and addresses that let an observer split traffic per tunnel.",
        _spi_visibility_verdict,
        property_key="association_visibility",
        points=EXPOSURE_POINTS,
    ),
    Rule(
        "META-002",
        METADATA,
        "Volume and burst exposure",
        "Reports the packet and byte counts an observer can measure without decrypting anything.",
        _traffic_volume_verdict,
        property_key="volume_exposure",
        points=EXPOSURE_POINTS,
    ),
    Rule(
        "META-003",
        METADATA,
        "Class inference from metadata",
        "Reports what a classifier inferred from the metadata, discounted by its own confidence.",
        _class_inference_verdict,
        property_key="class_inference",
        points=INFERENCE_POINTS,
    ),
)

#: ``rule_id -> rule``, for reports and tests that address one rule by name.
RULE_INDEX: Mapping[str, Rule] = {rule.rule_id: rule for rule in RULES}


def applicable_rules(context: AssessmentContext) -> tuple[Rule, ...]:
    """The rules worth running against this capture, in catalogue order."""
    return tuple(rule for rule in RULES if rule.applies_to(context))


def describe_rules() -> list[dict[str, Any]]:
    """The catalogue as plain data, for the generated policy reference."""
    return [rule.describe() for rule in RULES]


__all__ = [
    "EXPOSURE_POINTS",
    "FAIL_SEVERITY_FLOOR",
    "GAP_POINTS",
    "INFORMATIONAL_POINTS",
    "INFERENCE_POINTS",
    "Rule",
    "RULES",
    "RULE_INDEX",
    "RuleVerdict",
    "STANDARD_POINTS",
    "TIER_RANK",
    "applicable_rules",
    "describe_rules",
]




