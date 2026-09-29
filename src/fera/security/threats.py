"""The threat matrix: what each weakness would actually let an attacker do.

A catalogue entry is never reported on its own.  It is reported when a finding
that names one of its rules exists, and the entry copies that finding's evidence
status, so a threat inherited from an unverifiable property says so instead of
reading like something an observer watched happen.

Likelihood and impact are stated per entry rather than derived from the score:
they answer a different question ("what would this cost if exploited") than the
gate does ("how bad is this deployment compared with the baseline").
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ..common.errors import ConfigValidationError
from .evidence import strongest
from .models import FindingStatus, RiskLevel, SecurityCategory, SecurityFinding, ThreatObservation

#: Likelihood and impact vocabulary, weakest first.
LIKELIHOOD_LEVELS: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH")
IMPACT_LEVELS: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH")

#: Likelihood x impact -> risk band.  Explicit and total, so no combination can
#: quietly fall through to a default the catalogue did not intend.
RISK_MATRIX: dict[tuple[str, str], RiskLevel] = {
    ("HIGH", "HIGH"): RiskLevel.CRITICAL,
    ("HIGH", "MEDIUM"): RiskLevel.HIGH,
    ("MEDIUM", "HIGH"): RiskLevel.HIGH,
    ("HIGH", "LOW"): RiskLevel.MODERATE,
    ("MEDIUM", "MEDIUM"): RiskLevel.MODERATE,
    ("LOW", "HIGH"): RiskLevel.MODERATE,
    ("MEDIUM", "LOW"): RiskLevel.LOW,
    ("LOW", "MEDIUM"): RiskLevel.LOW,
    ("LOW", "LOW"): RiskLevel.LOW,
}


def threat_risk(likelihood: str, impact: str) -> RiskLevel:
    """Band one likelihood/impact pair, refusing vocabulary it does not know."""
    likelihood = likelihood.upper()
    impact = impact.upper()
    if likelihood not in LIKELIHOOD_LEVELS:
        raise ConfigValidationError(
            f"likelihood must be one of: {', '.join(LIKELIHOOD_LEVELS)} (got {likelihood!r})",
            details={"likelihood": likelihood},
        )
    if impact not in IMPACT_LEVELS:
        raise ConfigValidationError(
            f"impact must be one of: {', '.join(IMPACT_LEVELS)} (got {impact!r})",
            details={"impact": impact},
        )
    return RISK_MATRIX[(likelihood, impact)]


@dataclass(frozen=True)
class ThreatDefinition:
    """One row of the threat matrix, before any finding has confirmed it."""

    threat_id: str
    threat: str
    category: SecurityCategory
    likelihood: str
    impact: str
    rule_ids: tuple[str, ...]
    recommendation: str
    #: When set, this threat is reported for rules that could *not* verify their
    #: property, not for rules that proved a weakness.
    from_unverified: bool = False

    def __post_init__(self) -> None:
        threat_risk(self.likelihood, self.impact)

    @property
    def risk(self) -> RiskLevel:
        return threat_risk(self.likelihood, self.impact)

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "threat": self.threat,
            "category": self.category.value,
            "likelihood": self.likelihood.upper(),
            "impact": self.impact.upper(),
            "risk": self.risk.value,
            "rule_ids": list(self.rule_ids),
            "recommendation": self.recommendation,
            "from_unverified": self.from_unverified,
        }


CRYPTO = SecurityCategory.CRYPTOGRAPHY
KEYX = SecurityCategory.KEY_EXCHANGE
SA = SecurityCategory.SA_SECURITY
REPLAY = SecurityCategory.REPLAY_PROTECTION
CONFIG = SecurityCategory.CONFIGURATION
METADATA = SecurityCategory.METADATA_PRIVACY

#: The matrix.  One entry per way a deployment can be attacked; the entry names
#: the rules whose findings put it in the report.
THREAT_CATALOGUE: tuple[ThreatDefinition, ...] = (
    ThreatDefinition(
        "T-IKE-CIPHER",
        "Weak cipher protecting the IKE SA itself",
        CRYPTO,
        "HIGH",
        "HIGH",
        ("CRYPTO-001",),
        "offer only AEAD ciphers (AES-GCM, ChaCha20-Poly1305) for the IKE SA",
    ),
    ThreatDefinition(
        "T-IKE-INTEGRITY",
        "IKE packets that a third party can forge without detection",
        CRYPTO,
        "MEDIUM",
        "HIGH",
        ("CRYPTO-002",),
        "authenticate every IKE SA with an integrity algorithm or use an AEAD cipher",
    ),
    ThreatDefinition(
        "T-PRF-WEAK",
        "Key material derived through a deprecated PRF",
        CRYPTO,
        "MEDIUM",
        "HIGH",
        ("CRYPTO-003",),
        "use PRF_HMAC_SHA2_256 or stronger for key derivation",
    ),
    ThreatDefinition(
        "T-TUNNEL-CIPHER",
        "Recorded tunnel traffic decrypted offline",
        CRYPTO,
        "HIGH",
        "HIGH",
        ("CRYPTO-004",),
        "use AES-GCM or ChaCha20-Poly1305 for the child SA",
    ),
    ThreatDefinition(
        "T-TUNNEL-INTEGRITY",
        "Payload tampering inside the tunnel that goes unnoticed",
        CRYPTO,
        "MEDIUM",
        "HIGH",
        ("CRYPTO-005",),
        "authenticate the child SA with an integrity algorithm or an AEAD cipher",
    ),
    ThreatDefinition(
        "T-DH-WEAK",
        "Shared secret recoverable with precomputation or special purpose hardware",
        KEYX,
        "MEDIUM",
        "HIGH",
        ("KEYX-001", "KEYX-002"),
        "use a 256 bit elliptic-curve group (19, 20, 21) or MODP 3072 and above",
    ),
    ThreatDefinition(
        "T-NO-FORWARD-SECRECY",
        "One leaked IKE key retroactively opens every child SA below it",
        KEYX,
        "MEDIUM",
        "HIGH",
        ("KEYX-003", "KEYX-004"),
        "enable PFS so child keys come from a fresh Diffie-Hellman exchange",
    ),
    ThreatDefinition(
        "T-KEY-EXPOSURE",
        "A leaked key keeps decrypting traffic until the SA is rekeyed",
        KEYX,
        "MEDIUM",
        "MEDIUM",
        ("KEYX-005", "KEYX-006"),
        "lower the SA lifetimes (8 h for IKE, 30 min for child SAs)",
    ),
    ThreatDefinition(
        "T-IDENTITY-UNVERIFIED",
        "Peer authentication asserted without anything on the wire to support it",
        KEYX,
        "MEDIUM",
        "HIGH",
        ("KEYX-007",),
        "confirm the authentication method out of band; a passive capture cannot show it",
        from_unverified=True,
    ),
    ThreatDefinition(
        "T-IKE-VERSION",
        "IKEv1, whose identity exchange and aggressive mode expose more than IKEv2",
        KEYX,
        "HIGH",
        "MEDIUM",
        ("KEYX-008",),
        "migrate to IKEv2",
    ),
    ThreatDefinition(
        "T-DOWNGRADE",
        "Negotiation steered towards a weak option the peer still offers",
        CONFIG,
        "MEDIUM",
        "HIGH",
        ("CONFIG-002",),
        "remove deprecated algorithms from the offered set instead of relying on peer choice",
    ),
    ThreatDefinition(
        "T-CONFIG-DRIFT",
        "Deployed tunnel does not match its documentation",
        CONFIG,
        "MEDIUM",
        "MEDIUM",
        ("CONFIG-003",),
        "reconcile the configuration with the capture and re-run the experiment",
    ),
    ThreatDefinition(
        "T-PLAINTEXT-TRAFFIC",
        "Traffic that should have been protected was observed unprotected",
        SA,
        "HIGH",
        "HIGH",
        ("SA-001",),
        "check the policy that selects the tunnel, not only the tunnel itself",
    ),
    ThreatDefinition(
        "T-SPI-GUESS",
        "Association identifiers that can be guessed or targeted",
        SA,
        "MEDIUM",
        "MEDIUM",
        ("SA-002",),
        "let the peers choose random SPIs instead of pinning them",
    ),
    ThreatDefinition(
        "T-NAT-BINDING",
        "Tunnel that depends on a NAT binding staying alive",
        SA,
        "MEDIUM",
        "LOW",
        ("SA-003",),
        "keep NAT keepalives enabled and shorten the child lifetime behind NAT",
    ),
    ThreatDefinition(
        "T-SEQUENCE-REUSE",
        "Reused or gapped sequence numbers that weaken replay defence",
        REPLAY,
        "MEDIUM",
        "MEDIUM",
        ("REPLAY-001",),
        "investigate the sender: a correct ESP implementation never repeats a sequence number",
    ),
    ThreatDefinition(
        "T-REPLAY-WINDOW-UNKNOWN",
        "Replayed packets may be accepted, because the receiver's policy is invisible",
        REPLAY,
        "MEDIUM",
        "MEDIUM",
        ("REPLAY-002", "REPLAY-003", "REPLAY-004"),
        "confirm anti-replay is enabled on the receiver; no capture can prove it",
        from_unverified=True,
    ),
    ThreatDefinition(
        "T-SPI-VISIBILITY",
        "Per-tunnel traffic counting from clear-text SPIs",
        METADATA,
        "HIGH",
        "LOW",
        ("META-001",),
        "mix tunnels together or pad them uniformly if per-tunnel volumes matter",
    ),
    ThreatDefinition(
        "T-VOLUME-EXPOSURE",
        "Volume and burst patterns revealing activity without decryption",
        METADATA,
        "HIGH",
        "LOW",
        ("META-002",),
        "enable traffic-flow-confidentiality padding",
    ),
    ThreatDefinition(
        "T-CLASS-INFERENCE",
        "Traffic classified from metadata alone",
        METADATA,
        "MEDIUM",
        "MEDIUM",
        ("META-003",),
        "pad payloads to fixed sizes and jitter the timings",
    ),
)

#: ``threat_id -> definition``, for tests and reports that address one threat.
THREAT_INDEX: Mapping[str, ThreatDefinition] = {item.threat_id: item for item in THREAT_CATALOGUE}


def _sources(
    definition: ThreatDefinition, findings: Iterable[SecurityFinding]
) -> tuple[SecurityFinding, ...]:
    """The findings that put one threat in the report."""
    named = [finding for finding in findings if finding.rule_id in definition.rule_ids]
    if definition.from_unverified:
        return tuple(finding for finding in named if finding.status is FindingStatus.NOT_VERIFIABLE)
    return tuple(finding for finding in named if finding.status.is_weakness)


def threat_matrix(findings: Iterable[SecurityFinding]) -> tuple[ThreatObservation, ...]:
    """Build the matrix for one assessment, in catalogue order.

    Threats are included only when a finding supports them, and each entry
    records the evidence status of that finding.  A threat that exists because a
    property could not be verified carries a ``NOT_VERIFIABLE`` evidence string
    and says in words that nothing was observed, so an unverifiable deployment
    never reads as a confirmed attack.
    """
    materialised = tuple(findings)
    observations: list[ThreatObservation] = []
    for definition in THREAT_CATALOGUE:
        sources = _sources(definition, materialised)
        if not sources:
            continue
        status = strongest(*(finding.evidence_status for finding in sources))
        rule_ids = tuple(finding.rule_id for finding in sources)
        detail = f"{status.value} ({', '.join(rule_ids)})"
        if definition.from_unverified:
            detail += " - not observed: the property could not be verified from this capture"
        observations.append(
            ThreatObservation(
                threat_id=definition.threat_id,
                threat=definition.threat,
                category=definition.category,
                likelihood=definition.likelihood.upper(),
                impact=definition.impact.upper(),
                risk=definition.risk,
                evidence=detail,
                recommendation=definition.recommendation,
                rule_ids=rule_ids,
            )
        )
    return tuple(observations)


def described_threats() -> list[dict[str, Any]]:
    """The catalogue as plain data, for the generated policy reference."""
    return [definition.to_dict() for definition in THREAT_CATALOGUE]


__all__ = [
    "IMPACT_LEVELS",
    "LIKELIHOOD_LEVELS",
    "RISK_MATRIX",
    "THREAT_CATALOGUE",
    "THREAT_INDEX",
    "ThreatDefinition",
    "described_threats",
    "threat_matrix",
    "threat_risk",
]
