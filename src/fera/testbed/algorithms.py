"""IPsec/IKEv2 transform definitions.

This module is the single source of truth for how FERA names algorithms and how
those names are translated into strongSwan proposal keywords.  No other module
is allowed to hard-code strongSwan algorithm names.

Correctness rules encoded here (see ``docs/ipsec_correctness.md``):

* AES-GCM is an AEAD mode: it provides confidentiality *and* integrity in a
  single transform.  Configuring an additional HMAC for ESP is a protocol
  error, not a hardening option, so such a combination is rejected.
* AES-CBC has no built-in integrity, so a separate integrity transform
  (HMAC-SHA-256/384/512) is mandatory for ESP and for the IKE_SA.
* The IKE_SA proposal and the CHILD_SA (ESP) proposal are different objects and
  are generated separately: IKE needs ``encryption [-integrity] [-prf] -dh``,
  ESP needs ``encryption [-integrity]`` plus a DH group only when PFS is
  requested.
* PFS is expressed in strongSwan purely by the presence of a DH group in the
  CHILD_SA/ESP proposal.  "PFS disabled" therefore means "no DH group in the
  ESP proposal"; it does **not** mean "no DH group in the IKE proposal".

Reference: https://docs.strongswan.org/docs/latest/config/proposals.html and
https://docs.strongswan.org/docs/latest/config/swanctl/swanctlConf.html
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..common.errors import ErrorCode, FeraError, UnsupportedCombinationError

PROPOSALS_DOC = "https://docs.strongswan.org/docs/latest/config/proposals.html"


class EncryptionAlg(str, Enum):
    """Encryption transforms supported by FERA experiments."""

    AES128_GCM = "aes128_gcm"
    AES256_GCM = "aes256_gcm"
    AES128_CBC = "aes128_cbc"
    AES256_CBC = "aes256_cbc"

    @property
    def info(self) -> EncryptionInfo:
        return ENCRYPTION_INFO[self]


@dataclass(frozen=True)
class EncryptionInfo:
    """Static description of an encryption transform."""

    alg: EncryptionAlg
    strongswan_keyword: str
    key_bits: int
    block_mode: str
    aead: bool
    default_prf: str
    description: str

    @property
    def display(self) -> str:
        return f"AES-{self.key_bits}-{self.block_mode.upper()}"


ENCRYPTION_INFO: Mapping[EncryptionAlg, EncryptionInfo] = {
    EncryptionAlg.AES128_GCM: EncryptionInfo(
        alg=EncryptionAlg.AES128_GCM,
        strongswan_keyword="aes128gcm16",
        key_bits=128,
        block_mode="gcm",
        aead=True,
        default_prf="prfsha256",
        description="AES-128 in GCM mode with a 16 octet ICV (AEAD, no separate integrity transform)",
    ),
    EncryptionAlg.AES256_GCM: EncryptionInfo(
        alg=EncryptionAlg.AES256_GCM,
        strongswan_keyword="aes256gcm16",
        key_bits=256,
        block_mode="gcm",
        aead=True,
        default_prf="prfsha384",
        description="AES-256 in GCM mode with a 16 octet ICV (AEAD, no separate integrity transform)",
    ),
    EncryptionAlg.AES128_CBC: EncryptionInfo(
        alg=EncryptionAlg.AES128_CBC,
        strongswan_keyword="aes128",
        key_bits=128,
        block_mode="cbc",
        aead=False,
        default_prf="prfsha256",
        description="AES-128 in CBC mode (requires a separate integrity transform, e.g. HMAC-SHA-256)",
    ),
    EncryptionAlg.AES256_CBC: EncryptionInfo(
        alg=EncryptionAlg.AES256_CBC,
        strongswan_keyword="aes256",
        key_bits=256,
        block_mode="cbc",
        aead=False,
        default_prf="prfsha384",
        description="AES-256 in CBC mode (requires a separate integrity transform, e.g. HMAC-SHA-384)",
    ),
}

#: strongSwan keyword for the CBC keyword ``aes128``/``aes256`` is AES-CBC with
#: the matching key length; documented at :data:`PROPOSALS_DOC`.
CBC_KEYWORD_NOTE = "strongSwan's `aes128`/`aes256` keywords mean AES-CBC with 128/256 bit keys."


class IntegrityAlg(str, Enum):
    """Integrity transforms.

    ``AEAD`` means "integrity is provided by the AEAD encryption transform";
    it is the only legal value for AES-GCM and is rejected for AES-CBC.
    """

    AEAD = "aead"
    HMAC_SHA256 = "hmac_sha256"
    HMAC_SHA384 = "hmac_sha384"
    HMAC_SHA512 = "hmac_sha512"

    @property
    def info(self) -> IntegrityInfo:
        return INTEGRITY_INFO[self]

    @property
    def is_hmac(self) -> bool:
        return self is not IntegrityAlg.AEAD


@dataclass(frozen=True)
class IntegrityInfo:
    """Static description of an integrity transform."""

    alg: IntegrityAlg
    strongswan_keyword: str | None
    hash_bits: int | None
    description: str

    @property
    def display(self) -> str:
        if self.alg is IntegrityAlg.AEAD:
            return "AEAD (integrity provided by the AEAD encryption transform)"
        return str(self.strongswan_keyword).upper()


INTEGRITY_INFO: Mapping[IntegrityAlg, IntegrityInfo] = {
    IntegrityAlg.AEAD: IntegrityInfo(
        alg=IntegrityAlg.AEAD,
        strongswan_keyword=None,
        hash_bits=None,
        description="No separate integrity transform: the AEAD encryption transform authenticates the payload",
    ),
    IntegrityAlg.HMAC_SHA256: IntegrityInfo(
        alg=IntegrityAlg.HMAC_SHA256,
        strongswan_keyword="sha256",
        hash_bits=256,
        description="HMAC-SHA-256 (truncated to 128 bits on the wire by default)",
    ),
    IntegrityAlg.HMAC_SHA384: IntegrityInfo(
        alg=IntegrityAlg.HMAC_SHA384,
        strongswan_keyword="sha384",
        hash_bits=384,
        description="HMAC-SHA-384",
    ),
    IntegrityAlg.HMAC_SHA512: IntegrityInfo(
        alg=IntegrityAlg.HMAC_SHA512,
        strongswan_keyword="sha512",
        hash_bits=512,
        description="HMAC-SHA-512",
    ),
}

class DhGroupKind(str, Enum):
    """Family of a Diffie-Hellman group."""

    MODP = "modp"
    ECP = "ecp"
    MONTGOMERY = "montgomery"


class DhGroup(str, Enum):
    """DH/ECDH groups offered by FERA.

    The values are the strongSwan proposal keywords, so a member can be used
    directly in a proposal string.
    """

    MODP2048 = "modp2048"
    MODP3072 = "modp3072"
    MODP4096 = "modp4096"
    ECP256 = "ecp256"
    ECP384 = "ecp384"
    ECP521 = "ecp521"
    CURVE25519 = "curve25519"

    @property
    def info(self) -> DhGroupInfo:
        return DH_GROUPS[self]


@dataclass(frozen=True)
class DhGroupInfo:
    """Static description of a DH group."""

    group: DhGroup
    keyword: str
    iana_group_number: int
    kind: DhGroupKind
    strength_bits: int
    description: str
    #: True when the group needs confirmation on the target host before use
    #: (newer/optional algorithm, e.g. X25519 via the openssl plugin).
    verify_locally: bool = False

    @property
    def display(self) -> str:
        return f"{self.keyword} (IANA group {self.iana_group_number}, {self.strength_bits}-bit {self.kind.value.upper()})"


DH_GROUPS: Mapping[DhGroup, DhGroupInfo] = {
    DhGroup.MODP2048: DhGroupInfo(
        group=DhGroup.MODP2048,
        keyword="modp2048",
        iana_group_number=14,
        kind=DhGroupKind.MODP,
        strength_bits=2048,
        description="RFC 3526 group 14 modular exponentiation, weakest group offered by FERA",
    ),
    DhGroup.MODP3072: DhGroupInfo(
        group=DhGroup.MODP3072,
        keyword="modp3072",
        iana_group_number=15,
        kind=DhGroupKind.MODP,
        strength_bits=3072,
        description="RFC 3526 group 15 modular exponentiation",
    ),
    DhGroup.MODP4096: DhGroupInfo(
        group=DhGroup.MODP4096,
        keyword="modp4096",
        iana_group_number=16,
        kind=DhGroupKind.MODP,
        strength_bits=4096,
        description="RFC 3526 group 16 modular exponentiation, expensive on small testbeds",
    ),
    DhGroup.ECP256: DhGroupInfo(
        group=DhGroup.ECP256,
        keyword="ecp256",
        iana_group_number=19,
        kind=DhGroupKind.ECP,
        strength_bits=256,
        description="RFC 5903 256-bit random ECDH (NIST P-256), default ECDH group",
    ),
    DhGroup.ECP384: DhGroupInfo(
        group=DhGroup.ECP384,
        keyword="ecp384",
        iana_group_number=20,
        kind=DhGroupKind.ECP,
        strength_bits=384,
        description="RFC 5903 384-bit random ECDH (NIST P-384)",
    ),
    DhGroup.ECP521: DhGroupInfo(
        group=DhGroup.ECP521,
        keyword="ecp521",
        iana_group_number=21,
        kind=DhGroupKind.ECP,
        strength_bits=521,
        description="RFC 5903 521-bit random ECDH (NIST P-521)",
    ),
    DhGroup.CURVE25519: DhGroupInfo(
        group=DhGroup.CURVE25519,
        keyword="curve25519",
        iana_group_number=31,
        kind=DhGroupKind.MONTGOMERY,
        strength_bits=255,
        description="X25519 (RFC 8731, IANA group 31); needs X25519 support in the loaded crypto plugin",
        verify_locally=True,
    ),
}

#: Default key exchange group (widely supported, cheap, modern).
DEFAULT_DH_GROUP = DhGroup.ECP256
#: Groups used by the representative experiment matrix.
MATRIX_DH_GROUPS: tuple[DhGroup, ...] = (DhGroup.ECP256, DhGroup.ECP384, DhGroup.MODP3072)
#: Groups that are technically available in strongSwan but never offered silently.
LEGACY_EXCLUDED_GROUPS: tuple[str, ...] = ("modp768", "modp1024", "ecp192", "modp1536")


def resolve_dh_group(value: DhGroup | str) -> DhGroup:
    """Coerce a string (enum value or strongSwan keyword) into a :class:`DhGroup`."""
    if isinstance(value, DhGroup):
        return value
    text = str(value).strip().lower()
    for group in DhGroup:
        if text in {group.value.lower(), group.info.keyword.lower()}:
            return group
    raise FeraError(
        f"unsupported DH/ECDH group: {value!r}",
        code=ErrorCode.UNSUPPORTED_ALGORITHM_COMBINATION,
        hint=f"supported groups: {', '.join(group.value for group in DhGroup)}",
        details={"requested": str(value), "supported": [group.value for group in DhGroup]},
    )


def resolve_encryption(value: EncryptionAlg | str) -> EncryptionAlg:
    """Coerce a string into an :class:`EncryptionAlg`."""
    if isinstance(value, EncryptionAlg):
        return value
    text = str(value).strip().lower()
    for alg in EncryptionAlg:
        if text == alg.value.lower():
            return alg
    raise FeraError(
        f"unsupported encryption algorithm: {value!r}",
        code=ErrorCode.UNSUPPORTED_ALGORITHM_COMBINATION,
        hint=f"supported algorithms: {', '.join(alg.value for alg in EncryptionAlg)}",
        details={"requested": str(value), "supported": [alg.value for alg in EncryptionAlg]},
    )


def resolve_integrity(value: IntegrityAlg | str | None) -> IntegrityAlg:
    """Coerce a string into an :class:`IntegrityAlg`.

    ``None``, ``"none"``, ``"aead"`` and ``"gcm"`` all mean
    :attr:`IntegrityAlg.AEAD`, i.e. "integrity is provided by the AEAD
    encryption transform and no separate integrity algorithm exists".
    """
    if isinstance(value, IntegrityAlg):
        return value
    text = str(value or "aead").strip().lower()
    if text in {"none", "aead", "gcm", "aead_gcm"}:
        return IntegrityAlg.AEAD
    for alg in IntegrityAlg:
        if text == alg.value.lower():
            return alg
    raise FeraError(
        f"unsupported integrity algorithm: {value!r}",
        code=ErrorCode.UNSUPPORTED_ALGORITHM_COMBINATION,
        hint=f"supported values: {', '.join(alg.value for alg in IntegrityAlg)} (use 'aead' for AES-GCM)",
        details={"requested": str(value), "supported": [alg.value for alg in IntegrityAlg]},
    )


def dh_group_number(group: DhGroup | str) -> int:
    """Return the IANA group number for a DH group."""
    return DH_GROUPS[resolve_dh_group(group)].iana_group_number


def supported_algorithms() -> dict[str, list[str]]:
    """Return the algorithm vocabulary as plain strings (for CLI output)."""
    return {
        "encryption": [alg.value for alg in EncryptionAlg],
        "integrity": [alg.value for alg in IntegrityAlg],
        "dh_group": [group.value for group in DhGroup],
    }


#: PRF keywords accepted for the IKE_SA proposal.
PRF_KEYWORDS: tuple[str, ...] = ("prfsha256", "prfsha384", "prfsha512")


@dataclass(frozen=True)
class TransformSet:
    """A validated pair of IKE_SA and CHILD_SA transform proposals.

    The class encodes the difference between IKE_SA parameters and CHILD_SA
    parameters: :attr:`ike_proposal` may contain a PRF and always contains a DH
    group, :attr:`esp_proposal` may contain an integrity transform and contains
    a DH group *only* when PFS is enabled.
    """

    encryption: EncryptionAlg
    integrity: IntegrityAlg
    ike_dh_group: DhGroup
    pfs: bool
    child_dh_group: DhGroup | None = None
    prf: str | None = None

    def __post_init__(self) -> None:
        enc = self.encryption.info
        if enc.aead and self.integrity is not IntegrityAlg.AEAD:
            raise UnsupportedCombinationError(
                f"{enc.display} is an AEAD mode: it already authenticates the payload, "
                f"so configuring {self.integrity.value} as a separate integrity transform is invalid",
                hint="use integrity: aead (or omit it) for AES-GCM experiments",
                details={
                    "encryption": self.encryption.value,
                    "integrity": self.integrity.value,
                    "rule": "AEAD encryption must not be combined with a separate HMAC integrity transform",
                },
            )
        if not enc.aead and self.integrity is IntegrityAlg.AEAD:
            raise UnsupportedCombinationError(
                f"{enc.display} provides confidentiality only: an integrity transform "
                "(HMAC-SHA-256/384/512) is required",
                hint="set integrity to hmac_sha256, hmac_sha384 or hmac_sha512",
                details={
                    "encryption": self.encryption.value,
                    "integrity": self.integrity.value,
                    "rule": "CBC encryption requires a separate integrity transform",
                },
            )
        if self.pfs and self.child_dh_group is None:
            raise UnsupportedCombinationError(
                "PFS is enabled but no CHILD_SA DH group was provided",
                hint="set pfs_dh_group (or leave dh_group to be used for both SAs)",
                details={"pfs": self.pfs},
            )
        if not self.pfs and self.child_dh_group is not None:
            raise UnsupportedCombinationError(
                "a CHILD_SA DH group was configured while PFS is disabled: in strongSwan a DH group "
                "inside the ESP proposal *is* PFS, so the two settings cannot contradict",
                hint="set pfs: true or remove pfs_dh_group",
                details={"pfs": self.pfs, "child_dh_group": self.child_dh_group.value},
            )
        if self.prf is not None and self.prf not in PRF_KEYWORDS:
            raise UnsupportedCombinationError(
                f"unsupported IKE PRF: {self.prf!r}",
                hint=f"supported PRFs: {', '.join(PRF_KEYWORDS)}",
                details={"prf": self.prf, "supported": list(PRF_KEYWORDS)},
            )


    # -- derived properties -------------------------------------------
    @property
    def encryption_info(self) -> EncryptionInfo:
        return self.encryption.info

    @property
    def integrity_info(self) -> IntegrityInfo:
        return self.integrity.info

    @property
    def aead(self) -> bool:
        return self.encryption_info.aead

    @property
    def effective_prf(self) -> str:
        """PRF used for the IKE_SA.

        For AEAD ciphers there is no integrity algorithm to derive the PRF
        from, so the PRF is named explicitly in the proposal.  For CBC ciphers
        strongSwan derives the PRF from the integrity algorithm when the
        proposal does not name one; :attr:`prf` records that derived value.
        """
        return self.prf or self.encryption_info.default_prf

    @property
    def prf_source(self) -> str:
        if self.prf is not None:
            return "explicit"
        return "default_for_aead" if self.aead else "derived_from_integrity_algorithm"

    @property
    def ike_integrity_keyword(self) -> str | None:
        """Integrity keyword in the IKE_SA proposal (``None`` for AEAD)."""
        return self.integrity_info.strongswan_keyword

    @property
    def esp_integrity_keyword(self) -> str | None:
        """Integrity keyword in the ESP/CHILD_SA proposal (``None`` for AEAD)."""
        return self.integrity_info.strongswan_keyword

    @property
    def ike_proposal(self) -> str:
        """strongSwan IKE_SA proposal: ``encryption[-integrity|-prf]-dh``."""
        parts = [self.encryption_info.strongswan_keyword]
        if self.aead:
            parts.append(self.effective_prf)
        else:
            parts.append(str(self.esp_integrity_keyword))
        parts.append(self.ike_dh_group.info.keyword)
        return "-".join(parts)

    @property
    def esp_proposal(self) -> str:
        """strongSwan CHILD_SA (ESP) proposal.

        The DH group is present only when PFS is enabled, which is exactly how
        strongSwan expresses PFS for a CHILD_SA.
        """
        parts = [self.encryption_info.strongswan_keyword]
        if not self.aead:
            parts.append(str(self.esp_integrity_keyword))
        if self.pfs and self.child_dh_group is not None:
            parts.append(self.child_dh_group.info.keyword)
        return "-".join(parts)

    @property
    def pfs_description(self) -> str:
        """Human readable PFS state for metadata and reports."""
        if self.pfs and self.child_dh_group is not None:
            return f"enabled ({self.child_dh_group.info.display})"
        return "disabled (CHILD_SA keys derived from the IKE_SA, no DH exchange)"

    def to_dict(self) -> dict[str, Any]:
        """Serialise the transform set for ground truth / manifest use."""
        return {
            "encryption": self.encryption.value,
            "encryption_strongswan_keyword": self.encryption_info.strongswan_keyword,
            "encryption_key_bits": self.encryption_info.key_bits,
            "encryption_block_mode": self.encryption_info.block_mode,
            "aead": self.aead,
            "integrity": self.integrity.value,
            "integrity_strongswan_keyword": self.esp_integrity_keyword,
            "integrity_source": "AEAD (encryption transform)" if self.aead else "separate HMAC transform",
            "ike_prf": self.effective_prf,
            "ike_prf_source": self.prf_source,
            "ike_dh_group": self.ike_dh_group.value,
            "ike_dh_group_number": self.ike_dh_group.info.iana_group_number,
            "pfs": self.pfs,
            "child_dh_group": self.child_dh_group.value if self.child_dh_group else None,
            "child_dh_group_number": (
                self.child_dh_group.info.iana_group_number if self.child_dh_group else None
            ),
            "ike_proposal": self.ike_proposal,
            "esp_proposal": self.esp_proposal,
            "esp_proposal_contains_dh_group": bool(self.pfs and self.child_dh_group is not None),
        }


def build_transforms(
    encryption: EncryptionAlg | str,
    integrity: IntegrityAlg | str | None = None,
    *,
    dh_group: DhGroup | str = DEFAULT_DH_GROUP,
    pfs: bool = True,
    pfs_dh_group: DhGroup | str | None = None,
    prf: str | None = None,
) -> TransformSet:
    """Build a validated :class:`TransformSet` from loosely typed input.

    ``integrity=None`` (or ``"aead"``/``"none"``) is only accepted together
    with an AEAD cipher; for CBC ciphers an explicit HMAC must be given.

    ``pfs_dh_group`` defaults to ``dh_group`` when PFS is enabled and is forced
    to ``None`` when PFS is disabled, because strongSwan represents PFS as the
    presence of a DH group in the ESP proposal.
    """
    enc = resolve_encryption(encryption)
    if integrity is None:
        if not ENCRYPTION_INFO[enc].aead:
            raise UnsupportedCombinationError(
                f"no integrity algorithm configured for {ENCRYPTION_INFO[enc].display}",
                hint="AES-CBC requires integrity: hmac_sha256 | hmac_sha384 | hmac_sha512",
                details={"encryption": enc.value, "integrity": None},
            )
        integ = IntegrityAlg.AEAD
    else:
        integ = resolve_integrity(integrity)
    ike_group = resolve_dh_group(dh_group)
    if not pfs and pfs_dh_group is not None:
        raise UnsupportedCombinationError(
            "pfs_dh_group was configured although PFS is disabled: a DH group in the ESP proposal "
            "would enable PFS, so the configuration would be self-contradictory",
            hint="set pfs: true, or remove pfs_dh_group",
            details={"pfs": bool(pfs), "pfs_dh_group": str(pfs_dh_group)},
        )
    child_group = resolve_dh_group(pfs_dh_group) if (pfs and pfs_dh_group is not None) else (
        ike_group if pfs else None
    )
    return TransformSet(
        encryption=enc,
        integrity=integ,
        ike_dh_group=ike_group,
        pfs=bool(pfs),
        child_dh_group=child_group,
        prf=prf,
    )


__all__ = [
    "CBC_KEYWORD_NOTE",
    "DEFAULT_DH_GROUP",
    "DH_GROUPS",
    "ENCRYPTION_INFO",
    "INTEGRITY_INFO",
    "LEGACY_EXCLUDED_GROUPS",
    "MATRIX_DH_GROUPS",
    "PROPOSALS_DOC",
    "PRF_KEYWORDS",
    "DhGroup",
    "DhGroupInfo",
    "DhGroupKind",
    "EncryptionAlg",
    "EncryptionInfo",
    "IntegrityAlg",
    "IntegrityInfo",
    "TransformSet",
    "build_transforms",
    "dh_group_number",
    "resolve_dh_group",
    "resolve_encryption",
    "resolve_integrity",
    "supported_algorithms",
]





