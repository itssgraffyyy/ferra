"""The rulebook: every threshold, weight and strength table in one file.

Rules in :mod:`fera.security.rules` read their judgements from here so that the
"how much does this cost" question has exactly one answer in the codebase.  The
module contains no protocol parsing and no verdicts - only tables, and the small
accessors that keep them from being misread.

Vocabulary
----------
Prompt 2 reports algorithms with the IANA names it decoded from the wire
(``ENCR_AES_GCM_16``, ``AUTH_HMAC_SHA2_256_128``, ``ECP_256``), while the testbed
describes the same thing with strongSwan-era keywords (``aes128_gcm``,
``hmac_sha256``, ``ecp256``).  Both arrive at the engine - the first as
``OBSERVED`` evidence, the second as ``CONFIGURED`` evidence - so every lookup in
this module goes through :func:`canonical_algorithm`, which folds the two
vocabularies onto the wire names.  Anything unrecognised keeps its own name and
lands in :attr:`PolicyTier.UNKNOWN`, which is reported but never penalised.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..analysis.constants import DH_GROUPS_IANA, ENCRYPTION_ALGORITHMS
from .evidence import EvidenceStatus
from .models import FindingStatus, RiskLevel, SecurityCategory, Severity

#: Identity of the baseline this policy implements, echoed into every report.
POLICY_ID = "fera_baseline"
POLICY_VERSION = "1.0.0"

#: ``AEAD`` is not a wire name: it is how the testbed says "no separate
#: integrity transform, the AEAD cipher authenticates the payload".
AEAD_SENTINEL = "AEAD"


class PolicyTier(str, Enum):
    """How the baseline judges one algorithm choice.

    ``FORBIDDEN`` means the algorithm must not be used at all (broken or
    null), ``DEPRECATED`` means it is still interoperable but below the
    baseline's strength floor, ``ACCEPTABLE`` meets the floor, ``RECOMMENDED``
    is what the baseline would configure itself, and ``UNKNOWN`` means the
    engine has no opinion and must say so instead of guessing.
    """

    RECOMMENDED = "RECOMMENDED"
    ACCEPTABLE = "ACCEPTABLE"
    DEPRECATED = "DEPRECATED"
    FORBIDDEN = "FORBIDDEN"
    UNKNOWN = "UNKNOWN"

    @property
    def is_weakness(self) -> bool:
        """Whether a proposal in this tier is a weakness worth reporting."""
        return self in (PolicyTier.DEPRECATED, PolicyTier.FORBIDDEN)


#: Tier -> severity of the finding it produces when it is the effective choice.
TIER_SEVERITY: dict[PolicyTier, Severity] = {
    PolicyTier.FORBIDDEN: Severity.CRITICAL,
    PolicyTier.DEPRECATED: Severity.HIGH,
    PolicyTier.ACCEPTABLE: Severity.INFO,
    PolicyTier.RECOMMENDED: Severity.INFO,
    PolicyTier.UNKNOWN: Severity.INFO,
}

#: Tier -> how far below the category ceiling the deduction lands, as a factor
#: of the tier's base points.  ``UNKNOWN`` has no base points at all.
TIER_BASE_POINTS: dict[PolicyTier, float] = {
    PolicyTier.FORBIDDEN: 20.0,
    PolicyTier.DEPRECATED: 12.0,
    PolicyTier.ACCEPTABLE: 0.0,
    PolicyTier.RECOMMENDED: 0.0,
    PolicyTier.UNKNOWN: 0.0,
}


@dataclass(frozen=True)
class AlgorithmPolicy:
    """The baseline's opinion of one algorithm, with the reason attached."""

    name: str
    tier: PolicyTier
    reason: str
    references: tuple[str, ...] = ()
    #: Security strength the algorithm actually delivers (bits), when it makes
    #: sense to state it.  Never inferred from the name.
    strength_bits: int | None = None

    @property
    def is_weakness(self) -> bool:
        return self.tier.is_weakness

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "tier": self.tier.value,
            "reason": self.reason,
            "references": list(self.references),
            "strength_bits": self.strength_bits,
        }


_RFC_8247_ENCRYPTION = "RFC 8247 section 2.1 (IKEv2 encryption algorithm transforms)"
_RFC_8247_PRF = "RFC 8247 section 2.2 (IKEv2 pseudorandom function transforms)"
_RFC_8247_INTEGRITY = "RFC 8247 section 2.3 (IKEv2 integrity algorithm transforms)"
_RFC_8247_DH = "RFC 8247 section 2.4 (IKEv2 Diffie-Hellman group transforms)"
_RFC_8247 = "RFC 8247 section 2 (IKEv2 algorithm implementation requirements)"
_SP_800_57 = "NIST SP 800-57 Part 1 Rev.5 Table 2 (security strength of algorithms)"
_SP_800_131A = "NIST SP 800-131A Rev.2 (transitions to stronger algorithms)"
_LOGJAM = "Ada et al., Logjam: Practical weak-field attacks in Diffie-Hellman, USENIX Security 2016"
_SWEET32 = "Bhargavan and Leurent, Sweet32, ACM CCS 2016"
_IPSEC_SCAN = "Fiterau-Brostean et al., Weak Parameters Not Deployed?, PAM 2017"


def _policy(
    name: str,
    tier: PolicyTier,
    reason: str,
    references: tuple[str, ...],
    strength_bits: int | None = None,
) -> AlgorithmPolicy:
    return AlgorithmPolicy(name, tier, reason, references, strength_bits)


# --------------------------------------------------------------------------
# Encryption transforms (keyed by the wire names Prompt 2 decodes)
# --------------------------------------------------------------------------
ENCRYPTION_POLICIES: dict[str, AlgorithmPolicy] = {
    "ENCR_AES_GCM_16": _policy(
        "ENCR_AES_GCM_16",
        PolicyTier.RECOMMENDED,
        "AES-GCM with a 128-bit ICV encrypts and authenticates in one transform; the "
        "full-length tag keeps a forgery attempt near 2^-128",
        (_RFC_8247_ENCRYPTION, "RFC 5282 section 3 (AES-GCM in IKEv2)"),
        128,
    ),
    "ENCR_AES_GCM_12": _policy(
        "ENCR_AES_GCM_12",
        PolicyTier.ACCEPTABLE,
        "AES-GCM with a 96-bit ICV: the cipher is fine, the shorter tag moves the "
        "forgery bound to roughly 2^-96",
        (_RFC_8247_ENCRYPTION, "RFC 5282 section 3 (AES-GCM in IKEv2)"),
        96,
    ),
    "ENCR_AES_GCM_8": _policy(
        "ENCR_AES_GCM_8",
        PolicyTier.DEPRECATED,
        "AES-GCM with a 64-bit ICV: a birthday-bound forgery effort near 2^32 packets "
        "is reachable on a busy tunnel, which is also why the truncated tag is the "
        "one place ESP's integrity stops being free",
        (_RFC_8247_ENCRYPTION, "RFC 5282 section 3 (AES-GCM in IKEv2)"),
        64,
    ),
    "ENCR_CHACHA20_POLY1305": _policy(
        "ENCR_CHACHA20_POLY1305",
        PolicyTier.RECOMMENDED,
        "AEAD with a 128-bit tag and no hardware dependency; the preferred choice on "
        "endpoints without AES instructions",
        (_RFC_8247_ENCRYPTION, "RFC 7634 section 2 (ChaCha20-Poly1305 in IPsec)"),
        128,
    ),
    "ENCR_AES_CBC": _policy(
        "ENCR_AES_CBC",
        PolicyTier.ACCEPTABLE,
        "AES-CBC provides confidentiality only, so a separate integrity transform is "
        "mandatory; padding oracles such as Lucky13 are mitigated, not designed away",
        (_RFC_8247_ENCRYPTION, "RFC 3602 section 1 (AES-CBC with HMAC in IPsec)"),
        128,
    ),
    "ENCR_3DES": _policy(
        "ENCR_3DES",
        PolicyTier.DEPRECATED,
        "3DES has a 64-bit block, so a birthday collision appears after a few million "
        "packets and turns the tunnel into a Sweet32-style ciphertext sampling "
        "problem; effective strength is 112 bits, not 168",
        (_RFC_8247_ENCRYPTION, _SP_800_131A, _SWEET32),
        112,
    ),
    "ENCR_DES": _policy(
        "ENCR_DES",
        PolicyTier.FORBIDDEN,
        "Single-DES has a 56-bit key, exhaustible with dedicated hardware, and a "
        "64-bit block",
        (_SP_800_131A, _RFC_8247_ENCRYPTION),
        56,
    ),
    "ENCR_DES_IV64": _policy(
        "ENCR_DES_IV64",
        PolicyTier.FORBIDDEN,
        "A 64-bit initialisation-vector variant of single-DES, so the same 56-bit key",
        (_RFC_8247_ENCRYPTION,),
        56,
    ),
    "ENCR_NULL": _policy(
        "ENCR_NULL",
        PolicyTier.FORBIDDEN,
        "NULL encryption leaves the payload in clear text; it exists for "
        "authentication-only testing and must never carry user traffic",
        ("RFC 2410 (the NULL encryption algorithm with IPsec)",),
        0,
    ),
}


# --------------------------------------------------------------------------
# Integrity transforms
# --------------------------------------------------------------------------
INTEGRITY_POLICIES: dict[str, AlgorithmPolicy] = {
    AEAD_SENTINEL: _policy(
        AEAD_SENTINEL,
        PolicyTier.RECOMMENDED,
        "No separate integrity transform, because the negotiated AEAD cipher already "
        "authenticates the payload; this is the intended configuration, not a gap",
        (_RFC_8247_INTEGRITY, "RFC 5282 section 2 (AEAD transforms in IKEv2)"),
        None,
    ),
    "AUTH_HMAC_SHA2_256_128": _policy(
        "AUTH_HMAC_SHA2_256_128",
        PolicyTier.RECOMMENDED,
        "HMAC-SHA-256 with a 128-bit truncated tag meets the 128-bit integrity target",
        (_RFC_8247_INTEGRITY,),
        128,
    ),
    "AUTH_HMAC_SHA2_384_192": _policy(
        "AUTH_HMAC_SHA2_384_192",
        PolicyTier.RECOMMENDED,
        "HMAC-SHA-384 with a 192-bit tag, the pairing RFC 8247 gives AES-256 suites",
        (_RFC_8247_INTEGRITY,),
        192,
    ),
    "AUTH_HMAC_SHA2_512_256": _policy(
        "AUTH_HMAC_SHA2_512_256",
        PolicyTier.RECOMMENDED,
        "HMAC-SHA-512 with a 256-bit tag",
        (_RFC_8247_INTEGRITY,),
        256,
    ),
    "AUTH_HMAC_SHA1_96": _policy(
        "AUTH_HMAC_SHA1_96",
        PolicyTier.DEPRECATED,
        "HMAC-SHA1-96 still resists forgery, but SHA-1 is deprecated for security use "
        "and the 96-bit tag puts collisions within a 2^-48 birthday bound",
        (_RFC_8247_INTEGRITY, _SP_800_131A),
        96,
    ),
    "AUTH_HMAC_MD5_96": _policy(
        "AUTH_HMAC_MD5_96",
        PolicyTier.FORBIDDEN,
        "MD5 has practical collisions and the transform truncates to 96 bits; it "
        "survives only for legacy interoperability",
        (_RFC_8247_INTEGRITY, _SP_800_131A),
        64,
    ),
    "NONE": _policy(
        "NONE",
        PolicyTier.FORBIDDEN,
        "No integrity transform at all: an on-path attacker can edit packets and the "
        "receiver has no way to notice",
        ("RFC 4303 section 3.4.4 (ICV verification)",),
        0,
    ),
}

# --------------------------------------------------------------------------
# Pseudorandom functions
# --------------------------------------------------------------------------
PRF_POLICIES: dict[str, AlgorithmPolicy] = {
    "PRF_HMAC_SHA2_256": _policy(
        "PRF_HMAC_SHA2_256",
        PolicyTier.RECOMMENDED,
        "SHA-256 based PRF, the IKEv2 default for 128-bit suites",
        (_RFC_8247_PRF,),
        128,
    ),
    "PRF_HMAC_SHA2_384": _policy(
        "PRF_HMAC_SHA2_384",
        PolicyTier.RECOMMENDED,
        "SHA-384 based PRF, the pairing RFC 8247 gives 256-bit encryption",
        (_RFC_8247_PRF,),
        192,
    ),
    "PRF_HMAC_SHA2_512": _policy(
        "PRF_HMAC_SHA2_512",
        PolicyTier.RECOMMENDED,
        "SHA-512 based PRF",
        (_RFC_8247_PRF,),
        256,
    ),
    "PRF_AES128_XCBC": _policy(
        "PRF_AES128_XCBC",
        PolicyTier.ACCEPTABLE,
        "AES-XCBC PRF: sound, but rarely implemented and no longer a default",
        (_RFC_8247_PRF, "RFC 4434 section 2 (AES-XCBC-PRF-128 for IKE)"),
        128,
    ),
    "PRF_AES128_CMAC": _policy(
        "PRF_AES128_CMAC",
        PolicyTier.ACCEPTABLE,
        "AES-CMAC PRF: sound, but rarely negotiated in current deployments",
        (_RFC_8247_PRF, "RFC 4434 section 3 (AES-CMAC-PRF-128 for IKE)"),
        128,
    ),
    "PRF_HMAC_SHA1": _policy(
        "PRF_HMAC_SHA1",
        PolicyTier.DEPRECATED,
        "SHA-1 based PRF; deprecated for new deployments even though HMAC hides the "
        "published SHA-1 collision attacks",
        (_RFC_8247_PRF, _SP_800_131A),
        80,
    ),
    "PRF_HMAC_MD5": _policy(
        "PRF_HMAC_MD5",
        PolicyTier.FORBIDDEN,
        "MD5 based PRF: derived keying material must not depend on MD5",
        (_RFC_8247_PRF, _SP_800_131A),
        64,
    ),
}


# --------------------------------------------------------------------------
# Diffie-Hellman groups
# --------------------------------------------------------------------------
#: ``strength_bits`` below is the security strength left after the discrete-log
#: attack, not the group's bit length, which is why MODP-3072 (128 bits of
#: strength) and ECP-256 (128 bits) share a tier while MODP-2048 (112 bits) does
#: not.
DH_POLICIES: dict[str, AlgorithmPolicy] = {
    policy.name: policy
    for policy in (
        _policy(
            "CURVE25519",
            PolicyTier.RECOMMENDED,
            "Curve25519: 128-bit strength, constant-time implementations are the norm "
            "and the group has no small-subgroup traps",
            (_RFC_8247_DH, _SP_800_57),
            128,
        ),
        _policy(
            "ECP_256",
            PolicyTier.RECOMMENDED,
            "NIST P-256: the cheapest group that reaches the 128-bit target",
            (_RFC_8247_DH, _SP_800_57),
            128,
        ),
        _policy(
            "ECP_384",
            PolicyTier.RECOMMENDED,
            "NIST P-384: 192-bit strength, the pairing this baseline gives AES-256",
            (_RFC_8247_DH, _SP_800_57),
            192,
        ),
        _policy(
            "ECP_521",
            PolicyTier.RECOMMENDED,
            "NIST P-521: 256-bit strength, more than the assessment requires",
            (_RFC_8247_DH, _SP_800_57),
            256,
        ),
        _policy(
            "MODP_2048",
            PolicyTier.ACCEPTABLE,
            "MODP-2048 is the interoperability floor and is worth about 112 bits, one "
            "notch below the 128-bit target of this baseline",
            (_RFC_8247_DH, _SP_800_57),
            112,
        ),
        _policy(
            "MODP_3072",
            PolicyTier.RECOMMENDED,
            "MODP-3072 reaches the 128-bit target for finite-field groups",
            (_RFC_8247_DH, _SP_800_57),
            128,
        ),
        _policy(
            "MODP_4096",
            PolicyTier.RECOMMENDED,
            "MODP-4096: above the target at the cost of a larger exponentiation",
            (_RFC_8247_DH, _SP_800_57),
            140,
        ),
        _policy(
            "MODP_6144",
            PolicyTier.RECOMMENDED,
            "MODP-6144: well above the target",
            (_RFC_8247_DH, _SP_800_57),
            152,
        ),
        _policy(
            "MODP_8192",
            PolicyTier.RECOMMENDED,
            "MODP-8192: well above the target, rarely negotiated because of its cost",
            (_RFC_8247_DH, _SP_800_57),
            176,
        ),
        _policy(
            "MODP_1536",
            PolicyTier.DEPRECATED,
            "MODP-1536 is worth roughly 96 bits, below the 112-bit floor SP 800-131A "
            "sets for finite-field Diffie-Hellman",
            (_RFC_8247_DH, _SP_800_131A, _IPSEC_SCAN),
            96,
        ),
        _policy(
            "MODP_1024",
            PolicyTier.FORBIDDEN,
            "A 1024-bit MODP group is within reach of a precomputation attack "
            "(Logjam), which also means recorded IKE_SA_INIT exchanges can be "
            "decrypted later once that precomputation is amortised",
            (_LOGJAM, _SP_800_131A, _IPSEC_SCAN),
            80,
        ),
        _policy(
            "MODP_768",
            PolicyTier.FORBIDDEN,
            "A 768-bit MODP group falls to academic-scale resources and must not "
            "appear in any proposal",
            (_LOGJAM, _SP_800_131A, _IPSEC_SCAN),
            64,
        ),
    )
}



# --------------------------------------------------------------------------
# Vocabulary folding: wire names, testbed keywords and group numbers
# --------------------------------------------------------------------------
_ENCRYPTION_ALIASES: dict[str, str] = {
    "aes128_gcm": "ENCR_AES_GCM_16",
    "aes192_gcm": "ENCR_AES_GCM_16",
    "aes256_gcm": "ENCR_AES_GCM_16",
    "aes128gcm16": "ENCR_AES_GCM_16",
    "aes192gcm16": "ENCR_AES_GCM_16",
    "aes256gcm16": "ENCR_AES_GCM_16",
    "aes_gcm": "ENCR_AES_GCM_16",
    "aes128_gcm12": "ENCR_AES_GCM_12",
    "aes256_gcm12": "ENCR_AES_GCM_12",
    "aes128_gcm8": "ENCR_AES_GCM_8",
    "aes256_gcm8": "ENCR_AES_GCM_8",
    "aes128_cbc": "ENCR_AES_CBC",
    "aes192_cbc": "ENCR_AES_CBC",
    "aes256_cbc": "ENCR_AES_CBC",
    "aes128": "ENCR_AES_CBC",
    "aes256": "ENCR_AES_CBC",
    "aes_cbc": "ENCR_AES_CBC",
    "chacha20poly1305": "ENCR_CHACHA20_POLY1305",
    "3des": "ENCR_3DES",
    "3des_cbc": "ENCR_3DES",
    "des3": "ENCR_3DES",
    "des": "ENCR_DES",
    "null": "ENCR_NULL",
}

_INTEGRITY_ALIASES: dict[str, str] = {
    "aead": AEAD_SENTINEL,
    "hmac_sha256": "AUTH_HMAC_SHA2_256_128",
    "sha256": "AUTH_HMAC_SHA2_256_128",
    "hmac_sha384": "AUTH_HMAC_SHA2_384_192",
    "sha384": "AUTH_HMAC_SHA2_384_192",
    "hmac_sha512": "AUTH_HMAC_SHA2_512_256",
    "sha512": "AUTH_HMAC_SHA2_512_256",
    "hmac_sha1": "AUTH_HMAC_SHA1_96",
    "hmac_sha_1_96": "AUTH_HMAC_SHA1_96",
    "sha1": "AUTH_HMAC_SHA1_96",
    "hmac_md5": "AUTH_HMAC_MD5_96",
    "md5": "AUTH_HMAC_MD5_96",
    "none": "NONE",
    "null": "NONE",
}

_PRF_ALIASES: dict[str, str] = {
    "prfsha256": "PRF_HMAC_SHA2_256",
    "prf_hmac_sha2_256": "PRF_HMAC_SHA2_256",
    "sha256": "PRF_HMAC_SHA2_256",
    "prfsha384": "PRF_HMAC_SHA2_384",
    "sha384": "PRF_HMAC_SHA2_384",
    "prfsha512": "PRF_HMAC_SHA2_512",
    "sha512": "PRF_HMAC_SHA2_512",
    "prfsha1": "PRF_HMAC_SHA1",
    "sha1": "PRF_HMAC_SHA1",
    "prfmd5": "PRF_HMAC_MD5",
    "md5": "PRF_HMAC_MD5",
    "aes_xcbc": "PRF_AES128_XCBC",
    "aes_cmac": "PRF_AES128_CMAC",
}

_DH_ALIASES: dict[str, str] = {
    "modp768": "MODP_768",
    "group1": "MODP_768",
    "modp1024": "MODP_1024",
    "group2": "MODP_1024",
    "modp1536": "MODP_1536",
    "group5": "MODP_1536",
    "modp2048": "MODP_2048",
    "group14": "MODP_2048",
    "modp3072": "MODP_3072",
    "group15": "MODP_3072",
    "modp4096": "MODP_4096",
    "group16": "MODP_4096",
    "modp6144": "MODP_6144",
    "group17": "MODP_6144",
    "modp8192": "MODP_8192",
    "group18": "MODP_8192",
    "ecp256": "ECP_256",
    "nistp256": "ECP_256",
    "group19": "ECP_256",
    "ecp384": "ECP_384",
    "nistp384": "ECP_384",
    "group20": "ECP_384",
    "ecp521": "ECP_521",
    "nistp521": "ECP_521",
    "group21": "ECP_521",
    "curve25519": "CURVE25519",
    "x25519": "CURVE25519",
    "group31": "CURVE25519",
}

#: IANA group number -> wire name, taken from the analyser's own table so the two
#: stages cannot drift apart on group numbering.
_DH_BY_NUMBER: dict[int, str] = {
    int(number): str(info["name"]) for number, info in DH_GROUPS_IANA.items()
}


def _compact(text: object) -> str:
    """Lower-case ``text`` with every separator removed.

    ``AES-256-GCM``, ``aes_256_gcm`` and ``AES256GCM`` all become ``aes256gcm``, so
    one alias entry covers every spelling a capture or a config file may use.  The
    tables below stay readable; this folding happens when they are indexed.
    """
    return "".join(character for character in str(text).lower() if character.isalnum())


def _index(aliases: Mapping[str, str], table: Mapping[str, AlgorithmPolicy]) -> dict[str, str]:
    """Compact-key index of an alias map plus the table's own wire names."""
    index = {_compact(alias): target for alias, target in aliases.items()}
    index.update({_compact(name): name for name in table})
    return index


_ENCRYPTION_INDEX = _index(_ENCRYPTION_ALIASES, ENCRYPTION_POLICIES)
_INTEGRITY_INDEX = _index(_INTEGRITY_ALIASES, INTEGRITY_POLICIES)
_PRF_INDEX = _index(_PRF_ALIASES, PRF_POLICIES)
_DH_INDEX = _index(_DH_ALIASES, DH_POLICIES)


def _fold(raw: object, index: Mapping[str, str]) -> str:
    """Resolve one spelling through ``index``; empty string when unstated."""
    text = str(raw).strip()
    if not text:
        return ""
    return index.get(_compact(text), text.upper())


def canonical_encryption(raw: object) -> str:
    """Wire name for an encryption algorithm, or the folded input when unknown."""
    return _fold(raw, _ENCRYPTION_INDEX)


def canonical_integrity(raw: object) -> str:
    """Wire name (or :data:`AEAD_SENTINEL`) for an integrity algorithm."""
    return _fold(raw, _INTEGRITY_INDEX)


def canonical_prf(raw: object) -> str:
    """Wire name for a PRF, or the folded input when unknown."""
    return _fold(raw, _PRF_INDEX)


def canonical_dh(raw: object) -> str:
    """Wire name for a DH group given as a number, keyword or wire name."""
    if isinstance(raw, bool):
        return ""
    if isinstance(raw, int):
        return _DH_BY_NUMBER.get(raw, f"DH_GROUP_{raw}")
    text = str(raw).strip()
    if not text:
        return ""
    if text.isdigit():
        return _DH_BY_NUMBER.get(int(text), f"DH_GROUP_{text}")
    return _fold(text, _DH_INDEX)



# --------------------------------------------------------------------------
# Lookups
# --------------------------------------------------------------------------
#: AEAD-ness and tag length come from the analyser's transform table so that a
#: future AEAD addition cannot silently look like a confidentiality-only cipher
#: here; the assessment's own table is about strength, not about mode structure.
_AEAD_BY_NAME: dict[str, Mapping[str, Any]] = {
    str(info["name"]): info for info in ENCRYPTION_ALGORITHMS.values() if info.get("aead")
}


def _unknown(raw: object, kind: str) -> AlgorithmPolicy:
    """The policy for something this baseline has no entry for."""
    name = str(raw).strip() or "UNSPECIFIED"
    return AlgorithmPolicy(
        name=name,
        tier=PolicyTier.UNKNOWN,
        reason=(
            f"{name} is not in the {POLICY_ID} {kind} table, so the assessment states "
            "that it cannot judge it instead of guessing a strength for it"
        ),
        references=(_RFC_8247,),
        strength_bits=None,
    )


def encryption_policy(raw: object) -> AlgorithmPolicy:
    """Strength of an encryption transform named in either vocabulary."""
    name = canonical_encryption(raw)
    return ENCRYPTION_POLICIES.get(name) or _unknown(raw, "encryption")


def integrity_policy(raw: object) -> AlgorithmPolicy:
    """Strength of an integrity transform named in either vocabulary."""
    name = canonical_integrity(raw)
    return INTEGRITY_POLICIES.get(name) or _unknown(raw, "integrity")


def prf_policy(raw: object) -> AlgorithmPolicy:
    """Strength of a pseudorandom function named in either vocabulary."""
    name = canonical_prf(raw)
    return PRF_POLICIES.get(name) or _unknown(raw, "PRF")


def dh_policy(raw: object) -> AlgorithmPolicy:
    """Strength of a Diffie-Hellman group given as number, keyword or wire name."""
    name = canonical_dh(raw)
    return DH_POLICIES.get(name) or _unknown(raw, "Diffie-Hellman group")


def is_aead(raw: object) -> bool:
    """Whether an encryption transform already authenticates the payload."""
    return canonical_encryption(raw) in _AEAD_BY_NAME


def aead_tag_bits(raw: object) -> int | None:
    """Authentication tag length of an AEAD transform, when it is one."""
    info = _AEAD_BY_NAME.get(canonical_encryption(raw))
    return None if info is None else int(info.get("icv_bits", 0))


def requires_separate_integrity(raw: object) -> bool:
    """Whether a cipher on its own leaves the payload unauthenticated.

    NULL encryption counts as not requiring integrity only in the trivial sense
    that it is already broken; the encryption rule reports it directly, so this
    stays ``False`` to keep the two rules from double counting.
    """
    name = canonical_encryption(raw)
    if name == "ENCR_NULL":
        return False
    return bool(name) and name not in _AEAD_BY_NAME


# --------------------------------------------------------------------------
# Lifetime ceilings
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class LifetimeCeilings:
    """How long one SA may stay in service before this baseline complains.

    The numbers are engineering judgement, not a normative requirement: RFC 7296
    requires rekeying to be *possible* but leaves lifetime choice to the operator,
    so the ceilings below state the exposure this project is willing to accept
    per key, and every report says so rather than quoting a standard.
    """

    preferred_s: int
    acceptable_s: int
    maximum_s: int
    rationale: str

    def tier_for(self, seconds: float | None) -> PolicyTier:
        """Tier for a lifetime in seconds (``None`` means not stated)."""
        if seconds is None:
            return PolicyTier.UNKNOWN
        if seconds <= 0:
            return PolicyTier.FORBIDDEN
        if seconds <= self.preferred_s:
            return PolicyTier.RECOMMENDED
        if seconds <= self.acceptable_s:
            return PolicyTier.ACCEPTABLE
        if seconds <= self.maximum_s:
            return PolicyTier.DEPRECATED
        return PolicyTier.FORBIDDEN


IKE_LIFETIME = LifetimeCeilings(
    preferred_s=28800,
    acceptable_s=86400,
    maximum_s=604800,
    rationale=(
        "an IKE SA key protects every child SA derived from it, so one day is the "
        "most exposure this baseline accepts and eight hours is the target"
    ),
)
CHILD_LIFETIME = LifetimeCeilings(
    preferred_s=1800,
    acceptable_s=3600,
    maximum_s=86400,
    rationale=(
        "a child SA key protects the bulk data flow, so the window in which a "
        "compromised key decrypts traffic should be minutes, not days"
    ),
)



# --------------------------------------------------------------------------
# Scoring arithmetic (the numbers themselves live here, the arithmetic in
# scoring.py)
# --------------------------------------------------------------------------
#: Category weights, summing to exactly 1.0.  Cryptography and key exchange carry
#: most of the weight because a broken algorithm or a missing PFS exchange
#: compromises the tunnel itself, while metadata exposure degrades only what an
#: observer can learn around it.
CATEGORY_WEIGHTS: dict[SecurityCategory, float] = {
    SecurityCategory.CRYPTOGRAPHY: 0.28,
    SecurityCategory.KEY_EXCHANGE: 0.24,
    SecurityCategory.SA_SECURITY: 0.14,
    SecurityCategory.REPLAY_PROTECTION: 0.12,
    SecurityCategory.CONFIGURATION: 0.12,
    SecurityCategory.METADATA_PRIVACY: 0.10,
}

#: How much of a rule's base deduction a verdict keeps.
STATUS_FACTORS: dict[FindingStatus, float] = {
    FindingStatus.FAIL: 1.0,
    FindingStatus.WARNING: 0.4,
    FindingStatus.PASS: 0.0,
    FindingStatus.NOT_VERIFIABLE: 0.0,
}

#: How much of a verdict the provenance is worth.  ``CONFIGURED`` is discounted
#: because a configured parameter is not proof of negotiated behaviour;
#: ``INFERRED`` is discounted twice over (the model may be wrong, and its
#: confidence is multiplied in as well); ``NOT_VERIFIABLE`` is worth nothing,
#: which is the whole point of the status.
EVIDENCE_FACTORS: dict[EvidenceStatus, float] = {
    EvidenceStatus.OBSERVED: 1.0,
    EvidenceStatus.CONFIGURED: 0.85,
    EvidenceStatus.INFERRED: 0.5,
    EvidenceStatus.NOT_VERIFIABLE: 0.0,
}

#: Weight of each evidence status in ``evidence_coverage`` (see scoring.py).  A
#: property settled from the wire counts fully, a configured one counts
#: three-quarters, an inferred one counts half, and an unverifiable one not at all.
COVERAGE_WEIGHTS: dict[EvidenceStatus, float] = {
    EvidenceStatus.OBSERVED: 1.0,
    EvidenceStatus.CONFIGURED: 0.75,
    EvidenceStatus.INFERRED: 0.5,
    EvidenceStatus.NOT_VERIFIABLE: 0.0,
}


def evidence_factor(status: EvidenceStatus, confidence: float = 1.0) -> float:
    """Deduction factor for one verdict's provenance.

    For ``INFERRED`` verdicts the model's own confidence scales the factor, so a
    55 percent guess costs less than a 99 percent one - but the verdict is still
    labelled inferred, because scaling a guess does not turn it into a measurement.
    """
    if status is EvidenceStatus.INFERRED:
        return EVIDENCE_FACTORS[status] * max(0.0, min(1.0, confidence))
    return EVIDENCE_FACTORS[status]


#: Security-score bands.  A score is only as trustworthy as its evidence, which is
#: reported next to it rather than folded into it.
RISK_BANDS: tuple[tuple[float, RiskLevel], ...] = (
    (85.0, RiskLevel.LOW),
    (70.0, RiskLevel.MODERATE),
    (50.0, RiskLevel.HIGH),
    (0.0, RiskLevel.CRITICAL),
)


def risk_level(security_score: float) -> RiskLevel:
    """Band for a 0-100 security score (higher is better)."""
    for floor, level in RISK_BANDS:
        if security_score >= floor:
            return level
    return RiskLevel.CRITICAL


# --------------------------------------------------------------------------
# Observation thresholds
# --------------------------------------------------------------------------
#: Below this many observed ESP packets, sequence-number and length statistics
#: say too little to draw a conclusion from, and the rules say so instead.
MIN_PACKETS_FOR_SEQUENCE_ANALYSIS = 20


@dataclass(frozen=True)
class MetadataThresholds:
    """When an observer can plausibly learn something from the unencrypted shell."""

    #: Fewer distinct observed payload sizes than this means the traffic collapses
    #: into a handful of message-length classes that a passive observer can label.
    distinct_length_classes_min: int = 4
    #: Share of ESP packets that land exactly on a block or padding boundary; at or
    #: above this, traffic-flow-confidentiality padding is plausibly in use.
    padding_aligned_share: float = 0.9
    #: A class prediction is only worth reporting as a finding at or above this
    #: confidence; below it the assessment states the guess without acting on it.
    prediction_confidence_min: float = 0.6
    #: ``-log2(confidence)`` at which a prediction is called inconclusive.
    prediction_surprisal_max_bits: float = 1.0


METADATA_THRESHOLDS = MetadataThresholds(
    distinct_length_classes_min=4,
    padding_aligned_share=0.9,
    prediction_confidence_min=0.6,
    prediction_surprisal_max_bits=1.0,
)



#: Alias tables keyed by vocabulary, so the generated reference can show which
#: spellings the engine understands (testbed keywords, strongSwan keywords, IANA
#: group numbers and wire names all fold onto the same entry).
POLICY_ALIASES: dict[str, dict[str, str]] = {
    "encryption": dict(sorted(_ENCRYPTION_ALIASES.items())),
    "integrity": dict(sorted(_INTEGRITY_ALIASES.items())),
    "prf": dict(sorted(_PRF_ALIASES.items())),
    "diffie_hellman": dict(sorted(_DH_ALIASES.items())),
}


# --------------------------------------------------------------------------
# Self-description (consumed by scripts/generate_security_policy_docs.py)
# --------------------------------------------------------------------------
def policy_catalogue() -> dict[str, Any]:
    """Every table in this module as plain data, for the generated reference."""
    return {
        "policy_id": POLICY_ID,
        "policy_version": POLICY_VERSION,
        "aead_sentinel": AEAD_SENTINEL,
        "tier_severity": {tier.value: severity.value for tier, severity in TIER_SEVERITY.items()},
        "tier_base_points": {tier.value: points for tier, points in TIER_BASE_POINTS.items()},
        "encryption": [policy.to_dict() for policy in ENCRYPTION_POLICIES.values()],
        "integrity": [policy.to_dict() for policy in INTEGRITY_POLICIES.values()],
        "prf": [policy.to_dict() for policy in PRF_POLICIES.values()],
        "diffie_hellman": [policy.to_dict() for policy in DH_POLICIES.values()],
        "lifetimes": {
            "ike": {
                "preferred_s": IKE_LIFETIME.preferred_s,
                "acceptable_s": IKE_LIFETIME.acceptable_s,
                "maximum_s": IKE_LIFETIME.maximum_s,
                "rationale": IKE_LIFETIME.rationale,
            },
            "child": {
                "preferred_s": CHILD_LIFETIME.preferred_s,
                "acceptable_s": CHILD_LIFETIME.acceptable_s,
                "maximum_s": CHILD_LIFETIME.maximum_s,
                "rationale": CHILD_LIFETIME.rationale,
            },
        },
        "category_weights": {
            category.value: weight for category, weight in CATEGORY_WEIGHTS.items()
        },
        "status_factors": {status.value: factor for status, factor in STATUS_FACTORS.items()},
        "evidence_factors": {
            status.value: factor for status, factor in EVIDENCE_FACTORS.items()
        },
        "coverage_weights": {
            status.value: weight for status, weight in COVERAGE_WEIGHTS.items()
        },
        "risk_bands": [
            {"min_security_score": floor, "risk_level": level.value}
            for floor, level in RISK_BANDS
        ],
        "metadata_thresholds": {
            "distinct_length_classes_min": METADATA_THRESHOLDS.distinct_length_classes_min,
            "padding_aligned_share_max": METADATA_THRESHOLDS.padding_aligned_share,
            "prediction_confidence_min": METADATA_THRESHOLDS.prediction_confidence_min,
            "prediction_surprisal_max_bits": METADATA_THRESHOLDS.prediction_surprisal_max_bits,
        },
        "min_packets_for_sequence_analysis": MIN_PACKETS_FOR_SEQUENCE_ANALYSIS,
    }


def check_policy() -> None:
    """Fail loudly if the tables contradict themselves.

    Called by the test suite, because a policy that sums to the wrong total or
    forgets a tier is exactly the kind of mistake that would otherwise surface as
    an inexplicable score.
    """
    total = sum(CATEGORY_WEIGHTS.values())
    if abs(total - 1.0) > 1e-9:
        raise AssertionError(f"CATEGORY_WEIGHTS must sum to 1.0 (got {total})")
    if set(CATEGORY_WEIGHTS) != set(SecurityCategory):
        raise AssertionError("every SecurityCategory needs a weight")
    for name, table, universe in (
        ("STATUS_FACTORS", STATUS_FACTORS, tuple(FindingStatus)),
        ("EVIDENCE_FACTORS", EVIDENCE_FACTORS, tuple(EvidenceStatus)),
        ("COVERAGE_WEIGHTS", COVERAGE_WEIGHTS, tuple(EvidenceStatus)),
    ):
        missing = [key.value for key in universe if key not in table]
        if missing:
            raise AssertionError(f"{name} has no entry for {', '.join(missing)}")
    if STATUS_FACTORS[FindingStatus.PASS] or STATUS_FACTORS[FindingStatus.NOT_VERIFIABLE]:
        raise AssertionError("PASS and NOT_VERIFIABLE must never carry a deduction factor")
    if EVIDENCE_FACTORS[EvidenceStatus.NOT_VERIFIABLE]:
        raise AssertionError("NOT_VERIFIABLE must never carry a deduction factor")
    if COVERAGE_WEIGHTS[EvidenceStatus.NOT_VERIFIABLE]:
        raise AssertionError("NOT_VERIFIABLE must not count towards evidence_coverage")
    if RISK_BANDS[0][1] is not RiskLevel.LOW or RISK_BANDS[-1][1] is not RiskLevel.CRITICAL:
        raise AssertionError("RISK_BANDS must run from LOW down to CRITICAL")
    algorithm_tables: tuple[tuple[Mapping[str, AlgorithmPolicy], str], ...] = (
        (ENCRYPTION_POLICIES, "ENCRYPTION_POLICIES"),
        (INTEGRITY_POLICIES, "INTEGRITY_POLICIES"),
        (PRF_POLICIES, "PRF_POLICIES"),
        (DH_POLICIES, "DH_POLICIES"),
    )
    for algorithm_table, label in algorithm_tables:
        for name, entry in algorithm_table.items():
            if entry.name != name:
                raise AssertionError(f"{label}[{name}].name says {entry.name!r}")
            if not entry.reason:
                raise AssertionError(f"{label}[{name}] has no reason")
            if entry.tier.is_weakness and TIER_BASE_POINTS[entry.tier] <= 0.0:
                raise AssertionError(f"{label}[{name}] is a weakness with no deduction")


__all__ = [
    "AEAD_SENTINEL",
    "CATEGORY_WEIGHTS",
    "CHILD_LIFETIME",
    "COVERAGE_WEIGHTS",
    "DH_POLICIES",
    "ENCRYPTION_POLICIES",
    "EVIDENCE_FACTORS",
    "IKE_LIFETIME",
    "INTEGRITY_POLICIES",
    "METADATA_THRESHOLDS",
    "MIN_PACKETS_FOR_SEQUENCE_ANALYSIS",
    "POLICY_ID",
    "POLICY_VERSION",
    "PRF_POLICIES",
    "POLICY_ALIASES",
    "PolicyTier",
    "AlgorithmPolicy",
    "LifetimeCeilings",
    "MetadataThresholds",
    "RISK_BANDS",
    "STATUS_FACTORS",
    "TIER_BASE_POINTS",
    "TIER_SEVERITY",
    "canonical_dh",
    "canonical_encryption",
    "canonical_integrity",
    "canonical_prf",
    "check_policy",
    "dh_policy",
    "encryption_policy",
    "integrity_policy",
    "policy_catalogue",
    "prf_policy",
    "risk_level",
]

