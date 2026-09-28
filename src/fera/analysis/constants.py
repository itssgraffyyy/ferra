"""Protocol constants and IANA registry mappings for IKEv2 and IPsec."""

from __future__ import annotations

from enum import IntEnum
from typing import Any

# IP Protocol Numbers
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ESP = 50
IPPROTO_AH = 51
IPPROTO_ICMPV6 = 58

# Standard IKE Ports
IKE_PORT_DEFAULT = 500
IKE_PORT_NATT = 4500


class IkeVersion(IntEnum):
    """IKE protocol major versions."""

    IKEV1 = 1
    IKEV2 = 2


class IkeExchangeType(IntEnum):
    """IKEv2 Exchange Types (RFC 7296 section 3.10 and IANA registry)."""

    IKE_SA_INIT = 34
    IKE_AUTH = 35
    CREATE_CHILD_SA = 36
    INFORMATIONAL = 37
    IKE_SESSION_RESUMPTION = 38
    GSA_AUTH = 39
    GSA_REGISTRATION = 40
    GSA_REKEY = 41

    @classmethod
    def describe(cls, value: int) -> str:
        try:
            return cls(value).name
        except ValueError:
            if value < 34:
                return f"IKEV1_EXCHANGE_{value}"
            return f"UNKNOWN_EXCHANGE_{value}"


class IkeTransformType(IntEnum):
    """IKEv2 Transform Types (RFC 7296 section 3.3.2)."""

    ENCRYPTION_ALGORITHM = 1
    PSEUDORANDOM_FUNCTION = 2
    INTEGRITY_ALGORITHM = 3
    DIFFIE_HELLMAN_GROUP = 4
    EXTENDED_SEQUENCE_NUMBERS = 5

    @classmethod
    def describe(cls, value: int) -> str:
        try:
            return cls(value).name
        except ValueError:
            return f"UNKNOWN_TRANSFORM_TYPE_{value}"


# IANA Encryption Transform IDs (Transform Type 1)
ENCRYPTION_ALGORITHMS: dict[int, dict[str, Any]] = {
    1: {"name": "ENCR_DES_IV64", "key_bits": 64, "aead": False},
    2: {"name": "ENCR_DES", "key_bits": 64, "aead": False},
    3: {"name": "ENCR_3DES", "key_bits": 192, "aead": False},
    12: {"name": "ENCR_AES_CBC", "key_bits": 128, "aead": False, "variable_key": True},
    18: {"name": "ENCR_AES_GCM_16", "key_bits": 128, "aead": True, "icv_bits": 128, "variable_key": True},
    19: {"name": "ENCR_AES_GCM_12", "key_bits": 128, "aead": True, "icv_bits": 96, "variable_key": True},
    20: {"name": "ENCR_AES_GCM_8", "key_bits": 128, "aead": True, "icv_bits": 64, "variable_key": True},
    28: {"name": "ENCR_CHACHA20_POLY1305", "key_bits": 256, "aead": True, "icv_bits": 128},
}

# IANA PRF Transform IDs (Transform Type 2)
PRF_ALGORITHMS: dict[int, str] = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    4: "PRF_HMAC_SHA2_256",
    5: "PRF_HMAC_SHA2_384",
    6: "PRF_HMAC_SHA2_512",
    7: "PRF_AES128_XCBC",
    8: "PRF_AES128_CMAC",
}

# IANA Integrity Transform IDs (Transform Type 3)
INTEGRITY_ALGORITHMS: dict[int, dict[str, Any]] = {
    0: {"name": "NONE", "auth_bits": 0},
    1: {"name": "AUTH_HMAC_MD5_96", "auth_bits": 96},
    2: {"name": "AUTH_HMAC_SHA1_96", "auth_bits": 96},
    12: {"name": "AUTH_HMAC_SHA2_256_128", "auth_bits": 128},
    13: {"name": "AUTH_HMAC_SHA2_384_192", "auth_bits": 192},
    14: {"name": "AUTH_HMAC_SHA2_512_256", "auth_bits": 256},
}

# IANA Diffie-Hellman Group IDs (Transform Type 4)
DH_GROUPS_IANA: dict[int, dict[str, Any]] = {
    1: {"name": "MODP_768", "bits": 768, "kind": "modp"},
    2: {"name": "MODP_1024", "bits": 1024, "kind": "modp"},
    5: {"name": "MODP_1536", "bits": 1536, "kind": "modp"},
    14: {"name": "MODP_2048", "bits": 2048, "kind": "modp"},
    15: {"name": "MODP_3072", "bits": 3072, "kind": "modp"},
    16: {"name": "MODP_4096", "bits": 4096, "kind": "modp"},
    17: {"name": "MODP_6144", "bits": 6144, "kind": "modp"},
    18: {"name": "MODP_8192", "bits": 8192, "kind": "modp"},
    19: {"name": "ECP_256", "bits": 256, "kind": "ecp"},
    20: {"name": "ECP_384", "bits": 384, "kind": "ecp"},
    21: {"name": "ECP_521", "bits": 521, "kind": "ecp"},
    31: {"name": "CURVE25519", "bits": 255, "kind": "montgomery"},
}

# IANA Extended Sequence Numbers (Transform Type 5)
ESN_VALUES: dict[int, str] = {
    0: "NO_ESN",
    1: "ESN",
}

PROTOCOL_IKE = 1
PROTOCOL_AH = 2
PROTOCOL_ESP = 3

PROTOCOL_NAMES: dict[int, str] = {
    PROTOCOL_IKE: "IKE",
    PROTOCOL_AH: "AH",
    PROTOCOL_ESP: "ESP",
}

__all__ = [
    "DH_GROUPS_IANA",
    "ENCRYPTION_ALGORITHMS",
    "ESN_VALUES",
    "IKE_PORT_DEFAULT",
    "IKE_PORT_NATT",
    "INTEGRITY_ALGORITHMS",
    "IPPROTO_AH",
    "IPPROTO_ESP",
    "IPPROTO_ICMP",
    "IPPROTO_ICMPV6",
    "IPPROTO_TCP",
    "IPPROTO_UDP",
    "IkeExchangeType",
    "IkeTransformType",
    "IkeVersion",
    "PRF_ALGORITHMS",
    "PROTOCOL_AH",
    "PROTOCOL_ESP",
    "PROTOCOL_IKE",
    "PROTOCOL_NAMES",
]
