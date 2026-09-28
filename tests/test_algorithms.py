"""Transform/proposal generation tests (IPsec correctness rules)."""

from __future__ import annotations

import pytest

from fera.common.errors import ErrorCode, UnsupportedCombinationError
from fera.testbed.algorithms import (
    DhGroup,
    EncryptionAlg,
    IntegrityAlg,
    build_transforms,
    dh_group_number,
    resolve_dh_group,
    resolve_encryption,
    resolve_integrity,
    supported_algorithms,
)


def test_aes_gcm_ike_proposal_names_prf_and_group() -> None:
    transforms = build_transforms(EncryptionAlg.AES128_GCM, None, dh_group=DhGroup.ECP256, pfs=True)
    assert transforms.aead is True
    assert transforms.ike_proposal == "aes128gcm16-prfsha256-ecp256"
    assert transforms.esp_proposal == "aes128gcm16-ecp256"


def test_aes_cbc_ike_proposal_uses_integrity_algorithm() -> None:
    transforms = build_transforms(
        EncryptionAlg.AES256_CBC, IntegrityAlg.HMAC_SHA384, dh_group=DhGroup.ECP384, pfs=True
    )
    assert transforms.aead is False
    assert transforms.ike_proposal == "aes256-sha384-ecp384"
    assert transforms.esp_proposal == "aes256-sha384-ecp384"
    assert transforms.prf_source == "derived_from_integrity_algorithm"
    assert transforms.effective_prf == "prfsha384"


def test_pfs_disabled_removes_dh_group_from_esp_proposal_only() -> None:
    with_pfs = build_transforms(EncryptionAlg.AES128_GCM, None, dh_group=DhGroup.ECP256, pfs=True)
    without_pfs = build_transforms(EncryptionAlg.AES128_GCM, None, dh_group=DhGroup.ECP256, pfs=False)
    assert with_pfs.esp_proposal == "aes128gcm16-ecp256"
    assert without_pfs.esp_proposal == "aes128gcm16"
    # the IKE_SA still performs a DH exchange: PFS only affects the CHILD_SA
    assert without_pfs.ike_proposal == with_pfs.ike_proposal
    assert "disabled" in without_pfs.pfs_description


def test_aead_with_separate_hmac_is_rejected() -> None:
    with pytest.raises(UnsupportedCombinationError) as error:
        build_transforms(EncryptionAlg.AES128_GCM, IntegrityAlg.HMAC_SHA256, dh_group=DhGroup.ECP256)
    assert error.value.code is ErrorCode.UNSUPPORTED_ALGORITHM_COMBINATION
    assert "AEAD" in error.value.message


def test_cbc_without_integrity_is_rejected() -> None:
    with pytest.raises(UnsupportedCombinationError) as error:
        build_transforms(EncryptionAlg.AES256_CBC, None, dh_group=DhGroup.ECP256)
    assert "integrity" in error.value.message.lower()


def test_cbc_with_aead_integrity_is_rejected() -> None:
    with pytest.raises(UnsupportedCombinationError):
        build_transforms(EncryptionAlg.AES128_CBC, IntegrityAlg.AEAD, dh_group=DhGroup.ECP256)


def test_pfs_contradiction_is_rejected() -> None:
    with pytest.raises(UnsupportedCombinationError):
        build_transforms(
            EncryptionAlg.AES128_GCM,
            None,
            dh_group=DhGroup.ECP256,
            pfs=False,
            pfs_dh_group=DhGroup.ECP384,
        )


def test_child_dh_group_defaults_to_ike_group() -> None:
    transforms = build_transforms(EncryptionAlg.AES256_GCM, None, dh_group=DhGroup.MODP3072, pfs=True)
    assert transforms.child_dh_group is DhGroup.MODP3072
    assert transforms.to_dict()["esp_proposal_contains_dh_group"] is True


def test_integrity_aliases_for_gcm() -> None:
    assert resolve_integrity(None) is IntegrityAlg.AEAD
    assert resolve_integrity("none") is IntegrityAlg.AEAD
    assert resolve_integrity("aead") is IntegrityAlg.AEAD


def test_unknown_algorithms_are_rejected_with_supported_list() -> None:
    with pytest.raises(Exception) as error:
        resolve_encryption("aes192_gcm")
    assert "supported algorithms" in str(error.value)

    with pytest.raises(Exception) as error_group:
        resolve_dh_group("modp1024")
    assert "modp2048" in str(error_group.value)

    with pytest.raises(Exception) as error_integrity:
        resolve_integrity("hmac_sha1")
    assert "hmac_sha256" in str(error_integrity.value)


def test_dh_group_numbers_match_iana_registry() -> None:
    assert dh_group_number(DhGroup.MODP2048) == 14
    assert dh_group_number(DhGroup.MODP3072) == 15
    assert dh_group_number(DhGroup.ECP256) == 19
    assert dh_group_number(DhGroup.CURVE25519) == 31


def test_curve25519_is_flagged_for_local_verification() -> None:
    assert DhGroup.CURVE25519.info.verify_locally is True
    assert DhGroup.ECP256.info.verify_locally is False


def test_supported_algorithms_vocabulary() -> None:
    vocabulary = supported_algorithms()
    assert set(vocabulary) == {"encryption", "integrity", "dh_group"}
    assert "aes128_gcm" in vocabulary["encryption"]
    assert "ecp384" in vocabulary["dh_group"]
