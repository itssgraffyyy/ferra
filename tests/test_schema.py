"""Experiment schema validation and serialisation tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from conftest import make_config
from fera.common.errors import ConfigValidationError, ErrorCode, FeraError
from fera.common.serialization import write_yaml
from fera.dataset.schema import (
    IpsecMode,
    TrafficClass,
    build_experiment_id,
    check_topology_compatibility,
    experiment_from_dict,
    load_experiment,
    save_experiment,
)
from fera.testbed.algorithms import DhGroup, EncryptionAlg, IntegrityAlg


def test_valid_config_round_trips_through_yaml(tmp_path: Path) -> None:
    config = make_config()
    path = tmp_path / "experiment.yaml"
    save_experiment(config, path)

    reloaded = load_experiment(path)
    assert reloaded == config
    assert reloaded.fingerprint == config.fingerprint
    assert reloaded.transforms.esp_proposal == config.transforms.esp_proposal


def test_gcm_with_separate_hmac_is_rejected() -> None:
    with pytest.raises(FeraError) as error:
        make_config(integrity=IntegrityAlg.HMAC_SHA256)
    assert error.value.code is ErrorCode.UNSUPPORTED_ALGORITHM_COMBINATION


def test_cbc_requires_hmac() -> None:
    with pytest.raises(FeraError) as error:
        make_config(encryption=EncryptionAlg.AES256_CBC, integrity=IntegrityAlg.AEAD)
    assert error.value.code is ErrorCode.UNSUPPORTED_ALGORITHM_COMBINATION


def test_cbc_with_hmac_is_accepted() -> None:
    config = make_config(encryption=EncryptionAlg.AES256_CBC, integrity=IntegrityAlg.HMAC_SHA512)
    assert config.transforms.esp_proposal == "aes256-sha512-ecp256"


def test_ikev1_is_rejected_as_unsupported() -> None:
    with pytest.raises(FeraError) as error:
        make_config(ike_version=1)
    assert error.value.code is ErrorCode.UNSUPPORTED_FEATURE


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"ip_version": 5}, "ip_version"),
        ({"capture_duration_s": 0.0}, "capture_duration_s"),
        ({"capture_duration_s": 10_000.0}, "capture_duration_s"),
        ({"traffic_port": 70000}, "traffic_port"),
        ({"seed": -1}, "seed"),
    ],
)
def test_invalid_field_values_are_rejected(kwargs: dict, message: str) -> None:
    with pytest.raises(ConfigValidationError) as error:
        make_config(**kwargs)
    assert message in error.value.message


def test_invalid_experiment_id_is_rejected() -> None:
    with pytest.raises(ConfigValidationError):
        make_config(experiment_id="Exp 1!")


def test_pfs_metadata_is_honest_about_semantics() -> None:
    with_pfs = make_config(pfs=True)
    without_pfs = make_config(pfs=False, experiment_id="exp_000_tunnel_aes128gcm_ecp256_pfsoff_ipv4_icmp")
    assert with_pfs.transforms.esp_proposal.endswith("ecp256")
    assert not without_pfs.transforms.esp_proposal.endswith("ecp256")
    assert with_pfs.fingerprint != without_pfs.fingerprint


def test_fingerprint_is_order_independent_and_stable() -> None:
    first = make_config()
    second = make_config(notes="different note, same parameters", tags=("x",))
    assert first.fingerprint == second.fingerprint
    assert first.identity_dict() == second.identity_dict()


def test_experiment_ids_are_deterministic() -> None:
    kwargs = {
        "mode": IpsecMode.TUNNEL,
        "encryption": EncryptionAlg.AES256_GCM,
        "dh_group": DhGroup.ECP384,
        "pfs": True,
        "ip_version": 6,
        "traffic_type": TrafficClass.VIDEO_LIKE,
    }
    first = build_experiment_id(index=7, **kwargs)
    second = build_experiment_id(index=7, **kwargs)
    assert first == second == "exp_007_tunnel_aes256gcm_ecp384_pfson_ipv6_video"
    assert build_experiment_id(**kwargs) == build_experiment_id(**kwargs)


def test_unknown_yaml_fields_are_rejected(tmp_path: Path) -> None:
    config = make_config()
    document = config.to_dict()
    document["surprise"] = "value"
    path = write_yaml(tmp_path / "experiment.yaml", document)
    with pytest.raises(ConfigValidationError) as error:
        load_experiment(path)
    assert "unknown field" in error.value.message


def test_tampered_derived_fields_are_detected(tmp_path: Path) -> None:
    config = make_config()
    document = config.to_dict()
    document["ipsec"]["esp_proposal"] = "aes256gcm16"
    path = write_yaml(tmp_path / "experiment.yaml", document)
    with pytest.raises(ConfigValidationError) as error:
        load_experiment(path)
    assert "esp_proposal" in error.value.details["mismatches"]


def test_transport_and_tunnel_selectors_differ(topology) -> None:
    tunnel = make_config(mode=IpsecMode.TUNNEL)
    transport = make_config(
        mode=IpsecMode.TRANSPORT, experiment_id="exp_001_transport_aes128gcm_ecp256_pfson_ipv4_icmp"
    )
    assert check_topology_compatibility(tunnel, topology) == []
    assert check_topology_compatibility(transport, topology) == []
    assert topology.selectors("transport", 4).local_ts == "10.10.10.1/32"
    assert topology.selectors("tunnel", 4).local_ts == "10.20.0.0/24"


def test_ipv6_unsupported_topology_is_reported() -> None:
    from fera.testbed.topology import Endpoint, TestbedTopology

    v4_only = TestbedTopology(
        name="v4only",
        endpoint_a=Endpoint(
            name="a", role="initiator", outer_ipv4="10.0.0.1/24", protected_ipv4="10.1.0.1/24"
        ),
        endpoint_b=Endpoint(
            name="b", role="responder", outer_ipv4="10.0.0.2/24", protected_ipv4="10.2.0.1/24"
        ),
    )
    config = make_config(ip_version=6, experiment_id="exp_000_tunnel_aes128gcm_ecp256_pfson_ipv6_icmp")
    problems = check_topology_compatibility(config, v4_only)
    assert problems and "IPv6" in problems[0]


def test_invalid_capture_filter_is_rejected() -> None:
    with pytest.raises(ConfigValidationError):
        make_config(capture_filter="esp; rm -rf /")


def test_experiment_config_is_frozen() -> None:
    config = make_config()
    assert hash(config) == hash(config)
    with pytest.raises(FrozenInstanceError):
        config.mode = IpsecMode.TRANSPORT  # type: ignore[misc]


def test_experiment_from_dict_requires_core_fields() -> None:
    with pytest.raises(ConfigValidationError):
        experiment_from_dict({"experiment_id": "exp_x"})

