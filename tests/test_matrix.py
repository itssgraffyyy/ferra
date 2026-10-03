"""Representative matrix generation and coverage verification tests."""

from __future__ import annotations

import pytest

from fera.dataset.matrix import (
    MATRIX_ENTRIES,
    CoverageCheck,
    build_matrix,
    check_coverage,
    configuration_key,
    coverage_report,
    render_coverage,
)
from fera.dataset.schema import (
    REQUIRED_TRAFFIC_CLASSES,
    IpsecMode,
    TrafficClass,
    check_topology_compatibility,
)
from fera.testbed.algorithms import EncryptionAlg, IntegrityAlg
from fera.testbed.topology import default_topology


@pytest.fixture(scope="module")
def matrix():
    return build_matrix()


def test_matrix_is_not_empty_and_validated(matrix) -> None:
    assert len(matrix) == len(MATRIX_ENTRIES)
    assert len(matrix) >= 12, "the matrix must stay representative, not minimal"


def test_matrix_ids_are_deterministic_and_unique(matrix) -> None:
    again = build_matrix()
    assert [config.experiment_id for config in matrix] == [config.experiment_id for config in again]
    ids = [config.experiment_id for config in matrix]
    assert len(set(ids)) == len(ids)
    assert ids[0].startswith("exp_000_")


def test_matrix_fingerprints_are_unique(matrix) -> None:
    fingerprints = [config.fingerprint for config in matrix]
    assert len(set(fingerprints)) == len(fingerprints), "duplicate parameter sets in the matrix"


def test_hash_id_style_is_also_deterministic() -> None:
    hashed = build_matrix(id_style="hash")
    assert len({config.experiment_id for config in hashed}) == len(hashed)
    assert build_matrix(id_style="hash")[0].experiment_id == hashed[0].experiment_id


def test_every_experiment_fits_the_default_topology(matrix) -> None:
    topology = default_topology()
    for config in matrix:
        assert check_topology_compatibility(config, topology) == [], config.experiment_id


def test_coverage_of_every_required_dimension(matrix) -> None:
    checks = check_coverage(matrix)
    failed = [check for check in checks if not check.passed]
    assert failed == [], f"uncovered dimensions: {[check.label for check in failed]}"
    report = coverage_report(checks, configs=matrix)
    assert report["all_passed"] is True
    assert report["requirements_passed"] == report["requirements_total"]


def test_coverage_detects_missing_dimensions() -> None:
    """The checker must fail when a dimension really is missing (no fake PASS)."""
    subset = [config for config in build_matrix() if config.mode is IpsecMode.TUNNEL]
    checks = {check.key: check for check in check_coverage(subset)}
    assert checks["mode_transport"].passed is False
    assert checks["mode_transport"].evidence == "none"
    assert checks["mode_tunnel"].passed is True


def test_coverage_flags_aead_and_hmac_misuse() -> None:
    """A crafted invalid sample must make the AEAD invariant fail."""
    config = build_matrix()[0]
    tampered = config.with_updates(experiment_id="exp_999_tunnel_aes128gcm_ecp256_pfson_ipv4_icmp2")
    checks = {check.key: check for check in check_coverage([tampered])}
    assert checks["aead_without_separate_hmac"].passed is True  # still consistent
    assert checks["cbc_requires_hmac"].passed is False  # no CBC experiment present


def test_required_traffic_classes_are_all_present(matrix) -> None:
    present = {config.traffic_type for config in matrix}
    for traffic_class in REQUIRED_TRAFFIC_CLASSES:
        assert traffic_class in present, f"{traffic_class.value} missing from the matrix"


def test_configuration_and_traffic_class_are_not_collinear(matrix) -> None:
    """A configuration must never imply a single traffic class.

    Perfectly collinear design ("all web = GCM, all video = CBC") lets a
    classifier score well by recognising the IPsec configuration instead of the
    traffic, which makes any held-out-configuration evaluation meaningless.
    Both directions are asserted: every configuration carries several classes
    and every class runs under several configurations.
    """
    by_configuration: dict[tuple[object, ...], set[TrafficClass]] = {}
    by_traffic: dict[TrafficClass, set[tuple[object, ...]]] = {}
    for config in matrix:
        key = configuration_key(config)
        by_configuration.setdefault(key, set()).add(config.traffic_type)
        by_traffic.setdefault(config.traffic_type, set()).add(key)

    single_class = {key: classes for key, classes in by_configuration.items() if len(classes) < 2}
    assert not single_class, f"configuration(s) carrying only one traffic class: {single_class}"
    single_config = {key: keys for key, keys in by_traffic.items() if len(keys) < 2}
    assert not single_config, f"traffic class(es) on only one configuration: {single_config}"


def test_coverage_reports_the_configuration_traffic_crossing(matrix) -> None:
    checks = {check.key: check for check in check_coverage(matrix)}
    assert checks["config_traffic_cross"].passed is True
    assert checks["config_traffic_cross"].evidence.startswith("15/15")
    assert checks["traffic_config_cross"].passed is True
    assert checks["traffic_config_cross"].evidence.startswith("6/6")


def test_coverage_detects_a_confounded_matrix() -> None:
    """The new checks must fail on a confounded subset, not just pass on the good one."""
    icmp_only = [config for config in build_matrix() if config.traffic_type is TrafficClass.ICMP]
    checks = {check.key: check for check in check_coverage(icmp_only)}
    assert checks["config_traffic_cross"].passed is False
    # One class across five configurations is fine in the other direction.
    assert checks["traffic_config_cross"].passed is True


def test_every_matrix_entry_is_crossed_with_a_second_class(matrix) -> None:
    """Each of the curated rows keeps its traffic class and gains a second one."""
    by_configuration: dict[tuple[object, ...], set[TrafficClass]] = {}
    for config in matrix:
        by_configuration.setdefault(configuration_key(config), set()).add(config.traffic_type)
    assert len(by_configuration) == len(MATRIX_ENTRIES) // 2
    assert all(len(classes) == 2 for classes in by_configuration.values())


def test_matrix_contains_expected_algorithm_and_pfs_combinations(matrix) -> None:
    combinations = {(config.mode, config.encryption, config.pfs) for config in matrix}
    assert (IpsecMode.TUNNEL, EncryptionAlg.AES128_GCM, True) in combinations
    assert (IpsecMode.TUNNEL, EncryptionAlg.AES128_GCM, False) in combinations
    assert (IpsecMode.TRANSPORT, EncryptionAlg.AES128_CBC, False) in combinations
    assert (IpsecMode.TRANSPORT, EncryptionAlg.AES256_CBC, True) in combinations
    assert len({config.dh_group for config in matrix}) >= 3


def test_matrix_labelling_is_honest(matrix) -> None:
    analogue_classes = {
        TrafficClass.EMAIL_LIKE,
        TrafficClass.VOIP_LIKE,
        TrafficClass.VIDEO_LIKE,
        TrafficClass.MESSAGING_LIKE,
    }
    for config in matrix:
        if config.traffic_type in analogue_classes:
            assert config.traffic_type.value.endswith("_like")
        assert "whatsapp" not in config.experiment_id
        assert "gmail" not in config.experiment_id


def test_capture_duration_override_is_applied() -> None:
    configs = build_matrix(capture_duration_s=5.0)
    assert {config.capture_duration_s for config in configs} == {5.0}


def test_render_coverage_output_shape(matrix) -> None:
    checks = check_coverage(matrix)
    rendered = render_coverage(checks)
    assert "Tunnel Mode" in rendered
    assert "PASS" in rendered
    assert f"{len(checks)}/{len(checks)} requirements satisfied" in rendered
    assert all(isinstance(check, CoverageCheck) for check in checks)


def test_matrix_gcm_experiments_have_no_separate_integrity(matrix) -> None:
    for config in matrix:
        if config.transforms.aead:
            assert config.integrity is IntegrityAlg.AEAD
        else:
            assert config.integrity.is_hmac
