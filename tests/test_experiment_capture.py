"""Capture-validation tests.

The decisive assertion is negative: **a capture with no ESP cannot evidence a
protected data path**, however clean the rest of it looks and however
successfully IKE negotiated. That is the historical failure, pinned so it
cannot regress.

Hashing is tested for determinism and for sensitivity to content, because a
manifest that points at "a file called capture.pcap" rather than at specific
bytes is not addressable evidence.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from fera.capture.sanity import CaptureValidationResult, ValidationStatus
from fera.common.errors import FeraError
from fera.experiment.capture import (
    CAPTURE_VALIDATION_SCHEMA,
    hash_capture,
    validate_capture_for_experiment,
)


def _result(
    *,
    status: ValidationStatus = ValidationStatus.VALID,
    esp: bool = True,
    ike: bool = True,
    packets: int = 12,
) -> CaptureValidationResult:
    return CaptureValidationResult(
        pcap_path=Path("stub"),
        status=status,
        method="test",
        packets=packets,
        ike_detected=ike,
        esp_detected=esp,
        ipv4_detected=True,
    )


@pytest.fixture
def capture(tmp_path: Path) -> Path:
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"feratest" * 64)
    return path


def test_hash_is_deterministic_and_content_addressed(capture: Path) -> None:
    first = hash_capture(capture)
    assert first == hash_capture(capture)
    assert first == hashlib.sha256(capture.read_bytes()).hexdigest()

    capture.write_bytes(b"different bytes entirely")
    assert hash_capture(capture) != first


def test_missing_capture_is_refused(tmp_path: Path) -> None:
    with pytest.raises(FeraError):
        hash_capture(tmp_path / "nope.pcap")
    with pytest.raises(FeraError):
        validate_capture_for_experiment(tmp_path / "nope.pcap")


def test_valid_capture_with_esp_supports_the_gate(capture: Path) -> None:
    evidence = validate_capture_for_experiment(capture, result=_result(esp=True))

    assert evidence.supports_esp_gate is True
    assert evidence.status == ValidationStatus.VALID.value
    assert evidence.esp_detected is True
    assert evidence.sha256 == hash_capture(capture)
    assert evidence.size_bytes == capture.stat().st_size


def test_capture_without_esp_cannot_evidence_a_protected_path(capture: Path) -> None:
    """The historical failure: IKE fine, ESP absent, payload went direct."""
    evidence = validate_capture_for_experiment(capture, result=_result(esp=False, ike=True))

    assert evidence.ike_detected is True, "IKE really was negotiated"
    assert evidence.esp_detected is False
    assert evidence.supports_esp_gate is False
    assert any("no ESP packets" in reason for reason in evidence.reasons)


def test_invalid_capture_never_supports_the_gate(capture: Path) -> None:
    evidence = validate_capture_for_experiment(
        capture, result=_result(status=ValidationStatus.INVALID, esp=True)
    )
    assert evidence.supports_esp_gate is False


def test_unverified_capture_never_supports_the_gate(capture: Path) -> None:
    evidence = validate_capture_for_experiment(
        capture, result=_result(status=ValidationStatus.UNVERIFIED, esp=True)
    )
    assert evidence.supports_esp_gate is False


def test_esp_absent_reason_is_omitted_when_not_expected(capture: Path) -> None:
    """A control-only experiment legitimately has no ESP; do not nag about it."""
    evidence = validate_capture_for_experiment(
        capture, expect_esp=False, result=_result(esp=False, packets=4)
    )
    assert not any("no ESP packets" in reason for reason in evidence.reasons)


def test_nat_t_is_recorded_but_never_credited(capture: Path) -> None:
    """UDP/4500 is encrypted payload, not proof of IKE or ESP."""
    evidence = validate_capture_for_experiment(capture, result=_result(esp=True, ike=True))
    assert evidence.nat_t_possible is True
    # The gate depends on esp_detected alone, not on the NAT-T flag.
    without = validate_capture_for_experiment(
        capture, result=_result(esp=True, ike=False)
    )
    assert without.nat_t_possible is True
    assert without.supports_esp_gate is True


def test_evidence_serialises_with_its_provenance(capture: Path) -> None:
    document = validate_capture_for_experiment(capture, result=_result()).to_dict()
    assert document["schema"] == CAPTURE_VALIDATION_SCHEMA
    assert document["valid"] is True
    assert document["supports_esp_gate"] is True
    assert len(document["sha256"]) == 64
    assert document["checked_at"]
