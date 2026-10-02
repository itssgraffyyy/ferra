"""Capture validation and the hashing that makes a capture addressable.

This module **builds on** :mod:`fera.capture.sanity`, which already checks that
a capture exists, parses, is non-empty, carries IKE/ESP, and matches the
expected IP version - and which already reports ``UNVERIFIED`` rather than
papering over a tshark/scanner disagreement.  None of that is repeated here.

What is added on top:

* a **content hash**, so a manifest can point at a specific file rather than a
  filename that could be swapped;
* the **real-ESP evidence decision**: whether this capture is sufficient to mark
  the ``esp_verified`` gate.  This is the check that would have caught the
  historical failure, where `ping` succeeded over a direct path and ESP carried
  nothing while every other indicator was green.

A note on NAT-T, because it has bitten this codebase before: UDP/4500 is **not**
evidence of IKE and **not** evidence of ESP.  A NAT-T capture puts encrypted
payloads on a UDP socket, and treating that as decoded IKE is how fabricated
exchanges used to appear.  This module only credits ESP when ESP is actually
present, and records NAT-T as a caveat rather than as proof.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..capture.sanity import CaptureValidationResult, ValidationStatus, validate_capture
from ..common.errors import ErrorCode, FeraError

#: Schema identifier of one capture-validation document.
CAPTURE_VALIDATION_SCHEMA = "fera_capture_validation_v1"


def _capture_error(message: str, **details: Any) -> FeraError:
    return FeraError(
        message,
        code=ErrorCode.CONFIG_VALIDATION_FAILED,
        hint="see docs/linux_experiments.md for the capture-validation contract",
        details=details,
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_capture(path: Path | str) -> str:
    """SHA-256 of a capture's bytes, streamed so a large PCAP costs no memory."""
    target = Path(path)
    digest = hashlib.sha256()
    try:
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise _capture_error(
            f"could not hash capture {target}: {exc}", path=str(target)
        ) from exc
    return digest.hexdigest()


@dataclass(frozen=True)
class CaptureEvidence:
    """Whether one capture supports marking the real-ESP evidence gate.

    ``esp_detected`` is the decisive field.  A capture where ESP is absent is
    exactly the "IKE negotiated, payload went direct" case, and it must not
    advance a run toward real-IPsec evidence no matter how healthy the rest of
    the run looks.
    """

    path: str
    sha256: str
    size_bytes: int
    status: str
    packets: int
    ike_detected: bool
    esp_detected: bool
    ipv4_detected: bool
    ipv6_detected: bool
    nat_t_possible: bool
    reasons: tuple[str, ...] = ()
    checked_at: str = ""

    @property
    def supports_esp_gate(self) -> bool:
        """True only when the capture is VALID and genuinely contains ESP."""
        return self.status == ValidationStatus.VALID.value and self.esp_detected

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": CAPTURE_VALIDATION_SCHEMA,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "status": self.status,
            "valid": self.status == ValidationStatus.VALID.value,
            "packets": self.packets,
            "ike_detected": self.ike_detected,
            "esp_detected": self.esp_detected,
            "ipv4_detected": self.ipv4_detected,
            "ipv6_detected": self.ipv6_detected,
            "nat_t_possible": self.nat_t_possible,
            "supports_esp_gate": self.supports_esp_gate,
            "reasons": list(self.reasons),
            "checked_at": self.checked_at,
        }


def validate_capture_for_experiment(
    path: Path | str,
    *,
    expected_ip_version: int | None = None,
    expect_ike: bool = True,
    expect_esp: bool = True,
    result: CaptureValidationResult | None = None,
) -> CaptureEvidence:
    """Validate one capture and decide whether it evidences genuine ESP.

    The underlying sanity check is delegated to
    :func:`fera.capture.sanity.validate_capture`; this adds hashing, the
    ESP-gate decision, and the NAT-T caveat as an explicit field so a reader
    can see *why* a capture was accepted rather than only that it was.
    """
    target = Path(path)
    if not target.is_file():
        raise _capture_error(f"capture not found: {target}", path=str(target))
    report = (
        result
        if result is not None
        else validate_capture(
            target,
            expected_ip_version=expected_ip_version,
            require_ike=expect_ike,
            require_esp=expect_esp,
        )
    )
    reasons = tuple(str(item) for item in (report.reasons or ()))
    if expect_esp and not report.esp_detected and report.status is ValidationStatus.VALID:
        # A well-formed capture that carries no ESP is exactly the historical
        # failure; say so rather than letting it pass silently.
        reasons = (
            *reasons,
            "no ESP packets were observed, so this capture cannot evidence a protected "
            "data path even if IKE was negotiated",
        )
    return CaptureEvidence(
        path=str(target),
        sha256=hash_capture(target),
        size_bytes=int(target.stat().st_size),
        status=report.status.value,
        packets=int(report.packets),
        ike_detected=bool(report.ike_detected),
        esp_detected=bool(report.esp_detected),
        ipv4_detected=bool(report.ipv4_detected),
        ipv6_detected=bool(report.ipv6_detected),
        # Recorded, never credited: NAT-T is encrypted payload over UDP/4500.
        nat_t_possible=bool(report.ike_detected or report.esp_detected),
        reasons=reasons,
        checked_at=_utc_now(),
    )


__all__ = [
    "CAPTURE_VALIDATION_SCHEMA",
    "CaptureEvidence",
    "hash_capture",
    "validate_capture_for_experiment",
]
