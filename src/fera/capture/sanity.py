"""Capture sanity checks (dataset validation, not protocol analysis).

A dataset sample is only accepted when the capture actually contains what the
experiment claims:

* IKE negotiation (UDP 500/4500),
* ESP protection (IP protocol 50),
* the expected IP version (IPv4/IPv6),
* at least one packet.

Two independent sources are used when available: ``tshark`` (authoritative
dissector) and FERA's own minimal PCAP scanner.  When they disagree the result
is reported as ``UNVERIFIED`` rather than papered over - a later stage must not
build on a capture whose content is questionable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ..common.errors import FeraError
from ..common.logging_utils import get_logger
from ..common.process import BaseRunner, SubprocessRunner
from .pcap_scan import PCAP_HEADER_BYTES, PcapScanResult, scan_pcap

logger = get_logger(__name__)


class ValidationStatus(str, Enum):
    """Outcome of a capture sanity check."""

    VALID = "VALID"
    INVALID = "INVALID"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class CaptureValidationResult:
    """Result of validating one capture against the experiment's expectation."""

    pcap_path: Path
    status: ValidationStatus
    method: str
    packets: int = 0
    bytes_on_disk: int = 0
    ike_detected: bool = False
    esp_detected: bool = False
    ipv4_detected: bool = False
    ipv6_detected: bool = False
    icmp_detected: bool = False
    expected_ip_version: int | None = None
    expected_ike: bool = True
    expected_esp: bool = True
    reasons: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return self.status is ValidationStatus.VALID

    def to_dict(self) -> dict[str, Any]:
        return {
            "pcap_path": str(self.pcap_path),
            "status": self.status.value,
            "valid": self.valid,
            "method": self.method,
            "packets": self.packets,
            "bytes_on_disk": self.bytes_on_disk,
            "ike_detected": self.ike_detected,
            "esp_detected": self.esp_detected,
            "ipv4_detected": self.ipv4_detected,
            "ipv6_detected": self.ipv6_detected,
            "icmp_detected": self.icmp_detected,
            "expected_ip_version": self.expected_ip_version,
            "expected_ike": self.expected_ike,
            "expected_esp": self.expected_esp,
            "reasons": list(self.reasons),
            "details": self.details,
        }

    def render_text(self) -> str:
        """Human readable report (used by ``scripts/validate_capture.py``)."""
        lines = [
            f"Capture: {self.pcap_path}",
            "",
            f"Packets: {self.packets}",
            f"Bytes on disk: {self.bytes_on_disk}",
            f"IKE detected: {'YES' if self.ike_detected else 'NO'}",
            f"ESP detected: {'YES' if self.esp_detected else 'NO'}",
            f"IPv4 detected: {'YES' if self.ipv4_detected else 'NO'}",
            f"IPv6 detected: {'YES' if self.ipv6_detected else 'NO'}",
            f"ICMP detected: {'YES' if self.icmp_detected else 'NO'}",
            f"Method: {self.method}",
        ]
        if self.expected_ip_version:
            lines.append(f"Expected IP version: IPv{self.expected_ip_version}")
        for reason in self.reasons:
            lines.append(f"Reason: {reason}")
        lines.append("")
        lines.append(f"Result: {self.status.value}")
        return "\n".join(lines)


_TSHARK_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s+frames:(\d+)\s+bytes:(\d+)\s*$")


def parse_tshark_protocol_hierarchy(output: str) -> dict[str, int]:
    """Parse ``tshark -q -z io,phs`` output into ``{protocol: frames}``."""
    counts: dict[str, int] = {}
    for line in output.splitlines():
        match = _TSHARK_LINE_RE.match(line)
        if not match:
            continue
        protocol, frames = match.group(1).lower(), int(match.group(2))
        counts[protocol] = max(counts.get(protocol, 0), frames)
    return counts


def tshark_protocol_counts(
    pcap_path: Path,
    runner: BaseRunner,
    *,
    timeout: float = 60.0,
) -> dict[str, int] | None:
    """Return protocol frame counts from tshark, or ``None`` when unavailable."""
    if runner.which("tshark") is None:
        return None
    command = ["tshark", "-r", str(pcap_path), "-q", "-z", "io,phs"]
    result = runner.run(command, timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("tshark failed on %s: %s", pcap_path.name, (result.stderr or "").strip()[:200])
        return None
    return parse_tshark_protocol_hierarchy(result.stdout or "")


def validate_capture(
    pcap_path: str | Path,
    *,
    expected_ip_version: int | None = None,
    require_ike: bool = True,
    require_esp: bool = True,
    min_packets: int = 1,
    runner: BaseRunner | None = None,
    use_tshark: bool = True,
) -> CaptureValidationResult:
    """Check that a capture contains what the experiment says it contains."""
    path = Path(pcap_path)
    reasons: list[str] = []
    details: dict[str, Any] = {}
    if not path.is_file():
        return CaptureValidationResult(
            pcap_path=path,
            status=ValidationStatus.INVALID,
            method="none",
            expected_ip_version=expected_ip_version,
            reasons=(f"capture file does not exist: {path}",),
        )
    size = path.stat().st_size
    if size <= PCAP_HEADER_BYTES:
        return CaptureValidationResult(
            pcap_path=path,
            status=ValidationStatus.INVALID,
            method="none",
            bytes_on_disk=size,
            expected_ip_version=expected_ip_version,
            reasons=(f"capture file is empty ({size} bytes)",),
        )

    scan: PcapScanResult | None = None
    scan_error: str | None = None
    try:
        scan = scan_pcap(path)
    except FeraError as exc:
        scan_error = exc.message
        details["pcap_scan_error"] = exc.to_dict()

    active_runner = runner if runner is not None else SubprocessRunner()
    tshark_counts = tshark_protocol_counts(path, active_runner) if use_tshark else None
    if tshark_counts is not None:
        details["tshark_protocol_frames"] = tshark_counts
    if scan is not None:
        details["pcap_scan"] = scan.to_dict()

    if tshark_counts is None and scan is None:
        return CaptureValidationResult(
            pcap_path=path,
            status=ValidationStatus.UNVERIFIED,
            method="none",
            bytes_on_disk=size,
            expected_ip_version=expected_ip_version,
            reasons=(
                "neither tshark nor the built-in scanner could read this capture",
                scan_error or "tshark unavailable",
            ),
            details=details,
        )
    return _judge_capture(
        path=path,
        size=size,
        scan=scan,
        tshark_counts=tshark_counts,
        expected_ip_version=expected_ip_version,
        require_ike=require_ike,
        require_esp=require_esp,
        min_packets=min_packets,
        reasons=reasons,
        details=details,
    )


def _judge_capture(
    *,
    path: Path,
    size: int,
    scan: PcapScanResult | None,
    tshark_counts: dict[str, int] | None,
    expected_ip_version: int | None,
    require_ike: bool,
    require_esp: bool,
    min_packets: int,
    reasons: list[str],
    details: dict[str, Any],
) -> CaptureValidationResult:
    """Combine both evidence sources into a verdict."""

    def frames(protocol: str) -> int:
        return int((tshark_counts or {}).get(protocol, 0))

    ike_from_tshark = frames("isakmp") + frames("ike") + frames("ikev2")
    esp_from_tshark = frames("esp")
    ipv4_from_tshark = frames("ip")
    ipv6_from_tshark = frames("ipv6")
    icmp_from_tshark = frames("icmp") + frames("icmpv6")
    total_tshark = max(tshark_counts.values()) if tshark_counts else 0

    scan_ike = scan.ike_packets if scan else 0
    scan_esp = scan.esp_packets if scan else 0
    scan_ipv4 = scan.ipv4_packets if scan else 0
    scan_ipv6 = scan.ipv6_packets if scan else 0
    scan_icmp = (scan.icmp_packets + scan.icmpv6_packets) if scan else 0

    ike_detected = bool(ike_from_tshark or scan_ike)
    esp_detected = bool(esp_from_tshark or scan_esp)
    ipv4_detected = bool(ipv4_from_tshark or scan_ipv4)
    ipv6_detected = bool(ipv6_from_tshark or scan_ipv6)
    icmp_detected = bool(icmp_from_tshark or scan_icmp)
    packets = max(scan.packets if scan else 0, total_tshark)

    methods: list[str] = []
    if tshark_counts is not None:
        methods.append("tshark")
    if scan is not None:
        methods.append("pcap_scan")
    method = "+".join(methods) or "none"

    status = ValidationStatus.VALID
    if packets < min_packets:
        status = ValidationStatus.INVALID
        reasons.append(f"capture contains {packets} packet(s), {min_packets} required")
    if require_ike and not ike_detected:
        status = ValidationStatus.INVALID
        reasons.append("no IKE negotiation (UDP 500/4500) found in the capture")
    if require_esp and not esp_detected:
        status = ValidationStatus.INVALID
        reasons.append("no ESP (IP protocol 50) found in the capture")
    if expected_ip_version == 4 and not ipv4_detected:
        status = ValidationStatus.INVALID
        reasons.append("no IPv4 traffic found although the experiment expects IPv4")
    if expected_ip_version == 6 and not ipv6_detected:
        status = ValidationStatus.INVALID
        reasons.append("no IPv6 traffic found although the experiment expects IPv6")
    if (
        tshark_counts is not None
        and scan is not None
        and status is ValidationStatus.VALID
        and ((ike_from_tshark > 0) != (scan_ike > 0) or (esp_from_tshark > 0) != (scan_esp > 0))
    ):
        status = ValidationStatus.UNVERIFIED
        reasons.append(
            "tshark and the built-in scanner disagree about IKE/ESP presence - manual inspection required"
        )
    if tshark_counts is None and status is ValidationStatus.VALID:
        reasons.append(
            "verified with FERA's built-in PCAP scanner only (tshark is not installed on this host)"
        )

    return CaptureValidationResult(
        pcap_path=path,
        status=status,
        method=method,
        packets=packets,
        bytes_on_disk=size,
        ike_detected=ike_detected,
        esp_detected=esp_detected,
        ipv4_detected=ipv4_detected,
        ipv6_detected=ipv6_detected,
        icmp_detected=icmp_detected,
        expected_ip_version=expected_ip_version,
        expected_ike=require_ike,
        expected_esp=require_esp,
        reasons=tuple(reasons),
        details=details,
    )


__all__ = [
    "CaptureValidationResult",
    "ValidationStatus",
    "parse_tshark_protocol_hierarchy",
    "tshark_protocol_counts",
    "validate_capture",
]


