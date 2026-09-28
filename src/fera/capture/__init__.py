"""Packet capture: filters, tcpdump/dumpcap orchestration, sanity checks."""

from __future__ import annotations

from .capture import (
    PCAP_HEADER_BYTES,
    CapturePlan,
    CaptureResult,
    CaptureSession,
    build_capture_command,
    capture_file_stats,
    require_capture_privileges,
    select_capture_tool,
)
from .filters import default_capture_filter, validate_bpf_filter
from .pcap_scan import PcapScanResult, scan_pcap
from .sanity import (
    CaptureValidationResult,
    ValidationStatus,
    parse_tshark_protocol_hierarchy,
    tshark_protocol_counts,
    validate_capture,
)

__all__ = [
    "PCAP_HEADER_BYTES",
    "CapturePlan",
    "CaptureResult",
    "CaptureSession",
    "CaptureValidationResult",
    "PcapScanResult",
    "ValidationStatus",
    "build_capture_command",
    "capture_file_stats",
    "default_capture_filter",
    "parse_tshark_protocol_hierarchy",
    "require_capture_privileges",
    "scan_pcap",
    "select_capture_tool",
    "tshark_protocol_counts",
    "validate_bpf_filter",
    "validate_capture",
]
