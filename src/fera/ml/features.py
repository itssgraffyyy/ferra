"""Versioned statistical features derived from ESP traffic metadata.

The ML stage classifies *encrypted* traffic, so features may only describe how
the traffic behaves - never what it contains and never what the experiment
configured:

* everything is derived from packet/flow **metadata** that the deterministic
  Prompt 2 analyser already produces (``analyze_pcap``); this module performs
  no protocol decoding of its own.  The only additional input it reads is the
  classic PCAP frame record header (timestamp + captured length), which is
  file-format metadata rather than packet content,
* ground truth documents are never passed in: labels are joined with the
  features only in the dataset stage, never here,
* :data:`FEATURE_WHITELIST` is the contract with every later stage - dataset
  building, training, inference and evaluation all consume the exact same
  ordered list.  Adding, removing or renaming a feature requires bumping
  :data:`FEATURE_SCHEMA`.

Direction is *normalised*: the sender of the first observed ESP packet is the
initiator and every forward/reverse feature is relative to it, so a capture
whose addresses are mirrored yields the same feature values.
"""

from __future__ import annotations

import math
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean, pstdev
from typing import Any

from ..analysis import AnalysisOutcome, analyze_pcap
from ..capture.pcap_scan import PCAP_HEADER_BYTES, PCAP_MAGIC_BE, PCAP_MAGIC_LE
from ..common.errors import ErrorCode, FeraError

#: Schema identifier written into every feature document.  Bump on any change
#: to :data:`FEATURE_WHITELIST` or to the meaning of an existing value.
FEATURE_SCHEMA = "fera_esp_features_v1"

#: Ordered contract of every feature an ML stage may consume.  The order is
#: the model input order; the names are the JSON keys of a feature document.
FEATURE_WHITELIST: tuple[str, ...] = (
    # capture level (scanner metadata)
    "capture_packets",
    "capture_bytes",
    "capture_duration_s",
    "packet_rate_pps",
    "byte_rate_bps",
    "avg_packet_len",
    "esp_packet_share",
    "ike_packet_share",
    "icmp_packet_share",
    "ipv6_packet_share",
    "truncated_packet_share",
    # ESP volume (decoded ESP headers + flow grouping)
    "esp_packets",
    "esp_bytes",
    "esp_flow_count",
    "esp_avg_len",
    "esp_len_min",
    "esp_len_max",
    "esp_len_std",
    "esp_avg_packets_per_flow",
    "esp_avg_bytes_per_flow",
    "esp_largest_flow_share",
    # direction, normalised to the initiator (first observed ESP sender)
    "esp_fwd_packets",
    "esp_bwd_packets",
    "esp_fwd_bytes",
    "esp_bwd_bytes",
    "esp_fwd_packet_share",
    "esp_fwd_byte_share",
    # timing between ESP packets
    "esp_iat_mean_s",
    "esp_iat_std_s",
    "esp_iat_max_s",
    "esp_span_s",
    # sequence number health across flows
    "esp_seq_gap_total",
    "esp_seq_replay_total",
    "esp_nonmonotonic_flow_share",
    # encapsulation
    "esp_udp_encap_share",
    # IKE context
    "ike_packet_count",
    "ike_exchange_count",
)


def _safe_div(numerator: float, denominator: float) -> float:
    """Return ``numerator / denominator`` or ``0.0`` when the denominator is 0."""
    return numerator / denominator if denominator else 0.0


def _frame_timestamps(pcap_path: Path) -> list[float]:
    """Read per-frame timestamps of a classic PCAP (format metadata only).

    Returns an empty list for inputs this reader does not understand; the
    deterministic analyser rejects unsupported formats before this matters.
    """
    raw = pcap_path.read_bytes()
    if len(raw) < PCAP_HEADER_BYTES:
        return []
    magic = raw[:4]
    if magic == PCAP_MAGIC_LE:
        endian = "<"
    elif magic == PCAP_MAGIC_BE:
        endian = ">"
    else:  # PCAPNG or unknown - timing features stay at 0.0
        return []
    timestamps: list[float] = []
    offset = PCAP_HEADER_BYTES
    while offset + 16 <= len(raw):
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack_from(f"{endian}IIII", raw, offset)
        offset += 16
        if offset + incl_len > len(raw):  # truncated tail frame: keep what we saw so far
            break
        timestamps.append(ts_sec + ts_usec / 1_000_000)
        offset += incl_len
    return timestamps


@dataclass(frozen=True)
class FeatureVector:
    """One capture's whitelisted feature values.

    Construction validates the whitelist contract and coerces every value to a
    finite ``float``; anything else raises :class:`FeraError` so a malformed
    vector can never reach training or inference.
    """

    pcap_path: str
    features: Mapping[str, float]

    def __post_init__(self) -> None:
        object.__setattr__(self, "pcap_path", str(self.pcap_path))
        missing = [name for name in FEATURE_WHITELIST if name not in self.features]
        extra = [name for name in self.features if name not in FEATURE_WHITELIST]
        if missing or extra:
            raise FeraError(
                "feature vector does not match the whitelist",
                code=ErrorCode.INTERNAL_ERROR,
                hint="rebuild the vector with fera.ml.extract_features or bump FEATURE_SCHEMA",
                details={"missing": missing, "extra": extra, "schema": FEATURE_SCHEMA},
            )
        cleaned: dict[str, float] = {}
        for name in FEATURE_WHITELIST:
            value = self.features[name]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise FeraError(
                    f"feature {name!r} is not numeric",
                    code=ErrorCode.INTERNAL_ERROR,
                    details={"feature": name, "value": repr(value)},
                )
            number = float(value)
            if not math.isfinite(number):
                raise FeraError(
                    f"feature {name!r} is not a finite number",
                    code=ErrorCode.INTERNAL_ERROR,
                    details={"feature": name, "value": repr(value)},
                )
            cleaned[name] = number
        object.__setattr__(self, "features", dict(cleaned))

    @property
    def schema(self) -> str:
        """Schema identifier this vector conforms to."""
        return FEATURE_SCHEMA

    def row(self) -> list[float]:
        """Values in whitelist order (the model input layout)."""
        return [self.features[name] for name in FEATURE_WHITELIST]

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable feature document."""
        return {
            "schema": FEATURE_SCHEMA,
            "pcap_path": self.pcap_path,
            "features": dict(self.features),
        }



def _capture_features(scan: Mapping[str, Any], timestamps: Sequence[float]) -> dict[str, float]:
    """Capture level features from scanner counters and frame timestamps."""
    packets = float(scan.get("packets", 0) or 0)
    captured_bytes = float(scan.get("captured_bytes", 0) or 0)
    duration = timestamps[-1] - timestamps[0] if len(timestamps) >= 2 else 0.0
    duration = max(duration, 0.0)
    icmp = float(scan.get("icmp_packets", 0) or 0) + float(scan.get("icmpv6_packets", 0) or 0)
    return {
        "capture_packets": packets,
        "capture_bytes": captured_bytes,
        "capture_duration_s": duration,
        "packet_rate_pps": _safe_div(packets, duration),
        "byte_rate_bps": _safe_div(captured_bytes, duration),
        "avg_packet_len": _safe_div(captured_bytes, packets),
        "esp_packet_share": _safe_div(float(scan.get("esp_packets", 0) or 0), packets),
        "ike_packet_share": _safe_div(float(scan.get("ike_packets", 0) or 0), packets),
        "icmp_packet_share": _safe_div(icmp, packets),
        "ipv6_packet_share": _safe_div(float(scan.get("ipv6_packets", 0) or 0), packets),
        "truncated_packet_share": _safe_div(float(scan.get("truncated_frames", 0) or 0), packets),
    }


def _esp_volume_features(
    esp_packets: Sequence[Any], esp_flows: Sequence[Mapping[str, Any]]
) -> dict[str, float]:
    """ESP volume and per-flow aggregate features."""
    lengths = [float(packet.length) for packet in esp_packets]
    esp_count = float(len(esp_packets))
    esp_bytes = sum(lengths)
    flow_count = float(len(esp_flows))
    largest_flow = max((float(flow.get("packets", 0) or 0) for flow in esp_flows), default=0.0)
    return {
        "esp_packets": esp_count,
        "esp_bytes": esp_bytes,
        "esp_flow_count": flow_count,
        "esp_avg_len": _safe_div(esp_bytes, esp_count),
        "esp_len_min": min(lengths, default=0.0),
        "esp_len_max": max(lengths, default=0.0),
        "esp_len_std": pstdev(lengths) if len(lengths) > 1 else 0.0,
        "esp_avg_packets_per_flow": _safe_div(esp_count, flow_count),
        "esp_avg_bytes_per_flow": _safe_div(esp_bytes, flow_count),
        "esp_largest_flow_share": _safe_div(largest_flow, esp_count),
    }


def _direction_features(esp_packets: Sequence[Any]) -> dict[str, float]:
    """Initiator-relative direction features (mirror invariant by construction)."""
    if not esp_packets:
        return {
            "esp_fwd_packets": 0.0,
            "esp_bwd_packets": 0.0,
            "esp_fwd_bytes": 0.0,
            "esp_bwd_bytes": 0.0,
            "esp_fwd_packet_share": 0.0,
            "esp_fwd_byte_share": 0.0,
        }
    initiator = min(esp_packets, key=lambda packet: packet.frame_index).src
    fwd = [packet for packet in esp_packets if packet.src == initiator]
    bwd = [packet for packet in esp_packets if packet.src != initiator]
    esp_count = float(len(esp_packets))
    esp_bytes = float(sum(packet.length for packet in esp_packets))
    fwd_bytes = float(sum(packet.length for packet in fwd))
    return {
        "esp_fwd_packets": float(len(fwd)),
        "esp_bwd_packets": float(len(bwd)),
        "esp_fwd_bytes": fwd_bytes,
        "esp_bwd_bytes": esp_bytes - fwd_bytes,
        "esp_fwd_packet_share": _safe_div(float(len(fwd)), esp_count),
        "esp_fwd_byte_share": _safe_div(fwd_bytes, esp_bytes),
    }


def _timing_features(esp_packets: Sequence[Any], timestamps: Sequence[float]) -> dict[str, float]:
    """Inter-arrival and span features between ESP packets."""
    frame_ids = sorted(packet.frame_index for packet in esp_packets)
    esp_times = [timestamps[index] for index in frame_ids if index < len(timestamps)]
    iats = [esp_times[index + 1] - esp_times[index] for index in range(len(esp_times) - 1)]
    span = esp_times[-1] - esp_times[0] if len(esp_times) >= 2 else 0.0
    return {
        "esp_iat_mean_s": fmean(iats) if iats else 0.0,
        "esp_iat_std_s": pstdev(iats) if len(iats) > 1 else 0.0,
        "esp_iat_max_s": max(iats, default=0.0),
        "esp_span_s": max(span, 0.0),
    }


def _health_features(
    esp_packets: Sequence[Any], esp_flows: Sequence[Mapping[str, Any]]
) -> dict[str, float]:
    """Sequence number health and encapsulation share."""
    flow_count = len(esp_flows)
    non_monotonic = sum(1 for flow in esp_flows if not flow.get("sequence_monotonic", True))
    udp_encapsulated = sum(1 for packet in esp_packets if packet.udp_encapsulated)
    gaps = sum(int(flow.get("sequence_gaps", 0) or 0) for flow in esp_flows)
    replays = sum(int(flow.get("sequence_replays", 0) or 0) for flow in esp_flows)
    return {
        "esp_seq_gap_total": float(gaps),
        "esp_seq_replay_total": float(replays),
        "esp_nonmonotonic_flow_share": _safe_div(float(non_monotonic), float(flow_count)),
        "esp_udp_encap_share": _safe_div(float(udp_encapsulated), float(len(esp_packets))),
    }


def extract_features(
    pcap_path: str | Path, *, outcome: AnalysisOutcome | None = None
) -> FeatureVector:
    """Extract the versioned feature vector of one capture.

    ``outcome`` may pass an already computed Prompt 2 analysis so the dataset
    stage can avoid parsing a capture twice; ground truth and experiment
    configuration are deliberately not accepted as inputs.
    """
    path = Path(pcap_path)
    analysis_outcome = analyze_pcap(path) if outcome is None else outcome
    scan = analysis_outcome.analysis.details.get("scan") or {}
    timestamps = _frame_timestamps(path)
    esp_packets = analysis_outcome.esp_packets
    esp_flows = analysis_outcome.analysis.esp_flows

    values: dict[str, float] = {}
    values.update(_capture_features(scan, timestamps))
    values.update(_esp_volume_features(esp_packets, esp_flows))
    values.update(_direction_features(esp_packets))
    values.update(_timing_features(esp_packets, timestamps))
    values.update(_health_features(esp_packets, esp_flows))
    values["ike_packet_count"] = float(scan.get("ike_packets", 0) or 0)
    values["ike_exchange_count"] = float(len(analysis_outcome.analysis.ike_exchanges))
    return FeatureVector(pcap_path=str(path), features=values)


__all__ = ["FEATURE_SCHEMA", "FEATURE_WHITELIST", "FeatureVector", "extract_features"]

