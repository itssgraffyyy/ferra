"""Traffic profile templates.

A *profile* holds the tunable defaults of a traffic class (packet sizes,
intervals, request counts, ports).  Profiles live in
``configs/templates/traffic_profiles.yaml`` so a reviewer can see - and change -
the traffic model without touching code; the built-in document below is the
fallback and the test suite fails if the two drift apart.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..common.errors import ConfigValidationError
from ..dataset.schema import TrafficClass

#: Built-in profile document (mirror of configs/templates/traffic_profiles.yaml).
TRAFFIC_PROFILE_DOCUMENT: dict[str, Any] = {
    "schema_version": 1,
    "description": (
        "Traffic model defaults per traffic class.  All values are deterministic inputs to the "
        "traffic generators; nothing here claims to reproduce a specific application."
    ),
    "responder": {
        "echo_port": 9099,
        "http_port": 8080,
        "iperf_port": 5201,
    },
    "profiles": {
        "icmp": {
            "interval_ms": 500,
            "payload_bytes": 56,
            "note": "ICMP echo request/reply, answered by the peer kernel",
        },
        "web": {
            "port": 8080,
            "request_count": 10,
            "payload_bytes": 2000000,
            "scheme": "http",
            "note": "HTTP object requests plus one larger transfer against the controlled endpoint",
        },
        "email_like": {
            "port": 9099,
            "sessions": 4,
            "request_bytes": 65536,
            "chunk_bytes": 8192,
            "pause_ms": 500,
            "note": "request/response sessions with mail-like message sizes",
        },
        "voip_like": {
            "port": 9099,
            "packet_size": 160,
            "interval_ms": 20,
            "bidirectional": False,
            "note": "G.711-shaped constant bit rate UDP flow (160 byte payloads every 20 ms)",
        },
        "video_like": {
            "port": 9099,
            "target_mbps": 4.0,
            "chunk_bytes": 16384,
            "burst_on_ms": 2000,
            "burst_off_ms": 500,
            "note": "sustained/bursty stream; iperf3 is used when available",
        },
        "messaging_like": {
            "port": 9099,
            "bursts": 6,
            "messages_per_burst": 3,
            "message_size": 320,
            "burst_gap_ms": 1200,
            "message_gap_ms": 250,
            "note": "short bursts of small messages with typing-like pauses",
        },
        "control": {
            "note": "no application traffic: IKE/ESP control traffic only",
        },
    },
}


def default_profiles() -> dict[str, dict[str, Any]]:
    """Return a mutable copy of the built-in profiles keyed by traffic class."""
    return {
        str(name): dict(values)
        for name, values in TRAFFIC_PROFILE_DOCUMENT["profiles"].items()
    }


def default_responder_settings() -> dict[str, Any]:
    """Return a copy of the responder port defaults."""
    return dict(TRAFFIC_PROFILE_DOCUMENT["responder"])


def _validate_profiles(document: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(document, Mapping):
        raise ConfigValidationError("traffic profile document must be a mapping")
    unknown_top = sorted(set(document) - {"schema_version", "description", "responder", "profiles"})
    if unknown_top:
        raise ConfigValidationError(
            f"traffic profile document contains unknown field(s): {', '.join(unknown_top)}"
        )
    profiles = document.get("profiles")
    if not isinstance(profiles, Mapping) or not profiles:
        raise ConfigValidationError("traffic profile document needs a non-empty 'profiles' mapping")
    known = {traffic.value for traffic in TrafficClass}
    unknown = sorted(str(name) for name in profiles if str(name) not in known)
    if unknown:
        raise ConfigValidationError(
            f"traffic profiles reference unknown traffic class(es): {', '.join(unknown)}",
            hint=f"known classes: {', '.join(sorted(known))}",
        )
    return {str(name): dict(values) for name, values in profiles.items()}


def load_profiles(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Load traffic profiles from ``path`` (defaults to the shipped template)."""
    if path is None:
        from ..common.paths import default_paths

        candidate = default_paths().traffic_profiles_file
        if not candidate.is_file():
            return default_profiles()
        path = candidate
    from ..common.serialization import load_document

    return _validate_profiles(load_document(Path(path)))


def profile_for(traffic_type: TrafficClass | str, profiles: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Return the parameter dict of one traffic class."""
    name = TrafficClass(traffic_type).value
    source = profiles if profiles is not None else default_profiles()
    values = dict(source.get(name, {}))
    values.pop("note", None)
    return values


__all__ = [
    "TRAFFIC_PROFILE_DOCUMENT",
    "default_profiles",
    "default_responder_settings",
    "load_profiles",
    "profile_for",
]
