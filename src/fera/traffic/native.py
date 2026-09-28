"""Native (in-process) traffic patterns.

Native patterns are used where no mature command line tool produces the required
*shape*: constant bit rate VoIP-like flows, messaging-like bursts and
email-like request/response exchanges.

Design notes:

* payload bytes come from a seeded RNG, so the same experiment produces the
  same pattern (determinism for reproducibility),
* sockets are created through injectable factories, which keeps the pattern
  logic unit-testable without a network,
* a responder (``fera.traffic.servers``) can run on the target side; classes
  that expect a response fail loudly when no responder answers instead of
  pretending that traffic was generated.
"""

from __future__ import annotations

import random
import socket
import time
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from ..common.errors import ErrorCode, FeraError
from ..common.logging_utils import get_logger
from .base import NativeStats, TrafficContext

logger = get_logger(__name__)

#: Port used by the FERA echo/HTTP responder when the experiment does not pin one.
DEFAULT_ECHO_PORT = 9099
#: Upper bound for a single native pattern (a runaway loop must not hang a run).
MAX_DURATION_S = 600.0


class DatagramSender(Protocol):
    """Minimal UDP sender interface (satisfied by :class:`UdpSender`)."""

    def send(self, payload: bytes) -> None: ...

    def receive(self, timeout_s: float) -> bytes | None: ...

    def close(self) -> None: ...


def deterministic_payload(seed: int, size: int) -> bytes:
    """Return ``size`` deterministic pseudo random bytes for ``seed``."""
    if size <= 0:
        return b""
    return random.Random(seed).randbytes(size)


class UdpSender:
    """Connected UDP socket used to emit a pattern."""

    def __init__(self, target: str, port: int, *, source: str | None = None) -> None:
        family = socket.AF_INET6 if ":" in target else socket.AF_INET
        self.socket = socket.socket(family, socket.SOCK_DGRAM)
        if source:
            self.socket.bind((source, 0))
        self.socket.connect((target, port))

    def send(self, payload: bytes) -> None:
        self.socket.send(payload)

    def receive(self, timeout_s: float) -> bytes | None:
        self.socket.settimeout(timeout_s)
        try:
            return self.socket.recv(65535)
        except TimeoutError:
            return None

    def close(self) -> None:
        try:
            self.socket.close()
        except OSError:  # pragma: no cover - defensive
            pass


def tcp_connector(target: str, port: int, *, source: str | None = None, timeout_s: float = 5.0) -> socket.socket:
    """Open a TCP connection to ``target:port`` (optionally binding a source address)."""
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    if source:
        sock.bind((source, 0))
    sock.connect((target, port))
    return sock


def _bounded_duration(value: Any, default: float) -> float:
    try:
        duration = float(value)
    except (TypeError, ValueError):
        duration = default
    if duration <= 0:
        duration = default
    return min(duration, MAX_DURATION_S)


def send_udp_pattern(
    parameters: Mapping[str, Any],
    context: TrafficContext,
    *,
    sender_factory: Callable[..., DatagramSender] = UdpSender,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> NativeStats:
    """Emit a constant-bit-rate UDP flow (VoIP-like shape).

    Parameters: ``port``, ``packet_size`` (bytes), ``interval_ms``, ``duration_s``,
    ``read_responses`` (bool).
    """
    port = int(parameters.get("port") or context.port or DEFAULT_ECHO_PORT)
    packet_size = int(parameters.get("packet_size", 160))
    interval_s = max(0.001, float(parameters.get("interval_ms", 20)) / 1000.0)
    duration_s = _bounded_duration(parameters.get("duration_s"), context.duration_s)
    read_responses = bool(parameters.get("read_responses", False))
    response_timeout_s = float(parameters.get("response_timeout_ms", 500)) / 1000.0

    payload = deterministic_payload(context.seed, packet_size)
    bytes_sent = 0
    packets_sent = 0
    responses = 0
    errors: list[str] = []
    started = clock()
    sender: DatagramSender | None = None
    try:
        sender = sender_factory(context.target, port, source=context.source)
        next_send = started
        while clock() - started < duration_s:
            sender.send(payload)
            bytes_sent += len(payload)
            packets_sent += 1
            if read_responses:
                reply = sender.receive(response_timeout_s)
                if reply is not None:
                    responses += 1
            next_send += interval_s
            remaining = next_send - clock()
            if remaining > 0:
                sleep(remaining)
    except OSError as exc:
        errors.append(f"UDP flow to {context.target}:{port} failed: {exc}")
    finally:
        if sender is not None:
            sender.close()
    if read_responses and responses == 0 and not errors:
        errors.append(
            f"no UDP response received from {context.target}:{port} - is the FERA responder "
            "running on the target endpoint?"
        )
    return NativeStats(
        bytes_sent=bytes_sent,
        packets_sent=packets_sent,
        duration_s=clock() - started,
        errors=tuple(errors),
    )


def send_udp_bursts(
    parameters: Mapping[str, Any],
    context: TrafficContext,
    *,
    sender_factory: Callable[..., DatagramSender] = UdpSender,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> NativeStats:
    """Emit bursty, small-message UDP traffic (messaging-like shape).

    Parameters: ``port``, ``bursts``, ``messages_per_burst``, ``message_size``,
    ``burst_gap_ms``, ``message_gap_ms``, ``duration_s``, ``read_responses``.
    """
    port = int(parameters.get("port") or context.port or DEFAULT_ECHO_PORT)
    duration_s = _bounded_duration(parameters.get("duration_s"), context.duration_s)
    bursts = int(parameters.get("bursts", 6))
    messages_per_burst = int(parameters.get("messages_per_burst", 3))
    message_size = int(parameters.get("message_size", 320))
    burst_gap_s = max(0.01, float(parameters.get("burst_gap_ms", 1200)) / 1000.0)
    message_gap_s = max(0.01, float(parameters.get("message_gap_ms", 250)) / 1000.0)
    read_responses = bool(parameters.get("read_responses", True))
    response_timeout_s = float(parameters.get("response_timeout_ms", 400)) / 1000.0
    rng = random.Random(context.seed + 7)

    bytes_sent = 0
    packets_sent = 0
    responses = 0
    errors: list[str] = []
    started = clock()
    sender: DatagramSender | None = None
    try:
        sender = sender_factory(context.target, port, source=context.source)
        for burst_index in range(max(1, bursts)):
            if clock() - started >= duration_s:
                break
            for message_index in range(max(1, messages_per_burst)):
                if clock() - started >= duration_s:
                    break
                size = max(32, int(message_size * rng.uniform(0.6, 1.4)))
                payload = deterministic_payload(context.seed + burst_index * 100 + message_index, size)
                sender.send(payload)
                bytes_sent += size
                packets_sent += 1
                if read_responses and sender.receive(response_timeout_s) is not None:
                    responses += 1
                sleep(message_gap_s)
            sleep(burst_gap_s)
    except OSError as exc:
        errors.append(f"bursty UDP flow to {context.target}:{port} failed: {exc}")
    finally:
        if sender is not None:
            sender.close()
    if read_responses and responses == 0 and not errors:
        errors.append(
            f"no UDP response received from {context.target}:{port} - start the FERA responder "
            "on the target endpoint (python -m fera.traffic.servers --proto udp)"
        )
    return NativeStats(
        bytes_sent=bytes_sent,
        packets_sent=packets_sent,
        duration_s=clock() - started,
        errors=tuple(errors),
    )


def send_tcp_stream(
    parameters: Mapping[str, Any],
    context: TrafficContext,
    *,
    connector_factory: Callable[..., socket.socket] = tcp_connector,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> NativeStats:
    """Emit a sustained, optionally bursting TCP stream (video-like shape).

    Parameters: ``port``, ``duration_s``, ``chunk_bytes``, ``target_mbps``
    (``None`` = as fast as possible), ``burst_on_ms``/``burst_off_ms`` (both
    required to enable bursts).
    """
    port = int(parameters.get("port") or context.port or DEFAULT_ECHO_PORT)
    duration_s = _bounded_duration(parameters.get("duration_s"), context.duration_s)
    chunk_bytes = max(1024, int(parameters.get("chunk_bytes", 16384)))
    target_mbps = parameters.get("target_mbps")
    burst_on_s = float(parameters.get("burst_on_ms", 0)) / 1000.0
    burst_off_s = float(parameters.get("burst_off_ms", 0)) / 1000.0
    payload = deterministic_payload(context.seed + 11, chunk_bytes)

    bytes_sent = 0
    packets_sent = 0
    errors: list[str] = []
    started = clock()
    sock: socket.socket | None = None
    try:
        sock = connector_factory(context.target, port, source=context.source)
        while clock() - started < duration_s:
            elapsed = clock() - started
            sock.sendall(payload)
            bytes_sent += chunk_bytes
            packets_sent += 1
            if burst_on_s > 0 and burst_off_s > 0:
                cycle = burst_on_s + burst_off_s
                phase = elapsed % cycle
                if phase >= burst_on_s:
                    sleep(min(burst_off_s, cycle - phase))
            if target_mbps:
                target_bytes = float(target_mbps) * 1_000_000 / 8.0
                expected = target_bytes * (clock() - started)
                if bytes_sent > expected:
                    sleep(min(0.25, (bytes_sent - expected) / target_bytes))
    except OSError as exc:
        errors.append(f"TCP stream to {context.target}:{port} failed: {exc}")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:  # pragma: no cover - defensive
                pass
    return NativeStats(
        bytes_sent=bytes_sent,
        packets_sent=packets_sent,
        duration_s=clock() - started,
        errors=tuple(errors),
    )


def send_tcp_request_response(
    parameters: Mapping[str, Any],
    context: TrafficContext,
    *,
    connector_factory: Callable[..., socket.socket] = tcp_connector,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> NativeStats:
    """Emit repeated request/response exchanges (email-like shape).

    Each session sends ``request_bytes`` in ``chunk_bytes`` writes and reads the
    responder's answer.  An unanswered session is reported as an error: the
    shape of this class requires a responder, and FERA does not pretend that a
    one-way write is an email-like exchange.
    """
    port = int(parameters.get("port") or context.port or DEFAULT_ECHO_PORT)
    sessions = max(1, int(parameters.get("sessions", 4)))
    request_bytes = max(1024, int(parameters.get("request_bytes", 65536)))
    chunk_bytes = max(512, int(parameters.get("chunk_bytes", 8192)))
    pause_s = max(0.0, float(parameters.get("pause_ms", 500)) / 1000.0)
    response_timeout_s = float(parameters.get("response_timeout_ms", 3000)) / 1000.0
    max_duration_s = _bounded_duration(parameters.get("duration_s"), context.duration_s)
    rng = random.Random(context.seed + 23)

    sent = 0
    received = 0
    sessions_ok = 0
    errors: list[str] = []
    started = clock()
    for session_index in range(sessions):
        if clock() - started >= max_duration_s:
            break
        size = max(1024, int(request_bytes * rng.uniform(0.75, 1.25)))
        payload = deterministic_payload(context.seed + session_index, size)
        sock: socket.socket | None = None
        try:
            sock = connector_factory(context.target, port, source=context.source)
            sock.settimeout(response_timeout_s)
            for offset in range(0, size, chunk_bytes):
                sock.sendall(payload[offset : offset + chunk_bytes])
                sent += min(chunk_bytes, size - offset)
            session_received = 0
            try:
                while True:
                    data = sock.recv(chunk_bytes)
                    if not data:
                        break
                    session_received += len(data)
            except TimeoutError:
                pass
            received += session_received
            if session_received > 0:
                sessions_ok += 1
            else:
                errors.append(
                    f"session {session_index + 1} received no response from {context.target}:{port} "
                    "(the FERA responder must run on the target endpoint)"
                )
        except OSError as exc:
            errors.append(f"session {session_index + 1} to {context.target}:{port} failed: {exc}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:  # pragma: no cover - defensive
                    pass
        sleep(pause_s)
    if errors and sessions_ok == 0:
        raise FeraError(
            f"no request/response session completed against {context.target}:{port}",
            code=ErrorCode.TRAFFIC_GENERATION_FAILED,
            hint="start the FERA responder on the responder endpoint: "
            "python -m fera.traffic.servers --proto tcp",
            details={"sessions": sessions, "errors": errors[:4]},
        )
    return NativeStats(
        bytes_sent=sent + received,
        packets_sent=max(1, sessions),
        duration_s=clock() - started,
        errors=tuple(errors[:4]),
    )


#: Native step kinds understood by :func:`fera.traffic.base.execute_plan`.
NATIVE_EXECUTORS: Mapping[str, Callable[[Mapping[str, Any], TrafficContext], NativeStats]] = {
    "udp_pattern": send_udp_pattern,
    "udp_bursts": send_udp_bursts,
    "tcp_stream": send_tcp_stream,
    "tcp_request_response": send_tcp_request_response,
}


__all__ = [
    "DEFAULT_ECHO_PORT",
    "MAX_DURATION_S",
    "NATIVE_EXECUTORS",
    "DatagramSender",
    "UdpSender",
    "deterministic_payload",
    "send_tcp_request_response",
    "send_tcp_stream",
    "send_udp_bursts",
    "send_udp_pattern",
    "tcp_connector",
]



