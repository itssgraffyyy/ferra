"""Responder services used by the traffic generators.

Some traffic classes only exist in *both* directions (a request and an answer).
FERA therefore ships a tiny, dependency free responder that runs on the
responder endpoint inside the testbed:

* ``--proto udp``  - echo server (messaging-like / bidirectional voip-like flows)
* ``--proto tcp``  - echo server (email-like and native video-like flows)
* ``--proto http`` - HTTP server serving ``/payload?bytes=N`` (web class)

Run it directly::

    python -m fera.traffic.servers --proto udp --bind 10.30.0.1 --port 9099
"""

from __future__ import annotations

import argparse
import contextlib
import socket
import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..common.logging_utils import configure_logging, get_logger

logger = get_logger(__name__)

DEFAULT_BIND = "0.0.0.0"
RECV_SIZE = 65536


def _address_family(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def serve_udp_echo(
    bind: str,
    port: int,
    *,
    duration_s: float | None = None,
    stop: threading.Event | None = None,
) -> None:
    """Echo every received datagram back to its sender."""
    stop_event = stop or threading.Event()
    with socket.socket(_address_family(bind), socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, port))
        sock.settimeout(0.5)
        deadline = time.monotonic() + duration_s if duration_s else None
        logger.info("UDP echo responder listening on %s:%d", bind, port)
        while not stop_event.is_set():
            if deadline is not None and time.monotonic() > deadline:
                logger.info("UDP echo responder reached its duration limit")
                return
            try:
                data, peer = sock.recvfrom(RECV_SIZE)
            except TimeoutError:
                continue
            except OSError as exc:  # pragma: no cover - defensive
                logger.warning("UDP responder socket error: %s", exc)
                return
            with contextlib.suppress(OSError):
                sock.sendto(data, peer)


def _serve_tcp_connection(connection: socket.socket) -> None:
    with connection:
        connection.settimeout(5.0)
        try:
            while True:
                data = connection.recv(RECV_SIZE)
                if not data:
                    return
                connection.sendall(data)
        except (TimeoutError, OSError):
            return


def serve_tcp_echo(
    bind: str,
    port: int,
    *,
    duration_s: float | None = None,
    stop: threading.Event | None = None,
) -> None:
    """Echo every TCP connection's payload back to the client."""
    stop_event = stop or threading.Event()
    with socket.socket(_address_family(bind), socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind, port))
        server.listen(16)
        server.settimeout(0.5)
        deadline = time.monotonic() + duration_s if duration_s else None
        logger.info("TCP echo responder listening on %s:%d", bind, port)
        while not stop_event.is_set():
            if deadline is not None and time.monotonic() > deadline:
                logger.info("TCP echo responder reached its duration limit")
                return
            try:
                connection, _peer = server.accept()
            except TimeoutError:
                continue
            except OSError as exc:  # pragma: no cover - defensive
                logger.warning("TCP responder socket error: %s", exc)
                return
            threading.Thread(target=_serve_tcp_connection, args=(connection,), daemon=True).start()


def serve_http(
    bind: str,
    port: int,
    *,
    default_bytes: int = 2_000_000,
    duration_s: float | None = None,
) -> None:
    """Serve a deterministic ``/payload`` object for the web traffic class."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlparse

    payload_cache: dict[int, bytes] = {}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
            logger.debug("http responder: %s", format % args)

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            parsed = urlparse(self.path)
            if parsed.path == "/payload":
                query = parse_qs(parsed.query)
                try:
                    size = int(query.get("bytes", [default_bytes])[0])
                except (TypeError, ValueError):
                    size = default_bytes
                size = max(1, min(size, 200_000_000))
                body = payload_cache.get(size)
                if body is None:
                    body = bytes(index % 251 for index in range(size))
                    payload_cache[size] = body
            else:
                body = f"FERA responder: {parsed.path}\n".encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    address: Any = (bind, port, 0, 0) if _address_family(bind) == socket.AF_INET6 else (bind, port)
    server = ThreadingHTTPServer(address, Handler)
    server.daemon_threads = True
    logger.info("HTTP responder listening on %s:%d", bind, port)
    if duration_s:
        timer = threading.Timer(duration_s, server.shutdown)
        timer.daemon = True
        timer.start()
    try:
        server.serve_forever(poll_interval=0.3)
    finally:
        server.server_close()


def responder_command(
    proto: str,
    *,
    host: str,
    port: int | None = None,
    duration_s: float | None = None,
    python_executable: str = "python3",
    pythonpath: str | Path | None = None,
    payload_bytes: int | None = None,
) -> list[str]:
    """Build the command that starts a responder on the target endpoint.

    ``pythonpath`` is passed through ``env`` so the responder can import
    ``fera`` inside a network namespace without installing the package.
    """
    from .profiles import default_responder_settings

    settings = default_responder_settings()
    defaults = {
        "udp": settings["echo_port"],
        "tcp": settings["echo_port"],
        "http": settings["http_port"],
    }
    if proto not in defaults:
        raise ValueError(f"unsupported responder protocol: {proto!r}")
    command: list[str] = []
    if pythonpath:
        command += ["env", f"PYTHONPATH={pythonpath}"]
    command += [
        python_executable,
        "-m",
        "fera.traffic.servers",
        "--proto",
        proto,
        "--bind",
        host,
        "--port",
        str(int(port or defaults[proto])),
    ]
    if duration_s:
        command += ["--duration", f"{float(duration_s):.1f}"]
    if payload_bytes and proto == "http":
        command += ["--payload-bytes", str(int(payload_bytes))]
    return command


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point (``python -m fera.traffic.servers``)."""
    parser = argparse.ArgumentParser(description="FERA testbed responder")
    parser.add_argument("--proto", choices=("udp", "tcp", "http"), required=True)
    parser.add_argument("--bind", default=DEFAULT_BIND)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--duration", type=float, default=None, help="stop after N seconds")
    parser.add_argument("--payload-bytes", type=int, default=2_000_000)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(list(argv) if argv is not None else None)
    configure_logging(args.log_level)

    try:
        if args.proto == "udp":
            serve_udp_echo(args.bind, args.port, duration_s=args.duration)
        elif args.proto == "tcp":
            serve_tcp_echo(args.bind, args.port, duration_s=args.duration)
        else:
            serve_http(args.bind, args.port, default_bytes=args.payload_bytes, duration_s=args.duration)
    except KeyboardInterrupt:  # pragma: no cover - interactive
        logger.info("responder interrupted")
    return 0


if __name__ == "__main__":  # pragma: no cover - module entry point
    sys.exit(main())


__all__ = [
    "DEFAULT_BIND",
    "main",
    "responder_command",
    "serve_http",
    "serve_tcp_echo",
    "serve_udp_echo",
]

