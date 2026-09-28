"""Shared pytest fixtures and helpers.

The helpers build the artefacts the pipeline consumes (experiment configs,
synthetic PCAP files, fake processes) so the tests exercise the real code paths
without a VPN, root privileges or a Linux kernel.
"""

from __future__ import annotations

import struct
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from fera.common.paths import ProjectPaths  # noqa: E402
from fera.dataset.schema import ExperimentConfig, IpsecMode, TrafficClass  # noqa: E402
from fera.testbed.algorithms import DhGroup, EncryptionAlg, IntegrityAlg  # noqa: E402
from fera.testbed.topology import default_topology  # noqa: E402


@pytest.fixture()
def repo_paths() -> ProjectPaths:
    """Paths of the real repository checkout."""
    return ProjectPaths(REPO_ROOT)


@pytest.fixture()
def sandbox_paths(tmp_path: Path) -> ProjectPaths:
    """A throw-away repository layout used by pipeline tests."""
    paths = ProjectPaths(tmp_path)
    paths.ensure_runtime_dirs()
    return paths


@pytest.fixture()
def topology():
    """The shipped default (namespace) topology."""
    return default_topology()


def make_config(
    experiment_id: str = "exp_000_tunnel_aes128gcm_ecp256_pfson_ipv4_icmp",
    *,
    mode: IpsecMode = IpsecMode.TUNNEL,
    encryption: EncryptionAlg = EncryptionAlg.AES128_GCM,
    integrity: IntegrityAlg = IntegrityAlg.AEAD,
    dh_group: DhGroup = DhGroup.ECP256,
    pfs: bool = True,
    ip_version: int = 4,
    traffic_type: TrafficClass = TrafficClass.ICMP,
    capture_duration_s: float = 2.0,
    **kwargs: Any,
) -> ExperimentConfig:
    """Build a valid experiment configuration for tests."""
    return ExperimentConfig(
        experiment_id=experiment_id,
        mode=mode,
        encryption=encryption,
        integrity=integrity,
        dh_group=dh_group,
        pfs=pfs,
        ip_version=ip_version,
        traffic_type=traffic_type,
        capture_duration_s=capture_duration_s,
        **kwargs,
    )


# --- synthetic PCAP construction -------------------------------------------
PCAP_MAGIC_LE = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)


def ethernet_ipv4(
    protocol: int, *, payload: bytes = b"\x00" * 16, src_port: int = 0, dst_port: int = 0
) -> bytes:
    """Build an Ethernet/IPv4 frame with the given IP protocol number."""
    if protocol == 17:  # UDP
        transport = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    elif protocol == 1:  # ICMP
        transport = b"\x08\x00\x00\x00" + payload
    else:
        transport = payload
    total_length = 20 + len(transport)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        protocol,
        0,
        bytes([10, 10, 10, 1]),
        bytes([10, 10, 10, 2]),
    )
    ethernet = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
    return ethernet + ip_header + transport


def ethernet_ipv6(
    protocol: int, *, payload: bytes = b"\x00" * 16, src_port: int = 0, dst_port: int = 0
) -> bytes:
    """Build an Ethernet/IPv6 frame with the given next-header value."""
    if protocol == 17:
        transport = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    else:
        transport = payload
    ip_header = struct.pack("!IHBB", 0x60000000, len(transport), protocol, 64)
    addresses = bytes.fromhex("fd001010000000000000000000000001") + bytes.fromhex(
        "fd001010000000000000000000000002"
    )
    ethernet = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x86\xdd"
    return ethernet + ip_header + addresses + transport


def write_pcap(path: Path, frames: Iterable[bytes]) -> Path:
    """Write a valid classic PCAP file containing ``frames``."""
    body = bytearray(PCAP_MAGIC_LE)
    for index, frame in enumerate(frames):
        body += struct.pack("<IIII", 1700000000 + index, 0, len(frame), len(frame))
        body += frame
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(body))
    return path


def ike_and_esp_frames() -> list[bytes]:
    """A minimal but realistic mix of IKE, ESP, ICMP and IPv6 frames."""
    return [
        ethernet_ipv4(17, src_port=500, dst_port=500),
        ethernet_ipv4(17, src_port=500, dst_port=500),
        ethernet_ipv4(50, payload=b"\x00" * 40),
        ethernet_ipv4(50, payload=b"\x00" * 40),
        ethernet_ipv4(1),
        ethernet_ipv6(17, src_port=4500, dst_port=4500),
        ethernet_ipv6(50, payload=b"\x00" * 40),
    ]


def command_contains(command: Sequence[str], *needles: str) -> bool:
    """True when every needle appears somewhere in the command."""
    joined = " ".join(str(part) for part in command)
    return all(needle in joined for needle in needles)


class FakeProcess:
    """Minimal stand-in for the process of a long running tool."""

    def __init__(self, *, pid: int = 4242, on_stop: Any = None, running: bool = True) -> None:
        self.pid = pid
        self.returncode: int | None = None
        self._running = running
        self._on_stop = on_stop
        self.terminated = False

    def poll(self) -> int | None:
        return None if self._running else self.returncode

    def wait(self, timeout: float | None = None) -> int | None:
        return None if self._running else self.returncode

    def terminate(self) -> None:
        self._stop(0)

    def kill(self) -> None:
        self._stop(-9)

    def _stop(self, returncode: int) -> None:
        self.terminated = True
        self._running = False
        self.returncode = returncode
        if self._on_stop is not None:
            self._on_stop()


class ScriptedRunner:
    """Deterministic stand-in for ``SubprocessRunner`` used by runner tests.

    ``responses`` maps a substring of the command line to ``(returncode, stdout)``;
    the first matching entry wins.  ``available_tools`` controls ``which``.
    ``spawn`` returns a fake process whose stop callback writes a synthetic PCAP
    to the file named after ``-w`` - exactly what a capture tool does.
    """

    name = "scripted"

    def __init__(
        self,
        *,
        responses: Sequence[tuple[str, int, str]] = (),
        available_tools: Sequence[str] = (
            "swanctl",
            "tcpdump",
            "tshark",
            "ping",
            "curl",
            "iperf3",
            "ip",
            "ipsec",
        ),
        capture_frames: Iterable[bytes] | None = None,
    ) -> None:
        self.responses = list(responses)
        self.available_tools = tuple(available_tools)
        self.commands: list[tuple[str, ...]] = []
        self.spawned: list[tuple[str, ...]] = []
        self.capture_frames = list(capture_frames) if capture_frames is not None else ike_and_esp_frames()

    def which(self, tool: str) -> str | None:
        return f"/usr/bin/{tool}" if tool in self.available_tools else None

    def run(
        self,
        command,
        *,
        timeout: float = 60.0,
        check: bool = False,
        not_found_code=None,
        env=None,
        cwd=None,
        input_text=None,
    ):
        from fera.common.process import CommandResult

        cmd = tuple(str(part) for part in command)
        self.commands.append(cmd)
        joined = " ".join(cmd)
        for needle, returncode, stdout in self.responses:
            if needle in joined:
                return CommandResult(cmd, returncode, stdout, "", 0.01)
        return CommandResult(cmd, 0, "", "", 0.01)

    def spawn(self, command, *, stdout_path=None, stderr_path=None):
        from fera.common.process import ProcessHandle

        cmd = tuple(str(part) for part in command)
        self.spawned.append(cmd)
        output_path: Path | None = None
        if "-w" in cmd:
            output_path = Path(cmd[cmd.index("-w") + 1])
        frames = self.capture_frames

        def on_stop() -> None:
            if output_path is not None:
                write_pcap(output_path, frames)

        return ProcessHandle(cmd, FakeProcess(on_stop=on_stop))


#: Output of ``swanctl --list-sas`` for an established tunnel (used by tests).
SWANCTL_ESTABLISHED = """
fera-exp_000: #1, ESTABLISHED, IKEv2, 1111..i 2222..r
  local  'endpoint-a.fera.test' @ 10.10.10.1[4500]
  remote 'endpoint-b.fera.test' @ 10.10.10.2[4500]
  AES_GCM_16-128/PRF_HMAC_SHA2_256/ECP_256
  established 10s ago, rekeying in 14390s, reauth in 14390s
  fera-child-exp_000: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-128
    installed 10s ago, rekeying in 3590s, expires in 7190s
    in  c0a81401/32 === 0/0, 84 bytes, 1 packets, 5s ago
    out 0/0 === c0a81401/32, 84 bytes, 1 packets, 5s ago
"""

#: Output of ``swanctl --list-sas`` before the SA exists.
SWANCTL_EMPTY = ""

#: Typical ``tshark -q -z io,phs`` output for a capture with IKE and ESP.
TSHARK_PHS = """
===================================================================
Protocol Hierarchy Statistics
Filter: \n
eth                                      frames:7 bytes:700
  ip                                     frames:5 bytes:500
    udp                                  frames:2 bytes:200
      isakmp                             frames:2 bytes:200
    esp                                  frames:2 bytes:200
    icmp                                 frames:1 bytes:100
  ipv6                                   frames:2 bytes:200
    udp                                  frames:1 bytes:100
      isakmp                             frames:1 bytes:100
    esp                                  frames:1 bytes:100
===================================================================
"""

