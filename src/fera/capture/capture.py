"""Packet capture orchestration (tcpdump / dumpcap).

The capture runner is deliberately boring and robust:

1. select an available capture tool (tcpdump preferred, dumpcap as fallback),
2. start it *before* IKE initiation so the negotiation is inside the capture,
3. stop it gracefully (SIGINT, so tcpdump flushes the file),
4. verify the file exists and is not empty,
5. keep the tool log next to the PCAP as evidence.

Commands are argument arrays - no shell is involved - and a configured BPF
filter is validated before use (see :mod:`fera.capture.filters`).
"""

from __future__ import annotations

import os
import platform
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..common.errors import ErrorCode, FeraError, PrivilegeError
from ..common.logging_utils import get_logger
from ..common.process import BaseRunner, ProcessHandle, SubprocessRunner

logger = get_logger(__name__)

#: Minimal size of a classic PCAP file (global header).
PCAP_HEADER_BYTES = 24


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class CapturePlan:
    """How a capture will be performed."""

    tool: str
    command: tuple[str, ...]
    output_path: Path
    interface: str
    filter: str | None = None
    snaplen: int = 0
    log_path: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        from ..common.process import format_command

        return {
            "tool": self.tool,
            "command": list(self.command),
            "command_display": format_command(self.command),
            "output_path": str(self.output_path),
            "interface": self.interface,
            "filter": self.filter,
            "snaplen": self.snaplen,
            "log_path": str(self.log_path) if self.log_path else None,
        }


@dataclass(frozen=True)
class CaptureResult:
    """Outcome of a capture session."""

    pcap_path: Path
    exists: bool
    size_bytes: int
    tool: str
    interface: str
    filter: str | None
    started_at: str
    stopped_at: str
    duration_s: float
    returncode: int | None
    error_code: ErrorCode | None = None
    message: str | None = None
    log_path: Path | None = None
    command: tuple[str, ...] = ()
    executed: bool = True

    @property
    def usable(self) -> bool:
        """True when a non-trivial capture file exists."""
        return self.exists and self.size_bytes > PCAP_HEADER_BYTES

    def to_dict(self) -> dict[str, Any]:
        from ..common.process import format_command

        return {
            "pcap_path": str(self.pcap_path),
            "exists": self.exists,
            "size_bytes": self.size_bytes,
            "tool": self.tool,
            "interface": self.interface,
            "filter": self.filter,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "duration_s": round(self.duration_s, 3),
            "returncode": self.returncode,
            "error_code": self.error_code.value if self.error_code else None,
            "message": self.message,
            "log_path": str(self.log_path) if self.log_path else None,
            "command_display": format_command(self.command) if self.command else None,
            "executed": self.executed,
            "usable": self.usable,
        }


def select_capture_tool(runner: BaseRunner, preferred: str | None = None) -> str:
    """Return the capture tool to use, or raise an explicit error."""
    candidates = (preferred,) if preferred else ("tcpdump", "dumpcap")
    for tool in candidates:
        if tool and runner.which(tool):
            return tool
    raise FeraError(
        "no packet capture tool available (tried: {})".format(", ".join(str(c) for c in candidates)),
        code=ErrorCode.CAPTURE_TOOL_NOT_AVAILABLE,
        hint="apt-get install tcpdump   (or install Wireshark's dumpcap)",
        details={"tried": [str(candidate) for candidate in candidates]},
    )


def build_capture_command(
    tool: str,
    *,
    interface: str,
    output_path: Path | str,
    bpf_filter: str | None = None,
    snaplen: int = 0,
    emit_stdout_log: bool = False,
) -> list[str]:
    """Build the capture command as an argument array.

    * ``tcpdump``: ``-n`` numeric, ``-s`` snap length, ``-U`` packet buffered
      writes (so a killed capture still contains everything), ``-w`` output.
    * ``dumpcap``: ``-q`` quiet, ``-s`` snap length, ``-w`` output, ``-f`` filter,
      ``--print`` only when the caller wants the summary on stdout.
    """
    output = str(output_path)
    if tool == "tcpdump":
        command = ["tcpdump", "-i", interface, "-n", "-s", str(int(snaplen)), "-U", "-w", output]
        if bpf_filter:
            command.append(bpf_filter)
        return command
    if tool == "dumpcap":
        command = ["dumpcap", "-i", interface, "-q", "-s", str(int(snaplen)), "-w", output]
        if bpf_filter:
            command += ["-f", bpf_filter]
        if emit_stdout_log:
            command.append("--print")
        return command
    raise FeraError(
        f"unsupported capture tool: {tool!r}",
        code=ErrorCode.CAPTURE_TOOL_NOT_AVAILABLE,
        hint="supported tools: tcpdump, dumpcap",
        details={"tool": tool},
    )


def require_capture_privileges(runner: BaseRunner) -> None:
    """Fail early when the process cannot capture packets on this platform."""
    if os.name != "posix":
        raise PrivilegeError(
            "packet capture is only supported on POSIX systems in this pipeline",
            hint="run the experiment runner on the Linux testbed (see docs/testbed.md)",
            details={"platform": platform.system()},
        )
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() != 0:
        raise PrivilegeError(
            "packet capture requires root (raw sockets / CAP_NET_RAW)",
            hint="run with sudo, or grant cap_net_raw+cap_net_admin to the capture binary",
            details={"uid": geteuid()},
        )


def capture_file_stats(path: Path | str) -> tuple[bool, int]:
    """Return ``(exists, size_bytes)`` for a capture file."""
    candidate = Path(path)
    try:
        return candidate.is_file(), candidate.stat().st_size if candidate.is_file() else 0
    except OSError:  # pragma: no cover - defensive
        return False, 0


class CaptureSession:
    """Start/stop one packet capture with clean process handling."""

    def __init__(
        self,
        *,
        output_path: Path | str,
        interface: str = "any",
        bpf_filter: str | None = None,
        snaplen: int = 0,
        tool: str | None = None,
        runner: BaseRunner | None = None,
        log_path: Path | str | None = None,
        require_privileges: bool = True,
        command_prefix: Sequence[str] = (),
    ) -> None:
        self.output_path = Path(output_path)
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snaplen = int(snaplen)
        self.runner = runner if runner is not None else SubprocessRunner()
        self.tool = tool
        self.log_path = Path(log_path) if log_path is not None else self.output_path.with_suffix(".log")
        self.require_privileges = require_privileges
        self.command_prefix = tuple(str(part) for part in command_prefix)
        self.handle: ProcessHandle | None = None
        self._started_at: str | None = None
        self._started_monotonic: float | None = None
        self._plan: CapturePlan | None = None

    # -- planning --------------------------------------------------------
    def plan(self) -> CapturePlan:
        """Return the capture plan (selecting a tool when needed)."""
        if self._plan is not None:
            return self._plan
        tool = self.tool if self.tool and self.runner.which(self.tool) else select_capture_tool(self.runner, self.tool)
        command = build_capture_command(
            tool,
            interface=self.interface,
            output_path=self.output_path,
            bpf_filter=self.bpf_filter,
            snaplen=self.snaplen,
        )
        self._plan = CapturePlan(
            tool=tool,
            command=(*self.command_prefix, *command),
            output_path=self.output_path,
            interface=self.interface,
            filter=self.bpf_filter,
            snaplen=self.snaplen,
            log_path=self.log_path,
        )
        return self._plan

    # -- lifecycle -------------------------------------------------------
    def start(self) -> CapturePlan:
        """Start the capture process and return the plan that was used."""
        plan = self.plan()
        if self.require_privileges:
            require_capture_privileges(self.runner)
        command = list(plan.command)
        if any(part in {"-i", "any"} for part in command) and plan.interface == "any" and plan.tool == "dumpcap":
            raise FeraError(
                "dumpcap cannot capture on the 'any' pseudo interface",
                code=ErrorCode.CAPTURE_START_FAILED,
                hint="set capture_interface to a real interface (e.g. fera-va) in the experiment",
                details={"tool": plan.tool},
            )
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._started_at = _utc_now()
        self._started_monotonic = time.monotonic()
        try:
            self.handle = self.runner.spawn(command, stdout_path=self.log_path, stderr_path=self.log_path)
        except FeraError as exc:
            raise FeraError(
                f"could not start packet capture: {exc.message}",
                code=ErrorCode.CAPTURE_START_FAILED,
                hint=exc.hint,
                details={**exc.details, "plan": plan.to_dict()},
            ) from exc
        # Give the tool a moment to open the output file and fail fast if it cannot.
        time.sleep(0.4)
        if self.handle.poll() not in (None, 0):
            tail = self.log_tail()
            raise FeraError(
                f"capture tool exited immediately (rc={self.handle.returncode})",
                code=ErrorCode.CAPTURE_START_FAILED,
                hint="check the capture log; a missing interface or privilege problem shows up here",
                details={"plan": plan.to_dict(), "log_tail": tail},
            )
        logger.info("capture started: %s -> %s", plan.tool, self.output_path)
        return plan

    @property
    def started_at(self) -> str | None:
        return self._started_at

    @property
    def executed(self) -> bool:
        """False when the capture was planned but not actually started (dry run)."""
        return self.handle is not None and self.handle.process is not None

    def log_tail(self, max_bytes: int = 4000) -> str:
        """Return the tail of the capture tool log ('' when absent)."""
        try:
            if self.log_path.is_file():
                data = self.log_path.read_bytes()
                return data[-max_bytes:].decode("utf-8", errors="replace")
        except OSError:  # pragma: no cover - defensive
            return ""
        return ""

    def stop(self, *, grace_period_s: float = 5.0) -> CaptureResult:
        """Stop the capture, then verify that the PCAP exists and is not empty."""
        plan = self.plan()
        stopped_at = _utc_now()
        duration = time.monotonic() - self._started_monotonic if self._started_monotonic is not None else 0.0
        returncode: int | None = None
        if self.handle is not None:
            returncode = self.handle.stop(grace_period_s=grace_period_s)
            self.handle.close()
        exists, size = capture_file_stats(self.output_path)
        error_code: ErrorCode | None = None
        message: str | None = None
        if not self.executed:
            message = "dry run: the capture tool was not started"
        elif not exists:
            error_code = ErrorCode.CAPTURE_EMPTY
            message = f"capture file was not created: {self.output_path}"
        elif size <= PCAP_HEADER_BYTES:
            error_code = ErrorCode.CAPTURE_EMPTY
            message = f"capture file contains no packets ({size} bytes): {self.output_path}"
        logger.info(
            "capture stopped: %s %d bytes (rc=%s)%s",
            self.output_path.name,
            size,
            returncode,
            f" -> {error_code.value}" if error_code else "",
        )
        return CaptureResult(
            pcap_path=self.output_path,
            exists=exists,
            size_bytes=size,
            tool=plan.tool,
            interface=plan.interface,
            filter=plan.filter,
            started_at=self._started_at or "",
            stopped_at=stopped_at,
            duration_s=duration,
            returncode=returncode,
            error_code=error_code,
            message=message,
            log_path=self.log_path,
            command=plan.command,
            executed=self.executed,
        )

    def __enter__(self) -> CaptureSession:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.stop()


__all__ = [
    "PCAP_HEADER_BYTES",
    "CapturePlan",
    "CaptureResult",
    "CaptureSession",
    "build_capture_command",
    "capture_file_stats",
    "require_capture_privileges",
    "select_capture_tool",
]


