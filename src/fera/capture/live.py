"""Bounded, local packet capture for the product's live mode.

This module does exactly one job: obtain a *bounded temporary PCAP* and hand
it to the existing orchestrator.  It contains no protocol parsing, no feature
extraction and no scoring - everything after the capture file exists is
:mod:`fera.core.orchestrator`'s job, which is what keeps the live path and the
uploaded-file path on one pipeline.

Design constraints:

* **Bounded.**  A capture is a file on disk with a hard duration limit
  (:data:`MAX_DURATION_S`) and a hard packet count, so a forgotten request can
  never fill the disk.
* **No shell.**  Commands are argument arrays executed through
  :class:`~fera.common.process.BaseRunner`; ``shell=True`` is never used and a
  user supplied interface name or filter can never be interpreted by a shell.
* **Honest about the environment.**  Privileged capture needs ``tcpdump`` or
  ``dumpcap`` and, on most systems, root or ``CAP_NET_RAW``.  When that is
  missing this module raises a specific :class:`~fera.common.errors.FeraError`
  (``TOOL_NOT_AVAILABLE`` / ``INSUFFICIENT_PRIVILEGES``) instead of writing an
  empty file that would later look like a capture with no traffic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..common.errors import ErrorCode, FeraError
from ..common.process import BaseRunner, SubprocessRunner

#: Capture tools tried, in order.  ``dumpcap`` is preferred where present
#: because it is the Wireshark capture binary and does not need root on a
#: machine where the user is already in the ``wireshark`` group.
CAPTURE_TOOLS: tuple[str, ...] = ("dumpcap", "tcpdump")

#: Default and permitted wall-clock bounds for one live capture.
DEFAULT_DURATION_S = 10
MIN_DURATION_S = 1
MAX_DURATION_S = 60

#: Hard cap on captured packets, independent of the duration bound.
MAX_PACKET_COUNT = 50_000

#: Snapshot length in bytes; enough for headers and flow statistics, and it
#: keeps a 60 second capture small.
SNAPLEN = 512

#: Interface names are restricted to a conservative POSIX-ish charset.  This is
#: the second layer of defence: the runner already never invokes a shell, and a
#: name that does not match cannot be passed to tcpdump at all.
_INTERFACE = re.compile(r"^[A-Za-z0-9._:-]{1,32}$")

#: Capture filter is restricted to the characters a BPF expression needs.
_FILTER = re.compile(r"^[A-Za-z0-9_ .:\[\]<>!=/()-]{0,200}$")



def validate_interface(interface: str) -> str:
    """Return ``interface`` if it is a plausible interface name.

    Rejects empty strings, path separators, whitespace and anything long enough
    to be an attempt at argument injection.  An operator who mistypes an
    interface gets a validation error instead of a confusing tcpdump failure.
    """
    candidate = str(interface or "").strip()
    if not _INTERFACE.match(candidate):
        raise FeraError(
            f"{interface!r} is not a valid interface name",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            hint="use a short interface name such as eth0, wlan0, any or lo",
            details={"interface": str(interface)[:64]},
        )
    return candidate


def validate_duration(duration: int | float) -> int:
    """Return ``duration`` when it is inside the documented bounds.

    Values outside the range are an operator error, not something to silently
    round: a request for 3600 seconds means the caller misunderstood the mode.
    """
    try:
        seconds = int(duration)
    except (TypeError, ValueError) as exc:
        raise FeraError(
            f"capture duration must be a whole number of seconds (got {duration!r})",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            details={"duration": str(duration)[:32]},
        ) from exc
    if not MIN_DURATION_S <= seconds <= MAX_DURATION_S:
        raise FeraError(
            f"capture duration must be between {MIN_DURATION_S} and {MAX_DURATION_S} seconds (got {seconds})",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            hint="live capture is intentionally bounded; use a longer offline capture for long runs",
            details={"duration": seconds, "min": MIN_DURATION_S, "max": MAX_DURATION_S},
        )
    return seconds


def validate_filter(capture_filter: str | None) -> str | None:
    """Return the capture filter when it is safe to pass to the capture tool."""
    if capture_filter is None or not str(capture_filter).strip():
        return None
    candidate = str(capture_filter).strip()
    if not _FILTER.match(candidate):
        raise FeraError(
            "capture filter contains unsupported characters",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            hint="use a simple BPF expression such as 'udp port 500 or ip proto 50'",
            details={"capture_filter": candidate[:64]},
        )
    return candidate


def find_capture_tool(runner: BaseRunner | None = None) -> str:
    """Return the path of the first usable capture tool.

    Raises ``TOOL_NOT_AVAILABLE`` listing what was looked for, so both
    ``GET /capabilities`` and the API error can state the real reason.
    """
    active = runner if runner is not None else SubprocessRunner()
    for tool in CAPTURE_TOOLS:
        found = active.which(tool)
        if found:
            return found
    raise FeraError(
        "no packet capture tool is installed",
        code=ErrorCode.TOOL_NOT_AVAILABLE,
        hint=(
            "install tcpdump (Debian/Ubuntu: apt install tcpdump) or wireshark's dumpcap, then retry; "
            "live capture stays unavailable until one is present"
        ),
        details={"searched": list(CAPTURE_TOOLS)},
    )


def live_capture_available(runner: BaseRunner | None = None) -> tuple[bool, str | None]:
    """Whether a live capture could plausibly run here, plus a reason when not.

    Deliberately cheap and side-effect free: it checks for the binary only and
    does *not* claim privileges are present.  ``True`` means "worth offering in
    the UI", not "a capture will succeed".
    """
    try:
        find_capture_tool(runner)
    except FeraError as exc:
        return False, exc.message
    return True, None


@dataclass(frozen=True)
class LiveCapture:
    """The outcome of one bounded live capture."""

    path: Path
    interface: str
    duration_s: int
    tool: str
    captured_at: str
    command: tuple[str, ...]
    size_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "interface": self.interface,
            "duration_s": self.duration_s,
            "tool": self.tool,
            "captured_at": self.captured_at,
            "command": list(self.command),
            "size_bytes": self.size_bytes,
        }


def build_command(
    tool: str,
    interface: str,
    target: Path,
    *,
    duration_s: int,
    capture_filter: str | None = None,
) -> tuple[str, ...]:
    """Return the argument array for a bounded capture.

    Kept separate from execution so the command shape can be asserted in a test
    without running a privileged capture.  No argument is ever concatenated into
    a shell string, and every value is its own list element.
    """
    name = Path(tool).name
    common: tuple[str, ...] = ("-i", interface, "-w", str(target), "-s", str(SNAPLEN))
    if name == "dumpcap":
        command = (str(tool), *common, "-a", f"duration:{duration_s}", "-c", str(MAX_PACKET_COUNT))
    else:
        command = (str(tool), *common, "-G", str(duration_s), "-W", "1", "-c", str(MAX_PACKET_COUNT))
    if capture_filter:
        command = (*command, capture_filter)
    return command


_PERMISSION_MARKERS = ("permission denied", "you don't have permission", "operation not permitted")


def classify_failure(result: Any, *, tool: str, duration_s: int) -> FeraError:
    """Map a failed capture process onto a specific :class:`FeraError`.

    The distinction matters to an operator: a missing tool is an install step, a
    permission error is a privilege step, and a timeout is a different problem
    again.  All three are reported rather than collapsed into "capture failed".
    """
    stderr = getattr(result, "stderr", "") or ""
    stdout = getattr(result, "stdout", "") or ""
    detail = f"{stderr} {stdout}".lower()
    details = {
        "tool": tool,
        "returncode": getattr(result, "returncode", None),
        "duration_s": duration_s,
        "stderr_tail": stderr[-500:],
    }
    if getattr(result, "timed_out", False):
        return FeraError(
            f"live capture did not stop within its {duration_s}s budget",
            code=ErrorCode.TIMEOUT,
            hint="try a shorter duration; the capture tool did not honour its stop condition",
            details=details,
        )
    if any(marker in detail for marker in _PERMISSION_MARKERS):
        return FeraError(
            f"live capture was refused: {tool} needs elevated privileges",
            code=ErrorCode.INSUFFICIENT_PRIVILEGES,
            hint="run the API as root, grant CAP_NET_RAW, or add the user to the wireshark group",
            details=details,
        )
    return FeraError(
        f"live capture failed (exit code {getattr(result, 'returncode', None)})",
        code=ErrorCode.CAPTURE_START_FAILED,
        hint="check that the interface exists and is up, then retry",
        details=details,
    )


def capture_live(
    interface: str,
    *,
    duration_s: int = DEFAULT_DURATION_S,
    target_dir: Path | str,
    capture_filter: str | None = None,
    runner: BaseRunner | None = None,
    timeout_slack_s: float = 15.0,
) -> LiveCapture:
    """Record a bounded capture of ``interface`` and return the resulting file.

    The tool is given a hard stop condition and a packet cap, so a forgotten
    request cannot fill the disk.  A run that produces no file, or an empty one,
    is treated as a failure and the partial file is removed: an empty PCAP handed
    to the analyser would look like a capture in which nothing happened, which is
    a claim the pipeline cannot support.
    """
    from ..core.bundle import utc_now

    active = runner if runner is not None else SubprocessRunner()
    resolved_interface = validate_interface(interface)
    seconds = validate_duration(duration_s)
    expression = validate_filter(capture_filter)
    tool = find_capture_tool(active)

    directory = Path(target_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().replace(":", "").replace("-", "")
    target = directory / f"live_{stamp}_{resolved_interface.replace(':', '_')}.pcap"
    command = build_command(tool, resolved_interface, target, duration_s=seconds, capture_filter=expression)
    captured_at = utc_now()

    try:
        result = active.run(command, timeout=float(seconds) + timeout_slack_s)
    except FeraError:
        target.unlink(missing_ok=True)
        raise
    except Exception as exc:  # noqa: BLE001 - runner boundary
        target.unlink(missing_ok=True)
        raise FeraError(
            f"live capture could not be started: {exc}",
            code=ErrorCode.CAPTURE_START_FAILED,
            details={"command": list(command)},
        ) from exc

    if not getattr(result, "ok", False):
        target.unlink(missing_ok=True)
        raise classify_failure(result, tool=Path(tool).name, duration_s=seconds)
    if not target.is_file():
        raise FeraError(
            f"{Path(tool).name} reported success but wrote no capture file",
            code=ErrorCode.CAPTURE_START_FAILED,
            hint="the capture directory may not be writable by this user",
            details={"command": list(command), "expected_path": str(target)},
        )
    size = target.stat().st_size
    if size == 0:
        target.unlink(missing_ok=True)
        raise FeraError(
            f"live capture produced an empty file after {seconds}s on {resolved_interface}",
            code=ErrorCode.CAPTURE_EMPTY,
            hint="check the interface is up and carrying traffic, or widen the capture filter",
            details={"interface": resolved_interface, "duration_s": seconds, "tool": Path(tool).name},
        )
    return LiveCapture(
        path=target,
        interface=resolved_interface,
        duration_s=seconds,
        tool=Path(tool).name,
        captured_at=captured_at,
        command=tuple(command),
        size_bytes=size,
    )


__all__ = [
    "CAPTURE_TOOLS",
    "DEFAULT_DURATION_S",
    "MAX_DURATION_S",
    "MAX_PACKET_COUNT",
    "MIN_DURATION_S",
    "SNAPLEN",
    "LiveCapture",
    "build_command",
    "capture_live",
    "classify_failure",
    "find_capture_tool",
    "live_capture_available",
    "validate_duration",
    "validate_filter",
    "validate_interface",
]

