"""Tool version collection for reproducibility metadata.

Every capture records the versions of the tools that produced it, so a dataset
sample can be traced back to a concrete toolchain.  Missing tools are recorded
as ``None`` instead of failing: a dataset that was captured without ``iperf3``
is still valid, it just cannot claim a version for it.
"""

from __future__ import annotations

import platform
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .process import BaseRunner

#: Tool -> version query arguments.
VERSION_ARGUMENTS: Mapping[str, Sequence[str]] = {
    "swanctl": ("--version",),
    "ipsec": ("--version",),
    "strongswan": ("version",),
    "tcpdump": ("--version",),
    "dumpcap": ("-v",),
    "tshark": ("-v",),
    "iperf3": ("--version",),
    "curl": ("--version",),
    "ping": ("-V",),
}

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[-.\w]*)?)")


def python_version() -> str:
    """Return the running Python version as ``major.minor.micro``."""
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def platform_summary() -> dict[str, Any]:
    """Return a compact, JSON serialisable platform description."""
    return {
        "python": python_version(),
        "executable": sys.executable,
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "platform": platform.platform(),
    }


def parse_version(raw: str | None) -> str | None:
    """Extract the first version-like token from ``raw``."""
    if not raw:
        return None
    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _VERSION_RE.search(line)
        if match:
            return match.group(1)
        return line
    return None


def tool_version(
    tool: str,
    runner: BaseRunner,
    *,
    arguments: Sequence[str] | None = None,
    timeout: float = 15.0,
) -> str | None:
    """Return the version of ``tool`` or ``None`` when it is unavailable."""
    path = runner.which(tool)
    if path is None:
        return None
    args = tuple(arguments) if arguments is not None else tuple(VERSION_ARGUMENTS.get(tool, ("--version",)))
    try:
        result = runner.run([tool, *args], timeout=timeout)
    except Exception:  # noqa: BLE001 - version probing must never break a run
        return None
    if not result.executed:
        # Dry-run: the tool exists (or at least `which` claimed so) but was not run.
        return None
    if not result.ok:
        return None
    return parse_version(result.stdout or result.stderr)


def collect_tool_versions(
    runner: BaseRunner,
    tools: Iterable[str] | None = None,
    *,
    timeout: float = 15.0,
) -> dict[str, str | None]:
    """Collect versions for all requested tools (in a stable order)."""
    requested = list(tools) if tools is not None else list(VERSION_ARGUMENTS)
    versions: dict[str, str | None] = {}
    for tool in requested:
        versions[tool] = tool_version(tool, runner, timeout=timeout)
    return versions


def tool_availability(runner: BaseRunner, tools: Iterable[str]) -> dict[str, str | None]:
    """Return a mapping of tool name to resolved path (``None`` when missing)."""
    return {tool: runner.which(tool) for tool in tools}


__all__ = [
    "VERSION_ARGUMENTS",
    "collect_tool_versions",
    "parse_version",
    "platform_summary",
    "python_version",
    "tool_availability",
    "tool_version",
]
