"""tshark discovery and structured field extraction."""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..common.errors import ErrorCode, FeraError
from ..common.logging_utils import get_logger
from ..common.process import BaseRunner, SubprocessRunner

logger = get_logger(__name__)

WINDOWS_CANDIDATES: tuple[str, ...] = (
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
)
POSIX_CANDIDATES: tuple[str, ...] = (
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
    "/opt/homebrew/bin/tshark",
)


class TsharkError(FeraError):
    """tshark is unavailable or failed to dissect a capture."""

    code = ErrorCode.TOOL_NOT_AVAILABLE


def find_tshark(explicit: str | Path | None = None) -> str | None:
    """Locate a tshark executable without executing anything."""
    if explicit:
        candidate = str(explicit)
        if Path(candidate).is_file():
            return candidate
        return None
    env_path = os.environ.get("FERA_TSHARK_PATH")
    if env_path and Path(env_path).is_file():
        return env_path
    on_path = shutil.which("tshark")
    if on_path:
        return on_path
    for candidate in (*WINDOWS_CANDIDATES, *POSIX_CANDIDATES):
        if Path(candidate).is_file():
            return candidate
    return None


@dataclass
class TsharkWrapper:
    """Thin wrapper around tshark using FERA's runner abstraction."""

    tshark_path: str | None = None
    runner: BaseRunner | None = None
    extra_args: tuple[str, ...] = ()
    available: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        resolved = find_tshark(self.tshark_path)
        self.tshark_path = resolved
        self.available = resolved is not None
        if self.runner is None:
            self.runner = SubprocessRunner()

    def _require(self) -> tuple[str, BaseRunner]:
        if not self.available or not self.tshark_path:
            raise TsharkError(
                "tshark is not available",
                code=ErrorCode.TOOL_NOT_AVAILABLE,
                hint="install Wireshark/tshark or analyse with --no-tshark",
            )
        assert self.runner is not None
        return self.tshark_path, self.runner

    def get_version(self) -> str | None:
        """Return the tshark version string, or None when unavailable."""
        try:
            path, runner = self._require()
        except TsharkError:
            return None
        result = runner.run([path, "--version"], timeout=30.0)
        if not result.ok:
            return None
        first_line = (result.stdout or "").splitlines()
        return first_line[0].strip() if first_line else None

    def extract_frames(
        self,
        pcap_path: str | Path,
        *,
        display_filter: str | None = None,
        fields: tuple[str, ...] = (),
        timeout: float = 120.0,
    ) -> list[dict[str, Any]]:
        """Dissect frames with ``tshark -T ek`` and return parsed JSON rows."""
        path, runner = self._require()
        command: list[str] = [path, "-r", str(pcap_path), "-T", "ek"]
        if display_filter:
            command += ["-Y", display_filter]
        if self.extra_args:
            command += list(self.extra_args)
        # -T ek emits one JSON object per line; ask for fields when given.
        for item in fields:
            command += ["-e", item]
        command += ["-x"]
        result = runner.run(command, timeout=timeout)
        if not result.ok and not (result.stdout or "").strip():
            raise TsharkError(
                f"tshark failed on {Path(pcap_path).name}: {(result.stderr or '').strip()[:300]}",
                code=ErrorCode.TOOL_NOT_AVAILABLE,
                details={"stderr": (result.stderr or "")[:2000]},
            )
        rows: list[dict[str, Any]] = []
        for line in (result.stdout or "").splitlines():
            text = line.strip().rstrip(",")
            if not text.startswith("{"):
                continue
            try:
                decoded = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(decoded, dict):
                layers = decoded.get("layers")
                rows.append({"layers": layers} if isinstance(layers, dict) else decoded)
        return rows


__all__ = ["POSIX_CANDIDATES", "WINDOWS_CANDIDATES", "TsharkError", "TsharkWrapper", "find_tshark"]
