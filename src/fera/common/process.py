"""Safe subprocess handling.

Every external command in FERA goes through this module.  Commands are always
passed as argument arrays (never concatenated into a shell string), so the
pipeline cannot be abused for shell injection; :func:`format_command` exists
for *display* only.

The runner abstraction (:class:`BaseRunner`) can be replaced by
:class:`RecordingRunner` for ``--dry-run`` and for unit tests, which keeps the
orchestration logic testable without a real VPN.
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ErrorCode, FeraError
from .logging_utils import get_logger

logger = get_logger(__name__)

DEFAULT_TIMEOUT_S = 60.0


def format_command(command: Sequence[Any]) -> str:
    """Return a shell-quoted, human readable command string (display only)."""
    return shlex.join([str(part) for part in command])


@dataclass(frozen=True)
class CommandResult:
    """Result of a finished (or intentionally not executed) command."""

    command: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    timed_out: bool = False
    executed: bool = True

    @property
    def ok(self) -> bool:
        """True when the command ran and exited with status 0."""
        return self.executed and self.returncode == 0 and not self.timed_out

    @property
    def display(self) -> str:
        return format_command(self.command)

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": list(self.command),
            "display": self.display,
            "returncode": self.returncode,
            "ok": self.ok,
            "timed_out": self.timed_out,
            "executed": self.executed,
            "duration_s": round(self.duration_s, 3),
            "stdout_tail": self.stdout[-2000:],
            "stderr_tail": self.stderr[-2000:],
        }


class ProcessHandle:
    """Wrapper around a long running process (used for packet capture)."""

    def __init__(
        self,
        command: Sequence[Any],
        process: subprocess.Popen[bytes] | Any | None,
        *,
        stdout_file: Any | None = None,
        stderr_file: Any | None = None,
        started_at: float | None = None,
    ) -> None:
        self.command: tuple[str, ...] = tuple(str(part) for part in command)
        self.process = process
        self.stdout_file = stdout_file
        self.stderr_file = stderr_file
        self.started_at = started_at if started_at is not None else time.monotonic()

    @property
    def pid(self) -> int | None:
        return getattr(self.process, "pid", None)

    @property
    def display(self) -> str:
        return format_command(self.command)

    def poll(self) -> int | None:
        if self.process is None:
            return None
        return self.process.poll()

    @property
    def returncode(self) -> int | None:
        return None if self.process is None else self.process.returncode

    def wait(self, timeout: float | None = None) -> int | None:
        if self.process is None:
            return None
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def signal_interrupt(self) -> None:
        """Ask the process to shut down gracefully (SIGINT on POSIX).

        ``tcpdump`` flushes and closes the capture file on SIGINT, which is why
        this is the preferred stop mechanism.
        """
        if self.process is None:
            return
        if os.name == "posix" and self.pid:
            try:
                os.kill(self.pid, signal.SIGINT)
                return
            except (ProcessLookupError, PermissionError, OSError):  # pragma: no cover
                pass
        self.terminate()

    def terminate(self) -> None:
        if self.process is None:
            return
        try:
            self.process.terminate()
        except Exception:  # pragma: no cover - defensive
            pass

    def kill(self) -> None:
        if self.process is None:
            return
        try:
            self.process.kill()
        except Exception:  # pragma: no cover - defensive
            pass

    def close(self) -> None:
        """Close log files and reap the process."""
        for stream in (self.stdout_file, self.stderr_file):
            if stream is not None:
                try:
                    stream.close()
                except Exception:  # pragma: no cover - defensive
                    pass
        if self.process is not None:
            self.wait(timeout=5.0)

    def stop(self, *, grace_period_s: float = 5.0, timeout_s: float = 10.0) -> int | None:
        """Stop the process gracefully, escalating to terminate/kill."""
        if self.process is None or self.poll() is not None:
            return self.returncode
        self.signal_interrupt()
        deadline = time.monotonic() + grace_period_s
        while time.monotonic() < deadline:
            if self.poll() is not None:
                return self.returncode
            time.sleep(0.1)
        self.terminate()
        if self.wait(timeout=timeout_s) is None:
            logger.warning("process did not terminate, sending SIGKILL: %s", self.display)
            self.kill()
            self.wait(timeout=timeout_s)
        return self.returncode


class BaseRunner:
    """Interface for command execution."""

    name = "base"

    def which(self, tool: str) -> str | None:
        """Return the absolute path of ``tool`` or ``None``."""
        raise NotImplementedError

    def run(
        self,
        command: Sequence[Any],
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        check: bool = False,
        not_found_code: ErrorCode = ErrorCode.TOOL_NOT_AVAILABLE,
        env: Mapping[str, str] | None = None,
        cwd: Path | str | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        """Run a command to completion and return its result."""
        raise NotImplementedError

    def spawn(
        self,
        command: Sequence[Any],
        *,
        stdout_path: Path | str | None = None,
        stderr_path: Path | str | None = None,
    ) -> ProcessHandle:
        """Start a long running command (packet capture)."""
        raise NotImplementedError


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


class SubprocessRunner(BaseRunner):
    """Real runner based on :mod:`subprocess`."""

    name = "subprocess"

    def which(self, tool: str) -> str | None:
        return shutil.which(tool)

    def run(
        self,
        command: Sequence[Any],
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        check: bool = False,
        not_found_code: ErrorCode = ErrorCode.TOOL_NOT_AVAILABLE,
        env: Mapping[str, str] | None = None,
        cwd: Path | str | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        cmd = tuple(str(part) for part in command)
        if not cmd:
            raise FeraError("attempted to run an empty command", code=ErrorCode.INTERNAL_ERROR)
        logger.debug("exec: %s", format_command(cmd))
        started = time.monotonic()
        merged_env = None
        if env is not None:
            merged_env = dict(os.environ)
            merged_env.update({str(key): str(value) for key, value in env.items()})
        try:
            completed = subprocess.run(  # noqa: S603 - argument array, shell never used
                list(cmd),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=merged_env,
                cwd=str(cwd) if cwd is not None else None,
                input=input_text,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except FileNotFoundError as exc:
            raise FeraError(
                f"required tool not found: {cmd[0]}",
                code=not_found_code,
                hint="install the tool or pass an explicit path",
                details={"command": list(cmd)},
            ) from exc
        except PermissionError as exc:
            raise FeraError(
                f"permission denied while executing: {cmd[0]}",
                code=ErrorCode.INSUFFICIENT_PRIVILEGES,
                hint="re-run with elevated privileges (root / NET_ADMIN capability)",
                details={"command": list(cmd)},
            ) from exc
        except subprocess.TimeoutExpired as exc:
            result = CommandResult(
                cmd,
                -1,
                _as_text(exc.stdout),
                _as_text(exc.stderr),
                time.monotonic() - started,
                timed_out=True,
            )
            logger.warning("command timed out after %.1fs: %s", timeout, result.display)
            if check:
                raise FeraError(
                    f"command timed out after {timeout:.1f}s: {result.display}",
                    code=ErrorCode.TIMEOUT,
                    details=result.to_dict(),
                ) from exc
            return result
        result = CommandResult(
            cmd,
            completed.returncode,
            completed.stdout or "",
            completed.stderr or "",
            time.monotonic() - started,
        )
        if check and not result.ok:
            raise FeraError(
                f"command failed with exit code {result.returncode}: {result.display}",
                code=ErrorCode.INTERNAL_ERROR,
                hint="inspect the captured stdout/stderr in the execution log",
                details=result.to_dict(),
            )
        return result

    def spawn(
        self,
        command: Sequence[Any],
        *,
        stdout_path: Path | str | None = None,
        stderr_path: Path | str | None = None,
    ) -> ProcessHandle:
        cmd = tuple(str(part) for part in command)
        if not cmd:
            raise FeraError("attempted to spawn an empty command", code=ErrorCode.INTERNAL_ERROR)
        stdout_file = None
        stderr_file = None
        try:
            if stdout_path is not None:
                Path(stdout_path).parent.mkdir(parents=True, exist_ok=True)
                stdout_file = open(str(stdout_path), "ab")  # noqa: SIM115 - handed to child
            if stderr_path is not None:
                Path(stderr_path).parent.mkdir(parents=True, exist_ok=True)
                stderr_file = open(str(stderr_path), "ab")  # noqa: SIM115 - handed to child
            logger.debug("spawn: %s", format_command(cmd))
            process = subprocess.Popen(  # noqa: S603 - argument array, shell never used
                list(cmd),
                stdout=stdout_file if stdout_file is not None else subprocess.DEVNULL,
                stderr=stderr_file if stderr_file is not None else subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError as exc:
            self._close_streams(stdout_file, stderr_file)
            raise FeraError(
                f"required tool not found: {cmd[0]}",
                code=ErrorCode.CAPTURE_TOOL_NOT_AVAILABLE,
                hint="install the capture tool (tcpdump / dumpcap)",
                details={"command": list(cmd)},
            ) from exc
        except PermissionError as exc:
            self._close_streams(stdout_file, stderr_file)
            raise FeraError(
                f"permission denied while starting: {cmd[0]}",
                code=ErrorCode.INSUFFICIENT_PRIVILEGES,
                hint="packet capture needs root on Linux",
                details={"command": list(cmd)},
            ) from exc
        return ProcessHandle(cmd, process, stdout_file=stdout_file, stderr_file=stderr_file)

    @staticmethod
    def _close_streams(*streams: Any) -> None:
        for stream in streams:
            if stream is not None:
                try:
                    stream.close()
                except Exception:  # pragma: no cover - defensive
                    pass


class RecordingRunner(BaseRunner):
    """Runner that *records* commands instead of executing them.

    Used for ``--dry-run`` (nothing may touch the machine) and by the test
    suite.  ``result_factory`` lets tests provide canned tool output.
    """

    name = "recording"

    def __init__(
        self,
        *,
        result_factory: Callable[[tuple[str, ...]], CommandResult] | None = None,
        available_tools: Sequence[str] | None = None,
        spawn_factory: Callable[[tuple[str, ...]], ProcessHandle] | None = None,
    ) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.spawned: list[tuple[str, ...]] = []
        self._result_factory = result_factory
        self._available_tools = tuple(available_tools) if available_tools is not None else None
        self._spawn_factory = spawn_factory

    def which(self, tool: str) -> str | None:
        if self._available_tools is None:
            return f"/usr/bin/{tool}"
        return f"/usr/bin/{tool}" if tool in self._available_tools else None

    def run(
        self,
        command: Sequence[Any],
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        check: bool = False,
        not_found_code: ErrorCode = ErrorCode.TOOL_NOT_AVAILABLE,
        env: Mapping[str, str] | None = None,
        cwd: Path | str | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        cmd = tuple(str(part) for part in command)
        self.commands.append(cmd)
        if self._result_factory is not None:
            result = self._result_factory(cmd)
        else:
            result = CommandResult(cmd, 0, "", "", 0.0, executed=False)
        logger.debug("would execute (not executed): %s", format_command(cmd))
        if check and not result.ok:
            raise FeraError(
                f"command failed with exit code {result.returncode}: {result.display}",
                code=ErrorCode.INTERNAL_ERROR,
                details=result.to_dict(),
            )
        return result

    def spawn(
        self,
        command: Sequence[Any],
        *,
        stdout_path: Path | str | None = None,
        stderr_path: Path | str | None = None,
    ) -> ProcessHandle:
        cmd = tuple(str(part) for part in command)
        self.spawned.append(cmd)
        logger.info("would start (not started): %s", format_command(cmd))
        if self._spawn_factory is not None:
            return self._spawn_factory(cmd)
        return ProcessHandle(cmd, None)


def run_command(
    command: Sequence[Any],
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
    check: bool = False,
    not_found_code: ErrorCode = ErrorCode.TOOL_NOT_AVAILABLE,
    cwd: Path | str | None = None,
) -> CommandResult:
    """Convenience wrapper that runs ``command`` via :class:`SubprocessRunner`."""
    return SubprocessRunner().run(
        command,
        timeout=timeout,
        check=check,
        not_found_code=not_found_code,
        cwd=cwd,
    )


__all__ = [
    "DEFAULT_TIMEOUT_S",
    "BaseRunner",
    "CommandResult",
    "ProcessHandle",
    "RecordingRunner",
    "SubprocessRunner",
    "format_command",
    "run_command",
]



