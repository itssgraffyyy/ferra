"""Shared building blocks: errors, logging, paths, processes, versions."""

from __future__ import annotations

from .errors import (
    ConfigValidationError,
    ErrorCode,
    FeraError,
    PrivilegeError,
    ToolUnavailableError,
    UnsupportedCombinationError,
)
from .logging_utils import (
    add_file_handler,
    configure_logging,
    get_logger,
    redact,
    register_secret,
    remove_handler,
)
from .paths import ProjectPaths, default_paths, find_repo_root
from .process import (
    BaseRunner,
    CommandResult,
    ProcessHandle,
    RecordingRunner,
    SubprocessRunner,
    format_command,
    run_command,
)
from .versions import (
    collect_tool_versions,
    parse_version,
    platform_summary,
    python_version,
    tool_availability,
    tool_version,
)

__all__ = [
    "BaseRunner",
    "CommandResult",
    "ConfigValidationError",
    "ErrorCode",
    "FeraError",
    "PrivilegeError",
    "ProcessHandle",
    "ProjectPaths",
    "RecordingRunner",
    "SubprocessRunner",
    "ToolUnavailableError",
    "UnsupportedCombinationError",
    "add_file_handler",
    "collect_tool_versions",
    "configure_logging",
    "default_paths",
    "find_repo_root",
    "format_command",
    "get_logger",
    "parse_version",
    "platform_summary",
    "python_version",
    "redact",
    "register_secret",
    "remove_handler",
    "run_command",
    "tool_availability",
    "tool_version",
]
