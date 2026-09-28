"""Structured errors and error codes for FERA.

Every failure mode that an operator (or a later pipeline stage) may need to
react to gets a machine readable :class:`ErrorCode`.  Codes are surfaced in
CLI output, execution logs and ground-truth metadata so all three speak the
same vocabulary.
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    """Machine readable failure codes."""

    OK = "OK"
    CONFIG_VALIDATION_FAILED = "CONFIG_VALIDATION_FAILED"
    UNSUPPORTED_ALGORITHM_COMBINATION = "UNSUPPORTED_ALGORITHM_COMBINATION"
    UNSUPPORTED_FEATURE = "UNSUPPORTED_FEATURE"
    EXPERIMENT_ALREADY_EXISTS = "EXPERIMENT_ALREADY_EXISTS"
    STRONGSWAN_NOT_INSTALLED = "STRONGSWAN_NOT_INSTALLED"
    SWANCTL_NOT_AVAILABLE = "SWANCTL_NOT_AVAILABLE"
    IPSEC_CONFIG_APPLY_FAILED = "IPSEC_CONFIG_APPLY_FAILED"
    IPSEC_INITIATION_FAILED = "IPSEC_INITIATION_FAILED"
    CAPTURE_TOOL_NOT_AVAILABLE = "CAPTURE_TOOL_NOT_AVAILABLE"
    CAPTURE_START_FAILED = "CAPTURE_START_FAILED"
    CAPTURE_EMPTY = "CAPTURE_EMPTY"
    CAPTURE_VALIDATION_FAILED = "CAPTURE_VALIDATION_FAILED"
    TRAFFIC_GENERATION_FAILED = "TRAFFIC_GENERATION_FAILED"
    IPV6_UNAVAILABLE = "IPV6_UNAVAILABLE"
    INSUFFICIENT_PRIVILEGES = "INSUFFICIENT_PRIVILEGES"
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    TOOL_NOT_AVAILABLE = "TOOL_NOT_AVAILABLE"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    TIMEOUT = "TIMEOUT"
    IO_ERROR = "IO_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class FeraError(Exception):
    """Base class for all FERA errors.

    The ``code`` attribute is a stable, machine readable identifier; ``hint``
    carries an actionable remediation hint; ``details`` carries structured
    context (command lines, exit codes, paths, ...) that is safe to log.
    """

    code: ErrorCode = ErrorCode.INTERNAL_ERROR

    def __init__(
        self,
        message: str,
        *,
        code: ErrorCode | None = None,
        hint: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        self.hint = hint
        self.details: dict[str, Any] = dict(details or {})

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON serialisable representation."""
        return {
            "code": self.code.value,
            "message": self.message,
            "hint": self.hint,
            "details": self.details,
        }

    def __str__(self) -> str:  # pragma: no cover - trivial
        base = f"[{self.code.value}] {self.message}"
        return f"{base} (hint: {self.hint})" if self.hint else base


class ConfigValidationError(FeraError):
    """An experiment configuration is invalid."""

    code = ErrorCode.CONFIG_VALIDATION_FAILED


class UnsupportedCombinationError(FeraError):
    """A requested combination of IPsec parameters cannot exist."""

    code = ErrorCode.UNSUPPORTED_ALGORITHM_COMBINATION


class ToolUnavailableError(FeraError):
    """A required external tool is not installed or not usable."""

    code = ErrorCode.TOOL_NOT_AVAILABLE


class PrivilegeError(FeraError):
    """The process lacks the privileges required for the requested action."""

    code = ErrorCode.INSUFFICIENT_PRIVILEGES


__all__ = [
    "ErrorCode",
    "FeraError",
    "ConfigValidationError",
    "UnsupportedCombinationError",
    "ToolUnavailableError",
    "PrivilegeError",
]
