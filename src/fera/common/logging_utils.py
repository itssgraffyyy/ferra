"""Logging helpers for FERA.

Rules enforced here:

* core modules use :func:`get_logger` instead of ``print``;
* every experiment run attaches a file handler, so the execution log explains
  what happened even if the console output is lost;
* secrets (testbed PSK, private keys) are registered with
  :func:`register_secret` and are automatically redacted from every record.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

LOGGER_NAME = "fera"
REDACTION_PLACEHOLDER = "***REDACTED***"
DEFAULT_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

_secrets: set[str] = set()
_configured = False


def register_secret(value: str | None, *, min_length: int = 4) -> None:
    """Register a secret string that must never appear in logs."""
    if not value or len(value) < min_length:
        return
    _secrets.add(value)


def clear_registered_secrets() -> None:
    """Forget all registered secrets (used by tests)."""
    _secrets.clear()


def redact(text: str) -> str:
    """Replace every registered secret in ``text`` by a placeholder."""
    if not text or not _secrets:
        return text
    redacted = text
    for secret in _secrets:
        if secret in redacted:
            redacted = redacted.replace(secret, REDACTION_PLACEHOLDER)
    return redacted


class SecretRedactingFilter(logging.Filter):
    """Redact registered secrets from log records."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 - stdlib API
        if not _secrets:
            return True
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        if any(secret in message for secret in _secrets):
            record.msg = redact(message)
            record.args = ()
        return True


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger inside the ``fera`` namespace."""
    if not name or name == LOGGER_NAME:
        return logging.getLogger(LOGGER_NAME)
    if name.startswith(f"{LOGGER_NAME}."):
        return logging.getLogger(name)
    short = name.split(".")[-1] if name.startswith("__") else name
    return logging.getLogger(f"{LOGGER_NAME}.{short}")


def _coerce_level(level: str | int) -> int:
    if isinstance(level, int):
        return level
    name = str(level).upper()
    if hasattr(logging, "getLevelNamesMapping"):
        return logging.getLevelNamesMapping().get(name, logging.INFO)
    mapping = {
        "CRITICAL": logging.CRITICAL,
        "FATAL": logging.FATAL,
        "ERROR": logging.ERROR,
        "WARN": logging.WARNING,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
        "NOTSET": logging.NOTSET,
    }
    return mapping.get(name, logging.INFO)


def _build_formatter() -> logging.Formatter:
    return logging.Formatter(fmt=DEFAULT_FORMAT, datefmt=DATE_FORMAT)


def configure_logging(
    level: str | int = logging.INFO,
    *,
    log_file: Path | None = None,
    stream: bool = True,
    force: bool = False,
) -> logging.Logger:
    """Configure the ``fera`` root logger once and return it.

    ``log_file`` adds (or replaces) a file handler so that every experiment run
    keeps its own execution log.
    """
    global _configured
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(min(_coerce_level(level), logging.DEBUG))
    logger.propagate = False
    redacting = SecretRedactingFilter()

    if force:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()
        _configured = False

    if not _configured:
        if stream:
            stream_handler = logging.StreamHandler(stream=sys.stderr)
            stream_handler.setFormatter(_build_formatter())
            stream_handler.addFilter(redacting)
            logger.addHandler(stream_handler)
        _configured = True

    if log_file is not None:
        add_file_handler(log_file, level=level)

    for handler in logger.handlers:
        handler.setLevel(min(_coerce_level(level), logging.DEBUG) if log_file is None else handler.level)
    return logger


def add_file_handler(path: Path, *, level: str | int | None = None, append: bool = True) -> logging.FileHandler:
    """Attach a file handler for ``path`` (creating parent directories)."""
    logger = logging.getLogger(LOGGER_NAME)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, mode="a" if append else "w", encoding="utf-8")
    handler.setFormatter(_build_formatter())
    handler.setLevel(_coerce_level(level) if level is not None else logging.DEBUG)
    handler.addFilter(SecretRedactingFilter())
    logger.addHandler(handler)
    return handler


def remove_handler(handler: logging.Handler | None) -> None:
    """Detach and close a handler previously added by this module."""
    if handler is None:
        return
    logger = logging.getLogger(LOGGER_NAME)
    logger.removeHandler(handler)
    try:
        handler.close()
    except Exception:  # pragma: no cover - defensive
        pass


def log_command(logger: logging.Logger, command: Sequence[Any], *, level: int = logging.DEBUG, prefix: str = "exec") -> None:
    """Log a command line (redacted, display only) without executing it."""
    from .process import format_command

    logger.log(level, "%s: %s", prefix, format_command(command))


__all__ = [
    "LOGGER_NAME",
    "REDACTION_PLACEHOLDER",
    "SecretRedactingFilter",
    "add_file_handler",
    "clear_registered_secrets",
    "configure_logging",
    "get_logger",
    "log_command",
    "redact",
    "register_secret",
    "remove_handler",
]
