"""YAML/JSON serialisation helpers.

YAML is the preferred on-disk format for experiment definitions because it is
human readable and diff friendly.  PyYAML is a hard dependency for that reason
(:mod:`requirements`) - but if a constrained environment cannot install it,
:func:`load_yaml` raises an explicit :class:`FeraError` instead of silently
misbehaving, and JSON remains available as a fully functional fallback format.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import ErrorCode, FeraError

try:  # pragma: no cover - exercised implicitly by the environment
    import yaml

    PYYAML_AVAILABLE = True
except Exception:  # noqa: BLE001 - optional at import time
    yaml = None  # type: ignore[assignment]
    PYYAML_AVAILABLE = False


def _require_yaml() -> Any:
    if not PYYAML_AVAILABLE:
        raise FeraError(
            "PyYAML is not installed, cannot read or write YAML files",
            code=ErrorCode.DEPENDENCY_MISSING,
            hint="python -m pip install pyyaml   (or use .json experiment files)",
            details={"module": "yaml"},
        )
    return yaml


def load_yaml(path: Path | str) -> Any:
    """Load a YAML document from ``path``."""
    module = _require_yaml()
    candidate = Path(path)
    if not candidate.is_file():
        raise FeraError(
            f"file not found: {candidate}",
            code=ErrorCode.IO_ERROR,
            details={"path": str(candidate)},
        )
    try:
        with candidate.open("r", encoding="utf-8") as handle:
            return module.safe_load(handle)
    except Exception as exc:  # noqa: BLE001 - yaml raises several types
        raise FeraError(
            f"invalid YAML in {candidate}: {exc}",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            details={"path": str(candidate)},
        ) from exc


def dump_yaml(data: Any, *, sort_keys: bool = False) -> str:
    """Serialise ``data`` to a YAML string (block style, no anchors)."""
    module = _require_yaml()
    return module.safe_dump(data, sort_keys=sort_keys, default_flow_style=False, allow_unicode=True)


def write_yaml(path: Path | str, data: Any, *, sort_keys: bool = False) -> Path:
    """Write ``data`` to ``path`` as YAML, creating parent directories."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dump_yaml(data, sort_keys=sort_keys), encoding="utf-8", newline="\n")
    return target


def load_json(path: Path | str) -> Any:
    """Load a JSON document from ``path``."""
    candidate = Path(path)
    if not candidate.is_file():
        raise FeraError(
            f"file not found: {candidate}",
            code=ErrorCode.IO_ERROR,
            details={"path": str(candidate)},
        )
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FeraError(
            f"invalid JSON in {candidate}: {exc}",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            details={"path": str(candidate)},
        ) from exc


def write_json(path: Path | str, data: Any, *, indent: int = 2) -> Path:
    """Write ``data`` to ``path`` as JSON, creating parent directories."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(data, indent=indent, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return target


def load_document(path: Path | str) -> Any:
    """Load a YAML or JSON document based on the file suffix."""
    candidate = Path(path)
    if candidate.suffix.lower() in {".json"}:
        return load_json(candidate)
    return load_yaml(candidate)


def write_document(path: Path | str, data: Any) -> Path:
    """Write a YAML or JSON document based on the file suffix."""
    candidate = Path(path)
    if candidate.suffix.lower() == ".json":
        return write_json(candidate, data)
    return write_yaml(candidate, data)


def write_text_file(path: Path | str, text: str) -> Path:
    """Write ``text`` with explicit LF newlines (Linux friendly scripts)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")
    return target


__all__ = [
    "PYYAML_AVAILABLE",
    "dump_yaml",
    "load_document",
    "load_json",
    "load_yaml",
    "write_document",
    "write_json",
    "write_text_file",
    "write_yaml",
]
