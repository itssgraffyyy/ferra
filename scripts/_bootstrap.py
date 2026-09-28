"""Shared bootstrap for the ``scripts/`` CLI entry points.

Ensures the repository's ``src`` directory is importable (so the scripts work
from a plain checkout without installing the package) and provides small
helpers for logging and result printing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

#: Repository root (``scripts/`` lives directly inside it).
REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def bootstrap_logging(level: str = "INFO") -> None:  # noqa: D103 - tiny helper
    from fera.common.logging_utils import configure_logging

    configure_logging(level)


def print_section(title: str) -> None:  # noqa: D103
    print()
    print(title)
    print("=" * len(title))


def print_json(data: Any) -> None:  # noqa: D103
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def write_json_output(path: str | Path, data: Any) -> Path:  # noqa: D103
    from fera.common.serialization import write_json

    return write_json(Path(path), data)


__all__ = [
    "REPO_ROOT",
    "SRC_DIR",
    "bootstrap_logging",
    "print_json",
    "print_section",
    "write_json_output",
]
