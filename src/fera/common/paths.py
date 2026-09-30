"""Repository path handling.

All FERA code uses :class:`pathlib.Path` and resolves locations through
:class:`ProjectPaths` instead of hard-coded, machine specific paths.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ErrorCode, FeraError

#: Markers used to locate the repository root when walking up from a file path.
ROOT_MARKERS = ("pyproject.toml", "requirements.txt", ".git")
#: Relative path that identifies a FERA source checkout.
PACKAGE_HINT = Path("src") / "fera"


def find_repo_root(start: Path | str | None = None) -> Path:
    """Return the repository root directory.

    The search walks upwards from ``start`` (default: this file) looking for a
    directory that contains :data:`PACKAGE_HINT` or one of :data:`ROOT_MARKERS`.
    As a last resort the current working directory is returned so an installed
    package still works.
    """
    candidate = Path(start).resolve() if start is not None else Path(__file__).resolve()
    current = candidate if candidate.is_dir() else candidate.parent
    for directory in (current, *current.parents):
        if (directory / PACKAGE_HINT).is_dir():
            return directory
        if any((directory / marker).exists() for marker in ROOT_MARKERS):
            return directory
    return Path.cwd()


@dataclass(frozen=True)
class ProjectPaths:
    """Layout of the FERA repository."""

    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root).resolve())

    # -- top level -----------------------------------------------------
    @property
    def src(self) -> Path:
        return self.root / "src"

    @property
    def package(self) -> Path:
        return self.src / "fera"

    @property
    def configs(self) -> Path:
        return self.root / "configs"

    @property
    def experiments_dir(self) -> Path:
        return self.configs / "experiments"

    @property
    def templates_dir(self) -> Path:
        return self.configs / "templates"

    @property
    def topology_file(self) -> Path:
        return self.templates_dir / "testbed_topology.yaml"

    @property
    def traffic_profiles_file(self) -> Path:
        return self.templates_dir / "traffic_profiles.yaml"

    @property
    def scripts(self) -> Path:
        return self.root / "scripts"

    @property
    def tests(self) -> Path:
        return self.root / "tests"

    @property
    def docs(self) -> Path:
        return self.root / "docs"

    # -- data ----------------------------------------------------------
    @property
    def data(self) -> Path:
        return self.root / "data"

    @property
    def raw(self) -> Path:
        return self.data / "raw"

    @property
    def processed(self) -> Path:
        return self.data / "processed"

    @property
    def manifests(self) -> Path:
        return self.data / "manifests"

    @property
    def default_manifest_file(self) -> Path:
        return self.manifests / "dataset.json"

    @property
    def environment_report_file(self) -> Path:
        return self.manifests / "environment.json"

    @property
    def logs(self) -> Path:
        return self.data / "logs"

    @property
    def bundles(self) -> Path:
        """Archive of completed analysis bundles (the product history)."""
        return self.data / "bundles"

    @property
    def uploads(self) -> Path:
        """Staging area for captures uploaded through the API."""
        return self.data / "uploads"

    @property
    def models(self) -> Path:
        """Directory searched for operator-trained traffic classifier artefacts."""
        return self.data / "models"

    # -- helpers ---------------------------------------------------------
    def ensure_runtime_dirs(self) -> None:
        """Create the directories the pipeline writes to."""
        for directory in (
            self.raw,
            self.processed,
            self.manifests,
            self.logs,
            self.bundles,
            self.uploads,
            self.experiments_dir,
            self.templates_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    def experiment_dir(self, experiment_id: str) -> Path:
        """Directory that holds all artefacts of one experiment run."""
        return self.raw / experiment_id

    def experiment_config_path(self, experiment_id: str) -> Path:
        """Path of the generated experiment definition."""
        return self.experiments_dir / f"{experiment_id}.yaml"

    def relative(self, path: Path | str) -> str:
        """Return a portable, POSIX style path relative to the repository root."""
        candidate = Path(path)
        try:
            resolved = candidate.resolve()
        except OSError:  # pragma: no cover - defensive
            resolved = candidate
        bases = (self.root, Path.cwd().resolve())
        for base in bases:
            try:
                return resolved.relative_to(base).as_posix()
            except ValueError:
                continue
        return resolved.as_posix()

    def resolve(self, path: str | Path) -> Path:
        """Resolve ``path`` relative to the repository root when it is relative."""
        candidate = Path(path)
        return candidate if candidate.is_absolute() else (self.root / candidate)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "configs": self.relative(self.configs),
            "experiments": self.relative(self.experiments_dir),
            "templates": self.relative(self.templates_dir),
            "data_raw": self.relative(self.raw),
            "data_processed": self.relative(self.processed),
            "data_manifests": self.relative(self.manifests),
            "docs": self.relative(self.docs),
        }

    def require_file(self, path: Path | str, *, description: str = "file") -> Path:
        """Return ``path`` if it exists, otherwise raise :class:`FeraError`."""
        candidate = Path(path)
        if not candidate.is_file():
            raise FeraError(
                f"{description} not found: {candidate}",
                code=ErrorCode.IO_ERROR,
                hint="check the path or run the generator script first",
                details={"path": str(candidate)},
            )
        return candidate


def default_paths(start: Path | str | None = None) -> ProjectPaths:
    """Return :class:`ProjectPaths` for the repository containing ``start``."""
    env_root = os.environ.get("FERA_ROOT")
    root = Path(env_root) if env_root else find_repo_root(start)
    return ProjectPaths(root)


__all__ = ["PACKAGE_HINT", "ROOT_MARKERS", "ProjectPaths", "default_paths", "find_repo_root"]

