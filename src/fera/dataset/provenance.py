"""Provenance: can this dataset be traced to the code and bytes that made it?

Two things a dataset needs and nothing here provided:

* **which source revision** produced it -- without the commit, a manifest cannot
  be traced to the code that generated it, and a result cannot be re-derived
  after the code changes;
* **whether the recorded capture hashes still hold** -- captures are hashed when
  a run finishes, but nothing ever re-checked them, so a replaced or truncated
  capture would still be reported as a valid sample.

Both are reported, never assumed: an unreadable revision or a missing file is
reported as unknown rather than silently treated as fine.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..common.paths import ProjectPaths

#: Schema identifier of one provenance document.
PROVENANCE_SCHEMA = "fera_provenance_v1"


def file_sha256(path: Path) -> str | None:
    """SHA-256 of a file, or ``None`` when it cannot be read.

    Streaming so a multi-gigabyte capture is not loaded into memory.
    """
    try:
        digest = hashlib.sha256()
        with Path(path).open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def source_revision(root: Path | str, runner: Any = None) -> dict[str, Any]:
    """Describe the git revision of the checkout, if there is one.

    Returns a mapping with ``known=False`` when git is unavailable or the tree is
    not a repository, rather than an empty string that reads like "revision 0".
    A dirty tree is reported explicitly: results from uncommitted changes are
    not reproducible from the commit alone.
    """
    import subprocess

    root_path = Path(root)

    def _git(*args: str) -> str | None:
        try:
            result = subprocess.run(  # noqa: S603 - fixed argv, no shell
                ["git", *args],
                cwd=root_path,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return result.stdout.strip() if result.returncode == 0 else None

    commit = _git("rev-parse", "HEAD")
    if not commit:
        return {"known": False, "commit": "", "branch": "", "dirty": False}
    status = _git("status", "--porcelain")
    return {
        "known": True,
        "commit": commit,
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD") or "",
        # Recorded because a dirty tree means the commit alone cannot reproduce
        # the results.
        "dirty": bool(status),
    }


@dataclass(frozen=True)
class VerificationReport:
    """Whether a dataset still matches what it claims to be."""

    checked: int = 0
    matched: int = 0
    mismatched: tuple[str, ...] = ()
    unhashed: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True only when every checkable capture still matches its hash."""
        return not self.mismatched and not self.missing

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PROVENANCE_SCHEMA,
            "checked": self.checked,
            "matched": self.matched,
            "mismatched": list(self.mismatched),
            "unhashed": list(self.unhashed),
            "missing": list(self.missing),
            "ok": self.ok,
            "notes": list(self.notes),
        }

    def render_text(self) -> str:
        lines = [
            f"captures checked : {self.checked}",
            f"  matched        : {self.matched}",
            f"  MISMATCHED     : {len(self.mismatched)}",
            f"  missing        : {len(self.missing)}",
            f"  no hash recorded: {len(self.unhashed)}",
            f"result: {'VERIFIED' if self.ok else 'NOT VERIFIED'}",
        ]
        for experiment_id in self.mismatched:
            lines.append(f"  changed : {experiment_id}")
        for experiment_id in self.missing:
            lines.append(f"  missing : {experiment_id}")
        for note in self.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)


def verify_manifest(
    manifest: Mapping[str, Any],
    paths: ProjectPaths,
) -> VerificationReport:
    """Re-hash every capture the manifest claims, and compare.

    A capture whose bytes no longer match its recorded SHA-256 is reported as
    *mismatched* rather than trusted: the manifest would otherwise keep
    advertising a valid sample for a file that has since been replaced.
    """
    checked = matched = 0
    mismatched: list[str] = []
    unhashed: list[str] = []
    missing: list[str] = []
    notes: list[str] = []
    for entry in manifest.get("samples") or ():
        if not isinstance(entry, Mapping):
            continue
        experiment_id = str(entry.get("experiment_id") or "")
        pcap_path = entry.get("pcap_path")
        recorded = str(entry.get("capture_sha256") or "")
        if not pcap_path:
            notes.append(f"{experiment_id or '<unknown>'}: no capture path in the manifest")
            continue
        checked += 1
        resolved = paths.resolve(str(pcap_path))
        if not resolved.is_file():
            missing.append(experiment_id)
            continue
        if not recorded:
            unhashed.append(experiment_id)
            continue
        actual = file_sha256(resolved)
        if actual == recorded:
            matched += 1
        else:
            mismatched.append(experiment_id)
    if unhashed:
        # Not a failure, but it is not verification either, and must not be
        # counted as a pass.
        notes.append(
            f"{len(unhashed)} capture(s) predate hash recording and cannot be verified"
        )
    return VerificationReport(
        checked=checked,
        matched=matched,
        mismatched=tuple(mismatched),
        unhashed=tuple(unhashed),
        missing=tuple(missing),
        notes=notes,
    )


def build_provenance(
    paths: ProjectPaths,
    manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """One document describing the code and bytes behind a dataset."""
    document: dict[str, Any] = {
        "schema": PROVENANCE_SCHEMA,
        "generated_at": _utc_now(),
        "source": source_revision(paths.root),
    }
    if manifest is not None:
        document["sample_count"] = int(manifest.get("sample_count") or 0)
        document["verification"] = verify_manifest(manifest, paths).to_dict()
    return document


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "PROVENANCE_SCHEMA",
    "VerificationReport",
    "build_provenance",
    "file_sha256",
    "source_revision",
    "verify_manifest",
]
