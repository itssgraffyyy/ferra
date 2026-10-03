#!/usr/bin/env python3
"""Verify a dataset: which code produced it, and do its captures still match?

    python scripts/verify_dataset.py
    python scripts/verify_dataset.py --manifest data/manifests/dataset.json
    python scripts/verify_dataset.py --json

Reports the source revision (with a dirty-tree flag) and re-hashes every capture
the manifest lists.  A capture whose bytes no longer match its recorded SHA-256 is
reported as changed, not trusted -- a manifest would otherwise keep advertising
a valid sample for a file that has since been replaced.

Exit status is non-zero when anything fails to verify, so this can gate a
pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import _bootstrap  # noqa: E402
from fera.common.errors import FeraError  # noqa: E402
from fera.common.paths import default_paths  # noqa: E402
from fera.dataset.provenance import build_provenance, verify_manifest  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify dataset provenance: source revision and capture hashes."
    )
    parser.add_argument("--manifest", default=None, help="dataset manifest (default: data/manifests/dataset.json)")
    parser.add_argument("--json", nargs="?", const="", default=None, help="write the report as JSON")
    parser.add_argument("--log-level", default="WARNING")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap.bootstrap_logging(args.log_level)
    paths = default_paths()
    target = Path(args.manifest) if args.manifest else paths.default_manifest_file

    if not target.is_file():
        print(f"manifest not found: {target}", file=sys.stderr)
        print("build one with: python scripts/build_manifest.py", file=sys.stderr)
        return 2

    try:
        manifest = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"could not read the manifest: {error}", file=sys.stderr)
        return 2

    report = verify_manifest(manifest, paths)
    document = build_provenance(paths, manifest)

    print("FERA dataset provenance")
    print("=" * 22)
    source = document.get("source") or {}
    if source.get("known"):
        state = "dirty" if source.get("dirty") else "clean"
        print(f"source commit : {source.get('commit')} ({source.get('branch')}, {state})")
        if source.get("dirty"):
            # A dirty tree cannot be reproduced from the commit alone.
            print("  note: uncommitted changes; the commit alone will not reproduce this")
    else:
        print("source commit : unknown (not a git checkout)")
    print()
    print(report.render_text())

    if args.json is not None:
        out = Path(args.json) if args.json else paths.manifests / "provenance.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        print(f"\nprovenance written to {out}")

    return 0 if report.ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FeraError as error:  # pragma: no cover - surfaced as a clean message
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
