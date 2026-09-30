"""Dev smoke: run the whole pipeline over a synthetic capture, then reload it.

Covers what no unit test covers cheaply: that the stages compose, that the bundle
survives a JSON round trip, and that input validation rejects what it should.

    python scripts/pipeline_smoke.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from analysis_smoke import build  # noqa: E402

from fera.common.errors import ErrorCode, FeraError  # noqa: E402
from fera.core.bundle import AnalysisBundle  # noqa: E402
from fera.core.orchestrator import CaptureSource, run_analysis  # noqa: E402

CONFIGURED = {
    "encryption": "AES_CBC",
    "integrity": "HMAC_SHA1_96",
    "prf": "PRF_HMAC_SHA1",
    "dh_group": 19,
    "pfs": True,
    "ike_version": 2,
    "replay_protection": True,
    "source": "pipeline smoke",
}


def report(bundle: AnalysisBundle) -> None:
    print(f"analysis_id: {bundle.analysis_id}")
    for name in ("protocol", "traffic", "security", "privacy"):
        stage = bundle.stages.get(name)
        detail = "" if stage is None else f" status={stage.status.value} ms={stage.duration_ms}"
        error = "" if stage is None or stage.error is None else f" error={stage.error.get('message')}"
        print(f"  stage {name:<9}{detail}{error}")
    print(f"  overall: {bundle.status}")
    print("  summary:", json.dumps(bundle.summary(), sort_keys=True))


def check_validation(capture: Path) -> None:
    """Every rejection path must carry a specific, actionable error code."""
    wrong = capture.parent / "not-a-capture.pcap"
    wrong.write_bytes(b"hello, world, definitely not a pcap file")
    cases = [
        ("missing file", CaptureSource.from_path(capture.parent / "nope.pcap"), ErrorCode.NOT_FOUND),
        ("wrong format", CaptureSource.from_path(wrong), ErrorCode.UNSUPPORTED_CONTENT),
        ("oversize", CaptureSource.from_path(capture, kind="upload", max_bytes=64), ErrorCode.PAYLOAD_TOO_LARGE),
    ]
    for label, source, expected in cases:
        try:
            source.validate()
        except FeraError as exc:
            flag = "ok" if exc.code is expected else "MISMATCH"
            print(f"  {label:<13} -> {exc.code.value} ({flag})")
        else:
            print(f"  {label:<13} -> accepted (MISMATCH, expected {expected.value})")


def main() -> int:
    capture = build(ROOT / "data" / "tmp" / "smoke_ipsec.pcap")
    print(f"capture: {capture.name} ({capture.stat().st_size} bytes)")
    bundle = run_analysis(
        CaptureSource.from_path(capture, kind="upload"),
        configured=CONFIGURED,
        persist=True,
    )
    report(bundle)

    written = Path(bundle.provenance.get("bundle_path", ""))
    restored = AnalysisBundle.from_dict(json.loads(written.read_text(encoding="utf-8")))
    print(f"reloaded from {written.name}: summary matches = {restored.summary() == bundle.summary()}")

    print("validation:")
    check_validation(capture)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
