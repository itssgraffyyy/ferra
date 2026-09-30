"""Dev smoke: exercise the HTTP API against the synthetic capture.

Checks the contract the UI depends on: health reports model availability, an
upload returns a full bundle even when a stage is unavailable, retrieval works,
and bad input gets the right status code instead of a stack trace.

    python scripts/api_smoke.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from fastapi.testclient import TestClient  # noqa: E402

from analysis_smoke import build  # noqa: E402
from fera.api.main import create_app  # noqa: E402

CAPTURE = ROOT / "data" / "tmp" / "smoke_ipsec.pcap"


def show(label: str, response: object, expected: int) -> dict:
    """Print one exchange and return its JSON body."""
    assert isinstance(response.status_code, int)
    flag = "ok" if response.status_code == expected else f"EXPECTED {expected}"
    print(f"{label:<34} {response.status_code:>3}  {flag}")
    try:
        return response.json()
    except json.JSONDecodeError:  # pragma: no cover - the API is JSON only
        return {}


def main() -> int:
    build(CAPTURE)
    client = TestClient(create_app())

    health = show("GET /health", client.get("/health"), 200)
    print("   model available:", health["analysis"]["model_available"], "|", health["analysis"]["model_reason"])

    with CAPTURE.open("rb") as handle:
        upload = show(
            "POST /analyze (pcap + configured)",
            client.post(
                "/analyze",
                files={"file": (CAPTURE.name, handle, "application/vnd.tcpdump.pcap")},
                data={"configured": json.dumps({"encryption": "AES_CBC", "dh_group": 19, "pfs": True})},
            ),
            200,
        )
    components = upload.get("components", {})
    print("   status:", upload.get("status"), "|", {k: v.get("status") for k, v in components.items()})
    security = components.get("security", {}).get("data", {})
    privacy = components.get("privacy", {}).get("data", {})
    print(
        "   security:",
        security.get("security_score"),
        security.get("risk_level"),
        "| coverage:",
        security.get("evidence_coverage"),
        "| privacy risk:",
        privacy.get("privacy_risk"),
    )
    analysis_id = str(upload.get("analysis_id"))

    show("GET /analyses/{id}", client.get(f"/analyses/{analysis_id}"), 200)
    show("GET /analyses/{id} (missing)", client.get("/analyses/deadbeef"), 404)

    show("POST /analyze (not a pcap)", client.post("/analyze", files={"file": ("x.pcap", b"nope", "")}), 415)
    show("POST /analyze (no file part)", client.post("/analyze", data={}), 422)
    show(
        "POST /analyze (configured not JSON)",
        client.post("/analyze", files={"file": (CAPTURE.name, CAPTURE.read_bytes(), "")}, data={"configured": "nope"}),
        422,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
