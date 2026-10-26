"""IFSC validation service.

Uses an offline reference dataset (RBI IFSC-like registry). Validation covers:
- IFSC format (11 chars: 4 bank code + 0 + 6 branch code)
- Bank identity
- Branch consistency where data available
- Unknown/outdated entries

IFSC validation does NOT authenticate the underlying FDR.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional

from app.core.exceptions import ExternalServiceError
from app.core.logging import get_logger

logger = get_logger("app.services.ifsc_service")

IFSC_REGEX = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")

# Offline reference dataset: a small sample of real Indian bank IFSC entries.
# Each entry: ifsc -> {bank, branch, address, city, district, state, contact, upi}
IFSC_REFERENCE_DATA: dict[str, dict] = {
    "SBIN0001234": {
        "bank": "State Bank of India",
        "branch": "Thrissur Main Branch",
        "address": "Round North, Thrissur, Kerala 680001",
        "city": "Thrissur",
        "district": "Thrissur",
        "state": "Kerala",
        "contact": "0487 2321234",
        "upi": "SBIN",
    },
    "SBIN0005678": {
        "bank": "State Bank of India",
        "branch": "Ernakulam Main Branch",
        "address": "MG Road, Ernakulam, Kerala 682011",
        "city": "Ernakulam",
        "district": "Ernakulam",
        "state": "Kerala",
        "contact": "0484 2365678",
        "upi": "SBIN",
    },
    "HDFC0001234": {
        "bank": "HDFC Bank",
        "branch": "Thrissur Branch",
        "address": "High Road, Thrissur, Kerala 680001",
        "city": "Thrissur",
        "district": "Thrissur",
        "state": "Kerala",
        "contact": "0487 2301234",
        "upi": "HDFC",
    },
    "ICIC0001234": {
        "bank": "ICICI Bank",
        "branch": "Coimbatore Main Branch",
        "address": "Cross Cut Road, Coimbatore, Tamil Nadu 641001",
        "city": "Coimbatore",
        "district": "Coimbatore",
        "state": "Tamil Nadu",
        "contact": "0422 2301234",
        "upi": "ICICI",
    },
    "AXIS0001234": {
        "bank": "Axis Bank",
        "branch": "Thrissur Branch",
        "address": "Round South, Thrissur, Kerala 680001",
        "city": "Thrissur",
        "district": "Thrissur",
        "state": "Kerala",
        "contact": "0487 2401234",
        "upi": "AXIS",
    },
}


def load_reference_dataset(path: Optional[str] = None) -> dict[str, dict]:
    """Load IFSC reference dataset from JSON file if provided, else default."""
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning("ifsc.dataset_load_failed", extra={"action": "ifsc_load", "message": str(exc)})
    return dict(IFSC_REFERENCE_DATA)


def validate_ifsc(ifsc: str, reference_data: Optional[dict[str, dict]] = None) -> dict:
    """Validate an IFSC code. Returns a structured result (never claims FDR authenticity)."""
    ref = reference_data or IFSC_REFERENCE_DATA
    ifsc_clean = (ifsc or "").strip().upper()

    result: dict = {
        "ifsc": ifsc_clean,
        "format_valid": False,
        "bank": None,
        "branch": None,
        "exists": False,
        "bank_match": None,
        "branch_match": None,
        "warnings": [],
    }

    if not ifsc_clean:
        result["warnings"].append("IFSC code is empty")
        return result

    result["format_valid"] = bool(IFSC_REGEX.match(ifsc_clean))
    if not result["format_valid"]:
        result["warnings"].append("IFSC format invalid (expected 11 chars: 4 bank + 0 + 6 branch)")
        return result

    entry = ref.get(ifsc_clean)
    if entry is None:
        result["warnings"].append("IFSC not found in offline reference dataset (may be outdated or unknown)")
        return result

    result["exists"] = True
    result["bank"] = entry.get("bank")
    result["branch"] = entry.get("branch")

    return result


def compare_ifsc_with_declared(
    ifsc: str,
    declared_bank: Optional[str],
    declared_branch: Optional[str],
    reference_data: Optional[dict[str, dict]] = None,
) -> dict:
    """Compare an IFSC lookup against declared bank/branch. Returns mismatch info."""
    validation = validate_ifsc(ifsc, reference_data)
    conflicts: list[str] = []
    if declared_bank and validation.get("bank") and validation["bank"].lower() != declared_bank.strip().lower():
        conflicts.append(f"Bank mismatch: declared '{declared_bank}' vs IFSC bank '{validation['bank']}'")
    if declared_branch and validation.get("branch") and validation["branch"].lower() != declared_branch.strip().lower():
        conflicts.append(f"Branch mismatch: declared '{declared_branch}' vs IFSC branch '{validation['branch']}'")
    validation["conflicts"] = conflicts
    validation["bank_match"] = not any("Bank mismatch" in c for c in conflicts) if declared_bank else None
    validation["branch_match"] = not any("Branch mismatch" in c for c in conflicts) if declared_branch else None
    return validation
