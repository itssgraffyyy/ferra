"""Deterministic report generation from the canonical analysis bundle.

Three artefacts, all rendered from *one* input - the bundle:

* an **executive** report for a decision maker (score, risk, top findings,
  top recommendations, and the honest list of what could not be verified);
* a **technical** report for an analyst (the full section set, every finding
  with its evidence, the threat matrix, the traffic prediction);
* a **raw JSON** export, which is simply the bundle document;
* a **PDF** rendering of either human-readable report (optional dependency).

The rule this module exists to enforce: **reports never re-analyse anything**.
There is no tshark call, no feature extraction, no scoring and no model
inference here.  Every number, verdict and evidence status is read out of the
bundle the stages already produced, so a report can never contain evidence the
analysis bundle does not have, and it can never turn a ``NOT_VERIFIABLE`` into a
failure.  Regenerating a report from the same bundle is byte-for-byte
reproducible apart from the generation timestamp.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from ..common.errors import ErrorCode, FeraError

#: Report types the product can produce.
EXECUTIVE = "executive"
TECHNICAL = "technical"
JSON = "json"
PDF = "pdf"

#: Every report type, in the order the API documents them.
REPORT_TYPES: tuple[str, ...] = (EXECUTIVE, TECHNICAL, JSON, PDF)

#: Content type per report type.
CONTENT_TYPES: dict[str, str] = {
    EXECUTIVE: "text/html; charset=utf-8",
    TECHNICAL: "text/html; charset=utf-8",
    JSON: "application/json",
    PDF: "application/pdf",
}

#: File suffix per report type.
SUFFIXES: dict[str, str] = {EXECUTIVE: "html", TECHNICAL: "html", JSON: "json", PDF: "pdf"}


def normalise_report_type(report_type: str | None) -> str:
    """Return a supported report type, or raise a validation error."""
    candidate = str(report_type or EXECUTIVE).strip().lower()
    if candidate not in REPORT_TYPES:
        raise FeraError(
            f"unknown report type {candidate!r}",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            hint=f"use one of: {', '.join(REPORT_TYPES)}",
            details={"requested": candidate, "supported": list(REPORT_TYPES)},
        )
    return candidate


def report_filename(analysis_id: str, report_type: str) -> str:
    """Return the download filename for one report.

    The analysis id is sanitised before it is placed in a filename: an id that
    arrived from a URL must never be able to introduce a path separator or a
    drive letter into a response header.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(analysis_id)).strip("._-") or "analysis"
    kind = normalise_report_type(report_type)
    if kind == JSON:
        return f"fera_{safe}.json"
    return f"fera_{safe}_{kind}.{SUFFIXES[kind]}"


def render_report(bundle: Mapping[str, Any], report_type: str, *, generated_at: str) -> bytes:
    """Render ``bundle`` into the bytes of the requested report.

    ``generated_at`` is passed in rather than read from the clock so the caller
    controls the one timestamp that legitimately differs between two renders of
    the same bundle.
    """
    kind = normalise_report_type(report_type)
    if kind == JSON:
        return (json.dumps(dict(bundle), indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if kind == PDF:
        from .pdf import to_pdf

        return to_pdf(dict(bundle), report_type=TECHNICAL, generated_at=generated_at)
    from .executive import build_executive
    from .technical import build_technical

    builder = build_executive if kind == EXECUTIVE else build_technical
    return builder(bundle, generated_at=generated_at).encode("utf-8")


__all__ = [
    "CONTENT_TYPES",
    "EXECUTIVE",
    "JSON",
    "PDF",
    "REPORT_TYPES",
    "SUFFIXES",
    "TECHNICAL",
    "component_data",
    "component_status",
    "coverage_value",
    "normalise_report_type",
    "render_report",
    "report_filename",
]



def _text(value: Any, default: str = "not reported") -> str:
    """Render a possibly-absent value without inventing one.

    ``None`` becomes an explicit "not reported" rather than a blank cell, so a
    reader can tell the difference between "the value is zero" and "the stage
    never produced this".
    """
    if value is None or value == "":
        return default
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    return str(value)


def _percent(value: Any) -> str:
    """Render a 0..1 ratio as a percentage, or say it is unknown."""
    if value is None:
        return "not reported"
    try:
        return f"{float(value) * 100:.0f}%"
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return str(value)


def _mapping(value: Any) -> dict[str, Any]:
    """Return ``value`` when it is a mapping, otherwise an empty dict."""
    return dict(value) if isinstance(value, Mapping) else {}


def coverage_value(security: Mapping[str, Any]) -> Any:
    """Return the evidence coverage ratio.

    The assessment emits a plain 0..1 float; older documents nested it under
    ``{"value": ...}``.  Both are accepted so a stored bundle keeps rendering.
    """
    raw = security.get("evidence_coverage")
    if isinstance(raw, Mapping):
        return raw.get("value")
    return raw


def component_data(bundle: Mapping[str, Any], name: str) -> dict[str, Any]:
    """Return one component's payload from a serialised bundle.

    A bundle stores each stage as ``components.<name> = {status, data, error,
    duration_ms, limitations}``.  Reports want the payload, so they go through
    this helper rather than reaching into the document themselves - it keeps the
    nesting in one place and returns ``{}`` for a stage that never ran, which
    every report section already renders as "not reported".
    """
    entry = _mapping(_mapping(_mapping(bundle).get("components")).get(name))
    return _mapping(entry.get("data"))


def component_status(bundle: Mapping[str, Any], name: str) -> str | None:
    """Return one component's status string, or ``None`` when it is absent."""
    entry = _mapping(_mapping(_mapping(bundle).get("components")).get(name))
    status = entry.get("status")
    return str(status) if status else None


def _sequence(value: Any) -> list[Any]:
    """Return ``value`` as a list, treating anything else as empty."""
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return list(value)
    return []


def _esc(value: Any) -> str:
    """HTML-escape a value.

    Report input is derived from capture content and file names, both of which
    can contain ``<`` and ``&``; escaping keeps a crafted file name from
    injecting markup into a document that gets opened in a browser.
    """
    import html

    return html.escape(_text(value, ""), quote=True)
