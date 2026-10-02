"""Build the executive report: a one-page summary for a decision maker.

Deliberately short.  A reader who is not a protocol engineer should get the
posture, the score, the material findings and the actions from one page, with
the uncertainty stated rather than buried.  Packet-level detail belongs in the
technical report and is not repeated here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from . import _mapping, _percent, _sequence, _text, component_data, coverage_value
from .render import _document, _esc, _table

#: How many findings and recommendations the executive page lists before it
#: defers to the technical report.
MAX_FINDINGS = 8
MAX_RECOMMENDATIONS = 6

#: Weakness statuses worth a decision maker's attention, worst first.
_STATUS_ORDER: tuple[str, ...] = ("FAIL", "WARNING", "NOT_VERIFIABLE", "PASS")

#: Severity names ranked worst first.
_SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _status_rank(item: Mapping[str, Any]) -> int:
    """Rank finding statuses so weaknesses surface above passing checks."""
    status = str(item.get("status", "")).upper()
    return _STATUS_ORDER.index(status) if status in _STATUS_ORDER else len(_STATUS_ORDER)


def _severity_rank(item: Mapping[str, Any]) -> int:
    """Sort findings worst-first using the backend's own severity names."""
    severity = str(item.get("severity", "")).upper()
    return _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else len(_SEVERITY_ORDER)


def _ordered_findings(security: Mapping[str, Any]) -> list[dict[str, Any]]:
    """All findings, weaknesses first and worst first within each group."""
    findings = [_mapping(item) for item in _sequence(security.get("findings"))]
    return sorted(findings, key=lambda item: (_status_rank(item), _severity_rank(item), str(item.get("title", ""))))


def _assessed(security: Mapping[str, Any], needle: str) -> dict[str, Any]:
    """Return the assessment's own verdict for a named property.

    The built-in pcap scanner sees ESP and SPI structure but not a negotiated
    cipher, so several posture facts only exist as security findings.  Pulling
    them from there (rather than inferring them) is what keeps the executive
    page from claiming a cipher the capture never carried.
    """
    for item in _sequence(security.get("findings")):
        candidate = _mapping(item)
        haystack = f"{candidate.get('rule_id', '')} {candidate.get('title', '')}".lower()
        if needle in haystack:
            return candidate
    return {}


def _status_word(finding: Mapping[str, Any], fallback: str = "not reported") -> str:
    """Render an assessed property as its verdict, or the fallback."""
    if not finding:
        return fallback
    status = str(finding.get("status", "")).upper()
    return status if status else fallback


def _overview_section(bundle: Mapping[str, Any], protocol: Mapping[str, Any], security: Mapping[str, Any]) -> list[str]:
    """The at-a-glance posture table.

    Values come from the protocol payload where the capture carries them and
    from the security findings where only the assessment could judge them; a
    property that is neither observed nor assessable is shown as NOT VERIFIABLE
    rather than as a pass.
    """
    risk = str(security.get("risk_level") or "NOT_REPORTED")
    scan = _mapping(_mapping(protocol.get("details")).get("scan"))
    pfs_status = str(_mapping(protocol.get("pfs")).get("status") or "NOT VERIFIABLE")
    rows = [
        ("Security score", _text(security.get("security_score"), "not scored")),
        ("Risk band", risk),
        ("ESP packets observed", _text(protocol.get("esp_packets") or scan.get("esp_packets"))),
        ("IKE packets observed", _text(protocol.get("ike_packets") or scan.get("ike_packets"))),
        ("Distinct ESP SPIs", _text(len(_sequence(protocol.get("esp_flows"))), default="0")),
        ("Encryption", _status_word(_assessed(security, "cipher"), "NOT VERIFIABLE")),
        ("Integrity / authentication", _status_word(_assessed(security, "integrity"), "NOT VERIFIABLE")),
        ("Key exchange (DH)", _status_word(_assessed(security, "dh group"), "NOT VERIFIABLE")),
        ("Anti-replay enforcement", _status_word(_assessed(security, "replay"), "NOT VERIFIABLE")),
        ("PFS", pfs_status),
    ]
    return ["<h2>At a glance</h2>", _table(("Measure", "Value"), rows)]



def _traffic_section(traffic: Mapping[str, Any]) -> list[str]:
    """Traffic intelligence, always labelled INFERRED or explicitly absent."""
    if not traffic.get("predicted_class"):
        reason = _text(traffic.get("reason") or "no compatible trained model", "unavailable")
        return [
            "<h2>Traffic intelligence</h2>",
            f'<p class="note">Traffic classification unavailable. Reason: {_esc(reason)}.</p>',
        ]
    rows = [
        (
            "Predicted traffic category",
            "UNKNOWN - no known category had sufficient support"
            if traffic.get("rejected")
            else _text(traffic.get("predicted_class")),
        ),
        (
            "Closest known category",
            _text(traffic.get("closest_known_class"), default="n/a"),
        ),
        ("Confidence", _percent(traffic.get("confidence"))),
        ("Evidence status", "INFERRED (model-derived, not observed)"),
    ]
    if traffic.get("rejected"):
        rows.append(
            (
                "Note",
                "The encrypted traffic could not be confidently assigned to one of the traffic "
                "categories known to the current model. This is not a security warning and does "
                "not indicate unusual or malicious activity.",
            )
        )
    if traffic.get("low_confidence"):
        rows.append(("Caution", "confidence is below the configured threshold; treat the label as weak"))
    if traffic.get("model_id"):
        rows.append(("Model", f"{traffic['model_id']} {traffic.get('model_version') or ''}".strip()))
    probabilities = _mapping(traffic.get("probabilities"))
    if probabilities:
        rows.extend(
            (f"  &nbsp;&nbsp;{name}", _percent(value)) for name, value in sorted(probabilities.items())
        )
    return [
        "<h2>Traffic intelligence</h2>",
        _table(("Measure", "Value"), rows),
        '<p class="note">This category is <strong>inferred</strong> from packet size and timing '
        "statistics by a statistical model. It is not an observation of the payload and must "
        "not be treated as confirmed content.</p>",
    ]


def _findings_section(findings: Sequence[Mapping[str, Any]]) -> list[str]:
    """Only the findings that represent a weakness or an open question."""
    interesting = [item for item in findings if _status_rank(item) <= 2][:MAX_FINDINGS]
    rows = [
        (str(item.get("title", "untitled")), str(item.get("status", "")), str(item.get("severity", "")))
        for item in interesting
    ]
    if not rows:
        return ["<h2>Major findings</h2>", '<p class="note">No failing or warning findings were raised.</p>']
    return [
        "<h2>Major findings</h2>",
        _table(("Finding", "Status", "Severity"), rows),
        '<p class="note">Findings marked NOT VERIFIABLE were not answered because a passive '
        "capture cannot settle them. They are <strong>not</strong> failures.</p>",
    ]


def _recommendations_section(security: Mapping[str, Any]) -> list[str]:
    """The recommended actions, with the reason each one exists."""
    items = [_mapping(item) for item in _sequence(security.get("recommendations"))][:MAX_RECOMMENDATIONS]
    rows = [
        (str(item.get("recommendation", "")), str(item.get("priority", "")), str(item.get("reason", "")))
        for item in items
    ]
    if not rows:
        return ["<h2>Recommended actions</h2>", '<p class="note">No recommendations were raised.</p>']
    return ["<h2>Recommended actions</h2>", _table(("Action", "Priority", "Why"), rows)]


def _privacy_section(privacy: Mapping[str, Any]) -> list[str]:
    """What an off-path observer could learn from this traffic."""
    rows = [
        ("Exposure score", _text(privacy.get("privacy_risk"), "not evaluated")),
        ("Exposure band", _text(privacy.get("exposure_level"), "not evaluated")),
        ("Most observable", _text(privacy.get("top_observable"), "nothing identified")),
    ]
    return ["<h2>Metadata exposure</h2>", _table(("Measure", "Value"), rows)]


def build_executive(bundle: Mapping[str, Any], *, generated_at: str) -> str:
    """Render the executive report for one canonical bundle."""
    source = _mapping(bundle.get("source"))
    protocol = component_data(bundle, "protocol")
    traffic = component_data(bundle, "traffic")
    security = component_data(bundle, "security")
    privacy = component_data(bundle, "privacy")
    findings = _ordered_findings(security)

    coverage_value_ = coverage_value(security)
    component_rows = [
        (str(name), _text(_mapping(stage).get("status") if isinstance(stage, Mapping) else stage))
        for name, stage in sorted(_mapping(bundle.get("components")).items())
    ]
    if component_rows:
        component_rows.insert(0, ("Overall analysis", _text(bundle.get("status"), "unknown")))

    honesty = ["<h2>Evidence coverage and limits</h2>"]
    honesty.append(
        _table(
            ("Measure", "Value"),
            [
                ("Evidence coverage", _percent(coverage_value_)),
                ("Security summary", _text(security.get("summary"), "not scored")),
                ("Capture source", f"{_text(source.get('kind'), 'unknown')} &middot; {_text(source.get('filename'), 'unnamed')}"),
            ],
        )
    )
    limitations = _sequence(bundle.get("limitations")) + _sequence(privacy.get("limitations"))
    if limitations:
        honesty.append("<h3>Limitations</h3>")
        honesty.append("<ul>" + "".join(f"<li>{_esc(item)}</li>" for item in limitations[:10]) + "</ul>")
    if component_rows:
        honesty.append("<h3>Analysis coverage</h3>")
        honesty.append(_table(("Stage", "Status"), component_rows))

    return _document(
        "FERA Executive Security Report",
        f"Analysis {_text(bundle.get('analysis_id'))}",
        [
            _overview_section(bundle, protocol, security),
            *_traffic_section(traffic),
            _findings_section(findings),
            _recommendations_section(security),
            _privacy_section(privacy),
            *honesty,
        ],
        generated_at=generated_at,
    )


__all__ = ["build_executive"]
