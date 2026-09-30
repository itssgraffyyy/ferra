"""Build the technical report: the full, sectioned account for an analyst.

This document is the audit trail.  It reproduces every field the bundle carries,
groups findings by the assessment category that produced them, shows the
evidence behind each verdict, and lists the questions the capture could not
answer.  Like the executive report it re-analyses nothing: it only reads the
bundle.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import _mapping, _percent, _sequence, _text, component_data, coverage_value
from .render import _document, _esc, _table

#: Human readable section titles for the technical report, in order.
SECTIONS: tuple[str, ...] = (
    "Analysis metadata",
    "Capture summary",
    "IPsec / IKE analysis",
    "VPN mode",
    "Cryptography",
    "Key exchange",
    "Security associations",
    "Perfect forward secrecy",
    "Key lifetime",
    "Replay protection",
    "Traffic intelligence",
    "Security assessment",
    "Threat matrix",
    "Privacy / metadata exposure",
    "Evidence coverage",
    "Not verifiable items",
    "Recommendations",
    "Limitations",
)


def _heading(index: int, extra: str = "") -> str:
    """Numbered section heading."""
    return f"<h2>{index}. {SECTIONS[index - 1]}{extra}</h2>"


def _kv(label: str, value: Any, *, default: str = "not reported") -> str:
    """One key/value table row."""
    return f'<tr><th style="width:32%">{_esc(label)}</th><td>{_esc(_text(value, default))}</td></tr>'


def _scan(protocol: Mapping[str, Any]) -> dict[str, Any]:
    """Packet counters the built-in scanner produced for this capture."""
    return _mapping(_mapping(protocol.get("details")).get("scan"))


def _ipsec_facts(protocol: Mapping[str, Any]) -> dict[str, Any]:
    """Merge the protocol payload with its scan counters.

    The analyser keeps the packet census under ``details.scan`` and the
    negotiation facts at the top level; several report sections need both, so
    they are merged once here rather than at every call site.
    """
    return {**_mapping(protocol), **_scan(protocol)}


def _details_section(bundle: Mapping[str, Any]) -> list[str]:
    """Section 1: identity, timing and provenance of the analysis itself."""
    provenance = _mapping(bundle.get("provenance"))
    tools = ", ".join(str(name) for name in _sequence(provenance.get("tshark")))
    return [
        _heading(1),
        "<table>"
        + _kv("Analysis ID", bundle.get("analysis_id"))
        + _kv("Created at", bundle.get("created_at"))
        + _kv("Bundle schema", bundle.get("schema_version"))
        + _kv("Overall status", bundle.get("status"), default="unknown")
        + _kv("Fera version", provenance.get("fera_version") or provenance.get("app_version"))
        + _kv("Tool availability", tools or "none recorded", default="none recorded")
        + _kv("tshark requested", provenance.get("tshark_requested"))
        + _kv("tshark used", provenance.get("tshark"), default="no external dissector was used")
        + _kv("Model directory", provenance.get("models"), default="no model directory recorded")
        + _kv("Finished at", provenance.get("finished_at"))
        + "</table>",
    ]


def _capture_section(source: Mapping[str, Any], protocol: Mapping[str, Any]) -> list[str]:
    """Section 2: what the file was and what was in it."""
    scan = _scan(protocol)
    return [
        _heading(2),
        "<table>"
        + _kv("Source mode", source.get("kind"), default="unknown")
        + _kv("Filename", source.get("filename"), default="unnamed")
        + _kv("Size (bytes)", source.get("size_bytes"))
        + _kv("SHA-256", source.get("sha256"), default="not computed")
        + _kv("Captured at", source.get("captured_at"), default="not recorded")
        + _kv("Capture format", scan.get("file_format"), default="not determined")
        + _kv("Link type", scan.get("linktype_name"), default="not determined")
        + _kv("Packets", protocol.get("packets") or scan.get("packets"))
        + _kv("Captured bytes", scan.get("captured_bytes"))
        + _kv("IKE packets", protocol.get("ike_packets") or scan.get("ike_packets"))
        + _kv("ESP packets", protocol.get("esp_packets") or scan.get("esp_packets"))
        + _kv("AH packets", scan.get("ah_packets"), default="none seen")
        + _kv("Truncated frames", scan.get("truncated_frames"), default="0")
        + "</table>",
    ]


def _ipsec_section(protocol: Mapping[str, Any]) -> list[str]:
    """Section 3: detection, IKE version, exchanges and NAT-T."""
    facts = _ipsec_facts(protocol)
    exchanges = [_mapping(item) for item in _sequence(protocol.get("ike_exchanges"))]
    rows = [
        (
            str(item.get("type") or item.get("name") or "exchange"),
            _text(item.get("version")),
            _text(item.get("status")),
        )
        for item in exchanges
    ]
    return [
        _heading(3),
        "<table>"
        + _kv("Analysis method", protocol.get("method"), default="not recorded")
        + _kv("IKE packets", facts.get("ike_packets"))
        + _kv("IKE exchanges parsed", len(exchanges))
        + _kv("ESP packets", facts.get("esp_packets"))
        + _kv("AH packets", facts.get("ah_packets"), default="none seen")
        + _kv("NAT-T (UDP encapsulation)", facts.get("natt"), default="not observed")
        + _kv("IPv4 packets", facts.get("ipv4_packets"), default="not counted")
        + _kv("IPv6 packets", facts.get("ipv6_packets"), default="not counted")
        + "</table>",
        _table(("Exchange", "Version", "Status"), rows) if rows else "",
    ]


def _mode_section(protocol: Mapping[str, Any]) -> list[str]:
    """Section 4: tunnel vs transport, with its evidence status."""
    return [
        _heading(4),
        "<table>"
        + _kv("Mode", protocol.get("mode"), default="not observed")
        + _kv("Mode evidence", protocol.get("mode_evidence") or protocol.get("evidence_status"), default="not recorded")
        + "</table>",
    ]


def _crypto_section(protocol: Mapping[str, Any]) -> list[str]:
    """Section 5: encryption, key size and integrity."""
    return [
        _heading(5),
        "<table>"
        + _kv("Encryption", protocol.get("encryption"), default="not observed")
        + _kv("Key size", protocol.get("key_length") or protocol.get("key_bits"), default="not observed")
        + _kv(
            "Integrity / authentication",
            protocol.get("integrity") or protocol.get("authentication"),
            default="not observed",
        )
        + _kv("AEAD", protocol.get("aead"), default="not determined")
        + _kv("PRF", protocol.get("prf"), default="not observed")
        + "</table>",
    ]


def _ke_section(protocol: Mapping[str, Any]) -> list[str]:
    """Section 6: key exchange."""
    return [
        _heading(6),
        "<table>"
        + _kv("DH group / KE", protocol.get("dh_group") or protocol.get("key_exchange"), default="not observed")
        + _kv("KE evidence", protocol.get("ke_evidence") or protocol.get("evidence_status"), default="not recorded")
        + "</table>",
    ]



def _sa_section(protocol: Mapping[str, Any]) -> list[str]:
    """Section 7: IKE SA, CHILD SA, SPIs, selectors and lifetime."""
    sas = [_mapping(item) for item in _sequence(protocol.get("sas") or protocol.get("sa_events"))]
    rows = [
        (
            str(_mapping(item).get("type") or _mapping(item).get("name") or "SA"),
            _text(item.get("spi") or item.get("spi_hex")),
            _text(item.get("state") or item.get("status")),
            _text(item.get("lifetime")),
        )
        for item in sas
    ]
    selectors = [
        f"{_mapping(item).get('src')} -> {_mapping(item).get('dst')}"
        for item in _sequence(protocol.get("traffic_selectors"))
    ]
    return [
        _heading(7),
        "<table>"
        + _kv("IKE SA SPI", protocol.get("ike_spi"), default="not observed")
        + _kv("CHILD SA SPI", protocol.get("child_spi") or protocol.get("esp_spi"), default="not observed")
        + _kv("Observable lifetime", protocol.get("lifetime") or protocol.get("sa_lifetime"), default="not observed")
        + _kv("SA events", len(sas))
        + "</table>",
        _table(("SA", "SPI", "State", "Lifetime"), rows) if rows else "",
        _table(("Traffic selector", ""), [(item, "") for item in selectors]) if selectors else "",
    ]


def _pfs(protocol: Mapping[str, Any]) -> dict[str, Any]:
    """PFS verdict, taken from the analyser (never re-derived here)."""
    pfs = _mapping(protocol.get("pfs"))
    if pfs:
        return pfs
    return _mapping(_mapping(protocol.get("details")).get("pfs"))


def _pfs_section(protocol: Mapping[str, Any]) -> list[str]:
    """Section 8: PFS status, with the evidence that supports the verdict."""
    pfs = _pfs(protocol)
    return [
        _heading(8),
        "<table>"
        + _kv("PFS status", pfs.get("status"), default="NOT VERIFIABLE")
        + _kv("PFS group", pfs.get("group") or pfs.get("dh_group"), default="not observed")
        + _kv("CHILD_SA DH groups", ", ".join(str(name) for name in _sequence(pfs.get("child_sa_dh_groups"))) or "none observed")
        + _kv("Reason", pfs.get("reason") or pfs.get("detail"), default="not recorded")
        + "</table>",
        '<p class="note">A passive capture can show a rekey carrying a new Diffie-Hellman group, '
        "but it cannot prove the receiving endpoint enforced it.</p>",
    ]


def _lifetime_section(protocol: Mapping[str, Any]) -> list[str]:
    """Section 9: key lifetime, separated into observed and configured."""
    return [
        _heading(9),
        "<table>"
        + _kv("Observed lifetime", protocol.get("observed_lifetime") or protocol.get("lifetime"), default="not observed")
        + _kv("Configured lifetime", protocol.get("configured_lifetime"), default="not supplied")
        + _kv("Rekey observed", protocol.get("rekey_observed"), default="not observed")
        + "</table>",
    ]


def _replay_section(protocol: Mapping[str, Any]) -> list[str]:
    """Section 10: sequence anomalies and enforcement verifiability."""
    return [
        _heading(10),
        "<table>"
        + _kv(
            "Sequence anomalies",
            protocol.get("sequence_anomalies") or protocol.get("replay_anomalies"),
            default="none observed",
        )
        + _kv("Anti-replay enforcement", protocol.get("anti_replay"), default="NOT VERIFIABLE")
        + "</table>",
        '<p class="note">Anti-replay enforcement is a property of the receiving endpoint. '
        "A capture shows the sequence numbers that were sent, never whether they were accepted.</p>",
    ]


def _first_finding(security: Mapping[str, Any], needle: str) -> dict[str, Any]:
    """Return the first finding whose id or title mentions ``needle``.

    Used to surface the assessment's own verdict for a named property when the
    protocol payload does not carry it.  The finding is quoted, never
    reinterpreted.
    """
    for item in _sequence(security.get("findings")):
        candidate = _mapping(item)
        haystack = f"{candidate.get('rule_id', '')} {candidate.get('title', '')}".lower()
        if needle in haystack:
            return candidate
    return {}


def _assessed(security: Mapping[str, Any], needle: str) -> dict[str, Any]:
    """PFS verdict from the security assessment, for properties the analyser missed."""
    return _first_finding(security, needle)


def _findings_by_category(security: Mapping[str, Any]) -> list[list[Any]]:
    """Split findings into (category, findings) buckets, largest first."""
    buckets: dict[str, list[Any]] = {}
    for item in _sequence(security.get("findings")):
        candidate = _mapping(item)
        buckets.setdefault(str(candidate.get("category") or "general"), []).append(candidate)
    return [[str(name).replace("_", " ").title(), items] for name, items in sorted(buckets.items(), key=lambda p: (-len(p[1]), p[0]))]




def _traffic_section(traffic: Mapping[str, Any]) -> list[str]:
    """Section 11: the model prediction, explicitly marked INFERRED."""
    if not traffic.get("predicted_class"):
        reason = _text(traffic.get("reason") or "no compatible trained model", "unavailable")
        return [
            _heading(11),
            f'<p class="note">Traffic classification unavailable. Reason: {_esc(reason)}.</p>',
        ]
    rows = [
        ("Predicted class", _text(traffic.get("predicted_class"))),
        ("Confidence", _percent(traffic.get("confidence"))),
        ("Evidence status", "INFERRED"),
        ("Low confidence", _text(traffic.get("low_confidence"), default="no")),
        ("Confidence threshold", _percent(traffic.get("confidence_threshold"))),
        ("Model ID", traffic.get("model_id")),
        ("Model version", traffic.get("model_version")),
        ("Feature schema", traffic.get("feature_schema")),
    ]
    probabilities = _mapping(traffic.get("probabilities"))
    rows.extend((f"p({name})", f"{float(value):.4f}") for name, value in sorted(probabilities.items()))
    return [_heading(11), "<table>" + "".join(_kv(*row) for row in rows) + "</table>"]


def _assessment_section(security: Mapping[str, Any]) -> list[str]:
    """Section 12: score, band, category scores and every finding."""
    categories = [
        (
            str(_mapping(item).get("category", "")).replace("_", " ").title(),
            _text(_mapping(item).get("score")),
            _text(_mapping(item).get("max_score")),
            _percent(_mapping(item).get("coverage")),
        )
        for item in (_mapping(entry) for entry in _sequence(security.get("category_scores")))
    ]
    blocks = [
        _heading(12),
        "<table>"
        + _kv("Security score", security.get("security_score"), default="not scored")
        + _kv("Risk level", security.get("risk_level"), default="not scored")
        + _kv("Summary", security.get("summary"), default="not scored")
        + _kv("Evidence coverage", _percent(coverage_value(security)))
        + "</table>",
        _table(("Category", "Score", "Max", "Coverage"), categories) if categories else "",
    ]
    for label, items in _findings_by_category(security):
        rows = [
            (
                str(_mapping(item).get("title", "untitled")),
                str(_mapping(item).get("status", "")),
                str(_mapping(item).get("severity", "")),
                str(_mapping(item).get("evidence_status") or _mapping(item).get("evidence", "not recorded")),
            )
            for item in items
        ]
        blocks.append(f"<h3>{_esc(label)}</h3>")
        blocks.append(_table(("Finding", "Status", "Severity", "Evidence"), rows) if rows else "")
    return blocks


def _threat_section(security: Mapping[str, Any]) -> list[str]:
    """Section 13: the threat matrix exactly as the assessment built it.

    Likelihood and impact are only shown when the assessment actually supplied
    them, so the table never implies a precision the backend did not produce.
    """
    threats = [_mapping(entry) for entry in _sequence(security.get("threat_matrix"))]
    has_risk_axes = any(item.get("likelihood") or item.get("impact") for item in threats)
    headers = ["Threat", "Risk", "Likelihood", "Impact", "Evidence", "Recommendation"] if has_risk_axes else [
        "Threat",
        "Risk",
        "Evidence",
        "Recommendation",
    ]
    rows = [
        (
            str(item.get("threat") or item.get("threat_id") or "threat"),
            str(item.get("risk", "")),
            *((str(item.get("likelihood", "")), str(item.get("impact", ""))) if has_risk_axes else ()),
            str(item.get("evidence", "")),
            str(item.get("recommendation", "")),
        )
        for item in threats
    ]
    return [_heading(13), _table(headers, rows)]


def _privacy_section(privacy: Mapping[str, Any]) -> list[str]:
    """Section 14: metadata exposure observations and their evidence."""
    rows = [
        (
            str(item.get("title", "observation")),
            str(item.get("topic", "")),
            str(item.get("exposure", "")),
            "; ".join(str(entry) for entry in _sequence(item.get("evidence"))),
        )
        for item in (_mapping(entry) for entry in _sequence(privacy.get("observations")))
    ]
    return [
        _heading(14),
        "<table>"
        + _kv("Privacy risk", privacy.get("privacy_risk"), default="not evaluated")
        + _kv("Exposure level", privacy.get("exposure_level"), default="not evaluated")
        + _kv("Coverage", _percent(privacy.get("coverage")))
        + _kv("Most observable", privacy.get("top_observable"), default="nothing identified")
        + "</table>",
        _table(("Observation", "Topic", "Exposure", "Evidence"), rows),
    ]


def _evidence_section(bundle: Mapping[str, Any], security: Mapping[str, Any]) -> list[str]:
    """Sections 15 and 16: the evidence tally, and everything left open."""
    tally = _mapping(_mapping(security.get("evidence")).get("counts")) or _mapping(
        security.get("evidence_counts")
    )
    counts = [(str(name), str(value)) for name, value in sorted(tally.items())]
    unverified = [
        str(_mapping(item).get("title", ""))
        for item in (_mapping(entry) for entry in _sequence(security.get("findings")))
        if str(_mapping(item).get("status", "")).upper() == "NOT_VERIFIABLE"
    ]
    stage_rows = [
        (str(name), str(_mapping(stage).get("status", "")), str(_mapping(stage).get("duration_ms", "")))
        for name, stage in sorted(_mapping(bundle.get("components")).items())
    ]
    blocks = [
        _heading(15),
        _table(("Evidence status", "Count"), counts)
        if counts
        else '<p class="note">No evidence tally was recorded.</p>',
        "<h3>Stage execution</h3>",
        _table(("Stage", "Status", "Duration (ms)"), stage_rows) if stage_rows else "",
        _heading(16),
    ]
    if unverified:
        blocks.append(_table(("Open question", "Status"), [(title, "NOT VERIFIABLE") for title in unverified]))
        blocks.append(
            '<p class="note">These are unanswered questions, not defects. A passive observer '
            "cannot settle them, and FERA reports them as unknown rather than guessing.</p>"
        )
    else:
        blocks.append('<p class="note">Every rule was decidable from this capture.</p>')
    return blocks


def _recommendations_section(security: Mapping[str, Any]) -> list[str]:
    """Section 17: every recommendation with its priority and rationale."""
    rows = [
        (
            str(item.get("recommendation", "")),
            str(item.get("priority", "")),
            str(item.get("severity", "")),
            str(item.get("reason", "")),
        )
        for item in (_mapping(entry) for entry in _sequence(security.get("recommendations")))
    ]
    return [_heading(17), _table(("Recommendation", "Priority", "Severity", "Why"), rows)]


def _limitations_section(bundle: Mapping[str, Any], privacy: Mapping[str, Any]) -> list[str]:
    """Section 18: everything that limits how far this analysis can be pushed."""
    provenance = _mapping(bundle.get("provenance"))
    entries = (
        _sequence(bundle.get("limitations"))
        + _sequence(privacy.get("limitations"))
        + _sequence(provenance.get("notes"))
    )
    unique = list(dict.fromkeys(str(item) for item in entries))
    blocks = [_heading(18)]
    if unique:
        blocks.append("<ul>" + "".join(f"<li>{_esc(item)}</li>" for item in unique[:30]) + "</ul>")
    else:
        blocks.append('<p class="note">No limitations were recorded for this analysis.</p>')
    blocks.append(
        '<p class="note">A passive capture observes what was transmitted. Properties enforced '
        "by an endpoint, or absent from the capture window, are reported as not verifiable "
        "rather than inferred.</p>"
    )
    return blocks


def build_technical(bundle: Mapping[str, Any], *, generated_at: str) -> str:
    """Render the technical report for one canonical bundle."""
    source = _mapping(bundle.get("source"))
    protocol = component_data(bundle, "protocol")
    traffic = component_data(bundle, "traffic")
    security = component_data(bundle, "security")
    privacy = component_data(bundle, "privacy")
    return _document(
        "FERA Technical Analysis Report",
        f"Analysis {_text(bundle.get('analysis_id'))}",
        [
            *_details_section(bundle),
            *_capture_section(source, protocol),
            *_ipsec_section(protocol),
            *_mode_section(protocol),
            *_crypto_section(protocol),
            *_ke_section(protocol),
            *_sa_section(protocol),
            *_pfs_section(protocol),
            *_lifetime_section(protocol),
            *_replay_section(protocol),
            *_traffic_section(traffic),
            *_assessment_section(security),
            *_threat_section(security),
            *_privacy_section(privacy),
            *_evidence_section(bundle, security),
            *_recommendations_section(security),
            *_limitations_section(bundle, privacy),
        ],
        generated_at=generated_at,
    )


__all__ = ["SECTIONS", "build_technical"]
