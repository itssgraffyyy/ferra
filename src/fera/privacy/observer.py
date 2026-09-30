"""Derive the metadata-exposure view of a capture from its analysis document.

Every observation here is computed from fields the protocol analyser already
produced, so the privacy answer and the security answer can never disagree about
what is in the capture.  Three rules govern the module:

1. **Cite, do not assert.**  An observation's ``evidence`` strings quote the
   document they came from (SPI, byte counts, transform names).  An observation
   with no evidence is not reported as ``none`` exposure, it is reported as
   ``unknown`` and lowers ``coverage`` instead of looking clean.
2. **Cleartext is the whole story.**  ESP hides the payload; the outer IP header,
   the SPI, the IKE negotiation and anything sent outside the tunnel are not
   hidden.  The checks are therefore about *headers and behaviour*, which is what
   a passive observer actually has.
3. **Mitigation, not alarm.**  Each observation states what reduces it, because
   "the endpoints are visible" is only useful next to "and only in tunnel mode,
   which is why the inner addresses stay private".
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .models import EXPOSURE_POINTS, Observation, PrivacyReport, exposure_band

TOPIC_LABELS: dict[str, str] = {
    "identity": "Endpoint identity",
    "configuration": "Configuration disclosure",
    "activity": "Activity and volume",
    "cleartext": "Cleartext context",
    "inference": "Statistical inference",
}


def _scan(analysis: Mapping[str, Any]) -> dict[str, Any]:
    details = analysis.get("details") or {}
    return dict(details.get("scan") or {})


def _flows(analysis: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [dict(item) for item in (analysis.get("esp_flows") or ())]


def _exchanges(analysis: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [dict(item) for item in (analysis.get("ike_exchanges") or ())]


def _endpoints(flows: list[dict[str, Any]]) -> list[str]:
    seen: list[str] = []
    for flow in flows:
        for key in ("src", "dst"):
            value = str(flow.get(key) or "")
            if value and value not in seen:
                seen.append(value)
    return seen


def _endpoint_identity(analysis: Mapping[str, Any]) -> Observation:
    """Tunnel mode hides inner addresses; the outer header never does."""
    flows = _flows(analysis)
    endpoints = _endpoints(flows)
    if not endpoints:
        return Observation(
            id="endpoint-identity",
            title="Peer endpoints visible in the outer IP header",
            topic="identity",
            exposure="unknown",
            finding="no ESP flow endpoints were recorded, so endpoint exposure could not be evaluated",
            evidence=("esp_flows is empty",),
        )
    pairs = sorted({f"{flow.get('src')} -> {flow.get('dst')}" for flow in flows})
    return Observation(
        id="endpoint-identity",
        title="Peer endpoints visible in the outer IP header",
        topic="identity",
        exposure="high",
        finding=(
            f"a passive observer learns that {endpoints[0]} and {endpoints[-1]} run an IPsec tunnel "
            f"({len(pairs)} directional flow(s)); inner addresses stay hidden, outer ones do not"
        ),
        evidence=tuple(
            f"esp_flows[{index}].src/dst = {pair}" for index, pair in enumerate(pairs)
        ),
        mitigations=(
            "route the tunnel through a concentrator so few outer endpoints carry many tunnels",
            "keep inner space non-routable so leaked flow records identify nothing routable",
        ),
    )


def _sa_identifiers(analysis: Mapping[str, Any]) -> Observation:
    """SPIs are cleartext and stable, so they are tracking identifiers."""
    flows = _flows(analysis)
    spis = [str(flow.get("spi") or "") for flow in flows if flow.get("spi")]
    if not spis:
        return Observation(
            id="sa-identifiers",
            title="Security parameters identifiers as tracking handles",
            topic="identity",
            exposure="unknown",
            finding="no ESP SPI was recorded, so identifier exposure could not be evaluated",
            evidence=("esp_flows carries no spi values",),
        )
    spans = [f"SPI {flow.get('spi')}: frames {flow.get('first_frame')}-{flow.get('last_frame')}" for flow in flows]
    return Observation(
        id="sa-identifiers",
        title="Security parameters identifiers as tracking handles",
        topic="identity",
        exposure="medium",
        finding=(
            f"{len(spis)} cleartext SPI value(s) label the tunnel for its whole lifetime, letting an "
            "observer stitch packets into one session and follow it across rekey boundaries"
        ),
        evidence=tuple(spans),
        mitigations=("rekey often enough that an SPI's useful lifetime is short",),
    )


def _negotiation(analysis: Mapping[str, Any]) -> Observation:
    """IKE proposals are unencrypted: the offered cipher suite is public."""
    exchanges = _exchanges(analysis)
    names: list[str] = []
    for exchange in exchanges:
        for proposal in exchange.get("proposals") or ():
            for key in ("encryption", "prf", "integrity"):
                names.extend(str(item) for item in (proposal.get(key) or ()))
            names.extend(f"DH_{item}" for item in (proposal.get("dh_groups") or ()))
    if not exchanges:
        return Observation(
            id="negotiation-disclosure",
            title="IKE negotiation discloses the offered cipher suite",
            topic="configuration",
            exposure="unknown",
            finding="no cleartext IKE exchange was captured, so negotiation exposure could not be evaluated",
            evidence=("ike_exchanges is empty; the negotiation may fall outside this capture window",),
            mitigations=("capture the whole SA establishment when the negotiable suite must be assessed",),
        )
    unique = sorted(dict.fromkeys(names))
    return Observation(
        id="negotiation-disclosure",
        title="IKE negotiation discloses the offered cipher suite",
        topic="configuration",
        exposure="medium",
        finding=(
            f"{len(exchanges)} cleartext IKE message(s) advertise "
            f"{', '.join(unique[:6]) or 'no named transforms'}; the ordered transform list fingerprints "
            "the peer's IPsec stack and reveals which legacy algorithms it is willing to accept"
        ),
        evidence=tuple(
            f"ike_exchanges[{index}].{exchange.get('exchange_name')} v{exchange.get('ike_version')} "
            f"ispi={exchange.get('initiator_spi')}"
            for index, exchange in enumerate(exchanges)
        ),
        mitigations=(
            "prefer IKEv2 with a narrow modern proposal list to shrink the fingerprint",
            "stop offering legacy transforms: the offer is visible even when it is never selected",
        ),
    )


def _volume(analysis: Mapping[str, Any]) -> Observation:
    """Packet and byte counts per flow are a coarse but real activity profile."""
    flows = _flows(analysis)
    if not flows:
        return Observation(
            id="volume-profile",
            title="Per-flow volume profile",
            topic="activity",
            exposure="unknown",
            finding="no ESP flow volume was recorded, so activity exposure could not be evaluated",
            evidence=("esp_flows is empty",),
        )
    total = sum(int(flow.get("bytes_total") or 0) for flow in flows)
    biggest = max(int(flow.get("bytes_total") or 0) for flow in flows)
    return Observation(
        id="volume-profile",
        title="Per-flow volume profile",
        topic="activity",
        exposure="medium" if len(flows) > 1 else "low",
        finding=(
            f"an observer can measure {total} encrypted bytes across {len(flows)} flow(s), the largest "
            f"carrying {biggest} bytes; packet sizes and burst shape survive encryption and are enough "
            "to profile what the tunnel is being used for"
        ),
        evidence=tuple(
            f"SPI {flow.get('spi')}: {flow.get('packets')} packets, {flow.get('bytes_total')} bytes "
            f"(frames {flow.get('first_frame')}-{flow.get('last_frame')})"
            for flow in flows
        ),
        mitigations=(
            "pad or shape traffic where bandwidth permits",
            "keep one tunnel per purpose so a single flow does not describe a whole site",
        ),
    )


def _cleartext(analysis: Mapping[str, Any]) -> Observation:
    """Everything outside ESP is readable; the analyser already counted it."""
    scan = _scan(analysis)
    if not scan:
        return Observation(
            id="cleartext-context",
            title="Non-ESP traffic captured in the clear",
            topic="cleartext",
            exposure="unknown",
            finding="the analysis carries no scan summary, so cleartext exposure could not be evaluated",
            evidence=("details.scan is absent",),
        )
    packets = int(scan.get("packets", 0) or 0)
    covered = int(scan.get("esp_packets", 0) or 0) + int(scan.get("ah_packets", 0) or 0)
    outside = max(0, packets - covered)
    share = (outside / packets * 100) if packets else 0.0
    parts = [f"details.scan.packets = {packets}", f"encrypted (ESP/AH) = {covered}", f"cleartext = {outside}"]
    for key, label in (("ike_packets", "IKE"), ("icmp_packets", "ICMP"), ("icmpv6_packets", "ICMPv6")):
        count = int(scan.get(key, 0) or 0)
        if count:
            parts.append(f"{label} = {count}")
    return Observation(
        id="cleartext-context",
        title="Non-ESP traffic captured in the clear",
        topic="cleartext",
        exposure="high" if share >= 25 else ("medium" if outside else "none"),
        finding=(
            f"{outside} of {packets} packet(s) ({share:.0f}%) travel outside the tunnel and are fully "
            "readable; a tunnel protects what carries through it, not what bypasses it"
        ),
        evidence=tuple(parts),
        mitigations=(
            "route DNS and management traffic through the tunnel, or encrypt them (DoH, TLS)",
            "confirm capture scope: a tunnel-interface capture shows cleartext that lives on another path",
        ),
    )


def _inference(analysis: Mapping[str, Any], prediction: Mapping[str, Any] | None) -> Observation:
    """If the traffic class is predictable from metadata, confidentiality is weaker."""
    if not prediction:
        return Observation(
            id="class-inference",
            title="Traffic class inferable from ciphertext statistics",
            topic="inference",
            exposure="unknown",
            finding=(
                "no classifier prediction was available, so how much of this traffic is predictable from "
                "packet-size and timing statistics alone was not measured in this run"
            ),
            evidence=("traffic stage produced no prediction",),
            mitigations=("train and load a traffic classifier to measure this exposure",),
        )
    klass = str(prediction.get("predicted_class") or "unknown")
    confidence = float(prediction.get("confidence") or 0.0)
    model_id = str(prediction.get("model_id") or "unknown")
    return Observation(
        id="class-inference",
        title="Traffic class inferable from ciphertext statistics",
        topic="inference",
        exposure="high" if confidence >= 0.8 else "medium",
        finding=(
            f"size and timing statistics alone classify this traffic as {klass} with "
            f"{confidence:.0%} confidence ({model_id}); encryption hides content, not behaviour"
        ),
        evidence=(f"traffic prediction predicted_class={klass} confidence={confidence:.3f} model_id={model_id}",),
        mitigations=(
            "constant-size pacing removes the size signal the classifier relies on",
            "treat traffic class as sensitive data while the model stays this confident",
        ),
    )


#: Every check runs on every capture; a check that cannot run reports ``unknown``.
CHECKS: tuple[Callable[..., Observation], ...] = (
    _endpoint_identity,
    _sa_identifiers,
    _negotiation,
    _volume,
    _cleartext,
)


def score(observations: tuple[Observation, ...]) -> tuple[int, int]:
    """Return ``(privacy_risk, coverage)`` for a set of observations.

    Risk is the share of the maximum achievable exposure points among the checks
    that could actually be evaluated, so a capture that hides nothing and a
    capture that barely parsed never share a score by accident.
    """
    evaluated = [item for item in observations if item.evaluable]
    if not evaluated:
        return 0, 0
    earned = sum(EXPOSURE_POINTS.get(item.exposure, 0) for item in evaluated)
    risk = int(round(100 * earned / (4 * len(evaluated))))
    coverage = int(round(100 * len(evaluated) / len(observations)))
    return risk, coverage


def observe_privacy(
    capture: Path | str,
    analysis: Mapping[str, Any],
    *,
    prediction: Mapping[str, Any] | None = None,
    analysis_id: str | None = None,
) -> PrivacyReport:
    """Assess what an off-path observer can learn from one analysed capture.

    ``analysis`` is the document produced by :meth:`fera.analysis.ProtocolAnalysis.to_dict`;
    ``prediction`` is the optional ML contract document, which sharpens the
    inference observation and changes nothing else.
    """
    document = dict(analysis)
    observations = tuple(check(document) for check in CHECKS) + (_inference(document, prediction),)
    risk, coverage = score(observations)
    ranked = sorted(
        (item for item in observations if item.evaluable),
        key=lambda item: (-EXPOSURE_POINTS.get(item.exposure, 0), item.id),
    )
    limitations = [
        f"{TOPIC_LABELS.get(item.topic, item.topic)} not evaluable: {item.finding}"
        for item in observations
        if not item.evaluable
    ]
    limitations.append(
        "exposure is scored from a single capture window; take repeat captures before treating any "
        "one volume or timing figure as this site's profile"
    )
    return PrivacyReport(
        analysis_id=analysis_id or str(document.get("analysis_id") or Path(capture).stem),
        observations=observations,
        privacy_risk=risk,
        exposure_level=exposure_band(risk),
        top_observable=(ranked[0].title if ranked else None),
        coverage=coverage,
        inputs={"capture": str(capture), "prediction": bool(prediction)},
        limitations=tuple(limitations),
    )


__all__ = ["CHECKS", "TOPIC_LABELS", "observe_privacy", "score"]
