"""Normalised inputs for the security assessment.

:class:`AssessmentContext` is the only place the assessment stage touches the
output of the earlier stages.  It accepts the documented JSON documents (so the
stage runs as a standalone analysis of artefacts on disk) as well as the native
objects (so callers that already hold them do not re-serialise), and it
normalises both into typed observations that the rules can read without knowing
where a value came from.

The context also owns the evidence hierarchy.  A rule never inspects raw
documents and never decides for itself whether a value was observed on the wire
or merely configured; it asks the context, and the context answers with a value
plus the strongest evidence that supports it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..analysis.models import ProtocolAnalysis
from ..common.errors import ConfigValidationError
from .evidence import EvidenceStatus, status_from_evidence_kind
from .ml_contract import TrafficPrediction, load_prediction

IKE_SCOPE = "IKE"
CHILD_SCOPES = ("ESP", "AH")
#: IKEv2 payload type 33 (SA) - RFC 7296 section 3.1.
PAYLOAD_SA = 33
#: IKEv2 payload type 45 (ENCR) - its presence proves the message body was
#: encrypted, which is what makes the responder's proposal selection
#: unobservable in IKE_AUTH (RFC 7296 section 3.1).
PAYLOAD_ENCR = 45


def _documents(value: Any, key: str) -> tuple[Mapping[str, Any], ...]:
    """Coerce ``value`` into a tuple of mappings (records or dicts alike)."""
    if value is None:
        return ()
    items: Iterable[Any]
    if isinstance(value, Mapping) or hasattr(value, "to_dict"):
        items = [value]
    else:
        items = list(value)
    documents: list[Mapping[str, Any]] = []
    for item in items:
        if isinstance(item, Mapping):
            documents.append(item)
        elif hasattr(item, "to_dict"):
            documents.append(item.to_dict())
        else:
            raise ConfigValidationError(
                f"{key} must contain mappings or records with to_dict()",
                details={key: repr(item)},
            )
    return tuple(documents)


def _ints(values: Any) -> tuple[int, ...]:
    if not isinstance(values, Iterable) or isinstance(values, (str, bytes)):
        return ()
    result: list[int] = []
    for value in values:
        try:
            result.append(int(value))
        except (TypeError, ValueError):
            continue
    return tuple(result)


def _strings(values: Any) -> tuple[str, ...]:
    if not isinstance(values, Iterable) or isinstance(values, (str, bytes)):
        return ()
    return tuple(str(value) for value in values if str(value))


@dataclass(frozen=True)
class AlgorithmUse:
    """One algorithm mentioned by a proposal, with what is known about it."""

    name: str
    key_bits: int | None = None
    aead: bool = False
    integrity_bits: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "key_bits": self.key_bits,
            "aead": self.aead,
            "integrity_bits": self.integrity_bits,
        }


@dataclass(frozen=True)
class ProposalObservation:
    """One SA proposal, seen in clear text, normalised for assessment."""

    scope: str
    number: int
    encryption: tuple[AlgorithmUse, ...] = ()
    integrity: tuple[AlgorithmUse, ...] = ()
    prf: tuple[AlgorithmUse, ...] = ()
    dh_groups: tuple[int, ...] = ()
    spi: str = ""
    exchange: str = ""
    initiator: bool = False
    response: bool = False
    frame_index: int = -1
    protocol_id: int = 0

    @property
    def is_child_sa(self) -> bool:
        return self.scope in CHILD_SCOPES

    @property
    def aead(self) -> bool:
        return any(item.aead for item in self.encryption)

    @property
    def has_integrity(self) -> bool:
        return any(item.name and item.name != "NONE" for item in self.integrity)

    @property
    def transform_summary(self) -> str:
        parts = [item.name for item in self.encryption]
        parts += [item.name for item in self.integrity]
        parts += [f"DH{group}" for group in self.dh_groups]
        return "/".join(parts) or "no transforms"

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "number": self.number,
            "encryption": [item.to_dict() for item in self.encryption],
            "integrity": [item.to_dict() for item in self.integrity],
            "prf": [item.to_dict() for item in self.prf],
            "dh_groups": list(self.dh_groups),
            "spi": self.spi,
            "exchange": self.exchange,
            "initiator": self.initiator,
            "response": self.response,
            "frame_index": self.frame_index,
            "protocol_id": self.protocol_id,
        }


@dataclass(frozen=True)
class ExchangeObservation:
    """One decoded IKE message (headers are always in clear text)."""

    frame_index: int
    ike_version: int
    exchange: str
    initiator: bool
    response: bool
    payload_types: tuple[int, ...] = ()
    proposal_count: int = 0

    @property
    def has_sa_payload(self) -> bool:
        return PAYLOAD_SA in self.payload_types

    @property
    def carries_encryption(self) -> bool:
        """Whether the message contains an encrypted payload (content hidden)."""
        return PAYLOAD_ENCR in self.payload_types

    def to_dict(self) -> dict[str, Any]:
        return {
            "frame_index": self.frame_index,
            "ike_version": self.ike_version,
            "exchange": self.exchange,
            "initiator": self.initiator,
            "response": self.response,
            "payload_types": list(self.payload_types),
            "proposal_count": self.proposal_count,
        }


@dataclass(frozen=True)
class EspFlowObservation:
    """One ESP flow (all packets sharing an SPI) as correlated by Prompt 2."""

    spi: str
    packets: int
    bytes_total: int
    src: str = ""
    dst: str = ""
    first_frame: int = -1
    last_frame: int = -1
    sequence_gaps: int = 0
    sequence_replays: int = 0
    sequence_monotonic: bool = True
    udp_encapsulated: bool = False
    encapsulation: str = "unknown"

    @property
    def average_packet_len(self) -> float:
        return self.bytes_total / self.packets if self.packets else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "spi": self.spi,
            "packets": self.packets,
            "bytes_total": self.bytes_total,
            "src": self.src,
            "dst": self.dst,
            "first_frame": self.first_frame,
            "last_frame": self.last_frame,
            "sequence_gaps": self.sequence_gaps,
            "sequence_replays": self.sequence_replays,
            "sequence_monotonic": self.sequence_monotonic,
            "udp_encapsulated": self.udp_encapsulated,
            "encapsulation": self.encapsulation,
        }


@dataclass(frozen=True)
class SequenceObservation:
    """ESP sequence-number health across every observed flow."""

    flows: int
    packets: int
    distinct_spi: int
    replays: int
    gaps: int
    non_monotonic_flows: int

    @property
    def evidence(self) -> EvidenceStatus:
        """Sequence numbers are only meaningful when ESP was captured."""
        return EvidenceStatus.OBSERVED if self.packets else EvidenceStatus.NOT_VERIFIABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "flows": self.flows,
            "packets": self.packets,
            "distinct_spi": self.distinct_spi,
            "replays": self.replays,
            "gaps": self.gaps,
            "non_monotonic_flows": self.non_monotonic_flows,
        }


@dataclass(frozen=True)
class ConfiguredParameters:
    """What the testbed says the experiment was configured with.

    Every field is optional: a partial configuration is normal (the testbed
    records what it actually set).  Values reported here are ``CONFIGURED``
    evidence - they answer "what did we set up", never "what did the wire show".
    """

    encryption: str | None = None
    integrity: str | None = None
    prf: str | None = None
    dh_group: int | str | None = None
    pfs: bool | None = None
    pfs_dh_group: int | str | None = None
    ike_version: int | None = None
    replay_protection: bool | None = None
    ike_sa_lifetime_s: int | None = None
    child_sa_lifetime_s: int | None = None
    proposal: str = ""
    source: str = "testbed.experiment_config"
    raw: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "encryption": self.encryption,
            "integrity": self.integrity,
            "prf": self.prf,
            "dh_group": self.dh_group,
            "pfs": self.pfs,
            "pfs_dh_group": self.pfs_dh_group,
            "ike_version": self.ike_version,
            "replay_protection": self.replay_protection,
            "ike_sa_lifetime_s": self.ike_sa_lifetime_s,
            "child_sa_lifetime_s": self.child_sa_lifetime_s,
            "proposal": self.proposal,
            "source": self.source,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, Any], *, source: str = "testbed.experiment_config") -> ConfiguredParameters:
        """Read a configuration document (an ``ExperimentConfig`` dump or similar).

        Both flat and nested layouts are accepted because the testbed writes the
        identity block nested while an ``ExperimentConfig.to_dict()`` is flat.
        """
        identity_block = document.get("identity")
        identity: Mapping[str, Any] = identity_block if isinstance(identity_block, Mapping) else {}
        ipsec_block = document.get("ipsec")
        ipsec: Mapping[str, Any] = ipsec_block if isinstance(ipsec_block, Mapping) else {}

        def pick(*keys: str) -> Any:
            blocks: tuple[Mapping[str, Any], ...] = (document, identity, ipsec)
            for block in blocks:
                for key in keys:
                    if key in block and block[key] is not None:
                        return block[key]
            return None

        dh_group = pick("dh_group", "ike_dh_group")
        pfs_dh = pick("pfs_dh_group", "child_dh_group")
        return cls(
            encryption=_text(pick("encryption")),
            integrity=_text(pick("integrity")),
            prf=_text(pick("prf")),
            dh_group=(dh_group if isinstance(dh_group, int) else _text(dh_group)),
            pfs=_optional_bool(pick("pfs")),
            pfs_dh_group=(pfs_dh if isinstance(pfs_dh, int) else _text(pfs_dh)),
            ike_version=_optional_int(pick("ike_version")),
            replay_protection=_optional_bool(pick("replay_protection", "replay_window")),
            ike_sa_lifetime_s=_optional_int(pick("ike_sa_lifetime_s", "ike_lifetime_s")),
            child_sa_lifetime_s=_optional_int(pick("child_sa_lifetime_s", "child_lifetime_s")),
            proposal=_text(pick("proposal", "esp_proposal")) or "",
            source=source,
            raw=dict(document),
        )


def _text(value: Any) -> str | None:
    """Normalise an enum-ish configuration value into a comparable string."""
    if value is None or isinstance(value, bool):
        return None
    if hasattr(value, "value") and not isinstance(value, (str, int, float)):
        return str(value.value)
    if isinstance(value, (str, int, float)):
        return str(value)
    return None


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"on", "true", "yes", "1"}:
            return True
        if lowered in {"off", "false", "no", "0"}:
            return False
    return None


def _proposal_view(proposal: Mapping[str, Any], exchange: Mapping[str, Any]) -> ProposalObservation:
    """Normalise one SA proposal, keeping the per-transform knowledge intact."""
    scope = str(proposal.get("protocol_name") or "IKE").upper()
    encryption: list[AlgorithmUse] = []
    integrity: list[AlgorithmUse] = []
    prf: list[AlgorithmUse] = []
    for transform in _documents(proposal.get("transforms"), "proposals.transforms"):
        use = AlgorithmUse(
            name=str(transform.get("name", "")),
            key_bits=_optional_int(transform.get("key_bits")),
            aead=bool(transform.get("aead", False)),
        )
        type_name = str(transform.get("type_name", ""))
        if type_name == "ENCRYPTION_ALGORITHM":
            encryption.append(use)
        elif type_name == "INTEGRITY_ALGORITHM":
            integrity.append(use)
        elif type_name == "PSEUDORANDOM_FUNCTION":
            prf.append(use)
    if not encryption:
        encryption = [AlgorithmUse(name=name) for name in _strings(proposal.get("encryption"))]
    if not integrity:
        integrity = [AlgorithmUse(name=name) for name in _strings(proposal.get("integrity"))]
    if not prf:
        prf = [AlgorithmUse(name=name) for name in _strings(proposal.get("prf"))]
    return ProposalObservation(
        scope=scope,
        number=_optional_int(proposal.get("proposal_number")) or 0,
        encryption=tuple(encryption),
        integrity=tuple(integrity),
        prf=tuple(prf),
        dh_groups=_ints(proposal.get("dh_groups")),
        spi=str(proposal.get("spi", "")),
        exchange=str(exchange.get("exchange_name", "")),
        initiator=bool(exchange.get("initiator", False)),
        response=bool(exchange.get("response", False)),
        frame_index=_optional_int(exchange.get("frame_index")) or -1,
        protocol_id=_optional_int(proposal.get("protocol_id")) or 0,
    )


def _exchange_view(exchange: Mapping[str, Any]) -> ExchangeObservation:
    return ExchangeObservation(
        frame_index=_optional_int(exchange.get("frame_index")) or -1,
        ike_version=_optional_int(exchange.get("ike_version")) or 0,
        exchange=str(exchange.get("exchange_name", "")),
        initiator=bool(exchange.get("initiator", False)),
        response=bool(exchange.get("response", False)),
        payload_types=_ints(exchange.get("payload_types")),
        proposal_count=len(_documents(exchange.get("proposals"), "ike_exchanges.proposals")),
    )


def _flow_view(flow: Mapping[str, Any]) -> EspFlowObservation:
    return EspFlowObservation(
        spi=str(flow.get("spi", "")),
        packets=_optional_int(flow.get("packets")) or 0,
        bytes_total=_optional_int(flow.get("bytes_total")) or 0,
        src=str(flow.get("src", "")),
        dst=str(flow.get("dst", "")),
        first_frame=_optional_int(flow.get("first_frame")) or -1,
        last_frame=_optional_int(flow.get("last_frame")) or -1,
        sequence_gaps=_optional_int(flow.get("sequence_gaps")) or 0,
        sequence_replays=_optional_int(flow.get("sequence_replays")) or 0,
        sequence_monotonic=bool(flow.get("sequence_monotonic", True)),
        udp_encapsulated=bool(flow.get("udp_encapsulated", False)),
        encapsulation=str(flow.get("encapsulation", "unknown")),
    )


def _sequence_view(flows: Sequence[EspFlowObservation], packets: int) -> SequenceObservation:
    return SequenceObservation(
        flows=len(flows),
        packets=packets,
        distinct_spi=len({flow.spi for flow in flows}),
        replays=sum(flow.sequence_replays for flow in flows),
        gaps=sum(flow.sequence_gaps for flow in flows),
        non_monotonic_flows=sum(1 for flow in flows if not flow.sequence_monotonic),
    )

@dataclass(frozen=True)
class AssessmentContext:
    """Everything the rules are allowed to know about one assessment.

    Rules receive this object and nothing else.  Every accessor that a rule uses
    to decide a verdict returns the value *and* the strongest evidence that
    supports it, so a rule cannot accidentally treat a configured value as an
    observation.
    """

    analysis_id: str = ""
    pcap_path: str = ""
    method: str = ""
    packets: int = 0
    ike_packets: int = 0
    esp_packets: int = 0
    exchanges: tuple[ExchangeObservation, ...] = ()
    ike_proposals: tuple[ProposalObservation, ...] = ()
    child_proposals: tuple[ProposalObservation, ...] = ()
    esp_flows: tuple[EspFlowObservation, ...] = ()
    sequence: SequenceObservation = field(
        default_factory=lambda: SequenceObservation(0, 0, 0, 0, 0, 0)
    )
    pfs_status: str = "NOT_VERIFIABLE"
    pfs_evidence: EvidenceStatus = EvidenceStatus.NOT_VERIFIABLE
    pfs_reason: str = ""
    pfs_child_dh_groups: tuple[int, ...] = ()
    scan: Mapping[str, Any] = field(default_factory=dict)
    configured: ConfiguredParameters | None = None
    traffic: TrafficPrediction | None = None
    analysis_warnings: tuple[str, ...] = ()

    # --- availability ----------------------------------------------------
    @property
    def proposals(self) -> tuple[ProposalObservation, ...]:
        return self.ike_proposals + self.child_proposals

    @property
    def has_ike(self) -> bool:
        return bool(self.exchanges) or self.ike_packets > 0

    @property
    def has_esp(self) -> bool:
        return bool(self.esp_flows) or self.esp_packets > 0

    @property
    def spi_count(self) -> int:
        return self.sequence.distinct_spi

    @property
    def cleartext_proposals(self) -> bool:
        """Whether at least one SA payload was readable."""
        return bool(self.proposals)

    @property
    def ike_versions(self) -> tuple[int, ...]:
        return tuple(sorted({exchange.ike_version for exchange in self.exchanges if exchange.ike_version}))

    @property
    def selection_observable(self) -> bool:
        """Whether the *selected* proposal (not just the offered set) is visible.

        IKEv2 returns its choice inside an encrypted exchange, so this is false
        for every normal capture: an offer of three proposals proves that three
        were offered, not which one was used.
        """
        for exchange in self.exchanges:
            if exchange.exchange in {"IKE_SA_INIT", "IKEV1_EXCHANGE_1", "IKEV1_EXCHANGE_2"}:
                continue
            if exchange.proposal_count and not exchange.carries_encryption:
                return True
        return False

    # --- evidence-aware resolvers ---------------------------------------
    def effective_encryption(
        self, *, child: bool
    ) -> tuple[tuple[AlgorithmUse, ...], EvidenceStatus]:
        """Encryption algorithms in effect for one SA scope, with their evidence."""
        scope_proposals = self.child_proposals if child else self.ike_proposals
        observed = tuple(use for proposal in scope_proposals for use in proposal.encryption if use.name)
        if observed:
            return observed, EvidenceStatus.OBSERVED
        if self.configured is not None and self.configured.encryption:
            return (AlgorithmUse(name=self.configured.encryption),), EvidenceStatus.CONFIGURED
        return (), EvidenceStatus.NOT_VERIFIABLE

    def effective_integrity(self, *, child: bool) -> tuple[tuple[AlgorithmUse, ...], EvidenceStatus]:
        """Integrity algorithms in effect for one SA scope, with their evidence."""
        scope_proposals = self.child_proposals if child else self.ike_proposals
        observed = tuple(use for proposal in scope_proposals for use in proposal.integrity if use.name)
        if observed:
            return observed, EvidenceStatus.OBSERVED
        if self.configured is not None and self.configured.integrity:
            return (AlgorithmUse(name=self.configured.integrity),), EvidenceStatus.CONFIGURED
        return (), EvidenceStatus.NOT_VERIFIABLE

    def effective_prf(self) -> tuple[tuple[AlgorithmUse, ...], EvidenceStatus]:
        observed = tuple(use for proposal in self.ike_proposals for use in proposal.prf if use.name)
        if observed:
            return observed, EvidenceStatus.OBSERVED
        if self.configured is not None and self.configured.prf:
            return (AlgorithmUse(name=self.configured.prf),), EvidenceStatus.CONFIGURED
        return (), EvidenceStatus.NOT_VERIFIABLE

    def effective_dh_groups(self, *, child: bool) -> tuple[tuple[int | str, ...], EvidenceStatus]:
        """Negotiated DH groups for one SA scope, falling back to configuration."""
        scope_proposals = self.child_proposals if child else self.ike_proposals
        observed = sorted({group for proposal in scope_proposals for group in proposal.dh_groups})
        if observed:
            return tuple(observed), EvidenceStatus.OBSERVED
        if self.configured is not None:
            configured_group = self.configured.pfs_dh_group if child else self.configured.dh_group
            if configured_group is None and not child:
                configured_group = self.configured.dh_group
            if configured_group is not None:
                return (configured_group,), EvidenceStatus.CONFIGURED
        return (), EvidenceStatus.NOT_VERIFIABLE




    def effective_pfs(self) -> tuple[bool | None, EvidenceStatus]:
        """Whether CHILD_SA keys come from a fresh DH exchange, and how we know."""
        if self.pfs_status == "OBSERVED":
            return True, EvidenceStatus.OBSERVED
        if self.pfs_status == "DISABLED":
            return False, EvidenceStatus.OBSERVED
        if self.configured is not None and self.configured.pfs is not None:
            return self.configured.pfs, EvidenceStatus.CONFIGURED
        return None, EvidenceStatus.NOT_VERIFIABLE

    def effective_lifetime(self, scope: str) -> tuple[int | None, EvidenceStatus]:
        """SA lifetime in seconds.

        A passive capture never contains a lifetime: rekey time is a property of
        the endpoints, not of the packets, so without configuration the answer is
        deliberately ``NOT_VERIFIABLE`` rather than an inference from rekey
        intervals we do not have.
        """
        if self.configured is not None:
            value = (
                self.configured.child_sa_lifetime_s if scope == "child" else self.configured.ike_sa_lifetime_s
            )
            if value is not None:
                return value, EvidenceStatus.CONFIGURED
        return None, EvidenceStatus.NOT_VERIFIABLE

    def effective_replay_protection(self) -> tuple[bool | None, EvidenceStatus]:
        """Replay-window state; the receiving policy is invisible on the wire."""
        if self.configured is not None and self.configured.replay_protection is not None:
            return self.configured.replay_protection, EvidenceStatus.CONFIGURED
        return None, EvidenceStatus.NOT_VERIFIABLE

    def effective_ike_version(self) -> tuple[int | None, EvidenceStatus]:
        versions = self.ike_versions
        if versions:
            return versions[-1], EvidenceStatus.OBSERVED
        if self.configured is not None and self.configured.ike_version is not None:
            return self.configured.ike_version, EvidenceStatus.CONFIGURED
        return None, EvidenceStatus.NOT_VERIFIABLE

    def metadata_summary(self) -> dict[str, Any]:
        """Metadata an observer sees without decrypting anything.

        Everything here is counted from the capture (``OBSERVED``); the packet
        size and timing detail that the ML stage adds is only present when a
        prediction carrying its feature vector was supplied.
        """
        summary: dict[str, Any] = {
            "capture_packets": self.packets,
            "capture_bytes": int(self.scan.get("captured_bytes", 0) or 0),
            "ike_packets": self.ike_packets,
            "esp_packets": self.esp_packets,
            "esp_flows": len(self.esp_flows),
            "distinct_esp_spi": self.sequence.distinct_spi,
            "esp_bytes": sum(flow.bytes_total for flow in self.esp_flows),
            "largest_flow_packets": max((flow.packets for flow in self.esp_flows), default=0),
            "udp_encapsulated_flows": sum(1 for flow in self.esp_flows if flow.udp_encapsulated),
            "ipv4_packets": int(self.scan.get("ipv4_packets", 0) or 0),
            "ipv6_packets": int(self.scan.get("ipv6_packets", 0) or 0),
            "truncated_frames": int(self.scan.get("truncated_frames", 0) or 0),
            "source": "analysis.esp_flows+analysis.details.scan",
        }
        if self.traffic is not None and self.traffic.features:
            summary["ml_feature_sizes"] = {
                name: self.traffic.features[name]
                for name in ("esp_len_min", "esp_len_max", "esp_len_std", "esp_avg_len")
                if name in self.traffic.features
            }
            summary["ml_feature_timing"] = {
                name: self.traffic.features[name]
                for name in ("esp_iat_mean_s", "esp_iat_std_s", "esp_span_s")
                if name in self.traffic.features
            }
        return summary

    def to_dict(self) -> dict[str, Any]:
        """Serialise the inputs this assessment was built from (provenance)."""
        return {
            "analysis_id": self.analysis_id,
            "pcap_path": self.pcap_path,
            "method": self.method,
            "packets": self.packets,
            "ike_packets": self.ike_packets,
            "esp_packets": self.esp_packets,
            "ike_versions": list(self.ike_versions),
            "ike_proposals": [item.to_dict() for item in self.ike_proposals],
            "child_proposals": [item.to_dict() for item in self.child_proposals],
            "esp_flows": [item.to_dict() for item in self.esp_flows],
            "sequence": self.sequence.to_dict(),
            "pfs": {
                "status": self.pfs_status,
                "kind": self.pfs_evidence.value,
                "child_sa_dh_groups": list(self.pfs_child_dh_groups),
                "reason": self.pfs_reason,
            },
            "selection_observable": self.selection_observable,
            "configured": (self.configured.to_dict() if self.configured else None),
            "traffic": (self.traffic.to_dict() if self.traffic else None),
            "analysis_warnings": list(self.analysis_warnings),
        }

    @classmethod
    def from_analysis(
        cls,
        analysis: ProtocolAnalysis | Mapping[str, Any],
        *,
        traffic: TrafficPrediction | Mapping[str, Any] | str | Path | None = None,
        configured: ConfiguredParameters | Mapping[str, Any] | None = None,
        analysis_id: str | None = None,
    ) -> AssessmentContext:
        """Build an assessment context from one Prompt 2 analysis.

        ``traffic`` accepts a :class:`TrafficPrediction`, a prediction document,
        or a path to one; ``None`` is the normal case and simply means the
        metadata rules have no model output to grade.  ``configured`` accepts a
        testbed configuration document (or an ``ExperimentConfig``).
        """
        document = analysis.to_dict() if isinstance(analysis, ProtocolAnalysis) else dict(analysis)
        exchange_documents = _documents(document.get("ike_exchanges"), "ike_exchanges")
        proposals: list[ProposalObservation] = []
        for exchange_document in exchange_documents:
            for proposal_document in _documents(exchange_document.get("proposals"), "proposals"):
                proposals.append(_proposal_view(proposal_document, exchange_document))
        flows = tuple(_flow_view(item) for item in _documents(document.get("esp_flows"), "esp_flows"))
        esp_packets = _optional_int(document.get("esp_packets")) or 0
        details_block = document.get("details")
        details: Mapping[str, Any] = details_block if isinstance(details_block, Mapping) else {}
        scan_block = details.get("scan")
        scan: Mapping[str, Any] = scan_block if isinstance(scan_block, Mapping) else {}
        pfs_block: Any = details.get("pfs")
        if not isinstance(pfs_block, Mapping):
            pfs_block = document.get("pfs")
        pfs_document: Mapping[str, Any] = pfs_block if isinstance(pfs_block, Mapping) else {}
        pcap_path = str(document.get("pcap_path", ""))
        if isinstance(traffic, TrafficPrediction):
            prediction: TrafficPrediction | None = traffic
        elif traffic is None:
            prediction = None
        else:
            prediction = load_prediction(traffic)
        if prediction is None and isinstance(document, Mapping):
            embedded = document.get("ml")
            prediction = load_prediction(embedded) if isinstance(embedded, Mapping) else None
        if isinstance(configured, ConfiguredParameters):
            configuration = configured
        elif isinstance(configured, Mapping):
            configuration = ConfiguredParameters.from_document(configured)
        else:
            configuration = None
        return cls(
            analysis_id=(analysis_id or Path(pcap_path).stem or "unknown"),
            pcap_path=pcap_path,
            method=str(document.get("method", "")),
            packets=_optional_int(document.get("packets")) or 0,
            ike_packets=_optional_int(document.get("ike_packets")) or 0,
            esp_packets=esp_packets,
            exchanges=tuple(_exchange_view(item) for item in exchange_documents),
            ike_proposals=tuple(item for item in proposals if item.scope == IKE_SCOPE),
            child_proposals=tuple(item for item in proposals if item.scope in CHILD_SCOPES),
            esp_flows=flows,
            sequence=_sequence_view(flows, esp_packets),
            pfs_status=str(pfs_document.get("status", "NOT_VERIFIABLE")),
            pfs_evidence=status_from_evidence_kind(pfs_document.get("kind")),
            pfs_reason=str(pfs_document.get("reason", "")),
            pfs_child_dh_groups=_ints(pfs_document.get("child_sa_dh_groups")),
            scan=dict(scan),
            configured=configuration,
            traffic=prediction,
            analysis_warnings=tuple(str(item) for item in (document.get("warnings") or ())),
        )


__all__ = [
    "CHILD_SCOPES",
    "IKE_SCOPE",
    "PAYLOAD_ENCR",
    "PAYLOAD_SA",
    "AlgorithmUse",
    "AssessmentContext",
    "ConfiguredParameters",
    "ExchangeObservation",
    "EspFlowObservation",
    "ProposalObservation",
    "SequenceObservation",
]
