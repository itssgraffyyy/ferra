"""Common experiment schema.

An *experiment* is the unit of work of the FERA dataset factory: one IPsec
configuration + one traffic class + one capture.  The schema is validated
strictly, because everything downstream (capture, ground truth, later ML
stages) trusts it:

* impossible combinations are rejected (AES-GCM with a separate HMAC, AES-CBC
  without integrity, PFS contradictions, ...),
* testbed dependent combinations (transport mode with network selectors,
  IPv6 on a v4-only topology) are rejected in combination with the topology,
* identifiers are deterministic, so regenerating the matrix never reorders or
  renames existing experiments,
* unknown YAML fields are rejected instead of being silently ignored.

Labels are deliberately honest: ``email_like``, ``voip_like``, ``video_like``
and ``messaging_like`` describe *traffic that behaves like* those classes.
Nothing in this repository claims to capture real WhatsApp/Gmail/YouTube
traffic unless a real endpoint capture is added explicitly.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any

from ..common.errors import ConfigValidationError, ErrorCode, FeraError
from ..common.serialization import load_document, write_document
from ..testbed.algorithms import (
    DhGroup,
    EncryptionAlg,
    IntegrityAlg,
    TransformSet,
    build_transforms,
    resolve_dh_group,
    resolve_encryption,
    resolve_integrity,
)

#: Current schema version written into every experiment file.
SCHEMA_VERSION = 1
#: IKE versions supported by FERA (IKEv2 only - IKEv1 is out of scope).
SUPPORTED_IKE_VERSIONS: tuple[int, ...] = (2,)
#: Supported inner/outer IP versions.
SUPPORTED_IP_VERSIONS: tuple[int, ...] = (4, 6)
#: Experiment identifier pattern.
EXPERIMENT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
#: Maximum capture duration accepted by the schema (seconds).
MAX_CAPTURE_DURATION_S = 3600.0


class IpsecMode(str, Enum):
    """IPsec encapsulation mode."""

    TUNNEL = "tunnel"
    TRANSPORT = "transport"


class TrafficClass(str, Enum):
    """Traffic classes of the FERA dataset.

    ``control`` means "no application traffic": the capture contains IKE/ESP
    control traffic only (useful for later stages that need a negative class).
    """

    ICMP = "icmp"
    WEB = "web"
    EMAIL_LIKE = "email_like"
    VOIP_LIKE = "voip_like"
    VIDEO_LIKE = "video_like"
    MESSAGING_LIKE = "messaging_like"
    CONTROL = "control"

    @property
    def is_labelled_analogue(self) -> bool:
        """True for honestly-labelled *analogues* rather than real applications.

        These classes are synthetic models of an application class.  A real
        capture (e.g. actual WhatsApp traffic) would be added under its own
        label and is intentionally not part of this vocabulary.
        """
        return self in {
            TrafficClass.EMAIL_LIKE,
            TrafficClass.VOIP_LIKE,
            TrafficClass.VIDEO_LIKE,
            TrafficClass.MESSAGING_LIKE,
        }


#: Data traffic classes that the problem statement requires.
REQUIRED_TRAFFIC_CLASSES: tuple[TrafficClass, ...] = (
    TrafficClass.ICMP,
    TrafficClass.WEB,
    TrafficClass.EMAIL_LIKE,
    TrafficClass.VOIP_LIKE,
    TrafficClass.VIDEO_LIKE,
    TrafficClass.MESSAGING_LIKE,
)

#: Short names used inside deterministic experiment identifiers.
TRAFFIC_SLUGS: Mapping[TrafficClass, str] = {
    TrafficClass.ICMP: "icmp",
    TrafficClass.WEB: "web",
    TrafficClass.EMAIL_LIKE: "email",
    TrafficClass.VOIP_LIKE: "voip",
    TrafficClass.VIDEO_LIKE: "video",
    TrafficClass.MESSAGING_LIKE: "msg",
    TrafficClass.CONTROL: "ctl",
}

#: Short names for encryption algorithms inside identifiers.
ENCRYPTION_SLUGS: Mapping[EncryptionAlg, str] = {
    EncryptionAlg.AES128_GCM: "aes128gcm",
    EncryptionAlg.AES256_GCM: "aes256gcm",
    EncryptionAlg.AES128_CBC: "aes128cbc",
    EncryptionAlg.AES256_CBC: "aes256cbc",
}


def build_experiment_id(
    *,
    mode: IpsecMode | str,
    encryption: EncryptionAlg | str,
    dh_group: DhGroup | str,
    pfs: bool,
    ip_version: int,
    traffic_type: TrafficClass | str,
    index: int | None = None,
    salt: str = "",
) -> str:
    """Build a deterministic experiment identifier.

    Two strategies are supported:

    ``index`` given
        ``exp_<NNN>_<slug>`` - stable, readable, used by the matrix generator
        (the index is derived from the deterministically sorted matrix).
    ``index`` omitted
        ``exp_<slug>_<hash>`` - fully parameter derived, order independent.

    ``salt`` allows disambiguating otherwise identical parameter sets (for
    example a different ``pfs_dh_group``).
    """
    mode_value = IpsecMode(mode).value
    enc_value = ENCRYPTION_SLUGS[EncryptionAlg(encryption)]
    dh_value = resolve_dh_group(dh_group).value
    traffic_value = TRAFFIC_SLUGS[TrafficClass(traffic_type)]
    pfs_value = "pfson" if pfs else "pfsoff"
    slug = f"{mode_value}_{enc_value}_{dh_value}_{pfs_value}_ipv{ip_version}_{traffic_value}"
    if index is not None:
        if index < 0:
            raise ConfigValidationError("experiment index must not be negative")
        return f"exp_{index:03d}_{slug}"
    digest = hashlib.sha256(f"{slug}|{salt}".encode()).hexdigest()[:8]
    return f"exp_{slug}_{digest}"


@dataclass(frozen=True)
class ExperimentConfig:
    """A fully validated IPsec experiment definition."""

    experiment_id: str
    mode: IpsecMode
    encryption: EncryptionAlg
    integrity: IntegrityAlg
    dh_group: DhGroup
    pfs: bool
    ip_version: int
    traffic_type: TrafficClass
    capture_duration_s: float = 20.0
    ike_version: int = 2
    pfs_dh_group: DhGroup | None = None
    prf: str | None = None
    ike_sa_lifetime_s: int = 14400
    child_sa_lifetime_s: int = 3600
    capture_interface: str | None = None
    capture_filter: str | None = None
    traffic_port: int | None = None
    seed: int | None = None
    tags: tuple[str, ...] = ()
    notes: str = ""
    generated_by: str | None = None

    # -- validation -----------------------------------------------------
    def __post_init__(self) -> None:
        if not EXPERIMENT_ID_PATTERN.match(self.experiment_id):
            raise ConfigValidationError(
                f"invalid experiment id {self.experiment_id!r}",
                hint="use 3-64 characters of [a-z0-9_-], starting with a letter or digit",
                details={"experiment_id": self.experiment_id},
            )
        if self.ike_version not in SUPPORTED_IKE_VERSIONS:
            raise FeraError(
                f"IKE version {self.ike_version} is not supported",
                code=ErrorCode.UNSUPPORTED_FEATURE,
                hint="this project is IKEv2 only (ike_version: 2)",
                details={"ike_version": self.ike_version, "supported": list(SUPPORTED_IKE_VERSIONS)},
            )
        if self.ip_version not in SUPPORTED_IP_VERSIONS:
            raise ConfigValidationError(
                f"unsupported ip_version {self.ip_version!r}",
                hint="use 4 or 6",
                details={"ip_version": self.ip_version},
            )
        if not 0 < float(self.capture_duration_s) <= MAX_CAPTURE_DURATION_S:
            raise ConfigValidationError(
                f"capture_duration_s must be within (0, {MAX_CAPTURE_DURATION_S}]",
                details={"capture_duration_s": self.capture_duration_s},
            )
        for name in ("ike_sa_lifetime_s", "child_sa_lifetime_s"):
            value = getattr(self, name)
            if int(value) <= 0:
                raise ConfigValidationError(
                    f"{name} must be a positive number of seconds",
                    details={name: value},
                )
        if self.traffic_port is not None and not 1 <= int(self.traffic_port) <= 65535:
            raise ConfigValidationError(
                f"traffic_port out of range: {self.traffic_port}",
                details={"traffic_port": self.traffic_port},
            )
        if len(self.notes) > 2000:
            raise ConfigValidationError("notes must not exceed 2000 characters")
        if self.seed is not None and int(self.seed) < 0:
            raise ConfigValidationError("seed must be a non-negative integer")
        normalized_tags = tuple(sorted({str(tag).strip().lower() for tag in self.tags if str(tag).strip()}))
        object.__setattr__(self, "tags", normalized_tags)
        # Algorithm validation happens inside TransformSet (AEAD vs HMAC, PFS).
        _ = self.transforms
        if self.capture_filter is not None:
            from ..capture.filters import validate_bpf_filter

            validate_bpf_filter(self.capture_filter)

    # -- derived IPsec parameters ---------------------------------------
    @property
    def transforms(self) -> TransformSet:
        """Validated IKE_SA/CHILD_SA transform set of this experiment."""
        return build_transforms(
            self.encryption,
            self.integrity,
            dh_group=self.dh_group,
            pfs=self.pfs,
            pfs_dh_group=self.pfs_dh_group,
            prf=self.prf,
        )

    @property
    def ike_proposal(self) -> str:
        return self.transforms.ike_proposal

    @property
    def esp_proposal(self) -> str:
        return self.transforms.esp_proposal

    @property
    def effective_seed(self) -> int:
        """Deterministic seed used by traffic generators.

        Derived from the experiment id when the configuration does not pin one,
        so re-running an experiment reproduces the same traffic pattern.
        """
        if self.seed is not None:
            return int(self.seed)
        digest = hashlib.sha256(self.experiment_id.encode("utf-8")).digest()
        return int.from_bytes(digest[:4], "big") % (2**31 - 1)

    @property
    def mode_value(self) -> str:
        return self.mode.value

    def child_sa_life_time_s(self) -> int:
        """Hard lifetime of the CHILD_SA.

        ``child_sa_lifetime_s`` is the *rekey* time; the hard lifetime is set
        slightly above it so a rekey can complete before the SA expires (this
        mirrors strongSwan's ``rekey_time``/``life_time`` pair).
        """
        return int(self.child_sa_lifetime_s) + 3600


    # -- identity / serialisation ---------------------------------------
    def identity_dict(self) -> dict[str, Any]:
        """The parameters that define *which* experiment this is.

        Deliberately excludes ``experiment_id`` (so that the same parameter set
        is detected as a duplicate regardless of its ordinal index) and
        free-form fields such as ``notes`` and ``tags``.
        """
        return {
            "mode": self.mode.value,
            "ike_version": self.ike_version,
            "encryption": self.encryption.value,
            "integrity": self.integrity.value,
            "dh_group": self.dh_group.value,
            "pfs": bool(self.pfs),
            "pfs_dh_group": self.pfs_dh_group.value if self.pfs_dh_group else None,
            "prf": self.prf,
            "ip_version": self.ip_version,
            "traffic_type": self.traffic_type.value,
            "capture_duration_s": float(self.capture_duration_s),
            "ike_sa_lifetime_s": int(self.ike_sa_lifetime_s),
            "child_sa_lifetime_s": int(self.child_sa_lifetime_s),
            "capture_interface": self.capture_interface,
            "capture_filter": self.capture_filter,
            "traffic_port": self.traffic_port,
            "seed": self.seed,
        }

    @property
    def fingerprint(self) -> str:
        """Deterministic hash of :meth:`identity_dict` (duplicate detection)."""
        canonical = json.dumps(self.identity_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Serialise the experiment to a plain, stable, JSON/YAML friendly dict."""
        transforms = self.transforms
        return {
            "schema_version": SCHEMA_VERSION,
            "experiment_id": self.experiment_id,
            "fingerprint": self.fingerprint,
            "ipsec": {
                "mode": self.mode.value,
                "ike_version": self.ike_version,
                "encryption": self.encryption.value,
                "integrity": self.integrity.value,
                "integrity_source": transforms.to_dict()["integrity_source"],
                "dh_group": self.dh_group.value,
                "pfs": bool(self.pfs),
                "pfs_dh_group": self.pfs_dh_group.value if self.pfs_dh_group else None,
                "prf": self.prf,
                "ike_sa_lifetime_s": int(self.ike_sa_lifetime_s),
                "child_sa_lifetime_s": int(self.child_sa_lifetime_s),
                "ike_proposal": transforms.ike_proposal,
                "esp_proposal": transforms.esp_proposal,
            },
            "ip_version": self.ip_version,
            "traffic": {
                "type": self.traffic_type.value,
                "port": self.traffic_port,
                "capture_duration_s": float(self.capture_duration_s),
                "label_basis": (
                    "synthetic analogue of the named application class"
                    if self.traffic_type.is_labelled_analogue
                    else "synthetic control/measurement traffic"
                ),
            },
            "capture": {
                "interface": self.capture_interface,
                "filter": self.capture_filter,
            },
            "reproducibility": {
                "seed": self.seed,
                "effective_seed": self.effective_seed,
                "generated_by": self.generated_by,
            },
            "tags": list(self.tags),
            "notes": self.notes,
        }

    def to_yaml(self) -> str:
        from ..common.serialization import dump_yaml

        return dump_yaml(self.to_dict())

    def summary(self) -> str:
        """One line human readable summary (used by CLIs)."""
        transforms = self.transforms
        return (
            f"{self.experiment_id}: {self.mode.value}/IKEv{self.ike_version} "
            f"{self.encryption.value}+{self.integrity.value} "
            f"dh={self.dh_group.value} pfs={'on' if self.pfs else 'off'} "
            f"ipv{self.ip_version} traffic={self.traffic_type.value} "
            f"({self.capture_duration_s:g}s) ike={transforms.ike_proposal} esp={transforms.esp_proposal}"
        )

    def with_updates(self, **changes: Any) -> ExperimentConfig:
        """Return a validated copy with ``changes`` applied."""
        return replace(self, **changes)


_TOP_LEVEL_KEYS = {
    "schema_version",
    "experiment_id",
    "fingerprint",
    "ipsec",
    "ip_version",
    "traffic",
    "capture",
    "reproducibility",
    "tags",
    "notes",
}
_IPSEC_KEYS = {
    "mode",
    "ike_version",
    "encryption",
    "integrity",
    "integrity_source",
    "dh_group",
    "pfs",
    "pfs_dh_group",
    "prf",
    "ike_sa_lifetime_s",
    "child_sa_lifetime_s",
    "ike_proposal",
    "esp_proposal",
}
_TRAFFIC_KEYS = {"type", "port", "capture_duration_s", "label_basis"}
_CAPTURE_KEYS = {"interface", "filter"}
_REPRO_KEYS = {"seed", "effective_seed", "generated_by"}


def _mapping(value: Any, *, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigValidationError(f"{context} must be a mapping", details={"got": type(value).__name__})
    return value


def _strict_keys(data: Mapping[str, Any], allowed: set[str], *, context: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigValidationError(
            f"{context} contains unknown field(s): {', '.join(unknown)}",
            hint=f"allowed fields: {', '.join(sorted(allowed))}",
            details={"unknown": unknown, "allowed": sorted(allowed)},
        )


def experiment_from_dict(data: Mapping[str, Any], *, verify_derived: bool = True) -> ExperimentConfig:
    """Build an :class:`ExperimentConfig` from a mapping, rejecting unknown fields.

    When ``verify_derived`` is true (the default) the derived fields stored in
    the document (proposal strings, fingerprint, effective seed) must match the
    values recomputed from the parameters.  A mismatch means somebody edited a
    generated file by hand or the schema drifted, and is reported instead of
    being silently accepted.
    """
    document = _mapping(data, context="experiment document")
    _strict_keys(document, _TOP_LEVEL_KEYS, context="experiment document")
    ipsec = _mapping(document.get("ipsec"), context="ipsec section")
    _strict_keys(ipsec, _IPSEC_KEYS, context="ipsec section")
    traffic = _mapping(document.get("traffic"), context="traffic section")
    _strict_keys(traffic, _TRAFFIC_KEYS, context="traffic section")
    capture = _mapping(document.get("capture", {}), context="capture section")
    _strict_keys(capture, _CAPTURE_KEYS, context="capture section")
    reproducibility = _mapping(document.get("reproducibility", {}), context="reproducibility section")
    _strict_keys(reproducibility, _REPRO_KEYS, context="reproducibility section")

    experiment_id = document.get("experiment_id")
    if not experiment_id:
        raise ConfigValidationError("experiment document is missing 'experiment_id'")
    if not traffic.get("type"):
        raise ConfigValidationError("experiment document is missing 'traffic.type'")
    for required in ("mode", "encryption", "integrity", "dh_group", "pfs"):
        if required not in ipsec:
            raise ConfigValidationError(f"experiment document is missing 'ipsec.{required}'")

    config = ExperimentConfig(
        experiment_id=str(experiment_id),
        mode=IpsecMode(str(ipsec["mode"])),
        encryption=resolve_encryption(ipsec["encryption"]),
        integrity=resolve_integrity(ipsec["integrity"]),
        dh_group=resolve_dh_group(ipsec["dh_group"]),
        pfs=bool(ipsec["pfs"]),
        ip_version=int(document.get("ip_version", 4)),
        traffic_type=TrafficClass(str(traffic["type"])),
        capture_duration_s=float(traffic.get("capture_duration_s", 20.0)),
        ike_version=int(ipsec.get("ike_version", 2)),
        pfs_dh_group=resolve_dh_group(ipsec["pfs_dh_group"]) if ipsec.get("pfs_dh_group") else None,
        prf=ipsec.get("prf"),
        ike_sa_lifetime_s=int(ipsec.get("ike_sa_lifetime_s", 14400)),
        child_sa_lifetime_s=int(ipsec.get("child_sa_lifetime_s", 3600)),
        capture_interface=capture.get("interface"),
        capture_filter=capture.get("filter"),
        traffic_port=int(traffic["port"]) if traffic.get("port") is not None else None,
        seed=int(reproducibility["seed"]) if reproducibility.get("seed") is not None else None,
        tags=tuple(document.get("tags") or ()),
        notes=str(document.get("notes") or ""),
        generated_by=reproducibility.get("generated_by"),
    )
    if verify_derived:
        mismatches: dict[str, Any] = {}
        if document.get("fingerprint") and document["fingerprint"] != config.fingerprint:
            mismatches["fingerprint"] = {"in_file": document["fingerprint"], "recomputed": config.fingerprint}
        for key, actual in (
            ("ike_proposal", config.ike_proposal),
            ("esp_proposal", config.esp_proposal),
        ):
            if ipsec.get(key) and ipsec[key] != actual:
                mismatches[key] = {"in_file": ipsec[key], "recomputed": actual}
        if reproducibility.get("effective_seed") is not None and int(
            reproducibility["effective_seed"]
        ) != config.effective_seed:
            mismatches["effective_seed"] = {
                "in_file": reproducibility["effective_seed"],
                "recomputed": config.effective_seed,
            }
        if mismatches:
            raise ConfigValidationError(
                "derived fields in the experiment document do not match the configured parameters "
                "(file edited by hand, or written by an incompatible FERA version)",
                hint="regenerate the file with scripts/generate_experiment_matrix.py",
                details={"mismatches": mismatches},
            )
    return config


def load_experiment(path: str | Path, *, verify_derived: bool = True) -> ExperimentConfig:
    """Load and validate an experiment definition from YAML or JSON."""
    document = load_document(Path(path))
    return experiment_from_dict(document, verify_derived=verify_derived)


def save_experiment(config: ExperimentConfig, path: str | Path) -> Path:
    """Write an experiment definition (YAML by default, JSON for ``.json``)."""
    return write_document(Path(path), config.to_dict())


def find_experiment_configs(directory: str | Path) -> list[Path]:
    """Return all experiment files of a directory, sorted by name.

    Files whose name starts with ``_`` are generator artefacts (matrix index,
    summaries) and are ignored, as are non-YAML/JSON files.
    """
    base = Path(directory)
    if not base.exists():
        return []
    files = [
        path
        for path in base.iterdir()
        if path.is_file()
        and not path.name.startswith("_")
        and path.suffix.lower() in {".yaml", ".yml", ".json"}
    ]
    return sorted(files, key=lambda path: path.name)


def check_topology_compatibility(config: ExperimentConfig, topology: Any) -> list[str]:
    """Return a list of reasons why ``config`` cannot run on ``topology``."""
    problems: list[str] = []
    if not topology.supports_ip_version(config.ip_version):
        problems.append(
            f"topology {topology.name!r} has no IPv{config.ip_version} addresses on both endpoints"
        )
    try:
        selectors = topology.selectors(config.mode_value, config.ip_version)
    except ConfigValidationError as exc:
        problems.append(exc.message)
        return problems
    if config.mode is IpsecMode.TRANSPORT and not selectors.host_to_host:
        problems.append(
            "transport mode requires host traffic selectors "
            f"(got local_ts={selectors.local_ts}, remote_ts={selectors.remote_ts})"
        )
    if config.mode is IpsecMode.TUNNEL and selectors.host_to_host:
        problems.append("tunnel mode with host-only selectors would not exercise encapsulation of a subnet")
    return problems


def require_topology_compatibility(config: ExperimentConfig, topology: Any) -> None:
    """Raise :class:`ConfigValidationError` when the topology cannot run the config."""
    problems = check_topology_compatibility(config, topology)
    if problems:
        raise ConfigValidationError(
            f"experiment {config.experiment_id!r} is not runnable on topology {topology.name!r}: "
            + "; ".join(problems),
            hint="fix the experiment parameters or the topology definition",
            details={"problems": problems, "topology": topology.name},
        )


__all__ = [
    "ENCRYPTION_SLUGS",
    "EXPERIMENT_ID_PATTERN",
    "MAX_CAPTURE_DURATION_S",
    "REQUIRED_TRAFFIC_CLASSES",
    "SCHEMA_VERSION",
    "SUPPORTED_IKE_VERSIONS",
    "SUPPORTED_IP_VERSIONS",
    "TRAFFIC_SLUGS",
    "ExperimentConfig",
    "IpsecMode",
    "TrafficClass",
    "build_experiment_id",
    "check_topology_compatibility",
    "experiment_from_dict",
    "find_experiment_configs",
    "load_experiment",
    "require_topology_compatibility",
    "save_experiment",
]




