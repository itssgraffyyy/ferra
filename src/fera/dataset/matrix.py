"""Representative experiment matrix and PS coverage verification.

Why a *representative* matrix and not the full Cartesian product?  The full
product of mode x encryption x integrity x DH group x PFS x IP version x
traffic class is in the thousands of captures - far more than a hackathon
timeline allows.  Instead the matrix is a curated set of experiments that
*collectively* demonstrates every dimension the problem statement demands,
while keeping single-parameter changes explicit:

* tunnel and transport mode, each with both cipher families,
* AEAD (AES-GCM) and non-AEAD (AES-CBC + HMAC) encryption, both key sizes,
* three DH/ECDH key exchange groups,
* PFS enabled and disabled, including a pair that differs *only* in PFS,
* IPv4 and IPv6,
* all six required traffic classes.

Every requirement is *computed* from the generated configurations by
:func:`check_coverage` - nothing in the coverage report is hard-coded, so the
matrix cannot drift away from the claim.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from ..testbed.algorithms import DhGroup, EncryptionAlg, IntegrityAlg
from .schema import (
    REQUIRED_TRAFFIC_CLASSES,
    ExperimentConfig,
    IpsecMode,
    TrafficClass,
    build_experiment_id,
)

DEFAULT_CAPTURE_DURATION_S = 20.0


@dataclass(frozen=True)
class MatrixEntry:
    """One row of the curated experiment matrix."""

    mode: IpsecMode
    encryption: EncryptionAlg
    integrity: IntegrityAlg
    dh_group: DhGroup
    pfs: bool
    ip_version: int
    traffic_type: TrafficClass
    pfs_dh_group: DhGroup | None = None
    capture_duration_s: float = DEFAULT_CAPTURE_DURATION_S
    ike_sa_lifetime_s: int = 14400
    child_sa_lifetime_s: int = 3600
    tags: tuple[str, ...] = ()
    notes: str = ""

    def to_kwargs(self) -> dict[str, Any]:
        """Return :class:`ExperimentConfig` keyword arguments (without the id)."""
        return {
            "mode": self.mode,
            "encryption": self.encryption,
            "integrity": self.integrity,
            "dh_group": self.dh_group,
            "pfs": self.pfs,
            "ip_version": self.ip_version,
            "traffic_type": self.traffic_type,
            "pfs_dh_group": self.pfs_dh_group,
            "capture_duration_s": self.capture_duration_s,
            "ike_sa_lifetime_s": self.ike_sa_lifetime_s,
            "child_sa_lifetime_s": self.child_sa_lifetime_s,
            "tags": self.tags,
            "notes": self.notes,
        }


#: Curated, deterministic matrix (order defines the ordinal experiment index).
MATRIX_ENTRIES: tuple[MatrixEntry, ...] = (
    # -- tunnel mode ----------------------------------------------------
    MatrixEntry(
        IpsecMode.TUNNEL,
        EncryptionAlg.AES128_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP256,
        True,
        4,
        TrafficClass.ICMP,
        tags=("baseline", "aead"),
        notes="baseline: IKEv2 tunnel, AES-128-GCM, ECDH P-256, PFS on, IPv4, ICMP",
    ),
    MatrixEntry(
        IpsecMode.TUNNEL,
        EncryptionAlg.AES256_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP384,
        True,
        4,
        TrafficClass.WEB,
        tags=("aead",),
        notes="tunnel, AES-256-GCM, ECDH P-384, PFS on, IPv4, web traffic",
    ),
    MatrixEntry(
        IpsecMode.TUNNEL,
        EncryptionAlg.AES128_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP256,
        False,
        4,
        TrafficClass.ICMP,
        tags=("pfs-off", "aead"),
        notes="PFS disabled (no DH group in the ESP proposal), otherwise identical to the baseline",
    ),
    MatrixEntry(
        IpsecMode.TUNNEL,
        EncryptionAlg.AES128_CBC,
        IntegrityAlg.HMAC_SHA256,
        DhGroup.MODP3072,
        True,
        4,
        TrafficClass.ICMP,
        tags=("cbc", "hmac"),
        notes="AES-128-CBC + HMAC-SHA-256, MODP-3072, PFS on, IPv4",
    ),
    MatrixEntry(
        IpsecMode.TUNNEL,
        EncryptionAlg.AES256_CBC,
        IntegrityAlg.HMAC_SHA384,
        DhGroup.ECP384,
        True,
        4,
        TrafficClass.VIDEO_LIKE,
        tags=("cbc", "hmac"),
        notes="AES-256-CBC + HMAC-SHA-384, ECDH P-384, PFS on, IPv4, video-like flow",
    ),
    MatrixEntry(
        IpsecMode.TUNNEL,
        EncryptionAlg.AES256_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP384,
        True,
        6,
        TrafficClass.ICMP,
        tags=("aead", "ipv6"),
        notes="IPv6 tunnel (IPv6 outer and inner), AES-256-GCM, PFS on",
    ),
    MatrixEntry(
        IpsecMode.TUNNEL,
        EncryptionAlg.AES128_CBC,
        IntegrityAlg.HMAC_SHA256,
        DhGroup.MODP3072,
        False,
        6,
        TrafficClass.MESSAGING_LIKE,
        tags=("cbc", "hmac", "ipv6", "pfs-off"),
        notes="IPv6 tunnel, AES-128-CBC + HMAC-SHA-256, PFS off, messaging-like bursts",
    ),
    MatrixEntry(
        IpsecMode.TUNNEL,
        EncryptionAlg.AES256_CBC,
        IntegrityAlg.HMAC_SHA512,
        DhGroup.MODP3072,
        True,
        4,
        TrafficClass.EMAIL_LIKE,
        tags=("cbc", "hmac"),
        notes="AES-256-CBC + HMAC-SHA-512, MODP-3072, email-like sessions",
    ),
    MatrixEntry(
        IpsecMode.TUNNEL,
        EncryptionAlg.AES128_GCM,
        IntegrityAlg.AEAD,
        DhGroup.CURVE25519,
        True,
        4,
        TrafficClass.MESSAGING_LIKE,
        tags=("aead", "dh-optional"),
        notes=(
            "X25519 key exchange (IANA group 31).  Old strongSwan builds reject the keyword; the "
            "runner surfaces that error instead of pretending the experiment worked."
        ),
    ),
    # -- transport mode -------------------------------------------------
    MatrixEntry(
        IpsecMode.TRANSPORT,
        EncryptionAlg.AES128_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP256,
        True,
        4,
        TrafficClass.ICMP,
        tags=("transport", "aead"),
        notes="transport mode, host selectors only, AES-128-GCM, PFS on, IPv4",
    ),
    MatrixEntry(
        IpsecMode.TRANSPORT,
        EncryptionAlg.AES256_CBC,
        IntegrityAlg.HMAC_SHA512,
        DhGroup.ECP384,
        True,
        4,
        TrafficClass.EMAIL_LIKE,
        tags=("transport", "cbc", "hmac"),
        notes="transport mode, AES-256-CBC + HMAC-SHA-512, PFS on, IPv4",
    ),
    MatrixEntry(
        IpsecMode.TRANSPORT,
        EncryptionAlg.AES256_GCM,
        IntegrityAlg.AEAD,
        DhGroup.MODP3072,
        True,
        6,
        TrafficClass.VOIP_LIKE,
        tags=("transport", "aead", "ipv6"),
        notes="IPv6 transport mode, AES-256-GCM, MODP-3072, PFS on, VoIP-like flow",
    ),
    MatrixEntry(
        IpsecMode.TRANSPORT,
        EncryptionAlg.AES128_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP256,
        False,
        6,
        TrafficClass.WEB,
        tags=("transport", "aead", "ipv6", "pfs-off"),
        notes="IPv6 transport mode, PFS off, web traffic",
    ),
    MatrixEntry(
        IpsecMode.TRANSPORT,
        EncryptionAlg.AES256_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP384,
        True,
        4,
        TrafficClass.VOIP_LIKE,
        tags=("transport", "aead"),
        notes="transport mode, AES-256-GCM, ECDH P-384, VoIP-like flow",
    ),
    MatrixEntry(
        IpsecMode.TRANSPORT,
        EncryptionAlg.AES128_CBC,
        IntegrityAlg.HMAC_SHA256,
        DhGroup.ECP256,
        False,
        4,
        TrafficClass.VIDEO_LIKE,
        tags=("transport", "cbc", "hmac", "pfs-off"),
        notes="transport mode, AES-128-CBC + HMAC-SHA-256, PFS off, video-like flow",
    ),
    # -- crossed traffic classes ----------------------------------------
    # Every configuration above is repeated once with a *different* traffic
    # class, so configuration and traffic class are not collinear: each
    # configuration carries two classes and each class is spread over several
    # configurations.  Without this, a classifier could score well by
    # recognising the IPsec configuration instead of the traffic
    # ("all web = GCM, all video = CBC").  Verified by the config_traffic_cross
    # and traffic_config_cross checks in check_coverage().
    MatrixEntry(  # exp_000 parameters, web instead of ICMP
        IpsecMode.TUNNEL,
        EncryptionAlg.AES128_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP256,
        True,
        4,
        TrafficClass.WEB,
        tags=("aead", "crossed"),
        notes="crossed: exp_000's parameters with web traffic instead of ICMP",
    ),
    MatrixEntry(  # exp_001 parameters, video-like instead of web
        IpsecMode.TUNNEL,
        EncryptionAlg.AES256_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP384,
        True,
        4,
        TrafficClass.VIDEO_LIKE,
        tags=("aead", "crossed"),
        notes="crossed: exp_001's parameters with video-like traffic instead of web",
    ),
    MatrixEntry(  # exp_002 parameters, email-like instead of ICMP
        IpsecMode.TUNNEL,
        EncryptionAlg.AES128_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP256,
        False,
        4,
        TrafficClass.EMAIL_LIKE,
        tags=("pfs_off", "aead", "crossed"),
        notes="crossed: exp_002's parameters with email-like traffic instead of ICMP",
    ),
    MatrixEntry(  # exp_003 parameters, VoIP-like instead of ICMP
        IpsecMode.TUNNEL,
        EncryptionAlg.AES128_CBC,
        IntegrityAlg.HMAC_SHA256,
        DhGroup.MODP3072,
        True,
        4,
        TrafficClass.VOIP_LIKE,
        tags=("cbc", "crossed"),
        notes="crossed: exp_003's parameters with VoIP-like traffic instead of ICMP",
    ),
    MatrixEntry(  # exp_004 parameters, web instead of video-like
        IpsecMode.TUNNEL,
        EncryptionAlg.AES256_CBC,
        IntegrityAlg.HMAC_SHA384,
        DhGroup.ECP384,
        True,
        4,
        TrafficClass.WEB,
        tags=("cbc", "crossed"),
        notes="crossed: exp_004's parameters with web traffic instead of video-like",
    ),
    MatrixEntry(  # exp_005 parameters, messaging-like instead of ICMP
        IpsecMode.TUNNEL,
        EncryptionAlg.AES256_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP384,
        True,
        6,
        TrafficClass.MESSAGING_LIKE,
        tags=("aead", "crossed"),
        notes="crossed: exp_005's parameters with messaging-like traffic instead of ICMP",
    ),
    MatrixEntry(  # exp_006 parameters, video-like instead of messaging-like
        IpsecMode.TUNNEL,
        EncryptionAlg.AES128_CBC,
        IntegrityAlg.HMAC_SHA256,
        DhGroup.MODP3072,
        False,
        6,
        TrafficClass.VIDEO_LIKE,
        tags=("pfs_off", "cbc", "crossed"),
        notes="crossed: exp_006's parameters with video-like traffic instead of messaging-like",
    ),
    MatrixEntry(  # exp_007 parameters, ICMP instead of email-like
        IpsecMode.TUNNEL,
        EncryptionAlg.AES256_CBC,
        IntegrityAlg.HMAC_SHA512,
        DhGroup.MODP3072,
        True,
        4,
        TrafficClass.ICMP,
        tags=("cbc", "crossed"),
        notes="crossed: exp_007's parameters with ICMP instead of email-like traffic",
    ),

    MatrixEntry(  # exp_008 parameters, email-like instead of messaging-like
        IpsecMode.TUNNEL,
        EncryptionAlg.AES128_GCM,
        IntegrityAlg.AEAD,
        DhGroup.CURVE25519,
        True,
        4,
        TrafficClass.EMAIL_LIKE,
        tags=("aead", "crossed"),
        notes="crossed: exp_008's parameters with email-like traffic instead of messaging-like",
    ),
    MatrixEntry(  # exp_009 parameters, VoIP-like instead of ICMP
        IpsecMode.TRANSPORT,
        EncryptionAlg.AES128_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP256,
        True,
        4,
        TrafficClass.VOIP_LIKE,
        tags=("aead", "crossed"),
        notes="crossed: exp_009's parameters with VoIP-like traffic instead of ICMP",
    ),
    MatrixEntry(  # exp_010 parameters, video-like instead of email-like
        IpsecMode.TRANSPORT,
        EncryptionAlg.AES256_CBC,
        IntegrityAlg.HMAC_SHA512,
        DhGroup.ECP384,
        True,
        4,
        TrafficClass.VIDEO_LIKE,
        tags=("cbc", "crossed"),
        notes="crossed: exp_010's parameters with video-like traffic instead of email-like",
    ),
    MatrixEntry(  # exp_011 parameters, web instead of VoIP-like
        IpsecMode.TRANSPORT,
        EncryptionAlg.AES256_GCM,
        IntegrityAlg.AEAD,
        DhGroup.MODP3072,
        True,
        6,
        TrafficClass.WEB,
        tags=("aead", "crossed"),
        notes="crossed: exp_011's parameters with web traffic instead of VoIP-like",
    ),
    MatrixEntry(  # exp_012 parameters, messaging-like instead of web
        IpsecMode.TRANSPORT,
        EncryptionAlg.AES128_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP256,
        False,
        6,
        TrafficClass.MESSAGING_LIKE,
        tags=("pfs_off", "aead", "crossed"),
        notes="crossed: exp_012's parameters with messaging-like traffic instead of web",
    ),
    MatrixEntry(  # exp_013 parameters, email-like instead of VoIP-like
        IpsecMode.TRANSPORT,
        EncryptionAlg.AES256_GCM,
        IntegrityAlg.AEAD,
        DhGroup.ECP384,
        True,
        4,
        TrafficClass.EMAIL_LIKE,
        tags=("aead", "crossed"),
        notes="crossed: exp_013's parameters with email-like traffic instead of VoIP-like",
    ),
    MatrixEntry(  # exp_014 parameters, messaging-like instead of video-like
        IpsecMode.TRANSPORT,
        EncryptionAlg.AES128_CBC,
        IntegrityAlg.HMAC_SHA256,
        DhGroup.ECP256,
        False,
        4,
        TrafficClass.MESSAGING_LIKE,
        tags=("pfs_off", "cbc", "crossed"),
        notes="crossed: exp_014's parameters with messaging-like traffic instead of video-like",
    ),

)


@dataclass(frozen=True)
class CoverageCheck:
    """One verified problem-statement requirement."""

    key: str
    label: str
    passed: bool
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "label": self.label, "passed": self.passed, "evidence": self.evidence}


def build_matrix(
    entries: Sequence[MatrixEntry] | None = None,
    *,
    id_style: str = "ordinal",
    capture_duration_s: float | None = None,
    tag: str | None = None,
    generated_by: str = "scripts/generate_experiment_matrix.py",
) -> list[ExperimentConfig]:
    """Turn the curated matrix into validated experiment configurations.

    ``id_style`` selects how experiment ids are derived: ``"ordinal"`` gives
    readable, position based ids (``exp_000_...``), ``"hash"`` gives purely
    parameter derived ids.  Both are deterministic.
    """
    rows = list(entries if entries is not None else MATRIX_ENTRIES)
    if id_style not in {"ordinal", "hash"}:
        raise ValueError(f"unsupported id_style: {id_style!r} (use 'ordinal' or 'hash')")
    configs: list[ExperimentConfig] = []
    for index, entry in enumerate(rows):
        experiment_id = build_experiment_id(
            mode=entry.mode,
            encryption=entry.encryption,
            dh_group=entry.dh_group,
            pfs=entry.pfs,
            ip_version=entry.ip_version,
            traffic_type=entry.traffic_type,
            index=index if id_style == "ordinal" else None,
            salt=entry.pfs_dh_group.value if entry.pfs_dh_group else "",
        )
        kwargs = entry.to_kwargs()
        if capture_duration_s is not None:
            kwargs["capture_duration_s"] = capture_duration_s
        if tag:
            kwargs["tags"] = (*kwargs["tags"], tag)
        configs.append(
            ExperimentConfig(
                experiment_id=experiment_id,
                generated_by=generated_by,
                **kwargs,
            )
        )
    return configs


def _example(configs: Sequence[ExperimentConfig], predicate: Callable[[ExperimentConfig], bool]) -> str:
    matches = [config.experiment_id for config in configs if predicate(config)]
    return f"{len(matches)} experiment(s), e.g. {matches[0]}" if matches else "none"


def configuration_key(config: ExperimentConfig) -> tuple[Any, ...]:
    """Identity of a *configuration*: every parameter except the traffic class.

    Mirrors ``fera.experiment.dryrun._configuration_id`` so the coverage report
    and the dry run group experiments the same way.  Leaving the traffic class
    out of the key is what makes "one configuration, several traffic classes" a
    property the checker can state and verify.
    """
    return (
        config.mode,
        config.encryption,
        config.integrity,
        config.dh_group,
        bool(config.pfs),
        int(config.ip_version),
    )


def check_coverage(
    configs: Sequence[ExperimentConfig],
    *,
    required_traffic_classes: Sequence[TrafficClass] = REQUIRED_TRAFFIC_CLASSES,
) -> list[CoverageCheck]:
    """Compute which problem-statement dimensions the configurations cover."""
    configs = list(configs)
    checks: list[CoverageCheck] = []

    def add(key: str, label: str, passed: bool, evidence: str) -> None:
        checks.append(CoverageCheck(key=key, label=label, passed=bool(passed), evidence=evidence))

    tunnel = [c for c in configs if c.mode is IpsecMode.TUNNEL]
    transport = [c for c in configs if c.mode is IpsecMode.TRANSPORT]
    add(
        "mode_tunnel",
        "Tunnel Mode",
        bool(tunnel),
        _example(configs, lambda c: c.mode is IpsecMode.TUNNEL),
    )
    add(
        "mode_transport",
        "Transport Mode",
        bool(transport),
        _example(configs, lambda c: c.mode is IpsecMode.TRANSPORT),
    )
    aes128 = [c for c in configs if c.encryption in {EncryptionAlg.AES128_GCM, EncryptionAlg.AES128_CBC}]
    aes256 = [c for c in configs if c.encryption in {EncryptionAlg.AES256_GCM, EncryptionAlg.AES256_CBC}]
    add("enc_aes128", "AES-128 (GCM and CBC)", bool(aes128), _example(configs, lambda c: c.encryption in {EncryptionAlg.AES128_GCM, EncryptionAlg.AES128_CBC}))
    add("enc_aes256", "AES-256 (GCM and CBC)", bool(aes256), _example(configs, lambda c: c.encryption in {EncryptionAlg.AES256_GCM, EncryptionAlg.AES256_CBC}))

    aead = [c for c in configs if c.transforms.aead]
    cbc = [c for c in configs if not c.transforms.aead]
    add("enc_gcm", "AES-GCM (AEAD)", bool(aead), _example(configs, lambda c: c.transforms.aead))
    add("enc_cbc_hmac", "AES-CBC + HMAC", bool(cbc), _example(configs, lambda c: not c.transforms.aead))

    aead_with_hmac = [c for c in configs if c.transforms.aead and c.integrity.is_hmac]
    add(
        "aead_without_separate_hmac",
        "AES-GCM never paired with a separate HMAC",
        not aead_with_hmac and bool(aead),
        (
            "no AEAD experiment configures a separate integrity transform"
            if not aead_with_hmac
            else f"INVALID: {[c.experiment_id for c in aead_with_hmac]}"
        ),
    )
    cbc_without_hmac = [c for c in configs if not c.transforms.aead and not c.integrity.is_hmac]
    add(
        "cbc_requires_hmac",
        "AES-CBC always carries an integrity transform",
        not cbc_without_hmac and bool(cbc),
        (
            "every CBC experiment has HMAC-SHA-256/384/512"
            if not cbc_without_hmac
            else f"INVALID: {[c.experiment_id for c in cbc_without_hmac]}"
        ),
    )

    groups = {c.dh_group for c in configs}
    add(
        "dh_groups",
        "Multiple DH/ECDH groups (>= 3)",
        len(groups) >= 3,
        f"{len(groups)} distinct group(s): {', '.join(sorted(group.value for group in groups))}",
    )
    pfs_on = [c for c in configs if c.pfs]
    pfs_off = [c for c in configs if not c.pfs]
    add("pfs_enabled", "PFS enabled", bool(pfs_on), _example(configs, lambda c: c.pfs))
    add("pfs_disabled", "PFS disabled", bool(pfs_off), _example(configs, lambda c: not c.pfs))

    def identity_without_pfs(config: ExperimentConfig) -> dict[str, Any]:
        identity = config.identity_dict()
        identity.pop("pfs", None)
        return identity

    pfs_pairs: list[str] = []
    for index, config in enumerate(configs):
        for other in configs[index + 1 :]:
            if identity_without_pfs(config) == identity_without_pfs(other) and config.pfs != other.pfs:
                pfs_pairs.append(f"{config.experiment_id} vs {other.experiment_id}")
    add(
        "pfs_isolated",
        "PFS on/off compared on an otherwise identical configuration",
        bool(pfs_pairs),
        f"{len(pfs_pairs)} pair(s): {pfs_pairs[0] if pfs_pairs else 'none'}",
    )

    ipv4 = [c for c in configs if c.ip_version == 4]
    ipv6 = [c for c in configs if c.ip_version == 6]
    add("ipv4", "IPv4", bool(ipv4), _example(configs, lambda c: c.ip_version == 4))
    add("ipv6", "IPv6", bool(ipv6), _example(configs, lambda c: c.ip_version == 6))

    for traffic_class in required_traffic_classes:
        present = [c for c in configs if c.traffic_type is traffic_class]
        def _has_traffic(c: ExperimentConfig, tc: TrafficClass = traffic_class) -> bool:
            return c.traffic_type is tc

        add(
            f"traffic_{traffic_class.value}",
            f"Traffic class: {traffic_class.value}",
            bool(present),
            _example(configs, _has_traffic),
        )

    algorithms = {c.encryption for c in configs}
    add(
        "all_encryption_algorithms",
        "Every encryption algorithm represented",
        len(algorithms) == len(EncryptionAlg),
        f"{len(algorithms)}/{len(EncryptionAlg)}: {', '.join(sorted(algorithm.value for algorithm in algorithms))}",
    )
    combos = {(c.mode.value, "gcm" if c.transforms.aead else "cbc") for c in configs}
    add(
        "mode_cipher_cross",
        "Mode x cipher family cross coverage (4 combinations)",
        len(combos) == 4,
        f"{len(combos)}/4 combinations: {sorted(combos)}",
    )
    # -- configuration and traffic class must not be collinear -------------
    # If every configuration carried exactly one traffic class, a classifier
    # could score well by recognising the IPsec configuration rather than the
    # traffic ("all web = GCM, all video = CBC").  Both directions are checked.
    by_configuration: dict[tuple[Any, ...], set[TrafficClass]] = {}
    by_traffic: dict[TrafficClass, set[tuple[Any, ...]]] = {}
    for config in configs:
        key = configuration_key(config)
        by_configuration.setdefault(key, set()).add(config.traffic_type)
        by_traffic.setdefault(config.traffic_type, set()).add(key)

    single_class = [key for key, classes in by_configuration.items() if len(classes) < 2]
    add(
        "config_traffic_cross",
        "Every configuration runs more than one traffic class",
        bool(by_configuration) and not single_class,
        (
            f"{len(by_configuration) - len(single_class)}/{len(by_configuration)} "
            "configurations carry 2+ traffic classes"
            if by_configuration
            else "none"
        ),
    )

    single_config = [traffic for traffic, keys in by_traffic.items() if len(keys) < 2]
    add(
        "traffic_config_cross",
        "Every traffic class runs under more than one configuration",
        bool(by_traffic) and not single_config,
        (
            f"{len(by_traffic) - len(single_config)}/{len(by_traffic)} "
            "traffic classes run on 2+ configurations"
            if by_traffic
            else "none"
        ),
    )
    return checks


def coverage_report(checks: Sequence[CoverageCheck], *, configs: Sequence[ExperimentConfig] | None = None) -> dict[str, Any]:
    """Machine readable coverage report."""
    passed = [check for check in checks if check.passed]
    return {
        "schema_version": 1,
        "requirements_total": len(checks),
        "requirements_passed": len(passed),
        "all_passed": len(passed) == len(checks) and bool(checks),
        "checks": [check.to_dict() for check in checks],
        "failed": [check.key for check in checks if not check.passed],
        **({"experiment_count": len(configs)} if configs is not None else {}),
    }


def render_coverage(checks: Sequence[CoverageCheck]) -> str:
    """Render the coverage table (``Tunnel Mode  PASS`` style)."""
    width = max((len(check.label) for check in checks), default=10)
    lines = []
    for check in checks:
        marker = "PASS" if check.passed else "FAIL"
        lines.append(f"{check.label.ljust(width)}  {marker}")
    passed = sum(1 for check in checks if check.passed)
    lines.append("")
    lines.append(f"{passed}/{len(checks)} requirements satisfied")
    failed = [check for check in checks if not check.passed]
    for check in failed:
        lines.append(f"  {check.label}: {check.evidence}")
    return "\n".join(lines)


__all__ = [
    "DEFAULT_CAPTURE_DURATION_S",
    "MATRIX_ENTRIES",
    "CoverageCheck",
    "MatrixEntry",
    "build_matrix",
    "check_coverage",
    "configuration_key",
    "coverage_report",
    "render_coverage",
]




