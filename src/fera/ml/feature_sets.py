"""Named feature subsets and the importance groups they map onto.

:data:`fera.ml.features.FEATURE_WHITELIST` stays the *only* schema contract: a
model artefact persists the ordered subset it was trained on, and the runtime
refuses a vector that cannot supply those columns.  This module therefore only
*selects* from the whitelist - it never adds a feature, and every name listed
here is checked against the whitelist when the module is imported.

Why a subset is needed at all: several whitelisted features describe the
**testbed** rather than the tunneled application.  The IKE counts measure how
often the experiment renegotiated, ``icmp_packet_share`` and
``ipv6_packet_share`` how the harness was wired, and ``truncated_packet_share``
what the capture filter did.  A classifier can reach a high score by reading that
setup instead of the ESP behaviour - which would turn an accuracy claim into a
claim about the harness.  The ``esp_core`` set exists so an experiment can
measure that risk by comparing the two sets
(:func:`fera.ml.train.ablate_feature_sets`) rather than assuming it away.
Automatically dropping them from the default set is deliberately *not* done
here: that decision needs the measurement first.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..common.errors import ErrorCode, FeraError
from .features import FEATURE_WHITELIST

#: Auxiliary / testbed-context features: legitimate metadata, but candidates for
#: being a testbed shortcut rather than application behaviour.
SHORTCUT_CANDIDATE_FEATURES: tuple[str, ...] = (
    "ike_packet_share",
    "ike_packet_count",
    "ike_exchange_count",
    "icmp_packet_share",
    "ipv6_packet_share",
    "truncated_packet_share",
)

#: Feature sets selectable by name (``all`` is the whitelist itself).
FEATURE_SETS: Mapping[str, tuple[str, ...]] = {
    "all": FEATURE_WHITELIST,
    "esp_core": tuple(
        name for name in FEATURE_WHITELIST if name not in set(SHORTCUT_CANDIDATE_FEATURES)
    ),
    "auxiliary": SHORTCUT_CANDIDATE_FEATURES,
}

#: Importance categories, keyed in report order.
FEATURE_GROUPS: Mapping[str, tuple[str, ...]] = {
    "volume": (
        "capture_packets",
        "capture_bytes",
        "capture_duration_s",
        "packet_rate_pps",
        "byte_rate_bps",
        "esp_packets",
        "esp_bytes",
        "esp_flow_count",
        "esp_avg_packets_per_flow",
        "esp_avg_bytes_per_flow",
    ),
    "size": ("avg_packet_len", "esp_avg_len", "esp_len_min", "esp_len_max", "esp_len_std"),
    "direction": (
        "esp_largest_flow_share",
        "esp_fwd_packets",
        "esp_bwd_packets",
        "esp_fwd_bytes",
        "esp_bwd_bytes",
        "esp_fwd_packet_share",
        "esp_fwd_byte_share",
    ),
    "timing": ("esp_iat_mean_s", "esp_iat_std_s", "esp_iat_max_s", "esp_span_s"),
    "sequence": ("esp_seq_gap_total", "esp_seq_replay_total", "esp_nonmonotonic_flow_share"),
    "encapsulation": ("esp_udp_encap_share",),
    "protocol_share": ("esp_packet_share",),
    "auxiliary_context": SHORTCUT_CANDIDATE_FEATURES,
}

#: The category a name outside every group falls into (never silently dropped).
FALLBACK_GROUP = "unclassified"

_GROUP_OF: dict[str, str] = {
    name: group for group, members in FEATURE_GROUPS.items() for name in members
}


def resolve_feature_set(name: str, features: Sequence[str] | None = None) -> tuple[str, ...]:
    """Resolve one named feature set to an ordered whitelist subset.

    Order always follows the whitelist, so a subset is a sub-selection and never
    a re-ordering of the model input contract.
    """
    if name not in FEATURE_SETS:
        raise FeraError(
            f"unknown feature set: {name}",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            hint=f"choose one of: {', '.join(sorted(FEATURE_SETS))}",
            details={"requested": name, "available": sorted(FEATURE_SETS)},
        )
    allowed = tuple(features) if features is not None else FEATURE_WHITELIST
    return tuple(feature for feature in allowed if feature in set(FEATURE_SETS[name]))


def resolve_features(features: Sequence[str] | None) -> tuple[str, ...]:
    """Validate an explicit feature list: whitelist only, no duplicates, kept ordered."""
    if features is None:
        return FEATURE_WHITELIST
    unknown = [name for name in features if name not in set(FEATURE_WHITELIST)]
    if unknown:
        raise FeraError(
            "feature list contains names outside the feature whitelist",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            hint="train against the whitelist, or extend it and bump FEATURE_SCHEMA",
            details={"unknown": unknown},
        )
    if len(set(features)) != len(features):
        raise FeraError(
            "feature list contains duplicates",
            code=ErrorCode.CONFIG_VALIDATION_FAILED,
            details={"features": list(features)},
        )
    return tuple(name for name in FEATURE_WHITELIST if name in set(features))


def feature_set_name(features: Sequence[str]) -> str:
    """Best known name of a feature list (for labelling an artefact)."""
    chosen = tuple(features)
    for name, members in FEATURE_SETS.items():
        if tuple(members) == chosen:
            return name
    return "custom"


def group_of(feature: str) -> str:
    """Importance category of one feature (:data:`FALLBACK_GROUP` when unmapped)."""
    return _GROUP_OF.get(feature, FALLBACK_GROUP)


def grouped_features(features: Sequence[str] | None = None) -> dict[str, tuple[str, ...]]:
    """Category -> features, in :data:`FEATURE_GROUPS` order, empties dropped."""
    allowed = set(FEATURE_WHITELIST if features is None else features)
    grouped = {
        group: tuple(name for name in members if name in allowed)
        for group, members in FEATURE_GROUPS.items()
    }
    return {group: members for group, members in grouped.items() if members}


# Import-time self check: a category that no longer matches the whitelist would
# silently under-report importance, which is worse than failing at import.
_STALE = sorted(
    name
    for members in FEATURE_GROUPS.values()
    for name in members
    if name not in set(FEATURE_WHITELIST)
)
if _STALE:  # pragma: no cover - development-time guard, never fires in a valid checkout
    raise FeraError(
        "feature group references a feature outside the whitelist",
        code=ErrorCode.INTERNAL_ERROR,
        hint="align FEATURE_GROUPS with FEATURE_WHITELIST",
        details={"stale": _STALE},
    )

__all__ = [
    "FALLBACK_GROUP",
    "FEATURE_GROUPS",
    "FEATURE_SETS",
    "SHORTCUT_CANDIDATE_FEATURES",
    "feature_set_name",
    "group_of",
    "grouped_features",
    "resolve_feature_set",
    "resolve_features",
]
