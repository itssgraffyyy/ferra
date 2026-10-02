"""Plan an experiment run without executing any of it.

This is the module that makes the real Linux workflow *inspectable from a
non-Linux host*.  On Windows it must be able to answer "what would this run do,
which stages need root, and where does it stop?" without pretending anything
happened.

The rule that shapes the whole module: **a dry run may never mark an evidence
gate.**  A dry run produces no IKE_SA, no XFRM state, no capture and no ESP, so
every gate stays false and the state stays ``PLANNED``.  That is enforced
structurally - :func:`plan_run` never receives an ``ExperimentState`` to
advance, only the plan - rather than by a convention someone could forget.

The matrix itself is **reused** from :mod:`fera.dataset.matrix` rather than
redeclared.  Re-deriving the experiment list here would give two matrices that
could disagree, and the coverage claim would follow whichever one a reader
happened to open.
"""

from __future__ import annotations

import platform as platform_module
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..common.errors import ErrorCode, FeraError
from ..dataset.matrix import (
    MATRIX_ENTRIES,
    MatrixEntry,
    build_matrix,
    check_coverage,
    coverage_report,
)
from .preflight import PreflightReport

#: Schema identifier of one dry-run plan.
DRY_RUN_SCHEMA = "fera_experiment_dry_run_v1"

#: Banner printed at the top of every dry-run report.
DRY_RUN_BANNER = "DRY RUN - NO EXPERIMENT EXECUTED"

#: Stages that cannot run without Linux, root and a working XFRM stack.
LINUX_ONLY_STAGES: tuple[str, ...] = (
    "preflight",
    "testbed_setup",
    "ipsec_establishment",
    "xfrm_verification",
    "traffic_generation",
    "capture",
    "capture_validation",
    "manifest_finalisation",
)

#: The full planned sequence, so a reader sees the whole workflow not just its
#: executable parts.
PLANNED_STAGES: tuple[str, ...] = (
    "preflight",
    "testbed_setup",
    "ipsec_establishment",
    "ike_verification",
    "child_sa_verification",
    "xfrm_verification",
    "traffic_generation",
    "capture",
    "esp_verification",
    "capture_validation",
    "manifest_finalisation",
    "dataset_eligibility",
)

@dataclass(frozen=True)
class PlannedExperiment:
    """One planned session: a matrix row, a repetition, and what it needs."""

    experiment_id: str
    configuration_id: str
    session_id: str
    repeat_id: int
    traffic_class: str
    mode: str
    encryption: str
    integrity: str
    dh_group: str
    pfs: bool
    ip_version: int
    capture_duration_s: float
    requires_linux: bool = True
    executable_here: bool = False
    blocked_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "configuration_id": self.configuration_id,
            "session_id": self.session_id,
            "repeat_id": self.repeat_id,
            "traffic_class": self.traffic_class,
            "mode": self.mode,
            "encryption": self.encryption,
            "integrity": self.integrity,
            "dh_group": self.dh_group,
            "pfs": self.pfs,
            "ip_version": self.ip_version,
            "capture_duration_s": self.capture_duration_s,
            "requires_linux": self.requires_linux,
            "executable_here": self.executable_here,
            "blocked_reason": self.blocked_reason,
        }


def _configuration_id(entry: MatrixEntry) -> str:
    """Stable identity of a *configuration*, shared by every traffic class.

    Two experiments with the same id differ only in traffic class, which is what
    makes "held-out configuration" evaluation possible later: the grouping key
    must not change when the traffic class does.
    """
    return (
        f"{entry.mode.value}-{entry.encryption.value}-{entry.integrity.value}"
        f"-{entry.dh_group.value}-pfs{int(entry.pfs)}-ipv{entry.ip_version}"
    )


def plan_experiments(
    *,
    repeats: int = 1,
    entries: Sequence[MatrixEntry] | None = None,
    preflight: PreflightReport | None = None,
) -> dict[str, Any]:
    """Describe the full experiment plan without executing any of it.

    Repeats are expanded into distinct **session ids** so that later grouped
    splitting has real independence boundaries.  Generating thousands of windows
    from one capture and calling them independent experiments is exactly the
    shortcut the group-aware split exists to prevent, so the plan is explicit
    about how many independent sessions it would produce.
    """
    if repeats < 1:
        raise _dry_run_error("repeats must be at least 1", repeats=repeats)
    matrix = tuple(entries) if entries is not None else MATRIX_ENTRIES
    if not matrix:
        raise _dry_run_error("the experiment matrix is empty")

    executable = bool(preflight is not None and preflight.can_run_real_experiments)
    reason = (
        ""
        if executable
        else "preflight did not report this host able to run real experiments"
    )

    planned: list[PlannedExperiment] = []
    sessions: set[str] = set()
    for index, entry in enumerate(matrix):
        configuration_id = _configuration_id(entry)
        for repeat in range(repeats):
            session_id = f"{configuration_id}--{entry.traffic_type.value}--r{repeat:02d}"
            if session_id in sessions:  # pragma: no cover - ids are constructed unique
                raise _dry_run_error("duplicate session id", session_id=session_id)
            sessions.add(session_id)
            planned.append(
                PlannedExperiment(
                    experiment_id=f"exp-{index:03d}-{repeat:02d}-{entry.traffic_type.value}",
                    configuration_id=configuration_id,
                    session_id=session_id,
                    repeat_id=repeat,
                    traffic_class=entry.traffic_type.value,
                    mode=entry.mode.value,
                    encryption=entry.encryption.value,
                    integrity=entry.integrity.value,
                    dh_group=entry.dh_group.value,
                    pfs=bool(entry.pfs),
                    ip_version=int(entry.ip_version),
                    capture_duration_s=float(entry.capture_duration_s),
                    executable_here=executable,
                    blocked_reason=reason,
                )
            )

    coverage = coverage_report(check_coverage(build_matrix(matrix)))
    configurations = sorted({item.configuration_id for item in planned})
    return {
        "banner": DRY_RUN_BANNER,
        "executed": False,
        "host": {
            "platform": sys.platform,
            "is_linux": is_linux(),
            "python": platform_module.python_version(),
        },
        "counts": {
            "matrix_configurations": len(matrix),
            "distinct_configurations": len(configurations),
            "repeats": int(repeats),
            "planned_sessions": len(planned),
            "distinct_session_ids": len(sessions),
        },
        "configurations": configurations,
        "experiments": [item.to_dict() for item in planned],
        "stages": [
            {
                "stage": name,
                "requires_linux": name in LINUX_ONLY_STAGES,
                "executable_here": name not in LINUX_ONLY_STAGES,
            }
            for name in PLANNED_STAGES
        ],
        "preflight": preflight.to_dict() if preflight is not None else None,
        "coverage": coverage,
        "evidence_gates": {
            "marked_verified": [],
            "note": (
                "a dry run verifies nothing: it produces no IKE_SA, no XFRM state, no "
                "capture and no ESP, so no evidence gate may be satisfied by planning"
            ),
        },
        "generated_at": _utc_now(),
        "notes": [
            DRY_RUN_BANNER,
            "configuration_id deliberately excludes the traffic class, so held-out-"
            "configuration evaluation has a grouping key that does not change with it",
            "each repetition is a distinct session id, giving grouped splitting real "
            "independence boundaries rather than many windows of one capture",
        ],
    }


def render_text(plan: Mapping[str, Any]) -> str:
    """Human-readable dry-run report, with the banner first and last."""
    counts = dict(plan.get("counts") or {})
    banner = str(plan.get("banner") or DRY_RUN_BANNER)
    lines = [
        banner,
        "=" * len(banner),
        "",
        f"host platform      : {plan['host']['platform']} (linux={plan['host']['is_linux']})",
        f"configurations      : {counts.get('distinct_configurations')}",
        f"planned sessions    : {counts.get('planned_sessions')} (repeats={counts.get('repeats')})",
        f"executed           : {plan.get('executed')}",
        "",
        "PLANNED STAGES:",
    ]
    for stage in plan.get("stages") or ():
        mark = "runnable here" if stage.get("executable_here") else "requires Linux/root"
        lines.append(f"  {stage['stage']:<26} {mark}")
    gates = dict(plan.get("evidence_gates") or {})
    lines.extend(
        [
            "",
            "EVIDENCE GATES:",
            f"  verified by this plan : {len(gates.get('marked_verified') or [])}",
            f"  note                  : {gates.get('note', '')}",
        ]
    )
    blocked = [item for item in plan.get("experiments") or () if item.get("blocked_reason")]
    if blocked:
        lines.extend(["", f"BLOCKED ({len(blocked)} session(s)):"])
        lines.append(f"  {blocked[0]['blocked_reason']}")
    lines.extend(["", banner])
    return "\n".join(lines)


__all__ = [
    "DRY_RUN_BANNER",
    "DRY_RUN_SCHEMA",
    "LINUX_ONLY_STAGES",
    "PLANNED_STAGES",
    "PlannedExperiment",
    "is_linux",
    "plan_experiments",
    "render_text",
]

def _dry_run_error(message: str, **details: Any) -> FeraError:
    return FeraError(
        message,
        code=ErrorCode.CONFIG_VALIDATION_FAILED,
        hint="see docs/linux_experiments.md for the planned workflow",
        details=details,
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_linux() -> bool:
    """Whether the *current* host is Linux.

    Used only to label planned stages, never to decide that a run succeeded.
    """
    return sys.platform.startswith("linux") and platform_module.system() == "Linux"
