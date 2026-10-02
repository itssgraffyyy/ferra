"""Experiment preflight: can this host run a *real* IPsec experiment?

This deliberately sits **on top of** :mod:`fera.testbed.environment` rather than
re-implementing it.  That module already probes the OS, privileges, strongSwan,
XFRM, capture tools, namespaces and IPv6, and already refuses to infer
readiness from installed binaries alone.  Re-doing those probes here would give
two answers that could disagree, which is the failure mode this project has
already been bitten by once.

What preflight adds is the *experiment* verdict: a single READY / PARTIAL /
BLOCKED answer, plus the specific reasons a real experiment cannot proceed, so
the workflow can refuse early and say why instead of failing halfway through a
capture.

The distinction that matters most: ``swanctl`` being on ``PATH`` does not make
a host READY.  A host is READY only when the kernel can actually carry IPsec -
XFRM state *and* policy are probed, not assumed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..common.errors import ErrorCode, FeraError
from ..common.paths import ProjectPaths, default_paths
from ..testbed.environment import EnvironmentReport, check_environment

#: Schema identifier of one preflight report.
PREFLIGHT_SCHEMA = "fera_experiment_preflight_v1"

READY = "READY"
PARTIAL = "PARTIAL"
BLOCKED = "BLOCKED"

PREFLIGHT_STATUSES: tuple[str, ...] = (READY, PARTIAL, BLOCKED)

#: Capabilities a real IPsec experiment cannot proceed without.
#:
#: These are the **actual check keys** produced by
#: :func:`fera.testbed.environment.check_environment`, not invented names.  An
#: earlier draft used names like ``linux_kernel`` and ``xfrm_state`` that do not
#: exist in that report; because an unknown key simply reads as "not
#: available", it would have marked a correctly configured Linux host BLOCKED -
#: a false negative on exactly the machine the workflow is meant to enable.
#: ``check_environment`` exposes XFRM as a single ``xfrm`` check, so
#: ``xfrm_state``/``xfrm_policy`` capability are covered by it here; the finer
#: per-gate split lives in :mod:`fera.experiment.gates`, which judges an actual
#: run rather than a host.
REQUIRED_CAPABILITIES: tuple[str, ...] = (
    "platform",
    "privileges",
    "swanctl",
    "capture_tool",
    "xfrm",
    "netns",
)


def _preflight_error(message: str, **details: Any) -> FeraError:
    return FeraError(
        message,
        code=ErrorCode.CONFIG_VALIDATION_FAILED,
        hint="run scripts/check_environment.py for the underlying capability report",
        details=details,
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class PreflightReport:
    """Whether this host can run a real IPsec experiment, and why not."""

    status: str
    blocking_reasons: tuple[str, ...]
    warnings: tuple[str, ...]
    available_capabilities: tuple[str, ...]
    missing_capabilities: tuple[str, ...]
    environment: Mapping[str, Any] = field(default_factory=dict)
    generated_at: str = ""
    notes: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        return self.status == READY

    @property
    def can_run_real_experiments(self) -> bool:
        """Only a READY host may start a run that could claim real evidence."""
        return self.status == READY

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PREFLIGHT_SCHEMA,
            "status": self.status,
            "ready": self.ready,
            "can_run_real_experiments": self.can_run_real_experiments,
            "blocking_reasons": list(self.blocking_reasons),
            "warnings": list(self.warnings),
            "available_capabilities": list(self.available_capabilities),
            "missing_capabilities": list(self.missing_capabilities),
            "environment": dict(self.environment),
            "generated_at": self.generated_at,
            "notes": list(self.notes),
        }

    def render_text(self) -> str:
        lines = [
            f"FERA experiment preflight ({self.generated_at})",
            "",
            f"STATUS : {self.status}",
            f"real IPsec experiments possible: {'yes' if self.can_run_real_experiments else 'no'}",
            "",
            f"available : {', '.join(self.available_capabilities) or '-'}",
            f"missing   : {', '.join(self.missing_capabilities) or '-'}",
        ]
        if self.blocking_reasons:
            lines.append("")
            lines.append("BLOCKING:")
            lines.extend(f"  - {reason}" for reason in self.blocking_reasons)
        if self.warnings:
            lines.append("")
            lines.append("WARNINGS:")
            lines.extend(f"  - {reason}" for reason in self.warnings)
        return "\n".join(lines)


def run_preflight(
    *,
    paths: ProjectPaths | None = None,
    expected_ip_version: int | None = None,
    capture_interface: str | None = None,
    require_real_experiments: bool = True,
    environment: EnvironmentReport | None = None,
) -> PreflightReport:
    """Probe the host and compose the experiment verdict.

    ``environment`` lets a caller (or a test) supply an already-probed report
    instead of shelling out.  ``require_real_experiments=False`` downgrades a
    blocking environment problem to a warning, which is what a dry run wants:
    it should be able to describe a Linux workflow on a Windows host without
    claiming the host could execute it.
    """
    resolved = paths if paths is not None else default_paths()
    report = (
        environment
        if environment is not None
        else check_environment(
            resolved,
            expected_ip_version=expected_ip_version,
            capture_interface=capture_interface,
        )
    )
    statuses = _check_map(report)
    detail = {item.key: item for item in report.checks}

    def _available(key: str) -> bool:
        return statuses.get(key) in {"AVAILABLE", "NOT_APPLICABLE"}

    missing: list[str] = []
    reasons: list[str] = []
    for capability in REQUIRED_CAPABILITIES:
        if not _available(capability):
            missing.append(capability)
            check = detail.get(capability)
            reason = f"{capability}: {check.status.value}" if check else f"{capability}: not probed"
            if check is not None and check.detail:
                reason = f"{reason} - {check.detail}"
            reasons.append(reason)

    warnings: list[str] = []
    for check in report.checks:
        if not check.required and check.status.value in {"MISSING", "UNVERIFIED"}:
            warnings.append(f"{check.key}: {check.status.value} - {check.detail}")
    if _available("platform") and not _available("netns"):
        warnings.append(
            "network namespaces are unavailable; the two-namespace testbed cannot be built "
            "and a two-VM topology would be required"
        )

    available = tuple(
        capability for capability in REQUIRED_CAPABILITIES if capability not in missing
    )

    if not missing:
        status = READY
    elif require_real_experiments:
        status = BLOCKED
    else:
        status = PARTIAL

    return PreflightReport(
        status=status,
        blocking_reasons=tuple(reasons) if require_real_experiments else (),
        warnings=tuple(warnings),
        available_capabilities=available,
        missing_capabilities=tuple(missing),
        environment={
            "ready": report.ready,
            "blocking_checks": [item.key for item in report.blocking_checks],
            "host": dict(report.host),
            "tool_versions": dict(report.tool_versions),
            "checks": {
                item.key: {
                    "status": item.status.value,
                    "detail": item.detail,
                    "required": item.required,
                }
                for item in report.checks
            },
        },
        generated_at=_utc_now(),
        notes=(
            "a host is READY only when XFRM state and policy are actually probed, not "
            "merely because strongSwan is installed",
            "PARTIAL means capabilities are missing but the workflow may still be "
            "described or dry-run; it never authorises a real-evidence claim",
        ),
    )


__all__ = [
    "BLOCKED",
    "PARTIAL",
    "PREFLIGHT_SCHEMA",
    "PREFLIGHT_STATUSES",
    "READY",
    "REQUIRED_CAPABILITIES",
    "PreflightReport",
    "run_preflight",
]
def _check_map(report: EnvironmentReport) -> dict[str, str]:
    """Environment check key -> status string."""
    return {item.key: item.status.value for item in report.checks}
