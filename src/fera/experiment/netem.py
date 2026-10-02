"""Network-condition (tc netem) planning, and the cleanup it implies.

Two things are deliberately separated here:

* **planning** the commands a run would execute on Linux, which is testable on
  any host because nothing is executed; and
* **cleanup** planning, because leaving a qdisc or a namespace behind silently
  changes the next run's behaviour - which is how "the second experiment
  behaved differently from the first" happens.

Nothing in this module runs ``tc``.  Every function returns the argument list it
*would* run, plus whether the current host could run it.  That is what makes the
robustness matrix reviewable before anyone touches a production box, and it is
why this file is safe on Windows.

No robustness result is produced here and none may be inferred: a condition is
*recorded as applied* only when a caller says so from a real run.
"""

from __future__ import annotations

import shutil
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..common.errors import ErrorCode, FeraError

#: Schema identifier of one network-condition document.
NETEM_SCHEMA = "fera_network_condition_v1"

#: The small, defensible set of conditions. Deliberately not a matrix: each
#: extra condition multiplies the experiment count, and a large one is not more
#: rigorous, just slower and less likely to be run properly.
CONDITIONS: Mapping[str, Mapping[str, Any]] = {
    "baseline": {"delay_ms": None, "jitter_ms": None, "loss_percent": None},
    "loss": {"delay_ms": None, "jitter_ms": None, "loss_percent": 1.0},
    "jitter": {"delay_ms": 20.0, "jitter_ms": 10.0, "loss_percent": None},
    "latency": {"delay_ms": 50.0, "jitter_ms": None, "loss_percent": None},
}

CONDITION_NAMES: tuple[str, ...] = tuple(CONDITIONS)


def _netem_error(message: str, **details: Any) -> FeraError:
    return FeraError(
        message,
        code=ErrorCode.CONFIG_VALIDATION_FAILED,
        hint="see docs/linux_experiments.md for the robustness procedure",
        details=details,
    )


def is_linux() -> bool:
    """Whether this host could execute ``tc`` at all."""
    return sys.platform.startswith("linux") and shutil.which("tc") is not None


@dataclass(frozen=True)
class NetworkCondition:
    """One planned netem condition, with the commands it would apply and undo.

    ``applied`` is a *claim by the caller* that the commands really ran.  Nothing
    here sets it, and a condition that was planned but never applied stays
    ``False`` so a manifest cannot record an impairment that did not happen.
    """

    name: str
    delay_ms: float | None = None
    jitter_ms: float | None = None
    loss_percent: float | None = None
    interface: str = ""
    applied: bool = False
    requires_root: bool = True

    def __post_init__(self) -> None:
        if self.name not in CONDITIONS:
            raise _netem_error(
                f"unknown network condition: {self.name}",
                known=list(CONDITION_NAMES),
            )
        for label, value in (
            ("delay_ms", self.delay_ms),
            ("jitter_ms", self.jitter_ms),
            ("loss_percent", self.loss_percent),
        ):
            if value is None:
                continue
            # Reject non-numbers explicitly: comparing a str to 0 raises
            # TypeError, which would escape as an implementation error rather
            # than a configuration mistake the caller can act on.
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise _netem_error(
                    f"{label} must be a number or None (got {value!r})", field=label
                )
            if value < 0:
                raise _netem_error(
                    f"{label} must be non-negative (got {value})", field=label
                )
        if self.loss_percent is not None and self.loss_percent > 100:
            raise _netem_error(
                "loss_percent cannot exceed 100", loss_percent=self.loss_percent
            )

    @property
    def is_baseline(self) -> bool:
        return self.name == "baseline"

    def qdisc_arguments(self) -> list[str]:
        """The ``netem`` limit arguments, empty for the baseline condition.

        Jitter is meaningless without delay, so a jitter-only condition carries
        the delay it needs.  Getting that wrong produces a qdisc that silently
        does nothing.
        """
        parts: list[str] = []
        delay = self.delay_ms
        if self.name == "jitter" and delay is None:
            delay = CONDITIONS["jitter"]["delay_ms"]
        if delay is not None:
            parts.extend(["delay", f"{delay}ms"])
        if self.jitter_ms is not None:
            if not parts:
                raise _netem_error(
                    "jitter requires a delay; netem rejects jitter without one",
                    condition=self.name,
                )
            parts.append(f"{self.jitter_ms}ms")
            parts.extend(["distribution", "normal"])
        if self.loss_percent is not None:
            parts.extend(["loss", f"{self.loss_percent}%"])
        return parts
    def apply_command(self) -> list[str] | None:
        """The full ``tc`` invocation, or ``None`` for the baseline condition.

        Baseline deliberately produces no command: applying an empty netem
        would still replace whatever qdisc a previous run left behind, which is
        a side effect a "no impairment" run should not have.
        """
        arguments = self.qdisc_arguments()
        if not arguments or not self.interface:
            return None
        return [
            "tc",
            "qdisc",
            "replace",
            "dev",
            self.interface,
            "root",
            "netem",
            *arguments,
        ]

    def cleanup_command(self) -> list[str] | None:
        """The idempotent undo: deleting a root qdisc is safe when none exists."""
        if not self.interface:
            return None
        return ["tc", "qdisc", "del", "dev", self.interface, "root"]

    def executable_here(self) -> bool:
        """Whether this host could actually apply the condition."""
        return bool(self.interface) and not self.is_baseline and is_linux()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": NETEM_SCHEMA,
            "name": self.name,
            "delay_ms": self.delay_ms,
            "jitter_ms": self.jitter_ms,
            "loss_percent": self.loss_percent,
            "interface": self.interface,
            "applied": self.applied,
            "requires_root": self.requires_root,
            "apply_command": self.apply_command(),
            "cleanup_command": self.cleanup_command(),
            "executable_here": self.executable_here(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> NetworkCondition:
        return cls(
            name=str(payload.get("name") or "baseline"),
            delay_ms=(None if payload.get("delay_ms") is None else float(payload["delay_ms"])),
            jitter_ms=(None if payload.get("jitter_ms") is None else float(payload["jitter_ms"])),
            loss_percent=(
                None if payload.get("loss_percent") is None else float(payload["loss_percent"])
            ),
            interface=str(payload.get("interface") or ""),
            applied=bool(payload.get("applied", False)),
            requires_root=bool(payload.get("requires_root", True)),
        )


def plan_condition(name: str, interface: str = "") -> NetworkCondition:
    """Build one planned condition with the matrix's defaults filled in."""
    if name not in CONDITIONS:
        raise _netem_error(f"unknown network condition: {name}", known=list(CONDITION_NAMES))
    defaults = CONDITIONS[name]
    return NetworkCondition(
        name=name,
        delay_ms=defaults["delay_ms"],
        jitter_ms=defaults["jitter_ms"],
        loss_percent=defaults["loss_percent"],
        interface=interface,
    )


def plan_matrix(interface: str = "", names: Sequence[str] | None = None) -> list[dict[str, Any]]:
    """Every planned condition, with the commands it would run and undo."""
    chosen = [str(item) for item in (names or CONDITION_NAMES)]
    return [plan_condition(name, interface).to_dict() for name in chosen]


__all__ = [
    "CONDITIONS",
    "CONDITION_NAMES",
    "NETEM_SCHEMA",
    "NetworkCondition",
    "is_linux",
    "plan_condition",
    "plan_matrix",
]
