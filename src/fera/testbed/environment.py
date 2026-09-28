"""Environment detection and capability reporting.

The development machine of a hackathon team is not necessarily the machine that
runs IPsec.  This module therefore *reports* capabilities instead of assuming
them, and the rest of FERA stays usable when strongSwan, XFRM, root or IPv6 are
missing:

``AVAILABLE``
    verified to work right now (the check actually ran),
``MISSING``
    the tool/capability could not be found (installable),
``UNVERIFIED``
    present but not proven (for example: no way to test it without running an
    experiment - FERA refuses to claim success here),
``UNSUPPORTED``
    this platform cannot provide the capability at all (for example XFRM on
    Windows),
``NOT_APPLICABLE``
    the check does not apply to the selected experiment (e.g. IPv6 checks for
    an IPv4 only run).
"""

from __future__ import annotations

import os
import platform
import socket
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from ..common.errors import ErrorCode, FeraError
from ..common.logging_utils import get_logger
from ..common.paths import ProjectPaths, default_paths
from ..common.process import BaseRunner, SubprocessRunner
from ..common.serialization import PYYAML_AVAILABLE
from ..common.versions import collect_tool_versions, platform_summary, python_version

logger = get_logger(__name__)

MINIMUM_PYTHON = (3, 10)
#: Tools the pipeline needs, grouped by role.
REQUIRED_TOOLS = ("swanctl", "tcpdump")
OPTIONAL_TOOLS = ("dumpcap", "tshark", "iperf3", "curl", "ping", "ip", "strongswan")


class CheckStatus(str, Enum):
    """Outcome of a single capability check."""

    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    UNVERIFIED = "UNVERIFIED"
    UNSUPPORTED = "UNSUPPORTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class CheckResult:
    """Result of one capability check."""

    key: str
    label: str
    status: CheckStatus
    detail: str
    required: bool = False
    remediation: str | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status in {CheckStatus.AVAILABLE, CheckStatus.NOT_APPLICABLE}

    @property
    def blocking(self) -> bool:
        return self.required and not self.ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "status": self.status.value,
            "detail": self.detail,
            "required": self.required,
            "ok": self.ok,
            "blocking": self.blocking,
            "remediation": self.remediation,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class EnvironmentReport:
    """Full capability report of the machine FERA runs on."""

    checks: tuple[CheckResult, ...]
    host: Mapping[str, Any] = field(default_factory=dict)
    tool_versions: Mapping[str, str | None] = field(default_factory=dict)
    generated_at: str = ""

    @property
    def blocking_checks(self) -> tuple[CheckResult, ...]:
        return tuple(check for check in self.checks if check.blocking)

    @property
    def ready(self) -> bool:
        """True when every mandatory capability is available right now."""
        return not self.blocking_checks

    def check(self, key: str) -> CheckResult | None:
        for result in self.checks:
            if result.key == key:
                return result
        return None

    def status(self, key: str) -> CheckStatus:
        result = self.check(key)
        return result.status if result else CheckStatus.UNVERIFIED

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {status.value: 0 for status in CheckStatus}
        for check in self.checks:
            counts[check.status.value] += 1
        counts["blocking"] = len(self.blocking_checks)
        return counts

    def blocker_reason(self) -> str | None:
        """Human readable reason why an end-to-end run cannot happen here."""
        if self.ready:
            return None
        parts = [f"{check.key}: {check.detail}" for check in self.blocking_checks]
        return "; ".join(parts)

    def suggested_error_code(self) -> ErrorCode:
        """Map the first blocking check to the matching :class:`ErrorCode`."""
        mapping = {
            "platform": ErrorCode.UNSUPPORTED_PLATFORM,
            "strongswan": ErrorCode.STRONGSWAN_NOT_INSTALLED,
            "swanctl": ErrorCode.SWANCTL_NOT_AVAILABLE,
            "capture_tool": ErrorCode.CAPTURE_TOOL_NOT_AVAILABLE,
            "privileges": ErrorCode.INSUFFICIENT_PRIVILEGES,
            "xfrm": ErrorCode.UNSUPPORTED_PLATFORM,
            "ipv6": ErrorCode.IPV6_UNAVAILABLE,
            "python_version": ErrorCode.DEPENDENCY_MISSING,
            "pyyaml": ErrorCode.DEPENDENCY_MISSING,
        }
        for check in self.blocking_checks:
            if check.key in mapping:
                return mapping[check.key]
        return ErrorCode.UNSUPPORTED_PLATFORM

    def require_ready(self) -> None:
        """Raise a structured error when the machine cannot run experiments."""
        if self.ready:
            return
        reason = self.blocker_reason()
        hints = [check.remediation for check in self.blocking_checks if check.remediation]
        raise FeraError(
            f"environment is not ready for an IPsec experiment: {reason}",
            code=self.suggested_error_code(),
            hint=hints[0] if hints else "run scripts/check_environment.py for details",
            details={"blocking_checks": [check.to_dict() for check in self.blocking_checks]},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "generated_at": self.generated_at,
            "host": dict(self.host),
            "tool_versions": dict(self.tool_versions),
            "ready": self.ready,
            "blocker_reason": self.blocker_reason(),
            "summary": self.summary(),
            "checks": [check.to_dict() for check in self.checks],
        }

    def render_text(self) -> str:
        """Render the report as an aligned, human readable table."""
        width = max((len(check.label) for check in self.checks), default=10)
        lines = [
            f"FERA environment report ({self.generated_at})",
            "",
            f"{'CHECK'.ljust(width)}  {'STATUS':<12} DETAIL",
            f"{'-' * width}  {'-' * 12} {'-' * 40}",
        ]
        for check in self.checks:
            marker = "!" if check.blocking else " "
            lines.append(f"{check.label.ljust(width)}  {check.status.value:<12} {check.detail}{marker}")
        lines.append("")
        counts = self.summary()
        lines.append(
            "summary: "
            + ", ".join(f"{key}={value}" for key, value in counts.items() if key != "blocking")
            + f", blocking={counts['blocking']}"
        )
        if self.ready:
            lines.append("result: READY for IPsec experiments on this machine")
        else:
            lines.append(f"result: NOT READY - {self.blocker_reason()}")
        for check in self.blocking_checks:
            if check.remediation:
                lines.append(f"  -> {check.key}: {check.remediation}")
        return "\n".join(lines)


def is_wsl() -> bool:
    """True when running inside the Windows Subsystem for Linux."""
    for path in ("/proc/sys/kernel/osrelease", "/proc/version"):
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if "microsoft" in text or "wsl" in text:
            return True
    return False


def _check_platform() -> CheckResult:
    system = platform.system()
    if system == "Linux":
        return CheckResult(
            key="platform",
            label="OS / platform",
            status=CheckStatus.AVAILABLE,
            detail=f"Linux {platform.release()} ({platform.machine()})",
            required=True,
            evidence={"system": system, "release": platform.release(), "wsl": is_wsl()},
        )
    return CheckResult(
        key="platform",
        label="OS / platform",
        status=CheckStatus.UNSUPPORTED,
        detail=f"{system} cannot run the Linux XFRM/IPsec kernel path",
        required=True,
        remediation=(
            "run FERA inside a Linux VM or a Linux network namespace testbed "
            "(docs/testbed.md).  WSL2 may work when its kernel exposes XFRM - "
            "run scripts/check_environment.py inside the distribution to find out."
        ),
        evidence={"system": system, "wsl": is_wsl()},
    )


def _check_python() -> CheckResult:
    current = sys.version_info[:3]
    if current[:2] >= MINIMUM_PYTHON:
        return CheckResult(
            key="python_version",
            label="Python",
            status=CheckStatus.AVAILABLE,
            detail=f"{python_version()} (>= {MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]} required)",
            required=True,
            evidence={"executable": sys.executable},
        )
    return CheckResult(
        key="python_version",
        label="Python",
        status=CheckStatus.MISSING,
        detail=f"{python_version()} is too old",
        required=True,
        remediation=f"use Python >= {MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]}",
    )


def _check_pyyaml() -> CheckResult:
    if PYYAML_AVAILABLE:
        return CheckResult(
            key="pyyaml",
            label="PyYAML",
            status=CheckStatus.AVAILABLE,
            detail="YAML experiment definitions are supported",
            required=True,
        )
    return CheckResult(
        key="pyyaml",
        label="PyYAML",
        status=CheckStatus.MISSING,
        detail="PyYAML is not installed",
        required=True,
        remediation="python -m pip install pyyaml",
    )


def _check_privileges() -> CheckResult:
    if os.name == "posix":
        geteuid = getattr(os, "geteuid", None)
        uid = geteuid() if geteuid is not None else -1
        if uid == 0:
            return CheckResult(
                key="privileges",
                label="Privileges",
                status=CheckStatus.AVAILABLE,
                detail="running as root (uid 0)",
                required=True,
            )
        return CheckResult(
            key="privileges",
            label="Privileges",
            status=CheckStatus.MISSING,
            detail=f"running as uid {uid} without packet capture / XFRM rights",
            required=True,
            remediation="re-run the experiment runner with sudo (root is required by tcpdump and XFRM)",
        )
    return CheckResult(
        key="privileges",
        label="Privileges",
        status=CheckStatus.UNSUPPORTED,
        detail="privilege model of this platform is not supported for XFRM/IPsec",
        required=True,
        remediation="run inside Linux (VM, bare metal or WSL2 with XFRM support)",
    )


def _check_xfrm(runner: BaseRunner) -> CheckResult:
    if platform.system() != "Linux":
        return CheckResult(
            key="xfrm",
            label="Kernel XFRM/IPsec",
            status=CheckStatus.UNSUPPORTED,
            detail="not a Linux kernel: no XFRM/IPsec subsystem available",
            required=True,
        )
    if not Path("/proc/net/xfrm_stat").exists():
        return CheckResult(
            key="xfrm",
            label="Kernel XFRM/IPsec",
            status=CheckStatus.UNSUPPORTED,
            detail="/proc/net/xfrm_stat is missing (kernel built without XFRM)",
            required=True,
            remediation="use a kernel with CONFIG_XFRM, CONFIG_XFRM_USER and CONFIG_INET_ESP",
        )
    result = runner.run(["ip", "xfrm", "state"], timeout=15.0)
    stderr = (result.stderr or "").strip()
    evidence: dict[str, Any] = {"probe": result.display, "returncode": result.returncode}
    if result.ok:
        return CheckResult(
            key="xfrm",
            label="Kernel XFRM/IPsec",
            status=CheckStatus.AVAILABLE,
            detail="`ip xfrm state` succeeded: XFRM netlink interface works",
            required=True,
            evidence=evidence,
        )
    if "not permitted" in stderr.lower() or "operation not permitted" in stderr.lower():
        return CheckResult(
            key="xfrm",
            label="Kernel XFRM/IPsec",
            status=CheckStatus.MISSING,
            detail="XFRM exists but requires root (CAP_NET_ADMIN)",
            required=True,
            remediation="re-run with sudo",
            evidence={**evidence, "stderr": stderr[:400]},
        )
    return CheckResult(
        key="xfrm",
        label="Kernel XFRM/IPsec",
        status=CheckStatus.UNSUPPORTED,
        detail=f"`ip xfrm state` failed: {stderr[:200] or 'unknown error'}",
        required=True,
        remediation="the kernel lacks XFRM/XFRM_USER/INET_ESP support (kernel modules may need loading)",
        evidence=evidence,
    )


def _check_swanctl(runner: BaseRunner) -> CheckResult:
    path = runner.which("swanctl")
    if not path:
        return CheckResult(
            key="swanctl",
            label="strongSwan swanctl",
            status=CheckStatus.MISSING,
            detail="swanctl not found",
            required=True,
            remediation=(
                "install strongSwan with swanctl support "
                "(apt-get install strongswan strongswan-swanctl)"
            ),
        )
    result = runner.run(["swanctl", "--version"], timeout=15.0)
    version_lines = (result.stdout or result.stderr).strip().splitlines()
    return CheckResult(
        key="swanctl",
        label="strongSwan swanctl",
        status=CheckStatus.AVAILABLE,
        detail=version_lines[0] if version_lines else f"swanctl found at {path}",
        required=True,
        evidence={"path": path, "version_output": "\n".join(version_lines[:3])},
    )


def _check_charon(runner: BaseRunner) -> CheckResult:
    """Check whether a charon daemon is reachable over VICI.

    Optional: FERA starts its own instance in the network namespace testbed and
    the runner reports the real failure if no daemon answers.
    """
    if runner.which("swanctl") is None:
        return CheckResult(
            key="charon",
            label="charon daemon (vici)",
            status=CheckStatus.MISSING,
            detail="swanctl is missing, cannot probe the daemon",
            required=False,
            remediation="install strongSwan first",
        )
    result = runner.run(["swanctl", "--stats"], timeout=15.0)
    if result.ok:
        return CheckResult(
            key="charon",
            label="charon daemon (vici)",
            status=CheckStatus.AVAILABLE,
            detail="daemon reachable over vici (`swanctl --stats` succeeded)",
            required=False,
        )
    stderr = (result.stderr or "").strip()
    return CheckResult(
        key="charon",
        label="charon daemon (vici)",
        status=CheckStatus.MISSING,
        detail=f"no daemon on the default vici socket ({stderr[:120]})",
        required=False,
        remediation="start it (systemctl start strongswan) or use the netns testbed which starts its own instance",
    )


def _check_capture_tool(runner: BaseRunner) -> CheckResult:
    tcpdump = runner.which("tcpdump")
    if tcpdump:
        result = runner.run(["tcpdump", "--version"], timeout=15.0)
        first = (result.stderr or result.stdout).strip().splitlines()
        return CheckResult(
            key="capture_tool",
            label="Capture tool",
            status=CheckStatus.AVAILABLE,
            detail=f"tcpdump -> {tcpdump}" + (f" ({first[0]})" if first else ""),
            required=True,
            evidence={"tool": "tcpdump", "path": tcpdump},
        )
    dumpcap = runner.which("dumpcap")
    if dumpcap:
        return CheckResult(
            key="capture_tool",
            label="Capture tool",
            status=CheckStatus.AVAILABLE,
            detail=f"dumpcap -> {dumpcap} (tcpdump missing, falling back to dumpcap)",
            required=True,
            evidence={"tool": "dumpcap", "path": dumpcap},
        )
    return CheckResult(
        key="capture_tool",
        label="Capture tool",
        status=CheckStatus.MISSING,
        detail="neither tcpdump nor dumpcap found",
        required=True,
        remediation="apt-get install tcpdump (or install Wireshark's dumpcap)",
    )


def _check_tool(
    tool: str,
    runner: BaseRunner,
    *,
    label: str,
    role: str,
    required: bool,
    remediation: str,
) -> CheckResult:
    path = runner.which(tool)
    if path:
        return CheckResult(
            key=f"tool_{tool}",
            label=label,
            status=CheckStatus.AVAILABLE,
            detail=f"{tool} -> {path} ({role})",
            required=required,
            evidence={"path": path},
        )
    return CheckResult(
        key=f"tool_{tool}",
        label=label,
        status=CheckStatus.MISSING,
        detail=f"{tool} not found ({role})",
        required=required,
        remediation=remediation,
    )


def _check_ipv6(runner: BaseRunner, *, required: bool) -> CheckResult:  # noqa: ARG001
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        probe.close()
    except OSError as exc:
        return CheckResult(
            key="ipv6",
            label="IPv6",
            status=CheckStatus.MISSING,
            detail=f"cannot create an IPv6 socket: {exc}",
            required=required,
            remediation="enable IPv6 on the host or restrict the experiment matrix to IPv4",
        )
    disabled_path = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6")
    disabled: str | None = None
    if disabled_path.exists():
        try:
            disabled = disabled_path.read_text(encoding="utf-8").strip()
        except OSError:  # pragma: no cover - defensive
            disabled = None
    if disabled == "1":
        return CheckResult(
            key="ipv6",
            label="IPv6",
            status=CheckStatus.MISSING,
            detail="IPv6 is disabled on this host (disable_ipv6=1)",
            required=required,
            remediation="sysctl -w net.ipv6.conf.all.disable_ipv6=0",
        )
    return CheckResult(
        key="ipv6",
        label="IPv6",
        status=CheckStatus.AVAILABLE,
        detail="IPv6 sockets available" + (f" (disable_ipv6={disabled})" if disabled is not None else ""),
        required=required,
        evidence={"disable_ipv6": disabled},
    )


def _check_netns(runner: BaseRunner) -> CheckResult:
    if platform.system() != "Linux":
        return CheckResult(
            key="netns",
            label="Network namespaces",
            status=CheckStatus.UNSUPPORTED,
            detail="network namespaces are a Linux feature",
            required=False,
        )
    result = runner.run(["ip", "netns", "list"], timeout=15.0)
    if result.ok:
        namespaces = [line.split()[0] for line in (result.stdout or "").splitlines() if line.strip()]
        return CheckResult(
            key="netns",
            label="Network namespaces",
            status=CheckStatus.AVAILABLE,
            detail=f"`ip netns list` works ({len(namespaces)} existing namespace(s))",
            required=False,
            evidence={"namespaces": namespaces},
        )
    stderr = (result.stderr or "").strip()
    return CheckResult(
        key="netns",
        label="Network namespaces",
        status=CheckStatus.MISSING,
        detail=f"`ip netns list` failed: {stderr[:160] or 'unknown error'}",
        required=False,
        remediation="root/CAP_NET_ADMIN is required; otherwise use the two-VM topology",
    )


def list_interfaces() -> list[str]:
    """Return network interface names of the host (Linux: ``/sys/class/net``)."""
    sysfs = Path("/sys/class/net")
    if sysfs.is_dir():
        return sorted(entry.name for entry in sysfs.iterdir() if entry.is_dir() and entry.name != "lo")
    return []


def _check_interfaces(runner: BaseRunner, capture_interface: str | None) -> CheckResult:
    if platform.system() != "Linux":
        return CheckResult(
            key="interfaces",
            label="Capture interface",
            status=CheckStatus.UNVERIFIED,
            detail="interface enumeration is only implemented for Linux",
            required=False,
            remediation="on Linux the interface list is read from /sys/class/net",
        )
    available = list_interfaces()
    if capture_interface is None:
        return CheckResult(
            key="interfaces",
            label="Capture interface",
            status=CheckStatus.AVAILABLE,
            detail=f"no explicit interface configured; {len(available)} candidate interface(s) found",
            required=False,
            evidence={"interfaces": available},
        )
    if capture_interface in available or capture_interface == "any":
        return CheckResult(
            key="interfaces",
            label="Capture interface",
            status=CheckStatus.AVAILABLE,
            detail=f"configured capture interface {capture_interface!r} exists",
            required=True,
            evidence={"interfaces": available},
        )
    return CheckResult(
        key="interfaces",
        label="Capture interface",
        status=CheckStatus.MISSING,
        detail=f"configured capture interface {capture_interface!r} does not exist",
        required=True,
        remediation=f"available interfaces: {', '.join(available) or 'none detected'}",
        evidence={"interfaces": available},
    )


def _check_conftest(runner: BaseRunner) -> CheckResult:
    """Check for ``ipsec conftest``, which validates config syntax offline."""
    if runner.which("ipsec") is None:
        return CheckResult(
            key="conftest",
            label="ipsec conftest",
            status=CheckStatus.MISSING,
            detail="ipsec CLI not found",
            required=False,
            remediation="ships with the strongSwan package; enables offline config syntax validation",
        )
    result = runner.run(["ipsec", "conftest"], timeout=15.0)
    combined = f"{result.stdout}\n{result.stderr}".lower()
    if "conftest" in combined:
        return CheckResult(
            key="conftest",
            label="ipsec conftest",
            status=CheckStatus.AVAILABLE,
            detail="config syntax validator available (used as a pre-flight check)",
            required=False,
        )
    return CheckResult(
        key="conftest",
        label="ipsec conftest",
        status=CheckStatus.UNVERIFIED,
        detail="ipsec CLI present but conftest behaviour could not be identified",
        required=False,
    )


def _check_wsl() -> CheckResult:
    if not is_wsl():
        return CheckResult(
            key="virtualization",
            label="Virtualization",
            status=CheckStatus.NOT_APPLICABLE,
            detail="not running inside WSL",
            required=False,
        )
    return CheckResult(
        key="virtualization",
        label="Virtualization",
        status=CheckStatus.UNVERIFIED,
        detail=(
            "WSL2 detected: XFRM behaviour depends on the WSL kernel build and is only proven by a "
            "successful SA (see the 'Kernel XFRM/IPsec' check and the first successful experiment)"
        ),
        required=False,
        remediation="for a guaranteed environment use a Linux VM or a bare metal Linux host",
    )


def check_environment(
    paths: ProjectPaths | None = None,
    runner: BaseRunner | None = None,
    *,
    expected_ip_version: int | None = None,
    capture_interface: str | None = None,
    include_tool_versions: bool = True,
) -> EnvironmentReport:
    """Run all capability checks and return the report.

    ``expected_ip_version`` marks the IPv6 check as mandatory for IPv6
    experiments; ``capture_interface`` (when given) must exist on this host.
    """
    active_runner = runner if runner is not None else SubprocessRunner()
    resolved_paths = paths if paths is not None else default_paths()

    checks: list[CheckResult] = [
        _check_platform(),
        _check_python(),
        _check_pyyaml(),
        _check_swanctl(active_runner),
        _check_charon(active_runner),
        _check_privileges(),
        _check_xfrm(active_runner),
        _check_capture_tool(active_runner),
        _check_ipv6(active_runner, required=expected_ip_version == 6),
        _check_netns(active_runner),
        _check_interfaces(active_runner, capture_interface),
        _check_wsl(),
        _check_tool(
            "strongswan",
            active_runner,
            label="strongSwan CLI",
            role="interoperability / debugging only",
            required=False,
            remediation="install the strongSwan package for `strongswan version` and `ipsec conftest`",
        ),
        _check_tool(
            "tshark",
            active_runner,
            label="tshark",
            role="capture sanity check and protocol counting",
            required=False,
            remediation="apt-get install tshark   (optional: FERA falls back to its own PCAP scanner)",
        ),
        _check_tool(
            "dumpcap",
            active_runner,
            label="dumpcap",
            role="alternative capture backend",
            required=False,
            remediation="install Wireshark/dumpcap if tcpdump is unavailable",
        ),
        _check_tool(
            "iperf3",
            active_runner,
            label="iperf3",
            role="throughput traffic for video-like flows",
            required=False,
            remediation="apt-get install iperf3   (optional: FERA falls back to its own TCP generator)",
        ),
        _check_tool(
            "curl",
            active_runner,
            label="curl",
            role="web traffic generation",
            required=False,
            remediation="apt-get install curl   (optional: only used for the web class)",
        ),
        _check_tool(
            "ping",
            active_runner,
            label="ping",
            role="ICMP traffic generation",
            required=False,
            remediation="install iputils-ping   (required for the ICMP traffic class)",
        ),
        _check_conftest(active_runner),
    ]
    versions = collect_tool_versions(active_runner) if include_tool_versions else {}
    host = dict(platform_summary())
    host["paths"] = resolved_paths.to_dict()
    host["interfaces"] = list_interfaces()
    report = EnvironmentReport(
        checks=tuple(checks),
        host=host,
        tool_versions=versions,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    logger.debug(
        "environment: ready=%s blocking=%d",
        report.ready,
        len(report.blocking_checks),
    )
    return report


def write_environment_report(report: EnvironmentReport, path: Path | str | None = None) -> Path:
    """Persist an environment report as JSON (evidence for the dataset)."""
    from ..common.serialization import write_json

    target = Path(path) if path is not None else default_paths().environment_report_file
    write_json(target, report.to_dict())
    return target


__all__ = [
    "MINIMUM_PYTHON",
    "OPTIONAL_TOOLS",
    "REQUIRED_TOOLS",
    "CheckResult",
    "CheckStatus",
    "EnvironmentReport",
    "check_environment",
    "is_wsl",
    "list_interfaces",
    "write_environment_report",
]






