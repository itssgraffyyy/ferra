"""strongSwan control plane.

Thin, explicit wrapper around ``swanctl`` (the modern, vici based interface).
FERA talks to strongSwan *only* through this module, so:

* commands are always built as argument arrays (no shell involved),
* every call can be prefixed for a network namespace or a remote host,
* a non default VICI socket is addressed with ``--uri``,
* failure modes map to explicit :class:`ErrorCode` values.

The legacy ``ipsec.conf``/``starter`` workflow is deliberately **not** mixed
in: the testbed documentation states that ``swanctl`` is required, and the
environment checker reports ``swanctl`` availability separately.
"""

from __future__ import annotations

import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..common.errors import ErrorCode, FeraError
from ..common.logging_utils import get_logger
from ..common.process import BaseRunner, CommandResult

logger = get_logger(__name__)

#: Default VICI socket of a distribution strongSwan installation.
DEFAULT_VICI_SOCKET = "/run/charon.vici"

_IKE_SA_RE = re.compile(r"^(\S+?): #(\d+), ([A-Z_]+), IKEv([12])\b")
_CHILD_SA_RE = re.compile(
    r"^(\S+?): #(\d+), reqid (\d+), ([A-Z_]+), ((?:TUNNEL|TRANSPORT|BEET|PASS|DROP)(?:-in-UDP|-in-IPCOMP|-in-IPCOMP-UDP)?), ESP:(\S+)",
)
_IKE_PROPOSAL_RE = re.compile(r"^[A-Z0-9_]+(?:-[A-Z0-9_]+)*/[A-Z0-9_]*(?:/[A-Z0-9_]+)*$")


@dataclass(frozen=True)
class SaState:
    """Self-reported state of an SA as seen by one endpoint.

    These values come from the *local* strongSwan instance (``swanctl
    --list-sas``).  They are runtime evidence, not a passive-observation claim.
    """

    ike_state: str | None = None
    child_state: str | None = None
    ike_proposal_reported: str | None = None
    esp_proposal_reported: str | None = None
    encapsulation_reported: str | None = None
    ike_sa_id: str | None = None
    child_sa_id: str | None = None
    raw: str = ""

    @property
    def established(self) -> bool:
        return self.ike_state == "ESTABLISHED"

    @property
    def child_installed(self) -> bool:
        return self.child_state == "INSTALLED"

    @property
    def usable(self) -> bool:
        """True when an IKE_SA is established and a CHILD_SA is installed."""
        return self.established and self.child_state == "INSTALLED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ike_state": self.ike_state,
            "child_state": self.child_state,
            "ike_proposal_reported_by_local_endpoint": self.ike_proposal_reported,
            "esp_proposal_reported_by_local_endpoint": self.esp_proposal_reported,
            "encapsulation_reported_by_local_endpoint": self.encapsulation_reported,
            "ike_sa_id": self.ike_sa_id,
            "child_sa_id": self.child_sa_id,
            "source": "swanctl --list-sas (local endpoint self report)",
        }


def parse_sas(output: str) -> SaState:
    """Parse the human readable output of ``swanctl --list-sas``.

    The parser is tolerant by design: unknown lines are ignored, and missing
    values stay ``None`` so that a partially established SA is reported as
    such instead of being mistaken for a healthy one.
    """
    ike_state: str | None = None
    ike_sa_id: str | None = None
    child_state: str | None = None
    child_sa_id: str | None = None
    ike_proposal: str | None = None
    esp_proposal: str | None = None
    encapsulation: str | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        child_match = _CHILD_SA_RE.match(line)
        if child_match:
            child_sa_id = child_match.group(2)
            child_state = child_match.group(4)
            encapsulation = child_match.group(5)
            esp_proposal = child_match.group(6)
            continue
        ike_match = _IKE_SA_RE.match(line)
        if ike_match:
            ike_sa_id = ike_match.group(2)
            ike_state = ike_match.group(3)
            continue
        if ike_state is not None and ike_proposal is None and _IKE_PROPOSAL_RE.match(line):
            ike_proposal = line
    return SaState(
        ike_state=ike_state,
        child_state=child_state,
        ike_proposal_reported=ike_proposal,
        esp_proposal_reported=esp_proposal,
        encapsulation_reported=encapsulation,
        ike_sa_id=ike_sa_id,
        child_sa_id=child_sa_id,
        raw=output,
    )


class IpsecController:
    """Controls the strongSwan instance of a single endpoint."""

    def __init__(
        self,
        runner: BaseRunner,
        *,
        endpoint_label: str,
        command_prefix: Sequence[str] = (),
        swanctl: str = "swanctl",
        uri: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.runner = runner
        self.endpoint_label = endpoint_label
        self.command_prefix = tuple(str(part) for part in command_prefix)
        self.swanctl = swanctl
        self.uri = uri
        self.timeout = timeout

    # -- command construction -------------------------------------------
    def command(self, *arguments: str) -> list[str]:
        """Build the full swanctl command for this endpoint.

        The VICI socket is selected with ``--uri`` when configured, and the
        command is prefixed for the endpoint (``ip netns exec ...`` or
        ``ssh ...``) when the endpoint is not local.

        ``--uri`` is appended *after* the subcommand on purpose.  swanctl parses
        its general options only once it has seen the subcommand, so
        ``swanctl --uri <uri> --stats`` dies with ``unrecognized option '--uri'``
        while ``swanctl --stats --uri <uri>`` connects: a leading ``--uri`` makes
        every control call fail and the daemon look unreachable.
        """
        parts = [self.swanctl, *(str(argument) for argument in arguments)]
        if self.uri:
            parts += ["--uri", self.uri]
        return [*self.command_prefix, *parts]

    @property
    def available(self) -> bool:
        """True when the swanctl binary can be resolved on this endpoint."""
        return self.runner.which(self.swanctl) is not None

    def require_available(self) -> None:
        """Raise an explicit error when swanctl is missing."""
        if not self.available:
            raise FeraError(
                f"swanctl is not available on {self.endpoint_label}",
                code=ErrorCode.SWANCTL_NOT_AVAILABLE,
                hint="install strongSwan (strongswan + strongswan-swanctl) on the endpoint, "
                "or point FERA at a host that has it",
                details={"endpoint": self.endpoint_label, "swanctl": self.swanctl},
            )

    # -- low level -------------------------------------------------------
    def _run(
        self,
        *arguments: str,
        timeout: float | None = None,
        check: bool = True,
        error_code: ErrorCode = ErrorCode.IPSEC_CONFIG_APPLY_FAILED,
        error_message: str = "swanctl command failed",
    ) -> CommandResult:
        command = self.command(*arguments)
        result = self.runner.run(command, timeout=timeout or self.timeout)
        if not result.ok:
            logger.error("%s: %s (rc=%s)", self.endpoint_label, error_message, result.returncode)
            if check:
                raise FeraError(
                    f"{error_message} on {self.endpoint_label}: {result.display}",
                    code=error_code,
                    hint="inspect swanctl stderr/daemon log in the execution log",
                    details={
                        "endpoint": self.endpoint_label,
                        "command": result.display,
                        "returncode": result.returncode,
                        "stderr_tail": result.stderr[-2000:],
                    },
                )
        return result

    # -- configuration ---------------------------------------------------
    def load_connections(self, config_file: Path | str, *, check: bool = True) -> CommandResult:
        """Load the ``connections`` section of a specific file."""
        return self._run(
            "--load-conns",
            "--file",
            str(config_file),
            check=check,
            error_message="loading swanctl connections failed",
        )

    def load_credentials(self, secrets_file: Path | str, *, check: bool = True) -> CommandResult:
        """Load the ``secrets`` section of a specific file."""
        return self._run(
            "--load-creds",
            "--file",
            str(secrets_file),
            check=check,
            error_message="loading swanctl credentials failed",
        )

    def load_all(self, config_file: Path | str, *, check: bool = True) -> CommandResult:
        """Load connections, credentials, pools and authorities from one file."""
        return self._run(
            "--load-all",
            "--file",
            str(config_file),
            check=check,
            error_message="loading swanctl configuration failed",
        )

    def list_connections(self, *, check: bool = False) -> CommandResult:
        return self._run("--list-conns", check=check, error_message="listing connections failed")

    def stats(self, *, check: bool = False) -> CommandResult:
        return self._run("--stats", check=check, error_message="querying daemon stats failed")

    def list_algorithms(self, *, raw: bool = True, check: bool = False) -> CommandResult:
        """Return the algorithms the local daemon actually loaded.

        Recorded as evidence in the environment report / execution log; FERA
        does not *pretend* to map these names onto proposal keywords.
        """
        return self._run(
            "--list-algs",
            *(("--raw",) if raw else ()),
            check=check,
            error_message="listing algorithms failed",
        )

    def version(self) -> str | None:
        """Return the swanctl version string, or ``None`` when unavailable."""
        if not self.available:
            return None
        result = self._run("--version", check=False)
        return (result.stdout or result.stderr).strip().splitlines()[0] if result.ok else None


    # -- SA lifecycle ----------------------------------------------------
    def initiate(
        self,
        *,
        child: str,
        timeout: float | None = None,
        check: bool = True,
    ) -> CommandResult:
        """Initiate a CHILD_SA (and the IKE_SA it belongs to)."""
        return self._run(
            "--initiate",
            "--child",
            child,
            timeout=timeout,
            check=check,
            error_code=ErrorCode.IPSEC_INITIATION_FAILED,
            error_message="IPsec initiation failed",
        )

    def initiate_ike(self, *, ike: str, timeout: float | None = None, check: bool = True) -> CommandResult:
        """Initiate an IKE_SA without a specific CHILD_SA."""
        return self._run(
            "--initiate",
            "--ike",
            ike,
            timeout=timeout,
            check=check,
            error_code=ErrorCode.IPSEC_INITIATION_FAILED,
            error_message="IPsec IKE_SA initiation failed",
        )

    def terminate(self, *, ike: str, check: bool = False) -> CommandResult:
        """Terminate an IKE_SA (and all its CHILD_SAs)."""
        return self._run("--terminate", "--ike", ike, check=check, error_message="termination failed")

    def list_sas(self, *, check: bool = False) -> CommandResult:
        return self._run("--list-sas", check=check, error_message="listing SAs failed")

    def sa_state(self) -> SaState:
        """Return the current SA state of this endpoint."""
        result = self.list_sas(check=False)
        if not result.ok and not result.executed:
            return SaState(raw="<not executed>")
        return parse_sas(result.stdout or "")

    def wait_for_child(
        self,
        *,
        timeout_s: float = 30.0,
        poll_interval_s: float = 1.0,
        sleep: Any = time.sleep,
    ) -> SaState:
        """Poll ``swanctl --list-sas`` until the CHILD_SA is installed.

        Returns the last observed state; the caller decides whether the timeout
        is a failure (an unestablished SA must never be recorded as a valid
        sample).  ``sleep`` is injectable so tests run instantly.
        """
        deadline = time.monotonic() + max(0.0, timeout_s)
        state = self.sa_state()
        while not state.usable and time.monotonic() < deadline:
            sleep(poll_interval_s)
            state = self.sa_state()
        if state.usable:
            logger.info(
                "%s: SA established (IKE=%s, CHILD=%s, ESP reported=%s)",
                self.endpoint_label,
                state.ike_state,
                state.child_state,
                state.esp_proposal_reported,
            )
        else:
            logger.warning(
                "%s: SA not established within %.1fs (IKE=%s, CHILD=%s)",
                self.endpoint_label,
                timeout_s,
                state.ike_state,
                state.child_state,
            )
        return state


__all__ = [
    "DEFAULT_VICI_SOCKET",
    "IpsecController",
    "SaState",
    "parse_sas",
]


