"""strongSwan ``swanctl`` configuration generation.

FERA never keeps hand-copied strongSwan configuration files: every experiment
renders its configuration from the experiment schema plus the testbed topology.

Two files are produced per endpoint:

``swanctl.conf``
    The reproducible connection/child definition.  Contains no credentials, so
    it can be committed with a dataset or attached to a report.
``swanctl.secrets``
    Optional PSK credential file (mode 0600).  Written only when a secret is
    supplied, never logged, and never part of an experiment's public artefacts.

The generated configuration follows the documented proposal syntax
(``encryption[-integrity|-prf]-dh`` for IKE, ``encryption[-integrity][-dh]``
for ESP) and encodes PFS exactly as strongSwan does: a CHILD_SA proposal
contains a DH group if and only if PFS is requested.
"""

from __future__ import annotations

import secrets as secrets_module
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..common.errors import ConfigValidationError
from ..common.logging_utils import register_secret
from ..dataset.schema import ExperimentConfig, IpsecMode
from .topology import TestbedTopology, host_address

#: Default jitter for rekey operations.  Set to zero so that a capture window
#: observes a deterministic rekey schedule.
RAND_TIME = "0s"
#: Seconds of DPD inactivity before a peer is probed.
DPD_DELAY = "30s"


def format_swanctl_time(seconds: int) -> str:
    """Format a duration as a strongSwan time value (``3600s``)."""
    return f"{int(seconds)}s"


def generate_psk(nbytes: int = 32) -> str:
    """Generate a random pre-shared key for the isolated testbed.

    The value is a hex string (so it survives every quoting layer intact) and is
    registered for log redaction immediately.
    """
    if nbytes < 16:
        raise ConfigValidationError("testbed PSK must be at least 16 bytes")
    value = secrets_module.token_hex(nbytes)
    register_secret(value)
    return value


@dataclass(frozen=True)
class GeneratedFile:
    """One generated configuration file."""

    path: Path
    content: str
    kind: str
    contains_credentials: bool = False
    mode: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "kind": self.kind,
            "contains_credentials": self.contains_credentials,
            "mode": f"0{self.mode:o}" if self.mode else None,
        }


def connection_name(experiment_id: str) -> str:
    """Name of the generated IKE connection (deterministic)."""
    return f"fera-{experiment_id}"


def child_name(experiment_id: str) -> str:
    """Name of the generated CHILD_SA (deterministic)."""
    return f"fera-child-{experiment_id}"


def render_header(
    config: ExperimentConfig,
    *,
    endpoint_label: str,
    generated_at: str | None = None,
) -> str:
    """Return the informational comment block of a generated file."""
    timestamp = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    transforms = config.transforms
    lines = [
        "# FERA - generated strongSwan swanctl configuration.  Do not edit by hand.",
        f"# experiment            : {config.experiment_id}",
        f"# configuration hash    : {config.fingerprint}",
        f"# endpoint              : {endpoint_label}",
        f"# ipsec mode            : {config.mode.value}",
        f"# ike version           : {config.ike_version}",
        f"# ike proposal          : {transforms.ike_proposal}",
        f"# esp proposal          : {transforms.esp_proposal}",
        f"# pfs                   : {transforms.pfs_description}",
        f"# integrity source      : {transforms.to_dict()['integrity_source']}",
        f"# ip version            : {config.ip_version}",
        f"# ike sa rekey time     : {format_swanctl_time(config.ike_sa_lifetime_s)}",
        f"# child sa rekey time   : {format_swanctl_time(config.child_sa_lifetime_s)}",
        f"# generated             : {timestamp}",
        "# regenerate with      : python scripts/run_experiment.py --config <experiment>",
        "# credentials are kept out of this file on purpose (see swanctl.secrets).",
        "",
    ]
    return "\n".join(lines)


def render_swanctl_conf(
    config: ExperimentConfig,
    topology: TestbedTopology,
    endpoint_key: str,
    *,
    generated_at: str | None = None,
) -> str:
    """Render the ``swanctl.conf`` for one endpoint of an experiment.

    ``endpoint_key`` selects the endpoint (``"a"``/``"b"``); the local and
    remote sides, the traffic selectors and the IKE identities are derived from
    it, so both endpoints always describe the *same* SA mirror-symmetrically.
    """
    endpoint = topology.endpoint(endpoint_key)
    peer = topology.peer_of(endpoint_key)
    if not endpoint.supports(config.ip_version) or not peer.supports(config.ip_version):
        raise ConfigValidationError(
            f"endpoint {endpoint.name!r} or its peer has no IPv{config.ip_version} address",
            hint="choose an experiment IP version supported by both endpoints",
        )
    local_address = host_address(str(endpoint.outer_address(config.ip_version)))
    remote_address = host_address(str(peer.outer_address(config.ip_version)))
    selectors = topology.selectors(
        config.mode_value,
        config.ip_version,
        direction="a_to_b" if endpoint.role == "initiator" else "b_to_a",
    )
    if config.mode is IpsecMode.TRANSPORT and not selectors.host_to_host:
        raise ConfigValidationError(
            "transport mode requires host selectors, refusing to generate a subnet based configuration",
            details=selectors.to_dict(),
        )
    transforms = config.transforms
    conn = connection_name(config.experiment_id)
    child = child_name(config.experiment_id)
    header = render_header(config, endpoint_label=endpoint.describe(), generated_at=generated_at)

    body = f"""connections {{
\t{conn} {{
\t\tversion      = {config.ike_version}
\t\tlocal_addrs  = {local_address}
\t\tremote_addrs = {remote_address}
\t\tproposals    = {transforms.ike_proposal}
\t\trekey_time   = {format_swanctl_time(config.ike_sa_lifetime_s)}
\t\treauth_time  = 0s
\t\tdpd_delay    = {DPD_DELAY}
\t\tmobike       = no
\t\tencap       = no

\t\tlocal {{
\t\t\tauth = psk
\t\t\tid   = {endpoint.ike_id}
\t\t}}

\t\tremote {{
\t\t\tauth = psk
\t\t\tid   = {peer.ike_id}
\t\t}}

\t\tchildren {{
\t\t\t{child} {{
\t\t\t\tmode          = {config.mode.value}
\t\t\t\tlocal_ts      = {selectors.local_ts}
\t\t\t\tremote_ts     = {selectors.remote_ts}
\t\t\t\tesp_proposals = {transforms.esp_proposal}
\t\t\t\trekey_time    = {format_swanctl_time(config.child_sa_lifetime_s)}
\t\t\t\tlife_time     = {format_swanctl_time(config.child_sa_life_time_s())}
\t\t\t\trand_time     = {RAND_TIME}
\t\t\t\tstart_action  = none
\t\t\t\tdpd_action    = clear
\t\t\t\tclose_action  = none
\t\t\t}}
\t\t}}
\t}}
}}
"""
    return header + body


def render_secrets_file(
    config: ExperimentConfig,
    topology: TestbedTopology,
    psk: str,
    *,
    generated_at: str | None = None,
) -> str:
    """Render the PSK credential file for an experiment.

    Both peer identities are listed with the same secret, so initiator and
    responder locate the credential for either direction of the SA.
    """
    header = render_header(config, endpoint_label="shared credentials", generated_at=generated_at)
    entries = []
    for index, endpoint in enumerate((topology.endpoint_a, topology.endpoint_b), start=1):
        entries.append(
            f"\tike-fera-{index} {{\n\t\tid     = {endpoint.ike_id}\n\t\tsecret = {psk}\n\t}}"
        )
    body = "secrets {\n" + "\n".join(entries) + "\n}\n"
    return header + body


@dataclass(frozen=True)
class EndpointConfigBundle:
    """Generated configuration of a single endpoint."""

    key: str
    endpoint_name: str
    role: str
    connection_name: str
    child_name: str
    content: str
    file_name: str = "swanctl.conf"

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint_key": self.key,
            "endpoint_name": self.endpoint_name,
            "role": self.role,
            "connection_name": self.connection_name,
            "child_name": self.child_name,
            "file_name": self.file_name,
            "sha256": _sha256(self.content),
            "bytes": len(self.content.encode("utf-8")),
        }


@dataclass(frozen=True)
class SwanctlConfigBundle:
    """Everything needed to apply one experiment to a strongSwan testbed."""

    experiment_id: str
    connection_name: str
    child_name: str
    endpoint_a: EndpointConfigBundle
    endpoint_b: EndpointConfigBundle
    secrets_content: str | None = None
    secrets_file_name: str = "swanctl.secrets"

    @property
    def endpoints(self) -> tuple[EndpointConfigBundle, ...]:
        return (self.endpoint_a, self.endpoint_b)

    def endpoint(self, key: str) -> EndpointConfigBundle:
        for bundle in self.endpoints:
            if bundle.key == key:
                return bundle
        raise ConfigValidationError(f"unknown endpoint key {key!r}", hint="use a|b")

    def to_dict(self) -> dict[str, Any]:
        """Metadata of the generated configuration (never the PSK itself)."""
        return {
            "connection_name": self.connection_name,
            "child_name": self.child_name,
            "endpoints": [bundle.to_dict() for bundle in self.endpoints],
            "credentials_file": (
                {
                    "file_name": self.secrets_file_name,
                    "sha256": _sha256(self.secrets_content or ""),
                    "contains_credentials": True,
                    "value": "redacted",
                }
                if self.secrets_content
                else None
            ),
        }

    def write(self, base_dir: Path, *, secrets_dir: Path | None = None) -> list[GeneratedFile]:
        """Write the generated files.

        ``base_dir`` receives one sub directory per endpoint.  The secrets file
        (when present) is written to ``secrets_dir`` - a location that is kept
        out of the dataset and excluded from version control - with mode 0600.
        """
        base = Path(base_dir)
        written: list[GeneratedFile] = []
        for bundle in self.endpoints:
            directory = base / _endpoint_directory(bundle)
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / bundle.file_name
            path.write_text(bundle.content, encoding="utf-8", newline="\n")
            written.append(GeneratedFile(path=path, content=bundle.content, kind="swanctl.conf"))
        if self.secrets_content:
            target_dir = Path(secrets_dir) if secrets_dir is not None else base / "secrets"
            target_dir.mkdir(parents=True, exist_ok=True)
            secret_path = target_dir / self.secrets_file_name
            secret_path.write_text(self.secrets_content, encoding="utf-8", newline="\n")
            try:  # POSIX only; on Windows the mode argument is ignored
                secret_path.chmod(0o600)
            except OSError:  # pragma: no cover - platform dependent
                pass
            written.append(
                GeneratedFile(
                    path=secret_path,
                    content=self.secrets_content,
                    kind="swanctl.secrets",
                    contains_credentials=True,
                    mode=0o600,
                )
            )
        return written


def _endpoint_directory(bundle: EndpointConfigBundle) -> str:
    return f"endpoint-{bundle.key}"


def _sha256(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def render_strongswan_conf(
    *,
    vici_socket: str,
    log_file: str | None = None,
    threads: int = 8,
) -> str:
    """Render a ``strongswan.conf`` for a dedicated charon instance.

    Used by the network namespace testbed, where each endpoint runs its own
    charon with a private VICI socket (``swanctl --uri`` then talks to exactly
    one endpoint instance).

    ``strongswan.conf(5)`` documents settings in the dotted spelling (the VICI
    socket is ``charon.plugins.vici.socket``), but that is documentation
    notation: the settings parser reads a section key as a NAME and stops at a
    dot, so a dotted key is a syntax error (*unexpected ., expecting : or '{'
    or '='*) and charon aborts during startup instead of running.  The file is
    therefore written in the nested form, matching ``/etc/strongswan.conf``.

    The same rule applies to the filelog ``<name>``, which is a section key
    too, so a log path like ``.../charon-a.log`` cannot be the section name:
    it is passed as ``path`` instead, which ``strongswan.conf(5)`` says must be
    used "if the path contains characters that aren't allowed in section
    names".
    """
    socket_uri = vici_socket if vici_socket.startswith("unix://") else f"unix://{vici_socket}"
    lines = [
        "# FERA - generated strongswan.conf for a dedicated charon instance.",
        "# vici socket of this instance:",
        "charon {",
        "  plugins {",
        "    vici {",
        f"      socket = {socket_uri}",
        "    }",
        "    # The resolve plugin runs /sbin/resolvconf synchronously while the",
        "    # daemon starts.  On hosts where that is a symlink to resolvectl it",
        "    # waits for systemd-resolved and never returns, which leaves charon",
        "    # accepting VICI connections but never answering them: swanctl hangs",
        "    # on every command and the testbed looks like a slow daemon.",
        "    # A testbed endpoint needs no DNS servers installed.",
        "    resolve {",
        "      load = no",
        "    }",
        "  }",
        f"  threads = {int(threads)}",
    ]
    if log_file:
        lines += [
            "  filelog {",
            "    fera {",
            f"      path = {log_file}",
            "      default = 1",
            "      flush_line = yes",
            "    }",
            "  }",
        ]
    lines.append("}")
    return "\n".join(lines) + "\n"


def generate_config(
    config: ExperimentConfig,
    topology: TestbedTopology,
    *,
    psk: str | None = None,
    generated_at: str | None = None,
) -> SwanctlConfigBundle:
    """Generate the strongSwan configuration bundle for one experiment.

    Parameters
    ----------
    config:
        Validated experiment definition.
    topology:
        Testbed the experiment will run on.
    psk:
        Pre-shared key for the testbed.  When omitted, no credential file is
        generated (useful for ``--dry-run`` and for syntax checks).
    """
    bundle_a = EndpointConfigBundle(
        key="a",
        endpoint_name=topology.endpoint_a.name,
        role=topology.endpoint_a.role,
        connection_name=connection_name(config.experiment_id),
        child_name=child_name(config.experiment_id),
        content=render_swanctl_conf(config, topology, "a", generated_at=generated_at),
    )
    bundle_b = EndpointConfigBundle(
        key="b",
        endpoint_name=topology.endpoint_b.name,
        role=topology.endpoint_b.role,
        connection_name=connection_name(config.experiment_id),
        child_name=child_name(config.experiment_id),
        content=render_swanctl_conf(config, topology, "b", generated_at=generated_at),
    )
    secrets_content = (
        render_secrets_file(config, topology, psk, generated_at=generated_at) if psk else None
    )
    if psk:
        register_secret(psk)
    return SwanctlConfigBundle(
        experiment_id=config.experiment_id,
        connection_name=connection_name(config.experiment_id),
        child_name=child_name(config.experiment_id),
        endpoint_a=bundle_a,
        endpoint_b=bundle_b,
        secrets_content=secrets_content,
    )


__all__ = [
    "DPD_DELAY",
    "RAND_TIME",
    "EndpointConfigBundle",
    "GeneratedFile",
    "SwanctlConfigBundle",
    "child_name",
    "connection_name",
    "format_swanctl_time",
    "generate_config",
    "generate_psk",
    "render_header",
    "render_secrets_file",
    "render_strongswan_conf",
    "render_swanctl_conf",
]



