"""Central experiment runner (the dataset factory pipeline).

One run executes, in order::

    LOAD EXPERIMENT -> VALIDATE CONFIG -> GENERATE STRONGSWAN CONFIG -> APPLY CONFIG
    -> START CAPTURE -> ESTABLISH IPSEC -> GENERATE TRAFFIC -> STOP CAPTURE
    -> VALIDATE OUTPUT -> SAVE PCAP + GROUND TRUTH + LOGS

Rules the runner enforces:

* an existing run directory is never overwritten silently (``--overwrite`` is
  required), so a dataset cannot be corrupted by accident,
* a run that did not establish the SA, did not generate traffic, or produced an
  invalid capture is **not** a dataset sample (``valid_capture: false``),
* failures are explicit: every early exit records an :class:`ErrorCode`,
* the machine's capabilities are checked before the first mutating step, and a
  missing strongSwan/XFRM/root fails with an actionable message instead of a
  stack trace.
"""

from __future__ import annotations

import hashlib
import os
import platform
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from ..capture.capture import CaptureResult, CaptureSession
from ..capture.filters import default_capture_filter
from ..capture.sanity import CaptureValidationResult, validate_capture
from ..common.errors import ErrorCode, FeraError
from ..common.logging_utils import add_file_handler, get_logger, register_secret, remove_handler
from ..common.paths import ProjectPaths, default_paths
from ..common.process import BaseRunner, SubprocessRunner
from ..common.serialization import write_json, write_yaml
from ..common.versions import collect_tool_versions, platform_summary
from ..experiment.gates import GateEvidence, derive_gate_state, probe_xfrm
from ..experiment.netem import NetworkCondition, plan_condition
from ..testbed.environment import EnvironmentReport, check_environment
from ..testbed.ipsec_control import IpsecController, SaState
from ..testbed.namespaces import default_socket_dir, vici_socket_path
from ..testbed.swanctl_config import generate_config, generate_psk
from ..testbed.topology import TestbedTopology, load_topology
from ..traffic.base import TrafficResult
from ..traffic.registry import generate_traffic, get_generator
from ..traffic.servers import responder_command
from .ground_truth import build_ground_truth
from .manifest import build_manifest, write_manifest
from .matrix import configuration_key
from .schema import ExperimentConfig, require_topology_compatibility

logger = get_logger(__name__)

#: Seconds of the capture window reserved for IKE negotiation and teardown.
TRAFFIC_MARGIN_S = 5.0
#: tool -> responder protocol used for traffic classes that need an answer.
RESPONDER_PROTOCOLS: Mapping[str, str] = {
    "web": "http",
    "email_like": "tcp",
    "video_like": "tcp",
    "messaging_like": "udp",
    "voip_like": "udp",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RunStatus(str, Enum):
    """Outcome of one experiment run."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    DRY_RUN = "DRY_RUN"
    SKIPPED_EXISTING = "SKIPPED_EXISTING"
    UNSUPPORTED_ENVIRONMENT = "UNSUPPORTED_ENVIRONMENT"


@dataclass(frozen=True)
class RunnerSettings:
    """Knobs of the runner (CLI options, no hidden globals)."""

    dry_run: bool = False
    overwrite: bool = False
    keep_sa: bool = False
    update_manifest: bool = False
    responder: bool = True
    capture_interface: str | None = None
    capture_filter: str | None = None
    capture_tool: str | None = None
    capture_snaplen: int = 0
    capture_grace_period_s: float = 5.0
    sa_wait_timeout_s: float = 30.0
    traffic_timeout_s: float = 300.0
    topology_path: str | None = None
    raw_dir: Path | None = None
    psk: str | None = None
    python_executable: str = "python3"
    log_level: str = "INFO"
    verify_environment: bool = True
    #: netem condition applied during the run (``"baseline"`` = none).
    network_condition: str = "baseline"
    #: Interface the qdisc is applied to.  ``None`` means the capture interface,
    #: which is what an impairment experiment actually wants to shape.
    network_interface: str | None = None
    #: Session this run belongs to.  Repeats of one configuration share a
    #: configuration but must land in the same split, so the split key is the
    #: session, not the experiment id.
    session_id: str | None = None


@dataclass(frozen=True)
class RunOutcome:
    """Result of a run, including where everything was written."""

    experiment_id: str
    status: RunStatus
    experiment_dir: Path
    error_code: ErrorCode | None = None
    message: str | None = None
    pcap_path: Path | None = None
    ground_truth_path: Path | None = None
    valid_capture: bool = False
    integration_verified: bool = False
    duration_s: float = 0.0
    capture: Mapping[str, Any] | None = None
    validation: Mapping[str, Any] | None = None
    sa: Mapping[str, Any] | None = None
    traffic: Mapping[str, Any] | None = None
    #: Evidence-gate state for this run (see :mod:`fera.experiment.gates`).
    gates: Mapping[str, Any] | None = None

    @property
    def succeeded(self) -> bool:
        return self.status is RunStatus.SUCCESS

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "status": self.status.value,
            "experiment_dir": str(self.experiment_dir),
            "error_code": self.error_code.value if self.error_code else None,
            "message": self.message,
            "pcap_path": str(self.pcap_path) if self.pcap_path else None,
            "ground_truth_path": str(self.ground_truth_path) if self.ground_truth_path else None,
            "valid_capture": self.valid_capture,
            "integration_verified": self.integration_verified,
            "duration_s": round(self.duration_s, 3),
            "capture": dict(self.capture) if self.capture else None,
            "validation": dict(self.validation) if self.validation else None,
            "sa": dict(self.sa) if self.sa else None,
            "traffic": dict(self.traffic) if self.traffic else None,
            "gates": dict(self.gates) if self.gates else None,
        }


class ExperimentRunner:
    """Runs one experiment end to end and produces the dataset artefacts."""

    def __init__(
        self,
        config: ExperimentConfig,
        *,
        paths: ProjectPaths | None = None,
        settings: RunnerSettings | None = None,
        topology: TestbedTopology | None = None,
        runner: BaseRunner | None = None,
    ) -> None:
        self.config = config
        self.paths = paths if paths is not None else default_paths()
        self.settings = settings if settings is not None else RunnerSettings()
        self.topology = topology if topology is not None else load_topology(self.settings.topology_path)
        self.command_runner = runner if runner is not None else SubprocessRunner()
        raw_root = Path(self.settings.raw_dir) if self.settings.raw_dir is not None else self.paths.raw
        self.experiment_dir = raw_root / config.experiment_id
        self.ipsec_dir = self.experiment_dir / "ipsec"
        self.secrets_dir = self.experiment_dir / "secrets"
        self.pcap_path = self.experiment_dir / "capture.pcap"
        self.ground_truth_path = self.experiment_dir / "ground_truth.json"
        self.log_path = self.experiment_dir / "execution.log"
        self._log_handler: Any | None = None
        self._capture: CaptureSession | None = None
        self._responder: Any | None = None
        self._controllers: dict[str, IpsecController] = {}
        self._started_monotonic = time.monotonic()

    # -- plumbing --------------------------------------------------------
    def endpoint_prefix(self, key: str) -> tuple[str, ...]:
        """Command prefix that executes a command on the given endpoint."""
        endpoint = self.topology.endpoint(key)
        return tuple(endpoint.wrap_command([]))

    def controller(self, key: str) -> IpsecController:
        """Return (and memoise) the swanctl controller of an endpoint."""
        if key not in self._controllers:
            uri = self._vici_uri(key)
            endpoint = self.topology.endpoint(key)
            self._controllers[key] = IpsecController(
                self.command_runner,
                endpoint_label=endpoint.describe(),
                command_prefix=self.endpoint_prefix(key),
                uri=uri,
            )
        return self._controllers[key]

    def _vici_uri(self, key: str) -> str | None:
        """VICI URI of an endpoint.

        Per endpoint charon instances (network namespace testbed) use a private
        socket; the default (``None``) leaves swanctl talking to the standard
        instance of the local host.
        """
        if self.settings.dry_run:
            return None
        endpoint = self.topology.endpoint(key)
        if endpoint.netns or endpoint.command_prefix:
            return f"unix://{vici_socket_path(default_socket_dir(), key)}"
        return None

    def capture_interface(self) -> str:
        """Interface the capture listens on (inside endpoint A)."""
        if self.settings.capture_interface:
            return self.settings.capture_interface
        if self.config.capture_interface:
            return self.config.capture_interface
        topology_interface = self.topology.capture_interface("a")
        return topology_interface or "any"

    def capture_filter(self) -> str | None:
        """BPF filter of the capture (experiment value wins over the default)."""
        if self.settings.capture_filter:
            return self.settings.capture_filter
        if self.config.capture_filter:
            return self.config.capture_filter
        return default_capture_filter(ip_version=self.config.ip_version)

    def traffic_duration(self) -> float:
        """Traffic duration inside the capture window."""
        return max(1.0, float(self.config.capture_duration_s) - TRAFFIC_MARGIN_S)

    def _resolve_psk(self) -> str:
        """Testbed PSK: explicit setting, environment, or freshly generated."""
        candidate = self.settings.psk or os.environ.get("FERA_TESTBED_PSK")
        if candidate:
            register_secret(candidate)
            return candidate
        return generate_psk()

    def _attach_execution_log(self) -> None:
        self._log_handler = add_file_handler(self.log_path, level=self.settings.log_level)

    def _detach_execution_log(self) -> None:
        remove_handler(self._log_handler)
        self._log_handler = None

    def _prepare_run_dir(self) -> None:
        """Create the run directory, refusing to overwrite an existing run."""
        if self.experiment_dir.exists() and not self.settings.overwrite:
            raise FeraError(
                f"experiment directory already exists: {self.experiment_dir}",
                code=ErrorCode.EXPERIMENT_ALREADY_EXISTS,
                hint="pass --overwrite to replace it, or use a different experiment id",
                details={"path": str(self.experiment_dir)},
            )
        self.experiment_dir.mkdir(parents=True, exist_ok=True)
        self.ipsec_dir.mkdir(parents=True, exist_ok=True)


    # -- pipeline ---------------------------------------------------------
    def run(self) -> RunOutcome:
        """Execute the full pipeline, converting failures into outcomes."""
        self._started_monotonic = time.monotonic()
        try:
            return self._run_pipeline()
        except FeraError as exc:
            logger.error("experiment failed: %s", exc)
            return self._record_failure(exc.code, exc.message, exc.details)
        except Exception as exc:  # noqa: BLE001 - never leave a half-written run unexplained
            logger.exception("unexpected error during experiment %s", self.config.experiment_id)
            return self._record_failure(
                ErrorCode.INTERNAL_ERROR,
                f"unexpected error: {type(exc).__name__}: {exc}",
            )
        finally:
            self._detach_execution_log()

    def _run_pipeline(self) -> RunOutcome:
        require_topology_compatibility(self.config, self.topology)
        self._prepare_run_dir()
        self._attach_execution_log()
        logger.info("=== FERA experiment %s ===", self.config.experiment_id)
        logger.info("%s", self.config.summary())

        write_yaml(self.experiment_dir / "experiment.yaml", self.config.to_dict())

        psk = None if self.settings.dry_run else self._resolve_psk()
        generated = generate_config(self.config, self.topology, psk=psk)
        written_files = generated.write(self.ipsec_dir, secrets_dir=self.secrets_dir)
        write_json(self.experiment_dir / "generated_config.json", generated.to_dict())
        logger.info(
            "generated strongSwan configuration for %s (ike=%s, esp=%s)",
            self.config.experiment_id,
            self.config.ike_proposal,
            self.config.esp_proposal,
        )
        secrets_file = next((f.path for f in written_files if f.contains_credentials), None)

        environment: EnvironmentReport | None = None
        if self.settings.verify_environment and not self.settings.dry_run:
            environment = check_environment(
                self.paths,
                self.command_runner,
                expected_ip_version=self.config.ip_version,
                capture_interface=self.capture_interface(),
                # The capture runs on the endpoint ("a"), so the interface must be
                # looked up in that endpoint's namespace.  On the host a testbed
                # interface such as fera-va does not exist, and checking it there
                # would abort every real run with a false "does not exist".
                interface_command_prefix=self.endpoint_prefix("a"),
            )
            write_json(self.experiment_dir / "environment.json", environment.to_dict())
            if not environment.ready:
                return self._record_environment_blocker(environment, generated)

        capture_settings = {
            "interface": self.capture_interface(),
            "filter": self.capture_filter(),
            "tool": self.settings.capture_tool,
            "pcap_path": str(self.pcap_path),
        }
        if self.settings.dry_run:
            return self._finish_dry_run(generated, capture_settings)

        self._apply_configuration(generated, secrets_file)
        self._start_capture()
        applied = self._apply_network_condition(self._netem_condition())
        try:
            sa_a, sa_b = self._establish_ipsec(generated)
            traffic_result = self._run_traffic(generated)
            capture_result = self._stop_capture()
            validation = self._validate_capture()
        finally:
            # Runs on every exit path, including a failed experiment: a qdisc
            # left behind silently changes the next run's behaviour.
            self._cleanup_network_condition(applied)
        self._teardown(generated)

        valid_capture = bool(validation.valid and traffic_result.generated)
        if not traffic_result.generated:
            logger.error("traffic generation did not succeed: %s", traffic_result.message)
        if capture_result.error_code is not None:
            logger.error("capture problem: %s", capture_result.message)

        failure_code: ErrorCode | None = None
        failure_message: str | None = None
        if not valid_capture:
            failure_code = (
                capture_result.error_code or traffic_result.error_code or ErrorCode.CAPTURE_VALIDATION_FAILED
            )
            failure_message = (
                capture_result.message
                or traffic_result.message
                or "; ".join(validation.reasons)
                or "capture did not pass validation"
            )

        gates = self._derive_gates(
            sa_a=sa_a,
            validation=validation,
            traffic_result=traffic_result,
            valid_capture=valid_capture,
        )
        write_json(self.experiment_dir / "network_condition.json", applied.to_dict())
        document = self._build_ground_truth(
            execution_status=(RunStatus.SUCCESS.value if valid_capture else RunStatus.FAILED.value),
            valid_capture=valid_capture,
            integration_verified=gates["real_ipsec_verified"],
            gate_state=gates,
            error_code=failure_code,
            error_message=failure_message,
            capture_result=capture_result,
            validation=validation,
            sa_states={"a": sa_a, "b": sa_b},
            traffic_result=traffic_result,
            generated=generated,
            network_condition=applied.to_dict(),
        )
        ground_truth_file = document.write(self.ground_truth_path)
        logger.info("ground truth written: %s", ground_truth_file)
        write_json(self.experiment_dir / "gates.json", gates)
        if not gates["real_ipsec_verified"]:
            # The capture may still be a valid file, but a run that did not prove
            # it crossed ESP must not be advertised as real-IPsec evidence.
            logger.warning(
                "run %s is not real-IPsec verified; missing evidence gates: %s",
                self.config.experiment_id,
                ", ".join(gates["missing_gates"]),
            )
        self._maybe_update_manifest()

        return RunOutcome(
            experiment_id=self.config.experiment_id,
            status=RunStatus.SUCCESS if valid_capture else RunStatus.FAILED,
            experiment_dir=self.experiment_dir,
            error_code=failure_code,
            message=failure_message,
            pcap_path=self.pcap_path,
            ground_truth_path=ground_truth_file,
            valid_capture=valid_capture,
            integration_verified=gates["real_ipsec_verified"],
            duration_s=time.monotonic() - self._started_monotonic,
            capture=capture_result.to_dict(),
            validation=validation.to_dict(),
            sa={"initiator": sa_a.to_dict(), "responder": sa_b.to_dict()},
            traffic=traffic_result.to_dict(),
            gates=gates,
        )


    # -- pipeline steps ---------------------------------------------------
    def _derive_gates(
        self,
        *,
        sa_a: SaState,
        validation: CaptureValidationResult,
        traffic_result: TrafficResult,
        valid_capture: bool,
    ) -> dict[str, Any]:
        """Collect observed evidence and hand it to the gates module.

        ``integration_verified`` used to be a literal ``True`` here, so any run
        that produced a parseable capture claimed real-IPsec integration even
        when the payload had crossed a cleartext path — the precise failure
        :mod:`fera.experiment.gates` was written to catch.  It is now derived
        from observations only.
        """
        xfrm = probe_xfrm(self.command_runner)
        evidence = GateEvidence(
            ike_established=sa_a.established,
            child_installed=sa_a.child_installed,
            # None when the probe could not run, so "not probed" is never
            # silently reported as "probed and empty".
            xfrm_state=bool(xfrm["state_entries"]) if xfrm["state_available"] else None,
            xfrm_policy=bool(xfrm["policy_entries"]) if xfrm["policy_available"] else None,
            protected_payload=traffic_result.generated,
            esp_observed=validation.esp_detected,
            details={
                "experiment_id": self.config.experiment_id,
                # Same definition of "same configuration" the coverage checker
                # uses, so gate records join to the matrix without translation.
                "configuration_id": repr(configuration_key(self.config)),
                "traffic_class": self.config.traffic_type.value,
                "xfrm": xfrm,
                "sa": sa_a.to_dict(),
                "packets": validation.packets,
            },
        )
        return derive_gate_state(evidence, failed=not valid_capture)

    def _apply_configuration(self, generated: Any, secrets_file: Path | None) -> None:
        """Load the generated connection/credential files on both endpoints."""
        for key in ("a", "b"):
            controller = self.controller(key)
            controller.require_available()
            bundle = generated.endpoint(key)
            config_file = self.ipsec_dir / f"endpoint-{key}" / bundle.file_name
            controller.load_connections(config_file)
            if secrets_file is not None:
                controller.load_credentials(secrets_file)
            logger.info("configuration loaded on %s", controller.endpoint_label)

    def _start_capture(self) -> None:
        session = CaptureSession(
            output_path=self.pcap_path,
            interface=self.capture_interface(),
            bpf_filter=self.capture_filter(),
            snaplen=self.settings.capture_snaplen,
            tool=self.settings.capture_tool,
            runner=self.command_runner,
            log_path=self.experiment_dir / "capture.log",
            command_prefix=self.endpoint_prefix("a"),
        )
        session.start()
        self._capture = session

    def _establish_ipsec(self, generated: Any) -> tuple[SaState, SaState]:
        """Initiate the SA from the initiator and verify that it came up."""
        initiator = self.controller("a")
        initiator.initiate(
            child=generated.child_name,
            timeout=max(30.0, self.settings.sa_wait_timeout_s),
        )
        state_a = initiator.wait_for_child(timeout_s=self.settings.sa_wait_timeout_s)
        state_b = self.controller("b").sa_state()
        if not state_a.usable:
            raise FeraError(
                "IPsec SA did not come up on the initiator "
                f"(IKE={state_a.ike_state}, CHILD={state_a.child_state})",
                code=ErrorCode.IPSEC_INITIATION_FAILED,
                hint=(
                    "inspect execution.log and the capture log; typical causes are a PSK mismatch, an "
                    "unsupported proposal on this strongSwan build, or a missing charon instance"
                ),
                details={
                    "initiator_state": state_a.to_dict(),
                    "responder_state": state_b.to_dict(),
                    "configured_ike_proposal": self.config.ike_proposal,
                    "configured_esp_proposal": self.config.esp_proposal,
                },
            )
        logger.info(
            "SA established: %s / %s (endpoint reported ESP: %s)",
            state_a.ike_state,
            state_a.child_state,
            state_a.esp_proposal_reported,
        )
        if not state_b.established:
            logger.warning(
                "the responder endpoint does not report an established IKE_SA (it may use a "
                "different vici socket than the one FERA queried)"
            )
        return state_a, state_b

    def _responder_protocol(self) -> str | None:
        """Protocol of the responder needed by this experiment (or ``None``)."""
        generator = get_generator(self.config.traffic_type)
        if not generator.needs_responder:
            return None
        return RESPONDER_PROTOCOLS.get(self.config.traffic_type.value)

    def _start_responder(self) -> None:
        """Start the FERA responder on endpoint B when the traffic class needs it."""
        protocol = self._responder_protocol()
        if not protocol or not self.settings.responder:
            return
        target = self.topology.traffic_target(self.config.mode_value, self.config.ip_version)
        command = responder_command(
            protocol,
            host=target,
            duration_s=self.traffic_duration() + 30.0,
            python_executable=self.settings.python_executable,
            pythonpath=self.paths.src,
        )
        self._responder = self.command_runner.spawn([*self.endpoint_prefix("b"), *command])
        logger.info("responder started on %s: %s", self.topology.endpoint_b.name, " ".join(command))
        time.sleep(1.0)  # give the responder time to bind before traffic starts

    def _stop_responder(self) -> None:
        if self._responder is None:
            return
        self._responder.stop(grace_period_s=2.0)
        self._responder = None


    def _run_traffic(self, generated: Any) -> TrafficResult:
        """Generate the experiment's traffic inside the capture window."""
        self._start_responder()
        try:
            result = generate_traffic(
                self.config.traffic_type,
                target=self.topology.traffic_target(self.config.mode_value, self.config.ip_version),
                source=self.topology.traffic_source(self.config.mode_value, self.config.ip_version),
                duration_s=self.traffic_duration(),
                ip_version=self.config.ip_version,
                port=self.config.traffic_port,
                seed=self.config.effective_seed,
                runner=self.command_runner,
                command_prefix=self.endpoint_prefix("a"),
            )
        finally:
            self._stop_responder()
        return result

    def _netem_condition(self) -> NetworkCondition:
        """The condition to apply, with its interface resolved."""
        interface = self.settings.network_interface or self.capture_interface()
        return plan_condition(self.settings.network_condition, interface=interface)

    def _apply_network_condition(self, condition: NetworkCondition) -> NetworkCondition:
        """Apply the planned qdisc and record honestly whether it took effect.

        ``fera.experiment.netem`` plans but never executes -- its docstring is
        explicit about that -- so execution lives here.  ``applied`` is set only
        when ``tc`` actually succeeded: a condition that was requested but not
        applied must never be recorded as applied, or a manifest would claim an
        impairment that did not happen.

        A condition that cannot be applied here (no interface, the baseline
        condition, or no ``tc``) is not an error.  The run proceeds unimpaired
        and says so, which is the honest outcome for a host that cannot shape
        its traffic.
        """
        command = condition.apply_command()
        if command is None:
            logger.info("network condition '%s' needs no qdisc", condition.name)
            return condition
        if not condition.executable_here():
            logger.warning(
                "cannot apply network condition '%s' on this host (interface=%r); "
                "the run proceeds unimpaired",
                condition.name,
                condition.interface,
            )
            return condition
        result = self.command_runner.run(command, timeout=30.0, check=False)
        if not result.ok:
            logger.warning(
                "network condition '%s' was not applied (tc rc=%s: %s); the run "
                "proceeds unimpaired rather than recording an impairment that "
                "did not happen",
                condition.name,
                result.returncode,
                (result.stderr or "").strip(),
            )
            return condition
        logger.info("network condition '%s' applied: %s", condition.name, " ".join(command))
        return replace(condition, applied=True)

    def _cleanup_network_condition(self, condition: NetworkCondition) -> None:
        """Remove the qdisc.  Best effort, and never the reason a run fails.

        A qdisc left behind changes the next run's behaviour, which is how "the
        second experiment behaved differently from the first" happens.
        """
        command = condition.cleanup_command()
        if command is None or not condition.applied:
            return
        try:
            result = self.command_runner.run(command, timeout=30.0, check=False)
        except Exception as exc:  # noqa: BLE001 - cleanup must not mask the result
            logger.warning("could not clean up the netem qdisc: %s", exc)
            return
        if result.ok:
            logger.info("netem qdisc removed from %s", condition.interface)
        else:
            logger.warning(
                "could not remove the netem qdisc from %s (tc rc=%s); the next run "
                "on this interface may inherit it",
                condition.interface,
                result.returncode,
            )

    def _stop_capture(self) -> CaptureResult:
        if self._capture is None:
            raise FeraError("internal error: capture was never started", code=ErrorCode.INTERNAL_ERROR)
        result = self._capture.stop(grace_period_s=self.settings.capture_grace_period_s)
        self._capture = None
        if result.error_code is not None:
            logger.error("capture unusable: %s", result.message)
        return result

    def _validate_capture(self) -> CaptureValidationResult:
        validation = validate_capture(
            self.pcap_path,
            expected_ip_version=self.config.ip_version,
            require_ike=True,
            require_esp=True,
            runner=self.command_runner,
        )
        logger.info(
            "capture validation: %s (%s)", validation.status.value, "; ".join(validation.reasons)
        )
        write_json(self.experiment_dir / "capture_validation.json", validation.to_dict())
        return validation

    def _teardown(self, generated: Any) -> None:
        """Terminate the SA unless the caller asked to keep it."""
        if self.settings.keep_sa:
            logger.info("--keep-sa: leaving the SA in place")
            return
        for key in ("a", "b"):
            try:
                self.controller(key).terminate(ike=generated.connection_name, check=False)
            except Exception as exc:  # noqa: BLE001 - teardown must never mask the result
                logger.warning("could not terminate the SA on endpoint %s: %s", key, exc)

    # -- artefacts ---------------------------------------------------------
    def _capture_sha256(self) -> str | None:
        try:
            digest = hashlib.sha256()
            with self.pcap_path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
            return digest.hexdigest()
        except OSError:  # pragma: no cover - defensive
            return None

    def _tool_versions(self) -> dict[str, str | None]:
        tools = ("swanctl", "tcpdump", "dumpcap", "tshark", "iperf3", "curl", "ping", "strongswan")
        try:
            return collect_tool_versions(self.command_runner, tools)
        except Exception:  # noqa: BLE001 - version probing must not break a run
            return {}

    @property
    def session_id(self) -> str:
        """The session this run belongs to.

        Defaults to the experiment id, which reproduces the previous split
        behaviour exactly for a single run per experiment.  Repeats must set it
        explicitly to the shared session id, otherwise each repeat would derive
        its own key and a repeated capture could leak across the split boundary.
        """
        return self.settings.session_id or self.config.experiment_id

    def _build_ground_truth(
        self,
        *,
        execution_status: str,
        valid_capture: bool,
        integration_verified: bool,
        error_code: ErrorCode | None,
        error_message: str | None,
        gate_state: Mapping[str, Any] | None = None,
        capture_result: CaptureResult | None = None,
        validation: CaptureValidationResult | None = None,
        sa_states: Mapping[str, SaState] | None = None,
        traffic_result: TrafficResult | None = None,
        generated: Any = None,
        network_condition: Mapping[str, Any] | None = None,
        notes: str | None = None,
    ) -> Any:
        capture_details: dict[str, Any] = dict(capture_result.to_dict()) if capture_result else {}
        sha256 = self._capture_sha256()
        if sha256:
            capture_details["sha256"] = sha256
        if traffic_result is not None:
            capture_details["traffic"] = traffic_result.to_dict()
        if network_condition is not None:
            # Records what was *requested* and, separately, whether it was
            # actually applied, so no artefact can claim an impairment that did
            # not happen.
            capture_details["network_condition"] = dict(network_condition)
        sa_details: dict[str, Any] = {}
        if sa_states:
            sa_details = {f"endpoint_{key}": state.to_dict() for key, state in sa_states.items()}
        return build_ground_truth(
            self.config,
            self.topology,
            execution_status=execution_status,
            dry_run=self.settings.dry_run,
            valid_capture=valid_capture,
            integration_verified=integration_verified,
            gate_state=gate_state,
            error_code=error_code.value if error_code else None,
            error_message=error_message,
            pcap_path=str(self.pcap_path),
            pcap_relative_path=self.paths.relative(self.pcap_path),
            capture_details=capture_details,
            validation=validation.to_dict() if validation else None,
            sa_details=sa_details,
            tool_versions=self._tool_versions(),
            host=platform_summary() | {"capture_environment": platform.platform()},
            timing={
                "run_started_at": datetime.fromtimestamp(
                    time.time() - (time.monotonic() - self._started_monotonic), tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "run_finished_at": _utc_now(),
                "run_duration_s": round(time.monotonic() - self._started_monotonic, 3),
            },
            experiment_config_path=self.paths.relative(self.experiment_dir / "experiment.yaml"),
            generated_config=generated.to_dict() if generated is not None else None,
            session_id=self.session_id,
            notes=notes,
        )

    def _maybe_update_manifest(self) -> None:
        if not self.settings.update_manifest:
            return
        manifest = build_manifest(paths=self.paths, raw_dir=self.experiment_dir.parent)
        target = write_manifest(manifest, self.paths.default_manifest_file)
        logger.info("dataset manifest updated: %s (%d sample(s))", target, manifest["sample_count"])


    # -- failure / dry-run bookkeeping -------------------------------------
    def _record_failure(
        self,
        code: ErrorCode,
        message: str,
        details: Mapping[str, Any] | None = None,
    ) -> RunOutcome:
        """Persist an explicit failure record (never a dataset sample)."""
        try:
            self.experiment_dir.mkdir(parents=True, exist_ok=True)
        except OSError:  # pragma: no cover - defensive
            pass
        if self.experiment_dir.is_dir():
            try:
                write_json(
                    self.experiment_dir / "failure.json",
                    {
                        "schema_version": 1,
                        "experiment_id": self.config.experiment_id,
                        "recorded_at": _utc_now(),
                        "error_code": code.value,
                        "message": message,
                        "details": dict(details or {}),
                    },
                )
                if not self.ground_truth_path.exists():
                    document = self._build_ground_truth(
                        execution_status=RunStatus.FAILED.value,
                        valid_capture=False,
                        integration_verified=False,
                        error_code=code,
                        error_message=message,
                    )
                    document.write(self.ground_truth_path)
            except OSError as exc:  # pragma: no cover - defensive
                logger.error("could not write the failure record: %s", exc)
        return RunOutcome(
            experiment_id=self.config.experiment_id,
            status=RunStatus.FAILED,
            experiment_dir=self.experiment_dir,
            error_code=code,
            message=message,
            ground_truth_path=self.ground_truth_path if self.ground_truth_path.exists() else None,
            valid_capture=False,
            integration_verified=False,
            duration_s=time.monotonic() - self._started_monotonic,
        )

    def _record_environment_blocker(self, environment: EnvironmentReport, generated: Any) -> RunOutcome:
        """Report that this machine cannot run the experiment (never faked)."""
        document = self._build_ground_truth(
            execution_status=RunStatus.UNSUPPORTED_ENVIRONMENT.value,
            valid_capture=False,
            integration_verified=False,
            error_code=environment.suggested_error_code(),
            error_message=environment.blocker_reason(),
            generated=generated,
            notes="environment blocker: " + (environment.blocker_reason() or "unknown"),
        )
        document.write(self.ground_truth_path)
        logger.error("environment not ready: %s", environment.blocker_reason())
        return RunOutcome(
            experiment_id=self.config.experiment_id,
            status=RunStatus.UNSUPPORTED_ENVIRONMENT,
            experiment_dir=self.experiment_dir,
            error_code=environment.suggested_error_code(),
            message=environment.blocker_reason(),
            ground_truth_path=self.ground_truth_path,
            valid_capture=False,
            integration_verified=False,
            duration_s=time.monotonic() - self._started_monotonic,
        )

    def _planned_capture(self) -> dict[str, Any]:
        """Capture command that *would* be used (dry run evidence)."""
        try:
            session = CaptureSession(
                output_path=self.pcap_path,
                interface=self.capture_interface(),
                bpf_filter=self.capture_filter(),
                snaplen=self.settings.capture_snaplen,
                tool=self.settings.capture_tool,
                runner=self.command_runner,
                log_path=self.experiment_dir / "capture.log",
                command_prefix=self.endpoint_prefix("a"),
                require_privileges=False,
            )
            return session.plan().to_dict()
        except FeraError as exc:
            return {"error_code": exc.code.value, "message": exc.message, "hint": exc.hint}


    def _finish_dry_run(self, generated: Any, capture_settings: Mapping[str, Any]) -> RunOutcome:
        """Write the full execution plan without touching the network."""
        from ..traffic.base import TrafficContext

        try:
            generator = get_generator(self.config.traffic_type)
            traffic_plan: dict[str, Any] = generator.build_plan(
                TrafficContext(
                    traffic_type=self.config.traffic_type,
                    target=self.topology.traffic_target(self.config.mode_value, self.config.ip_version),
                    source=self.topology.traffic_source(self.config.mode_value, self.config.ip_version),
                    ip_version=self.config.ip_version,
                    duration_s=self.traffic_duration(),
                    seed=self.config.effective_seed,
                    port=self.config.traffic_port,
                    command_prefix=self.endpoint_prefix("a"),
                )
            ).to_dict()
        except FeraError as exc:
            traffic_plan = {"error_code": exc.code.value, "message": exc.message}

        protocol = self._responder_protocol()
        plan_document = {
            "schema_version": 1,
            "experiment_id": self.config.experiment_id,
            "generated_at": _utc_now(),
            "note": "dry run: no command in this plan was executed",
            "capture": dict(capture_settings) | {"planned_command": self._planned_capture()},
            "ipsec": {
                key: {
                    "config_file": str(self.ipsec_dir / f"endpoint-{key}" / generated.endpoint(key).file_name),
                    "load_conns": self.controller(key).command(
                        "--load-conns",
                        "--file",
                        str(self.ipsec_dir / f"endpoint-{key}" / generated.endpoint(key).file_name),
                    ),
                    "initiate": self.controller(key).command("--initiate", "--child", generated.child_name),
                    "list_sas": self.controller(key).command("--list-sas"),
                    "terminate": self.controller(key).command(
                        "--terminate", "--ike", generated.connection_name
                    ),
                }
                for key in ("a", "b")
            },
            "traffic": traffic_plan,
            "responder": (
                responder_command(
                    protocol,
                    host=self.topology.traffic_target(self.config.mode_value, self.config.ip_version),
                    duration_s=self.traffic_duration() + 30.0,
                    pythonpath=self.paths.src,
                )
                if protocol
                else None
            ),
        }
        write_json(self.experiment_dir / "dry_run_plan.json", plan_document)
        document = self._build_ground_truth(
            execution_status=RunStatus.DRY_RUN.value,
            valid_capture=False,
            integration_verified=False,
            error_code=None,
            error_message=None,
            generated=generated,
            notes="dry run: configuration and commands were generated but not executed",
        )
        document.write(self.ground_truth_path)
        logger.info("dry run complete: plan written to %s", self.experiment_dir / "dry_run_plan.json")
        return RunOutcome(
            experiment_id=self.config.experiment_id,
            status=RunStatus.DRY_RUN,
            experiment_dir=self.experiment_dir,
            message="dry run: nothing was executed",
            ground_truth_path=self.ground_truth_path,
            valid_capture=False,
            integration_verified=False,
            duration_s=time.monotonic() - self._started_monotonic,
        )


def run_experiment(
    config: ExperimentConfig,
    *,
    paths: ProjectPaths | None = None,
    settings: RunnerSettings | None = None,
    topology: TestbedTopology | None = None,
    runner: BaseRunner | None = None,
) -> RunOutcome:
    """Convenience wrapper: run one validated experiment configuration."""
    return ExperimentRunner(
        config,
        paths=paths,
        settings=settings,
        topology=topology,
        runner=runner,
    ).run()


__all__ = [
    "RESPONDER_PROTOCOLS",
    "TRAFFIC_MARGIN_S",
    "ExperimentRunner",
    "RunOutcome",
    "RunStatus",
    "RunnerSettings",
    "run_experiment",
]






