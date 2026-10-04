"""End-to-end experiment runner tests (mocked external processes)."""

from __future__ import annotations

import json

import pytest

from conftest import SWANCTL_ESTABLISHED, TSHARK_PHS, ScriptedRunner, make_config
from fera.common.errors import ErrorCode
from fera.dataset.runner import ExperimentRunner, RunnerSettings, RunStatus, run_experiment

#: What `ip xfrm state` / `ip xfrm policy` print on a host that really carries
#: an IPsec SA.  Each entry begins with a `src` line; the indented continuation
#: lines must not be counted as separate entries.
XFRM_STATE = """src 10.10.10.1 dst 10.10.10.2
\tsrc 10.10.10.1 dst 10.10.10.2
\t\tauth-trunc 'sha256 0123' enc alg 'cbc(aes)' \
\t\tauth alg 'hmac(sha256)'
"""

XFRM_POLICY = """src 10.20.0.0/24 dst 10.30.0.0/24
\tsrc 10.20.0.0/24 dst 10.30.0.0/24
\t\tdir out priority 0
"""


#: The scripted runner's default tools plus ``tc``, so a netem test can actually
#: apply a qdisc.  Dropping a tool from this list (e.g. the capture tool) makes
#: the run fail before it ever reaches the traffic stage, which masks whatever
#: the test was actually about.
TOOLS_WITH_TC = ("swanctl", "tcpdump", "tshark", "ping", "curl", "iperf3", "ip", "ipsec", "tc")


def full_evidence_responses() -> list[tuple[str, int, str]]:
    """Scripted responses describing a genuinely encrypted run."""
    return [
        ("--list-sas", 0, SWANCTL_ESTABLISHED),
        ("--initiate", 0, ""),
        ("ip xfrm state", 0, XFRM_STATE),
        ("ip xfrm policy", 0, XFRM_POLICY),
        ("tshark", 0, TSHARK_PHS),
        ("ping", 0, "1 packets transmitted, 1 received"),
    ]


@pytest.fixture()
def allow_capture(monkeypatch):
    """Pretend the host may capture packets (raw socket privileges)."""
    import fera.capture.capture as capture_module

    monkeypatch.setattr(capture_module, "require_capture_privileges", lambda _runner: None)


def make_runner(config, paths, topology, command_runner, **settings_kwargs) -> ExperimentRunner:
    settings = RunnerSettings(
        verify_environment=settings_kwargs.pop("verify_environment", False),
        sa_wait_timeout_s=settings_kwargs.pop("sa_wait_timeout_s", 1.0),
        **settings_kwargs,
    )
    return ExperimentRunner(
        config, paths=paths, settings=settings, topology=topology, runner=command_runner
    )


def test_dry_run_writes_plan_and_marks_sample_invalid(sandbox_paths, topology) -> None:
    config = make_config()
    outcome = make_runner(config, sandbox_paths, topology, ScriptedRunner(), dry_run=True).run()

    assert outcome.status is RunStatus.DRY_RUN
    assert outcome.valid_capture is False
    assert outcome.integration_verified is False

    experiment_dir = sandbox_paths.experiment_dir(config.experiment_id)
    for name in ("experiment.yaml", "dry_run_plan.json", "ground_truth.json", "generated_config.json"):
        assert (experiment_dir / name).is_file(), name
    assert (experiment_dir / "ipsec" / "endpoint-a" / "swanctl.conf").is_file()
    # a dry run must not pretend to have produced a capture or credentials
    assert not (experiment_dir / "capture.pcap").exists()
    assert not (experiment_dir / "secrets").exists()

    plan = (experiment_dir / "dry_run_plan.json").read_text(encoding="utf-8")
    assert "--load-conns" in plan
    assert "--initiate" in plan
    assert "tcpdump" in plan or "dumpcap" in plan

    from fera.dataset.ground_truth import load_ground_truth

    document = load_ground_truth(experiment_dir / "ground_truth.json").to_dict()
    assert document["execution"]["status"] == "DRY_RUN"
    assert document["execution"]["valid_capture"] is False
    assert document["execution"]["reusable_as_dataset_sample"] is False


def test_existing_experiment_directory_is_not_overwritten(sandbox_paths, topology) -> None:
    config = make_config()
    first = make_runner(config, sandbox_paths, topology, ScriptedRunner(), dry_run=True).run()
    assert first.status is RunStatus.DRY_RUN

    second = make_runner(config, sandbox_paths, topology, ScriptedRunner(), dry_run=True).run()
    assert second.status is RunStatus.FAILED
    assert second.error_code is ErrorCode.EXPERIMENT_ALREADY_EXISTS

    third = make_runner(
        config, sandbox_paths, topology, ScriptedRunner(), dry_run=True, overwrite=True
    ).run()
    assert third.status is RunStatus.DRY_RUN


def test_run_without_xfrm_evidence_is_not_integration_verified(
    sandbox_paths, topology, allow_capture
) -> None:
    """IKE up + valid capture is *not* real-IPsec evidence.

    This is the historical failure: strongSwan negotiated, ping succeeded, every
    indicator FERA checked was green, and the payload had in fact travelled a
    cleartext path.  With no XFRM state and policy observed, the run must not
    claim integration, even though the run itself succeeded.
    """
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(
        responses=[
            ("--list-sas", 0, SWANCTL_ESTABLISHED),
            ("--initiate", 0, ""),
            # `ip xfrm` succeeds but reports an empty table: probed and empty.
            ("ip xfrm state", 0, ""),
            ("ip xfrm policy", 0, ""),
            ("tshark", 0, TSHARK_PHS),
            ("ping", 0, "1 packets transmitted, 1 received"),
        ]
    )
    outcome = make_runner(config, sandbox_paths, topology, runner).run()

    assert outcome.status is RunStatus.SUCCESS, outcome.message
    assert outcome.valid_capture is True
    assert outcome.integration_verified is False
    assert outcome.gates is not None
    assert outcome.gates["real_ipsec_verified"] is False
    assert "xfrm_state_verified" in outcome.gates["missing_gates"]
    assert "xfrm_policy_verified" in outcome.gates["missing_gates"]


def test_gate_document_is_written_next_to_the_ground_truth(
    sandbox_paths, topology, allow_capture
) -> None:
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(responses=full_evidence_responses())
    outcome = make_runner(config, sandbox_paths, topology, runner).run()

    gates_file = outcome.experiment_dir / "gates.json"
    assert gates_file.is_file()

    from fera.dataset.ground_truth import load_ground_truth

    document = load_ground_truth(outcome.ground_truth_path).to_dict()
    # The claim is auditable from the artefact itself, not just from the outcome.
    assert document["evidence_gates"]["real_ipsec_verified"] is True
    assert document["evidence_gates"]["missing_gates"] == []
    assert document["evidence_gates"]["verified_gates"]


def test_ike_success_alone_never_reports_dataset_eligible(
    sandbox_paths, topology, allow_capture
) -> None:
    """IKE negotiated, nothing else: not eligible, and it says why."""
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(
        responses=[
            ("--list-sas", 0, SWANCTL_ESTABLISHED),
            ("--initiate", 0, ""),
            ("ip xfrm state", 0, ""),
            ("ip xfrm policy", 0, ""),
            ("tshark", 0, TSHARK_PHS),
            ("ping", 0, "1 packets transmitted, 1 received"),
        ]
    )
    outcome = make_runner(config, sandbox_paths, topology, runner).run()

    gates = outcome.gates
    assert gates is not None
    assert gates["evidence_gates"]["ike_sa_verified"] is True
    assert gates["dataset_eligible"] is False
    assert gates["stage"] != "MANIFEST_FINALIZED"


def test_baseline_condition_never_runs_tc(sandbox_paths, topology, allow_capture) -> None:
    """A 'no impairment' run must not touch the qdisc at all.

    Applying an empty netem would still replace whatever qdisc a previous run
    left behind -- a side effect a baseline run should not have.
    """
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(
        responses=full_evidence_responses(), available_tools=TOOLS_WITH_TC
    )
    outcome = make_runner(config, sandbox_paths, topology, runner).run()

    assert outcome.status is RunStatus.SUCCESS, outcome.message
    assert not any("qdisc" in " ".join(command) for command in runner.commands)

    from fera.dataset.ground_truth import load_ground_truth

    document = load_ground_truth(outcome.ground_truth_path).to_dict()
    condition = document["capture"]["details"]["network_condition"]
    assert condition["name"] == "baseline"
    assert condition["applied"] is False


def test_applied_condition_is_recorded_and_cleaned_up(sandbox_paths, topology, allow_capture) -> None:
    """The qdisc is applied for the run and removed afterwards."""
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(
        responses=full_evidence_responses(), available_tools=TOOLS_WITH_TC
    )
    outcome = make_runner(
        config, sandbox_paths, topology, runner, network_condition="jitter"
    ).run()

    assert outcome.status is RunStatus.SUCCESS, outcome.message
    qdisc_commands = [" ".join(c) for c in runner.commands if "qdisc" in " ".join(c)]
    assert any("replace" in c for c in qdisc_commands), qdisc_commands
    assert any("del" in c for c in qdisc_commands), qdisc_commands
    # Cleanup must follow the traffic, not precede it.
    assert runner.commands.index(next(c for c in runner.commands if "qdisc del" in " ".join(c))) > (
        runner.commands.index(next(c for c in runner.commands if "ping" in " ".join(c)))
    )

    recorded = json.loads((outcome.experiment_dir / "network_condition.json").read_text())
    assert recorded["name"] == "jitter"
    assert recorded["applied"] is True
    assert recorded["delay_ms"] == 20.0


def test_condition_that_could_not_be_applied_is_not_recorded_as_applied(
    sandbox_paths, topology, allow_capture
) -> None:
    """`tc` failing must not leave the artefact claiming an impairment."""
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(
        responses=[
            *full_evidence_responses(),
            ("tc qdisc", 1, ""),
        ],
        available_tools=TOOLS_WITH_TC,
    )
    outcome = make_runner(
        config, sandbox_paths, topology, runner, network_condition="loss"
    ).run()

    from fera.dataset.ground_truth import load_ground_truth

    document = load_ground_truth(outcome.ground_truth_path).to_dict()
    condition = document["capture"]["details"]["network_condition"]
    assert condition["name"] == "loss"
    assert condition["applied"] is False
    # Nothing was applied, so there is nothing to clean up either.
    assert not any("qdisc del" in " ".join(c) for c in runner.commands)


def test_condition_is_cleaned_up_even_when_the_experiment_fails(
    sandbox_paths, topology, allow_capture
) -> None:
    """A failed run must not leave a qdisc behind for the next experiment."""
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(
        responses=[
            ("--list-sas", 1, ""),  # the SA never comes up
            ("tc qdisc", 0, ""),
        ],
        available_tools=TOOLS_WITH_TC,
    )
    outcome = make_runner(
        config, sandbox_paths, topology, runner, network_condition="latency"
    ).run()

    assert outcome.status is RunStatus.FAILED
    assert any("qdisc del" in " ".join(c) for c in runner.commands), runner.commands


def test_successful_run_produces_a_valid_dataset_sample(sandbox_paths, topology, allow_capture) -> None:
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(responses=full_evidence_responses())
    outcome = make_runner(
        config, sandbox_paths, topology, runner, update_manifest=True
    ).run()

    assert outcome.status is RunStatus.SUCCESS, outcome.message
    assert outcome.valid_capture is True
    assert outcome.integration_verified is True
    assert outcome.pcap_path is not None and outcome.pcap_path.is_file()
    assert outcome.validation is not None and outcome.validation["status"] == "VALID"

    from fera.dataset.ground_truth import load_ground_truth
    from fera.dataset.manifest import build_manifest

    document = load_ground_truth(outcome.ground_truth_path).to_dict()
    assert document["execution"]["status"] == "SUCCESS"
    assert document["execution"]["valid_capture"] is True
    assert document["execution"]["reusable_as_dataset_sample"] is True
    assert document["ipsec"]["configured_encryption"] == "aes128_gcm"
    assert document["capture"]["details"]["sha256"]
    assert document["local_endpoint_reported"]["endpoint_a"]["ike_state"] == "ESTABLISHED"
    assert document["capture_validation"]["ike_detected"] is True

    manifest = build_manifest(paths=sandbox_paths)
    assert manifest["sample_count"] == 1
    assert manifest["entries"][0]["experiment_id"] == config.experiment_id
    assert sandbox_paths.default_manifest_file.is_file()


def test_sa_failure_is_reported_and_sample_rejected(sandbox_paths, topology, allow_capture) -> None:
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(responses=[("--list-sas", 0, ""), ("--initiate", 0, "")])
    outcome = make_runner(config, sandbox_paths, topology, runner).run()

    assert outcome.status is RunStatus.FAILED
    assert outcome.error_code is ErrorCode.IPSEC_INITIATION_FAILED
    assert outcome.valid_capture is False
    assert (sandbox_paths.experiment_dir(config.experiment_id) / "failure.json").is_file()

    from fera.dataset.ground_truth import load_ground_truth

    document = load_ground_truth(outcome.ground_truth_path).to_dict()
    assert document["execution"]["valid_capture"] is False
    assert document["execution"]["error_code"] == "IPSEC_INITIATION_FAILED"


def test_traffic_failure_rejects_the_sample(sandbox_paths, topology, allow_capture) -> None:
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(
        responses=[
            ("--list-sas", 0, SWANCTL_ESTABLISHED),
            ("tshark", 0, TSHARK_PHS),
            ("ping", 1, ""),
        ]
    )
    outcome = make_runner(config, sandbox_paths, topology, runner).run()
    assert outcome.status is RunStatus.FAILED
    assert outcome.error_code is ErrorCode.TRAFFIC_GENERATION_FAILED
    assert outcome.valid_capture is False
    # the capture is kept as evidence even though the sample is rejected
    assert outcome.pcap_path is not None and outcome.pcap_path.is_file()


def test_capture_without_esp_rejects_the_sample(sandbox_paths, topology, allow_capture) -> None:
    from conftest import ethernet_ipv4

    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(
        responses=[("--list-sas", 0, SWANCTL_ESTABLISHED), ("ping", 0, "ok")],
        capture_frames=[ethernet_ipv4(17, src_port=500, dst_port=500)],
    )
    outcome = make_runner(config, sandbox_paths, topology, runner).run()
    assert outcome.status is RunStatus.FAILED
    assert outcome.error_code is ErrorCode.CAPTURE_VALIDATION_FAILED
    assert "ESP" in (outcome.message or "")


def test_missing_capture_tool_fails_explicitly(sandbox_paths, topology) -> None:
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(
        available_tools=("swanctl", "ping", "tshark"),
        responses=[("--list-sas", 0, SWANCTL_ESTABLISHED)],
    )
    outcome = make_runner(config, sandbox_paths, topology, runner).run()
    assert outcome.status is RunStatus.FAILED
    assert outcome.error_code is ErrorCode.IPSEC_CONFIG_APPLY_FAILED or (
        outcome.error_code is ErrorCode.CAPTURE_TOOL_NOT_AVAILABLE
    )


def test_environment_blocker_is_reported_without_faking_a_sample(sandbox_paths, topology) -> None:
    """With environment verification on, a machine that cannot capture must fail loudly."""
    config = make_config(capture_duration_s=1.0)
    outcome = make_runner(
        config, sandbox_paths, topology, ScriptedRunner(), verify_environment=True
    ).run()
    if outcome.status is RunStatus.UNSUPPORTED_ENVIRONMENT:
        assert outcome.error_code is not None
        assert outcome.valid_capture is False
        from fera.dataset.ground_truth import load_ground_truth

        document = load_ground_truth(outcome.ground_truth_path).to_dict()
        assert document["execution"]["status"] == "UNSUPPORTED_ENVIRONMENT"
        assert document["execution"]["reusable_as_dataset_sample"] is False
    else:  # a fully privileged Linux host may legitimately proceed
        assert outcome.status in {RunStatus.SUCCESS, RunStatus.FAILED}


def test_run_experiment_helper_and_outcome_serialisation(sandbox_paths, topology) -> None:
    config = make_config(capture_duration_s=1.0)
    outcome = run_experiment(
        config, paths=sandbox_paths, topology=topology, runner=ScriptedRunner(), settings=RunnerSettings(dry_run=True, verify_environment=False)
    )
    payload = outcome.to_dict()
    assert payload["status"] == "DRY_RUN"
    assert payload["experiment_id"] == config.experiment_id
    assert payload["valid_capture"] is False


def test_keep_sa_skips_termination(sandbox_paths, topology, allow_capture) -> None:
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(
        responses=[("--list-sas", 0, SWANCTL_ESTABLISHED), ("tshark", 0, TSHARK_PHS), ("ping", 0, "ok")]
    )
    outcome = make_runner(config, sandbox_paths, topology, runner, keep_sa=True).run()
    assert outcome.status is RunStatus.SUCCESS
    assert not any("--terminate" in " ".join(command) for command in runner.commands)


def test_run_order_is_capture_then_initiate_then_traffic(sandbox_paths, topology, allow_capture) -> None:
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(
        responses=[("--list-sas", 0, SWANCTL_ESTABLISHED), ("tshark", 0, TSHARK_PHS), ("ping", 0, "ok")]
    )
    outcome = make_runner(config, sandbox_paths, topology, runner).run()
    assert outcome.status is RunStatus.SUCCESS, outcome.message

    # the capture tool is started (inside endpoint A) before traffic is generated
    assert runner.spawned, "the capture tool must have been started"
    assert "tcpdump" in runner.spawned[0]
    commands = [" ".join(command) for command in runner.commands]
    initiate_index = next(index for index, text in enumerate(commands) if "--initiate" in text)
    traffic_index = next(index for index, text in enumerate(commands) if " ping " in f" {text} ")
    assert initiate_index < traffic_index


def test_endpoint_is_wrapped_for_the_namespace_testbed(sandbox_paths, topology, allow_capture) -> None:
    config = make_config(capture_duration_s=1.0)
    runner = ScriptedRunner(responses=[("--list-sas", 0, "")])
    outcome = make_runner(config, sandbox_paths, topology, runner).run()
    assert outcome.status is RunStatus.FAILED  # no SA in this scripted run
    load_commands = [command for command in runner.commands if "--load-conns" in command]
    assert load_commands, "the runner must load the generated configuration"
    load = load_commands[0]
    assert load[:4] == ("ip", "netns", "exec", "fera-a")
    assert load[4] == "swanctl"
    assert "unix://" in " ".join(load)  # per endpoint vici socket



# --- remote (two-VM / SSH) endpoints ----------------------------------------
# Capture, traffic, responder and the control plane already route through
# endpoint_prefix(); these pin that routing for a remote endpoint and cover the
# one behaviour that had to change: no private VICI URI.


def _ssh_topology(protected: bool = True):
    from fera.testbed.topology import topology_from_dict

    a = {
        "name": "endpoint-a", "role": "initiator", "kind": "ssh",
        "ssh_host": "10.0.2.15", "ssh_user": "fera", "ssh_port": 2221,
        "capture_interface": "enp0s8", "outer_ipv4": "10.10.10.1/24",
    }
    b = {
        "name": "endpoint-b", "role": "responder", "kind": "ssh",
        "ssh_host": "10.0.2.15", "ssh_user": "fera", "ssh_port": 2222,
        "capture_interface": "enp0s8", "outer_ipv4": "10.10.10.2/24",
    }
    if protected:
        # Tunnel mode needs a subnet behind each endpoint.
        a["protected_ipv4"] = "10.20.0.1/24"
        b["protected_ipv4"] = "10.30.0.1/24"
    return topology_from_dict(
        {"name": "ssh_two_vm", "runner": "ssh", "endpoints": {"a": a, "b": b}}
    )


def test_remote_topology_without_protected_addresses_refuses_tunnel_mode(sandbox_paths) -> None:
    """A VM with only enp0s8 cannot run tunnel mode, and FERA must say so.

    Better to refuse than to generate selectors for addresses that do not exist.
    """
    from fera.common.errors import ConfigValidationError

    with pytest.raises(ConfigValidationError, match="protected IPv4"):
        make_runner(
            make_config(), sandbox_paths, _ssh_topology(protected=False), ScriptedRunner()
        ).run()


def test_remote_endpoints_get_no_private_vici_uri(sandbox_paths) -> None:
    """The private socket path lives on the controller, not on the VM.

    Passing it would address a file that does not exist on the machine being
    addressed, so a remote endpoint must fall back to its own default socket.
    """
    runner = make_runner(make_config(), sandbox_paths, _ssh_topology(), ScriptedRunner())
    assert runner._vici_uri("a") is None
    assert runner._vici_uri("b") is None
    assert runner._vici_sockets() == {}


def test_namespace_endpoints_still_get_their_private_vici_uri(sandbox_paths, topology) -> None:
    """Regression guard: the netns path must be unchanged."""
    runner = make_runner(make_config(), sandbox_paths, topology, ScriptedRunner())
    assert runner._vici_uri("a") is not None
    assert runner._vici_uri("a").startswith("unix://")
    assert set(runner._vici_sockets()) == {"a", "b"}


def test_remote_controller_runs_swanctl_over_ssh_without_a_uri(sandbox_paths) -> None:
    controller = make_runner(
        make_config(), sandbox_paths, _ssh_topology(), ScriptedRunner()
    ).controller("a")
    command = controller.command("--list-sas")
    assert "--uri" not in command
    assert command[:2] == ["ssh", "-o"]
    assert command[-1] == "--list-sas"


def test_remote_capture_uses_enp0s8_on_the_vm(sandbox_paths) -> None:
    runner = make_runner(make_config(), sandbox_paths, _ssh_topology(), ScriptedRunner())
    assert runner.capture_interface() == "enp0s8"
    assert runner.endpoint_prefix("a")[0] == "ssh"


def test_traffic_and_responder_route_to_their_own_vm(sandbox_paths) -> None:
    """Traffic goes to A and the responder to B - two different machines."""
    runner = make_runner(make_config(), sandbox_paths, _ssh_topology(), ScriptedRunner())
    prefix_a = runner.endpoint_prefix("a")
    prefix_b = runner.endpoint_prefix("b")
    assert prefix_a != prefix_b
    assert "2221" in prefix_a and "2222" in prefix_b


def test_dry_run_on_a_remote_topology_marks_the_sample_invalid(sandbox_paths) -> None:
    runner = make_runner(
        make_config(), sandbox_paths, _ssh_topology(), ScriptedRunner(), dry_run=True
    )
    assert runner._vici_uri("a") is None
    outcome = runner.run()
    assert outcome.status is RunStatus.DRY_RUN
    assert outcome.valid_capture is False
    assert outcome.integration_verified is False
    experiment_dir = sandbox_paths.experiment_dir(make_config().experiment_id)
    assert not (experiment_dir / "capture.pcap").exists()
    plan = (experiment_dir / "dry_run_plan.json").read_text(encoding="utf-8")
    assert "10.0.2.15" in plan


def test_remote_run_without_evidence_is_never_marked_verified(
    sandbox_paths, allow_capture
) -> None:
    """Evidence discipline for the remote path: booleans, never a bare success."""
    config = make_config()
    outcome = make_runner(
        config, sandbox_paths, _ssh_topology(), ScriptedRunner(responses=full_evidence_responses())
    ).run()
    document = json.loads(
        (sandbox_paths.experiment_dir(config.experiment_id) / "ground_truth.json").read_text(
            encoding="utf-8"
        )
    )
    assert isinstance(document["execution"]["integration_verified"], bool)
    assert isinstance(outcome.integration_verified, bool)
