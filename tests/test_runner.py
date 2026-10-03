"""End-to-end experiment runner tests (mocked external processes)."""

from __future__ import annotations

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

