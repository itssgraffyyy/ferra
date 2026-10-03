"""Part 4 evidence-gate tests.

The property under test is a negative one, and it is the one that failed in
practice: **a run that establishes IKE_SA is not a successful real-IPsec
experiment.** strongSwan came up, IKE negotiated, ping succeeded, and the
payload had travelled a direct unprotected path. Every indicator was green.

These tests also assert that a dry run cannot mark any gate, because a gate
marked without an experiment behind it is exactly how fabricated evidence would
enter the pipeline.
"""

from __future__ import annotations

import pytest

from fera.common.errors import FeraError
from fera.experiment.gates import (
    EVIDENCE_GATES,
    ExperimentState,
    GateEvidence,
    Stage,
    _xfrm_entries,
    derive_gate_state,
    probe_xfrm,
)
from fera.experiment.preflight import (
    BLOCKED,
    PARTIAL,
    READY,
    REQUIRED_CAPABILITIES,
    run_preflight,
)
from fera.testbed.environment import CheckResult, CheckStatus, EnvironmentReport


def _all_gates(state: ExperimentState) -> ExperimentState:
    for gate in EVIDENCE_GATES:
        state.satisfy(gate)
    return state


def test_a_new_run_verifies_nothing() -> None:
    state = ExperimentState(experiment_id="exp-001")
    assert state.stage is Stage.PLANNED
    assert state.real_ipsec_verified is False
    assert state.missing_gates == list(EVIDENCE_GATES)
    assert state.dataset_eligible is False


def test_gates_are_ordered_and_all_required() -> None:
    assert EVIDENCE_GATES == (
        "ike_sa_verified",
        "child_sa_verified",
        "xfrm_state_verified",
        "xfrm_policy_verified",
        "protected_payload_verified",
        "esp_verified",
    )


def test_unknown_gate_is_refused() -> None:
    with pytest.raises(FeraError):
        ExperimentState(experiment_id="exp-001").satisfy("trust_me_verified")


def test_ike_success_alone_is_not_real_ipsec_success() -> None:
    """The historical failure mode, stated as an executable assertion."""
    state = ExperimentState(experiment_id="exp-001")
    state.satisfy("ike_sa_verified")

    assert state.real_ipsec_verified is False
    with pytest.raises(FeraError) as excinfo:
        state.assert_ike_is_not_success()
    assert "not real-IPsec verified" in str(excinfo.value)


def test_partial_gates_never_grant_dataset_eligibility() -> None:
    state = ExperimentState(experiment_id="exp-001")
    for gate in EVIDENCE_GATES[:-1]:
        state.satisfy(gate)

    assert state.real_ipsec_verified is False
    with pytest.raises(FeraError) as excinfo:
        state.assert_dataset_eligible()
    assert "esp_verified" in str(excinfo.value.details)


def test_advance_refuses_to_skip_an_unsatisfied_gate() -> None:
    state = ExperimentState(experiment_id="exp-001")
    with pytest.raises(FeraError):
        state.advance(Stage.ESP_VERIFIED)
    assert state.stage is Stage.PLANNED


def test_advance_proceeds_when_the_gate_is_satisfied() -> None:
    state = ExperimentState(experiment_id="exp-001")
    state.satisfy("ike_sa_verified")
    assert state.advance(Stage.IKE_VERIFIED) is Stage.IKE_VERIFIED


def test_full_gate_set_grants_eligibility() -> None:
    state = _all_gates(ExperimentState(experiment_id="exp-001"))
    assert state.real_ipsec_verified is True
    assert state.missing_gates == []
    state.assert_dataset_eligible()
    state.assert_ike_is_not_success()


def test_dry_run_cannot_verify_a_gate() -> None:
    """A planned run is PLANNED; there is no path that marks a gate by planning."""
    state = ExperimentState(experiment_id="exp-001")
    for stage in (Stage.PREFLIGHT_PASSED, Stage.TESTBED_READY):
        state.stage = stage
    assert state.real_ipsec_verified is False
    with pytest.raises(FeraError):
        state.assert_dataset_eligible()


def test_failure_records_a_reason_and_blocks_eligibility() -> None:
    """A FAILED run must never feed the dataset, even with every gate set."""
    state = _all_gates(ExperimentState(experiment_id="exp-001"))
    assert state.dataset_eligible is True

    assert state.fail("capture produced no ESP packets") is Stage.FAILED
    assert "no ESP packets" in state.failure_reason
    # The gates may all be true, but a failed run is not eligible.
    assert state.real_ipsec_verified is True
    assert state.dataset_eligible is False
    with pytest.raises(FeraError):
        state.assert_dataset_eligible()


def test_state_round_trips_through_a_document() -> None:
    state = ExperimentState(
        experiment_id="exp-001",
        session_id="sess-1",
        configuration_id="cfg-aes128-gcm",
        repeat_id=2,
        traffic_class="web",
    )
    state.satisfy("ike_sa_verified")
    state.evidence["esp_packets"] = 118

    restored = ExperimentState.from_dict(state.to_dict())
    assert restored.experiment_id == state.experiment_id
    assert restored.session_id == state.session_id
    assert restored.configuration_id == state.configuration_id
    assert restored.repeat_id == 2
    assert restored.gates["ike_sa_verified"] is True
    assert restored.gates["esp_verified"] is False
    assert restored.evidence["esp_packets"] == 118
    assert restored.real_ipsec_verified is False
# ------------------------------------------------------------- preflight


def _environment(statuses: dict[str, str]) -> EnvironmentReport:
    """Build a synthetic environment report so preflight is testable without a host."""
    return EnvironmentReport(
        checks=tuple(
            CheckResult(key=key, label=key, status=CheckStatus(value), detail="test")
            for key, value in statuses.items()
        ),
        host={"platform": "test"},
        tool_versions={},
        generated_at="2026-01-01T00:00:00Z",
    )


def _linux_like() -> dict[str, str]:
    return dict.fromkeys(REQUIRED_CAPABILITIES, "AVAILABLE")


def test_preflight_reports_ready_when_everything_is_probed() -> None:
    report = run_preflight(
        require_real_experiments=True, environment=_environment(_linux_like())
    )
    assert report.status == READY
    assert report.ready is True
    assert report.can_run_real_experiments is True
    assert report.missing_capabilities == ()
    assert report.blocking_reasons == ()


def test_preflight_blocks_a_host_missing_xfrm() -> None:
    statuses = _linux_like()
    statuses["xfrm"] = "UNSUPPORTED"
    report = run_preflight(
        require_real_experiments=True, environment=_environment(statuses)
    )
    assert report.status == BLOCKED
    assert report.can_run_real_experiments is False
    assert "xfrm" in report.missing_capabilities
    assert any("xfrm" in reason for reason in report.blocking_reasons)


def test_preflight_blocks_a_host_missing_a_capture_tool() -> None:
    statuses = _linux_like()
    statuses["capture_tool"] = "MISSING"
    report = run_preflight(
        require_real_experiments=True, environment=_environment(statuses)
    )
    assert report.status == BLOCKED
    assert "capture_tool" in report.missing_capabilities


def test_installed_binaries_alone_do_not_make_a_host_ready() -> None:
    """swanctl present but no XFRM must still block - the historical trap."""
    statuses = _linux_like()
    statuses["xfrm"] = "UNSUPPORTED"
    report = run_preflight(
        require_real_experiments=True, environment=_environment(statuses)
    )
    assert report.available_capabilities  # swanctl and friends ARE available
    assert report.can_run_real_experiments is False


def test_dry_run_may_describe_a_blocked_host() -> None:
    statuses = _linux_like()
    statuses["xfrm"] = "UNSUPPORTED"
    report = run_preflight(
        require_real_experiments=False, environment=_environment(statuses)
    )
    assert report.status == PARTIAL
    # Still not authorised for real evidence, whatever the status label.
    assert report.can_run_real_experiments is False
    assert report.blocking_reasons == ()


def test_required_capabilities_are_real_environment_check_keys() -> None:
    """A typo here reads as 'missing' and would block a good Linux host."""
    report = run_preflight(
        require_real_experiments=True, environment=_environment(_linux_like())
    )
    embedded = set(report.environment["checks"])
    assert set(REQUIRED_CAPABILITIES) <= embedded, sorted(
        set(REQUIRED_CAPABILITIES) - embedded
    )


def test_preflight_serialises_and_renders() -> None:
    report = run_preflight(
        require_real_experiments=True, environment=_environment({"xfrm": "UNSUPPORTED"})
    )
    document = report.to_dict()
    assert document["schema"] == "fera_experiment_preflight_v1"
    assert document["status"] in (READY, PARTIAL, BLOCKED)
    assert "BLOCKED" in report.render_text()


# --- XFRM evidence collection ------------------------------------------------

#: Two SAs, each printed as a `src` line followed by indented continuations.
TWO_SA_STATE = (
    "src 10.10.10.1 dst 10.10.10.2\n"
    "\tsrc 10.10.10.1 dst 10.10.10.2\n"
    "\t\tauth-trunc 'sha256 0123' enc alg 'aes'\n"
    "src 10.10.10.1 dst 10.10.10.3\n"
    "\tsrc 10.10.10.1 dst 10.10.10.3\n"
)


class _StubRunner:
    """Minimal runner returning a canned `ip xfrm` response."""

    def __init__(self, stdout: str = "", *, returncode: int = 0, stderr: str = "") -> None:
        self._stdout = stdout
        self._returncode = returncode
        self._stderr = stderr
        self.commands: list[list[str]] = []

    def run(self, command, **_kwargs):
        self.commands.append([str(part) for part in command])

        class _Result:
            ok = self._returncode == 0
            stdout = self._stdout
            stderr = self._stderr
            returncode = self._returncode

        return _Result()


def test_xfrm_entries_counts_blocks_not_continuation_lines() -> None:
    """Indented continuation lines must not be counted as separate entries.

    An inflated count would make an almost-empty table look populated and could
    satisfy the XFRM gates on a host that never established an SA.
    """
    assert _xfrm_entries(TWO_SA_STATE) == 2
    assert _xfrm_entries("") == 0
    assert _xfrm_entries("\n\n") == 0


def test_probe_xfrm_reports_the_entries_it_observed() -> None:
    result = probe_xfrm(_StubRunner(TWO_SA_STATE))
    assert result["available"] is True
    assert result["state_entries"] == 2
    assert result["policy_entries"] == 2
    assert result["reason"] == ""


def test_probe_xfrm_reports_a_refused_probe_without_claiming_no_sa() -> None:
    result = probe_xfrm(_StubRunner("", returncode=1, stderr="Operation not permitted"))
    assert result["available"] is False
    assert "Operation not permitted" in result["reason"]


def test_unprobed_xfrm_is_distinct_from_an_empty_table() -> None:
    """A host that cannot probe XFRM must not look like one with no SA.

    Both readings lead to "not verified", but they mean different things and the
    evidence document has to be able to tell them apart.
    """
    empty = derive_gate_state(GateEvidence(True, True, False, False, True, True))
    unprobed = derive_gate_state(GateEvidence(True, True, None, None, True, True))
    assert empty["real_ipsec_verified"] is False
    assert unprobed["real_ipsec_verified"] is False
    assert (
        empty["evidence"]["xfrm_state_present"]
        is not unprobed["evidence"]["xfrm_state_present"]
    )


def test_every_gate_must_be_satisfied_before_verification() -> None:
    full = derive_gate_state(GateEvidence(True, True, True, True, True, True))
    assert full["real_ipsec_verified"] is True
    assert full["missing_gates"] == []
    assert full["stage"] == "MANIFEST_FINALIZED"

    for missing in (
        GateEvidence(False, True, True, True, True, True),
        GateEvidence(True, False, True, True, True, True),
        GateEvidence(True, True, False, True, True, True),
        GateEvidence(True, True, True, False, True, True),
        GateEvidence(True, True, True, True, False, True),
        GateEvidence(True, True, True, True, True, False),
    ):
        state = derive_gate_state(missing)
        assert state["real_ipsec_verified"] is False
        assert state["missing_gates"], state
        assert state["dataset_eligible"] is False


def test_protected_payload_without_a_child_sa_is_not_a_gate() -> None:
    """Traffic that generated successfully proves nothing without a CHILD_SA.

    This is the historical failure in miniature: bytes moved and every indicator
    looked green, but no SA protected them.
    """
    state = derive_gate_state(GateEvidence(True, False, True, True, True, True))
    assert "protected_payload_verified" in state["missing_gates"]
    assert state["real_ipsec_verified"] is False


def test_a_failed_run_is_never_dataset_eligible() -> None:
    state = derive_gate_state(GateEvidence(True, True, True, True, True, True), failed=True)
    assert state["real_ipsec_verified"] is True
    assert state["stage"] == "FAILED"
    assert state["dataset_eligible"] is False
