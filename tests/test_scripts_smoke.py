"""Smoke tests for the CLI entry points in ``scripts/``.

These run the scripts as real subprocesses, which verifies the command line
surface (argument names, exit codes) end to end.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT, ike_and_esp_frames, write_pcap

SCRIPTS = REPO_ROOT / "scripts"


def run_script(name: str, *arguments: str, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / name), *arguments],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=timeout,
        check=False,
    )


def test_check_environment_script_runs(tmp_path: Path) -> None:
    result = run_script("check_environment.py", "--quiet", "--json", str(tmp_path / "env.json"))
    assert result.returncode == 0, result.stderr
    assert "ready=" in result.stdout
    assert (tmp_path / "env.json").is_file()


def test_check_environment_strict_exit_code() -> None:
    result = run_script("check_environment.py", "--quiet", "--strict")
    # either the machine is ready (0) or it is blocked (1) - never a crash
    assert result.returncode in {0, 1}
    assert "ready=" in result.stdout


def test_generate_experiment_matrix_print_only() -> None:
    result = run_script("generate_experiment_matrix.py", "--print-only")
    assert result.returncode == 0, result.stderr
    assert "Tunnel Mode" in result.stdout
    assert "requirements satisfied" in result.stdout


def test_generate_and_check_matrix_round_trip(tmp_path: Path) -> None:
    out_dir = tmp_path / "experiments"
    generated = run_script("generate_experiment_matrix.py", "--out", str(out_dir))
    assert generated.returncode == 0, generated.stderr
    files = sorted(out_dir.glob("exp_*.yaml"))
    assert len(files) >= 12
    assert (out_dir / "_matrix_index.json").is_file()

    coverage = run_script("check_matrix_coverage.py", "--experiments", str(out_dir))
    assert coverage.returncode == 0, coverage.stderr
    assert "PASS" in coverage.stdout
    assert "FAIL" not in coverage.stdout

    # regenerating without --force must keep the files (no silent overwrite)
    again = run_script("generate_experiment_matrix.py", "--out", str(out_dir))
    assert again.returncode == 0
    assert "keep " in again.stdout


def test_run_experiment_dry_run_via_cli(tmp_path: Path) -> None:
    out_dir = tmp_path / "experiments"
    assert run_script("generate_experiment_matrix.py", "--out", str(out_dir)).returncode == 0
    config_file = sorted(out_dir.glob("exp_*.yaml"))[0]
    raw_dir = tmp_path / "raw"

    result = run_script(
        "run_experiment.py",
        "--config",
        str(config_file),
        "--dry-run",
        "--raw-dir",
        str(raw_dir),
        "--json",
        str(tmp_path / "outcome.json"),
    )
    assert result.returncode == 0, result.stderr
    assert "DRY_RUN" in result.stdout

    run_dir = next(path for path in raw_dir.iterdir() if path.is_dir())
    for name in ("experiment.yaml", "dry_run_plan.json", "ground_truth.json", "execution.log"):
        assert (run_dir / name).is_file(), name
    assert (run_dir / "ipsec" / "endpoint-a" / "swanctl.conf").is_file()
    assert (tmp_path / "outcome.json").is_file()

    # no dataset sample is produced by a dry run
    manifest = run_script("build_manifest.py", "--raw", str(raw_dir), "--out", str(tmp_path / "dataset.json"))
    assert manifest.returncode == 0, manifest.stderr
    assert "samples         : 0" in manifest.stdout
    assert "rejected        : 1" in manifest.stdout


def test_validate_capture_script(tmp_path: Path) -> None:
    good = write_pcap(tmp_path / "good.pcap", ike_and_esp_frames())
    result = run_script("validate_capture.py", "--pcap", str(good), "--expected-ip-version", "4")
    assert result.returncode == 0, result.stderr
    assert "IKE detected: YES" in result.stdout
    assert "ESP detected: YES" in result.stdout
    assert "Result: VALID" in result.stdout

    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"\x00" * 8)
    bad = run_script("validate_capture.py", "--pcap", str(empty))
    assert bad.returncode == 1
    assert "INVALID" in bad.stdout


def test_setup_netns_testbed_print_only() -> None:
    result = run_script("setup_netns_testbed.py", "--print-only")
    assert result.returncode == 0, result.stderr
    assert "ip netns add fera-a" in result.stdout
    assert "10.20.0.1/24" in result.stdout
    assert "ip -6 route replace fd00:30::/64 via fd00:10:10::2 src fd00:20::1" in result.stdout


def test_assess_security_on_synthetic_pcap(tmp_path: Path) -> None:
    pcap = write_pcap(tmp_path / "demo.pcap", ike_and_esp_frames())
    report = tmp_path / "security" / "report.json"
    result = run_script(
        "assess_security.py",
        "--pcap",
        str(pcap),
        "--no-tshark",
        "--out",
        str(report),
        "--json",
    )
    assert result.returncode == 0, result.stderr
    assert report.is_file()
    assert "security_score" in result.stdout

    gated = run_script(
        "assess_security.py",
        "--pcap",
        str(pcap),
        "--no-tshark",
        "--out",
        str(tmp_path / "security2.json"),
        "--fail-under",
        "100",
    )
    assert gated.returncode == 1
    assert "below --fail-under" in gated.stderr


def test_generate_security_policy_docs_check() -> None:
    result = run_script("generate_security_policy_docs.py", "--check")
    assert result.returncode == 0, result.stderr
    assert "up to date" in result.stdout


def test_build_manifest_on_empty_directory(tmp_path: Path) -> None:
    result = run_script(
        "build_manifest.py",
        "--raw",
        str(tmp_path / "raw"),
        "--out",
        str(tmp_path / "manifests" / "dataset.json"),
    )
    assert result.returncode == 0, result.stderr
    assert "samples         : 0" in result.stdout


def test_run_pipeline_plans_every_stage_without_executing(tmp_path: Path) -> None:
    """The single entry point must compose all five stages and exit 0.

    A dry run still writes the experiment *specifications* -- they are plans, not
    results -- so the experiment stage has something to plan against.
    """
    result = run_script(
        "run_pipeline.py",
        "--dry-run",
        "--experiments-dir", str(tmp_path / "experiments"),
        "--raw-dir", str(tmp_path / "raw"),
    )
    assert result.returncode == 0, result.stderr
    assert "pipeline summary" in result.stdout
    for stage in ("matrix", "experiments", "manifest", "dataset", "verify"):
        assert stage in result.stdout, stage
    # The matrix really was written, and nothing was captured.
    assert list((tmp_path / "experiments").glob("exp_*.yaml"))
    assert not list((tmp_path / "raw").glob("*/capture.pcap"))


def test_run_pipeline_can_skip_a_stage(tmp_path: Path) -> None:
    result = run_script(
        "run_pipeline.py",
        "--dry-run",
        "--skip", "experiments",
        "--experiments-dir", str(tmp_path / "experiments"),
        "--raw-dir", str(tmp_path / "raw"),
    )
    assert result.returncode == 0, result.stderr
    assert "experiments: SKIPPED" in result.stdout


# --- diagnose_testbed.py ---------------------------------------------------
# The diagnostic exists because one underlying fault surfaced as four different
# errors depending on which layer noticed it last.  These tests pin the layer
# logic, not the host: they must behave identically whatever this machine is.


def test_diagnose_testbed_runs_and_reports_every_layer() -> None:
    result = run_script("diagnose_testbed.py", "--vici-timeout", "2")
    # 0 = healthy, 1 = something is broken; never a crash (2+).
    assert result.returncode in {0, 1}, result.stderr
    for layer in ("run_mount", "capture_tool", "namespaces", "interfaces", "vici", "xfrm"):
        assert layer in result.stdout, result.stdout
    assert "failing layer(s)" in result.stdout or "All probed layers healthy" in result.stdout


def test_diagnose_testbed_json_is_machine_readable() -> None:
    import json

    result = run_script("diagnose_testbed.py", "--json", "--vici-timeout", "2")
    assert result.returncode in {0, 1}, result.stderr
    report = json.loads(result.stdout)
    probes = report["probes"]
    assert probes
    for probe in probes:
        assert probe["status"] in {"ok", "bad", "unknown"}
        assert probe["name"] and probe["detail"]


def test_diagnose_testbed_is_read_only() -> None:
    """It must never mount, unmount, start or stop anything.

    Ad-hoc diagnostics of this problem twice shadowed the host's /run; the tool
    that replaces them has to be provably incapable of that.  A plain substring
    scan is not good enough - this file legitimately *tells* the user to mount
    /run as remediation - so the check parses the module and inspects what is
    actually called and executed.
    """
    import ast

    tree = ast.parse((SCRIPTS / "diagnose_testbed.py").read_text(encoding="utf-8"))

    forbidden_attributes = {"Popen", "system", "fork", "execv", "execve", "spawnv"}
    # Programs that change the host: never run, in any form.
    forbidden_programs = {"mount", "umount", "systemctl", "service", "kill", "rm", "tee", "reboot", "shutdown"}
    # Mutating verbs an `ip` invocation could carry.
    ip_mutations = {"set", "add", "del", "flush", "change", "replace", "append", "up", "down"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in forbidden_attributes:
            pytest.fail(f"diagnose_testbed.py calls forbidden {node.attr}()")

    commands: list[list[str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_run"):
            continue
        assert node.args, "_run must be called with a literal command"
        (command,) = node.args
        assert isinstance(command, ast.List) and command.elts, "command must be a literal list"
        tokens: list[str] = []
        for index, element in enumerate(command.elts):
            if index == 0:
                # The program must be a fixed literal - never something built.
                assert isinstance(element, ast.Constant), "the program must be a literal"
            # Arguments may legitimately be derived (the VICI URI is built from
            # the socket directory); render anything non-literal back to source.
            tokens.append(element.value if isinstance(element, ast.Constant) else ast.unparse(element))
        commands.append(tokens)

    assert commands, "the diagnostic must actually probe something"
    for tokens in commands:
        program = tokens[0]
        assert program not in forbidden_programs, f"diagnose_testbed.py may not run {program!r}"
        if program == "ip":
            # `ip` can mutate; this tool may only ever ask.
            assert not (ip_mutations & set(tokens)), f"mutating ip invocation: {tokens}"
        if program == "swanctl":
            # swanctl can load connections and terminate SAs; only list them.
            assert "--list-sas" in tokens, f"non read-only swanctl invocation: {tokens}"
            assert not ({"--load-conns", "--initiate", "--terminate", "--clear"} & set(tokens)), tokens

