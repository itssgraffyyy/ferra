# Linux Experiments: Running FERA for Real

This is the operating manual for running FERA on a real Linux host: the order of
commands, what each gate means, and — just as important — **what has never been
done yet.**

Read the honesty section (§8) before trusting any number FERA produces. It is
the most important part of this document.

---

## 1. Status: what is real and what is not

FERA's experiment machinery is **built and tested, but has never been executed
against a real Linux host.** Every gate, planner, and validator in
`src/fera/experiment/` was written and unit-tested on a Windows machine where
`tc`, XFRM, and strongSwan are all absent.

| Area | State |
|---|---|
| Evidence gates & state machine | Implemented, tested |
| Preflight capability checker | Implemented, tested |
| Dry-run / matrix / session planner | Implemented, tested |
| Capture validation & SHA-256 hashing | Implemented, tested |
| Canonical experiment manifest | Implemented, tested |
| netem robustness planning | Implemented, tested — **planning only** |
| **Real Linux / strongSwan / XFRM execution** | **Never performed** |
| **Real ESP captures** | **None exist** |
| **Applied netem robustness results** | **None exist** |
| **Real model metrics (ML / OOD / privacy)** | **None exist** |
| **Testbed-verified privacy claims** | **None exist** |

Anything downstream of real execution — dataset statistics, model accuracy,
OOD scores, privacy-attacker success rates — is currently **simulated or
unmeasured.** `docs/limitations.md` tracks this in more detail.

### 1.1 A known wiring gap

`scripts/run_experiment.py` is the real execution driver. It **does not yet
import or call** `fera.experiment.netem`, `preflight`, `gates`, or `manifest`.

This means the netem procedure in §5 is **manual**. You apply and clean up the
qdisc yourself around each `run_experiment.py` invocation. Wiring the planner
into the driver is outstanding work, and the manual ordering below is what that
wiring will have to reproduce.

---

## 2. Requirements

Per `docs/limitations.md` and `scripts/check_environment.py`:

- Linux (bare metal or VM) with `CONFIG_XFRM` and `CONFIG_INET_ESP`.
- Root, or `CAP_NET_ADMIN` + `CAP_NET_RAW`.
- `strongswan` with `swanctl` available.
- `tcpdump` **or** `dumpcap`.
- `iproute2` (for `ip netns`, `tc`) — required for the namespace testbed.

Verify before doing anything else:

```bash
python scripts/check_environment.py --strict
```

`--strict` exits non-zero when the environment is not ready. Probe the actual
capability keys it reports — `platform`, `privileges`, `swanctl`,
`capture_tool`, `xfrm`, `netns` — rather than assuming presence of a binary is
sufficient.

**WSL2 is not a substitute.** Default WSL2 kernels lack reliable XFRM in network
namespaces, and VICI sockets cannot live across a `/mnt/c` mount. Run
`check_environment.py` *inside* WSL before considering it.

---

## 3. Bring up the namespace testbed

Print the script first and read it. `--print-only` changes nothing:

```bash
python scripts/setup_netns_testbed.py --print-only
```

When the generated script looks right:

```bash
python scripts/setup_netns_testbed.py --apply --start-charon
```

Endpoints live in namespaces with separate vici sockets (default
`/run/fera-testbed`), logs in `data/logs/netns`. See `docs/testbed.md` for
addresses, traffic selectors, and the topology file
(`configs/templates/testbed_topology.yaml`).

**Always tear down when finished** — leftover namespaces are the classic cause
of "the second run behaved differently from the first":

```bash
python scripts/setup_netns_testbed.py --stop-charon
python scripts/setup_netns_testbed.py --teardown
```

---

## 4. Plan before you run

Generate the experiment matrix:

```bash
python scripts/generate_experiment_matrix.py --print-only
```

### 4.1 Known matrix defect — fix before collecting real captures

**The current curated matrix is confounded.** All 15 entries map to 15
configurations, and **every configuration currently carries exactly one traffic
class.** Configuration and traffic class are perfectly collinear.

The consequence is concrete: any measured difference between configurations is
*unidentifiable* from a difference between traffic classes. A result attributing
behaviour to, say, the cipher suite could be entirely an artefact of that suite
never having been paired with ICMP or VoIP traffic.

A test pins this so it cannot drift silently. **Do not collect representative
real captures until each configuration has been paired with more than one
traffic class.**

### 4.2 Dry run

```bash
python scripts/run_experiment.py --config configs/experiments --dry-run
```

A dry run writes the full plan and **executes nothing**. It never advances an
evidence gate and can never produce a real dataset entry. Treat a clean dry run
as "the plan is coherent", never as "the experiment succeeded".

---

## 5. Netem robustness (manual, until wired)

`src/fera/experiment/netem.py` **plans**; it never executes. Plan the conditions:

```python
from fera.experiment.netem import plan_condition, plan_matrix

for row in plan_matrix(interface="veth-a"):
    print(row["name"], row["apply_command"], row["cleanup_command"])
```

| Condition | Settings | `tc` effect |
|---|---|---|
| `baseline` | none | **no command at all** |
| `loss` | 1% | packet loss |
| `latency` | 50 ms | added delay |
| `jitter` | 20 ms delay ±10 ms | variable delay |

Apply and clean up around **each** run:

```bash
# baseline: deliberately do nothing (see 5.1)
tc qdisc replace dev veth-a root netem loss 1.0%
python scripts/run_experiment.py --experiment-id <id>
tc qdisc del dev veth-a root
```

### 5.1 Three things that will silently ruin a robustness matrix

- **Baseline must not run any `tc` command.** Applying an empty netem still
  replaces whatever qdisc a previous run left behind. A "no impairment"
  baseline that clobbers state is not a baseline.

- **Jitter must always carry its delay.** `netem` silently ignores jitter
  without a delay. A jitter-only command runs cleanly, exits zero, impairs
  nothing, and produces a capture that looks perfectly valid — the worst kind of
  failure, because the matrix appears to have worked. `NetworkCondition` refuses
  `jitter_ms` with `delay_ms=None` rather than degrade quietly.

- **Cleanup must be unconditional.** `tc qdisc del dev <iface> root` is safe
  when no qdisc exists. A leftover qdisc silently changes the next run.

`applied` stays `False` unless a caller asserts real execution. A condition that
was planned but never applied **cannot** be recorded as an impairment that
happened.

---

## 6. Run, capture, validate, manifest

```bash
python scripts/run_experiment.py --config configs/experiments \
    --capture-tool tcpdump --capture-interface veth-a \
    --update-manifest
```

Validate a capture independently before trusting it:

```bash
python scripts/validate_capture.py --pcap <file.pcap> --expected-ip-version 4
```

Rebuild the dataset manifest:

```bash
python scripts/build_manifest.py --raw data/raw --out data/manifests/dataset.json
```

### 6.1 Evidence rules that will not bend

These are enforced in `src/fera/experiment/gates.py` and covered by tests:

- **IKE success ≠ IPsec success.** A negotiated SA with no ESP is not a
  protected-packet observation.
- **ESP requires a valid capture actually containing ESP.** The gate opens only
  on capture evidence.
- **NAT-T presence credits neither IKE nor ESP.** Port 4500 alone proves nothing
  about protection.
- **Failed or blocked runs never enter the real dataset** — eligibility requires
  complete gates *and* a non-failed, non-blocked stage.
- **Ground truth is `CONFIGURED`, never `OBSERVED`.** We configured the cipher;
  we did not measure it from the wire.
- **Dry runs never advance gates.**
- Manifest status is *derived* from state plus capture evidence, never asserted.

---

## 7. Analysis, ML, and privacy

```bash
python scripts/build_dataset.py
python scripts/train_model.py
python scripts/privacy_experiment.py
```

Privacy countermeasures are **simulated** (deterministic padding plus
byte-overhead accounting). Provenance guards prevent a simulated
countermeasure from ever being recorded as testbed-verified. See
`docs/privacy_intelligence.md`.

**Any metric produced today comes from simulated or fixture data.** Treat every
number as a pipeline demonstration, not an empirical finding.

---

## 8. Honesty checklist

Before quoting a FERA result, confirm:

1. Was this run on a **real Linux host**, not Windows or WSL2?
2. Does the capture **actually contain ESP**, validated by
   `validate_capture.py`?
3. Was the run **not** a dry run?
4. Is ground truth labelled `CONFIGURED`?
5. Are model metrics from **real captures**, or from simulation/fixtures?
6. For any privacy claim: is the countermeasure **simulated**? If so it is not
   testbed-verified, regardless of how the result is phrased.

If any answer is "no" or "unclear", the result must not be presented as
empirical evidence. `docs/limitations.md` is the canonical list.

---

## 9. Outstanding work

- Wire `netem`, `preflight`, `gates`, and `manifest` into `run_experiment.py`
  (removing the manual ordering in §5).
- Add traffic/capture lifecycle management and repeated-session orchestration.
- **Fix the matrix confounding in §4.1.**
- Add the artifact-directory layout and a single reproducibility CLI.
- Perform the first real run, then replace this document's pending items with
  measured results.


