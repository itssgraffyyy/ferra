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

### 1.1 What has now been exercised on a real Linux host

The testbed bring-up has been run for real (WSL2 Linux 6.18, strongSwan
5.9.13), inside an unprivileged user namespace (`unshare -Urnm`), and it
surfaced four defects that no unit test could have caught. All four are fixed:

| Defect | Symptom | Why no test caught it |
|---|---|---|
| `strongswan.conf` written with dotted keys | charon aborted with *syntax error, unexpected .*; **no daemon ever started** | the test asserted the rendered *string*, nobody parsed it |
| `swanctl --uri` emitted *before* the subcommand | every control call failed with *unrecognized option '--uri'* | `IpsecController` had no tests at all |
| both charons sharing `/var/run` | second daemon aborted (*charon already running*), its VICI socket was never opened | `--start-charon` reported success either way |
| (fixed) filelog path used as a section key | a dotted log path is not a legal section name | same as row 1 |

`ip netns`, XFRM policies/ESP SAs (`cbc(aes)`+`hmac(sha256)` and
`aead "rfc4106(gcm(aes))"`), and both charon instances with reachable VICI
sockets now come up unprivileged.

**Still blocking a real run:**

* `swanctl` accepts the VICI connection but never receives a reply, so
  `--load-conns` / `--initiate` hang. Root cause not yet identified.
* `libstrongswan-standard-plugins` is not installed, and it is the package
  that ships `gcm.so` / `ctr.so` / `ccm.so`. Without it strongSwan cannot
  negotiate `aes128gcm16`, so **every AES-GCM entry of the matrix is
  unrunnable on such a host** (the kernel offers `rfc4106(gcm(aes))`; strongSwan
  userspace does not). Install with
  `sudo apt-get install libstrongswan-standard-plugins`.

### 1.2 A known wiring gap

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

### 4.1 Configuration / traffic-class crossing — resolved

**The shipped matrix is no longer confounded.** The 15 curated configurations are
each repeated with a second traffic class (30 entries), so:

* **every configuration carries two traffic classes**, and
* **every traffic class runs under at least four configurations** (6 classes,
  4–6 configurations each).

Configuration and traffic class are therefore not collinear: a measured
difference between configurations can no longer be an artefact of a suite that
happened never to have been paired with ICMP or VoIP traffic, and a classifier
cannot score well by recognising the configuration instead of the traffic.

This is *computed*, not asserted by hand: `check_matrix_coverage.py` reports the
`config_traffic_cross` and `traffic_config_cross` requirements, and both fail if
the matrix ever regresses to one class per configuration. A test asserts the same
property through the dry-run planner.

> Note: crossing doubles the capture count for the same coverage (15 → 30 real
> sessions). That is the price of an identifiable experiment, and it is cheaper
> than the full Cartesian product.

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
- ~~**Fix the matrix confounding in §4.1.**~~ Done — every configuration is now
  crossed with a second traffic class, enforced by the `config_traffic_cross` /
  `traffic_config_cross` coverage checks.
- Add the artifact-directory layout and a single reproducibility CLI.
- Perform the first real run, then replace this document's pending items with
  measured results.


