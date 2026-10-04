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

**Still blocking a full strongSwan run:**

* **A charon started in a network namespace accepts VICI connections and never
  answers them.** This is where the work actually stands after eleven
  instrumented runs. The daemon is *not* broken and *not* stuck in
  initialisation — as **real root** it starts completely:

  ```
  loaded plugins: … socket-default … vici …
  dropped capabilities, running as uid 0, gid 0
  spawning 8 worker threads
  installed bypass policy for 10.10.10.0/24        (ipsec0 created, netlink live)
  ```

  Its socket is a genuine listener owned by the daemon, and a raw `connect()`
  proves the connection is *accepted*:

  ```
  u_str LISTEN 0 3 /var/lib/fera-testbed/charon-a.vici  users:(("charon",pid=125855,fd=24))
  connect() SUCCEEDED -> something IS listening
     connected but NO reply in 5s -> accepted, never serviced
  Recv-Q after the attempt: 0     -> accept() happened; only the reply is missing
  ```

  Four consecutive probes with a **180 s** budget each all expired, so this is a
  hang and not slowness. The daemon binds the socket, accepts, and never services
  the request.

  Note the unprivileged case too: under `unshare -Urnm` the daemon behaves the
  same way. Running as real root therefore did *not* fix it — it only removed a
  second, unrelated blocker. An earlier draft of this document blamed the user
  namespace; that was withdrawn, because the host's own daemon answers VICI
  correctly (`uptime: 12 hours`, 16 worker threads, `IKE_SAs: 0`) and the only
  difference is the namespace charon runs in.

* **Why the diagnosis took eleven runs.** Five explanations were proposed and
  refuted, recorded here so the next attempt does not repeat them:

  | Claim | Refuted by |
  |---|---|
  | charon never finishes initialisation | run 5: plugins load, workers spawn, XFRM policies install |
  | the user namespace is the cause | run 5: root charon answers fine |
  | a successful tmpfs mount hides `/run` | run 8: socket dir moved outside `/run`, symptom unchanged |
  | a slow filesystem starves the event loop | run 11: `/home` is plain ext4 on `/dev/sdd`, not a WSL volume |
  | the probe budget was too short | run 11: 4 × 180 s all expired |
  | the network namespace is the cause | run 8: a host-netns daemon with FERA's conf hung too (`rc=124`) |

  Run 10 is the reason several of these could not be separated: it started three
  daemons *simultaneously* and probed them in sequence, so V and V2 — differing
  only in their filelog configuration — reported opposite results. Every earlier
  A/B is confounded in the same way.

* **Operational warning — a diagnostic took the host's `/run` with it.** A probe
  daemon was once started as a bare `sh -c 'mount -t tmpfs … /var/run'` without
  `unshare -m`. Because `/var/run` is a symlink to `/run`, that mounted a tmpfs
  over `/run` **in the host mount namespace** and hid `/run/charon.vici`, so the
  host's own strongSwan daemon became uncontrollable by `swanctl`. Repair with
  `umount -l /run` (possibly after killing leftover probe daemons), or reboot.
  FERA itself never does this: `setup_netns_testbed` starts daemons through
  `ip netns exec`, which always gets a private mount namespace. Any *ad hoc*
  probe must do the same.

* **Two defects that privileges did expose** (`fd17e8f`), both now fixed. They
  were invisible unprivileged because each had a working unprivileged fallback:

  | Defect | Symptom | Why unprivileged runs looked fine |
  |---|---|---|
  | capture interface looked up on the host | `environment not ready: … capture interface 'fera-va' does not exist` — the run aborted before any traffic | `fera-va` lives in the endpoint namespace and never on the host, so `/sys/class/net` cannot see it; the check now probes `ip -o link show` behind the endpoint prefix |
  | private tmpfs shadowed `/run` | charon bound **no** VICI socket at all | unprivileged the mount is denied and `\|\| true` swallows it, leaving the real `/run` intact |

  A third followed from the second: the socket must live **outside** `/run`,
  because any private `/var/run` shadows `/run` itself. As root
  `default_socket_dir()` now returns `/var/lib/fera-testbed`
  (`de441c2`). Note that a *fixed* socket path is not enough — `ip netns exec`
  gives each invocation a fresh mount namespace, so the socket directory must be
  reachable from both charon's namespace and the client's.

* `libstrongswan-standard-plugins` ships `gcm.so` / `ctr.so` / `ccm.so`.
  Without it strongSwan cannot negotiate `aes128gcm16`, so **every AES-GCM
  entry of the matrix is unrunnable** (the kernel offers `rfc4106(gcm(aes))`;
  strongSwan userspace does not). It was missing here and is **now installed**:
  `/usr/lib/ipsec/plugins/libstrongswan-gcm.so` is present on this host, so
  GCM is no longer a blocker.

### 1.1.1 Genuine ESP without strongSwan

Because the daemon is unusable here, one real IPsec run was obtained by
installing XFRM state and policy **directly** — two namespaces joined by a veth,
matching `cbc(aes)` + `hmac(sha256)` keys on both ends, a route for the
protected subnet, and `tcpdump` on the wire. Verified with `tshark`:

```
11  2.757707  10.10.10.1 → 10.10.10.2  ESP 166 ESP (SPI=0x00001000)
12  3.776442  10.10.10.1 → 10.10.10.2  ESP 166 ESP (SPI=0x00001000)
14  4.800777  10.10.10.1 → 10.10.10.2  ESP 166 ESP (SPI=0x00001000)
16  5.824169  10.10.10.1 → 10.10.10.2  ESP 166 ESP (SPI=0x00001000)
```

`ip -s xfrm state` on the sending side reports `lastused`, so the SA was not
merely installed but used. That is **real ESP encapsulation**: the payload
really was encrypted in tunnel mode.

What this run is **not**, stated plainly:

* there is **no IKE** — the keys were configured statically, so a capture of
  this shape fails `validate_capture`'s IKE requirement, and it must not be
  presented as a strongSwan result;
* it is **one-directional** — outbound packets encapsulate correctly, replies
  do not come back, so the decapsulation path is still unproven;
* it exercises the **kernel's** XFRM stack, not strongSwan's proposal
  negotiation.

It does prove what the blockers could not: this host can carry genuine ESP, so
the reason FERA cannot collect a dataset here is the IKE daemon, not the IPsec
implementation.

### 1.2 Gate and netem wiring: resolved

`scripts/run_experiment.py` no longer takes `integration_verified` on trust. It
used to pass a literal `True` into the ground truth document, so **any run that
produced a parseable capture claimed real-IPsec integration** — including one
where the payload had crossed a cleartext path. That is exactly the failure
`fera.experiment.gates` was written to catch, and nothing consulted it.

The runner now collects observed evidence and derives the claim:

| Gate | Evidence it requires |
|---|---|
| `ike_sa_verified` | `swanctl --list-sas` reports `ESTABLISHED` |
| `child_sa_verified` | the CHILD_SA reports `INSTALLED` |
| `xfrm_state_verified` | `ip xfrm state` lists at least one entry |
| `xfrm_policy_verified` | `ip xfrm policy` lists at least one entry |
| `protected_payload_verified` | traffic generated **and** a CHILD_SA was installed |
| `esp_verified` | ESP present in the capture |

`integration_verified` is true only when all six hold. Each run also writes
`gates.json`, and the ground truth document embeds the same gate state, so the
claim can be audited from the artefacts rather than taken on trust. A run with
unmet gates still exits `SUCCESS` with a valid capture — the capture is real —
but it is no longer advertised as real-IPsec evidence.

Two deliberate distinctions: an XFRM probe that *could not run* (unprivileged
`RTNETLINK answers: Operation not permitted`) is recorded as **not probed**
rather than **no SA exists**; and traffic that generated successfully does not
satisfy the protected-payload gate on its own, since bytes moving proves nothing
about which path they took.

`fera.experiment.netem` is now **wired into the driver**:

```bash
sudo python scripts/run_experiment.py --config <experiment> \
    --network-condition jitter            # baseline | loss | jitter | latency
```

The qdisc is applied after capture starts and removed in a `finally` block, so
it is cleaned up even when the experiment fails — a qdisc left behind silently
changes the next run's behaviour, which is how "the second experiment behaved
differently from the first" happens. Use `--network-interface` to target an
interface other than the capture interface.

Each run writes `network_condition.json` and the ground truth embeds the same
document. `applied` is set **only** when `tc` actually succeeded: a condition
that was requested but could not be applied is recorded as not applied and the
run proceeds unimpaired, so no artefact can claim an impairment that did not
happen. The `baseline` condition issues no command at all, because replacing an
empty qdisc would itself clobber whatever a previous run left behind.

Planning still stays in `fera.experiment.netem`, which executes nothing by
design; the runner performs the execution.

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

## 5. Netem robustness (wired)

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

Apply and clean up around **each** run, with the driver doing both:

```bash
# The driver applies the qdisc, runs the experiment, and removes the qdisc
# afterwards -- including when the experiment fails.
sudo python scripts/run_experiment.py --experiment-id <id> --network-condition loss
```

To shape the traffic by hand instead, the same ordering still applies:

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

### 6.0 Verify what you produced

A manifest records a SHA-256 per capture, but nothing re-checked those hashes —
a replaced or truncated capture would still be advertised as a valid sample.
`verify_dataset.py` re-hashes every capture the manifest lists and reports which
code produced the dataset:

```bash
python scripts/verify_dataset.py                 # exit 0 only if everything matches
python scripts/verify_dataset.py --json data/manifests/provenance.json
```

```
FERA dataset provenance
source commit : a438bb2… (main, dirty)
  note: uncommitted changes; the commit alone will not reproduce this

captures checked : 1
  matched        : 1
result: VERIFIED
```

Three states are reported separately, because they mean different things:

| State | Meaning |
|---|---|
| `matched` | the bytes still hash to what the run recorded |
| `MISMATCHED` | the capture changed after the run — **not** a valid sample |
| `no hash recorded` | predates hash recording; unverifiable, never counted as a pass |

The **dirty** flag matters as much as the commit: results produced from
uncommitted changes cannot be reproduced from the commit alone, so the report
says so rather than implying a clean revision.

### 6.1 Repeated sessions

A single capture is not an experiment. `--repeats N` runs each experiment N
times:

```bash
sudo python scripts/run_experiment.py --config configs/experiments --repeats 3 \
    --capture-interface veth-a --update-manifest
```

Each repeat gets **its own `experiment_id`** (`…--r01`, `--r02`, …) so it writes
its own directory and derives its own traffic seed, but they all share the
original id as their **`session_id`**.

The dataset splits on the *session*, not the experiment id. This matters: three
repeats of one configuration are three windows into the same tunnel, so treating
them as independent samples would let a capture appear in training and its
sibling in the test set — inflating every reported score. `split_integrity()`
proves no session straddles the boundary, and it fails loudly if one does.

Ground truth written before sessions existed has no `session_id`; those samples
fall back to splitting on the experiment id, so existing datasets keep working.

### 6.2 Evidence rules that will not bend

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

- ~~Wire `netem`, `preflight`, `gates`, and `manifest` into `run_experiment.py`.~~
  Done — the runner derives `integration_verified` from observed evidence
  (§1.2), and `--network-condition` applies and cleans up the netem qdisc
  (§5). The `ExperimentManifest` type in `fera/experiment/manifest.py` is still
  unused dead code and can be deleted or wired separately.
- ~~Add traffic/capture lifecycle management and repeated-session orchestration.~~
  Repeated sessions are wired: `--repeats N` runs each experiment N times with
  distinct experiment ids that **share one session**, and the dataset splits on
  the session so a repeated capture cannot land on both sides of the train/test
  boundary. See §6.
- ~~**Fix the matrix confounding in §4.1.**~~ Done — every configuration is now
  crossed with a second traffic class, enforced by the `config_traffic_cross` /
  `traffic_config_cross` coverage checks.
- ~~Add the artifact-directory layout and a single reproducibility CLI.~~
  Done — `scripts/run_pipeline.py` runs matrix → experiments → manifest →
  dataset → verify in one command (with `--dry-run` to plan without executing and
  `--skip` for a single stage), and `scripts/verify_dataset.py` records the source
  revision and re-hashes every capture, exiting non-zero when anything fails
  (§6.0).
- Perform the first real run, then replace this document's pending items with
  measured results.


