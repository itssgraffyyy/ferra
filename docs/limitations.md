# Platform Limitations & Execution Boundaries

This document details the platform limitations, prerequisites, and degradation
behaviours of the Linux testbed (Stage 1), plus the epistemic boundaries of the
analysis, ML, and security assessment stages.

---

## Operating System Support

### Linux (Bare Metal or Virtual Machine)
* **Status**: Fully Supported (Target Deployment Platform).
* **Requirements**:
  * Root privileges (`sudo`) or `CAP_NET_ADMIN` + `CAP_NET_RAW`.
  * Linux kernel with XFRM support enabled (`CONFIG_XFRM`, `CONFIG_INET_ESP`).
  * `strongswan` and `strongswan-swanctl` packages installed.
  * `tcpdump` or `dumpcap` for network packet capture.

### Windows Subsystem for Linux (WSL2)
* **Status**: Conditional / Partial.
* **Limitations**:
  * Default WSL2 kernels may lack full XFRM transformations or state tracking in network namespaces.
  * Unix domain sockets across `/mnt/c` mounts are not supported by the Linux kernel; VICI runtime sockets must reside on native Linux mounts (e.g. `/run` or `/tmp`).
  * Run `scripts/check_environment.py` inside WSL to probe kernel XFRM capabilities before executing real experiments.

### Windows / macOS Native
* **Status**: Development, Dry-Run, and Validation Only.
* **Limitations**:
  * Kernel IPsec (XFRM) and Linux network namespaces (`ip netns`) are unavailable.
  * Packet capture via `tcpdump` inside namespaces is unsupported.
  * The full test suite, schema validation, configuration generator, dry-run runner, and offline PCAP parser execute natively on Windows and macOS.

---

## Tool Availability & Fallback Behaviour

| Tool | If Present | If Missing / Fallback |
|------|------------|-----------------------|
| `strongSwan` | Live tunnel negotiation | Fails with `IPSEC_DAEMON_NOT_FOUND` in live runs; fully mockable in dry-run/unit tests |
| `tcpdump` / `dumpcap` | Full raw packet capture | Fails with `CAPTURE_TOOL_NOT_AVAILABLE` in live runs; dry-run bypasses capture |
| `tshark` | Protocol hierarchy sanity checking | Falls back to internal pure-Python `pcap_scan.py` frame parser |
| `curl` / `ping` / `iperf3` | External traffic generation | Falls back to in-process native socket traffic generators (`fera.traffic.native`) |
| `tshark` | Deep protocol dissection during analysis | Falls back to FERA's own deterministic IKEv2 / ESP decoder and PCAP scanner |

---

## Analysis, ML, and Security Assessment Boundaries

The protocol analyser, the dataset builder, and the security assessment are pure
Python and run on any operating system: they only need a PCAP (plus, for the
dataset, the `ground_truth.json` written beside it).  Their limits are
epistemological rather than platform ones.

### What a passive capture cannot decide
* The proposal an initiator *offered* is clear text in `IKE_SA_INIT`; the
  proposal the responder *selected* often sits inside the encrypted `IKE_AUTH`
  exchange.  Where it cannot be read, the analyser reports `NOT_VERIFIABLE` and
  the assessment lowers `evidence_coverage` instead of deducting points, so an
  unknown never looks like a weakness or like a pass.
* Receiver-side policy (replay window size, DPD/lifetime settings the peer
  actually enforces, certificate validation behaviour) is not on the wire.
  Rules about it are reported from the testbed's own configuration, graded
  `CONFIGURED` - an assertion about intent, not a measurement of the tunnel.
* Nothing is decrypted and no active probing happens: FERA never attempts
  padding-oracle, downgrade, or implementation-specific exploitation.  The score
  compares what was observed against the curated baseline in
  `docs/security_baseline.md`; it is not a penetration-test result.

### Policy baseline provenance
The algorithm tiers, lifetime ceilings, metadata thresholds, category weights,
and risk bands are a curated opinion encoded once, in `fera.security.policy`.
`docs/security_baseline.md` is generated from those tables by
`scripts/generate_security_policy_docs.py`; edit the tables, never the document.

### ML stage limits
* **No trained model is committed.**  `fera.ml` ships the feature contract
  (`FEATURE_WHITELIST`, `FEATURE_SCHEMA`), the labelled dataset factory, and
  the trainer (`fera.ml.train`, `scripts/train_model.py`).  Model binaries are
  gitignored because they are large, environment-specific, and not source.
  Until one is trained, the product reports the traffic stage as `UNAVAILABLE`
  with a reason; it never substitutes a default class.
* **A training run that could not be measured says so.**  When the split
  produces no usable test block, the training report carries
  `performance_status != MEASURED` and prepends an explicit note to the model
  metadata, so an unverified model cannot be read as a performance claim.
* Features describe traffic *behaviour* only - counts, sizes, timing, direction
  split.  Payload content, configuration values, and labels never enter a
  feature vector, and non-finite values are rejected instead of clipped.
* Splits are grouped by experiment id, so near-duplicate captures of one run
  cannot straddle a train/test boundary and inflate a reported accuracy.  The
  exact group keys per split are recorded in the training report as a leakage
  audit trail.
* Selection uses validation macro-F1 only; the test block is opened once, after
  the winner exists.
* **Shortcut risk is measured, not assumed.**  `ablate_feature_sets` re-runs the
  whole pipeline per feature set with split, seed and candidates held constant.
  A full-set score far above `esp_core` is reported as a caution that the model
  may be reading the harness rather than the traffic.
* A classifier result reaches the assessment only as a `fera_ml_prediction_v1`
  document, is graded `INFERRED`, and its confidence is reported as the
  surprisal it claims (`-log2(confidence)`) rather than as a probability of
  correctness.  Missing model identity is reported, not silently accepted, and a
  labelled sample passed off as a prediction is refused.  In the product path a
  classifier never observes the app behind the ciphertext, so its output is
  `INFERRED` by construction.

## Product Layer Boundaries

### What the dashboard does not do
The React frontend renders the canonical bundle and nothing else.  It does not
parse packets, recompute a security score, re-derive a threat, or interpret a
finding.  Every badge, score and matrix cell it displays is a value the backend
produced.  This is what stops a UI and a report from disagreeing.

### Live capture is unverified in this environment
`fera.capture.live` shells out to `tcpdump`/`dumpcap` with an argument list
(never `shell=True`), bounded to 10s by default and 60s maximum, and feeds the
result into the same orchestrator as an upload.  The subprocess boundary is
unit-tested with a fake runner - command construction, invalid duration,
invalid interface, missing tool, permission failure, timeout, cleanup.

**A real privileged capture has not been executed on the machine this was
developed on (Windows).**  To validate on Linux:

```bash
sudo apt-get install tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
python scripts/check_environment.py            # confirms the tool and privileges
curl http://localhost:8000/capabilities        # live_capture should be "available"
curl -X POST http://localhost:8000/live/analyze \
  -H 'content-type: application/json' -d '{"interface":"eth0","duration_s":10}'
```

Until that is done, treat live capture as `IMPLEMENTED — ENVIRONMENT
VALIDATION PENDING`.  The unit tests prove the code builds the right command
and handles each failure; they do not prove a packet was ever captured.

### PDF export is optional
PDF rendering uses `reportlab`, which is not a required dependency.  Without it
the API serves HTML reports and `/capabilities` reports `report_generation`
with a `pdf_reason`.  HTML export needs no extra package.

### IPv6 is not analysed at IPv4 depth
IPv6 packets are parsed and counted, but the deep IKE/ESP field extraction,
flow statistics, and feature coverage are not at parity with IPv4.  Surfaces
show only what the analyser actually extracts rather than implying parity.
This is a known, separate Prompt 2 repair - see `docs/ps_traceability.md`.

### Upload safety
Uploads are size-limited, extension- and magic-checked, and stored under a
generated name; the user-supplied filename is displayed but never used as a
filesystem path, so a traversal-style name cannot escape the upload directory.
No shell command is ever built from user input.

### History is a cache, not a second truth
SQLite (`data/fera.db`) holds summary columns for listing and filtering.  The
canonical bundle document remains authoritative: reopening an analysis returns
the stored bundle and does not re-run any stage.

### Ground truth isolation
Ground truth enters the pipeline in exactly one place: `fera.ml.dataset`, which
writes a `label` beside a feature vector that was computed independently of it.
Everywhere else the isolation is structural rather than a rule to remember:

* `extract_features` has no parameter through which a label or a configuration
  value could arrive (a test pins the signature), and the dataset module refuses
  to run unless the label key is absent from `FEATURE_WHITELIST`.
* `fera.security.ml_contract` refuses outright a document that presents a
  ground-truth `label` where a `predicted_class` was expected.
* The configuration channel reads a fixed key set (`encryption`, `integrity`,
  `prf`, the DH/PFS groups, the lifetimes, replay protection, the proposal).  The
  label and id fields of a ground-truth document are not among them, so one
  handed to `--config` is ignored rather than scored.

The result is that no score in this repository is computed from the answer key:
the strongest claim about traffic class is an `INFERRED` one, and only when a
classifier actually supplied a prediction document.
