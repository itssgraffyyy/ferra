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
* **No trained model ships with the repository.**  `fera.ml` is the feature
  contract (`FEATURE_WHITELIST`, `FEATURE_SCHEMA`) and the labelled dataset
  factory; there is no trainer, no evaluation harness, and therefore no accuracy
  claim anywhere in this repository.
* Features describe traffic *behaviour* only - counts, sizes, timing, direction
  split.  Payload content, configuration values, and labels never enter a
  feature vector, and non-finite values are rejected instead of clipped.
* Splits are grouped by experiment id, so near-duplicate captures of one run
  cannot straddle a train/test boundary and inflate a reported accuracy.
* A classifier result reaches the assessment only as a `fera_ml_prediction_v1`
  document, is graded `INFERRED`, and its confidence is reported as the
  surprisal it claims (`-log2(confidence)`) rather than as a probability of
  correctness.  Missing model identity is reported, not silently accepted, and a
  labelled sample passed off as a prediction is refused.

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
