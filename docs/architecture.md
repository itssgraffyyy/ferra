# FERA Architecture

This document describes the high-level design of the FERA pipeline: the IPsec
testbed and dataset factory that produce labelled captures, the deterministic
protocol analyser, the ML feature/dataset stage, and the evidence-graded
security assessment that consumes them.

---

## Purpose and Scope

The foundation stage produces *clean, labelled, reproducible IPsec VPN traffic datasets*
with unambiguous ground truth.  Three later stages consume those artefacts:

| Stage | Package | Reads | Produces |
|-------|---------|-------|----------|
| Protocol analysis | `fera.analysis` | `capture.pcap` | evidence-graded `ProtocolAnalysis` document |
| ML dataset | `fera.ml` | analysis documents, plus ground truth in the dataset module | versioned feature vectors, labelled dataset with grouped splits |
| Security assessment | `fera.security` | analysis document, optionally the testbed configuration and a classifier prediction | findings, threat matrix, weighted score |

Ground truth is an input to the dataset module only.  Neither the analyser nor
the assessment reads it, so a security score can never be steered by the answer
key; a classifier prediction is accepted as `INFERRED` evidence and carries its
own confidence into the report.

---

## Component Layout

```
src/fera/
├── common/             # Subprocess execution, logging, JSON/YAML serialization, errors
├── testbed/            # IPsec algorithms, topology models, swanctl conf generation,
│                       # network namespaces, charon VICI control, host environment checks
├── traffic/            # Generators (ICMP, Web/HTTP, Voip-like, Video-like, Messaging-like, Email-like)
├── capture/            # Capture orchestration (tcpdump/dumpcap), PCAP frame parser, sanity checks
├── dataset/            # Schema validation, representative matrix, ground truth, manifest, runner
├── analysis/           # Deterministic IKEv2 / ESP decoding, SA correlation, ESP flow statistics,
│                       # evidence provenance, optional tshark cross-check
├── ml/                 # Feature extraction from analysis output, labelled dataset with grouped splits
└── security/           # Generated policy tables, rule catalogue, evidence grading, scoring,
                        # threat matrix, assessment model
```

### 1. `fera.common`
* **Errors & Codes (`errors.py`)**: Structured `FeraError` exception hierarchy tagged with canonical `ErrorCode` enums and actionable remediation hints.
* **Process Abstraction (`process.py`)**: Subprocess execution interface with timeout enforcement, safe credential redaction, and `ScriptedRunner` for deterministic unit testing.
* **Logging (`logging_utils.py`)**: Unified logger with secret-masking filters (PSKs, private keys).
* **Serialization (`serialization.py`)**: Safe YAML and JSON dumping with atomic file writes and consistent formatting.

### 2. `fera.testbed`
* **Algorithms (`algorithms.py`)**: Validates proposal syntax according to RFC 7296 and strongSwan specifications. Enforces AEAD vs cipher + HMAC rules, and strict PFS DH-group linkage.
* **Topology (`topology.py`)**: Models endpoints, outer transit links, LAN subnets, and routing table structures.
* **Swanctl Config (`swanctl_config.py`)**: Deterministically generates `swanctl.conf` and separated secrets files with 0600 POSIX permissions.
* **IPsec Control (`ipsec_control.py`)**: Automates configuration loading, connection initiation, and live SA parsing via swanctl CLI and VICI sockets.
* **Network Namespaces (`namespaces.py`)**: Configures dual network namespaces (`fera-a`, `fera-b`) connected via virtual ethernet (`veth`) pairs.
* **Environment Detection (`environment.py`)**: Probes host capabilities: kernel XFRM state/policy support, raw socket capture privileges, namespace isolation, and installed binaries.

### 3. `fera.traffic`
* **Traffic Generators (`base.py`, `registry.py`)**: Uniform generator protocol producing declarative `TrafficPlan` structures before execution.
* **Native Patterns (`native.py`)**: Deterministic in-process UDP and TCP flow generators for environments lacking external traffic generators.
* **Application Profiles**:
  * `icmp.py`: Ping sequences with controlled packet counts and intervals.
  * `web.py`: HTTP request flows with repeatable path access patterns.
  * `voip_like.py`: Constant-bitrate UDP audio flow simulation.
  * `video_like.py`: High-throughput TCP video stream simulation.
  * `messaging_like.py`: Bursty small-packet chat sessions.
  * `email_like.py`: Request-response email message transmissions.
  * `control.py`: Pure IKE/ESP control plane traffic without application payload.

### 4. `fera.capture`
* **Capture Orchestration (`capture.py`)**: Manages `tcpdump` / `dumpcap` subprocess lifecycles with PID tracking, graceful termination, and file size validation.
* **BPF Filter Verification (`capture.py`)**: Validates BPF filter expressions against unwanted characters or injection vulnerabilities.
* **Pure Python PCAP Parser (`pcap_scan.py`)**: Standalone PCAP frame header unpacker counting IKE (UDP 500/4500), ESP (protocol 50), IPv4, and IPv6 frames without external tool dependencies.
* **Tshark Sanity Verification (`sanity.py`)**: Optional deep protocol hierarchy validation via `tshark -q -z io,phs`.

### 5. `fera.dataset`
* **Schema Validation (`schema.py`)**: Fully validated `ExperimentConfig` dataclasses with strict immutability, slugification, and round-trip serialization.
* **Matrix Generation (`matrix.py`)**: Constructs representative factorial experiment matrices spanning encryption ciphers, integrity algorithms, DH groups, IP versions, and traffic profiles.
* **Experiment Runner (`runner.py`)**: End-to-end execution coordinator: pre-flight checks → config deployment → capture initiation → IPsec handshake → traffic generation → capture finalization → ground truth writing.
* **Manifest Builder (`manifest.py`)**: Scans dataset raw directories and compiles a dataset catalog (`manifest.json`) indexing all valid experiments, captures, and SA states.

### 6. `fera.analysis`
* **Analyser (`analyzer.py`)**: one deterministic pass over a PCAP producing the `ProtocolAnalysis` document - packet and flow counts, IKE exchanges, ESP flows, PFS verdict and warnings. No ML, no guessing: a field the capture cannot answer stays `NOT_VERIFIABLE`.
* **IKE Decoding (`ike.py`, `constants.py`)**: exchanges, proposals and transforms decoded against the IANA identifier registries for encryption, integrity, PRF algorithms and DH groups.
* **ESP Flows (`esp.py`)**: per-SPI flow records - packet and byte counts, length distribution, direction split, inter-arrival statistics - which are also the input of the ML stage.
* **SA Correlation (`sa.py`)**: links clear-text IKE proposals to observed ESP flows and decides whether child SA PFS is enabled, disabled, or not decidable from this capture.
* **Evidence Provenance (`provenance.py`)**: every statement carries `OBSERVED`, `INFERRED` (deterministically derived) or `NOT_VERIFIABLE`; an encrypted `IKE_AUTH` payload keeps the selected child proposal unverifiable instead of guessed.
* **Optional Tshark Cross-check (`tshark.py`)**: external dissection when `tshark` is installed, with FERA's own scanner as the always-available fallback.

### 7. `fera.ml`
* **Feature Extraction (`features.py`)**: 37 whitelisted statistical features (`FEATURE_WHITELIST`, `FEATURE_SCHEMA`) derived only from analysis output plus PCAP frame headers. Ground truth and configuration values never enter the vector, and non-finite values are refused rather than clipped.
* **Dataset Factory (`dataset.py`)**: joins feature vectors with ground-truth labels (`DATASET_SCHEMA`), assigns grouped train/val/test splits per experiment id so near-duplicate captures cannot straddle a boundary, and validates documents both when written and when read back.

### 8. `fera.security`
* **Context (`context.py`)**: adapts an analysis document - optionally the testbed configuration and a classifier prediction - into one `AssessmentContext`. Each piece of information keeps the grade of the source it came from.
* **Evidence (`evidence.py`)**: the four grades with their precedence. Only `OBSERVED`, `CONFIGURED` and `INFERRED` may change a score; `NOT_VERIFIABLE` lowers `evidence_coverage` instead, which keeps "unknown" apart from "weak".
* **Policy (`policy.py`)**: the generated tables - encryption/integrity/PRF/DH tiers, lifetime ceilings, metadata thresholds, category weights, evidence and status factors, risk bands. `scripts/generate_security_policy_docs.py` renders `docs/security_baseline.md` from these tables, so documentation and engine cannot drift apart.
* **Rules (`rules.py`)**: 26 pure functions of the context across the six weighted categories (cryptography, key exchange, SA security, replay protection, configuration, metadata privacy). A rule states a verdict and cites evidence; it never computes points.
* **Scoring (`scoring.py`)**: the only place a verdict becomes a deduction. Tier base points are scaled by status and evidence factors, and a verdict that cites no evidence costs nothing whichever status it claims.
* **Threats (`threats.py`)**: 20 catalogue entries, each mapped to the rules that can expose it, with per-entry likelihood and impact combined through the risk matrix. An entry inherits the evidence status of the finding that triggered it.
* **Assessment (`assessment.py`)**: assembles findings, the per-category ledger, the threat matrix, metadata exposure, fingerprintability, recommendations and limitations into the serialisable `SecurityAssessment` (`fera_security_assessment_v1`), written by `scripts/assess_security.py` to `data/processed/security/<id>.json`.
* **ML Contract (`ml_contract.py`)**: `TrafficPrediction` (`fera_ml_prediction_v1`) is the only door through which classifier output reaches the assessment. It requires a predicted class and a confidence inside `[0, 1]`, tolerates missing model identity but reports it through `complete_metadata`, flags any feature outside the Prompt 3 whitelist, and refuses a document that carries a ground-truth `label` instead of a `predicted_class`.
