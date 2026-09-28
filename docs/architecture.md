# FERA Architecture (Stage 1)

This document describes the high-level design of the **FERA Stage 1** pipeline:
foundation, IPsec testbed, and dataset factory.

---

## Purpose and Scope

Stage 1 is dedicated to producing *clean, labelled, reproducible IPsec VPN traffic datasets*
with unambiguous ground truth. Protocol disassembly, machine-learning classification,
and security evaluation stages consume the datasets produced here.

---

## Component Layout

```
src/fera/
├── common/             # Subprocess execution, logging, JSON/YAML serialization, errors
├── testbed/            # IPsec algorithms, topology models, swanctl conf generation,
│                       # network namespaces, charon VICI control, host environment checks
├── traffic/            # Generators (ICMP, Web/HTTP, Voip-like, Video-like, Messaging-like, Email-like)
├── capture/            # Capture orchestration (tcpdump/dumpcap), PCAP frame parser, sanity checks
└── dataset/            # Schema validation, representative matrix, ground truth, manifest, runner
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
