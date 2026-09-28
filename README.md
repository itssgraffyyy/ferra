# FERA — IPsec VPN Protocol Analysis and Security Assessment Platform

**Stage 1 (this repository state): foundation + IPsec testbed + dataset factory.**

The goal of this stage is a *reproducible pipeline* that produces a labelled
IPsec dataset:

```
experiment configuration  →  strongSwan IPsec configuration  →  establish VPN
        →  generate labelled traffic  →  capture packets
        →  PCAP + ground truth + manifest
```

Later stages (protocol parsing, ML traffic classification, security scoring,
product API, dashboard, reports) consume these artefacts.  They are **not**
part of this stage.

---

## Setup

### Python

```bash
python -m pip install -r requirements.txt        # PyYAML (runtime)
python -m pip install -r requirements-dev.txt    # pytest / ruff / mypy (development)
```

Python ≥ 3.10 is required.  The repository works from a plain checkout: the
scripts insert `src/` into `sys.path`, so installing the package is optional
(`pip install -e .` also works).

### Linux tools (for real experiments only)

| Tool | Purpose | Install |
|------|---------|---------|
| strongSwan (`swanctl`, `charon`) | IPsec endpoints | `apt-get install strongswan strongswan-swanctl` |
| `tcpdump` (or `dumpcap`) | packet capture | `apt-get install tcpdump` |
| `tshark` (optional) | capture sanity check | `apt-get install tshark` |
| `iperf3` (optional) | throughput traffic | `apt-get install iperf3` |
| `curl` (optional) | web traffic | `apt-get install curl` |
| `ping` (iputils) | ICMP traffic | `apt-get install iputils-ping` |

Everything except `swanctl`/`tcpdump` is optional; FERA reports what is missing
and either falls back (e.g. its own PCAP scanner instead of tshark) or fails
explicitly.  See `docs/limitations.md`.

## Quick start

```bash
# 1. What can this machine do?  (never claims a testbed works without probing it)
python scripts/check_environment.py

# 2. Generate the representative experiment matrix + verify PS coverage
python scripts/generate_experiment_matrix.py
python scripts/check_matrix_coverage.py

# 3. Run one experiment (needs the Linux testbed, see docs/testbed.md)
sudo python scripts/setup_netns_testbed.py --apply --start-charon
sudo python scripts/run_experiment.py --config configs/experiments/exp_000_*.yaml --update-manifest

# 4. Dataset index + sanity check of a single capture
python scripts/build_manifest.py
python scripts/validate_capture.py --pcap data/raw/exp_000_*/capture.pcap
```

Without a Linux testbed the whole pipeline can still be exercised:

```bash
python scripts/run_experiment.py --config configs/experiments/exp_000_*.yaml --dry-run
# → writes experiment.yaml, the generated swanctl.conf of both endpoints,
#   the exact command plan, and ground_truth.json (status DRY_RUN)
```

## Architecture

```
                 ┌───────────────┐   configs/experiments/*.yaml (schema validated)
                 │  experiment   │◄── scripts/generate_experiment_matrix.py
                 │  definition   │    configs/templates/*.yaml (topology, profiles)
                 └───────┬───────┘
                         ▼
   src/fera/testbed  ── strongSwan swanctl.conf (per endpoint, no credentials)
   src/fera/testbed  ── swanctl control plane (load → initiate → list-sas → terminate)
                         ▼
   src/fera/traffic  ── ICMP / web / email_like / voip_like / video_like / messaging_like
                         ▼
   src/fera/capture  ── tcpdump/dumpcap orchestration + sanity check (IKE, ESP, IP version)
                         ▼
   src/fera/dataset  ── ground truth + manifest + runner (data/raw/<experiment>/)
```

| Package | Responsibility |
|---------|----------------|
| `fera.common` | errors/error codes, logging (with secret redaction), paths, safe subprocess, tool versions |
| `fera.testbed` | algorithm vocabulary, topology, `swanctl.conf` generation, swanctl control, environment detection, netns scripts |
| `fera.traffic` | traffic generators, profiles, testbed responder |
| `fera.capture` | capture orchestration, BPF filter validation, PCAP scanning, capture sanity check |
| `fera.dataset` | experiment schema, representative matrix, ground truth, manifest, experiment runner |

Details: `docs/architecture.md`, `docs/testbed.md`, `docs/experiment_matrix.md`,
`docs/limitations.md`, `docs/ipsec_correctness.md`.

---

## Stage 1 Verification & Testing

FERA maintains a comprehensive automated test suite and static analysis checks:

```bash
# Run test suite
python -m pytest

# Run linting and code formatting check
python -m ruff check src tests

# Run type checking
python -m mypy
```

### Key Stage 1 Highlights
- **100% Test Coverage Across Core Components**: Includes algorithm rule validation, schema parsing, configuration rendering, traffic generators, PCAP framing, and runner execution flows.
- **Strict RFC / strongSwan Cryptographic Rules**: Enforces AEAD cipher uniqueness, prevents illegitimate HMAC pairings on AEAD proposals, and guarantees deterministic child SA Diffie-Hellman mappings.
- **Standalone PCAP Analysis**: Custom binary parser extracts frame details and counts without relying on third-party dissection utilities.
- **Resilient Execution Controls**: Redacts credentials in logs, isolates namespace runtime sockets on local paths, and generates structured failure artifacts upon unhandled execution events.

