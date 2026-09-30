# FERA — IPsec VPN Protocol Analysis and Security Assessment Platform

**Current repository state: complete offline product — capture → analyse →
classify → assess → explain → store → visualise → report.**

The pipeline is reproducible end to end:

```
PCAP upload  OR  bounded live capture
                 │
                 ▼
           CaptureSource
                 │
                 ▼
      capture → protocol analysis   (fera.analysis — deterministic IKEv2/ESP)
                 → ML inference       (fera.ml — classifier, INFERRED)
                 → security assessment(fera.security — score, findings, threats)
                 → privacy observation(fera.privacy — metadata exposure)
                 │
                 ▼
      CANONICAL ANALYSIS BUNDLE     (fera.core — one schema, one source of truth)
                 │
       ┌─────────┼─────────┐
       ▼         ▼         ▼
  Dashboard   Reports   SQLite history
  (frontend)  (PDF/HTML/JSON)
```

Ground truth stops at the dataset boundary. The analysis and security stages
read the capture (plus, optionally, the testbed's own configuration and a
classifier prediction document) and never the answer key, so a security score
can never be steered by a label.

The dashboard, reports, persistence and exports all consume the canonical
bundle. None of them recomputes a protocol fact or a security score.

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

## Quick start — the product

```bash
# 1. Backend (product API)
python -m pip install fastapi uvicorn python-multipart
python -m uvicorn fera.api.main:app --port 8000

#    Ask what this installation can actually do, and why not more:
curl http://localhost:8000/capabilities

# 2. Dashboard
cd frontend && npm install && npm run dev

# 3. Analyse a capture (or use the Analyze view)
curl -F "file=@capture.pcap" http://localhost:8000/analyze

# 4. Reports and history
curl "http://localhost:8000/analyses/<id>/report?type=executive&format=html"
curl http://localhost:8000/analyses
```

Full walkthrough: `docs/user_guide.md`, `docs/demo_guide.md`.

## Quick start — building the dataset

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

# 5. Labelled ML dataset (features + ground truth, grouped train/val/test splits)
python scripts/build_dataset.py

# 5b. Train the traffic classifier (nothing is committed — you train it)
python scripts/train_model.py
python scripts/train_model.py --ablate      # feature-set / shortcut-risk ablation

# 6. Security assessment of one capture: analysis -> rules -> score
python scripts/assess_security.py --pcap data/raw/exp_000_*/capture.pcap

#    ... or assess an existing analysis document, adding configuration (graded
#    CONFIGURED) and a classifier prediction (graded INFERRED) as extra evidence
python scripts/assess_security.py --analysis data/processed/analysis/exp_000.json \
    --config configs/experiments/exp_000.yaml --ml-prediction prediction.json

# 7. Regenerate the security baseline reference (rules / threats / policy tables)
python scripts/generate_security_policy_docs.py
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
                         ▼
   src/fera/analysis ── deterministic IKEv2 / ESP decode, SA correlation, ESP flows
                        (evidence-graded observations, never predictions)
                         ▼
       src/fera/ml   ── 37 whitelisted statistical features from the analysis
                        output; labels join only here (data/processed/ml)
                         ▼
   src/fera.security ── 26 evidence-graded rules -> findings, threat matrix (20
                        threats, 6 weighted categories) and a 0-100 score
```

| Package | Responsibility |
|---------|----------------|
| `fera.common` | errors/error codes, logging (with secret redaction), paths, safe subprocess, tool versions |
| `fera.testbed` | algorithm vocabulary, topology, `swanctl.conf` generation, swanctl control, environment detection, netns scripts |
| `fera.traffic` | traffic generators, profiles, testbed responder |
| `fera.capture` | capture orchestration, BPF filter validation, PCAP scanning, capture sanity check |
| `fera.dataset` | experiment schema, representative matrix, ground truth, manifest, experiment runner |
| `fera.analysis` | PCAP to structured IKEv2/ESP observations (exchanges, proposals, SAs, ESP flows), each carrying its own evidence grade |
| `fera.ml` | versioned feature extraction from the analysis output, labelled dataset with grouped train/val/test splits |
| `fera.security` | generated policy tables, rule catalogue, evidence grading, scoring, threat matrix, assessment report |
| `fera.core` | capture-to-bundle orchestration and the canonical analysis result (one schema) |
| `fera.storage` | SQLite analysis history — summary rows for listing; the bundle stays authoritative |
| `fera.reports` | deterministic executive / technical reports, HTML and PDF, rendered from the stored bundle |
| `fera.privacy` | metadata exposure observer |
| `fera.api` | FastAPI product service: analyze, history, export, reports, model status, capabilities |

Details: `docs/architecture.md`, `docs/user_guide.md`, `docs/demo_guide.md`,
`docs/ps_traceability.md`, `docs/testbed.md`, `docs/experiment_matrix.md`,
`docs/limitations.md`, `docs/ipsec_correctness.md`, `docs/security_baseline.md`.

---

## Verification & Testing

FERA maintains a comprehensive automated test suite and static analysis checks:

```bash
# Run test suite
python -m pytest

# Run linting and code formatting check
python -m ruff check src tests scripts

# Run type checking
python -m mypy
```

### Key Highlights
- **100% Test Coverage Across Core Components**: Includes algorithm rule validation, schema parsing, configuration rendering, traffic generators, PCAP framing, and runner execution flows.
- **Strict RFC / strongSwan Cryptographic Rules**: Enforces AEAD cipher uniqueness, prevents illegitimate HMAC pairings on AEAD proposals, and guarantees deterministic child SA Diffie-Hellman mappings.
- **Standalone PCAP Analysis**: Custom binary parser extracts frame details and counts without relying on third-party dissection utilities.
- **Resilient Execution Controls**: Redacts credentials in logs, isolates namespace runtime sockets on local paths, and generates structured failure artifacts upon unhandled execution events.
- **Evidence-Graded Analysis And Assessment**: Every analytical statement carries an evidence grade (`OBSERVED` / `INFERRED` / `NOT_VERIFIABLE` in the analyser, `OBSERVED` / `CONFIGURED` / `INFERRED` / `NOT_VERIFIABLE` in the assessment); a property a passive capture cannot decide lowers evidence coverage instead of moving the score.
- **Ground Truth Isolation**: ground truth is read by exactly one module (`fera.ml.dataset`); `extract_features` accepts no label or configuration input, the security stage refuses a labelled sample presented as a prediction, and the configuration channel reads only fixed algorithm keys, so no score can be derived from the answer key.
- **A Trained Model Is Not Committed**: the repository ships the *trainer* (`fera.ml.train`), not a model binary. Until you train one, the traffic stage reports `UNAVAILABLE` with a reason and every other stage stays fully usable — no fallback class, no hard-coded prediction. Train with `python scripts/train_model.py`; the API discovers whatever is in `data/models/`.
- **Honest Unavailability**: `/capabilities`, `/models/status` and the dashboard all distinguish *present*, *absent*, and *present but unverifiable*. A missing tshark, a missing capture tool, or a missing model is reported with a reason, never papered over.
- **One Source Of Truth**: the canonical analysis bundle is the only result document. Dashboard, reports, exports and history all read it; none of them re-runs analysis or recomputes a score.
- **Offline-First**: after local dependencies are installed, the entire analysis path — parsing, features, inference, assessment, privacy, persistence, API, dashboard, reports — runs with no network access. No cloud services, no LLM, no telemetry.

