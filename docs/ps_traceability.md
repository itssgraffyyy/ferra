# PS Traceability

Map from the problem statement to FERA implementation, with the evidence that
each row was actually verified.

## How to read the status column

| Status | Meaning |
|--------|---------|
| `IMPLEMENTED — CODE VERIFIED` | Implemented and covered by an automated test that passes here. |
| `IMPLEMENTED — ENVIRONMENT VALIDATION PENDING` | Implemented and unit-tested, but the real-world path (a live strongSwan tunnel, a privileged capture) has not been exercised on this machine. |
| `PARTIAL` | Real functionality exists, but it does not cover the whole requirement. |
| `NOT_STARTED` | Not implemented. |

Nothing here is marked verified on the strength of a synthetic test alone.

---

## A. VPN Testbed

| PS requirement | Implementation | Verification | Status |
|---|---|---|---|
| Tunnel mode | `fera.testbed.algorithms` proposal vocabulary; `swanctl_config` type=tunnel | `tests/test_swanctl_config.py`, `tests/test_algorithms.py` | ENVIRONMENT VALIDATION PENDING |
| Transport mode | same, `type=transport` | `tests/test_algorithms.py` | ENVIRONMENT VALIDATION PENDING |
| AES-128 / AES-256 | algorithm vocabulary + tier table `fera.security.policy` | `tests/test_algorithms.py`, `tests/test_policy_tables.py` | CODE VERIFIED |
| AES-GCM | AEAD validation (no separate HMAC on an AEAD proposal) | `tests/test_algorithms.py` | CODE VERIFIED |
| AES-CBC + HMAC | cipher/integrity pairing validation | `tests/test_algorithms.py` | CODE VERIFIED |
| DH groups | group vocabulary; child-SA PFS linkage rules | `tests/test_algorithms.py`, `tests/test_policy_tables.py` | CODE VERIFIED |
| PFS on/off | `sa.py` decides enabled / disabled / not-decidable | `tests/test_sa_pfs.py` | CODE VERIFIED |
| IPv4 | netns topology, ESP flow records | `tests/test_topology.py`, `tests/test_esp_flows.py` | ENVIRONMENT VALIDATION PENDING |
| IPv6 | parsed, but **not** at full IPv4 depth | `docs/limitations.md` | PARTIAL |
| Traffic generators | `fera.traffic` — ICMP, web, VoIP-like, video-like, messaging-like, email-like; native socket fallback | `tests/test_traffic_*.py` | ENVIRONMENT VALIDATION PENDING |

## B. Traffic Capture

| PS requirement | Implementation | Verification | Status |
|---|---|---|---|
| IKE capture | `fera.capture` orchestration, `fera.analysis.ike` decoder | `tests/test_capture_*.py`, `tests/test_ike*.py` | CODE VERIFIED |
| ESP capture | `fera.analysis.esp` flow records | `tests/test_esp_flows.py` | CODE VERIFIED |
| AH | recognised as a protocol; no full AH decoder | — | PARTIAL |
| Normal (non-IPsec) traffic | same capture path; analysed as ordinary flows | `tests/test_analysis.py` | CODE VERIFIED |
| Batch input (PCAP upload) | `POST /analyze` → `fera.core.orchestrator` | `tests/test_api_product.py` | CODE VERIFIED |
| Live input | `fera.capture.live` — bounded tcpdump/dumpcap capture | `tests/test_capture_live.py` | ENVIRONMENT VALIDATION PENDING |

## C. AI Identification

| PS requirement | Implementation | Verification | Status |
|---|---|---|---|
| IPsec detected | `ProtocolAnalysis.ipsec_detected` | `tests/test_analysis.py` | CODE VERIFIED |
| IKE version | `ike.py`, IANA registry tables | `tests/test_ike*.py` | CODE VERIFIED |
| Mode | tunnel/transport from SA correlation | `tests/test_sa.py` | CODE VERIFIED |
| Encryption / authentication | proposal transforms, evidence-graded | `tests/test_analysis.py` | CODE VERIFIED |
| Key exchange | KE payload / DH group | `tests/test_ike*.py` | CODE VERIFIED |
| SA characteristics | IKE SA + CHILD SA, SPIs, selectors | `tests/test_sa.py` | CODE VERIFIED |
| Traffic prediction | `fera.ml.train` / `inference` → bundle `traffic` stage | `tests/test_ml_*.py`, `tests/test_api_product.py` | CODE VERIFIED |


## D. Security Assessment

| PS requirement | Implementation | Verification | Status |
|---|---|---|---|
| Crypto strength | `fera.security.rules` cryptography tier rules | `tests/test_security_rules.py` | CODE VERIFIED |
| Configuration | rules graded `CONFIGURED` from the testbed config | `tests/test_security_rules.py` | CODE VERIFIED |
| SA security | SA category rules | `tests/test_security_rules.py` | CODE VERIFIED |
| Key lifetime | lifetime rules; observed vs configured vs not verifiable | `tests/test_security_rules.py` | CODE VERIFIED |
| Replay | replay rules; enforcement is `NOT_VERIFIABLE` from a passive capture | `tests/test_security_rules.py` | CODE VERIFIED |
| PFS | PFS rules consume `sa.py` evidence | `tests/test_security_rules.py` | CODE VERIFIED |
| Cipher suite | cipher-suite rules | `tests/test_security_rules.py` | CODE VERIFIED |
| Metadata exposure | `fera.privacy.observer` (checkpoint 5A) | `tests/test_privacy_observer.py` | CODE VERIFIED |

## E. Output

| PS requirement | Implementation | Verification | Status |
|---|---|---|---|
| Security score | `fera.security.scoring`, single owner of the 0-100 score | `tests/test_security_scoring.py` | CODE VERIFIED |
| Risk score / band | `policy` risk bands | `tests/test_security_scoring.py` | CODE VERIFIED |
| Traffic analysis | ML `traffic` stage of the bundle | `tests/test_ml_inference.py` | CODE VERIFIED |
| Metadata inference | privacy observer + `INFERRED` exposure findings | `tests/test_privacy_observer.py` | CODE VERIFIED |
| Executive report | `fera.reports.executive` → HTML/PDF | `tests/test_reports.py` | CODE VERIFIED |
| Technical report | `fera.reports.technical` (sections A-R) → HTML/PDF | `tests/test_reports.py` | CODE VERIFIED |
| Threat matrix | `fera.security.threats`, 20 entries; rendered, never recomputed in the UI | `tests/test_security_threats.py` | CODE VERIFIED |
| AI confidence | `confidence` + `probabilities` in the traffic stage | `tests/test_ml_inference.py` | CODE VERIFIED |

## Deliverables

| Deliverable | Where | Status |
|---|---|---|
| Working prototype | `fera.api` + `frontend/` — capture → analyse → classify → assess → store → visualise → report | CODE VERIFIED (build/typecheck/tests pass; a live end-to-end run has not been performed on this machine) |

---

## Remaining gaps

1. **IPv6 deep-analysis equivalence.** IPv6 is parsed but not to the depth IPv4
   reaches. `docs/limitations.md` states exactly what is and is not extracted.
   Deliberately deferred — repairing it is a Prompt 2 task, not a product task.
2. **AH.** Recognised, not deeply decoded.
3. **No trained model is committed.** The repository ships the trainer, not a
   model binary. Without one the traffic stage reports `UNAVAILABLE` with a
   reason, and protocol and security analysis remain fully usable.
4. **PDF export needs `reportlab`**, an optional dependency. HTML export needs
   nothing. The capability endpoint reports which is in play.
5. **Live capture and the strongSwan testbed are unvalidated on this machine.**
   This host is Windows; the testbed needs Linux namespaces and `CAP_NET_RAW`.
   `docs/limitations.md` gives the Linux validation procedure.

| AI classification engine | `fera.ml.train`, `inference`, `explain`, `feature_sets` | CODE VERIFIED |
| Interactive dashboard | `frontend/src/views/` — Analyze, Overview, Protocol, Traffic, Security, Threat, Evidence, History, Reports | CODE VERIFIED (build + typecheck pass) |
| Security report | `fera.reports` executive + technical, HTML and PDF | CODE VERIFIED |
| Dataset pipeline | `fera.dataset`, `scripts/build_dataset.py`, `fera.ml.train` | CODE VERIFIED |
| Technical documentation | `docs/` | CODE VERIFIED |
