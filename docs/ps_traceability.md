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

The row above is the **PS requirement** and remains the core deliverable: FERA
predicts the traffic type inside ESP. The rows below are an *additional* FERA
capability (Differentiator #2), not a substitute for it. The closed-set
classifier above still works and is what produces a class when the evidence
supports one.

| Additional capability | Implementation | Verification | Status |
|---|---|---|---|
| Calibrated confidence (vs. raw probability) | `fera.ml.calibration` — multiclass Brier, log loss, top-label ECE, reliability curve; `FrozenEstimator` keeps the base model unrefitted | functional checks; `python -m compileall`, ruff, mypy | IMPLEMENTED — REAL-DATA VALIDATION PENDING |
| Open-world KNOWN/UNKNOWN decision | `fera.ml.openworld` — confidence / margin / entropy signals, provenance-tagged thresholds | `tests/test_ml_openworld_integration.py` | IMPLEMENTED — UNIT/INTEGRATION TESTED, REAL-DATA VALIDATION PENDING |
| UNKNOWN does not become a security FAIL | `fera.security.rules` reports the metadata rule `NOT_VERIFIABLE`/INFO for a rejected sample | `tests/test_ml_openworld_integration.py::test_security_rule_reports_unknown_as_not_verifiable_not_fail` | IMPLEMENTED — INTEGRATION TESTED |
| UNKNOWN stays `INFERRED`, distinct from `NOT_VERIFIABLE` | `TrafficPrediction.decision` / `is_unknown`; documented in every payload | `tests/test_ml_openworld_integration.py::test_unknown_is_not_the_same_claim_as_not_verifiable` | IMPLEMENTED — INTEGRATION TESTED |
| Threshold provenance survives into artefacts and UI | `RejectionPolicy.source` → `model.json` → bundle → report/dashboard | `test_threshold_provenance_is_persisted_and_flagged` | IMPLEMENTED — INTEGRATION TESTED |
| Backward compatibility with pre-#2 artefacts | `policy_from_metadata` loads a model with no `open_world` block with rejection **disabled** | `test_old_artifact_without_open_world_loads_with_rejection_disabled` | IMPLEMENTED — UNIT-TESTED |
| Held-out-class (leave-one-class-out) rejection evaluation | `fera.ml.heldout.held_out_class_experiment` | `tests/test_ml_heldout.py` (9 tests) | IMPLEMENTED — INTEGRATION TESTED ON FIXTURES ONLY |
| Real open-world rejection rates / coverage | — | — | **NOT VERIFIABLE** until a real strongSwan ESP dataset exists |

A fixture run of the held-out-class experiment is explicitly stamped
`MEASURED ON SYNTHETIC FIXTURE - NOT EXPERIMENTAL EVIDENCE`. On the current
fixture it reports an unknown-rejection rate of **0.0** with full coverage: the
synthetic rows are linearly separable in a way real encrypted traffic is not, so
the model stays confident on the held-out class. That is a measurement of the
fixture, not a weakness of the mechanism, and it is reported rather than hidden.

No threshold, rejection rate, coverage figure or open-world accuracy is claimed
anywhere in this repository. Every number above is either a code-verification
statement or an explicit "pending".


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

## Static analysis and test status

| Gate | Command | Result |
| --- | --- | --- |
| Unit and integration tests | `python -m pytest tests -q` | 355 passed, 0 failed |
| Lint | `python -m ruff check .` | All checks passed |
| Type check | `python -m mypy src` | No issues in 82 source files |
| Frontend build | `npm run build` (in `frontend/`) | built, 196 kB |

`tests/test_ml_train.py` covers the two guarantees that a passing score would
otherwise hide: `ablate_feature_sets` never persists a deployable artefact, and
a feature set that cannot train is recorded as a `blocked` row rather than
aborting the comparison.

The type checker was previously not part of the reported gates. It is now, and
it is clean; the fixes it forced were real defects rather than annotation churn:
a `None` `pfs_doc` that would have raised `AttributeError` on a capture with no
PFS data, and a `partial` replacing a default-argument lambda that mypy could not
infer.
