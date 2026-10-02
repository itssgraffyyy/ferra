# Encrypted Traffic Privacy Intelligence (Part 3)

> **Status: IMPLEMENTED — SIMULATED COUNTERMEASURE — REAL-DATA VALIDATION PENDING.**
> The experiment loop runs end-to-end and is tested. Every number it currently
> produces comes from synthetic fixtures. No privacy improvement, latency or
> throughput figure is claimed anywhere.

## 1. The differentiator

The problem statement already requires predicting traffic type inside ESP. That
is **not** the differentiator. The differentiator is the closed loop:

```
DETECT -> EXPLAIN -> MEASURE -> MITIGATE -> RE-ATTACK -> VERIFY -> COMPARE
```

A system that only classifies traffic has found a leak and stopped. Closing the
loop means applying a mitigation, re-attacking it, and reporting what the
attacker recovers.

## 2. Threat model

The observer is **passive and off-path**: they see the outer IP headers, the
SPI values, and the sizes and timings of the ESP packets. They cannot decrypt.
Encryption hides payload *content*; it never hid metadata *structure*.

FERA models exactly that observer. Features come from encrypted-side metadata
only — packet counts, sizes, inter-arrival times, direction shares, sequence
behaviour. Nothing here decrypts ESP, and nothing here claims to.

The attacker modelled is a supervised classifier trained on such metadata, which
is the standard published threat model for encrypted-traffic analysis.

## 3. Feature families

Part 1's families are reused, not re-invented (`fera.ml.train.FAMILY_FEATURES`):

| Family | Columns |
|---|---|
| `size` | `avg_packet_len`, `esp_avg_len`, `esp_len_min`, `esp_len_max`, `esp_len_std` |
| `timing` | `esp_iat_mean_s`, `esp_iat_std_s`, `esp_iat_max_s`, `esp_span_s` |
| `direction` | forward/reverse packet and byte counts and shares |
| `combined` | the whole approved whitelist (reference row) |

A statement the analysis supports: *"on this measured dataset, inference relied
substantially on size-related observables."*

A statement it does **not** support: *"packet size is always the reason
encrypted traffic leaks."* Conclusions stay dataset-specific.

## 4. Countermeasure interface

`PrivacyCountermeasure` (ABC) exposes `apply()`, `describe()`, `overhead()` and
`provenance()`. The privacy pipeline talks only to this interface, so a real TFC
implementation, a dummy-traffic generator or a timing shaper can be added as a
subclass later without restructuring the experiment.

## 5. Simulated size normalisation

`SizeNormalizationCountermeasure` pads the `size` feature columns:

- `mode='bucket'` rounds each length up to the next multiple of `bucket_size`;
- `mode='fixed'` pads every packet up to `target_size`;
- packets at or above `max_pad_size` are transmitted **unchanged** — padding
  must never shrink a datagram, and a "constant size" that silently exempts
  large packets would be a lie.

Only size columns are rewritten. Labels, split keys, split assignments and group
identity are copied verbatim, and each mitigated row is stamped with the
countermeasure's provenance so it can never be mistaken for a captured one.

**What is simulated:** an endpoint padding outbound packets so their lengths
reveal less about the inner traffic.

**What is not:** RFC 4303 Traffic Flow Confidentiality (this is *not* TFC), a real
implementation's padding-boundary behaviour, dummy traffic, and any timing or
direction effect. `describe()` states all of this in the document itself.

## 6. Countermeasure provenance

| State | Meaning |
|---|---|
| `SIMULATED_COUNTERMEASURE` | applied in software to already-captured data |
| `CONFIGURED_NOT_VERIFIED` | declared by a testbed config, no capture demonstrates it |
| `TESTBED_VERIFIED_COUNTERMEASURE` | applied in a real testbed and observed on the wire |

Two machine-checkable guards:

1. `CountermeasureProvenance(state=TESTBED_VERIFIED)` **raises** without an
   evidence capture;
2. `assert_provenance_permits_claims()` raises when a caller asks to claim
   experimental evidence from a non-verified provenance.

The Windows host cannot satisfy (1), and no amount of fixture execution changes
that. `run_privacy_experiment` also refuses `status=EXPERIMENTAL_EVIDENCE`
together with `claiming_experimental=True` on a simulated mechanism.
## 7. Attacker A — frozen

Trained and selected on **baseline** traffic, then evaluated unchanged against
mitigated traffic. The mitigated rows never reach its fitting, selection or
calibration. It measures how much the mitigation disrupts an attacker that has
not seen it.

## 8. Attacker B — adaptive

Retrained and reselected on **mitigated** traffic, then evaluated once on the
held-out mitigated split. Grouping and the Part 1 train/validation/test contract
are preserved; Part 1's leakage guards apply unchanged.

A mitigation that defeats A but not B **has been adapted to**. Reporting only A
would overstate the result, which is why both are always emitted.

## 9. Privacy vs. cost

Reported: baseline / Attacker A / Attacker B macro F1 and deltas, coverage, and
byte overhead (original bytes, transformed bytes, absolute and percentage).

Reported as `NOT_MEASURED`: **latency, throughput, jitter**. Byte overhead is
computable from the transformation; a latency or throughput cost is not, and
inferring one from a byte count would be fabricating a measurement.

## 10. Calibration and UNKNOWN

Part 1/2 behaviour is preserved rather than bypassed: the experiment records
each attacker's calibration state and open-world policy state. Because the
comparison is closed-set, `unknown_rejection_rate` is `null` rather than a
fabricated zero.

An increase in UNKNOWN after mitigation is an observed classifier behaviour. It
is **not** a privacy guarantee, and UNKNOWN is never read as proof of it.

## 11. Honest status

The run status is `SIMULATED - NOT REAL-DATA EVIDENCE`, and the limitations block
says so in words. No document produced on the current host can claim
`EXPERIMENTAL_EVIDENCE`, and attempting to is an error.

## 12. What is *not* claimed

- that FERA defeats traffic analysis;
- that FERA proves anonymity;
- that TFC eliminates metadata leakage;
- that padding prevents traffic classification;
- any X% privacy improvement;
- any latency or throughput figure.

## 13. Commands

```bash
python scripts/privacy_experiment.py --dataset data/processed/ml
python scripts/privacy_experiment.py --dataset data/processed/ml --mode fixed --target-size 1400
python scripts/privacy_experiment.py --dataset data/processed/ml --json --output data/privacy.json
```

## 14. Real-data validation plan

Once a Linux host with working XFRM exists:

1. capture baseline real ESP traffic across the experiment matrix;
2. build the baseline dataset;
3. train the baseline attacker;
4. apply a **real** countermeasure in the testbed (strongSwan-level), capture again;
5. re-run Attacker A against the real mitigated capture;
6. re-run Attacker B on the real mitigated dataset;
7. compare, and only then set provenance to `TESTBED_VERIFIED_COUNTERMEASURE`
   with the capture path and hash recorded.

Steps 4-6 cannot be simulated. Until they happen, every Part 3 number is a
methodology check, not a finding.