# Open-World Traffic Intelligence (Differentiator #2)

> **Status: IMPLEMENTED — REAL-DATA VALIDATION PENDING.**
> Every mechanism below is unit/integration tested. No rejection rate, coverage
> figure, calibration result or accuracy is claimed, because the real strongSwan
> ESP dataset these would be measured on does not exist yet. See
> [What is still pending](#10-what-is-still-pending).

## 1. The problem

A closed-set classifier answers "which known class is this?" — but that question
has an answer even when the evidence supports none. A flow from an application
FERA has never seen still gets stamped `web` with whatever probability the argmax
happened to produce, and everything downstream reads that as a finding.

FERA additionally answers a second question: *does the evidence justify assigning
any known class at all?* A flow may come back `UNKNOWN`.

This is **additional** to the core problem statement. Predicting the traffic type
inside ESP remains the requirement; open-world rejection is what FERA does when
that prediction is not supported.

## 2. What UNKNOWN means — and what it does not

`UNKNOWN` means: **FERA did not find sufficient support for a known traffic
class.**

It does **not** mean:

- the traffic is malicious, an attack, or an anomaly;
- FERA has identified a novel application;
- the traffic is unidentifiable forever;
- the traffic is private, or protected;
- any protocol or security fact is undetermined.

The last point is the important distinction. `NOT_VERIFIABLE` is a different
claim: it says FERA *cannot determine* a protocol/security fact from the available
evidence. `UNKNOWN` is an **inference about traffic class** — it is `INFERRED`,
exactly like a known-class prediction. The two are never substituted for one
another in any payload, and `UNKNOWN` never becomes a security `FAIL`.

## 3. Raw probability vs. calibrated confidence

A classifier's `predict_proba` output is **not** a calibrated confidence. A model
can be right 90% of the time while its 0.9 predictions are only 70% correct.
FERA never presents a raw softmax score as "87% sure" without saying whether it
was checked.

`fera.ml.calibration` fits a probability map with
`CalibratedClassifierCV(FrozenEstimator(...))`. The base estimator is **frozen**:
calibration refits the probability map only, so the model that won selection on
validation stays the model that ships, and calibration cannot silently re-open
model selection on held-back data.

Calibration is fitted on the **validation** split only, and
`assert_partition_disjoint` makes "calibration never saw a test group" a
machine-checked invariant rather than a convention.

Metrics reported (definitions are written *into* the payload so they cannot be
misread as their binary or one-vs-rest namesakes):

| Metric | Definition |
|---|---|
| Brier score | **multiclass**: mean over rows of sum_k (p_k - y_k)^2, range [0, 2] |
| Log loss | **multiclass**: mean of -ln p(true class) |
| ECE | **top-label**: sample-weighted abs(mean confidence - accuracy) per confidence bin |
| Reliability curve | **top-label**: argmax confidence vs. whether the argmax was correct |

`isotonic` is supported but demands >=100 calibration rows; `sigmoid` (Platt) is
the default at >=20. Asking for isotonic without the data is an error, not a
silently overfitted curve.

## 4. Rejection signals

Three independent signals, deliberately **not** fused into one opaque score:

| Signal | Rejects when | Notes |
|---|---|---|
| `confidence` | calibrated top-class probability < threshold | default, always on |
| `margin` | top-1 minus top-2 < threshold | opt-in (`use_margin`) |
| `entropy` | predictive entropy > threshold (bits) | opt-in (`use_entropy`) |

Default rule: `reject if confidence < T_conf`. A transparent rule an operator can
read off one line is worth more than a tuned combination nobody can predict.

Rejection reasons are stable string constants (`LOW_CALIBRATED_CONFIDENCE`,
`LOW_TOP1_TOP2_MARGIN`, `HIGH_PREDICTIVE_ENTROPY`, `OPEN_WORLD_DISABLED`)
because a report, a dashboard and a test all quote the same token.

## 5. Threshold provenance

Every policy carries a `source`:

| Source | Meaning |
|---|---|
| `VALIDATION-DERIVED` | fitted on a validation partition |
| `UNCALIBRATED_DEFAULT` | a placeholder; not an operating point |
| `NOT_SET` | rejection disabled |

`RejectionPolicy.experimental` is true unless the thresholds were **both**
validation-derived **and** calibrated. An unfitted operating point can never read
as validated. The dashboard prints `CALIBRATED` / `UNCALIBRATED` and the reports
## 6. End-to-end flow

```
PCAP / LIVE
  -> deterministic analysis
  -> ESP features
  -> trained classifier
  -> calibrated probabilities        (fera.ml.calibration)
  -> rejection policy                (fera.ml.openworld)
  -> KNOWN or UNKNOWN
  -> security assessment             (UNKNOWN -> NOT_VERIFIABLE/INFO, never FAIL)
  -> canonical bundle
  -> API / dashboard / reports
```

The decision is made **once**, in `TrafficModel.predict`. The frontend reads
`decision` from the bundle; it never re-derives UNKNOWN from a confidence value,
because a UI threshold would silently disagree with the model's own policy the
first time either changed.

On rejection the probability table is preserved: the closest known class, its
calibrated probability and the ranked alternatives all survive, because "FERA was
not sure, and here is what it was choosing between" is far more useful than a
bare `UNKNOWN`.

**Backward compatibility:** an artefact written before Differentiator #2 has no
`open_world` block and loads with rejection **disabled** — no thresholds are
invented for it.

## 7. Evaluation

Two evaluations exist, and both are stamped with their provenance.

### 7.1 Held-out class (leave-one-class-out)

`fera.ml.heldout.held_out_class_experiment` answers: *if a traffic class were
absent from training, would FERA still assign it a known class?*

1. every row of the held-out class is removed before anything else happens;
2. training, candidate selection and calibration use only the remaining classes;
3. the rejection threshold is swept on the validation split's **known** rows — the
   unknown pool is never consulted;
4. only once the estimator, calibration and policy are frozen is the held-out
   class applied.

The returned document proves the isolation: `held_out_class_in_model_classes:
False`, `overlapping_groups: []`, and every sweep row carries `unknown_rows: 0`.

Closed-set metrics are computed over **accepted** rows only. Scoring a rejected
row as a wrong prediction would silently make the open-world filter look worse
than it is.

Structural invalidity (`reasons`) is kept separate from caveats (`limitations`).
An earlier version appended "calibration data too small" to `reasons`, which
flipped an otherwise sound measurement to `NOT MEASURABLE` — a fixture's small
validation split silently invalidated the whole experiment.

### 7.2 Held-out configuration

`fera.ml.heldout.evaluate_held_out_configurations` asks a different question:
does the classifier generalise to an IPsec configuration it never encountered?
A model that scores well on a same-configuration split but badly here has learned
the configuration, not the traffic.

Configuration identity comes from trusted experiment metadata and is used **only**
to partition the evaluation — it is never appended to a feature row.

### 7.3 Metrics

| Metric | Meaning |
|---|---|
| `known_acceptance_rate` | fraction of known rows not rejected |
| `known_false_rejection_rate` | 1 minus `known_acceptance_rate` |
| `known_accuracy_when_accepted` | accuracy over accepted known rows |
| `unknown_rejection_rate` | fraction of held-out unknown rows rejected |
| `coverage` | fraction of **all** rows accepted |

Without unknown validation data the unknown metrics report `None` and the status
reads `UNVERIFIED - UNKNOWN VALIDATION DATA REQUIRED`, rather than a fabricated
0.0 or 1.0.

## 8. Honest fixture result

Run on the current synthetic fixture, the held-out class is **not rejected**:

| Metric | Value |
|---|---|
| unknown rejection rate | **0.0** |
| coverage | 1.0 |
| known false-rejection rate | 0.0 |

The synthetic rows are linearly separable in a way real encrypted traffic is not,
so the model stays confident on the unseen class. This is a measurement of the
fixture, not of the mechanism. It is reported rather than hidden, and every
fixture run is stamped `MEASURED ON SYNTHETIC FIXTURE - NOT EXPERIMENTAL EVIDENCE`.

## 9. Limitations

- `UNKNOWN` does **not** prove a novel application identity.
- Known traffic can be **falsely rejected**; that is the cost of the filter.
- Unknown traffic can be **falsely accepted**; that is the limit of the filter.
- Rejection quality depends entirely on training diversity and on the network
  conditions present in the data.
- A threshold is only as good as the validation data behind it; with no such data
  the default is a placeholder and says so.
- Nothing here decrypts ESP. Traffic inference uses encrypted-flow metadata only.

## 10. What is still pending

Every item below is blocked **only** on real strongSwan ESP captures, which
require a Linux host with working XFRM. `docs/limitations.md` records why this
development machine cannot provide one.

- real held-out-class rejection rate, coverage and false-rejection rate;
- a fitted, validation-derived threshold (the default is a placeholder);
- a real calibration curve and before/after Brier, log-loss and ECE;
- real held-out-configuration generalisation;
- any accuracy figure of any kind.

## 11. Commands

```bash
python scripts/train_model.py --held-out-class voip_like
python scripts/train_model.py --held-out-config --held-out-configs <ids>
python scripts/train_model.py --feature-families
python scripts/train_model.py --calibration-method sigmoid
python scripts/train_model.py --open-world-threshold 0.6
```

`--held-out-config` requires the experiment manifest beside the dataset and
refuses to run without it: a fabricated configuration grouping would silently
invalidate the result it claims to measure.
print the threshold's provenance.

Threshold selection uses `threshold_sweep`, which takes **known-class data
only** — tuning against held-out unknowns would leak the very partition the
open-world experiment later measures.