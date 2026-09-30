# User Guide

How to run FERA as a product: upload a capture, read the result, use the
history, get reports, and capture live traffic.

For a scripted walkthrough see `docs/demo_guide.md`. For what the system can and
cannot conclude, see `docs/limitations.md`.

---

## Concepts you need first

**One pipeline, one result.** Everything FERA shows you — dashboard, reports,
history, exports — comes from the same *canonical analysis bundle*. Nothing is
recomputed for display. If the dashboard says a finding is `NOT_VERIFIABLE`,
the report says the same, because it is literally the same value.

**Evidence grades.** FERA does not flatten every result into an equally certain
statement. Each conclusion carries a grade:

| Grade | Meaning |
|-------|---------|
| `OBSERVED` | Read directly from the bytes on the wire. |
| `CONFIGURED` | Taken from the testbed's own configuration — an assertion of intent, not a measurement of the running tunnel. |
| `INFERRED` | Derived, e.g. a classifier's guess from traffic statistics. |
| `NOT_VERIFIABLE` | A passive capture cannot decide this. **Not** a failure and **not** a pass. |

`NOT_VERIFIABLE` lowers *evidence coverage* rather than the security score. An
unknown is never silently counted as a weakness, and never as a strength.

**Analysis state.** `COMPLETE` (everything ran), `PARTIAL` (core analysis
succeeded, an optional or environment-dependent stage did not), or `FAILED` (no
meaningful result could be produced).

---

## Installation

```bash
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt     # pytest / ruff / mypy
```

For the product API:

```bash
python -m pip install fastapi uvicorn python-multipart
```

Optional:

| Package | Enables | Without it |
|---------|---------|------------|
| `scikit-learn`, `joblib` | training and ML inference | traffic stage reports `UNAVAILABLE` with a reason; everything else works |
| `reportlab` | PDF export | HTML export works; the capability endpoint says so |
| `tshark` | external dissection cross-check | FERA's own decoder is used |

## Running the backend

```bash
python -m uvicorn fera.api.main:app --port 8000
```

or `python -m fera.api.main`.

## Running the dashboard

```bash
cd frontend
npm install
npm run dev      # development
npm run build    # production bundle into frontend/dist
```

The dashboard talks to the local API and nothing else. There is no cloud
service, no telemetry, and no external call in the analysis path.

---

## Analysing a capture

**Upload.** Use the Analyze view, or:

```bash
curl -F "file=@capture.pcap" http://localhost:8000/analyze
```

Accepted: `.pcap` and `.pcapng`. Limits and rejections are explicit —
too large is `413`, wrong type `415`, unreadable content a structured failure.
The uploaded filename is displayed but never used as a filesystem path.

**Live capture** (Linux, `tcpdump`/`dumpcap`, `CAP_NET_RAW`):

```bash

## Reading the result

The dashboard has nine views. What each is for:

| View | Use it to |
|------|-----------|
| Analyze | Start an analysis; see the state (`READY`/`UPLOADING`/`ANALYZING`/`COMPLETE`/`PARTIAL`/`FAILED`) |
| Overview | The one-page posture |
| Protocol | IKE/ESP detail: exchanges, proposals, SAs, SPIs, selectors, statistics |
| Traffic | ML prediction, confidence, probabilities, model identity |
| Security | Score, risk band, category scores, findings |
| Threat Matrix | The backend's threat matrix |
| Evidence | Every conclusion with its evidence grade |
| History | Previous analyses, reopened without re-running |
| Reports | Download executive / technical / JSON |

Nothing is hidden behind a generic error. If traffic classification is
unavailable, Traffic Intelligence says so and gives the reason.

## Training a model

FERA ships the trainer, **not** a model. Until you train one, the traffic stage
is honestly unavailable.

```bash
python scripts/build_dataset.py          # labelled dataset, grouped splits
python scripts/train_model.py             # train + persist to data/models/<model_id>
python scripts/train_model.py --json      # the full training report
python scripts/train_model.py --ablate    # feature-set ablation (persists nothing)
```

The product API discovers whatever is in `data/models/`. No restart step is
needed beyond the API's normal model discovery.

The training report states the selected candidate, the held-out test metrics,
and a `performance_status`. If a run could not be measured, the report says so
rather than implying a verified number.

## History

Every analysis is stored in a local SQLite database (`data/fera.db`). The
canonical bundle stays authoritative; the database holds summary columns for
listing and filtering only.

```bash
curl "http://localhost:8000/analyses?limit=20"
curl "http://localhost:8000/analyses?source_mode=upload&risk_band=high"
curl http://localhost:8000/analyses/<id>        # the stored bundle
curl -X DELETE http://localhost:8000/analyses/<id>
```

Newest first. Reopening an analysis does **not** re-run it.

## Reports and exports

```bash
curl "http://localhost:8000/analyses/<id>/report?type=executive&format=html"
curl "http://localhost:8000/analyses/<id>/report?type=technical&format=html"
curl "http://localhost:8000/analyses/<id>/report?type=json&format=html"
curl "http://localhost:8000/analyses/<id>/report?type=executive&format=pdf"
curl -o bundle.json "http://localhost:8000/analyses/<id>/export"
```

Filenames are generated by the server (`fera_<analysis-id>_executive.pdf`, …),
so a download cannot be steered into a path.

## API reference

| Route | Purpose |
|-------|---------|
| `GET /health` | process liveness — and what it can do here |
| `GET /version` | running version and schema identifiers |
| `GET /capabilities` | what this installation can actually do, and why not |
| `GET /models/status` | classifier identity and verification status |
| `POST /analyze` | upload a capture, get the canonical bundle |
| `POST /live/analyze` | bounded live capture through the same pipeline |
| `GET /analyses` | history summaries, filterable |
| `GET /analyses/{id}` | the stored canonical bundle |
| `DELETE /analyses/{id}` | remove a stored analysis |
| `GET /analyses/{id}/export` | canonical bundle as JSON |
| `GET /analyses/{id}/report` | executive / technical / JSON report |

Errors use FERA's structured error codes: `404` not found, `413` too large,
`415` unsupported type, `422` invalid input, `500` unexpected failure. A stage
that could not run is *not* an HTTP 500 — it is a `PARTIAL` result carrying the
reason.

## Offline operation

After local dependencies are installed, the whole analysis path is offline:
protocol parsing, feature extraction, ML inference, security assessment, privacy
analysis, persistence, the API, the dashboard, and reports. Nothing phones home.
The only network access is the API↔dashboard hop on localhost, plus whichever
system packages you install.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Traffic stage `UNAVAILABLE` | no model in `data/models/` | train one (`scripts/train_model.py`) |
| `live_capture: unavailable` | no `tcpdump`/`dumpcap`, or no privileges | install and grant `CAP_NET_RAW`; Linux only |
| PDF download fails | `reportlab` missing | `pip install reportlab`, or use HTML |
| `415` on upload | not a PCAP/PCAPNG | check the file — magic bytes are validated |
| `413` on upload | over the size limit | split or shorten the capture |
| Dashboard shows no data | API not running | start `uvicorn fera.api.main:app` |

curl -X POST http://localhost:8000/live/analyze \
  -H 'content-type: application/json' \
  -d '{"interface": "eth0", "duration_s": 10}'
```

Bounded (default 10s, max 60s), and the result goes through **the same**
analysis pipeline as an upload. On a host without a capture tool you get a
clear environment blocker, never a fabricated result.
