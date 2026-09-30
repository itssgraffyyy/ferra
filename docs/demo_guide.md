# Demo Guide

A short, reproducible walkthrough of the FERA product. Everything below runs
locally and offline once dependencies are installed.

Live capture (step 4b) needs Linux and privileges — see the note at the end.
Everything else works on any platform.

---

## 1. Start the backend

```bash
python -m pip install -r requirements.txt
python -m pip install fastapi uvicorn python-multipart   # product API
python -m uvicorn fera.api.main:app --port 8000
```

Check it is alive and honest about its environment:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/capabilities
```

`/capabilities` is the interesting one: it tells you which optional pieces are
actually present — tshark, a trained model, a capture tool, PDF support. If
something is missing it says so with a reason instead of pretending.

## 2. Start the frontend

```bash
cd frontend
npm install
npm run dev
```

Open the printed URL (default <http://localhost:5173>). It talks to the local
API and nothing else.

## 3. Upload a capture

On the **Analyze** view, choose a `.pcap` / `.pcapng` file and start the
analysis. The state label moves `READY → UPLOADING → ANALYZING → COMPLETE`
(or `PARTIAL`, or `FAILED`). FERA does not show a fake progress bar: if the
backend does not report progress, the UI says so rather than animating a
guess.

You can also do it headlessly:

```bash
curl -F "file=@capture.pcap" http://localhost:8000/analyze
```

## 4. Work through the views

1. **Overview** — the one-page posture: IPsec detected, IKE version, mode,
   encryption, integrity, DH, PFS, predicted traffic, security score, risk
   band, privacy exposure, evidence coverage.
2. **Protocol Analysis** — exchanges, proposals, IKE SA, CHILD SA, SPIs,
   traffic selectors, SA events, observable lifetime, PFS, packet/flow
   statistics.
3. **Traffic Intelligence** — predicted class, confidence, the full probability
   distribution, model id/version, feature schema. The evidence badge reads
   `INFERRED`: a classifier is inferring from statistics, not observing.
4. **Security Assessment** — overall score, risk band, per-category scores, and
   the findings list.
5. **Threat Matrix** — the backend's threat matrix, rendered as-is.
6. **Evidence / Findings** — every conclusion with its grade:
   `OBSERVED`, `CONFIGURED`, `INFERRED`, `NOT_VERIFIABLE`.
7. **History** — the analyses you have run, from real SQLite.
8. **Reports** — download executive, technical, or raw JSON.

## 5. Read the evidence grades honestly

This is the part worth demonstrating. Suppose the capture is ESP-only:

- PFS shows **NOT VERIFIABLE** — the capture does not contain what would be
  needed to decide it. That is not a failure, and it is not a pass.
- The traffic class shows **INFERRED**, with a confidence number that is
  deliberately kept separate from security severity.
- The overall state shows **PARTIAL**, because core analysis succeeded but an
  optional stage was unavailable.

A capture that cannot be parsed at all shows **FAILED** with a structured
error — not a stack trace.

## 6. Generate the reports

From the **Reports** view, or directly:

```bash
curl "http://localhost:8000/analyses/<id>/report?type=executive&format=html"
curl "http://localhost:8000/analyses/<id>/report?type=technical&format=html"
curl "http://localhost:8000/analyses/<id>/report?type=json&format=html"
curl -O "http://localhost:8000/analyses/<id>/report?type=executive&format=pdf"
curl -o bundle.json "http://localhost:8000/analyses/<id>/export"
```

PDF requires the optional `reportlab` package. Without it the API still serves
HTML and says why PDF is unavailable.

Reports are rendered from the stored bundle. Nothing is re-analysed, so a
report cannot claim evidence the analysis does not have.

## 7. Reopen from history

Restart the backend, then:

```bash
curl http://localhost:8000/analyses
curl http://localhost:8000/analyses/<id>
```

The stored bundle comes back intact and the analysis is **not** re-run. The
History view does the same when you click a row.

## 8. Optional: live capture

On Linux, with `tcpdump` or `dumpcap` installed and `CAP_NET_RAW`:

```bash
curl -X POST http://localhost:8000/live/analyze \
  -H 'content-type: application/json' \
  -d '{"interface": "eth0", "duration_s": 10}'
```

Bounded to a short window (default 10s, max 60s). The capture is written to a
temporary file and then goes through **the same** orchestrator as an upload.

On a host without a capture tool the endpoint returns a clear environment
blocker, and `/capabilities` reports `live_capture: unavailable` up front. It
does not fabricate a result.

---

## A good demo narrative

1. Upload a strong AES-GCM tunnel capture → high score, low risk band.
2. Upload a legacy capture → the same pipeline produces traceable findings and
   recommendations against it. No score is hard-coded.
3. Upload an ESP-only capture → show `NOT VERIFIABLE` on PFS and lifetime, and
   explain that this is the correct answer, not a bug.
4. Point at `data/models/` being empty → Traffic Intelligence says
   `UNAVAILABLE: no compatible trained model`, and nothing else degrades.
5. Train a model (`scripts/train_model.py`), restart, re-upload → the traffic
   stage now fills in, still marked `INFERRED`.
