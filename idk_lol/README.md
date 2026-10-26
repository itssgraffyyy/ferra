# FDR Sentinel

**FDR Sentinel (SIH26265)** — a secure Financial Deposit Receipt (FDR) compliance platform
built for the AICTE Science & Innovation Hub (SIH) project.

This repository contains the **FastAPI backend** service. It exposes a RESTful API for
managing institutions, security obligations, financial instruments, documents, OCR
extraction, reconciliation policies, compliance findings, resolution cases, and audit
trails.

---

## Stack

- **Runtime:** Python 3.11+ (3.14 used in this workspace)
- **Web framework:** FastAPI + Uvicorn
- **ORM:** SQLAlchemy 2.0 (DeclarativeBase)
- **DB migration:** Alembic
- **Auth:** JWT (session/refresh tokens via `python-jose`) + CSRF cookies
- **Validation/Serialization:** Pydantic v2 / pydantic-settings
- **Password hashing:** passlib[bcrypt]
- **Document store:** SHA-256 content-addressed local storage (extensible to S3)

---

## Project layout

```text
backend/
  app/
    api/
      deps.py              # dependency injections: DB, current user, authz
      endpoints/           # instruments, obligations, institutions, documents, OCR,
                          #   reconciliation, policy, findings, cases, audit, auth, health
      middleware/          # audit, CSRF, global error handler
    core/
      config.py            # pydantic-settings driven configuration
      exceptions.py        # domain exceptions (AuthenticationError, etc.)
      logging.py           # structured logging setup
      security.py          # password hashing, JWT/session token helpers
    crud/                  # generic CRUD + domain-specific implementations
    db/
      base.py              # Base, TimestampMixin, IdMixin
      session.py           # SQLAlchemy engine/session factory
      init_db.py           # create_all + dev data seed (SEED_DATA)
    models/                # SQLAlchemy ORM models (User, Institution, Obligation, ... OCRJob, ...)
    schemas/               # Pydantic request/response schemas
    services/              # business logic services (auth, OCR, policy, reconciliation, ...)
    main.py                # FastAPI app factory + middleware wiring
  migrations/              # Alembic version scripts
  storage/                 # uploaded documents (local content-addressed layout)
  tests/                   # smoke + behavioural tests
scripts/
  compile_all.py           # compile all app python files (syntax check)
  smoke_test.py            # full startup smoke test: deps -> compile -> DB init -> API round-trip
```

---

## Dev setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r backend/requirements.txt
cd backend
cp .env.example .env
# adjust DATABASE_URL / SEED_DATA as needed
uvicorn app.main:app --factory --reload
```

- **Database:** `sqlite:///./fdr_sentinel.db` (local dev) or a
  `postgresql+psycopg2://...` URL (production). Set via `DATABASE_URL`.
- **Seed:** with `SEED_DATA=true` (default) a fresh local instance seeds a dev admin
  user and two sample institutions/obligations/instruments.

### Auth demo credentials (seeded)

| Role | Email | Password |
|---|---|---|
| AICTE Admin | `admin@aictedemo.example.in` | `AdminPass123!` |
| Reviewing Officer | `officer@aictedemo.example.in` | `OfficerPass123!` |
| Security Audit Reviewer | `auditor@aictedemo.example.in` | `AuditorPass123!` |
| Institution User (GMEC) | `registrar@gmec.example.in` | `CollegePass123!` |

Login returns `session_token` + `csrf_token` cookies. Builder/API clients may instead use
the `Authorization: Bearer <session_token>` header.

---

## Smoke test / dev loop

```bash
# 1. Syntax check all app files
python scripts/compile_all.py

# 2. Start before/after: compile -> init db -> live API create/read round-trip
python scripts/smoke_test.py
```

`smoke_test.py` exercises: dependency installation, compile check (77+ files), database
initialisation + seed, and an authenticated create/list round-trip through the running
API (login -> CSRF -> institution creation -> list).

---

## API surface

| Area | Endpoints |
|---|---|
| Institutions | `POST/GET /api/v1/institutions` |
| Obligations | `POST/GET /api/v1/obligations` |
| Instruments | `POST/GET/PUT /api/v1/instruments` |
| Documents | `GET/POST /api/v1/documents`, `GET /api/v1/documents/{id}` (byte+metadata) |
| OCR | `POST /api/v1/documents/{id}/ocr`, `GET /api/v1/ocr-jobs/{id}` |
| Reconciliation | `GET /api/v1/reconciliations` + `GET /api/v1/policy-evaluations` |
| Policy | `GET /api/v1/policies`, `GET /api/v1/regulatory-rules` |
| Findings | `GET/POST /api/v1/findings`, `PUT /api/v1/findings/{id}/status` |
| Cases | `POST/GET /api/v1/cases`, `POST /api/v1/cases/{id}/resolve` |
| Audit | `GET /api/v1/audit-events` (actor/institution filters, pagination) |
| Auth | `POST /api/v1/auth/login`, `refresh`, `logout`, `GET /auth/me`, `GET /auth/csrf-token` |
| Health | `GET /api/v1/health` |

Protected endpoints require `require_permission(...)`; institution-scoped resources require
`require_institution_access(...)`.

---

## Migrations

```bash
cd backend
alembic revision --autogenerate -m "describe"
alembic upgrade head
```

`migrations/env.py` reads `DATABASE_URL` from the application settings so it matches the
running app (SQLite is the default local target; `render_as_batch=True` keeps SQLite
migrations production-safe).

---

## Notes / guards

- The OCR engine is **simulated** by default (`OCR_ENGINE=simulated`) — synthetic output,
  never presented as real OCR. Set `tesseract`/`paddleocr` for production OCR.
- Document uploads are content-addressed by SHA-256 and never served raw without a
  metadata lookup scoped to instrument access.
- Secrets live in `.env` (gitignored). Always override the `dev-*` defaults in production.
