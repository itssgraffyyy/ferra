"""Startup smoke test for FDR Sentinel.

Runs:
  1. Backend compile check (all app python files compile).
  2. Database initialization (create_all + dev seed).
  3. A quick create/read round-trip through the running API.

Usage:
    python -m scripts.smoke_test
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
BACKEND = BASE / "backend"
SCRIPTS = BASE / "scripts"

REQUIRED_PACKAGES = [
    "fastapi",
    "uvicorn",
    "sqlalchemy",
    "alembic",
    "pydantic-settings",
    "passlib[bcrypt]",
    "python-jose[cryptography]",
    "python-multipart",
    "pypdf",
    "pdfplumber",
    "Pillow",
    "python-dateutil",
    "requests",
    "pytest",
    "httpx",
]


def step_compile() -> int:
    print("[1/4] Compiling backend source files...")
    env = dict(os.environ)
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "compile_all.py")],
        cwd=str(BACKEND),
        capture_output=True,
        text=True,
        env=env,
    )
    print(result.stdout.strip())
    if result.returncode != 0:
        print("COMPILE FAILED", result.stderr)
def _ensure_dependencies() -> list[str]:
    """Install any missing runtime dependencies via pip."""
    missing = [p for p in REQUIRED_PACKAGES if not _importable(p)]
    if missing:
        print("[0/4] Installing missing runtime dependencies...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *missing],
            check=False,
        )
    return missing
    return result.returncode


def _read(url: str, timeout: float = 5.0) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return {"status": resp.status, "body": resp.read().decode("utf-8")}


def _post(url: str, payload: dict, timeout: float = 10.0) -> dict:
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return {"status": resp.status, "body": resp.read().decode("utf-8")}


def step_DB() -> int:
    from app.db.init_db import init_db

    print("[2/4] Initializing database (create_all + dev seed)...")
    try:
        init_db()
    except Exception as exc:  # noqa: BLE001
        print("DB INIT FAILED:", exc)
        return 1
    print("Database initialized and seed data loaded.")
    return 0


def step_smoke() -> int:
    print("[3/4] Starting uvicorn in background...")
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            "8123",
        ],
        cwd=str(BACKEND),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = "http://127.0.0.1:8123/api/v1"
    try:
        deadline = time.time() + 30
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                out = proc.stdout.read() if proc.stdout else ""
                print("UVICORN EXITED EARLY:\n", out)
                return 1
            try:
                body = _read(base + "/health", timeout=2)
                if body["status"] == 200:
                    ready = True
                    print("Health endpoint ready:", body["body"])
                    break
            except (urllib.error.URLError, OSError, ValueError):
                time.sleep(0.5)
        if not ready:
            print("Health endpoint did not become ready in time.")
            return 1

        # Login as the seeded admin user.
        login = _post(base + "/auth/login", {
            "email": "admin@aictedemo.example.in",
            "password": "AdminPass123!",
        })
        print("Login (admin):", login["status"])
        if login["status"] != 200:
            print("LOGIN FAILED:", login["body"])
            return 1
        csrf = login["body"].split('"csrf_token":"')[1].split('"')[0]
        session = login["body"].split('"session_token":"')[1].split('"')[0]

        # Create an institution (requires institution:write).
        inst_payload = {
            "name": "Smoke Test Institute",
            "code": "SMK" + str(int(time.time()))[-6:],
            "category": "Government",
            "address": "Test City, India",
            "contact_email": "reg@smoke.test",
            "status": "active",
        }
        req = urllib.request.Request(
            base + "/institutions",
            data=urllib.parse.urlencode(inst_payload).encode("utf-8"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-CSRF-Token": csrf,
            },
        )
        req.add_header("Cookie", f"fdr_session={session}; fdr_csrf={csrf}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            print("Create institution:", resp.status, resp.read().decode()[:200])

        # Quick list.
        with urllib.request.urlopen(base + "/institutions", timeout=10) as resp:
            print("List institutions:", resp.status)
        print("[3/4] Smoke create/read round-trip OK.")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def main() -> int:
    # Make the backend package importable for the in-process DB init step.
    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))

    _ensure_dependencies()
    rc = step_compile()
    if rc != 0:
        return rc
    rc = step_DB()
    if rc != 0:
        return rc
    rc = step_smoke()
    print("\nSMOKE TEST", "PASSED" if rc == 0 else "FAILED")
    return rc


def _importable(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


if __name__ == "__main__":
    sys.exit(main())
