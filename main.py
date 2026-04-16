from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="License Server")

# ── storage ──────────────────────────────────────────────────────────────────
DATA_FILE = Path(os.getenv("DATA_FILE", "licenses.json"))


def _load() -> Dict[str, Any]:
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save(data: Dict[str, Any]) -> None:
    DATA_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


# ── seed keys on first run ────────────────────────────────────────────────────
SEED_KEYS_ENV = os.getenv("SEED_KEYS", "")  # comma-separated, e.g. ABCD-EFGH-IJKL-MNOP,XXXX-...


def _ensure_seed_keys() -> None:
    if not SEED_KEYS_ENV:
        return
    data = _load()
    changed = False
    for key in SEED_KEYS_ENV.split(","):
        key = key.strip()
        if key and key not in data:
            data[key] = {"device_id": None, "activated_at": None, "machine_name": None, "active": True}
            changed = True
    if changed:
        _save(data)


_ensure_seed_keys()

# ── admin token ───────────────────────────────────────────────────────────────
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-me-secret")


# ── endpoints ─────────────────────────────────────────────────────────────────

@app.post("/activate")
async def activate(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"valid": False, "detail": "Invalid JSON body."}, status_code=400)

    license_key = (body.get("license_key") or "").strip()
    device_id   = (body.get("device_id") or "").strip()

    if not license_key:
        return JSONResponse({"valid": False, "detail": "License key is required."}, status_code=400)

    data = _load()

    if license_key not in data:
        return JSONResponse({"valid": False, "detail": "License key not found."}, status_code=403)

    entry = data[license_key]

    if not entry.get("active", True):
        return JSONResponse({"valid": False, "detail": "License key has been revoked."}, status_code=403)

    # Bind device on first use
    if not entry.get("device_id"):
        entry["device_id"]      = device_id
        entry["activated_at"]   = datetime.now(timezone.utc).isoformat()
        entry["machine_name"]   = body.get("machine_name", "")
        entry["os_name"]        = body.get("os_name", "")
        entry["mac_address"]    = body.get("mac_address", "")
        data[license_key] = entry
        _save(data)
        return JSONResponse({"valid": True, "message": "License activated successfully."})

    # Already bound — check same device
    if entry["device_id"] != device_id:
        return JSONResponse(
            {"valid": False, "detail": "License key is already activated on another device."},
            status_code=403,
        )

    return JSONResponse({"valid": True, "message": "License valid."})


# ── admin endpoints ────────────────────────────────────────────────────────────

def _check_admin(request: Request) -> bool:
    token = request.headers.get("X-Admin-Token", "")
    return token == ADMIN_TOKEN


@app.post("/admin/add")
async def admin_add(request: Request) -> JSONResponse:
    if not _check_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    key = (body.get("key") or "").strip()
    if not key:
        return JSONResponse({"error": "key required"}, status_code=400)
    data = _load()
    if key in data:
        return JSONResponse({"error": "Key already exists"}, status_code=409)
    data[key] = {"device_id": None, "activated_at": None, "machine_name": None, "active": True}
    _save(data)
    return JSONResponse({"ok": True, "key": key})


@app.post("/admin/revoke")
async def admin_revoke(request: Request) -> JSONResponse:
    if not _check_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    key = (body.get("key") or "").strip()
    data = _load()
    if key not in data:
        return JSONResponse({"error": "Key not found"}, status_code=404)
    data[key]["active"] = False
    _save(data)
    return JSONResponse({"ok": True})


@app.post("/admin/reset")
async def admin_reset(request: Request) -> JSONResponse:
    """Reset device binding so key can be activated on a new machine."""
    if not _check_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    key = (body.get("key") or "").strip()
    data = _load()
    if key not in data:
        return JSONResponse({"error": "Key not found"}, status_code=404)
    data[key]["device_id"]    = None
    data[key]["activated_at"] = None
    data[key]["machine_name"] = None
    _save(data)
    return JSONResponse({"ok": True})


@app.get("/admin/list")
async def admin_list(request: Request) -> JSONResponse:
    if not _check_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    data = _load()
    return JSONResponse(data)


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok"})
