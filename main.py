from __future__ import annotations

import json
import os
import secrets
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="License Server")

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


SEED_KEYS_ENV = os.getenv("SEED_KEYS", "")


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

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-me-secret")


def _gen_key() -> str:
    alphabet = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4)]
    return "-".join(parts)


# ── activation endpoint ───────────────────────────────────────────────────────

@app.post("/activate")
async def activate(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"valid": False, "detail": "Invalid JSON body."}, status_code=400)

    license_key = (body.get("license_key") or "").strip()
    device_id = (body.get("device_id") or "").strip()

    if not license_key:
        return JSONResponse({"valid": False, "detail": "License key is required."}, status_code=400)

    data = _load()

    if license_key not in data:
        return JSONResponse({"valid": False, "detail": "License key not found."}, status_code=403)

    entry = data[license_key]

    if not entry.get("active", True):
        return JSONResponse({"valid": False, "detail": "License key has been revoked."}, status_code=403)

    # Check expiration
    expires_at = entry.get("expires_at")
    if expires_at:
        try:
            exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                return JSONResponse(
                    {"valid": False, "detail": f"License key expired on {exp.strftime('%Y-%m-%d')}."},
                    status_code=403,
                )
        except Exception:
            pass

    if not entry.get("device_id"):
        entry["device_id"] = device_id
        entry["activated_at"] = datetime.now(timezone.utc).isoformat()
        entry["machine_name"] = body.get("machine_name", "")
        entry["os_name"] = body.get("os_name", "")
        entry["mac_address"] = body.get("mac_address", "")
        data[license_key] = entry
        _save(data)
        return JSONResponse({"valid": True, "message": "License activated successfully."})

    if entry["device_id"] != device_id:
        return JSONResponse(
            {"valid": False, "detail": "License key is already activated on another device."},
            status_code=403,
        )

    return JSONResponse({"valid": True, "message": "License valid."})


# ── admin JSON API ────────────────────────────────────────────────────────────

def _check_admin(request: Request) -> bool:
    token = request.headers.get("X-Admin-Token", "") or request.query_params.get("token", "")
    return token == ADMIN_TOKEN


@app.post("/admin/add")
async def admin_add(request: Request) -> JSONResponse:
    if not _check_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    key = (body.get("key") or "").strip() or _gen_key()
    expires_at = (body.get("expires_at") or "").strip() or None
    data = _load()
    if key in data:
        return JSONResponse({"error": "Key already exists"}, status_code=409)
    data[key] = {
        "device_id": None,
        "activated_at": None,
        "machine_name": None,
        "active": True,
        "expires_at": expires_at,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save(data)
    return JSONResponse({"ok": True, "key": key})


@app.post("/admin/set_expiry")
async def admin_set_expiry(request: Request) -> JSONResponse:
    if not _check_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    key = (body.get("key") or "").strip()
    expires_at = (body.get("expires_at") or "").strip() or None
    data = _load()
    if key not in data:
        return JSONResponse({"error": "Key not found"}, status_code=404)
    data[key]["expires_at"] = expires_at
    _save(data)
    return JSONResponse({"ok": True})


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


@app.post("/admin/enable")
async def admin_enable(request: Request) -> JSONResponse:
    if not _check_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    key = (body.get("key") or "").strip()
    data = _load()
    if key not in data:
        return JSONResponse({"error": "Key not found"}, status_code=404)
    data[key]["active"] = True
    _save(data)
    return JSONResponse({"ok": True})


@app.post("/admin/reset")
async def admin_reset(request: Request) -> JSONResponse:
    if not _check_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    key = (body.get("key") or "").strip()
    data = _load()
    if key not in data:
        return JSONResponse({"error": "Key not found"}, status_code=404)
    data[key]["device_id"] = None
    data[key]["activated_at"] = None
    data[key]["machine_name"] = None
    _save(data)
    return JSONResponse({"ok": True})


@app.post("/admin/delete")
async def admin_delete(request: Request) -> JSONResponse:
    if not _check_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    key = (body.get("key") or "").strip()
    data = _load()
    if key not in data:
        return JSONResponse({"error": "Key not found"}, status_code=404)
    del data[key]
    _save(data)
    return JSONResponse({"ok": True})


@app.get("/admin/list")
async def admin_list(request: Request) -> JSONResponse:
    if not _check_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return JSONResponse(_load())


# ── admin web dashboard ───────────────────────────────────────────────────────

ADMIN_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>License Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 24px; background: #0f172a; color: #e2e8f0; }
  h1 { margin: 0 0 20px; font-size: 22px; }
  .card { background: #1e293b; border-radius: 10px; padding: 20px; margin-bottom: 20px; border: 1px solid #334155; }
  label { display: block; margin-bottom: 6px; color: #94a3b8; font-size: 13px; }
  input[type=text], input[type=password] { width: 100%; padding: 10px; background: #0f172a; border: 1px solid #334155; color: #e2e8f0; border-radius: 6px; font-family: monospace; font-size: 14px; }
  input:focus { outline: none; border-color: #3b82f6; }
  button { padding: 8px 14px; background: #3b82f6; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: 500; font-size: 13px; margin-right: 6px; }
  button:hover { background: #2563eb; }
  button.danger { background: #dc2626; }
  button.danger:hover { background: #b91c1c; }
  button.ghost { background: #475569; }
  button.ghost:hover { background: #334155; }
  button.success { background: #16a34a; }
  button.success:hover { background: #15803d; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #334155; font-size: 13px; }
  th { color: #94a3b8; font-weight: 500; }
  td.key { font-family: monospace; font-weight: 600; color: #60a5fa; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 500; }
  .badge.active { background: #16a34a; color: white; }
  .badge.revoked { background: #dc2626; color: white; }
  .badge.unused { background: #475569; color: white; }
  .badge.bound { background: #f59e0b; color: white; }
  .row { display: flex; gap: 10px; align-items: end; flex-wrap: wrap; }
  .row > div { flex: 1; min-width: 200px; }
  .hint { color: #94a3b8; font-size: 12px; margin-top: 6px; }
  .login { max-width: 400px; margin: 80px auto; }
  .toast { position: fixed; top: 20px; right: 20px; padding: 12px 18px; border-radius: 6px; background: #16a34a; color: white; z-index: 1000; display: none; }
  .toast.error { background: #dc2626; }
  .empty { text-align: center; padding: 40px 20px; color: #94a3b8; }
  .stats { display: flex; gap: 20px; margin-bottom: 16px; }
  .stat { background: #0f172a; padding: 12px 16px; border-radius: 8px; border: 1px solid #334155; }
  .stat .num { font-size: 22px; font-weight: 600; }
  .stat .lbl { color: #94a3b8; font-size: 12px; }
</style>
</head>
<body>

<div id="login" class="login" style="display:none">
  <div class="card">
    <h1>License Admin</h1>
    <label>Admin Token</label>
    <input type="password" id="token" placeholder="Enter admin token" onkeypress="if(event.key==='Enter') doLogin()">
    <div class="hint">Set this via ADMIN_TOKEN env variable on your server</div>
    <br>
    <button onclick="doLogin()">Login</button>
  </div>
</div>

<div id="panel" style="display:none">
  <h1>License Admin Dashboard</h1>

  <div class="stats">
    <div class="stat"><div class="num" id="s-total">0</div><div class="lbl">Total Keys</div></div>
    <div class="stat"><div class="num" id="s-active">0</div><div class="lbl">Active</div></div>
    <div class="stat"><div class="num" id="s-bound">0</div><div class="lbl">In Use</div></div>
    <div class="stat"><div class="num" id="s-revoked">0</div><div class="lbl">Revoked</div></div>
  </div>

  <div class="card">
    <div class="row">
      <div>
        <label>License key</label>
        <input type="text" id="newKey" placeholder="Leave blank to auto-generate, or enter XXXX-XXXX-XXXX-XXXX">
      </div>
      <div style="flex:0 0 180px">
        <label>Expires on (optional)</label>
        <input type="date" id="expDate">
      </div>
      <div style="flex:0 0 auto">
        <label>&nbsp;</label>
        <select id="expPreset" onchange="applyPreset()">
          <option value="">Or pick preset...</option>
          <option value="7">7 days</option>
          <option value="30">30 days</option>
          <option value="90">3 months</option>
          <option value="180">6 months</option>
          <option value="365">1 year</option>
          <option value="lifetime">Lifetime (no expiry)</option>
        </select>
      </div>
      <div style="flex:0">
        <label>&nbsp;</label>
        <div>
          <button class="success" onclick="generateKey()">Random Key</button>
          <button onclick="addKey()">Add Key</button>
          <button class="ghost" onclick="loadKeys()">Refresh</button>
          <button class="ghost" onclick="logout()">Logout</button>
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <table>
      <thead>
        <tr>
          <th>Key</th>
          <th>Status</th>
          <th>Expires</th>
          <th>Activated</th>
          <th>Machine</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
    <div id="empty" class="empty" style="display:none">No keys yet. Add one above.</div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
let TOKEN = localStorage.getItem('licAdminToken') || '';

function show(el, display='block') { document.getElementById(el).style.display = display; }
function hide(el) { document.getElementById(el).style.display = 'none'; }

function toast(msg, isError=false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast' + (isError ? ' error' : '');
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 2500);
}

async function api(path, method='GET', body=null) {
  const opts = { method, headers: { 'X-Admin-Token': TOKEN, 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  if (res.status === 401) {
    TOKEN = '';
    localStorage.removeItem('licAdminToken');
    show('login'); hide('panel');
    throw new Error('Unauthorized');
  }
  return res.json();
}

async function doLogin() {
  const t = document.getElementById('token').value.trim();
  if (!t) { toast('Enter a token', true); return; }
  TOKEN = t;
  try {
    await api('/admin/list');
    localStorage.setItem('licAdminToken', TOKEN);
    hide('login'); show('panel');
    loadKeys();
  } catch(e) { toast('Invalid token', true); }
}

function logout() {
  TOKEN = '';
  localStorage.removeItem('licAdminToken');
  hide('panel'); show('login');
}

async function loadKeys() {
  try {
    const data = await api('/admin/list');
    renderKeys(data);
  } catch(e) {}
}

function renderKeys(data) {
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';
  const keys = Object.keys(data);
  let active=0, bound=0, revoked=0;
  const now = new Date();
  keys.forEach(k => {
    const e = data[k];
    const expired = e.expires_at && new Date(e.expires_at) < now;
    if (!e.active) revoked++;
    else { active++; if (e.device_id) bound++; }
    const tr = document.createElement('tr');
    let status;
    if (!e.active) status = '<span class="badge revoked">Revoked</span>';
    else if (expired) status = '<span class="badge revoked">Expired</span>';
    else if (e.device_id) status = '<span class="badge bound">In Use</span>';
    else status = '<span class="badge unused">Unused</span>';
    let expires = '-';
    if (e.expires_at) {
      const d = new Date(e.expires_at);
      const daysLeft = Math.ceil((d - now) / 86400000);
      if (daysLeft < 0) expires = `<span style="color:#dc2626">${d.toLocaleDateString()} (expired)</span>`;
      else if (daysLeft <= 7) expires = `<span style="color:#f59e0b">${d.toLocaleDateString()} (${daysLeft}d left)</span>`;
      else expires = `${d.toLocaleDateString()} (${daysLeft}d left)`;
    } else {
      expires = '<span style="color:#16a34a">Lifetime</span>';
    }
    const activated = e.activated_at ? new Date(e.activated_at).toLocaleDateString() : '-';
    const machine = e.machine_name || '-';
    let actions = '';
    if (e.active) {
      actions += `<button class="danger" onclick="revokeKey('${k}')">Revoke</button>`;
    } else {
      actions += `<button class="success" onclick="enableKey('${k}')">Enable</button>`;
    }
    if (e.device_id) {
      actions += `<button class="ghost" onclick="resetKey('${k}')">Reset Device</button>`;
    }
    actions += `<button class="ghost" onclick="editExpiry('${k}', '${e.expires_at || ''}')">Edit Expiry</button>`;
    actions += `<button class="ghost" onclick="copyKey('${k}')">Copy</button>`;
    actions += `<button class="danger" onclick="deleteKey('${k}')">Delete</button>`;
    tr.innerHTML = `<td class="key">${k}</td><td>${status}</td><td>${expires}</td><td>${activated}</td><td>${machine}</td><td>${actions}</td>`;
    tbody.appendChild(tr);
  });
  document.getElementById('s-total').textContent = keys.length;
  document.getElementById('s-active').textContent = active;
  document.getElementById('s-bound').textContent = bound;
  document.getElementById('s-revoked').textContent = revoked;
  document.getElementById('empty').style.display = keys.length ? 'none' : 'block';
}

function applyPreset() {
  const val = document.getElementById('expPreset').value;
  const exp = document.getElementById('expDate');
  if (!val) return;
  if (val === 'lifetime') { exp.value = ''; return; }
  const d = new Date();
  d.setDate(d.getDate() + parseInt(val, 10));
  exp.value = d.toISOString().split('T')[0];
}

async function editExpiry(key, current) {
  const input = prompt(`Set expiration for ${key}\n\nEnter date as YYYY-MM-DD (e.g. 2026-12-31), or leave blank for lifetime:`, current ? current.split('T')[0] : '');
  if (input === null) return;
  const expires_at = input.trim() ? input.trim() + 'T23:59:59Z' : null;
  const res = await api('/admin/set_expiry', 'POST', { key, expires_at });
  if (res.error) { toast(res.error, true); return; }
  toast('Expiry updated');
  loadKeys();
}

function genKey() {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const part = () => Array.from({length:4}, ()=>a[Math.floor(Math.random()*a.length)]).join('');
  return `${part()}-${part()}-${part()}-${part()}`;
}

function generateKey() {
  document.getElementById('newKey').value = genKey();
}

async function addKey() {
  const key = document.getElementById('newKey').value.trim();
  const expDateVal = document.getElementById('expDate').value;
  const expires_at = expDateVal ? expDateVal + 'T23:59:59Z' : null;
  const res = await api('/admin/add', 'POST', { key, expires_at });
  if (res.error) { toast(res.error, true); return; }
  toast(`Added: ${res.key}`);
  document.getElementById('newKey').value = '';
  document.getElementById('expDate').value = '';
  document.getElementById('expPreset').value = '';
  loadKeys();
}

async function revokeKey(key) {
  if (!confirm(`Revoke ${key}?`)) return;
  await api('/admin/revoke', 'POST', { key });
  toast('Revoked');
  loadKeys();
}

async function enableKey(key) {
  await api('/admin/enable', 'POST', { key });
  toast('Enabled');
  loadKeys();
}

async function resetKey(key) {
  if (!confirm(`Reset device binding for ${key}? User can activate on new PC.`)) return;
  await api('/admin/reset', 'POST', { key });
  toast('Device reset');
  loadKeys();
}

async function deleteKey(key) {
  if (!confirm(`Delete ${key}? This cannot be undone.`)) return;
  await api('/admin/delete', 'POST', { key });
  toast('Deleted');
  loadKeys();
}

function copyKey(key) {
  navigator.clipboard.writeText(key);
  toast('Copied');
}

// init
if (TOKEN) {
  api('/admin/list').then(data => {
    hide('login'); show('panel'); renderKeys(data);
  }).catch(() => { show('login'); });
} else {
  show('login');
}
</script>

</body>
</html>
"""


@app.get("/admin", response_class=HTMLResponse)
async def admin_page() -> HTMLResponse:
    return HTMLResponse(ADMIN_HTML)


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok"})
