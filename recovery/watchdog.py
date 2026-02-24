"""
CouchPotato Holdings — Site Watchdog
======================================
Runs as a PythonAnywhere always-on task.
Polls client sites, detects outages/defacement, pushes status to GitHub,
and fires Telegram alerts when state changes.

Setup (PythonAnywhere):
    1. Upload this file + clients.json to your PythonAnywhere home directory
    2. Set environment variables in your PA bash console:
           export GITHUB_TOKEN=ghp_...          # PAT with repo write scope
           export GITHUB_REPO=Peekabot/Couch.Potato
           export TELEGRAM_TOKEN=123:ABC...     # from @BotFather
           export TELEGRAM_CHAT_ID=-1001234...  # your chat or group ID
    3. Add to PythonAnywhere Always-on Tasks:
           python3 /home/<user>/recovery/watchdog.py
    4. That's it. The loop runs forever, sleeping between checks.

What it detects:
    - DOWN       : HTTP error, timeout, connection refused
    - DEGRADED   : Response time > SLOW_THRESHOLD_S seconds
    - DEFACED    : Homepage SHA-256 differs from last known-good hash
    - UP         : All clear

On state change → sends Telegram message + pushes status.json to GitHub.
GitHub Actions (restore.yml) watches status.json and triggers restore.
"""

import os
import json
import time
import hashlib
import datetime
import urllib.request
import urllib.error

# ── Config from environment ───────────────────────────────────────────────────
GITHUB_TOKEN   = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO    = os.environ.get("GITHUB_REPO", "Peekabot/Couch.Potato")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT  = os.environ.get("TELEGRAM_CHAT_ID", "")

# Paths (relative to this file so it works on PythonAnywhere and locally)
_HERE         = os.path.dirname(os.path.abspath(__file__))
CLIENTS_FILE  = os.path.join(_HERE, "clients.json")
STATUS_FILE   = os.path.join(_HERE, "status.json")
HASHES_FILE   = os.path.join(_HERE, ".content_hashes.json")  # hidden, local only
LOG_FILE      = os.path.join(_HERE, "watchdog.log")

POLL_INTERVAL_S  = 5 * 60   # 5 minutes between full sweeps
SLOW_THRESHOLD_S = 5.0       # seconds before marking a site DEGRADED
REQUEST_TIMEOUT  = 10        # seconds per HTTP request


# ── Logging ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.datetime.utcnow().isoformat()


def _log(msg: str) -> None:
    line = f"[{_now()}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ── HTTP helpers (stdlib only) ────────────────────────────────────────────────

def _get(url: str, timeout: int = REQUEST_TIMEOUT) -> tuple[int, float, bytes]:
    """
    GET url. Returns (status_code, elapsed_seconds, body_bytes).
    Returns (0, elapsed, b"") on network/timeout error.
    """
    t0 = time.monotonic()
    try:
        req  = urllib.request.Request(url, headers={"User-Agent": "CouchPotato-Watchdog/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(65536)   # first 64 KB is enough for hash check
            elapsed = time.monotonic() - t0
            return resp.status, elapsed, body
    except urllib.error.HTTPError as e:
        return e.code, time.monotonic() - t0, b""
    except Exception:
        return 0, time.monotonic() - t0, b""


def _post_json(url: str, payload: dict, headers: dict = None) -> dict:
    """POST JSON, return parsed response dict. Raises on failure."""
    body = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def _put_json(url: str, payload: dict, headers: dict = None) -> dict:
    """PUT JSON (for GitHub contents API). Returns parsed response."""
    body = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="PUT",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


# ── Site health check ─────────────────────────────────────────────────────────

def _load_hashes() -> dict:
    if os.path.exists(HASHES_FILE):
        with open(HASHES_FILE) as f:
            return json.load(f)
    return {}


def _save_hashes(hashes: dict) -> None:
    with open(HASHES_FILE, "w") as f:
        json.dump(hashes, f)


def check_site(client: dict, known_hashes: dict) -> dict:
    """
    Check one client site. Returns a status record:
    {
        "id":      "example-static",
        "name":    "...",
        "url":     "https://...",
        "type":    "static" | "dynamic",
        "state":   "up" | "down" | "degraded" | "defaced",
        "code":    200,
        "ms":      142,
        "checked": "2026-02-24T...",
        "reason":  "..."        # only on non-up states
    }
    """
    site_id = client["id"]
    url     = client["url"]
    code, elapsed, body = _get(url)
    ms  = int(elapsed * 1000)
    now = _now()

    if code == 0:
        return {
            "id": site_id, "name": client["name"], "url": url,
            "type": client.get("type", "static"),
            "state": "down", "code": 0, "ms": ms,
            "checked": now, "reason": "connection failed / timeout",
        }

    if code >= 400:
        return {
            "id": site_id, "name": client["name"], "url": url,
            "type": client.get("type", "static"),
            "state": "down", "code": code, "ms": ms,
            "checked": now, "reason": f"HTTP {code}",
        }

    # Defacement check: compare body hash to last known-good
    body_hash = hashlib.sha256(body).hexdigest()
    prev_hash = known_hashes.get(site_id)
    if prev_hash and body_hash != prev_hash:
        return {
            "id": site_id, "name": client["name"], "url": url,
            "type": client.get("type", "static"),
            "state": "defaced", "code": code, "ms": ms,
            "checked": now,
            "reason": f"homepage hash changed ({prev_hash[:8]}→{body_hash[:8]})",
            "hash": body_hash,
        }

    # Store/update hash for known-good state
    known_hashes[site_id] = body_hash

    if elapsed > SLOW_THRESHOLD_S:
        return {
            "id": site_id, "name": client["name"], "url": url,
            "type": client.get("type", "static"),
            "state": "degraded", "code": code, "ms": ms,
            "checked": now, "reason": f"slow response ({ms}ms > {int(SLOW_THRESHOLD_S*1000)}ms)",
        }

    return {
        "id": site_id, "name": client["name"], "url": url,
        "type": client.get("type", "static"),
        "state": "up", "code": code, "ms": ms, "checked": now,
    }


# ── Telegram alerts ───────────────────────────────────────────────────────────

_STATE_EMOJI = {"up": "✅", "down": "🔴", "degraded": "🟡", "defaced": "🚨"}


def _telegram_alert(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        _log("Telegram not configured — skipping alert")
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        _post_json(url, {"chat_id": TELEGRAM_CHAT, "text": text, "parse_mode": "Markdown"})
        _log(f"Telegram alert sent: {text[:60]}")
    except Exception as e:
        _log(f"Telegram alert FAILED: {e}")


def _build_alert(prev: dict | None, curr: dict) -> str | None:
    """Return alert text if state changed, else None."""
    prev_state = prev.get("state") if prev else None
    curr_state = curr["state"]
    if prev_state == curr_state:
        return None

    emoji = _STATE_EMOJI.get(curr_state, "❓")
    name  = curr["name"]
    url   = curr["url"]
    ms    = curr["ms"]
    reason = curr.get("reason", "")

    if curr_state == "up":
        return f"{emoji} *{name}* is back UP\n{url}\nResponse: {ms}ms"
    elif curr_state == "down":
        return f"{emoji} *{name}* is DOWN\n{url}\n{reason}"
    elif curr_state == "degraded":
        return f"{emoji} *{name}* is DEGRADED\n{url}\n{reason}"
    elif curr_state == "defaced":
        return f"{emoji} *DEFACEMENT DETECTED* — {name}\n{url}\n{reason}\nRestore triggered."
    return None


# ── GitHub status.json push ───────────────────────────────────────────────────

def _push_status_to_github(status: dict) -> None:
    """
    Upsert recovery/status.json in the GitHub repo via the Contents API.
    This push is what triggers the GitHub Actions restore workflow.
    """
    if not GITHUB_TOKEN:
        _log("GITHUB_TOKEN not set — writing status.json locally only")
        return

    import base64
    api_url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/recovery/status.json"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept":        "application/vnd.github.v3+json",
    }

    # Get current SHA (required for updates)
    sha = None
    try:
        req = urllib.request.Request(api_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            sha = json.loads(resp.read())["sha"]
    except Exception:
        pass  # File doesn't exist yet — first push

    content_b64 = base64.b64encode(
        json.dumps(status, indent=2).encode()
    ).decode()

    payload = {
        "message": f"watchdog: status update {_now()}",
        "content": content_b64,
    }
    if sha:
        payload["sha"] = sha

    try:
        _put_json(api_url, payload, headers)
        _log("status.json pushed to GitHub")
    except Exception as e:
        _log(f"GitHub push FAILED: {e}")


# ── Main loop ─────────────────────────────────────────────────────────────────

def _load_clients() -> list:
    with open(CLIENTS_FILE) as f:
        return json.load(f)["clients"]


def _load_prev_status() -> dict:
    if os.path.exists(STATUS_FILE):
        with open(STATUS_FILE) as f:
            return json.load(f).get("sites", {})
    return {}


def run_sweep() -> bool:
    """
    Check all clients once. Returns True if any state changed.
    """
    clients      = _load_clients()
    prev_sites   = _load_prev_status()
    known_hashes = _load_hashes()
    changed      = False
    new_sites    = {}

    for client in clients:
        site_id = client["id"]
        try:
            result = check_site(client, known_hashes)
        except Exception as e:
            _log(f"ERROR checking {client.get('id', '?')}: {e}")
            continue

        new_sites[site_id] = result
        state = result["state"]
        _log(f"  {site_id}: {state} ({result['ms']}ms)")

        # Alert on state change
        prev = prev_sites.get(site_id)
        alert_text = _build_alert(prev, result)
        if alert_text:
            changed = True
            if client.get("alert_telegram", True):
                _telegram_alert(alert_text)

    _save_hashes(known_hashes)

    # Write status.json locally
    status = {"updated": _now(), "sites": new_sites}
    with open(STATUS_FILE, "w") as f:
        json.dump(status, f, indent=2)

    # Push to GitHub if anything changed (triggers Actions restore workflow)
    if changed:
        _push_status_to_github(status)

    return changed


def main() -> None:
    _log("=" * 50)
    _log("CouchPotato Watchdog started")
    _log(f"  Clients file : {CLIENTS_FILE}")
    _log(f"  Status file  : {STATUS_FILE}")
    _log(f"  GitHub repo  : {GITHUB_REPO}")
    _log(f"  Poll interval: {POLL_INTERVAL_S}s")
    _log(f"  Telegram     : {'configured' if TELEGRAM_TOKEN else 'NOT configured'}")
    _log("=" * 50)

    while True:
        _log(f"Sweep starting...")
        try:
            changed = run_sweep()
            _log(f"Sweep complete. Changed: {changed}")
        except Exception as e:
            _log(f"Sweep ERROR: {e}")
        time.sleep(POLL_INTERVAL_S)


if __name__ == "__main__":
    main()
