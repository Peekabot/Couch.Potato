"""
The Academy - iOS Security Lab
================================
Intentionally vulnerable Flask app for security training.
Run on Pythonista (iOS) or iSH. Practice red/blue team techniques locally.

IMPORTANT
---------
This app contains DELIBERATE vulnerabilities for educational use only.
Run on localhost. Never expose to untrusted networks.

Usage:
    python3 security_lab.py            # http://127.0.0.1:5001
    python3 security_lab.py --port 5002

Practice scenarios (red team):
    1. Reflected XSS (comment box)
    2. SQL Injection simulation (login)
    3. Cookie / session forgery (weak HMAC secret)
    4. Path traversal awareness (file lookup)

Blue team defenses (built-in, always active):
    - Rate limiter : 60 req/min per IP, sliding window, returns 429
    - Body size cap: 64 KB max POST, returns 413
    - Event log    : bus/lab_events.jsonl (JSONL, append-only)
    - /metrics     : live per-IP request rates + event kind summary
    - /logs        : last 30 events from the event log

iOS/Pythonista compatibility notes:
    - debug=False  : disables auto-reloader (no subprocesses)
    - threaded=False: prevents Werkzeug from spawning a monitor subprocess
    - stdlib only  : no subprocess, no os.system, no shell calls
"""

import os
import sys
import json
import uuid
import socket
import hashlib
import datetime
import argparse
import threading
import collections

try:
    from flask import Flask, request, render_template_string, make_response, jsonify
except ImportError:
    raise SystemExit("Flask required: pip install flask")

# ── Bus integration ───────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB_LOG  = os.path.join(BASE_DIR, "bus", "lab_events.jsonl")
os.makedirs(os.path.dirname(LAB_LOG), exist_ok=True)


def _now() -> str:
    return datetime.datetime.utcnow().isoformat()


def _log_event(kind: str, data: dict) -> None:
    """Append an attack/observation event to the bus log (JSONL, one line each)."""
    record = {"time": _now(), "kind": kind, **data}
    with open(LAB_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")


# ── Blue-team: rate limiter (sliding window, stdlib only) ─────────────────────

class RateLimiter:
    """
    Per-IP sliding-window rate limiter.  No external deps — works on iSH/Pythonista.

    Tracks timestamps of recent requests for each IP in a deque.
    On each check it evicts timestamps older than `window_seconds` then
    compares the remaining count against `limit`.

    Thread-safe (lock-protected), but the lab runs with threaded=False
    so the lock is mainly defensive.
    """
    def __init__(self, limit: int = 60, window_seconds: int = 60):
        self.limit          = limit
        self.window         = window_seconds
        self._buckets: dict[str, collections.deque] = {}
        self._lock          = threading.Lock()
        # counters for /metrics
        self.total_blocked  = 0
        self.blocked_ips: dict[str, int] = {}

    def is_allowed(self, ip: str) -> tuple[bool, int]:
        """
        Returns (allowed, current_count).
        Side-effect: increments blocked counters when limit exceeded.
        """
        now = datetime.datetime.utcnow().timestamp()
        cutoff = now - self.window

        with self._lock:
            dq = self._buckets.setdefault(ip, collections.deque())
            # Evict expired timestamps
            while dq and dq[0] < cutoff:
                dq.popleft()
            count = len(dq)
            if count >= self.limit:
                self.total_blocked += 1
                self.blocked_ips[ip] = self.blocked_ips.get(ip, 0) + 1
                return False, count
            dq.append(now)
            return True, count + 1

    def snapshot(self) -> dict:
        """Return current per-IP counts (for /metrics)."""
        now    = datetime.datetime.utcnow().timestamp()
        cutoff = now - self.window
        with self._lock:
            return {
                ip: len([t for t in dq if t >= cutoff])
                for ip, dq in self._buckets.items()
            }


_rate_limiter = RateLimiter(limit=60, window_seconds=60)

# Maximum allowed request body size (bytes). Blocks memory-exhaustion payloads.
_MAX_BODY = 64 * 1024   # 64 KB


# ── Config ────────────────────────────────────────────────────────────────────
# VULNERABILITY: weak secret — intentional for cookie-forgery exercise
SECRET = "dev-key-2024"

app = Flask(__name__)


# ── Blue-team: before_request guards ─────────────────────────────────────────

@app.before_request
def guard_rate_limit():
    """
    Blue Team defense #1 — IP-based rate limiting.
    Returns 429 when a single IP exceeds 60 requests/minute.

    What it stops: HTTP flood attacks sending thousands of requests/s.
    What it teaches: rate limiting is the first layer; a real defender
      also adds IP blocking, CAPTCHA, and upstream WAF rules.
    """
    ip = request.remote_addr or "unknown"
    allowed, count = _rate_limiter.is_allowed(ip)
    if not allowed:
        _log_event("rate_limit_triggered", {
            "ip":    ip,
            "count": count,
            "limit": _rate_limiter.limit,
            "path":  request.path,
        })
        return (
            f"429 Too Many Requests\n"
            f"IP {ip} has sent {count} requests in {_rate_limiter.window}s.\n"
            f"Limit: {_rate_limiter.limit}/min.\n\n"
            "[BLUE] Rate limiter fired. Event logged to bus/lab_events.jsonl."
        ), 429, {"Content-Type": "text/plain"}


@app.before_request
def guard_body_size():
    """
    Blue Team defense #2 — request body size cap.
    Returns 413 for bodies larger than 64 KB.

    What it stops: memory-exhaustion attacks that POST megabytes of data
      hoping to OOM the server or slow it with hashing/logging.
    What it teaches: always cap Content-Length before reading the body.
    """
    length = request.content_length
    if length and length > _MAX_BODY:
        _log_event("oversized_body", {
            "ip":     request.remote_addr,
            "bytes":  length,
            "limit":  _MAX_BODY,
            "path":   request.path,
        })
        return (
            f"413 Request Too Large\n"
            f"Body size {length} bytes exceeds {_MAX_BODY} byte limit.\n\n"
            "[BLUE] Body size guard fired. Event logged."
        ), 413, {"Content-Type": "text/plain"}


# In-memory "users table" for SQLi demo (no real DB needed)
USERS = {
    "admin":  "admin123",
    "alice":  "password1",
    "bob":    "letmein",
}


# ── Templates ─────────────────────────────────────────────────────────────────
_INDEX = """<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Academy Security Lab</title>
  <style>
    *{box-sizing:border-box}
    body{font-family:monospace;background:#111;color:#eee;margin:0;padding:16px}
    h1{color:#0f0;font-size:1.1em}h3{color:#fc0;margin-top:0}
    .card{background:#1e1e1e;border-left:4px solid #c00;padding:12px;margin:10px 0;border-radius:4px}
    .blue{border-left-color:#06f}
    input,textarea{background:#2a2a2a;color:#eee;border:1px solid #555;padding:8px;
      width:100%;margin:4px 0;border-radius:3px;font-family:monospace}
    button{background:#c00;color:#fff;border:none;padding:8px 16px;
      cursor:pointer;border-radius:3px;font-family:monospace}
    .blue button{background:#06f}
    a{color:#06f}
  </style>
</head>
<body>
<h1>&#x1F5A5; Academy Security Lab — iOS Edition</h1>
<p style="color:#888;font-size:.85em">
  All vulnerabilities are intentional. Localhost only. Educational use.
</p>

<div class="card">
  <h3>1. Reflected XSS</h3>
  <form action="/xss" method="post">
    <input name="comment" placeholder='Try: &lt;img src=x onerror=alert(1)&gt;'>
    <button>Post</button>
  </form>
</div>

<div class="card">
  <h3>2. SQL Injection (simulated)</h3>
  <form action="/login" method="post">
    <input name="username" placeholder="Username — try: admin' --">
    <input name="password" type="password" placeholder="Password">
    <button>Login</button>
  </form>
</div>

<div class="card">
  <h3>3. Cookie / Session Forgery</h3>
  <form action="/cookie/set" method="post">
    <input name="role" placeholder="Role to store — try: admin">
    <button>Set Cookie</button>
  </form>
  <a href="/cookie/read"><button style="margin-top:6px">Read Cookie</button></a>
</div>

<div class="card">
  <h3>4. Path Traversal Awareness</h3>
  <form action="/file" method="post">
    <input name="path" placeholder="File path — try: ../../etc/passwd">
    <button>Lookup</button>
  </form>
</div>

<div class="card blue">
  <h3>&#x1F6E1; Blue Team: Monitoring</h3>
  <a href="/metrics"><button>Live Metrics</button></a>
  &nbsp;<a href="/logs"><button>Event Log</button></a>
  &nbsp;<a href="/logs/clear"><button>Clear Log</button></a>
  <p style="color:#888;font-size:.8em;margin:6px 0 0">
    Rate limit: 60 req/min per IP &bull; Body cap: 64 KB &bull; All events logged to bus/
  </p>
</div>
</body>
</html>"""

_RESULT = """<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Result — Academy Lab</title>
  <style>
    body{font-family:monospace;background:#111;color:#eee;margin:0;padding:16px}
    .box{background:#1e1e1e;padding:14px;border-radius:4px;white-space:pre-wrap;word-break:break-all}
    h2{color:#fc0}a{color:#06f}
    .label{color:#888;font-size:.85em}
  </style>
</head>
<body>
<h2>{{ title }}</h2>
<div class="box">{{ body|safe }}</div>
<p><a href="/">&#8592; Back</a></p>
</body>
</html>"""


def _render(title: str, body: str):
    return render_template_string(_RESULT, title=title, body=body)


# ── 1. Reflected XSS ─────────────────────────────────────────────────────────

@app.route("/xss", methods=["POST"])
def xss():
    """
    VULNERABILITY: user input reflected into HTML without escaping.
    The template uses |safe, so <script> and event-handler payloads execute.

    Fix: remove |safe and let Jinja2 auto-escape, or call html.escape() first.
    """
    comment = request.form.get("comment", "")
    _log_event("xss_attempt", {"payload": comment[:512], "ip": request.remote_addr})

    # The vulnerability: `comment` ends up inside `body` which the template
    # renders with |safe. Any HTML/JS in `comment` will execute.
    body = (
        f"Your comment:\n\n{comment}\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "[VULN] Input reflected with |safe — no escaping.\n"
        "[FIX]  Jinja2 auto-escaping or html.escape() before embedding."
    )
    return _render("XSS Playground", body)


# ── 2. SQL Injection (simulated) ─────────────────────────────────────────────

def _sqli_check(username: str, password: str) -> tuple[bool, str]:
    """
    Simulates what a vulnerable raw-SQL query would do.
    Returns (authenticated, explanation).
    Classic bypass: username = "admin' --"
    """
    # What a vulnerable query would look like:
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    # Detect comment-based bypass (-- or #)
    stripped = username.split("--")[0].split("#")[0].strip().rstrip("'")
    if stripped in USERS and ("--" in username or "#" in username):
        return True, f"Bypassed! Comment neutralised the password check.\nQuery: {query}"

    # Detect OR-based bypass
    if "' or " in username.lower() or "' or " in password.lower() or "1=1" in username.lower():
        return True, f"Bypassed! OR condition forced true result.\nQuery: {query}"

    # Legitimate check
    if USERS.get(username) == password:
        return True, f"Valid credentials.\nQuery: {query}"

    return False, f"Invalid credentials.\nQuery: {query}"


@app.route("/login", methods=["POST"])
def login():
    """
    VULNERABILITY: username/password concatenated directly into query string.
    Fix: parameterised queries — cursor.execute('...WHERE username=?', (username,))
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    _log_event("login_attempt", {
        "username": username[:128],
        "ip": request.remote_addr,
    })

    authed, explanation = _sqli_check(username, password)
    status  = "AUTHENTICATED" if authed else "REJECTED"
    label   = "[VULN] Raw string concatenation into query." if authed and ("--" in username or "or" in username.lower()) else ""

    body = (
        f"Status: {status}\n\n"
        f"{explanation}\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{label}\n"
        "[FIX]  Use parameterised queries or an ORM."
    )
    return _render("SQL Injection Lab", body)


# ── 3. Cookie / Session Forgery ───────────────────────────────────────────────

def _sign(value: str) -> str:
    """VULNERABILITY: uses MD5 + a weak, hardcoded secret."""
    return hashlib.md5(f"{value}:{SECRET}".encode()).hexdigest()


@app.route("/cookie/set", methods=["POST"])
def cookie_set():
    """
    VULNERABILITY: role is stored in a plaintext cookie with a weak MD5 signature.
    An attacker who knows the algorithm and guesses/leaks SECRET can forge cookies.
    Fix: use Flask's itsdangerous (cryptographically signed) sessions.
    """
    role = request.form.get("role", "guest")[:64]
    sig  = _sign(role)

    _log_event("cookie_set", {"role": role, "ip": request.remote_addr})

    resp = make_response(_render(
        "Cookie Set",
        (
            f"role={role}\n"
            f"sig={sig}\n\n"
            f"SECRET used: {SECRET}\n"
            f"Algorithm:   MD5(value + ':' + secret)\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "[VULN] Weak secret + MD5 = forgeable signature.\n"
            "[FIX]  Flask signed sessions (itsdangerous / HS256)."
        )
    ))
    resp.set_cookie("lab_role", role, httponly=True)
    resp.set_cookie("lab_sig",  sig,  httponly=True)
    return resp


@app.route("/cookie/read")
def cookie_read():
    role = request.cookies.get("lab_role", "(not set)")
    sig  = request.cookies.get("lab_sig",  "(not set)")

    expected = _sign(role) if role != "(not set)" else "—"
    valid     = sig == expected

    _log_event("cookie_read", {"role": role, "valid": valid, "ip": request.remote_addr})

    body = (
        f"lab_role : {role}\n"
        f"lab_sig  : {sig}\n\n"
        f"Expected : {expected}\n"
        f"Valid    : {valid}\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"[CHALLENGE] Forge a cookie with role=admin.\n"
        f"  Algorithm: MD5(role + ':' + secret)\n"
        f"  Weak secret: '{SECRET}'\n"
        "[FIX]  cryptographically secure session tokens."
    )
    return _render("Cookie Reader", body)


# ── 4. Path Traversal Awareness ───────────────────────────────────────────────

# The lab root — only files inside here are served intentionally.
_LAB_ROOT = os.path.join(BASE_DIR, "bus")


@app.route("/file", methods=["POST"])
def file_lookup():
    """
    Demonstrates path traversal. Shows what a vulnerable handler would return,
    then shows the sanitised result the safe handler actually uses.

    The SAFE handler never reads files outside _LAB_ROOT.
    """
    raw_path = request.form.get("path", "")
    abs_path = os.path.realpath(os.path.join(_LAB_ROOT, raw_path.lstrip("/")))

    _log_event("path_traversal_attempt", {
        "raw": raw_path[:256],
        "resolved": abs_path,
        "ip": request.remote_addr,
    })

    inside_root = abs_path.startswith(os.path.realpath(_LAB_ROOT))

    if inside_root and os.path.isfile(abs_path):
        try:
            with open(abs_path) as f:
                content = f.read(2048)
            body = (
                f"Path (raw)     : {raw_path}\n"
                f"Path (resolved): {abs_path}\n\n"
                f"Contents (first 2 KB):\n{content}\n\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "[INFO] Path was inside lab root — served safely."
            )
        except OSError as e:
            body = f"Read error: {e}"
    else:
        body = (
            f"Path (raw)     : {raw_path}\n"
            f"Path (resolved): {abs_path}\n\n"
            "BLOCKED — path resolves outside the lab root.\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "[VULN] A naive handler would read this file.\n"
            f"[FIX]  os.path.realpath() + startswith(root) guard.\n"
            f"       Lab root: {_LAB_ROOT}"
        )

    return _render("Path Traversal Lab", body)


# ── Blue-team log viewer ───────────────────────────────────────────────────────

@app.route("/logs")
def view_logs():
    if not os.path.exists(LAB_LOG):
        return _render("Event Log", "No events yet.")

    with open(LAB_LOG) as f:
        lines = f.readlines()

    recent = lines[-30:]  # last 30 events
    events = []
    for line in recent:
        try:
            ev = json.loads(line)
            events.append(f"[{ev['time']}] {ev['kind']:25s} ip={ev.get('ip','?')}")
        except json.JSONDecodeError:
            events.append(line.rstrip())

    body = "\n".join(events) + f"\n\nTotal events logged: {len(lines)}"
    return _render("Blue Team: Event Log", body)


@app.route("/logs/clear")
def clear_logs():
    if os.path.exists(LAB_LOG):
        open(LAB_LOG, "w").close()
    return _render("Logs Cleared", "Event log cleared.")


# ── Blue-team: metrics endpoint ───────────────────────────────────────────────

@app.route("/metrics")
def metrics():
    """
    Blue Team view: live request rates + event summary.
    Shows per-IP request counts in the current sliding window,
    total rate-limit triggers, and a count breakdown by event kind.
    """
    ip_counts  = _rate_limiter.snapshot()
    top_ips    = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

    # Read event log and summarise by kind
    kind_counts: dict[str, int] = {}
    total_events = 0
    if os.path.exists(LAB_LOG):
        with open(LAB_LOG) as f:
            for line in f:
                try:
                    ev = json.loads(line)
                    k  = ev.get("kind", "unknown")
                    kind_counts[k] = kind_counts.get(k, 0) + 1
                    total_events  += 1
                except json.JSONDecodeError:
                    pass

    lines = [
        f"=== Blue Team Metrics ===",
        f"Window  : last {_rate_limiter.window}s",
        f"Limit   : {_rate_limiter.limit} req/window",
        f"",
        f"--- Active IPs (requests in window) ---",
    ]
    if top_ips:
        for ip, count in top_ips[:20]:
            bar     = "#" * min(count, 40)
            blocked = _rate_limiter.blocked_ips.get(ip, 0)
            flag    = " [BLOCKED]" if blocked else ""
            lines.append(f"  {ip:<18} {count:>4} req  {bar}{flag}")
    else:
        lines.append("  (no requests yet)")

    lines += [
        f"",
        f"Total rate-limit triggers: {_rate_limiter.total_blocked}",
        f"",
        f"--- Event log summary ({total_events} total) ---",
    ]
    for kind, count in sorted(kind_counts.items(), key=lambda x: x[1], reverse=True):
        lines.append(f"  {kind:<30} {count}")

    return _render("Blue Team: Metrics", "\n".join(lines))


# ── Health / recon endpoint ───────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "security_lab",
        "scenarios": ["xss", "sqli", "cookie_forgery", "path_traversal"],
        "log": LAB_LOG,
    })


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Academy iOS Security Lab")
    parser.add_argument("--port", type=int, default=5001,
                        help="Port to listen on (default: 5001, avoids clash with receiver on 5000)")
    args = parser.parse_args()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    print("=" * 60)
    print("The Academy - iOS Security Lab (intentionally vulnerable)")
    print("=" * 60)
    print(f"  URL      : http://127.0.0.1:{args.port}")
    print(f"  Log      : {LAB_LOG}")
    print(f"  Scenarios: XSS, SQLi, Cookie Forgery, Path Traversal")
    print("  WARNING  : Do NOT expose to untrusted networks")
    print("=" * 60)

    # Both flags are required for Pythonista/iOS:
    # debug=False    — no reloader (reloader spawns subprocesses, iOS blocks them)
    # threaded=False — no monitor thread that tries to fork
    app.run(host="127.0.0.1", port=args.port, debug=False, threaded=False)
