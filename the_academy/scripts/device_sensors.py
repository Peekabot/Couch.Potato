"""
The Academy - iOS Device Sensors
===================================
Pythonista-only. Exposes iPhone sensors and controls to the Academy LAN so
that other nodes (EliteBook, Mac) can read sensor data and trigger actions
via the same HTTP-JSON interface used by the rest of the Academy.

IMPORTANT: Requires Pythonista 3 on iOS. The Pythonista-specific imports
(motion, location, notification, console) are imported with a graceful fallback
so the file can be syntax-checked on desktop Python without crashing.

Endpoints:
    GET  /health              Node discovery — compatible with job_queue.py
    GET  /ping                Liveness + timestamp
    GET  /ip                  Device LAN IP
    GET  /time                Current UTC time
    GET  /loc                 GPS fix  (lat, lon, alt, accuracy)
    GET  /accel               Accelerometer + gravity (X/Y/Z)
    POST /notify              Send local push notification
                                Body: {"msg": "text", "sound": true}
    POST /shortcut            Trigger an iOS Shortcut by name
                                Body: {"name": "My Shortcut"}
    POST /browse              Open a URL in Safari (https only)
                                Body: {"url": "https://..."}

Usage:
    python3 device_sensors.py           # default port 5002
    python3 device_sensors.py --port 5003

Port layout (all Academy services):
    5000  academy_receiver.py   (inbox / scrape receiver)
    5001  security_lab.py       (red/blue team training)
    5002  device_sensors.py     (this file — iOS sensors)
    4444  node_agent.py         (compute node on EliteBook/Mac)

iOS/Pythonista notes:
    - debug=False, threaded=False  — no subprocess forks allowed on iOS
    - motion.start_updates() called at startup; non-blocking per-request reads
    - location.start_updates() called at startup; first fix may take a few seconds
"""

import os
import re
import json
import socket
import datetime
import argparse
import urllib.parse

try:
    from flask import Flask, request, jsonify
except ImportError:
    raise SystemExit("Flask required: pip install flask")

# ── Pythonista sensor imports ─────────────────────────────────────────────────
# Graceful fallback: these modules only exist in Pythonista on iOS.
# On desktop Python / iSH the server still starts; sensor endpoints return 503.
try:
    import motion
    import location
    import notification
    import console
    import webbrowser as _webbrowser
    _HAS_SENSORS = True
    motion.start_updates()
    location.start_updates()
except ImportError:
    _HAS_SENSORS = False

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_PORT  = 5002
_NOTIFY_MAX   = 128   # max push notification message length (chars)
# Shortcut names: alphanumeric, spaces, hyphens, underscores only.
# Blocks URL-scheme injection (e.g. names containing & or ?)
_SHORTCUT_RE  = re.compile(r'^[\w\s\-]+$')

app = Flask(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.datetime.utcnow().isoformat()


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _require_sensors():
    """Return a 503 response dict if sensors are unavailable, else None."""
    if not _HAS_SENSORS:
        return jsonify({"error": "Pythonista sensors not available on this platform"}), 503
    return None


def _require_json():
    """Return a 415 response if the request is not JSON, else None."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    return None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    """
    Node discovery endpoint — same shape as node_agent.py /health.
    job_queue.py uses this to detect live nodes; returning an empty jobs list
    marks this as a sensor-only node (no job dispatch).
    """
    return jsonify({
        "status":      "ok",
        "node":        socket.gethostname(),
        "ip":          _local_ip(),
        "service":     "device_sensors",
        "has_sensors": _HAS_SENSORS,
        "jobs":        [],   # sensor-only node; job dispatch not supported
        "time":        _now(),
    })


@app.route("/ping")
def ping():
    return jsonify({"pong": True, "ip": _local_ip(), "time": _now()})


@app.route("/ip")
def ip_addr():
    return jsonify({"ip": _local_ip()})


@app.route("/time")
def time_now():
    return jsonify({"utc": _now()})


@app.route("/loc")
def loc():
    """
    Return the current GPS fix.
    Requires Location permission granted to Pythonista in iOS Settings.
    The first call after start_updates() may return None until a fix is acquired.
    """
    err = _require_sensors()
    if err:
        return err
    fix = location.get_location()
    if not fix:
        return jsonify({"error": "no GPS fix yet — retry in a few seconds"}), 503
    return jsonify({
        "lat":      fix["latitude"],
        "lon":      fix["longitude"],
        "alt":      fix.get("altitude"),
        "accuracy": fix.get("horizontal_accuracy"),
        "time":     _now(),
    })


@app.route("/accel")
def accel():
    """
    Return the current accelerometer readings.
    user_accel: device motion excluding gravity (activity detection).
    gravity:    gravity vector in device coordinates (orientation).
    """
    err = _require_sensors()
    if err:
        return err
    ua = motion.get_user_acceleration()
    gv = motion.get_gravity()
    return jsonify({
        "user_accel": {"x": round(ua[0], 4), "y": round(ua[1], 4), "z": round(ua[2], 4)},
        "gravity":    {"x": round(gv[0], 4), "y": round(gv[1], 4), "z": round(gv[2], 4)},
        "time":       _now(),
    })


@app.route("/notify", methods=["POST"])
def notify():
    """
    Schedule a local push notification.

    Body (JSON):
        {
            "msg":   "Job complete on EliteBook",   # required, max 128 chars
            "sound": true                            # optional, default true
        }

    Use from other Academy nodes to signal the operator (you) when a job
    finishes without needing to keep a terminal tab open.
    """
    err = _require_sensors() or _require_json()
    if err:
        return err

    data  = request.get_json(silent=True) or {}
    msg   = str(data.get("msg", "")).strip()[:_NOTIFY_MAX]
    if not msg:
        return jsonify({"error": "'msg' field is required and must be non-empty"}), 400

    notification.schedule(msg, "Academy", 0)
    return jsonify({"sent": True, "msg": msg, "time": _now()})


@app.route("/shortcut", methods=["POST"])
def shortcut():
    """
    Trigger an iOS Shortcut by name.

    Body (JSON):  {"name": "My Shortcut"}

    Name is validated against ^[\\w\\s\\-]+$ before being embedded in the
    shortcuts:// URL scheme — prevents URL-scheme injection via & or ?.
    The shortcut must already exist on the device.
    """
    err = _require_sensors() or _require_json()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"error": "'name' field is required"}), 400
    if not _SHORTCUT_RE.match(name):
        return jsonify({
            "error": "name must contain only letters, numbers, spaces, hyphens, underscores",
        }), 400

    url = f"shortcuts://run-shortcut?name={urllib.parse.quote(name)}"
    _webbrowser.open(url)
    return jsonify({"triggered": name, "url_scheme": url, "time": _now()})


@app.route("/browse", methods=["POST"])
def browse():
    """
    Open a URL in the in-app browser.

    Body (JSON):  {"url": "https://example.com"}

    Only https:// URLs are accepted — prevents data: / javascript: injection
    and ensures links opened this way are at least transport-encrypted.
    """
    err = _require_sensors() or _require_json()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    url  = str(data.get("url", "")).strip()
    if not re.match(r'^https://', url, re.IGNORECASE):
        return jsonify({"error": "url must begin with https://"}), 400

    _webbrowser.open(url)
    return jsonify({"opened": url, "time": _now()})


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Academy iOS Device Sensors")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"Port (default: {DEFAULT_PORT})")
    args = parser.parse_args()

    ip = _local_ip()
    print("=" * 60)
    print("The Academy - iOS Device Sensors")
    print("=" * 60)
    print(f"  Listening : http://{ip}:{args.port}")
    print(f"  Sensors   : {'ACTIVE' if _HAS_SENSORS else 'unavailable — run in Pythonista'}")
    print(f"  Discovery : GET http://{ip}:{args.port}/health")
    print()
    print("  Read-only  : /ping  /ip  /time  /loc  /accel")
    print("  Write      : POST /notify  /shortcut  /browse")
    print()
    print("  Port layout:")
    print("    5000  academy_receiver  (inbox / scrape)")
    print("    5001  security_lab      (red/blue team)")
    print(f"    {args.port:<4}  device_sensors    (this)")
    print("    4444  node_agent        (EliteBook / Mac)")
    print("=" * 60)

    # threaded=False + debug=False: both required on iOS/Pythonista.
    # Werkzeug's threaded mode and auto-reloader both try to spawn subprocesses,
    # which iOS blocks with EPERM.
    app.run(host="0.0.0.0", port=args.port, debug=False, threaded=False)
