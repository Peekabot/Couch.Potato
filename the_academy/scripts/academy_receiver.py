"""
The Academy - Agent-Aware Code Receiver
========================================
Run on Pythonista (iOS). Receives code payloads from any agent,
stamps identity metadata, and writes to the file-based message bus.

Agents identify themselves via the X-Agent request header.
Supported agents: claude, gemini, grok (falls back to 'unknown')

Endpoints:
    POST /send_code          Raw code payload (X-Agent header required)
    POST /scrape             Safari scrape payload (JSON body)
    GET  /bus/state          Bus state + message counters
    GET  /bus/inbox/<agent>  List pending messages
    GET  /bus/inbox/<agent>/<file>     Read a message
    DELETE /bus/inbox/<agent>/<file>   Consume a message

Usage (iSH or Shortcuts):
    curl -X POST http://<ios-ip>:5000/send_code \
         -H "X-Agent: claude" \
         -H "Content-Type: text/plain" \
         --data-binary @myfile.py
"""

import os
import re
import json
import datetime

try:
    from flask import Flask, request, jsonify
except ImportError:
    raise SystemExit("Flask required: pip install flask")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUS_DIR   = os.path.join(BASE_DIR, "bus")
INBOX_DIR = os.path.join(BUS_DIR, "inbox")
STATE_FILE = os.path.join(BUS_DIR, "state.json")

KNOWN_AGENTS  = {"claude", "gemini", "grok"}
SCRAPE_DIR    = os.path.join(BUS_DIR, "scrapes")
# Maximum DOM snapshot stored per scrape (bytes). 0 = disabled.
DOM_SIZE_LIMIT = 256 * 1024   # 256 KB

# ── App ───────────────────────────────────────────────────────────────────────
app = Flask(__name__)


def _timestamp() -> str:
    return datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")


def _load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"message_count": {a: 0 for a in KNOWN_AGENTS}, "active": True}


def _save_state(state: dict) -> None:
    state["last_updated"] = datetime.datetime.utcnow().isoformat()
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def _agent_inbox(agent: str) -> str:
    """Return (and create if needed) the inbox path for an agent."""
    path = os.path.join(INBOX_DIR, agent)
    os.makedirs(path, exist_ok=True)
    return path


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/send_code", methods=["POST"])
def receive_code():
    """
    Accept a raw code payload.
    Header:  X-Agent: <agent-id>
    Body:    raw source text (any language)
    Returns: JSON confirmation with file path and agent attribution.
    """
    agent = request.headers.get("X-Agent", "unknown").lower().strip()
    if agent not in KNOWN_AGENTS:
        agent = "unknown"

    raw = request.get_data(as_text=True)
    if not raw:
        return jsonify({"error": "empty body"}), 400

    ts       = _timestamp()
    filename = f"{agent}_{ts}.py"
    inbox    = _agent_inbox(agent)
    filepath = os.path.join(inbox, filename)

    header = (
        f"# Agent:     {agent}\n"
        f"# Timestamp: {ts}\n"
        f"# Source:    {request.remote_addr}\n"
        f"# Bus:       the_academy/bus/inbox/{agent}/{filename}\n\n"
    )

    with open(filepath, "w") as f:
        f.write(header + raw)

    # Update state counters
    state = _load_state()
    state["message_count"].setdefault(agent, 0)
    state["message_count"][agent] += 1
    _save_state(state)

    return jsonify({
        "agent":   agent,
        "file":    filename,
        "inbox":   f"the_academy/bus/inbox/{agent}/",
        "message": f"[{agent}] Saved to {filename}",
    }), 201


@app.route("/bus/state", methods=["GET"])
def bus_state():
    """Return current bus state (message counts, last update)."""
    return jsonify(_load_state())


@app.route("/bus/inbox/<agent>", methods=["GET"])
def list_inbox(agent: str):
    """List pending messages in an agent's inbox."""
    if agent not in KNOWN_AGENTS:
        return jsonify({"error": "unknown agent"}), 404
    inbox = _agent_inbox(agent)
    files = sorted(f for f in os.listdir(inbox) if not f.startswith("."))
    return jsonify({"agent": agent, "pending": files, "count": len(files)})


@app.route("/bus/inbox/<agent>/<filename>", methods=["GET", "DELETE"])
def message(agent: str, filename: str):
    """
    GET    - read a message from an agent's inbox
    DELETE - consume (delete) it after processing
    """
    if agent not in KNOWN_AGENTS:
        return jsonify({"error": "unknown agent"}), 404

    filepath = os.path.join(INBOX_DIR, agent, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "not found"}), 404

    if request.method == "DELETE":
        os.remove(filepath)
        return jsonify({"deleted": filename}), 200

    with open(filepath) as f:
        content = f.read()
    return content, 200, {"Content-Type": "text/plain"}


@app.route("/scrape", methods=["POST"])
def receive_scrape():
    """
    Accept a Safari scrape payload posted as JSON.

    Expected JSON body (all fields optional except 'url'):
    {
        "url":      "https://example.com/page",   # required
        "title":    "Page Title",
        "selected": "highlighted text on page",
        "dom":      "<html>...</html>",            # optional, may be large
        "agent":    "claude"                       # which agent to route to
    }

    The scrape is saved as a .json file in bus/scrapes/ and also
    dropped as a structured message in the target agent's inbox.
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    payload = request.get_json(silent=True) or {}

    url = payload.get("url", "").strip()
    if not url:
        return jsonify({"error": "'url' field is required"}), 400

    # Sanitise URL: must look like http(s)://... — reject anything else
    if not re.match(r'^https?://', url, re.IGNORECASE):
        return jsonify({"error": "url must begin with http:// or https://"}), 400

    title    = str(payload.get("title", ""))[:1024]
    selected = str(payload.get("selected", ""))[:65536]
    agent    = payload.get("agent", "claude").lower().strip()
    if agent not in KNOWN_AGENTS:
        agent = "claude"

    # Enforce DOM size cap
    dom_raw = payload.get("dom", "")
    if dom_raw and DOM_SIZE_LIMIT > 0:
        dom_raw = dom_raw[:DOM_SIZE_LIMIT]

    ts       = _timestamp()
    filename = f"scrape_{ts}.json"

    scrape_record = {
        "type":      "safari_scrape",
        "agent":     agent,
        "timestamp": ts,
        "source_ip": request.remote_addr,
        "url":       url,
        "title":     title,
        "selected":  selected,
        "has_dom":   bool(dom_raw),
        "dom":       dom_raw,
    }

    # Persist to bus/scrapes/
    os.makedirs(SCRAPE_DIR, exist_ok=True)
    scrape_path = os.path.join(SCRAPE_DIR, filename)
    with open(scrape_path, "w") as f:
        json.dump(scrape_record, f, indent=2)

    # Also drop a lightweight message into the agent's inbox
    inbox    = _agent_inbox(agent)
    msg_name = f"scrape_ref_{ts}.json"
    msg_body = {k: v for k, v in scrape_record.items() if k != "dom"}
    msg_body["scrape_file"] = f"the_academy/bus/scrapes/{filename}"
    with open(os.path.join(inbox, msg_name), "w") as f:
        json.dump(msg_body, f, indent=2)

    # Update counters
    state = _load_state()
    state.setdefault("scrape_count", 0)
    state["scrape_count"] += 1
    state["message_count"].setdefault(agent, 0)
    state["message_count"][agent] += 1
    _save_state(state)

    return jsonify({
        "agent":       agent,
        "scrape_file": filename,
        "inbox_msg":   msg_name,
        "url":         url,
        "has_dom":     bool(dom_raw),
        "message":     f"[{agent}] Scrape saved: {filename}",
    }), 201


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import socket

    def _local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "localhost"

    ip = _local_ip()
    print("=" * 60)
    print("The Academy - Agent Identity Receiver")
    print("=" * 60)
    print(f"  Listening : http://{ip}:5000")
    print(f"  Bus root  : {BUS_DIR}")
    print(f"  Agents    : {', '.join(sorted(KNOWN_AGENTS))}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
