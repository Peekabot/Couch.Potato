"""
The Academy - Bus Router
=========================
Scans the outbox for pending messages and routes each one to
the correct agent inbox based on the `to:` header in the file.

Message format (plain text file in outbox/):
    to: gemini
    from: claude
    subject: handoff
    ---
    <body content>

Run from iSH via cron or manually:
    python3 the_academy/scripts/bus_router.py

Or as a one-shot after pushing:
    python3 the_academy/scripts/bus_router.py --once
"""

import os
import sys
import json
import shutil
import datetime

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUS_DIR    = os.path.join(BASE_DIR, "bus")
OUTBOX_DIR = os.path.join(BUS_DIR, "outbox")
INBOX_DIR  = os.path.join(BUS_DIR, "inbox")
STATE_FILE = os.path.join(BUS_DIR, "state.json")
LOG_FILE   = os.path.join(BUS_DIR, "router.log")

KNOWN_AGENTS = {"claude", "gemini", "grok"}


def _now() -> str:
    return datetime.datetime.utcnow().isoformat()


def _log(msg: str) -> None:
    line = f"[{_now()}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def _load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"message_count": {a: 0 for a in KNOWN_AGENTS}}


def _save_state(state: dict) -> None:
    state["last_updated"] = _now()
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def parse_message(filepath: str) -> dict:
    """
    Parse a message file into headers + body.
    Header lines are `key: value` pairs before the `---` separator.
    Everything after `---` is the body.
    """
    with open(filepath) as f:
        raw = f.read()

    headers = {}
    body = raw

    if "---" in raw:
        head_block, _, body = raw.partition("---")
        for line in head_block.strip().splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

    return {"headers": headers, "body": body.strip()}


def route_message(filepath: str, state: dict) -> bool:
    """
    Route a single outbox file to the correct agent inbox.
    Returns True on success, False on parse/routing error.
    """
    filename = os.path.basename(filepath)
    msg = parse_message(filepath)
    headers = msg["headers"]

    to_agent   = headers.get("to", "").lower()
    from_agent = headers.get("from", "unknown").lower()

    if to_agent not in KNOWN_AGENTS:
        _log(f"SKIP {filename}: unknown recipient '{to_agent}'")
        return False

    dest_dir  = os.path.join(INBOX_DIR, to_agent)
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, filename)

    shutil.move(filepath, dest_path)

    state["message_count"].setdefault(to_agent, 0)
    state["message_count"][to_agent] += 1

    _log(f"ROUTE {filename}: {from_agent} -> {to_agent}")
    return True


def run_router() -> int:
    """
    Process all pending messages in the outbox.
    Returns count of successfully routed messages.
    """
    if not os.path.isdir(OUTBOX_DIR):
        _log(f"ERROR: outbox not found at {OUTBOX_DIR}")
        return 0

    pending = [
        f for f in os.listdir(OUTBOX_DIR)
        if not f.startswith(".") and os.path.isfile(os.path.join(OUTBOX_DIR, f))
    ]

    if not pending:
        _log("No pending messages in outbox.")
        return 0

    state = _load_state()
    routed = 0

    for filename in sorted(pending):
        filepath = os.path.join(OUTBOX_DIR, filename)
        if route_message(filepath, state):
            routed += 1

    _save_state(state)
    _log(f"Done: {routed}/{len(pending)} messages routed.")
    return routed


if __name__ == "__main__":
    count = run_router()
    sys.exit(0 if count >= 0 else 1)
