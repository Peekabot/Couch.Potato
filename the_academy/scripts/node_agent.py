"""
The Academy - Compute Node Agent
==================================
Run on each compute node (EliteBook, Mac, etc.) connected via iPhone hotspot.
Accepts jobs from the orchestrator, executes registered handlers, returns results.

SECURITY MODEL
--------------
- No shell passthrough. Job types are registered at startup as Python callables.
- Unknown job types are rejected with 400.
- All job I/O is JSON. No eval/exec anywhere.

Usage:
    python3 node_agent.py                  # default port 4444
    python3 node_agent.py --port 4445

Registration (add your own handlers below JOB_HANDLERS):
    JOB_HANDLERS["my_task"] = handle_my_task
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

try:
    from flask import Flask, request, jsonify
except ImportError:
    raise SystemExit("Flask required: pip install flask")

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_PORT = 4444
NODE_ID      = socket.gethostname()

app = Flask(__name__)

# In-memory result store (last N results per job type)
_results: dict = {}
_results_lock  = threading.Lock()
MAX_RESULTS    = 50   # per job type


# ── Job handlers ──────────────────────────────────────────────────────────────
# Each handler receives a dict payload and returns a dict result.
# Raise ValueError for invalid input; RuntimeError for execution failure.

def handle_ping(payload: dict) -> dict:
    """Health/identity check. Returns node info."""
    return {
        "node":    NODE_ID,
        "ip":      _local_ip(),
        "echo":    payload.get("message", ""),
        "time":    _now(),
    }


def handle_checksum(payload: dict) -> dict:
    """Compute SHA-256 of provided text content."""
    content = payload.get("content")
    if content is None:
        raise ValueError("'content' field required")
    digest = hashlib.sha256(str(content).encode()).hexdigest()
    return {"sha256": digest, "length": len(str(content))}


def handle_file_list(payload: dict) -> dict:
    """List files in a given directory (must be within allowed root)."""
    ALLOWED_ROOT = os.path.expanduser("~/Academy_workspace")
    path = payload.get("path", ALLOWED_ROOT)
    abs_path = os.path.realpath(os.path.expanduser(path))

    # Path traversal guard
    if not abs_path.startswith(os.path.realpath(ALLOWED_ROOT)):
        raise ValueError(f"Path outside allowed root: {ALLOWED_ROOT}")

    if not os.path.isdir(abs_path):
        raise ValueError(f"Not a directory: {abs_path}")

    entries = []
    for name in sorted(os.listdir(abs_path)):
        full = os.path.join(abs_path, name)
        entries.append({
            "name":  name,
            "type":  "dir" if os.path.isdir(full) else "file",
            "size":  os.path.getsize(full) if os.path.isfile(full) else None,
        })
    return {"path": abs_path, "entries": entries, "count": len(entries)}


# ── Handler registry ──────────────────────────────────────────────────────────
JOB_HANDLERS: dict = {
    "ping":       handle_ping,
    "checksum":   handle_checksum,
    "file_list":  handle_file_list,
    # Add more handlers here:
    # "render":   handle_render,
    # "compile":  handle_compile,
}


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


def _store_result(job_type: str, job_id: str, result: dict) -> None:
    with _results_lock:
        bucket = _results.setdefault(job_type, [])
        bucket.append({"job_id": job_id, "result": result, "time": _now()})
        if len(bucket) > MAX_RESULTS:
            bucket.pop(0)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Node discovery endpoint. Returns identity and registered job types."""
    return jsonify({
        "status":    "ok",
        "node":      NODE_ID,
        "ip":        _local_ip(),
        "jobs":      sorted(JOB_HANDLERS.keys()),
        "time":      _now(),
    })


@app.route("/job/<job_type>", methods=["POST"])
def submit_job(job_type: str):
    """
    Submit a job for immediate synchronous execution.
    Body: JSON payload passed to the job handler.
    Returns: JSON result + job_id.
    """
    if job_type not in JOB_HANDLERS:
        return jsonify({
            "error":    f"Unknown job type: '{job_type}'",
            "accepted": sorted(JOB_HANDLERS.keys()),
        }), 400

    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    payload = request.get_json(silent=True) or {}
    job_id  = str(uuid.uuid4())[:8]

    try:
        result = JOB_HANDLERS[job_type](payload)
    except ValueError as e:
        return jsonify({"error": str(e), "job_id": job_id}), 400
    except RuntimeError as e:
        return jsonify({"error": str(e), "job_id": job_id}), 500
    except Exception as e:
        return jsonify({"error": f"Unexpected: {e}", "job_id": job_id}), 500

    record = {
        "job_id":   job_id,
        "job_type": job_type,
        "node":     NODE_ID,
        "time":     _now(),
        "result":   result,
    }
    _store_result(job_type, job_id, result)

    return jsonify(record), 200


@app.route("/result/latest", methods=["GET"])
def result_latest():
    """Return the most recent result across all job types."""
    with _results_lock:
        all_results = [
            entry
            for bucket in _results.values()
            for entry in bucket
        ]
    if not all_results:
        return jsonify({"error": "no results yet"}), 404
    latest = max(all_results, key=lambda r: r["time"])
    return jsonify(latest)


@app.route("/result/<job_type>", methods=["GET"])
def result_by_type(job_type: str):
    """Return all stored results for a given job type."""
    with _results_lock:
        bucket = list(_results.get(job_type, []))
    if not bucket:
        return jsonify({"error": f"no results for '{job_type}'"}), 404
    return jsonify({"job_type": job_type, "results": bucket, "count": len(bucket)})


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Academy Node Agent")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    ip = _local_ip()
    print("=" * 60)
    print(f"The Academy - Node Agent [{NODE_ID}]")
    print("=" * 60)
    print(f"  Listening : http://{ip}:{args.port}")
    print(f"  Jobs      : {', '.join(sorted(JOB_HANDLERS.keys()))}")
    print(f"  Discovery : GET http://{ip}:{args.port}/health")
    print("=" * 60)
    app.run(host="0.0.0.0", port=args.port, debug=False)
