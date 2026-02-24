"""
The Academy - Job Queue Orchestrator
======================================
Runs on the iPhone (Pythonista or iSH). Discovers compute nodes on the
hotspot LAN, dispatches jobs with exponential-backoff retry, and writes
results back to the file-based message bus.

Usage:
    # Discover nodes on hotspot (default: 192.168.0.0/24)
    python3 job_queue.py discover

    # Submit a job to a specific node
    python3 job_queue.py submit --node 192.168.0.101 --type ping

    # Submit a job to any available node (auto-select)
    python3 job_queue.py submit --type checksum --payload '{"content":"hello"}'

    # Collect latest result from all known nodes
    python3 job_queue.py collect

    # Run the queue processor (drain bus/jobs/pending/ continuously)
    python3 job_queue.py run

Notes:
    - Node registry is persisted to bus/nodes.json
    - Jobs are files in bus/jobs/pending/, moved to running/ then done/
    - Results land in bus/results/<job_id>.json
    - Retry: up to 4 attempts with backoff 2s, 4s, 8s, 16s
"""

import os
import sys
import json
import time
import uuid
import shutil
import socket
import datetime
import argparse
import threading

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass  # stdlib, always available

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUS_DIR     = os.path.join(BASE_DIR, "bus")
JOBS_DIR    = os.path.join(BUS_DIR, "jobs")
PENDING_DIR = os.path.join(JOBS_DIR, "pending")
RUNNING_DIR = os.path.join(JOBS_DIR, "running")
DONE_DIR    = os.path.join(JOBS_DIR, "done")
RESULTS_DIR = os.path.join(BUS_DIR, "results")
NODES_FILE  = os.path.join(BUS_DIR, "nodes.json")
LOG_FILE    = os.path.join(BUS_DIR, "queue.log")

NODE_PORT    = 4444
SCAN_TIMEOUT = 1.0    # seconds per host during discovery
MAX_RETRIES  = 4
BACKOFF_BASE = 2      # seconds; actual delays: 2, 4, 8, 16


# ── Logging ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.datetime.utcnow().isoformat()


def _log(msg: str) -> None:
    line = f"[{_now()}] {msg}"
    print(line)
    os.makedirs(BUS_DIR, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


# ── HTTP helpers (no requests library; stdlib only for iSH compat) ────────────

def _http_get(url: str, timeout: float = 5.0) -> dict:
    """GET url → parsed JSON dict. Raises on network or HTTP error."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _http_post(url: str, payload: dict, timeout: float = 10.0) -> dict:
    """POST JSON payload → parsed JSON dict. Raises on network or HTTP error."""
    body = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _http_post_with_retry(url: str, payload: dict) -> dict:
    """
    POST with exponential-backoff retry.
    Retries on connection errors and HTTP 5xx responses.
    Raises RuntimeError after MAX_RETRIES exhausted.
    """
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = _http_post(url, payload)
            return result
        except urllib.error.HTTPError as e:
            if e.code < 500:
                raise   # 4xx = caller error, don't retry
            last_err = f"HTTP {e.code}"
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            last_err = str(e)

        if attempt < MAX_RETRIES:
            wait = BACKOFF_BASE ** attempt   # 2, 4, 8, 16
            _log(f"  Retry {attempt}/{MAX_RETRIES} in {wait}s — {last_err}")
            time.sleep(wait)

    raise RuntimeError(f"Failed after {MAX_RETRIES} attempts: {last_err}")


# ── Node registry ─────────────────────────────────────────────────────────────

def _load_nodes() -> dict:
    if os.path.exists(NODES_FILE):
        with open(NODES_FILE) as f:
            return json.load(f)
    return {}


def _save_nodes(nodes: dict) -> None:
    os.makedirs(BUS_DIR, exist_ok=True)
    with open(NODES_FILE, "w") as f:
        json.dump(nodes, f, indent=2)


def _probe_node(ip: str, port: int = NODE_PORT) -> dict | None:
    """
    Check if a node agent is running at ip:port.
    Returns the /health response dict or None.
    """
    try:
        url  = f"http://{ip}:{port}/health"
        data = _http_get(url, timeout=SCAN_TIMEOUT)
        if data.get("status") == "ok":
            return data
    except Exception:
        pass
    return None


def cmd_discover(subnet: str = "192.168.0") -> None:
    """
    Scan a /24 subnet for Academy node agents.
    Stores live nodes to bus/nodes.json.

    Uses threads to scan all 254 hosts concurrently.
    """
    _log(f"Scanning {subnet}.1-254 on port {NODE_PORT} ...")
    found: dict = {}
    lock = threading.Lock()

    def _scan(ip: str) -> None:
        result = _probe_node(ip)
        if result:
            with lock:
                found[ip] = {
                    "node":       result.get("node", ip),
                    "jobs":       result.get("jobs", []),
                    "last_seen":  _now(),
                }
                _log(f"  Found node: {ip}  ({result.get('node', '?')})")

    threads = [
        threading.Thread(target=_scan, args=(f"{subnet}.{i}",), daemon=True)
        for i in range(1, 255)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=SCAN_TIMEOUT + 1)

    existing = _load_nodes()
    existing.update(found)
    _save_nodes(existing)
    _log(f"Discovery complete. {len(found)} new node(s). Total: {len(existing)}.")
    print(json.dumps(found, indent=2))


# ── Job lifecycle ─────────────────────────────────────────────────────────────

def _make_job(job_type: str, payload: dict, target_node: str | None = None) -> dict:
    return {
        "job_id":      str(uuid.uuid4())[:8],
        "job_type":    job_type,
        "payload":     payload,
        "target_node": target_node,   # None = auto-select
        "created_at":  _now(),
        "attempts":    0,
        "status":      "pending",
    }


def _write_job(job: dict, state: str) -> str:
    dirs = {"pending": PENDING_DIR, "running": RUNNING_DIR, "done": DONE_DIR}
    dest_dir = dirs[state]
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, f"{job['job_id']}.json")
    with open(path, "w") as f:
        json.dump(job, f, indent=2)
    return path


def _move_job(job: dict, from_state: str, to_state: str) -> None:
    dirs = {"pending": PENDING_DIR, "running": RUNNING_DIR, "done": DONE_DIR}
    src  = os.path.join(dirs[from_state], f"{job['job_id']}.json")
    dst  = os.path.join(dirs[to_state],   f"{job['job_id']}.json")
    os.makedirs(dirs[to_state], exist_ok=True)
    if os.path.exists(src):
        shutil.move(src, dst)


def _write_result(job: dict, result: dict) -> None:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, f"{job['job_id']}.json")
    record = {
        "job_id":    job["job_id"],
        "job_type":  job["job_type"],
        "node":      job.get("target_node"),
        "completed": _now(),
        "result":    result,
    }
    with open(path, "w") as f:
        json.dump(record, f, indent=2)
    _log(f"  Result written: {path}")


def _select_node(job_type: str, prefer: str | None = None) -> str | None:
    nodes = _load_nodes()
    if prefer and prefer in nodes:
        return prefer
    # First node that supports the requested job type
    for ip, meta in nodes.items():
        if job_type in meta.get("jobs", []):
            return ip
    # Fallback: any node
    return next(iter(nodes), None)


def _execute_job(job: dict) -> dict:
    """
    Dispatch a single job to a node. Returns the result dict.
    Raises RuntimeError on failure.
    """
    node_ip = job.get("target_node") or _select_node(job["job_type"])
    if not node_ip:
        raise RuntimeError("No available node for job type: " + job["job_type"])

    job["target_node"] = node_ip
    url    = f"http://{node_ip}:{NODE_PORT}/job/{job['job_type']}"
    _log(f"  Dispatching job {job['job_id']} ({job['job_type']}) → {node_ip}")
    return _http_post_with_retry(url, job["payload"])


# ── CLI commands ──────────────────────────────────────────────────────────────

def cmd_submit(job_type: str, payload: dict, node: str | None = None) -> None:
    """Submit a job immediately and print the result."""
    job = _make_job(job_type, payload, target_node=node)
    _write_job(job, "pending")
    _log(f"Job queued: {job['job_id']} ({job_type})")

    _move_job(job, "pending", "running")
    job["status"]   = "running"
    job["attempts"] = 1

    try:
        result = _execute_job(job)
        job["status"] = "done"
        _move_job(job, "running", "done")
        _write_result(job, result)
        print(json.dumps(result, indent=2))
    except RuntimeError as e:
        job["status"] = "failed"
        job["error"]  = str(e)
        _move_job(job, "running", "done")
        _log(f"Job {job['job_id']} FAILED: {e}")
        sys.exit(1)


def cmd_collect() -> None:
    """Pull latest result from every known node and print a summary."""
    nodes = _load_nodes()
    if not nodes:
        _log("No nodes registered. Run: python3 job_queue.py discover")
        return

    summary = {}
    for ip in nodes:
        try:
            url    = f"http://{ip}:{NODE_PORT}/result/latest"
            result = _http_get(url, timeout=5.0)
            summary[ip] = result
            _log(f"  {ip}: {result.get('job_type')} @ {result.get('time', '?')}")
        except Exception as e:
            summary[ip] = {"error": str(e)}
            _log(f"  {ip}: unreachable ({e})")

    print(json.dumps(summary, indent=2))


def cmd_run(poll_interval: float = 2.0) -> None:
    """
    Continuously drain pending jobs from bus/jobs/pending/.
    Ctrl-C to stop.
    """
    _log("Queue processor started. Watching bus/jobs/pending/ ...")
    try:
        while True:
            pending = sorted(
                f for f in os.listdir(PENDING_DIR)
                if f.endswith(".json") and not f.startswith(".")
            ) if os.path.isdir(PENDING_DIR) else []

            for filename in pending:
                path = os.path.join(PENDING_DIR, filename)
                try:
                    with open(path) as f:
                        job = json.load(f)
                except (json.JSONDecodeError, OSError):
                    continue

                _move_job(job, "pending", "running")
                job["status"]   = "running"
                job["attempts"] = job.get("attempts", 0) + 1

                try:
                    result = _execute_job(job)
                    job["status"] = "done"
                    _move_job(job, "running", "done")
                    _write_result(job, result)
                except RuntimeError as e:
                    job["status"] = "failed"
                    job["error"]  = str(e)
                    _move_job(job, "running", "done")
                    _log(f"Job {job.get('job_id')} FAILED: {e}")

            time.sleep(poll_interval)
    except KeyboardInterrupt:
        _log("Queue processor stopped.")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Academy Job Queue")
    sub    = parser.add_subparsers(dest="cmd", required=True)

    # discover
    p_disc = sub.add_parser("discover", help="Scan LAN for node agents")
    p_disc.add_argument("--subnet", default="192.168.0",
                        help="First 3 octets, e.g. 192.168.1 (default: 192.168.0)")

    # submit
    p_sub = sub.add_parser("submit", help="Submit a job")
    p_sub.add_argument("--type",    required=True, help="Job type (e.g. ping)")
    p_sub.add_argument("--node",    default=None,  help="Target node IP (auto if omitted)")
    p_sub.add_argument("--payload", default="{}",  help="JSON payload string")

    # collect
    sub.add_parser("collect", help="Pull latest result from all nodes")

    # run
    p_run = sub.add_parser("run", help="Run queue processor daemon")
    p_run.add_argument("--interval", type=float, default=2.0,
                       help="Poll interval in seconds (default: 2)")

    args = parser.parse_args()

    if args.cmd == "discover":
        cmd_discover(args.subnet)
    elif args.cmd == "submit":
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError as e:
            sys.exit(f"Invalid --payload JSON: {e}")
        cmd_submit(args.type, payload, node=args.node)
    elif args.cmd == "collect":
        cmd_collect()
    elif args.cmd == "run":
        cmd_run(poll_interval=args.interval)
