#!/usr/bin/env python3
"""
Agent Runner — executes scheduled tasks for all clients.

Reads recovery/clients.json, runs each client's scheduled tasks,
saves markdown reports to reports/{client_id}/, and sends a
Telegram summary.

Usage:
    python automation/agent_runner.py --schedule nightly|weekly|monthly
"""

import os
import sys
import ssl
import json
import socket
import asyncio
import argparse
import urllib.request
from datetime import date, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from brain import ask_claude

CLIENTS_FILE = Path(__file__).parent.parent / "recovery" / "clients.json"
REPORTS_DIR  = Path(__file__).parent.parent / "reports"


# ─── TASK IMPLEMENTATIONS ─────────────────────────────────────────────────────

def check_uptime(client: dict) -> dict:
    """HTTP check — status code and response time."""
    import time
    url = client["url"]
    try:
        start = time.time()
        req = urllib.request.Request(url, headers={"User-Agent": "CouchPotato-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            elapsed_ms = int((time.time() - start) * 1000)
            return {"status": "up", "http_code": r.status, "response_ms": elapsed_ms}
    except urllib.error.HTTPError as e:
        return {"status": "error", "http_code": e.code, "error": str(e)}
    except Exception as e:
        return {"status": "down", "error": str(e)}


def check_ssl(client: dict) -> dict:
    """Check SSL certificate validity and days until expiry."""
    url = client["url"]
    try:
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=10),
            server_hostname=hostname
        ) as sock:
            cert = sock.getpeercert()
            expire_str = cert["notAfter"]  # e.g. "Mar 15 12:00:00 2026 GMT"
            expire_dt  = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left  = (expire_dt - datetime.utcnow()).days
            status     = "ok" if days_left > 14 else ("warning" if days_left > 0 else "expired")
            return {
                "status": status,
                "expires": expire_str,
                "days_remaining": days_left,
            }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def check_security_headers(client: dict) -> dict:
    """Fetch response headers and score security header coverage."""
    url = client["url"]
    watched = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CouchPotato-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            headers  = {k.lower(): v for k, v in r.headers.items()}
            present  = {h: headers[h] for h in watched if h in headers}
            missing  = [h for h in watched if h not in headers]
            return {
                "score":   f"{len(present)}/{len(watched)}",
                "present": present,
                "missing": missing,
            }
    except Exception as e:
        return {"error": str(e)}


# Task name → function mapping.  Add new tasks here.
TASK_REGISTRY = {
    "uptime_check":    check_uptime,
    "ssl_check":       check_ssl,
    "header_analysis": check_security_headers,
}


# ─── AI ANALYSIS ──────────────────────────────────────────────────────────────

async def run_ai_analysis(client: dict, results: dict, schedule: str) -> str:
    prompt = f"""You are reviewing automated monitoring results for a client website.

Client:   {client['name']}
URL:      {client['url']}
Schedule: {schedule}
Date:     {date.today().isoformat()}

Results:
{json.dumps(results, indent=2)}

Write a brief, actionable summary (3-5 bullet points). Flag anything that needs \
immediate attention. Be direct and specific."""
    return await ask_claude(prompt)


# ─── REPORTING ────────────────────────────────────────────────────────────────

def save_report(client_id: str, schedule: str, content: str) -> Path:
    report_dir = REPORTS_DIR / client_id
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"{date.today().isoformat()}-{schedule}.md"
    path.write_text(content)
    return path


def send_telegram(token: str, chat_id: str, message: str) -> None:
    body = json.dumps({
        "chat_id":    chat_id,
        "text":       message,
        "parse_mode": "Markdown",
    }).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=10)


# ─── PER-CLIENT RUNNER ────────────────────────────────────────────────────────

async def run_client(client: dict, schedule: str) -> str | None:
    """Run all tasks for one client on the given schedule. Returns report text."""
    tasks_to_run = client.get("schedule", {}).get(schedule, [])
    if not tasks_to_run:
        return None

    print(f"  [{client['id']}] Running: {', '.join(tasks_to_run)}")

    results = {}
    for task_name in tasks_to_run:
        if task_name not in TASK_REGISTRY:
            results[task_name] = {"error": f"Unknown task '{task_name}'"}
            continue
        try:
            results[task_name] = TASK_REGISTRY[task_name](client)
        except Exception as e:
            results[task_name] = {"error": str(e)}

    # AI narrative if Claude is available
    analysis = ""
    if os.getenv("ANTHROPIC_API_KEY"):
        try:
            analysis = await run_ai_analysis(client, results, schedule)
        except Exception as e:
            analysis = f"(AI analysis unavailable: {e})"

    lines = [
        f"# {client['name']} — {schedule.capitalize()} Report",
        f"",
        f"**Date:** {date.today().isoformat()}  ",
        f"**URL:** {client['url']}  ",
        f"**Schedule:** {schedule}",
        f"",
        f"## Raw Results",
        f"```json",
        json.dumps(results, indent=2),
        f"```",
    ]
    if analysis:
        lines += ["", "## Analysis", "", analysis]

    return "\n".join(lines)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

async def main(schedule: str) -> None:
    if not CLIENTS_FILE.exists():
        print(f"ERROR: clients file not found: {CLIENTS_FILE}")
        sys.exit(1)

    with open(CLIENTS_FILE) as f:
        clients = json.load(f)["clients"]

    telegram_token   = os.getenv("TELEGRAM_TOKEN")
    telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID")

    print(f"CouchPotato Agent — {schedule} run — {date.today().isoformat()}")
    print(f"Clients loaded: {len(clients)}")

    reports = []
    for client in clients:
        report_text = await run_client(client, schedule)
        if report_text is None:
            print(f"  [{client['id']}] No {schedule} tasks configured — skipping")
            continue
        path = save_report(client["id"], schedule, report_text)
        print(f"  [{client['id']}] Saved: {path}")
        reports.append((client, path))

    if not reports:
        print(f"No clients have tasks configured for '{schedule}' schedule.")
        return

    # Telegram summary
    if telegram_token and telegram_chat_id:
        lines = [f"*CouchPotato {schedule.capitalize()} Run* — {date.today().isoformat()}\n"]
        for client, path in reports:
            lines.append(f"• {client['name']}: `{path.name}`")
        try:
            send_telegram(telegram_token, telegram_chat_id, "\n".join(lines))
            print("Telegram notification sent.")
        except Exception as e:
            print(f"Telegram notification failed: {e}")
    else:
        print("Telegram not configured — skipping notification.")

    print(f"Done. {len(reports)} report(s) generated.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run scheduled agent tasks")
    parser.add_argument(
        "--schedule",
        choices=["nightly", "weekly", "monthly"],
        required=True,
        help="Which schedule cadence to run",
    )
    args = parser.parse_args()
    asyncio.run(main(args.schedule))
