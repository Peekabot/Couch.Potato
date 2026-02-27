"""
Interface Calculus — Telegram Reporter
=======================================
Sends wall-crossing alerts and periodic status summaries
to a Telegram chat using the Bot API.

Setup:
  1. Create a bot via @BotFather → get TELEGRAM_BOT_TOKEN
  2. Get your chat ID via @userinfobot → set TELEGRAM_CHAT_ID

Environment variables:
  TELEGRAM_BOT_TOKEN  — bot token (e.g. "123456:ABC-...")
  TELEGRAM_CHAT_ID    — chat or group ID (e.g. "-100123456789")

Rate limiting: max 1 alert per 10 seconds to avoid flood.
"""

import os
import time
import threading
from typing import Optional

try:
    import requests as _requests
    _HTTP = True
except ImportError:
    _HTTP = False
    print("[telegram] requests not installed — alerts silenced")

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID",   "")
API_BASE  = f"https://api.telegram.org/bot{BOT_TOKEN}"

RATE_LIMIT_S     = 10.0    # minimum seconds between alerts
SUMMARY_INTERVAL = 300.0   # status summary every 5 minutes


class TelegramReporter:
    def __init__(self):
        self._last_alert_time  = 0.0
        self._alert_count      = 0
        self._last_summary_time = time.time()
        self._lock = threading.Lock()

        if not BOT_TOKEN or not CHAT_ID:
            print("[telegram] BOT_TOKEN or CHAT_ID not set — reporter inactive")
            self._active = False
        elif not _HTTP:
            self._active = False
        else:
            self._active = True

    def _send(self, text: str) -> bool:
        """POST a message to the Telegram Bot API (non-blocking via thread)."""
        if not self._active:
            return False

        def _post():
            try:
                resp = _requests.post(
                    f"{API_BASE}/sendMessage",
                    json={"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown"},
                    timeout=5,
                )
                if resp.status_code != 200:
                    print(f"[telegram] API error {resp.status_code}: {resp.text[:80]}")
            except Exception as e:
                print(f"[telegram] send failed: {e}")

        t = threading.Thread(target=_post, daemon=True)
        t.start()
        return True

    def alert(self, message: str):
        """Send a rate-limited alert."""
        now = time.time()
        with self._lock:
            if now - self._last_alert_time < RATE_LIMIT_S:
                return
            self._last_alert_time = now
            self._alert_count    += 1

        text = f"🔴 *INTERFACE ALERT* #{self._alert_count}\n`{message}`"
        self._send(text)
        print(f"[telegram] ALERT: {message}")

    def status(self, data: dict):
        """Send a periodic status summary."""
        now = time.time()
        with self._lock:
            if now - self._last_summary_time < SUMMARY_INTERVAL:
                return
            self._last_summary_time = now

        Re     = data.get("reynolds",   "?")
        regime = data.get("regime",     "?")
        V      = data.get("voltage_V",  "?")
        T      = data.get("temp_C",     "?")
        dec    = data.get("decision",   "?")
        sim_t  = data.get("sim", {}).get("sim_t_s", "?")
        wall   = data.get("sim", {}).get("wall_strength", "?")

        text = (
            f"📊 *Interface Status*\n"
            f"Re = `{Re}` ({regime})\n"
            f"V = `{V}` V  |  T = `{T}` °C\n"
            f"Decision: `{dec}`\n"
            f"Sim time: `{sim_t}` s  |  Wall: `{wall}`"
        )
        self._send(text)

    def send_raw(self, text: str):
        """Send arbitrary message (no rate limit)."""
        self._send(text)

    @property
    def active(self) -> bool:
        return self._active
