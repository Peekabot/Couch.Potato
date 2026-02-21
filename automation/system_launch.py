#!/usr/bin/env python3
"""
system_launch.py - CPU Heartbeat Monitor with MCMC State Estimation
====================================================================
Samples CPU load using a Markov Chain state model, then logs each
reading to a Google Sheets dashboard via the gspread API.

Usage:
    python system_launch.py                  # run with defaults
    python system_launch.py --interval 30    # sample every 30 s
    python system_launch.py --sheet "Peeka Dashboard"
"""

import argparse
import logging
import os
import random
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import psutil

try:
    import gspread
    from google.oauth2.service_account import Credentials
    SHEETS_AVAILABLE = True
except ImportError:
    SHEETS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("system_launch")

# ---------------------------------------------------------------------------
# MCMC CPU State Model
# ---------------------------------------------------------------------------

# Discrete CPU states with percentage thresholds
CPU_STATES = ["IDLE", "NORMAL", "HIGH", "CRITICAL"]
CPU_THRESHOLDS = {"IDLE": (0, 30), "NORMAL": (30, 70), "HIGH": (70, 90), "CRITICAL": (90, 100)}

# Empirical transition matrix: rows = current state, cols = next state
# Order: IDLE, NORMAL, HIGH, CRITICAL
_BASE_TRANSITIONS: Dict[str, List[float]] = {
    "IDLE":     [0.70, 0.25, 0.04, 0.01],
    "NORMAL":   [0.20, 0.55, 0.20, 0.05],
    "HIGH":     [0.05, 0.30, 0.45, 0.20],
    "CRITICAL": [0.02, 0.13, 0.35, 0.50],
}


def cpu_pct_to_state(pct: float) -> str:
    """Map a raw CPU percentage to a discrete state label."""
    for state, (lo, hi) in CPU_THRESHOLDS.items():
        if lo <= pct < hi:
            return state
    return "CRITICAL"  # 100 %


class MCMCMonitor:
    """
    Markov Chain Monte Carlo CPU monitor.

    Maintains:
      - a running Markov chain over discrete CPU states
      - an online estimate of the steady-state distribution via MC sampling
      - the empirical transition counts to allow the matrix to adapt over time
    """

    def __init__(self, warmup_steps: int = 20):
        self._state_index = {s: i for i, s in enumerate(CPU_STATES)}
        # Counts of observed transitions (smoothed with 1 pseudo-count)
        self._counts: List[List[float]] = [
            list(row) for row in
            [_BASE_TRANSITIONS[s] for s in CPU_STATES]
        ]
        self._current_state: str = "IDLE"
        self._visit_counts: Dict[str, int] = {s: 0 for s in CPU_STATES}
        self._total_steps: int = 0
        self._warmup_steps = warmup_steps

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _row_probs(self, state: str) -> List[float]:
        """Return normalised transition probabilities for *state*."""
        row = self._counts[self._state_index[state]]
        total = sum(row)
        return [v / total for v in row]

    def _sample_next_state(self, state: str) -> str:
        """Draw the next state from the Markov chain."""
        probs = self._row_probs(state)
        r = random.random()
        cumulative = 0.0
        for s, p in zip(CPU_STATES, probs):
            cumulative += p
            if r < cumulative:
                return s
        return CPU_STATES[-1]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def observe(self, pct: float) -> Tuple[str, str, Dict[str, float]]:
        """
        Record an observed CPU percentage.

        Updates the transition count matrix (online learning), advances
        the Markov chain, and returns:
          (observed_state, predicted_next_state, steady_state_distribution)
        """
        observed = cpu_pct_to_state(pct)

        # Update transition count from previous state -> observed state
        from_idx = self._state_index[self._current_state]
        to_idx = self._state_index[observed]
        self._counts[from_idx][to_idx] += 1

        # Advance the chain
        self._current_state = observed
        self._visit_counts[observed] += 1
        self._total_steps += 1

        # Predict next state from chain
        predicted_next = self._sample_next_state(observed)

        # Monte Carlo steady-state estimate (after warmup)
        steady_state = self._steady_state_estimate()

        return observed, predicted_next, steady_state

    def _steady_state_estimate(self) -> Dict[str, float]:
        """Empirical visit-frequency estimate of the steady-state distribution."""
        total = max(self._total_steps, 1)
        return {s: self._visit_counts[s] / total for s in CPU_STATES}

    @property
    def warmed_up(self) -> bool:
        return self._total_steps >= self._warmup_steps


# ---------------------------------------------------------------------------
# Google Sheets Logger
# ---------------------------------------------------------------------------

SHEETS_SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive.file",
]

# Column headers written on first use
SHEET_HEADERS = [
    "timestamp",
    "cpu_pct",
    "mem_pct",
    "observed_state",
    "predicted_next",
    "p_idle",
    "p_normal",
    "p_high",
    "p_critical",
    "hostname",
]


class SheetsLogger:
    """Appends rows to a Google Sheets worksheet."""

    def __init__(self, sheet_name: str, credentials_path: str):
        if not SHEETS_AVAILABLE:
            raise RuntimeError(
                "gspread / google-auth not installed. "
                "Run: pip install gspread google-auth"
            )
        creds = Credentials.from_service_account_file(
            credentials_path, scopes=SHEETS_SCOPES
        )
        self._gc = gspread.authorize(creds)
        self._sheet_name = sheet_name
        self._ws = self._open_or_create_worksheet()

    def _open_or_create_worksheet(self) -> "gspread.Worksheet":
        try:
            spreadsheet = self._gc.open(self._sheet_name)
        except gspread.SpreadsheetNotFound:
            spreadsheet = self._gc.create(self._sheet_name)
            log.info("Created new spreadsheet: %s", self._sheet_name)

        ws = spreadsheet.sheet1
        # Write headers if the sheet is empty
        if ws.row_count == 0 or not ws.row_values(1):
            ws.append_row(SHEET_HEADERS)
            log.info("Wrote headers to worksheet.")
        return ws

    def append(self, row: Dict[str, object]) -> None:
        """Append a dict keyed by SHEET_HEADERS column names."""
        values = [row.get(col, "") for col in SHEET_HEADERS]
        self._ws.append_row(values, value_input_option="USER_ENTERED")


# ---------------------------------------------------------------------------
# Console-only fallback logger
# ---------------------------------------------------------------------------


class ConsoleLogger:
    """Prints rows to stdout when Sheets is not configured."""

    _header_printed = False

    def append(self, row: Dict[str, object]) -> None:
        if not self._header_printed:
            print("\t".join(SHEET_HEADERS))
            ConsoleLogger._header_printed = True
        print("\t".join(str(row.get(col, "")) for col in SHEET_HEADERS))


# ---------------------------------------------------------------------------
# Sampling loop
# ---------------------------------------------------------------------------


def build_logger(args: argparse.Namespace):
    """Return a SheetsLogger if credentials are present, else ConsoleLogger."""
    creds_path = args.credentials or os.getenv("GOOGLE_CREDENTIALS_JSON")
    if creds_path and os.path.isfile(creds_path) and SHEETS_AVAILABLE:
        log.info("Google Sheets logging enabled -> %s", args.sheet)
        return SheetsLogger(args.sheet, creds_path)
    log.warning(
        "No Google credentials found; falling back to console output. "
        "Set GOOGLE_CREDENTIALS_JSON or pass --credentials to enable Sheets."
    )
    return ConsoleLogger()


def run(args: argparse.Namespace) -> None:
    monitor = MCMCMonitor(warmup_steps=args.warmup)
    logger = build_logger(args)
    hostname = os.uname().nodename

    log.info(
        "System launch monitor started | interval=%ds warmup=%d steps",
        args.interval,
        args.warmup,
    )

    while True:
        cpu_pct = psutil.cpu_percent(interval=1)
        mem_pct = psutil.virtual_memory().percent

        observed, predicted_next, steady = monitor.observe(cpu_pct)

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        row: Dict[str, object] = {
            "timestamp": timestamp,
            "cpu_pct": round(cpu_pct, 2),
            "mem_pct": round(mem_pct, 2),
            "observed_state": observed,
            "predicted_next": predicted_next,
            "p_idle": round(steady["IDLE"], 4),
            "p_normal": round(steady["NORMAL"], 4),
            "p_high": round(steady["HIGH"], 4),
            "p_critical": round(steady["CRITICAL"], 4),
            "hostname": hostname,
        }

        log.info(
            "CPU %.1f%% | MEM %.1f%% | state=%s -> next=%s | warmed_up=%s",
            cpu_pct,
            mem_pct,
            observed,
            predicted_next,
            monitor.warmed_up,
        )

        try:
            logger.append(row)
        except Exception as exc:
            log.error("Failed to log row: %s", exc)

        # Emit a warning if the chain has been in CRITICAL for too long
        if observed == "CRITICAL" and steady["CRITICAL"] > 0.5:
            log.warning(
                "CRITICAL CPU state dominates (p=%.2f). "
                "Check running processes.",
                steady["CRITICAL"],
            )

        time.sleep(max(0, args.interval - 1))  # -1 to account for cpu_percent(interval=1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="CPU heartbeat monitor with MCMC state estimation and Sheets logging."
    )
    p.add_argument(
        "--interval", type=int, default=60,
        help="Sampling interval in seconds (default: 60)",
    )
    p.add_argument(
        "--warmup", type=int, default=20,
        help="Number of steps before steady-state estimates are considered reliable (default: 20)",
    )
    p.add_argument(
        "--sheet", default="Peekabot Dashboard",
        help='Google Sheets spreadsheet name (default: "Peekabot Dashboard")',
    )
    p.add_argument(
        "--credentials",
        help="Path to Google service-account JSON (overrides GOOGLE_CREDENTIALS_JSON env var)",
    )
    return p.parse_args()


if __name__ == "__main__":
    run(parse_args())
