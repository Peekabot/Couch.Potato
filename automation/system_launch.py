#!/usr/bin/env python3
"""
system_launch.py — CPU Heartbeat Monitor with MCMC State Estimation
====================================================================
Samples CPU load via a Markov Chain state model and logs each reading
to Google Sheets (or stdout).  Temperature T=0.2 makes next-state
predictions sharp/deterministic; raise T toward 1.0 for more exploration.

Usage:
    python system_launch.py                        # defaults
    python system_launch.py --interval 30 --temperature 0.2
    python system_launch.py --sheet "Peeka Dashboard" --credentials creds.json
"""

import argparse
import json
import logging
import os
import random
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import numpy as np
import psutil

try:
    import gspread
    from google.oauth2.service_account import Credentials
    SHEETS_AVAILABLE = True
except ImportError:
    SHEETS_AVAILABLE = False

try:
    from groq import Groq as GroqClient
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

# ---------------------------------------------------------------------------
# Structured logger — emits JSON lines so Gemini @Workspace can parse them
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",          # raw JSON lines
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("system_launch")


def _jlog(level: str, event: str, **fields) -> None:
    """Emit a single JSON-line log record."""
    record = {"ts": datetime.now(timezone.utc).isoformat(), "lvl": level,
              "event": event, **fields}
    getattr(log, level.lower(), log.info)(json.dumps(record))


# ---------------------------------------------------------------------------
# Du & Do character layer
# ---------------------------------------------------------------------------

# Maps MCMC states → avatar stamina language (Dumbells & Doorknobs world)
_DU_DO: Dict[str, Dict[str, str]] = {
    "IDLE":     {"stamina": "resting",   "mood": "calm",      "symbol": "○"},
    "NORMAL":   {"stamina": "active",    "mood": "focused",   "symbol": "◑"},
    "HIGH":     {"stamina": "straining", "mood": "alert",     "symbol": "◕"},
    "CRITICAL": {"stamina": "overdrive", "mood": "max-output","symbol": "●"},
}

# Personalize hostname → character name
_CHARACTER_MAP: Dict[str, str] = {
    "macbook":      "Dumbell-Prime",
    "elitebook":    "Doorknob-Alpha",
    "pythonanywhe": "Intracrook-Node",
}

# Du & Do server class → load-tolerance modifier (+N added to NORMAL/HIGH thresholds)
# "Inventor" class hardware handles HIGH load with a +10 Con-save buffer
_SERVER_CLASS_MAP: Dict[str, str] = {
    "macbook":      "Inventor",
    "elitebook":    "Standard",
    "pythonanywhe": "Standard",
}
_CLASS_MODIFIERS: Dict[str, int] = {
    "Inventor": 10,
    "Standard": 0,
}


def _character_name(hostname: str) -> str:
    for key, name in _CHARACTER_MAP.items():
        if key in hostname.lower():
            return name
    return hostname


def _server_class(hostname: str) -> str:
    for key, cls in _SERVER_CLASS_MAP.items():
        if key in hostname.lower():
            return cls
    return "Standard"


# ---------------------------------------------------------------------------
# MCMC CPU State Model
# ---------------------------------------------------------------------------

CPU_STATES = ["IDLE", "NORMAL", "HIGH", "CRITICAL"]

# Thresholds applied to max(cpu, mem) — both resources drive state
_RESOURCE_THRESHOLDS = [
    ("IDLE",   15),
    ("NORMAL", 50),
    ("HIGH",   80),
]


def resource_to_state(cpu: float, mem: float, modifier: int = 0) -> str:
    """Maps max(cpu, mem) to Du&Do state: IDLE → CRITICAL.

    modifier is a class-based Con-save bonus applied to NORMAL and HIGH
    thresholds only — IDLE stays fixed (resting is resting regardless of class).
    """
    val = max(cpu, mem)
    thresholds = [
        ("IDLE",   15),
        ("NORMAL", 50 + modifier),
        ("HIGH",   80 + modifier),
    ]
    for state, threshold in thresholds:
        if val < threshold:
            return state
    return "CRITICAL"


class MCMCMonitor:
    """
    Markov Chain Monte Carlo monitor with temperature-scaled sampling.

    State is driven by max(cpu, mem) — whichever resource is more stressed.
    Laplace-smoothed count matrix (ones prior) eliminates the need for
    hand-coded base transitions; steady state is solved via eigendecomposition.

    temperature T=0.2  → sharp, near-deterministic next-state prediction
    temperature T=1.0  → unscaled (standard) Markov sampling
    temperature T>1.0  → exploratory / diffuse predictions
    """

    def __init__(self, warmup_steps: int = 20, temperature: float = 0.2,
                 class_modifier: int = 0):
        self._state_index = {s: i for i, s in enumerate(CPU_STATES)}
        self._counts = np.ones((4, 4))      # Laplace smoothing — uniform prior
        self._current_state: str = "IDLE"
        self._total_steps: int = 0
        self._warmup_steps = warmup_steps
        self._temperature = max(temperature, 1e-6)   # guard against division by zero
        self._class_modifier = class_modifier        # Du&Do Con-save bonus

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _row_probs(self, state: str) -> List[float]:
        row = self._counts[self._state_index[state]]
        return (row / row.sum()).tolist()

    def _sample_next_state(self, state: str) -> str:
        """Draw next state; T<1 sharpens the distribution toward the mode."""
        probs = self._row_probs(state)
        if self._temperature != 1.0:
            inv_t = 1.0 / self._temperature
            scaled = [p ** inv_t for p in probs]
            total = sum(scaled)
            probs = [p / total for p in scaled]
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

    def observe(self, cpu: float, mem: float) -> Tuple[str, str, Dict[str, float]]:
        """Record cpu+mem %, update chain, return (observed, predicted_next, steady)."""
        observed = resource_to_state(cpu, mem, self._class_modifier)
        from_idx = self._state_index[self._current_state]
        to_idx   = self._state_index[observed]
        self._counts[from_idx, to_idx] += 1

        self._current_state = observed
        self._total_steps += 1

        predicted_next = self._sample_next_state(observed)
        steady_state   = self._steady_state_estimate()
        return observed, predicted_next, steady_state

    def _steady_state_estimate(self) -> Dict[str, float]:
        """Stationary distribution π via left eigenvector of the transition matrix."""
        S = self._counts.copy()
        S /= S.sum(axis=1, keepdims=True)                # row-normalize
        try:
            eigenvals, eigenvecs = np.linalg.eig(S.T)
            mask = np.isclose(eigenvals, 1.0)
            if not mask.any():
                raise ValueError("no unit eigenvalue")
            pi = eigenvecs[:, mask].real[:, 0]
            pi = np.abs(pi) / np.abs(pi).sum()
        except Exception:
            pi = np.full(4, 0.25)                        # fallback: uniform
        return {s: float(round(pi[i], 4)) for i, s in enumerate(CPU_STATES)}

    @property
    def warmed_up(self) -> bool:
        return self._total_steps >= self._warmup_steps


# ---------------------------------------------------------------------------
# Groq LPU predictor (optional — enriches predicted_next with a narrative)
# ---------------------------------------------------------------------------

class GroqPredictor:
    """Thin wrapper around the Groq API for narrative state commentary."""

    _SYSTEM = (
        "You are a terse system oracle. Given server telemetry, "
        "respond in ≤12 words describing what the server will do next."
    )

    def __init__(self, model: str = "llama3-8b-8192"):
        if not GROQ_AVAILABLE:
            raise RuntimeError("pip install groq")
        self._client = GroqClient(api_key=os.environ["GROQ_API_KEY"])
        self._model = model

    def predict(self, observed: str, cpu: float, mem: float,
                steady: Dict[str, float]) -> str:
        prompt = (
            f"state={observed} cpu={cpu:.1f}% mem={mem:.1f}% "
            f"p_idle={steady['IDLE']:.2f} p_critical={steady['CRITICAL']:.2f}"
        )
        try:
            resp = self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "system", "content": self._SYSTEM},
                          {"role": "user",   "content": prompt}],
                max_tokens=24,
                temperature=0.2,
            )
            return resp.choices[0].message.content.strip()
        except Exception as exc:
            return f"(groq err: {exc})"


def _build_groq() -> Optional[GroqPredictor]:
    if GROQ_AVAILABLE and os.environ.get("GROQ_API_KEY"):
        try:
            return GroqPredictor()
        except Exception as exc:
            _jlog("warning", "groq_unavailable", reason=str(exc))
    return None


# ---------------------------------------------------------------------------
# Google Sheets logger
# ---------------------------------------------------------------------------

SHEETS_SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive.file",
]

SHEET_HEADERS = [
    "timestamp", "cpu_pct", "mem_pct",
    "observed_state", "predicted_next",
    "p_idle", "p_normal", "p_high", "p_critical",
    "hostname", "character", "server_class", "stamina", "groq_insight",
]


class SheetsLogger:
    def __init__(self, sheet_name: str, credentials_path: str):
        if not SHEETS_AVAILABLE:
            raise RuntimeError("pip install gspread google-auth")
        creds = Credentials.from_service_account_file(
            credentials_path, scopes=SHEETS_SCOPES)
        gc  = gspread.authorize(creds)
        try:
            ss = gc.open(sheet_name)
        except gspread.SpreadsheetNotFound:
            ss = gc.create(sheet_name)
            _jlog("info", "sheets_created", sheet=sheet_name)
        self._ws = ss.sheet1
        if not self._ws.row_values(1):
            self._ws.append_row(SHEET_HEADERS)

    def append(self, row: Dict) -> None:
        self._ws.append_row(
            [row.get(c, "") for c in SHEET_HEADERS],
            value_input_option="USER_ENTERED",
        )


class ConsoleLogger:
    _hdr = False
    def append(self, row: Dict) -> None:
        if not ConsoleLogger._hdr:
            print("\t".join(SHEET_HEADERS))
            ConsoleLogger._hdr = True
        print("\t".join(str(row.get(c, "")) for c in SHEET_HEADERS))


def _build_logger(args: argparse.Namespace):
    creds = args.credentials or os.getenv("GOOGLE_CREDENTIALS_JSON")
    if creds and os.path.isfile(creds) and SHEETS_AVAILABLE:
        _jlog("info", "sheets_enabled", sheet=args.sheet)
        return SheetsLogger(args.sheet, creds)
    _jlog("warning", "sheets_fallback", reason="no credentials")
    return ConsoleLogger()


# ---------------------------------------------------------------------------
# Main sampling loop
# ---------------------------------------------------------------------------

def run(args: argparse.Namespace) -> None:
    hostname     = os.uname().nodename
    character    = _character_name(hostname)
    srv_class    = _server_class(hostname)
    modifier     = _CLASS_MODIFIERS.get(srv_class, 0)

    monitor  = MCMCMonitor(warmup_steps=args.warmup, temperature=args.temperature,
                           class_modifier=modifier)
    logger   = _build_logger(args)
    groq     = _build_groq()

    _jlog("info", "monitor_start",
          interval=args.interval, warmup=args.warmup,
          temperature=args.temperature, hostname=hostname,
          character=character, server_class=srv_class,
          class_modifier=modifier, groq=groq is not None)

    while True:
        cpu_pct = psutil.cpu_percent(interval=1)
        mem_pct = psutil.virtual_memory().percent

        observed, predicted_next, steady = monitor.observe(cpu_pct, mem_pct)
        avatar  = _DU_DO[observed]
        stamina = avatar["stamina"]
        symbol  = avatar["symbol"]

        groq_insight = groq.predict(observed, cpu_pct, mem_pct, steady) \
                       if groq and monitor.warmed_up else ""

        row = {
            "timestamp":     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "cpu_pct":       round(cpu_pct, 2),
            "mem_pct":       round(mem_pct, 2),
            "observed_state":  observed,
            "predicted_next":  predicted_next,
            "p_idle":        round(steady["IDLE"],     4),
            "p_normal":      round(steady["NORMAL"],   4),
            "p_high":        round(steady["HIGH"],     4),
            "p_critical":    round(steady["CRITICAL"], 4),
            "hostname":      hostname,
            "character":     character,
            "server_class":  srv_class,
            "stamina":       stamina,
            "groq_insight":  groq_insight,
        }

        _jlog("info", "pulse",
              symbol=symbol, state=observed, next=predicted_next,
              cpu=cpu_pct, mem=mem_pct, stamina=stamina,
              character=character, server_class=srv_class,
              warmed_up=monitor.warmed_up, groq=groq_insight or None)

        if observed == "CRITICAL" and steady["CRITICAL"] > 0.5:
            _jlog("warning", "critical_dominant",
                  p_critical=round(steady["CRITICAL"], 3),
                  character=character)

        try:
            logger.append(row)
        except Exception as exc:
            _jlog("error", "log_failed", reason=str(exc))

        time.sleep(max(0, args.interval - 1))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="CPU heartbeat monitor — MCMC state estimation, Du & Do logging."
    )
    p.add_argument("--interval",    type=int,   default=30,
                   help="Sampling interval in seconds (default 30)")
    p.add_argument("--warmup",      type=int,   default=20,
                   help="Steps before steady-state estimates stabilize (default 20)")
    p.add_argument("--temperature", type=float, default=0.2,
                   help="Sampling temperature T (default 0.2 — sharp predictions)")
    p.add_argument("--sheet",       default="Server_MCMC_Logs",
                   help='Google Sheets name (default "Server_MCMC_Logs")')
    p.add_argument("--credentials",
                   help="Path to Google service-account JSON")
    return p.parse_args()


if __name__ == "__main__":
    run(_parse())
