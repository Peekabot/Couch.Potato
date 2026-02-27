"""
Interface Calculus — Pythonista Aggregator
==========================================
Run on iPhone (Pythonista + Flask) or desktop.

Receives sensor packets from ESP32 nodes, computes the interface
density metric (Reynolds-analogue for plasma boundary layers),
dispatches to Groq for decisions, and returns actuation commands.

Start:
    python3 aggregator.py

Endpoints:
    POST /sensor      — ESP32 sensor packet
    GET  /status      — latest readings + Reynolds number
    GET  /log         — last N log entries (JSON)
"""

from flask import Flask, request, jsonify
import json
import math
import time
import csv
import os
import threading
from datetime import datetime
from collections import deque

# ── Import subsystems ────────────────────────────────────────────────────────

try:
    from groq_interface import GroqDecisionEngine
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    print("[WARN] groq_interface not available — running in log-only mode")

try:
    from tpu_sim import InterfaceSimulator
    TPU_AVAILABLE = True
except ImportError:
    TPU_AVAILABLE = False
    print("[WARN] tpu_sim not available — physics simulation disabled")

try:
    from telegram_reporter import TelegramReporter
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

# ── Config ───────────────────────────────────────────────────────────────────

HOST       = "0.0.0.0"
PORT       = 5050
LOG_FILE   = "interface_log.csv"
LOG_MAXLEN = 500       # in-memory ring buffer

# Interface physics constants
# Reynolds-analogue: Re_if = (V * L) / ν_if
# where V = voltage proxy for flow velocity
#       L = characteristic length (fixed for bench setup, metres)
#       ν_if = kinematic "viscosity" of the interface (derived from temp/current)
L_CHAR       = 0.01    # 1 cm — electrode gap or plasma length
REYNOLDS_WALL = 2300   # laminar→turbulent transition threshold

app = Flask(__name__)

# Shared state (thread-safe via GIL for simple reads/writes)
log_buffer: deque = deque(maxlen=LOG_MAXLEN)
latest: dict      = {}
lock = threading.Lock()

# Subsystem instances
groq_engine = GroqDecisionEngine()   if GROQ_AVAILABLE  else None
simulator   = InterfaceSimulator()   if TPU_AVAILABLE   else None
telegram    = TelegramReporter()     if TELEGRAM_AVAILABLE else None

# ── CSV logging ───────────────────────────────────────────────────────────────

def _init_csv():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "timestamp", "node",
                "voltage_V", "current_mA", "power_mW", "temp_C",
                "reynolds", "regime", "decision",
            ])

def _append_csv(row: dict):
    with open(LOG_FILE, "a", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            row["timestamp"], row.get("node", "?"),
            row.get("voltage_V"),  row.get("current_mA"),
            row.get("power_mW"),   row.get("temp_C"),
            row.get("reynolds"),   row.get("regime"),
            row.get("decision"),
        ])


# ── Interface physics ─────────────────────────────────────────────────────────

def compute_reynolds(voltage_V: float, current_mA: float, temp_C: float) -> float:
    """
    Interface Reynolds number analogue.

    We treat the plasma boundary layer as a thin viscous film:
      Re_if = (V_proxy * L) / ν_if

    V_proxy  = voltage (V) — proxy for interface "flow velocity"
    ν_if     = effective kinematic viscosity, derived from temperature
               using an Arrhenius-like relation:
               ν_if = ν_ref * exp(E_a / (k_B * T))
               simplified to: ν_if = C / (T_K^alpha)

    Power density (mW/cm²) scales the result for current loading.
    """
    T_K = temp_C + 273.15 if temp_C > -273 else 300.0
    T_K = max(T_K, 200.0)

    # Effective viscosity (arbitrary units, dimensionally consistent)
    C_visc = 1e-4
    alpha  = 1.5
    nu_if  = C_visc / (T_K ** alpha)

    reynolds = (voltage_V * L_CHAR) / max(nu_if, 1e-12)

    # Scale by current loading
    I_A = current_mA / 1000.0
    if I_A > 0:
        reynolds *= (1.0 + math.log1p(I_A * 100))

    return round(reynolds, 2)


def classify_regime(reynolds: float) -> str:
    if reynolds < 1000:
        return "laminar"
    elif reynolds < REYNOLDS_WALL:
        return "transitional"
    else:
        return "turbulent"


# ── Default actuation command ─────────────────────────────────────────────────

def _safe_actuation(decision: str, reynolds: float) -> dict:
    """
    Fallback actuation when Groq is unavailable.
    Simple threshold-based rules.
    """
    regime = classify_regime(reynolds)
    if regime == "turbulent":
        return {"led_on": True, "relay_on": True,  "blink_ms": 500}
    elif regime == "transitional":
        return {"led_on": True, "relay_on": False, "blink_ms": 200}
    else:
        return {"led_on": False, "relay_on": False, "blink_ms": 0}


# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/sensor", methods=["POST"])
def receive_sensor():
    """Accept sensor payload from ESP32, return actuation command."""
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "bad JSON"}), 400

    voltage_V  = float(data.get("voltage_V",  0.0))
    current_mA = float(data.get("current_mA", 0.0))
    power_mW   = float(data.get("power_mW",   0.0))
    temp_C     = float(data.get("temp_C",     25.0))
    node       = data.get("node", "unknown")

    # Physics
    reynolds = compute_reynolds(voltage_V, current_mA, temp_C)
    regime   = classify_regime(reynolds)

    # AI decision
    decision = "hold"
    actuation = {}
    sim_result = {}

    if groq_engine:
        decision, actuation = groq_engine.decide(
            voltage_V=voltage_V,
            current_mA=current_mA,
            power_mW=power_mW,
            temp_C=temp_C,
            reynolds=reynolds,
            regime=regime,
        )
    else:
        actuation = _safe_actuation(decision, reynolds)

    # Parallel physics simulation (non-blocking)
    if simulator:
        sim_result = simulator.step(voltage_V, current_mA, temp_C, reynolds)

    # Build log entry
    entry = {
        "timestamp":  datetime.utcnow().isoformat() + "Z",
        "node":       node,
        "voltage_V":  voltage_V,
        "current_mA": current_mA,
        "power_mW":   power_mW,
        "temp_C":     temp_C,
        "reynolds":   reynolds,
        "regime":     regime,
        "decision":   decision,
        "sim":        sim_result,
        "actuate":    actuation,
    }

    with lock:
        log_buffer.append(entry)
        latest.update(entry)

    _append_csv(entry)

    # Alert if wall crossed
    if regime == "turbulent" and telegram:
        telegram.alert(
            f"WALL CROSSED: Re={reynolds:.0f} | {node} | {temp_C:.1f}°C | {decision}"
        )

    print(
        f"[{entry['timestamp']}] {node} | "
        f"V={voltage_V:.3f}V I={current_mA:.1f}mA "
        f"T={temp_C:.1f}°C Re={reynolds:.0f} [{regime}] → {decision}"
    )

    return jsonify({"actuate": actuation, "reynolds": reynolds, "regime": regime})


@app.route("/status", methods=["GET"])
def status():
    with lock:
        return jsonify(latest)


@app.route("/log", methods=["GET"])
def log_view():
    n = int(request.args.get("n", 50))
    with lock:
        entries = list(log_buffer)[-n:]
    return jsonify(entries)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _init_csv()
    print("=" * 60)
    print("Interface Calculus — Aggregator")
    print("=" * 60)
    print(f"  Groq AI:    {'ON' if GROQ_AVAILABLE  else 'OFF (threshold fallback)'}")
    print(f"  TPU sim:    {'ON' if TPU_AVAILABLE   else 'OFF'}")
    print(f"  Telegram:   {'ON' if TELEGRAM_AVAILABLE else 'OFF'}")
    print(f"  Log file:   {LOG_FILE}")
    print(f"  Listening:  http://{HOST}:{PORT}")
    print("=" * 60)
    app.run(host=HOST, port=PORT, threaded=True)
