"""
Interface Calculus — Groq Decision Engine
==========================================
Uses Groq's inference API (llama-3.3-70b-versatile or similar)
to decide whether to adjust plasma load, hold, or reset, based on
live sensor readings and Reynolds number.

Groq is used (not Claude) because latency is <200ms — fast enough
for a physical control loop running at 2Hz.

Set environment variable:
    export GROQ_API_KEY="gsk_..."
"""

import os
import json
import time
from typing import Tuple

try:
    from groq import Groq
    _GROQ_SDK = True
except ImportError:
    _GROQ_SDK = False
    print("[WARN] groq package not installed. Run: pip install groq")

GROQ_MODEL   = "llama-3.3-70b-versatile"
MAX_TOKENS   = 256
TEMPERATURE  = 0.1   # low temperature — we want deterministic control decisions

SYSTEM_PROMPT = """You are a real-time controller for an interface physics experiment.
You receive sensor readings from a breadboard plasma/electrode rig and must decide how to actuate it.

Sensor context:
- voltage_V: bus voltage across the interface (V)
- current_mA: current through the plasma layer (mA)
- power_mW: instantaneous power (mW)
- temp_C: interface temperature (°C)
- reynolds: Interface Reynolds number (dimensionless, turbulence proxy)
  - < 1000: laminar (stable, good)
  - 1000–2300: transitional (monitor)
  - > 2300: turbulent (WALL EVENT — act immediately)

You must respond ONLY with a valid JSON object. No explanation, no prose.

Schema:
{
  "decision": "hold" | "reduce_load" | "increase_load" | "reset" | "plasma_burst",
  "reason": "<one short sentence>",
  "actuate": {
    "led_on": true | false,
    "relay_on": true | false,
    "blink_ms": 0-1000
  }
}

Rules:
- turbulent → "reduce_load" or "reset"; relay_on=false; led blink 500ms
- transitional → "hold" or "reduce_load"; monitor
- laminar → "hold" or "increase_load" if power is low
- temp_C > 80 → "reset" immediately regardless of Reynolds
- Never return relay_on=true when decision is "reset"
"""


class GroqDecisionEngine:
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY", "")
        self.client  = Groq(api_key=self.api_key) if _GROQ_SDK and self.api_key else None
        self._call_count = 0
        self._last_decision = "hold"

    def decide(
        self,
        voltage_V: float,
        current_mA: float,
        power_mW: float,
        temp_C: float,
        reynolds: float,
        regime: str,
    ) -> Tuple[str, dict]:
        """
        Query Groq and return (decision_string, actuation_dict).
        Falls back to rule-based logic on API failure.
        """
        if self.client is None:
            return self._rule_based(reynolds, temp_C)

        user_msg = json.dumps({
            "voltage_V":  round(voltage_V,  3),
            "current_mA": round(current_mA, 2),
            "power_mW":   round(power_mW,   2),
            "temp_C":     round(temp_C,     1),
            "reynolds":   round(reynolds,   1),
            "regime":     regime,
        })

        try:
            t0 = time.time()
            chat = self.client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_msg},
                ],
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE,
                response_format={"type": "json_object"},
            )
            latency_ms = (time.time() - t0) * 1000
            self._call_count += 1

            raw = chat.choices[0].message.content
            result = json.loads(raw)

            decision  = result.get("decision",  "hold")
            actuation = result.get("actuate",   {})
            reason    = result.get("reason",    "")

            self._last_decision = decision
            print(f"  [Groq {latency_ms:.0f}ms] {decision} — {reason}")

            return decision, actuation

        except Exception as e:
            print(f"  [Groq ERROR] {e} — falling back to rules")
            return self._rule_based(reynolds, temp_C)

    def _rule_based(self, reynolds: float, temp_C: float) -> Tuple[str, dict]:
        """Deterministic fallback — no network needed."""
        if temp_C > 80:
            return "reset", {"led_on": True, "relay_on": False, "blink_ms": 1000}
        if reynolds > 2300:
            return "reduce_load", {"led_on": True, "relay_on": False, "blink_ms": 500}
        if reynolds > 1000:
            return "hold", {"led_on": True, "relay_on": False, "blink_ms": 200}
        return "hold", {"led_on": False, "relay_on": False, "blink_ms": 0}

    @property
    def stats(self) -> dict:
        return {
            "groq_available":  self.client is not None,
            "model":           GROQ_MODEL,
            "calls":           self._call_count,
            "last_decision":   self._last_decision,
        }
