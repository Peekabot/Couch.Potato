# Interface Calculus — Physical Loop

The smallest complete implementation of Interface Calculus:

```
Breadboard → ESP32 → Pythonista aggregator → Groq → TPU sim → ESP32
                                           ↘ Telegram
                                           ↘ interface_log.csv
```

---

## Files

| File | Role |
|---|---|
| `esp32/main.py` | MicroPython firmware — sensor read + HTTP POST + actuate |
| `aggregator.py` | Flask server — Reynolds calc, Groq dispatch, log |
| `groq_interface.py` | Groq LLM decision engine (llama-3.3-70b) |
| `tpu_sim.py` | 1D advection-diffusion interface physics simulator |
| `telegram_reporter.py` | Wall-crossing alerts + periodic status |

---

## Hardware

| Micro | Role | Interface |
|---|---|---|
| ESP32 DevKit | WiFi bridge, sensor read | HTTP → Pythonista |
| RPi Pico | ADC for battery/thermistors | Serial over USB |
| Arduino Uno | Plasma trigger, PWM | GPIO via breadboard |
| ATTiny85 | Low-power backup sensor | I2C → ESP32 |

**ESP32 wiring:**
- INA219 SDA → GPIO 21, SCL → GPIO 22 (I2C voltage/current)
- NTC thermistor + 10kΩ divider → GPIO 34 (ADC temperature)
- LED → GPIO 2 (actuation indicator)
- Relay → GPIO 5 (plasma/load trigger)

---

## Setup

### 1. Desktop / Pythonista aggregator

```bash
pip install -r requirements.txt
export GROQ_API_KEY="gsk_..."
export TELEGRAM_BOT_TOKEN="123456:ABC-..."
export TELEGRAM_CHAT_ID="-100123456789"
python3 aggregator.py
```

### 2. ESP32 firmware

Edit `esp32/main.py`:
```python
WIFI_SSID      = "your_network"
WIFI_PASSWORD  = "your_password"
AGGREGATOR_URL = "http://YOUR_MACHINE_IP:5050/sensor"
```

Flash with `mpremote`:
```bash
pip install mpremote
mpremote connect /dev/ttyUSB0 cp esp32/main.py :main.py
mpremote connect /dev/ttyUSB0 reset
```

### 3. Verify the loop

```bash
# Watch aggregator output
python3 aggregator.py

# Inject a test packet (no hardware)
curl -X POST http://localhost:5050/sensor \
  -H "Content-Type: application/json" \
  -d '{"node":"test","voltage_V":2.5,"current_mA":50,"power_mW":125,"temp_C":45}'

# Check status
curl http://localhost:5050/status

# View last 10 log entries
curl http://localhost:5050/log?n=10
```

---

## The Physics

**Interface Reynolds number:**

```
Re_if = (V · L) / ν_if(T)
```

- `V` — bus voltage (proxy for interface flow velocity)
- `L` — 0.01 m (electrode gap / plasma length)
- `ν_if(T)` — effective kinematic viscosity, temperature-dependent

| Re range | Regime | Action |
|---|---|---|
| < 1000 | laminar | hold / increase load |
| 1000–2300 | transitional | monitor |
| > 2300 | **turbulent** | reduce load / reset + Telegram alert |

**1D simulator** (`tpu_sim.py`) solves:

```
∂φ/∂t = −u ∂φ/∂x + D ∂²φ/∂x²
```

Wall events appear as sharp gradients in φ near x = L/2.

---

## Loop timing

| Stage | Latency |
|---|---|
| ESP32 sample + POST | ~100 ms |
| Flask receipt + Reynolds | <1 ms |
| Groq decision (llama-3.3-70b) | ~150 ms |
| TPU sim (50 steps, numpy) | ~5 ms |
| Telegram alert (async) | non-blocking |
| Total round-trip | ~300 ms |

**Effective loop rate: ~2–3 Hz** — fast enough for plasma boundary control.

---

## TPU / JAX acceleration

Set `USE_JAX=1` and install JAX to run the simulator on GPU/TPU:

```bash
pip install jax[cuda12]   # NVIDIA GPU
USE_JAX=1 python3 aggregator.py
```

The simulator is structured as a pure-numpy computation; switching to JAX
requires only importing `jax.numpy` instead of `numpy`, which the code
handles automatically.
