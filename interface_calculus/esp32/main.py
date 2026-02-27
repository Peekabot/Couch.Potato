"""
ESP32 MicroPython Firmware — Interface Calculus Node
=====================================================
Role: WiFi bridge, sensor reader, actuator endpoint.

Hardware:
  - ESP32 DevKit (MicroPython >= 1.22)
  - INA219 on I2C (SDA=21, SCL=22) — voltage + current
  - NTC thermistor on ADC pin 34 — temperature
  - LED on GPIO 2 — actuation indicator
  - Optional relay on GPIO 5 — plasma/load trigger

Wiring (I2C):
  INA219 VCC  → 3.3V
  INA219 GND  → GND
  INA219 SDA  → GPIO 21
  INA219 SCL  → GPIO 22
  INA219 VIN+ → sense resistor / battery +
  INA219 VIN- → sense resistor / load

Wiring (thermistor voltage divider):
  3.3V → 10kΩ → GPIO34 → NTC → GND

Flash this file as main.py using:
  mpremote cp main.py :main.py
"""

import machine
import network
import urequests
import ujson
import time
import math

# ── Config ──────────────────────────────────────────────────────────────────

WIFI_SSID     = "YOUR_SSID"
WIFI_PASSWORD = "YOUR_PASSWORD"
AGGREGATOR_URL = "http://192.168.1.100:5050/sensor"   # Pythonista/desktop IP
POLL_INTERVAL  = 2.0   # seconds between readings
NODE_ID        = "esp32-node-01"

# GPIO
PIN_LED    = 2
PIN_RELAY  = 5
PIN_THERM  = 34   # ADC1 channel

# Thermistor Steinhart-Hart constants (10kΩ NTC, B=3950)
THERM_R0  = 10000   # 10kΩ at 25°C
THERM_B   = 3950
THERM_T0  = 298.15  # 25°C in Kelvin
THERM_R_SERIES = 10000  # series resistor value

# INA219 I2C address
INA219_ADDR = 0x40

# ── Hardware init ────────────────────────────────────────────────────────────

led   = machine.Pin(PIN_LED,   machine.Pin.OUT)
relay = machine.Pin(PIN_RELAY, machine.Pin.OUT)
adc   = machine.ADC(machine.Pin(PIN_THERM))
adc.atten(machine.ADC.ATTN_11DB)   # 0–3.3V range
i2c   = machine.I2C(0, scl=machine.Pin(22), sda=machine.Pin(21), freq=400000)


# ── INA219 minimal driver ────────────────────────────────────────────────────

class INA219:
    REG_CONFIG      = 0x00
    REG_SHUNT_V     = 0x01
    REG_BUS_V       = 0x02
    REG_POWER       = 0x03
    REG_CURRENT     = 0x04
    REG_CALIBRATION = 0x05

    def __init__(self, i2c, addr=0x40):
        self.i2c  = i2c
        self.addr = addr
        # 32V, 2A range; calibration = 4096 / (0.1 * 0.01) but we use raw reads
        self._write_reg(self.REG_CONFIG, 0x399F)        # 32V, 320mV shunt, 12-bit, continuous
        self._write_reg(self.REG_CALIBRATION, 4096)

    def _write_reg(self, reg, value):
        data = bytearray([reg, (value >> 8) & 0xFF, value & 0xFF])
        self.i2c.writeto(self.addr, data)

    def _read_reg(self, reg):
        self.i2c.writeto(self.addr, bytearray([reg]))
        raw = self.i2c.readfrom(self.addr, 2)
        return (raw[0] << 8) | raw[1]

    def bus_voltage_V(self):
        raw = self._read_reg(self.REG_BUS_V)
        return ((raw >> 3) * 4) / 1000.0   # LSB = 4mV

    def shunt_voltage_mV(self):
        raw = self._read_reg(self.REG_SHUNT_V)
        if raw > 32767:
            raw -= 65536
        return raw * 0.01   # LSB = 10µV → result in mV

    def current_mA(self):
        """Derived from shunt, assumes 0.1Ω shunt resistor."""
        return self.shunt_voltage_mV() / 0.1   # V=IR → I=V/R

    def power_mW(self):
        return self.bus_voltage_V() * self.current_mA()


# ── Thermistor reader ────────────────────────────────────────────────────────

def read_temperature_C():
    """Steinhart-Hart equation for NTC thermistor."""
    raw = adc.read()                           # 0–4095
    v_out = (raw / 4095.0) * 3.3              # voltage at ADC
    if v_out <= 0 or v_out >= 3.3:
        return None
    r_ntc = THERM_R_SERIES * v_out / (3.3 - v_out)
    ln_r  = math.log(r_ntc / THERM_R0)
    temp_k = 1.0 / (1.0 / THERM_T0 + ln_r / THERM_B)
    return temp_k - 273.15


# ── WiFi ─────────────────────────────────────────────────────────────────────

def wifi_connect():
    sta = network.WLAN(network.STA_IF)
    sta.active(True)
    if not sta.isconnected():
        print("Connecting to WiFi...")
        sta.connect(WIFI_SSID, WIFI_PASSWORD)
        timeout = 15
        while not sta.isconnected() and timeout > 0:
            time.sleep(1)
            timeout -= 1
            led.value(not led.value())   # blink while connecting
    if sta.isconnected():
        led.value(1)
        print("WiFi connected:", sta.ifconfig()[0])
        return True
    else:
        led.value(0)
        print("WiFi FAILED")
        return False


# ── Actuation ────────────────────────────────────────────────────────────────

def actuate(command: dict):
    """
    Execute actuation command from aggregator.
    command keys:
      led_on   : bool
      relay_on : bool
      blink_ms : int  (LED blink duration, 0 = no blink)
    """
    if command.get("led_on"):
        led.value(1)
    else:
        led.value(0)

    if command.get("relay_on"):
        relay.value(1)
    else:
        relay.value(0)

    blink_ms = command.get("blink_ms", 0)
    if blink_ms > 0:
        for _ in range(blink_ms // 100):
            led.value(not led.value())
            time.sleep_ms(100)
        led.value(0)

    print("Actuated:", command)


# ── Main loop ────────────────────────────────────────────────────────────────

def main():
    if not wifi_connect():
        machine.reset()   # hard reset and retry

    try:
        ina = INA219(i2c)
    except Exception as e:
        print("INA219 init failed:", e)
        ina = None

    while True:
        try:
            # Read sensors
            voltage_V  = ina.bus_voltage_V()    if ina else 0.0
            current_mA = ina.current_mA()       if ina else 0.0
            power_mW   = ina.power_mW()         if ina else 0.0
            temp_C     = read_temperature_C()
            if temp_C is None:
                temp_C = -999.0   # sentinel for "no reading"

            payload = {
                "node":       NODE_ID,
                "ts":         time.time(),
                "voltage_V":  round(voltage_V,  4),
                "current_mA": round(current_mA, 3),
                "power_mW":   round(power_mW,   3),
                "temp_C":     round(temp_C,     2),
            }

            print("TX:", payload)

            resp = urequests.post(
                AGGREGATOR_URL,
                data=ujson.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=5,
            )

            if resp.status_code == 200:
                cmd = resp.json()
                actuate(cmd.get("actuate", {}))
            resp.close()

        except OSError as e:
            print("Network error:", e)
            # Attempt reconnect
            wifi_connect()
        except Exception as e:
            print("Loop error:", e)

        time.sleep(POLL_INTERVAL)


main()
