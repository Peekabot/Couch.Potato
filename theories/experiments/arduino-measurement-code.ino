/*
 * CRT Phosphor Gamma Detection - Low Noise Voltage Measurement
 *
 * Hardware: Arduino Uno + INA219 current/voltage sensor
 * Resolution: ~4 μV (16-bit ADC)
 * Sample rate: 1 Hz (adjustable)
 *
 * Connections:
 * INA219 VIN+ --> CRT metal backing
 * INA219 VIN- --> CRT phosphor layer (or reversed based on polarity test)
 * INA219 SDA  --> Arduino A4
 * INA219 SCL  --> Arduino A5
 * INA219 VCC  --> Arduino 5V
 * INA219 GND  --> Arduino GND
 */

#include <Wire.h>
#include <Adafruit_INA219.h>

Adafruit_INA219 ina219;

// Configuration
const unsigned long SAMPLE_INTERVAL = 1000; // 1 Hz (1000 ms)
const int SAMPLES_PER_AVERAGE = 10;         // Average 10 readings
unsigned long lastSampleTime = 0;

void setup() {
  Serial.begin(115200);

  // Wait for serial connection (for logging)
  while (!Serial) {
    delay(10);
  }

  Serial.println("CRT Phosphor Gamma Detection - Voltage Monitor");
  Serial.println("===============================================");

  // Initialize INA219
  if (!ina219.begin()) {
    Serial.println("ERROR: Failed to find INA219 chip");
    while (1) { delay(10); }
  }

  // Set to high resolution mode
  // 16V range, 40mV shunt voltage range (for low currents)
  ina219.setCalibration_16V_400mA();

  Serial.println("INA219 initialized");
  Serial.println("Time(s),Voltage(uV),Current(uA),Power(uW)");

  delay(1000); // Settling time
}

void loop() {
  unsigned long currentTime = millis();

  if (currentTime - lastSampleTime >= SAMPLE_INTERVAL) {
    lastSampleTime = currentTime;

    // Take multiple samples and average (reduce noise)
    float voltage_sum = 0;
    float current_sum = 0;
    float power_sum = 0;

    for (int i = 0; i < SAMPLES_PER_AVERAGE; i++) {
      voltage_sum += ina219.getBusVoltage_V();
      current_sum += ina219.getCurrent_mA();
      power_sum += ina219.getPower_mW();
      delay(10); // Small delay between samples
    }

    // Calculate averages
    float voltage_V = voltage_sum / SAMPLES_PER_AVERAGE;
    float current_mA = current_sum / SAMPLES_PER_AVERAGE;
    float power_mW = power_sum / SAMPLES_PER_AVERAGE;

    // Convert to more useful units
    float voltage_uV = voltage_V * 1e6;  // V to μV
    float current_uA = current_mA * 1e3; // mA to μA
    float power_uW = power_mW * 1e3;     // mW to μW

    // Output CSV format: time, voltage, current, power
    Serial.print(currentTime / 1000.0, 3);
    Serial.print(",");
    Serial.print(voltage_uV, 2);
    Serial.print(",");
    Serial.print(current_uA, 2);
    Serial.print(",");
    Serial.println(power_uW, 2);
  }
}

/*
 * USAGE:
 *
 * 1. Upload this code to Arduino
 * 2. Connect INA219 to CRT phosphor as described above
 * 3. Open Serial Monitor (115200 baud)
 * 4. Data will stream in CSV format
 *
 * To log to file (Linux/Mac):
 *   screen -L /dev/ttyACM0 115200
 *   (data saved to screenlog.0)
 *
 * Or use Python script:
 *   python3 log_data.py > baseline_dark.csv
 *
 * INTERPRETING RESULTS:
 *
 * Baseline (no source):
 *   - Voltage: Should be near 0 ± 100 μV (noise floor)
 *   - Look for drift over 10 minutes (thermoelectric)
 *
 * With Am-241 gamma source:
 *   - Expected signal: 1000-10000 μV (1-10 mV)
 *   - Should be stable DC offset, not fluctuating
 *   - Current should be ~fA range (near zero for INA219)
 *
 * Signal criteria:
 *   SNR > 5  --> Real signal
 *   SNR < 2  --> Noise/artifact
 *   SNR 2-5  --> Borderline, need more averaging
 */
