#!/usr/bin/env python3
"""
Log Arduino INA219 data to CSV file with real-time plotting

Usage:
    python3 log_arduino_data.py --port /dev/ttyACM0 --output baseline_dark.csv
    python3 log_arduino_data.py --port /dev/ttyACM0 --output gamma_1cm.csv --plot

Requirements:
    pip install pyserial matplotlib numpy
"""

import serial
import argparse
import sys
import time
from datetime import datetime
import signal

# Optional plotting
try:
    import matplotlib.pyplot as plt
    import matplotlib.animation as animation
    import numpy as np
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False
    print("Warning: matplotlib not available, plotting disabled")

class ArduinoLogger:
    def __init__(self, port, baudrate=115200, output_file=None, plot=False):
        self.port = port
        self.baudrate = baudrate
        self.output_file = output_file
        self.plot_enabled = plot and PLOTTING_AVAILABLE
        self.ser = None
        self.file = None
        self.running = True

        # Data storage for plotting
        self.times = []
        self.voltages = []
        self.max_points = 1000

        # Statistics
        self.sample_count = 0
        self.voltage_sum = 0
        self.voltage_sum_sq = 0

    def connect(self):
        """Connect to Arduino"""
        try:
            self.ser = serial.Serial(self.port, self.baudrate, timeout=1)
            print(f"Connected to {self.port} at {self.baudrate} baud")

            # Wait for Arduino to reset
            time.sleep(2)

            # Skip header lines
            for _ in range(5):
                line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                print(f"Header: {line}")

            return True
        except serial.SerialException as e:
            print(f"Error connecting to {self.port}: {e}")
            return False

    def open_output_file(self):
        """Open output CSV file"""
        if self.output_file:
            try:
                self.file = open(self.output_file, 'w')
                # Write CSV header
                self.file.write("timestamp,time_s,voltage_uV,current_uA,power_uW\n")
                print(f"Logging to: {self.output_file}")
                return True
            except IOError as e:
                print(f"Error opening output file: {e}")
                return False
        return True

    def update_stats(self, voltage):
        """Update running statistics"""
        self.sample_count += 1
        self.voltage_sum += voltage
        self.voltage_sum_sq += voltage**2

    def get_stats(self):
        """Get mean and standard deviation"""
        if self.sample_count == 0:
            return 0, 0

        mean = self.voltage_sum / self.sample_count
        variance = (self.voltage_sum_sq / self.sample_count) - mean**2
        std = variance**0.5 if variance > 0 else 0

        return mean, std

    def process_line(self, line):
        """Process one line of data from Arduino"""
        try:
            # Parse CSV: time_s,voltage_uV,current_uA,power_uW
            parts = line.split(',')
            if len(parts) == 4:
                time_s = float(parts[0])
                voltage_uV = float(parts[1])
                current_uA = float(parts[2])
                power_uW = float(parts[3])

                # Update statistics
                self.update_stats(voltage_uV)

                # Store for plotting
                if self.plot_enabled:
                    self.times.append(time_s)
                    self.voltages.append(voltage_uV)

                    # Keep only last N points
                    if len(self.times) > self.max_points:
                        self.times.pop(0)
                        self.voltages.pop(0)

                # Write to file with timestamp
                if self.file:
                    timestamp = datetime.now().isoformat()
                    self.file.write(f"{timestamp},{time_s},{voltage_uV},{current_uA},{power_uW}\n")
                    self.file.flush()

                # Print to console every 10 samples
                if self.sample_count % 10 == 0:
                    mean, std = self.get_stats()
                    print(f"[{self.sample_count:4d}] V={voltage_uV:8.1f} μV | Mean={mean:8.1f} μV | Std={std:6.1f} μV")

        except (ValueError, IndexError) as e:
            # Skip malformed lines
            pass

    def run(self):
        """Main logging loop"""
        if not self.connect():
            return False

        if not self.open_output_file():
            return False

        print("\nLogging started. Press Ctrl+C to stop.\n")
        print("Samples | Voltage (μV) | Mean (μV) | Std (μV)")
        print("=" * 60)

        try:
            while self.running:
                if self.ser.in_waiting:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        self.process_line(line)

        except KeyboardInterrupt:
            print("\n\nStopping...")

        finally:
            self.cleanup()

        return True

    def cleanup(self):
        """Clean up resources"""
        # Print final statistics
        mean, std = self.get_stats()
        print("\n" + "=" * 60)
        print("FINAL STATISTICS:")
        print(f"  Samples:     {self.sample_count}")
        print(f"  Mean:        {mean:.2f} μV")
        print(f"  Std Dev:     {std:.2f} μV")
        print(f"  SNR:         {abs(mean)/std:.2f}" if std > 0 else "  SNR:         N/A")
        print("=" * 60)

        # Close serial
        if self.ser and self.ser.is_open:
            self.ser.close()
            print("Serial port closed")

        # Close file
        if self.file:
            self.file.close()
            print(f"Data saved to: {self.output_file}")

    def plot_data(self):
        """Plot collected data"""
        if not PLOTTING_AVAILABLE or len(self.times) == 0:
            return

        plt.figure(figsize=(12, 6))

        # Voltage vs time
        plt.subplot(2, 1, 1)
        plt.plot(self.times, self.voltages, 'b-', alpha=0.6)
        mean, std = self.get_stats()
        plt.axhline(mean, color='r', linestyle='--', label=f'Mean = {mean:.1f} μV')
        plt.axhline(mean + 3*std, color='orange', linestyle=':', label=f'±3σ = {3*std:.1f} μV')
        plt.axhline(mean - 3*std, color='orange', linestyle=':')
        plt.xlabel('Time (s)')
        plt.ylabel('Voltage (μV)')
        plt.title('CRT Phosphor Voltage Measurement')
        plt.legend()
        plt.grid(True, alpha=0.3)

        # Histogram
        plt.subplot(2, 1, 2)
        plt.hist(self.voltages, bins=50, edgecolor='black', alpha=0.7)
        plt.axvline(mean, color='r', linestyle='--', label=f'Mean = {mean:.1f} μV')
        plt.xlabel('Voltage (μV)')
        plt.ylabel('Count')
        plt.title('Voltage Distribution')
        plt.legend()
        plt.grid(True, alpha=0.3)

        plt.tight_layout()

        # Save plot
        plot_filename = self.output_file.replace('.csv', '_plot.png') if self.output_file else 'measurement_plot.png'
        plt.savefig(plot_filename, dpi=150)
        print(f"Plot saved to: {plot_filename}")

        plt.show()


def main():
    parser = argparse.ArgumentParser(description='Log Arduino INA219 voltage measurements')
    parser.add_argument('--port', '-p', default='/dev/ttyACM0',
                        help='Serial port (default: /dev/ttyACM0)')
    parser.add_argument('--baud', '-b', type=int, default=115200,
                        help='Baud rate (default: 115200)')
    parser.add_argument('--output', '-o', required=True,
                        help='Output CSV file')
    parser.add_argument('--plot', action='store_true',
                        help='Show plot after logging (requires matplotlib)')

    args = parser.parse_args()

    logger = ArduinoLogger(
        port=args.port,
        baudrate=args.baud,
        output_file=args.output,
        plot=args.plot
    )

    success = logger.run()

    # Show plot if requested
    if success and args.plot:
        logger.plot_data()

    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
