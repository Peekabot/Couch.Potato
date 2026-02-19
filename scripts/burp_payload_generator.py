#!/usr/bin/env python3
"""
Burp Payload Generator for Substrate Analysis

Reads substrate analysis output and generates ready-to-use
HTTP requests for Burp Suite Repeater.

Usage:
    # Generate payloads from analysis
    python3 burp_payload_generator.py substrate_analysis_report.txt

    # Generate and copy to clipboard
    python3 burp_payload_generator.py substrate_analysis_report.txt --copy

    # Only show CRITICAL findings
    python3 burp_payload_generator.py substrate_analysis_report.txt --severity CRITICAL
"""

import re
import sys
import json
from pathlib import Path
from dataclasses import dataclass
from typing import List

try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False


@dataclass
class TestCase:
    type: str
    parameter: str
    test_value: any
    description: str


@dataclass
class Prediction:
    number: int
    severity: str
    operation_name: str
    endpoint: str
    method: str
    operation_type: str
    gap_type: str
    parameter: str
    impact: float
    cost: float
    confidence: float
    cve_class: str
    test_cases: List[TestCase]


class BurpPayloadGenerator:
    def __init__(self, report_path: str):
        self.report_path = report_path
        self.predictions = []

    def parse_report(self):
        """Parse substrate analysis report"""
        with open(self.report_path, 'r') as f:
            content = f.read()

        # Split into prediction sections
        sections = re.split(r'\n\d+\. (CRITICAL|HIGH|MEDIUM|LOW) - ', content)

        for i in range(1, len(sections), 2):
            severity = sections[i]
            section_content = sections[i + 1]

            try:
                prediction = self._parse_prediction(severity, section_content, (i // 2) + 1)
                if prediction:
                    self.predictions.append(prediction)
            except Exception as e:
                print(f"Warning: Failed to parse prediction: {e}")
                continue

    def _parse_prediction(self, severity: str, content: str, number: int) -> Prediction:
        """Parse individual prediction section"""

        # Extract operation name
        operation_match = re.search(r'^(\w+)', content)
        operation_name = operation_match.group(1) if operation_match else "unknown"

        # Extract endpoint and method
        endpoint_match = re.search(r'Endpoint: (\w+) (.+)', content)
        method = endpoint_match.group(1) if endpoint_match else "POST"
        endpoint = endpoint_match.group(2) if endpoint_match else "/unknown"

        # Extract operation type
        op_type_match = re.search(r'Operation Type: (\w+)', content)
        operation_type = op_type_match.group(1) if op_type_match else "unknown"

        # Extract gap type
        gap_match = re.search(r'Gap Type: (.+)', content)
        gap_type = gap_match.group(1) if gap_match else "unknown"

        # Extract parameter
        param_match = re.search(r'Parameter: (\w+)', content)
        parameter = param_match.group(1) if param_match else "unknown"

        # Extract metrics
        impact_match = re.search(r'Impact \(ΔS\*\): ([\d.]+)', content)
        impact = float(impact_match.group(1)) if impact_match else 0.0

        cost_match = re.search(r'Cost to Exploit: ([\d.]+)', content)
        cost = float(cost_match.group(1)) if cost_match else 0.0

        confidence_match = re.search(r'Confidence: ([\d.]+)', content)
        confidence = float(confidence_match.group(1)) if confidence_match else 0.0

        # Extract CVE class
        cve_match = re.search(r'CVE Class: (.+)', content)
        cve_class = cve_match.group(1) if cve_match else "Unknown"

        # Extract test cases
        test_cases = []
        test_case_pattern = r'- (\w+): (.+)\n\s+Parameter: (\w+) = (.+)'

        for match in re.finditer(test_case_pattern, content):
            test_type = match.group(1)
            description = match.group(2)
            param = match.group(3)
            value = match.group(4)

            # Try to parse value as number
            try:
                if '.' in value:
                    test_value = float(value)
                else:
                    test_value = int(value)
            except:
                # Keep as string, remove quotes if present
                test_value = value.strip("'\"")

            test_cases.append(TestCase(
                type=test_type,
                parameter=param,
                test_value=test_value,
                description=description
            ))

        return Prediction(
            number=number,
            severity=severity,
            operation_name=operation_name,
            endpoint=endpoint,
            method=method,
            operation_type=operation_type,
            gap_type=gap_type,
            parameter=parameter,
            impact=impact,
            cost=cost,
            confidence=confidence,
            cve_class=cve_class,
            test_cases=test_cases
        )

    def generate_http_request(self, prediction: Prediction, test_case: TestCase,
                            host: str = "api.target.com") -> str:
        """Generate HTTP request for Burp Repeater"""

        # Build request line
        request = f"{prediction.method} {prediction.endpoint} HTTP/1.1\n"
        request += f"Host: {host}\n"
        request += "Content-Type: application/json\n"
        request += "Authorization: Bearer YOUR_TOKEN_HERE\n"

        # For GET requests with path parameters
        if prediction.method == "GET":
            request += "\n"
            return request

        # For POST/PUT/PATCH with JSON body
        request += "\n"

        # Build JSON body
        body = {}

        # Add the test case parameter
        body[test_case.parameter] = test_case.test_value

        # Add common parameters based on operation type
        if prediction.operation_type == "financial":
            if "cart" in prediction.operation_name.lower():
                body.setdefault("cart_id", "YOUR_CART_ID")
                body.setdefault("currency", "USD")
            elif "payment" in prediction.operation_name.lower():
                body.setdefault("customer_id", "YOUR_CUSTOMER_ID")
                body.setdefault("payment_method_id", "pm_xxxxx")
            elif "refund" in prediction.operation_name.lower():
                body.setdefault("order_id", "ORDER_ID_HERE")

        elif prediction.operation_type == "authorization":
            if "promote" in prediction.operation_name.lower():
                body.setdefault("user_id", "YOUR_USER_ID")
            if "grant" in prediction.operation_name.lower():
                body.setdefault("permission", "PERMISSION_NAME")

        elif prediction.operation_type == "authentication":
            body.setdefault("email", "your@email.com")

        # Pretty print JSON
        request += json.dumps(body, indent=2)

        return request

    def generate_curl_command(self, prediction: Prediction, test_case: TestCase,
                             host: str = "https://api.target.com") -> str:
        """Generate curl command for testing"""

        cmd = f"curl -X {prediction.method} '{host}{prediction.endpoint}' \\\n"
        cmd += "  -H 'Content-Type: application/json' \\\n"
        cmd += "  -H 'Authorization: Bearer YOUR_TOKEN_HERE' \\\n"

        if prediction.method != "GET":
            # Build JSON body
            body = {test_case.parameter: test_case.test_value}
            cmd += f"  -d '{json.dumps(body)}'\n"

        return cmd

    def print_prediction_summary(self, prediction: Prediction):
        """Print formatted prediction summary"""
        print("=" * 80)
        print(f"PREDICTION #{prediction.number}: {prediction.severity} - {prediction.operation_name}")
        print("=" * 80)
        print(f"Endpoint:      {prediction.method} {prediction.endpoint}")
        print(f"Type:          {prediction.operation_type}")
        print(f"Gap:           {prediction.gap_type}")
        print(f"Parameter:     {prediction.parameter}")
        print(f"Impact (ΔS*):  {prediction.impact:.2f}/10")
        print(f"Confidence:    {prediction.confidence:.2f}")
        print(f"CVE Class:     {prediction.cve_class}")
        print(f"Test Cases:    {len(prediction.test_cases)}")
        print()

    def generate_payloads_interactive(self, severity_filter: str = None):
        """Interactive payload generation"""

        filtered = self.predictions
        if severity_filter:
            filtered = [p for p in self.predictions if p.severity == severity_filter]

        print(f"\n{'='*80}")
        print(f"SUBSTRATE ANALYSIS → BURP PAYLOADS")
        print(f"{'='*80}\n")

        print(f"Total predictions: {len(self.predictions)}")
        if severity_filter:
            print(f"Filtered to {severity_filter}: {len(filtered)}")

        print("\n")

        for prediction in filtered:
            self.print_prediction_summary(prediction)

            # Show each test case
            for i, test_case in enumerate(prediction.test_cases, 1):
                print(f"\n{'-'*80}")
                print(f"Test Case {i}/{len(prediction.test_cases)}: {test_case.description}")
                print(f"{'-'*80}\n")

                # Generate HTTP request
                http_request = self.generate_http_request(prediction, test_case)
                print("HTTP REQUEST (paste in Burp Repeater):")
                print("-" * 40)
                print(http_request)
                print("-" * 40)

                # Generate curl command
                curl_cmd = self.generate_curl_command(prediction, test_case)
                print("\nCURL COMMAND (for terminal testing):")
                print("-" * 40)
                print(curl_cmd)
                print("-" * 40)

                # Offer to copy
                if CLIPBOARD_AVAILABLE:
                    print("\n[1] Copy HTTP request  [2] Copy curl  [3] Skip  [q] Quit")
                    choice = input("Your choice: ").strip()

                    if choice == '1':
                        pyperclip.copy(http_request)
                        print("✓ HTTP request copied to clipboard!")
                    elif choice == '2':
                        pyperclip.copy(curl_cmd)
                        print("✓ Curl command copied to clipboard!")
                    elif choice == 'q':
                        print("\nExiting...")
                        return
                else:
                    input("\nPress Enter to continue...")

            print("\n")

    def generate_all_payloads_file(self, output_path: str, severity_filter: str = None):
        """Generate all payloads to a file"""

        filtered = self.predictions
        if severity_filter:
            filtered = [p for p in self.predictions if p.severity == severity_filter]

        with open(output_path, 'w') as f:
            f.write("="*80 + "\n")
            f.write("BURP SUITE PAYLOADS - GENERATED FROM SUBSTRATE ANALYSIS\n")
            f.write("="*80 + "\n\n")

            f.write(f"Total predictions: {len(filtered)}\n")
            f.write(f"Target: YOUR_TARGET_HERE\n")
            f.write(f"Date: {Path(self.report_path).stat().st_mtime}\n\n")

            for prediction in filtered:
                f.write("\n" + "="*80 + "\n")
                f.write(f"PREDICTION #{prediction.number}: {prediction.severity} - {prediction.operation_name}\n")
                f.write("="*80 + "\n")
                f.write(f"Endpoint:      {prediction.method} {prediction.endpoint}\n")
                f.write(f"Gap:           {prediction.gap_type}\n")
                f.write(f"Parameter:     {prediction.parameter}\n")
                f.write(f"Impact (ΔS*):  {prediction.impact:.2f}/10\n")
                f.write(f"CVE Class:     {prediction.cve_class}\n\n")

                for i, test_case in enumerate(prediction.test_cases, 1):
                    f.write(f"\nTest Case {i}: {test_case.description}\n")
                    f.write("-"*80 + "\n")
                    f.write(self.generate_http_request(prediction, test_case))
                    f.write("\n" + "-"*80 + "\n")

                f.write("\n\n")

        print(f"\n✓ Payloads saved to: {output_path}")
        print(f"  Total predictions: {len(filtered)}")
        print(f"  Total test cases: {sum(len(p.test_cases) for p in filtered)}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate Burp Suite payloads from substrate analysis"
    )
    parser.add_argument('report', help='Path to substrate analysis report')
    parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                       help='Filter by severity')
    parser.add_argument('--output', '-o', help='Save all payloads to file')
    parser.add_argument('--interactive', '-i', action='store_true',
                       help='Interactive mode with clipboard support')

    args = parser.parse_args()

    # Check if report exists
    if not Path(args.report).exists():
        print(f"Error: Report not found: {args.report}")
        sys.exit(1)

    # Create generator
    generator = BurpPayloadGenerator(args.report)

    print("Parsing substrate analysis report...")
    generator.parse_report()
    print(f"✓ Parsed {len(generator.predictions)} predictions\n")

    if not CLIPBOARD_AVAILABLE and (args.interactive or not args.output):
        print("Warning: pyperclip not installed - clipboard features disabled")
        print("Install with: pip3 install pyperclip\n")

    # Generate payloads
    if args.output:
        generator.generate_all_payloads_file(args.output, args.severity)
    else:
        generator.generate_payloads_interactive(args.severity)


if __name__ == '__main__':
    main()
