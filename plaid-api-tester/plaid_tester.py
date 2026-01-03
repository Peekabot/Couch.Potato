#!/usr/bin/env python3
"""
Plaid API Security Tester
A tool for testing Plaid API implementations for common security vulnerabilities.

This is for authorized security testing and bug bounty purposes only.
"""

import os
import sys
import json
import time
import argparse
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin


class PlaidAPITester:
    """Security testing framework for Plaid API implementations."""

    def __init__(self, config_file: str = "config.json"):
        """Initialize the tester with configuration."""
        self.config = self.load_config(config_file)
        self.session = requests.Session()
        self.results = []
        self.base_url = self.config.get("base_url", "https://sandbox.plaid.com")
        self.client_id = self.config.get("client_id", "")
        self.secret = self.config.get("secret", "")
        self.access_token = None

    def load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file."""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[!] Config file {config_file} not found. Using defaults.")
            return {}
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing config file: {e}")
            return {}

    def log_result(self, test_name: str, status: str, severity: str,
                   details: str, response: Optional[Dict] = None):
        """Log test results."""
        result = {
            "timestamp": datetime.now().isoformat(),
            "test": test_name,
            "status": status,
            "severity": severity,
            "details": details,
            "response": response
        }
        self.results.append(result)

        # Color coding for terminal output
        colors = {
            "CRITICAL": "\033[91m",
            "HIGH": "\033[91m",
            "MEDIUM": "\033[93m",
            "LOW": "\033[92m",
            "INFO": "\033[94m",
            "RESET": "\033[0m"
        }

        color = colors.get(severity, colors["RESET"])
        print(f"{color}[{severity}] {test_name}: {status}{colors['RESET']}")
        if details:
            print(f"  └─ {details}")

    def test_authentication(self) -> bool:
        """Test basic authentication with Plaid API."""
        print("\n=== Testing Authentication ===")

        # Test 1: Valid credentials
        try:
            response = requests.post(
                urljoin(self.base_url, "/item/get"),
                json={
                    "client_id": self.client_id,
                    "secret": self.secret
                },
                timeout=10
            )

            if response.status_code == 200:
                self.log_result(
                    "Valid Credentials",
                    "PASSED",
                    "INFO",
                    "Authentication successful with valid credentials"
                )
            else:
                self.log_result(
                    "Valid Credentials",
                    "FAILED",
                    "HIGH",
                    f"Authentication failed: {response.status_code}",
                    response.json()
                )
                return False

        except Exception as e:
            self.log_result(
                "Valid Credentials",
                "ERROR",
                "HIGH",
                f"Exception during authentication: {str(e)}"
            )
            return False

        # Test 2: Invalid credentials
        response = requests.post(
            urljoin(self.base_url, "/item/get"),
            json={
                "client_id": "invalid",
                "secret": "invalid"
            },
            timeout=10
        )

        if response.status_code == 401 or response.status_code == 400:
            self.log_result(
                "Invalid Credentials Rejection",
                "PASSED",
                "INFO",
                "Invalid credentials properly rejected"
            )
        else:
            self.log_result(
                "Invalid Credentials Rejection",
                "VULNERABLE",
                "CRITICAL",
                f"Invalid credentials not rejected properly: {response.status_code}",
                response.json()
            )

        return True

    def test_rate_limiting(self):
        """Test rate limiting implementation."""
        print("\n=== Testing Rate Limiting ===")

        endpoint = urljoin(self.base_url, "/item/get")
        requests_sent = 0
        rate_limited = False

        for i in range(100):
            try:
                response = requests.post(
                    endpoint,
                    json={
                        "client_id": self.client_id,
                        "secret": self.secret
                    },
                    timeout=5
                )
                requests_sent += 1

                if response.status_code == 429:
                    rate_limited = True
                    self.log_result(
                        "Rate Limiting",
                        "PASSED",
                        "INFO",
                        f"Rate limiting activated after {requests_sent} requests"
                    )
                    break

                time.sleep(0.1)

            except Exception as e:
                break

        if not rate_limited:
            self.log_result(
                "Rate Limiting",
                "VULNERABLE",
                "MEDIUM",
                f"No rate limiting detected after {requests_sent} requests"
            )

    def test_idor_vulnerabilities(self):
        """Test for Insecure Direct Object References."""
        print("\n=== Testing IDOR Vulnerabilities ===")

        # Test with manipulated access tokens
        test_tokens = [
            "access-sandbox-valid",
            "access-sandbox-invalid",
            "../../../access-token",
            "access-production-token",
            "' OR '1'='1",
            "'; DROP TABLE users--"
        ]

        for token in test_tokens:
            try:
                response = requests.post(
                    urljoin(self.base_url, "/accounts/get"),
                    json={
                        "client_id": self.client_id,
                        "secret": self.secret,
                        "access_token": token
                    },
                    timeout=10
                )

                if response.status_code == 200:
                    self.log_result(
                        f"IDOR Test: {token[:30]}...",
                        "VULNERABLE",
                        "CRITICAL",
                        f"Unauthorized access with token: {token}",
                        response.json()
                    )
                elif response.status_code in [401, 400]:
                    self.log_result(
                        f"IDOR Test: {token[:30]}...",
                        "PASSED",
                        "INFO",
                        "Properly rejected invalid token"
                    )

            except Exception as e:
                self.log_result(
                    f"IDOR Test: {token[:30]}...",
                    "ERROR",
                    "LOW",
                    f"Exception: {str(e)}"
                )

    def test_account_linking(self):
        """Test account linking security."""
        print("\n=== Testing Account Linking Security ===")

        # Test public token exchange
        test_public_tokens = [
            "public-sandbox-test",
            "../../../etc/passwd",
            "public-' OR '1'='1",
            "public-<script>alert(1)</script>"
        ]

        for public_token in test_public_tokens:
            try:
                response = requests.post(
                    urljoin(self.base_url, "/item/public_token/exchange"),
                    json={
                        "client_id": self.client_id,
                        "secret": self.secret,
                        "public_token": public_token
                    },
                    timeout=10
                )

                if response.status_code == 200:
                    self.log_result(
                        f"Public Token Exchange: {public_token[:30]}...",
                        "VULNERABLE",
                        "CRITICAL",
                        f"Invalid public token accepted: {public_token}",
                        response.json()
                    )
                elif response.status_code in [400, 401]:
                    self.log_result(
                        f"Public Token Exchange: {public_token[:30]}...",
                        "PASSED",
                        "INFO",
                        "Invalid public token properly rejected"
                    )

            except Exception as e:
                self.log_result(
                    f"Public Token Exchange: {public_token[:30]}...",
                    "ERROR",
                    "LOW",
                    f"Exception: {str(e)}"
                )

    def test_transaction_manipulation(self):
        """Test for transaction data manipulation vulnerabilities."""
        print("\n=== Testing Transaction Manipulation ===")

        # Test date range manipulation
        malicious_dates = [
            {"start": "1900-01-01", "end": "2100-12-31"},
            {"start": "' OR '1'='1", "end": "2024-01-01"},
            {"start": "2024-01-01", "end": "../../../etc/passwd"},
            {"start": "-1", "end": "999999"}
        ]

        for dates in malicious_dates:
            try:
                response = requests.post(
                    urljoin(self.base_url, "/transactions/get"),
                    json={
                        "client_id": self.client_id,
                        "secret": self.secret,
                        "access_token": "test-token",
                        "start_date": dates["start"],
                        "end_date": dates["end"]
                    },
                    timeout=10
                )

                if response.status_code == 200:
                    data = response.json()
                    if "transactions" in data and len(data["transactions"]) > 10000:
                        self.log_result(
                            "Transaction Data Exposure",
                            "VULNERABLE",
                            "HIGH",
                            f"Excessive transaction data returned: {len(data['transactions'])} records",
                            {"dates": dates, "count": len(data["transactions"])}
                        )

            except Exception as e:
                self.log_result(
                    f"Transaction Manipulation: {dates}",
                    "ERROR",
                    "LOW",
                    f"Exception: {str(e)}"
                )

    def test_input_validation(self):
        """Test input validation and sanitization."""
        print("\n=== Testing Input Validation ===")

        # SQL Injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1' UNION SELECT * FROM users--",
            "admin'--",
            "' OR 1=1--"
        ]

        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]

        all_payloads = sql_payloads + xss_payloads

        for payload in all_payloads:
            try:
                response = requests.post(
                    urljoin(self.base_url, "/item/get"),
                    json={
                        "client_id": payload,
                        "secret": payload,
                        "access_token": payload
                    },
                    timeout=10
                )

                response_text = response.text

                # Check if payload is reflected in response
                if payload in response_text:
                    self.log_result(
                        f"Input Validation: {payload[:30]}...",
                        "VULNERABLE",
                        "HIGH",
                        f"Payload reflected in response without sanitization",
                        {"payload": payload}
                    )
                else:
                    self.log_result(
                        f"Input Validation: {payload[:30]}...",
                        "PASSED",
                        "INFO",
                        "Payload properly sanitized"
                    )

            except Exception as e:
                self.log_result(
                    f"Input Validation: {payload[:30]}...",
                    "ERROR",
                    "LOW",
                    f"Exception: {str(e)}"
                )

    def test_webhook_security(self):
        """Test webhook implementation security."""
        print("\n=== Testing Webhook Security ===")

        # Test webhook verification
        webhook_url = self.config.get("webhook_url", "")

        if not webhook_url:
            self.log_result(
                "Webhook Configuration",
                "SKIPPED",
                "INFO",
                "No webhook URL configured in config.json"
            )
            return

        # Test SSRF via webhook URL
        ssrf_payloads = [
            "http://localhost:8080",
            "http://127.0.0.1:22",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "http://internal.network/admin"
        ]

        for payload in ssrf_payloads:
            try:
                response = requests.post(
                    urljoin(self.base_url, "/item/webhook/update"),
                    json={
                        "client_id": self.client_id,
                        "secret": self.secret,
                        "access_token": "test-token",
                        "webhook": payload
                    },
                    timeout=10
                )

                if response.status_code == 200:
                    self.log_result(
                        f"Webhook SSRF: {payload}",
                        "VULNERABLE",
                        "CRITICAL",
                        f"SSRF vulnerability - internal URL accepted: {payload}",
                        {"payload": payload}
                    )
                elif response.status_code in [400, 401]:
                    self.log_result(
                        f"Webhook SSRF: {payload}",
                        "PASSED",
                        "INFO",
                        "Internal URL properly rejected"
                    )

            except Exception as e:
                self.log_result(
                    f"Webhook SSRF: {payload}",
                    "ERROR",
                    "LOW",
                    f"Exception: {str(e)}"
                )

    def test_ssl_tls(self):
        """Test SSL/TLS configuration."""
        print("\n=== Testing SSL/TLS Security ===")

        try:
            # Test with SSL verification disabled
            response = requests.get(self.base_url, verify=False, timeout=10)

            if response.status_code:
                self.log_result(
                    "SSL Certificate",
                    "INFO",
                    "INFO",
                    f"Server accessible at {self.base_url}"
                )

            # Check for HSTS header
            if 'Strict-Transport-Security' in response.headers:
                self.log_result(
                    "HSTS Header",
                    "PASSED",
                    "INFO",
                    f"HSTS enabled: {response.headers['Strict-Transport-Security']}"
                )
            else:
                self.log_result(
                    "HSTS Header",
                    "VULNERABLE",
                    "MEDIUM",
                    "HSTS header not found - susceptible to protocol downgrade attacks"
                )

        except Exception as e:
            self.log_result(
                "SSL/TLS Test",
                "ERROR",
                "MEDIUM",
                f"Exception: {str(e)}"
            )

    def generate_report(self, output_file: str = None):
        """Generate a detailed security testing report."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"reports/plaid_security_test_{timestamp}.json"

        # Ensure reports directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        report = {
            "timestamp": datetime.now().isoformat(),
            "target": self.base_url,
            "total_tests": len(self.results),
            "summary": self.get_summary(),
            "results": self.results
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Report saved to: {output_file}")
        self.print_summary()

    def get_summary(self) -> Dict:
        """Get summary statistics of test results."""
        summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
            "VULNERABLE": 0,
            "PASSED": 0,
            "ERROR": 0
        }

        for result in self.results:
            severity = result.get("severity", "INFO")
            status = result.get("status", "INFO")
            summary[severity] = summary.get(severity, 0) + 1
            summary[status] = summary.get(status, 0) + 1

        return summary

    def print_summary(self):
        """Print test summary to console."""
        summary = self.get_summary()

        print("\n" + "="*50)
        print("SECURITY TEST SUMMARY")
        print("="*50)
        print(f"Total Tests: {len(self.results)}")
        print(f"\nBy Severity:")
        print(f"  CRITICAL: {summary.get('CRITICAL', 0)}")
        print(f"  HIGH: {summary.get('HIGH', 0)}")
        print(f"  MEDIUM: {summary.get('MEDIUM', 0)}")
        print(f"  LOW: {summary.get('LOW', 0)}")
        print(f"  INFO: {summary.get('INFO', 0)}")
        print(f"\nBy Status:")
        print(f"  VULNERABLE: {summary.get('VULNERABLE', 0)}")
        print(f"  PASSED: {summary.get('PASSED', 0)}")
        print(f"  ERROR: {summary.get('ERROR', 0)}")
        print("="*50 + "\n")

    def run_all_tests(self):
        """Run all security tests."""
        print("\n" + "="*50)
        print("PLAID API SECURITY TESTER")
        print("="*50)
        print(f"Target: {self.base_url}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*50)

        # Run all tests
        self.test_authentication()
        self.test_rate_limiting()
        self.test_idor_vulnerabilities()
        self.test_account_linking()
        self.test_transaction_manipulation()
        self.test_input_validation()
        self.test_webhook_security()
        self.test_ssl_tls()

        # Generate report
        self.generate_report()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Plaid API Security Tester - For authorized testing only"
    )
    parser.add_argument(
        "-c", "--config",
        default="config.json",
        help="Path to configuration file (default: config.json)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file for report (default: reports/plaid_security_test_TIMESTAMP.json)"
    )
    parser.add_argument(
        "-t", "--test",
        choices=["auth", "rate", "idor", "linking", "transaction", "input", "webhook", "ssl", "all"],
        default="all",
        help="Specific test to run (default: all)"
    )

    args = parser.parse_args()

    # Initialize tester
    tester = PlaidAPITester(args.config)

    # Run requested tests
    if args.test == "all":
        tester.run_all_tests()
    elif args.test == "auth":
        tester.test_authentication()
        tester.generate_report(args.output)
    elif args.test == "rate":
        tester.test_rate_limiting()
        tester.generate_report(args.output)
    elif args.test == "idor":
        tester.test_idor_vulnerabilities()
        tester.generate_report(args.output)
    elif args.test == "linking":
        tester.test_account_linking()
        tester.generate_report(args.output)
    elif args.test == "transaction":
        tester.test_transaction_manipulation()
        tester.generate_report(args.output)
    elif args.test == "input":
        tester.test_input_validation()
        tester.generate_report(args.output)
    elif args.test == "webhook":
        tester.test_webhook_security()
        tester.generate_report(args.output)
    elif args.test == "ssl":
        tester.test_ssl_tls()
        tester.generate_report(args.output)


if __name__ == "__main__":
    main()
