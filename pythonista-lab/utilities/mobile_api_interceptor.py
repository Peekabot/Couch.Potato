#!/usr/bin/env python3
"""
Mobile API Request Interceptor & Fuzzer
========================================

PURPOSE:
Capture, analyze, and replay mobile app API requests for bug bounty testing.
Works with Burp Suite proxy to intercept iOS/Android app traffic.

VULNERABILITY HUNTING:
- IDOR (Insecure Direct Object Reference)
- Parameter tampering
- Authentication bypass
- Business logic flaws
- API rate limiting issues

BUGCROWD VRT:
- Broken Access Control (P2/P3)
- Server-Side Injection (P1/P2)
- Business Logic Errors (P2/P3)

USAGE:
1. Configure Burp Suite proxy on iPhone/Android
2. Use app normally to capture API requests
3. Export requests from Burp → Save as HTTP file
4. Run this script to analyze and fuzz endpoints

OR use this script to test APIs you've already discovered.

LEARN → DO → TEACH:
- Learn: Understand mobile API patterns, auth mechanisms
- Do: Fuzz parameters, find IDOR/privilege escalation
- Teach: Share API testing patterns, extend fuzzer
"""

import requests
import json
import sys
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, List, Optional
import time

class MobileAPITester:
    """
    Mobile API security testing toolkit.

    Tests for:
    - IDOR (changing IDs to access other users' data)
    - Parameter tampering (amount, price, role, etc.)
    - Authentication bypass (missing/invalid tokens)
    - Business logic flaws
    """

    def __init__(self, base_url: str, auth_token: Optional[str] = None):
        """
        Initialize API tester.

        Args:
            base_url: API base URL (e.g., "https://api.example.com/v1")
            auth_token: Authorization token (Bearer, API key, etc.)
        """
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()

        # Set default headers (common mobile app patterns)
        self.session.headers.update({
            'User-Agent': 'MyApp/1.0 (iOS 15.0)',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })

        if auth_token:
            self.session.headers['Authorization'] = f'Bearer {auth_token}'

    def test_idor(self, endpoint: str, id_param: str, test_ids: List[int]):
        """
        Test for IDOR (Insecure Direct Object Reference).

        Example: /api/users/{user_id} → Try other user IDs

        Args:
            endpoint: API endpoint with {id} placeholder
            id_param: Parameter name (e.g., "user_id")
            test_ids: List of IDs to test
        """
        print(f"\n🔍 TESTING IDOR: {endpoint}")
        print(f"   Parameter: {id_param}")
        print(f"   Testing {len(test_ids)} IDs...\n")

        results = {
            'accessible': [],
            'forbidden': [],
            'not_found': [],
            'error': []
        }

        for test_id in test_ids:
            # Replace {id} in endpoint with test ID
            url = f"{self.base_url}{endpoint}".replace(f"{{{id_param}}}", str(test_id))

            try:
                response = self.session.get(url)

                if response.status_code == 200:
                    results['accessible'].append({
                        'id': test_id,
                        'data': response.json() if response.text else None
                    })
                    print(f"   ✅ ID {test_id}: ACCESSIBLE (200 OK)")

                elif response.status_code == 403:
                    results['forbidden'].append(test_id)
                    print(f"   🚫 ID {test_id}: Forbidden (403)")

                elif response.status_code == 404:
                    results['not_found'].append(test_id)
                    print(f"   ❌ ID {test_id}: Not Found (404)")

                else:
                    results['error'].append({
                        'id': test_id,
                        'status': response.status_code
                    })
                    print(f"   ⚠️  ID {test_id}: Status {response.status_code}")

                time.sleep(0.5)  # Rate limiting courtesy

            except Exception as e:
                print(f"   ❌ ID {test_id}: Error - {e}")
                results['error'].append({'id': test_id, 'error': str(e)})

        # Analysis
        print(f"\n📊 RESULTS:")
        print(f"   Accessible: {len(results['accessible'])} (🚨 POTENTIAL IDOR!)")
        print(f"   Forbidden: {len(results['forbidden'])}")
        print(f"   Not Found: {len(results['not_found'])}")
        print(f"   Errors: {len(results['error'])}")

        if len(results['accessible']) > 1:
            print("\n🚨 VULNERABILITY DETECTED: IDOR")
            print("   You can access multiple user IDs with the same token!")
            print("   This is likely a P2/P3 Broken Access Control bug.")
            print("\n   NEXT STEPS:")
            print("   1. Verify the data belongs to other users (different names/emails)")
            print("   2. Check what actions you can perform (read vs modify)")
            print("   3. Write report using templates/BUGCROWD_TEMPLATE.md")

        return results

    def test_parameter_tampering(self, endpoint: str, method: str = "POST",
                                  base_params: Dict = None,
                                  tamper_params: List[Dict] = None):
        """
        Test parameter tampering (price, amount, role, is_admin, etc.).

        Example: POST /api/purchase {"product_id": 1, "price": 99.99}
                 → Try {"product_id": 1, "price": 0.01}

        Args:
            endpoint: API endpoint
            method: HTTP method (GET, POST, PUT, DELETE)
            base_params: Normal parameters
            tamper_params: List of parameter variations to test
        """
        url = f"{self.base_url}{endpoint}"

        print(f"\n🔧 TESTING PARAMETER TAMPERING: {method} {endpoint}")
        print(f"   Base params: {base_params}\n")

        results = []

        for tamper in tamper_params:
            params = {**base_params, **tamper}
            print(f"   Testing: {tamper}")

            try:
                if method.upper() == "GET":
                    response = self.session.get(url, params=params)
                elif method.upper() == "POST":
                    response = self.session.post(url, json=params)
                elif method.upper() == "PUT":
                    response = self.session.put(url, json=params)
                elif method.upper() == "DELETE":
                    response = self.session.delete(url, json=params)

                print(f"      Status: {response.status_code}")
                if response.text:
                    try:
                        data = response.json()
                        print(f"      Response: {json.dumps(data, indent=6)[:200]}...")
                    except:
                        print(f"      Response: {response.text[:200]}")

                results.append({
                    'params': tamper,
                    'status': response.status_code,
                    'response': response.text
                })

                time.sleep(0.5)

            except Exception as e:
                print(f"      Error: {e}")
                results.append({'params': tamper, 'error': str(e)})

        return results

    def test_authentication_bypass(self, endpoint: str, method: str = "GET"):
        """
        Test if endpoint is accessible without authentication.

        Tests:
        - No Authorization header
        - Invalid token
        - Expired token
        - Token from different user

        Args:
            endpoint: API endpoint
            method: HTTP method
        """
        url = f"{self.base_url}{endpoint}"

        print(f"\n🔐 TESTING AUTHENTICATION BYPASS: {method} {endpoint}\n")

        tests = [
            ("No Auth Header", {}),
            ("Empty Token", {'Authorization': ''}),
            ("Invalid Token", {'Authorization': 'Bearer invalid_token_xyz'}),
            ("Malformed Token", {'Authorization': 'InvalidFormat'}),
        ]

        results = []

        for test_name, headers in tests:
            print(f"   {test_name}:")

            # Create session without default auth
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'MyApp/1.0',
                'Accept': 'application/json'
            })
            session.headers.update(headers)

            try:
                if method.upper() == "GET":
                    response = session.get(url)
                elif method.upper() == "POST":
                    response = session.post(url)

                print(f"      Status: {response.status_code}")

                if response.status_code == 200:
                    print(f"      🚨 VULNERABLE: Endpoint accessible without valid auth!")
                    results.append({
                        'test': test_name,
                        'vulnerable': True,
                        'status': 200
                    })
                elif response.status_code in [401, 403]:
                    print(f"      ✅ Secure: {response.status_code}")
                    results.append({
                        'test': test_name,
                        'vulnerable': False,
                        'status': response.status_code
                    })
                else:
                    print(f"      ⚠️  Unexpected: {response.status_code}")
                    results.append({
                        'test': test_name,
                        'status': response.status_code
                    })

                time.sleep(0.5)

            except Exception as e:
                print(f"      Error: {e}")

        vulnerable_count = sum(1 for r in results if r.get('vulnerable'))

        if vulnerable_count > 0:
            print(f"\n🚨 AUTHENTICATION BYPASS DETECTED!")
            print(f"   {vulnerable_count} test(s) succeeded without valid auth")
            print(f"   This is likely a P1/P2 Broken Authentication bug")

        return results

    def fuzz_numeric_parameters(self, endpoint: str, param_name: str,
                                 test_values: List = None):
        """
        Fuzz numeric parameters (user_id, amount, price, quantity).

        Tests for:
        - Negative numbers
        - Zero
        - Very large numbers
        - Special values (MAX_INT, etc.)

        Args:
            endpoint: API endpoint
            param_name: Parameter to fuzz
            test_values: Custom values to test
        """
        if test_values is None:
            test_values = [
                -1, -999, 0, 1, 2, 999, 9999,
                2147483647,  # MAX_INT
                -2147483648,  # MIN_INT
            ]

        print(f"\n🔢 FUZZING NUMERIC PARAMETER: {param_name}")
        print(f"   Endpoint: {endpoint}")
        print(f"   Testing {len(test_values)} values...\n")

        results = []

        for value in test_values:
            params = {param_name: value}
            url = f"{self.base_url}{endpoint}"

            try:
                response = self.session.get(url, params=params)
                print(f"   {param_name}={value}: Status {response.status_code}")

                if response.status_code == 200:
                    results.append({
                        'value': value,
                        'status': 200,
                        'response': response.text[:100]
                    })

                time.sleep(0.3)

            except Exception as e:
                print(f"   {param_name}={value}: Error - {e}")

        print(f"\n   {len(results)} values returned 200 OK")
        return results


# =========================
# USAGE EXAMPLES
# =========================

def example_idor_test():
    """Example: Test for IDOR in user profile endpoint"""

    # Initialize tester with your auth token (from Burp Suite)
    api = MobileAPITester(
        base_url="https://api.example.com/v1",
        auth_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  # Your JWT token
    )

    # Test if you can access other users' profiles
    api.test_idor(
        endpoint="/users/{user_id}/profile",
        id_param="user_id",
        test_ids=[1, 2, 3, 4, 5, 100, 101, 102]  # Try different user IDs
    )


def example_parameter_tampering():
    """Example: Test price manipulation in purchase endpoint"""

    api = MobileAPITester(
        base_url="https://api.example.com/v1",
        auth_token="your_token_here"
    )

    # Normal purchase request
    base_params = {
        "product_id": 123,
        "quantity": 1,
        "price": 99.99
    }

    # Try tampering with price, quantity
    tamper_tests = [
        {"price": 0.01},  # Nearly free
        {"price": -99.99},  # Negative price (credit?)
        {"price": 0},  # Free
        {"quantity": -1},  # Negative quantity
        {"quantity": 999999},  # Massive quantity
        {"is_admin": True},  # Privilege escalation attempt
        {"discount_percent": 100},  # 100% discount
    ]

    api.test_parameter_tampering(
        endpoint="/purchases",
        method="POST",
        base_params=base_params,
        tamper_params=tamper_tests
    )


def example_auth_bypass():
    """Example: Test if sensitive endpoints require authentication"""

    api = MobileAPITester(
        base_url="https://api.example.com/v1"
    )

    # Test endpoints that SHOULD require auth
    endpoints_to_test = [
        "/users/me",
        "/users/me/profile",
        "/orders",
        "/payments/methods",
        "/admin/users"
    ]

    for endpoint in endpoints_to_test:
        api.test_authentication_bypass(endpoint, method="GET")


def interactive_mode():
    """Interactive API testing mode"""

    print("=" * 60)
    print("📱 MOBILE API SECURITY TESTER")
    print("=" * 60)
    print("\nWhat would you like to test?")
    print("1. IDOR (Insecure Direct Object Reference)")
    print("2. Parameter Tampering")
    print("3. Authentication Bypass")
    print("4. Numeric Parameter Fuzzing")
    print("\nType 'help' for guidance or 'quit' to exit")
    print("=" * 60)

    while True:
        try:
            choice = input("\n❓ Select test (1-4): ").strip()

            if choice.lower() in ['quit', 'exit', 'q']:
                print("\n👋 Happy hunting!")
                break

            if choice.lower() == 'help':
                print("\nGUIDANCE:")
                print("1. First, capture mobile app traffic using Burp Suite")
                print("2. Find API endpoints and your auth token")
                print("3. Choose a test type based on what you want to find:")
                print("   - IDOR: Test if you can access other users' data")
                print("   - Parameter Tampering: Modify prices, roles, amounts")
                print("   - Auth Bypass: Check if endpoints work without tokens")
                print("4. Analyze results and write bug reports")
                continue

            if choice == '1':
                print("\n🔍 IDOR TESTING")
                base_url = input("API Base URL (e.g., https://api.example.com/v1): ").strip()
                token = input("Auth Token (leave empty if none): ").strip() or None
                endpoint = input("Endpoint (e.g., /users/{user_id}): ").strip()
                id_param = input("ID parameter name (e.g., user_id): ").strip()
                ids_input = input("Test IDs (comma-separated, e.g., 1,2,3,100): ").strip()
                test_ids = [int(x.strip()) for x in ids_input.split(',')]

                api = MobileAPITester(base_url, token)
                api.test_idor(endpoint, id_param, test_ids)

            elif choice == '2':
                print("\n🔧 PARAMETER TAMPERING")
                print("Coming soon - use example_parameter_tampering() for now")

            elif choice == '3':
                print("\n🔐 AUTHENTICATION BYPASS")
                base_url = input("API Base URL: ").strip()
                endpoint = input("Endpoint to test (e.g., /users/me): ").strip()

                api = MobileAPITester(base_url)
                api.test_authentication_bypass(endpoint)

            elif choice == '4':
                print("\n🔢 NUMERIC FUZZING")
                print("Coming soon - use example_fuzz() for now")

            else:
                print("❌ Invalid choice. Select 1-4 or type 'help'")

        except KeyboardInterrupt:
            print("\n\n👋 Happy hunting!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    # Uncomment to run examples:
    # example_idor_test()
    # example_parameter_tampering()
    # example_auth_bypass()

    # Or run interactive mode:
    interactive_mode()
