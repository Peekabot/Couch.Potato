#!/usr/bin/env python3
"""
JWT Token Decoder and Analyzer
Decodes and analyzes JWT tokens for security issues
"""

import base64
import json
import sys
import hashlib
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)


def base64_url_decode(input_str: str) -> str:
    """
    Decode base64url encoded string

    Args:
        input_str: Base64url encoded string

    Returns:
        Decoded string
    """
    # Add padding if needed
    padding = 4 - len(input_str) % 4
    if padding != 4:
        input_str += '=' * padding

    # Replace URL-safe characters
    input_str = input_str.replace('-', '+').replace('_', '/')

    return base64.b64decode(input_str).decode('utf-8')


def decode_jwt(token: str) -> dict:
    """
    Decode JWT token into header, payload, and signature

    Args:
        token: JWT token string

    Returns:
        Dictionary with decoded components
    """
    try:
        parts = token.split('.')

        if len(parts) != 3:
            print(f"{Fore.RED}[!] Invalid JWT format. Expected 3 parts, got {len(parts)}{Style.RESET_ALL}")
            return None

        header = json.loads(base64_url_decode(parts[0]))
        payload = json.loads(base64_url_decode(parts[1]))
        signature = parts[2]

        return {
            'header': header,
            'payload': payload,
            'signature': signature,
            'raw_token': token
        }

    except Exception as e:
        print(f"{Fore.RED}[!] Error decoding JWT: {e}{Style.RESET_ALL}")
        return None


def analyze_jwt(jwt_data: dict):
    """
    Analyze JWT for security issues

    Args:
        jwt_data: Decoded JWT data
    """
    header = jwt_data['header']
    payload = jwt_data['payload']
    findings = []

    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}JWT TOKEN ANALYSIS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    # Display header
    print(f"\n{Fore.YELLOW}[+] Header:{Style.RESET_ALL}")
    print(json.dumps(header, indent=2))

    # Display payload
    print(f"\n{Fore.YELLOW}[+] Payload:{Style.RESET_ALL}")
    print(json.dumps(payload, indent=2))

    # Display signature
    print(f"\n{Fore.YELLOW}[+] Signature:{Style.RESET_ALL}")
    print(f"  {jwt_data['signature']}")

    # Security analysis
    print(f"\n{Fore.YELLOW}[+] Security Analysis:{Style.RESET_ALL}")

    # Check algorithm
    alg = header.get('alg', 'none')
    if alg == 'none':
        findings.append("CRITICAL: Algorithm is 'none' - no signature verification!")
        print(f"{Fore.RED}  ✗ {findings[-1]}{Style.RESET_ALL}")
    elif alg in ['HS256', 'HS384', 'HS512']:
        print(f"{Fore.GREEN}  ✓ Using HMAC algorithm: {alg}{Style.RESET_ALL}")
    elif alg in ['RS256', 'RS384', 'RS512']:
        print(f"{Fore.GREEN}  ✓ Using RSA algorithm: {alg}{Style.RESET_ALL}")
    else:
        findings.append(f"WARNING: Uncommon algorithm: {alg}")
        print(f"{Fore.YELLOW}  ⚠ {findings[-1]}{Style.RESET_ALL}")

    # Check expiration
    if 'exp' in payload:
        exp_timestamp = payload['exp']
        exp_datetime = datetime.fromtimestamp(exp_timestamp)
        now = datetime.now()

        if now > exp_datetime:
            findings.append(f"Token expired on {exp_datetime}")
            print(f"{Fore.RED}  ✗ {findings[-1]}{Style.RESET_ALL}")
        else:
            time_left = exp_datetime - now
            print(f"{Fore.GREEN}  ✓ Token valid until {exp_datetime} ({time_left} remaining){Style.RESET_ALL}")
    else:
        findings.append("No expiration time (exp) claim found")
        print(f"{Fore.YELLOW}  ⚠ {findings[-1]}{Style.RESET_ALL}")

    # Check issued at
    if 'iat' in payload:
        iat_timestamp = payload['iat']
        iat_datetime = datetime.fromtimestamp(iat_timestamp)
        print(f"{Fore.GREEN}  ✓ Token issued at {iat_datetime}{Style.RESET_ALL}")

    # Check not before
    if 'nbf' in payload:
        nbf_timestamp = payload['nbf']
        nbf_datetime = datetime.fromtimestamp(nbf_timestamp)
        now = datetime.now()

        if now < nbf_datetime:
            findings.append(f"Token not valid before {nbf_datetime}")
            print(f"{Fore.YELLOW}  ⚠ {findings[-1]}{Style.RESET_ALL}")

    # Check for sensitive data in payload
    sensitive_keys = ['password', 'secret', 'api_key', 'token', 'private_key']
    for key in payload.keys():
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            findings.append(f"Potential sensitive data in claim: {key}")
            print(f"{Fore.RED}  ✗ {findings[-1]}{Style.RESET_ALL}")

    # Check for common claims
    standard_claims = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti']
    print(f"\n{Fore.YELLOW}[+] Standard Claims:{Style.RESET_ALL}")
    for claim in standard_claims:
        if claim in payload:
            print(f"{Fore.GREEN}  ✓ {claim}: {payload[claim]}{Style.RESET_ALL}")

    # Summary
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}ANALYSIS SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"Total findings: {len(findings)}")

    if findings:
        print(f"\n{Fore.YELLOW}Issues:{Style.RESET_ALL}")
        for i, finding in enumerate(findings, 1):
            print(f"  {i}. {finding}")


def main():
    """Main function"""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <JWT_TOKEN>")
        print(f"Example: {sys.argv[0]} eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        sys.exit(1)

    token = sys.argv[1]

    # Decode and analyze
    jwt_data = decode_jwt(token)
    if jwt_data:
        analyze_jwt(jwt_data)


if __name__ == "__main__":
    main()
