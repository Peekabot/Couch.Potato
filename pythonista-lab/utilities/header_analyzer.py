#!/usr/bin/env python3
"""
Security Header Analyzer
Analyzes HTTP response headers for common security misconfigurations
"""

import requests
import sys
from typing import Dict, List, Tuple
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Security headers to check
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'recommended': 'max-age=31536000; includeSubDomains',
        'description': 'Enforces HTTPS connections'
    },
    'X-Frame-Options': {
        'recommended': 'DENY or SAMEORIGIN',
        'description': 'Prevents clickjacking attacks'
    },
    'X-Content-Type-Options': {
        'recommended': 'nosniff',
        'description': 'Prevents MIME-type sniffing'
    },
    'Content-Security-Policy': {
        'recommended': 'Custom policy based on application',
        'description': 'Prevents XSS and injection attacks'
    },
    'X-XSS-Protection': {
        'recommended': '1; mode=block',
        'description': 'Enables browser XSS filtering'
    },
    'Referrer-Policy': {
        'recommended': 'no-referrer or strict-origin-when-cross-origin',
        'description': 'Controls referrer information'
    },
    'Permissions-Policy': {
        'recommended': 'Custom policy based on application',
        'description': 'Controls browser features and APIs'
    }
}

# Headers that might leak information
INFORMATION_DISCLOSURE_HEADERS = [
    'Server',
    'X-Powered-By',
    'X-AspNet-Version',
    'X-AspNetMvc-Version',
    'X-Runtime'
]


def analyze_headers(url: str) -> Tuple[Dict, List[str]]:
    """
    Analyze security headers for a given URL

    Args:
        url: Target URL to analyze

    Returns:
        Tuple of (response headers dict, list of findings)
    """
    findings = []

    try:
        print(f"\n{Fore.CYAN}[*] Analyzing: {url}{Style.RESET_ALL}")
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers

        # Check for missing security headers
        print(f"\n{Fore.YELLOW}[+] Security Headers Analysis:{Style.RESET_ALL}")
        for header, info in SECURITY_HEADERS.items():
            if header in headers:
                print(f"{Fore.GREEN}✓ {header}: {headers[header]}{Style.RESET_ALL}")
            else:
                finding = f"Missing: {header} - {info['description']}"
                findings.append(finding)
                print(f"{Fore.RED}✗ {finding}{Style.RESET_ALL}")

        # Check for information disclosure
        print(f"\n{Fore.YELLOW}[+] Information Disclosure Check:{Style.RESET_ALL}")
        for header in INFORMATION_DISCLOSURE_HEADERS:
            if header in headers:
                finding = f"Info Leak: {header} = {headers[header]}"
                findings.append(finding)
                print(f"{Fore.RED}⚠ {finding}{Style.RESET_ALL}")

        # Check for insecure cookies
        print(f"\n{Fore.YELLOW}[+] Cookie Security:{Style.RESET_ALL}")
        cookies = response.cookies
        for cookie in cookies:
            cookie_issues = []
            if not cookie.secure:
                cookie_issues.append("Missing Secure flag")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                cookie_issues.append("Missing HttpOnly flag")
            if not cookie.has_nonstandard_attr('SameSite'):
                cookie_issues.append("Missing SameSite attribute")

            if cookie_issues:
                finding = f"Cookie '{cookie.name}': {', '.join(cookie_issues)}"
                findings.append(finding)
                print(f"{Fore.RED}⚠ {finding}{Style.RESET_ALL}")

        return headers, findings

    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        return {}, []


def generate_report(url: str, headers: Dict, findings: List[str]):
    """Generate a summary report"""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}SECURITY HEADER ANALYSIS REPORT{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"Target: {url}")
    print(f"Total Findings: {len(findings)}")

    if findings:
        print(f"\n{Fore.YELLOW}Issues Found:{Style.RESET_ALL}")
        for i, finding in enumerate(findings, 1):
            print(f"{i}. {finding}")
    else:
        print(f"\n{Fore.GREEN}✓ No security header issues detected!{Style.RESET_ALL}")


def main():
    """Main function"""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <URL>")
        print(f"Example: {sys.argv[0]} https://example.com")
        sys.exit(1)

    url = sys.argv[1]

    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    headers, findings = analyze_headers(url)
    generate_report(url, headers, findings)


if __name__ == "__main__":
    main()
