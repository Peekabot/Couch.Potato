#!/usr/bin/env python3
"""
Subdomain Enumeration Tool
Simple subdomain enumeration using common wordlists and DNS resolution
"""

import dns.resolver
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Common subdomain wordlist
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
    'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
    'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
    'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
    'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
    'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns',
    'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1',
    'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover',
    'info', 'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay',
    'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office',
    'exchange', 'ipv4', 'prod', 'production', 'stage', 'uat', 'qa', 'sandbox'
]


def resolve_subdomain(subdomain: str, domain: str) -> tuple:
    """
    Attempt to resolve a subdomain

    Args:
        subdomain: Subdomain to test
        domain: Base domain

    Returns:
        Tuple of (full_domain, ip_addresses) or None if not found
    """
    full_domain = f"{subdomain}.{domain}"

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        answers = resolver.resolve(full_domain, 'A')
        ips = [answer.to_text() for answer in answers]
        return (full_domain, ips)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return None
    except Exception:
        return None


def enumerate_subdomains(domain: str, wordlist: list = None, max_workers: int = 50):
    """
    Enumerate subdomains for a given domain

    Args:
        domain: Target domain
        wordlist: List of subdomain names to test
        max_workers: Number of concurrent workers
    """
    if wordlist is None:
        wordlist = COMMON_SUBDOMAINS

    print(f"{Fore.CYAN}[*] Starting subdomain enumeration for: {domain}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Testing {len(wordlist)} subdomains with {max_workers} workers{Style.RESET_ALL}\n")

    found_subdomains = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_subdomain = {
            executor.submit(resolve_subdomain, sub, domain): sub
            for sub in wordlist
        }

        # Process results as they complete
        for future in as_completed(future_to_subdomain):
            result = future.result()
            if result:
                full_domain, ips = result
                found_subdomains.append((full_domain, ips))
                ip_str = ', '.join(ips)
                print(f"{Fore.GREEN}[+] Found: {full_domain} -> {ip_str}{Style.RESET_ALL}")

    return found_subdomains


def load_wordlist(filename: str) -> list:
    """Load subdomain wordlist from file"""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Error: Wordlist file '{filename}' not found{Style.RESET_ALL}")
        sys.exit(1)


def main():
    """Main function"""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain> [wordlist_file]")
        print(f"Example: {sys.argv[0]} example.com")
        print(f"Example: {sys.argv[0]} example.com subdomains.txt")
        sys.exit(1)

    domain = sys.argv[1]

    # Load wordlist
    if len(sys.argv) > 2:
        wordlist = load_wordlist(sys.argv[2])
    else:
        wordlist = COMMON_SUBDOMAINS

    # Enumerate subdomains
    found = enumerate_subdomains(domain, wordlist)

    # Print summary
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}ENUMERATION COMPLETE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"Total subdomains found: {Fore.GREEN}{len(found)}{Style.RESET_ALL}")

    if found:
        print(f"\n{Fore.YELLOW}Discovered Subdomains:{Style.RESET_ALL}")
        for subdomain, ips in sorted(found):
            print(f"  • {subdomain}")


if __name__ == "__main__":
    main()
