#!/usr/bin/env python3
"""
Quick Recon Tool - Mobile Optimized
Fast subdomain enumeration and basic reconnaissance for iPhone
Designed for a-Shell, Pythonista 3, and iSH
"""

import sys
import json
from datetime import datetime
from pathlib import Path

# Mobile-friendly imports (minimal dependencies)
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("⚠️  dnspython not available. Install with: pip install dnspython")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("⚠️  requests not available. Install with: pip install requests")

# Mobile-optimized subdomain list (smaller for speed)
MOBILE_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'api', 'app',
    'test', 'staging', 'demo', 'portal', 'vpn', 'secure', 'login',
    'dashboard', 'cdn', 'static', 'media', 'assets', 'images'
]

class MobileRecon:
    """Lightweight recon tool optimized for mobile devices"""

    def __init__(self, domain, verbose=False):
        self.domain = domain.strip()
        self.verbose = verbose
        self.results = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'ips': set(),
            'live_hosts': []
        }

    def log(self, msg, level='info'):
        """Mobile-friendly logging"""
        icons = {'info': '📱', 'success': '✅', 'error': '❌', 'warning': '⚠️'}
        icon = icons.get(level, 'ℹ️')
        if self.verbose or level != 'info':
            print(f"{icon} {msg}")

    def dns_lookup(self, subdomain):
        """Quick DNS lookup"""
        if not DNS_AVAILABLE:
            return None

        full_domain = f"{subdomain}.{self.domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 1
            resolver.lifetime = 1
            answers = resolver.resolve(full_domain, 'A')
            ips = [str(answer) for answer in answers]
            return {'domain': full_domain, 'ips': ips}
        except:
            return None

    def check_http(self, url):
        """Quick HTTP check"""
        if not REQUESTS_AVAILABLE:
            return False

        try:
            resp = requests.get(url, timeout=3, allow_redirects=False)
            return resp.status_code < 500
        except:
            return False

    def enumerate_subdomains(self):
        """Fast subdomain enumeration"""
        self.log(f"Scanning {self.domain}...")

        found = 0
        for sub in MOBILE_SUBDOMAINS:
            result = self.dns_lookup(sub)
            if result:
                found += 1
                self.results['subdomains'].append(result)
                self.results['ips'].update(result['ips'])
                print(f"✅ {result['domain']} → {', '.join(result['ips'])}")

        self.log(f"Found {found} subdomains", 'success')
        return found

    def check_live_hosts(self):
        """Check which subdomains are serving HTTP/HTTPS"""
        self.log("Checking live hosts...")

        for sub_info in self.results['subdomains']:
            domain = sub_info['domain']

            # Try HTTPS first
            if self.check_http(f"https://{domain}"):
                self.results['live_hosts'].append({'domain': domain, 'protocol': 'https'})
                print(f"🌐 https://{domain} [LIVE]")
            elif self.check_http(f"http://{domain}"):
                self.results['live_hosts'].append({'domain': domain, 'protocol': 'http'})
                print(f"🌐 http://{domain} [LIVE]")

    def save_results(self):
        """Save results to file"""
        output_dir = Path.home() / 'Documents' / 'BugBounty' / 'recon'
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = output_dir / f"{self.domain}_{timestamp}.json"

        # Convert set to list for JSON serialization
        save_data = self.results.copy()
        save_data['ips'] = list(self.results['ips'])

        filename.write_text(json.dumps(save_data, indent=2))
        self.log(f"Saved to {filename}", 'success')
        return filename

    def print_summary(self):
        """Print mobile-friendly summary"""
        print("\n" + "="*40)
        print(f"📊 RECON SUMMARY: {self.domain}")
        print("="*40)
        print(f"⏰ Time: {self.results['timestamp']}")
        print(f"🔍 Subdomains: {len(self.results['subdomains'])}")
        print(f"🌐 Live Hosts: {len(self.results['live_hosts'])}")
        print(f"🖥️  Unique IPs: {len(self.results['ips'])}")
        print("="*40)

        if self.results['live_hosts']:
            print("\n🎯 Priority Targets:")
            for host in self.results['live_hosts']:
                print(f"  • {host['protocol']}://{host['domain']}")


def main():
    """Main function"""
    print("\n📱 Quick Recon - Mobile Bug Bounty Tool\n")

    if len(sys.argv) < 2:
        print("Usage: python quick_recon.py <domain> [-v]")
        print("Example: python quick_recon.py example.com -v")
        sys.exit(1)

    domain = sys.argv[1]
    verbose = '-v' in sys.argv or '--verbose' in sys.argv

    recon = MobileRecon(domain, verbose=verbose)

    # Run enumeration
    recon.enumerate_subdomains()

    # Check live hosts (optional, can be slow on cellular)
    if REQUESTS_AVAILABLE and input("\n🌐 Check live hosts? (y/n): ").lower() == 'y':
        recon.check_live_hosts()

    # Print summary
    recon.print_summary()

    # Save results
    if input("\n💾 Save results? (y/n): ").lower() == 'y':
        recon.save_results()

    print("\n✨ Recon complete!\n")


if __name__ == "__main__":
    main()
