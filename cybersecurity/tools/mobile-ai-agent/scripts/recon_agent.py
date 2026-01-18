#!/usr/bin/env python3
"""
Mobile AI Recon Agent
Automated reconnaissance agent optimized for PythonAnywhere and mobile control
"""

import os
import sys
import json
import logging
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

try:
    from notifications.telegram_notify import send_telegram_message
    from notifications.email_notify import send_email_report
except ImportError:
    print("Warning: Notification modules not found. Install requirements.txt")
    def send_telegram_message(*args, **kwargs):
        pass
    def send_email_report(*args, **kwargs):
        pass


class ReconAgent:
    """Automated reconnaissance agent for bug bounty hunting"""

    def __init__(self, config_path="config/config.json"):
        self.config_path = config_path
        self.config = self.load_config()
        self.setup_logging()
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "targets": [],
            "findings": [],
            "errors": []
        }

    def load_config(self):
        """Load configuration from JSON file"""
        try:
            config_file = Path(__file__).parent.parent / self.config_path
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logging.error(f"Config file not found: {config_file}")
            # Return default config
            return {
                "agent": {"name": "ReconAgent", "mode": "auto"},
                "notification": {"telegram_enabled": False},
                "targets": [],
                "tools": {
                    "subfinder": True,
                    "httpx": True,
                    "nuclei": False
                }
            }

    def setup_logging(self):
        """Configure logging"""
        log_dir = Path(__file__).parent.parent / "logs"
        log_dir.mkdir(exist_ok=True)

        log_file = log_dir / "recon_agent.log"

        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def run_command(self, command, timeout=300):
        """Execute shell command safely"""
        try:
            self.logger.info(f"Running: {command}")
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out: {command}")
            return "", "Timeout", 1
        except Exception as e:
            self.logger.error(f"Command failed: {e}")
            return "", str(e), 1

    def check_tool_installed(self, tool_name):
        """Check if a tool is installed"""
        stdout, _, returncode = self.run_command(f"which {tool_name}")
        return returncode == 0

    def install_tools(self):
        """Install required tools (PythonAnywhere compatible)"""
        self.logger.info("Checking required tools...")

        tools_to_check = {
            "subfinder": "GO111MODULE=on go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "httpx": "GO111MODULE=on go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "nuclei": "GO111MODULE=on go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
        }

        # Note: These won't work on PythonAnywhere free tier without Go
        # Alternative: Use API-based tools or Python alternatives

        for tool, install_cmd in tools_to_check.items():
            if not self.check_tool_installed(tool):
                self.logger.warning(f"{tool} not found. Use API alternatives or local install.")

    def enumerate_subdomains(self, target):
        """Enumerate subdomains using available tools"""
        self.logger.info(f"Starting subdomain enumeration for {target}")

        subdomains = set()
        output_dir = Path(__file__).parent.parent / "results" / target.replace('.', '_')
        output_dir.mkdir(parents=True, exist_ok=True)

        # Method 1: Subfinder (if installed)
        if self.config["tools"].get("subfinder") and self.check_tool_installed("subfinder"):
            output_file = output_dir / "subdomains_subfinder.txt"
            stdout, stderr, returncode = self.run_command(
                f"subfinder -d {target} -silent -o {output_file}"
            )
            if returncode == 0 and output_file.exists():
                with open(output_file, 'r') as f:
                    subdomains.update(line.strip() for line in f if line.strip())
                self.logger.info(f"Subfinder found {len(subdomains)} subdomains")

        # Method 2: crt.sh API (Python-based, always works)
        self.logger.info("Using crt.sh API for subdomain enumeration")
        try:
            import requests
            response = requests.get(
                f"https://crt.sh/?q=%.{target}&output=json",
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain and '*' not in subdomain:
                            subdomains.add(subdomain)
                self.logger.info(f"crt.sh found {len(subdomains)} total unique subdomains")
        except Exception as e:
            self.logger.error(f"crt.sh API error: {e}")

        # Save all subdomains
        all_subdomains_file = output_dir / "all_subdomains.txt"
        with open(all_subdomains_file, 'w') as f:
            for subdomain in sorted(subdomains):
                f.write(f"{subdomain}\n")

        self.logger.info(f"Total unique subdomains: {len(subdomains)}")
        return list(subdomains)

    def probe_live_hosts(self, subdomains, target):
        """Probe for live hosts"""
        self.logger.info(f"Probing {len(subdomains)} subdomains for live hosts")

        output_dir = Path(__file__).parent.parent / "results" / target.replace('.', '_')
        live_hosts = []

        # Method 1: httpx (if installed)
        if self.config["tools"].get("httpx") and self.check_tool_installed("httpx"):
            subdomains_file = output_dir / "all_subdomains.txt"
            live_file = output_dir / "live_hosts.txt"

            self.run_command(
                f"httpx -l {subdomains_file} -silent -o {live_file}"
            )

            if live_file.exists():
                with open(live_file, 'r') as f:
                    live_hosts = [line.strip() for line in f if line.strip()]

        # Method 2: Python requests (fallback)
        else:
            import requests
            for subdomain in subdomains[:50]:  # Limit to avoid timeouts
                for protocol in ['https', 'http']:
                    try:
                        url = f"{protocol}://{subdomain}"
                        response = requests.head(url, timeout=5, allow_redirects=True)
                        if response.status_code < 500:
                            live_hosts.append(url)
                            self.logger.info(f"Live: {url}")
                            break
                    except:
                        continue

            # Save live hosts
            live_file = output_dir / "live_hosts.txt"
            with open(live_file, 'w') as f:
                for host in live_hosts:
                    f.write(f"{host}\n")

        self.logger.info(f"Found {len(live_hosts)} live hosts")
        return live_hosts

    def vulnerability_scan(self, live_hosts, target):
        """Basic vulnerability scanning"""
        self.logger.info(f"Starting vulnerability scan on {len(live_hosts)} hosts")

        output_dir = Path(__file__).parent.parent / "results" / target.replace('.', '_')
        findings = []

        # Method 1: Nuclei (if installed)
        if self.config["tools"].get("nuclei") and self.check_tool_installed("nuclei"):
            live_file = output_dir / "live_hosts.txt"
            nuclei_output = output_dir / "nuclei_findings.json"

            stdout, stderr, returncode = self.run_command(
                f"nuclei -l {live_file} -severity low,medium,high,critical -json -o {nuclei_output}",
                timeout=600
            )

            if nuclei_output.exists():
                with open(nuclei_output, 'r') as f:
                    for line in f:
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                        except:
                            pass

        # Method 2: Basic security checks (Python)
        else:
            import requests
            self.logger.info("Running basic security checks")

            for host in live_hosts[:20]:  # Limit scans
                try:
                    response = requests.get(host, timeout=10)
                    headers = response.headers

                    # Check for common security headers
                    security_headers = [
                        'X-Frame-Options',
                        'X-Content-Type-Options',
                        'Strict-Transport-Security',
                        'Content-Security-Policy'
                    ]

                    missing_headers = [h for h in security_headers if h not in headers]
                    if missing_headers:
                        findings.append({
                            "host": host,
                            "type": "missing_security_headers",
                            "severity": "info",
                            "details": missing_headers
                        })

                    # Check for exposed info in headers
                    if 'Server' in headers:
                        findings.append({
                            "host": host,
                            "type": "server_disclosure",
                            "severity": "low",
                            "details": headers['Server']
                        })

                except Exception as e:
                    self.logger.debug(f"Scan error for {host}: {e}")

        # Save findings
        findings_file = output_dir / "findings.json"
        with open(findings_file, 'w') as f:
            json.dump(findings, f, indent=2)

        self.logger.info(f"Found {len(findings)} potential issues")
        return findings

    def generate_report(self, target, subdomains, live_hosts, findings):
        """Generate markdown report"""
        output_dir = Path(__file__).parent.parent / "results" / target.replace('.', '_')
        report_file = output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

        report = f"""# Reconnaissance Report - {target}

**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Agent**: {self.config['agent']['name']}

## Summary

- **Target**: {target}
- **Subdomains Found**: {len(subdomains)}
- **Live Hosts**: {len(live_hosts)}
- **Findings**: {len(findings)}

## Subdomains ({len(subdomains)})

```
{chr(10).join(sorted(subdomains)[:50])}
{"..." if len(subdomains) > 50 else ""}
```

## Live Hosts ({len(live_hosts)})

```
{chr(10).join(live_hosts[:30])}
{"..." if len(live_hosts) > 30 else ""}
```

## Findings ({len(findings)})

"""
        # Add findings details
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "info"), 4))

        for i, finding in enumerate(sorted_findings[:20], 1):
            severity = finding.get("severity", "info").upper()
            host = finding.get("host", "N/A")
            finding_type = finding.get("type", "Unknown")
            details = finding.get("details", "No details")

            report += f"""
### {i}. {finding_type} [{severity}]

- **Host**: {host}
- **Details**: {details}

---
"""

        # Save report
        with open(report_file, 'w') as f:
            f.write(report)

        self.logger.info(f"Report saved: {report_file}")
        return str(report_file), report

    def scan_target(self, target):
        """Complete scan workflow for a target"""
        self.logger.info(f"=" * 60)
        self.logger.info(f"Starting scan for: {target}")
        self.logger.info(f"=" * 60)

        try:
            # Step 1: Subdomain enumeration
            subdomains = self.enumerate_subdomains(target)

            # Step 2: Probe live hosts
            live_hosts = self.probe_live_hosts(subdomains, target)

            # Step 3: Vulnerability scanning
            findings = self.vulnerability_scan(live_hosts, target)

            # Step 4: Generate report
            report_path, report_content = self.generate_report(target, subdomains, live_hosts, findings)

            # Store results
            self.results["targets"].append({
                "target": target,
                "subdomains": len(subdomains),
                "live_hosts": len(live_hosts),
                "findings": len(findings),
                "report": report_path
            })

            # Send notification
            self.send_notification(target, subdomains, live_hosts, findings)

            self.logger.info(f"Scan complete for {target}")
            return True

        except Exception as e:
            self.logger.error(f"Scan failed for {target}: {e}")
            self.results["errors"].append({
                "target": target,
                "error": str(e)
            })
            return False

    def send_notification(self, target, subdomains, live_hosts, findings):
        """Send notification about scan results"""
        # Count findings by severity
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")

        message = f"""🔍 Scan Complete - {target}

📊 Results:
• Subdomains: {len(subdomains)}
• Live Hosts: {len(live_hosts)}
• Findings: {len(findings)}

🚨 Severity Breakdown:
• Critical: {critical}
• High: {high}
• Medium: {medium}

⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

        # Send Telegram notification
        if self.config["notification"].get("telegram_enabled"):
            try:
                send_telegram_message(
                    self.config["notification"]["telegram_bot_token"],
                    self.config["notification"]["telegram_chat_id"],
                    message
                )
                self.logger.info("Telegram notification sent")
            except Exception as e:
                self.logger.error(f"Failed to send Telegram notification: {e}")

        # Send email notification
        if self.config["notification"].get("email_enabled"):
            try:
                send_email_report(
                    self.config["notification"],
                    f"Recon Report - {target}",
                    message
                )
                self.logger.info("Email notification sent")
            except Exception as e:
                self.logger.error(f"Failed to send email notification: {e}")

    def run(self, targets=None):
        """Run reconnaissance on all targets"""
        if targets is None:
            targets = self.config.get("targets", [])

        if not targets:
            self.logger.warning("No targets specified")
            return

        self.logger.info(f"Starting reconnaissance for {len(targets)} target(s)")

        for target in targets:
            self.scan_target(target)

        # Save final results
        results_file = Path(__file__).parent.parent / "results" / f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        results_file.parent.mkdir(exist_ok=True)

        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)

        self.logger.info("All scans complete!")
        self.logger.info(f"Results saved: {results_file}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Mobile AI Recon Agent")
    parser.add_argument("-t", "--target", help="Single target to scan")
    parser.add_argument("-c", "--config", default="config/config.json", help="Config file path")
    parser.add_argument("-l", "--list", help="File containing list of targets")

    args = parser.parse_args()

    # Initialize agent
    agent = ReconAgent(config_path=args.config)

    # Determine targets
    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        with open(args.list, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]

    # Run agent
    agent.run(targets)


if __name__ == "__main__":
    main()
