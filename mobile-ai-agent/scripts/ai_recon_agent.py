#!/usr/bin/env python3
"""
AI-Enhanced Reconnaissance Agent
Uses Devstral Vibe for intelligent decision making in bug bounty hunting

Features:
- AI-powered target prioritization
- Intelligent vulnerability analysis
- Automated PoC generation
- Smart report enhancement
- Strategic next-step suggestions
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from scripts.recon_agent import ReconAgent
from ai.devstral_vibe import DevstralVibeAgent


class AIReconAgent(ReconAgent):
    """AI-enhanced reconnaissance agent with Devstral Vibe integration"""

    def __init__(self, config_path="config/config.json"):
        # Initialize base recon agent
        super().__init__(config_path)

        # Initialize AI agent
        self.ai_enabled = self.config.get("ai", {}).get("enabled", False)

        if self.ai_enabled:
            try:
                self.logger.info("Initializing Devstral Vibe AI agent...")
                self.ai_agent = DevstralVibeAgent(self.config)
                self.logger.info("AI agent ready!")
            except Exception as e:
                self.logger.error(f"Failed to initialize AI agent: {e}")
                self.logger.info("Continuing without AI features")
                self.ai_enabled = False
                self.ai_agent = None
        else:
            self.logger.info("AI features disabled in config")
            self.ai_agent = None

    def enumerate_subdomains(self, target):
        """Enhanced subdomain enumeration with AI prioritization"""
        # Run standard enumeration
        subdomains = super().enumerate_subdomains(target)

        # Use AI to prioritize
        if self.ai_enabled and self.ai_agent and len(subdomains) > 0:
            try:
                self.logger.info("🤖 AI prioritizing subdomains...")

                # Get target context if available
                context = self.config.get("targets_context", {}).get(target, "")

                # Get AI priorities
                priorities = self.ai_agent.prioritize_targets(subdomains, context)

                # Save priorities
                output_dir = Path(__file__).parent.parent / "results" / target.replace('.', '_')
                priorities_file = output_dir / "ai_priorities.json"

                with open(priorities_file, 'w') as f:
                    json.dump(priorities, f, indent=2)

                self.logger.info(f"AI identified {len(priorities)} priority targets")

                # Log top 3 priorities
                for i, priority in enumerate(priorities[:3], 1):
                    self.logger.info(
                        f"  {i}. {priority['subdomain']} "
                        f"(score: {priority['score']}/10) - {priority['reason']}"
                    )

                # Reorder subdomains based on AI priorities
                priority_domains = [p['subdomain'] for p in priorities]
                remaining = [s for s in subdomains if s not in priority_domains]
                subdomains = priority_domains + remaining

            except Exception as e:
                self.logger.error(f"AI prioritization failed: {e}")

        return subdomains

    def vulnerability_scan(self, live_hosts, target):
        """Enhanced vulnerability scanning with AI analysis"""
        # Run standard vulnerability scan
        findings = super().vulnerability_scan(live_hosts, target)

        # Use AI to analyze each finding
        if self.ai_enabled and self.ai_agent and len(findings) > 0:
            try:
                self.logger.info(f"🤖 AI analyzing {len(findings)} findings...")

                analyzed_findings = []
                for finding in findings:
                    try:
                        analyzed = self.ai_agent.analyze_vulnerability(finding)
                        analyzed_findings.append(analyzed)

                        # Log AI insights
                        if "ai_analysis" in analyzed:
                            analysis = analyzed["ai_analysis"]
                            if "worth_reporting" in analysis and analysis["worth_reporting"]:
                                self.logger.info(
                                    f"  ⚠️  High-value finding: {finding.get('type')} "
                                    f"(exploitability: {analysis.get('exploitability', 'N/A')}/10)"
                                )

                    except Exception as e:
                        self.logger.error(f"Failed to analyze finding: {e}")
                        analyzed_findings.append(finding)

                findings = analyzed_findings

                # Save analyzed findings
                output_dir = Path(__file__).parent.parent / "results" / target.replace('.', '_')
                analyzed_file = output_dir / "ai_analyzed_findings.json"

                with open(analyzed_file, 'w') as f:
                    json.dump(findings, f, indent=2)

            except Exception as e:
                self.logger.error(f"AI analysis failed: {e}")

        return findings

    def generate_pocs(self, findings, target):
        """Generate PoCs for high-value findings"""
        if not self.ai_enabled or not self.ai_agent:
            return

        self.logger.info("🤖 AI generating PoCs for high-value findings...")

        output_dir = Path(__file__).parent.parent / "results" / target.replace('.', '_')
        pocs_dir = output_dir / "pocs"
        pocs_dir.mkdir(exist_ok=True)

        # Filter for reportable findings
        high_value = [
            f for f in findings
            if f.get("ai_analysis", {}).get("worth_reporting", False)
            or f.get("severity") in ["high", "critical"]
        ]

        for i, finding in enumerate(high_value[:5], 1):  # Limit to top 5
            try:
                self.logger.info(f"  Generating PoC {i}/{min(5, len(high_value))}: {finding.get('type')}")

                poc = self.ai_agent.generate_poc(finding)

                # Save PoC
                poc_file = pocs_dir / f"poc_{i}_{finding.get('type', 'unknown').replace(' ', '_')}.md"
                with open(poc_file, 'w') as f:
                    f.write(f"# PoC: {finding.get('type')}\n\n")
                    f.write(f"**Host**: {finding.get('host')}\n")
                    f.write(f"**Severity**: {finding.get('severity')}\n\n")
                    f.write("---\n\n")
                    f.write(poc)

                self.logger.info(f"  PoC saved: {poc_file.name}")

            except Exception as e:
                self.logger.error(f"Failed to generate PoC: {e}")

    def generate_report(self, target, subdomains, live_hosts, findings):
        """Enhanced report generation with AI insights"""
        # Generate base report
        report_path, report_content = super().generate_report(target, subdomains, live_hosts, findings)

        # Enhance with AI
        if self.ai_enabled and self.ai_agent:
            try:
                self.logger.info("🤖 AI enhancing report...")

                enhanced_content = self.ai_agent.enhance_report(report_content, findings)

                # Save enhanced report
                output_dir = Path(__file__).parent.parent / "results" / target.replace('.', '_')
                enhanced_file = output_dir / f"ai_enhanced_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

                with open(enhanced_file, 'w') as f:
                    f.write(enhanced_content)

                self.logger.info(f"Enhanced report saved: {enhanced_file}")

                # Return enhanced version
                return str(enhanced_file), enhanced_content

            except Exception as e:
                self.logger.error(f"AI report enhancement failed: {e}")

        return report_path, report_content

    def suggest_next_steps(self, target, subdomains, live_hosts, findings):
        """Get AI suggestions for next steps"""
        if not self.ai_enabled or not self.ai_agent:
            return

        try:
            self.logger.info("🤖 AI suggesting next steps...")

            # Prepare scan results summary
            scan_results = {
                "subdomain_count": len(subdomains),
                "live_host_count": len(live_hosts),
                "finding_count": len(findings),
                "top_findings": [
                    {
                        "type": f.get("type"),
                        "severity": f.get("severity"),
                        "host": f.get("host")
                    }
                    for f in findings[:10]
                ]
            }

            suggestions = self.ai_agent.suggest_next_steps(scan_results)

            # Save suggestions
            output_dir = Path(__file__).parent.parent / "results" / target.replace('.', '_')
            suggestions_file = output_dir / "ai_next_steps.json"

            with open(suggestions_file, 'w') as f:
                json.dump(suggestions, f, indent=2)

            # Log suggestions
            self.logger.info("🎯 Recommended next steps:")
            for i, step in enumerate(suggestions[:5], 1):
                self.logger.info(f"  {i}. {step}")

        except Exception as e:
            self.logger.error(f"Failed to get AI suggestions: {e}")

    def scan_target(self, target):
        """AI-enhanced complete scan workflow"""
        self.logger.info(f"=" * 60)
        self.logger.info(f"🤖 Starting AI-enhanced scan for: {target}")
        self.logger.info(f"=" * 60)

        try:
            # Step 1: AI-prioritized subdomain enumeration
            subdomains = self.enumerate_subdomains(target)

            # Step 2: Probe live hosts
            live_hosts = self.probe_live_hosts(subdomains, target)

            # Step 3: AI-analyzed vulnerability scanning
            findings = self.vulnerability_scan(live_hosts, target)

            # Step 4: Generate PoCs for high-value findings
            self.generate_pocs(findings, target)

            # Step 5: AI-enhanced report generation
            report_path, report_content = self.generate_report(target, subdomains, live_hosts, findings)

            # Step 6: Get AI next-step suggestions
            self.suggest_next_steps(target, subdomains, live_hosts, findings)

            # Store results
            self.results["targets"].append({
                "target": target,
                "subdomains": len(subdomains),
                "live_hosts": len(live_hosts),
                "findings": len(findings),
                "report": report_path,
                "ai_enhanced": self.ai_enabled
            })

            # Send notification
            self.send_notification(target, subdomains, live_hosts, findings)

            self.logger.info(f"✅ AI-enhanced scan complete for {target}")
            return True

        except Exception as e:
            self.logger.error(f"Scan failed for {target}: {e}")
            self.results["errors"].append({
                "target": target,
                "error": str(e)
            })
            return False

    def send_notification(self, target, subdomains, live_hosts, findings):
        """Enhanced notification with AI insights"""
        # Count findings by severity
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")

        # Count AI-flagged high-value findings
        ai_flagged = sum(
            1 for f in findings
            if f.get("ai_analysis", {}).get("worth_reporting", False)
        )

        ai_status = "🤖 AI-Enhanced" if self.ai_enabled else "Standard"

        message = f"""🔍 {ai_status} Scan Complete - {target}

📊 Results:
• Subdomains: {len(subdomains)}
• Live Hosts: {len(live_hosts)}
• Findings: {len(findings)}
{f'• AI High-Value: {ai_flagged}' if self.ai_enabled else ''}

🚨 Severity Breakdown:
• Critical: {critical}
• High: {high}
• Medium: {medium}

⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

        if self.ai_enabled and ai_flagged > 0:
            message += f"\n🎯 AI identified {ai_flagged} high-value finding(s) worth investigating!\n"

        # Send via configured channels
        try:
            from notifications.telegram_notify import send_telegram_message

            if self.config["notification"].get("telegram_enabled"):
                send_telegram_message(
                    self.config["notification"]["telegram_bot_token"],
                    self.config["notification"]["telegram_chat_id"],
                    message
                )
                self.logger.info("Telegram notification sent")
        except Exception as e:
            self.logger.error(f"Failed to send notification: {e}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="AI-Enhanced Mobile Recon Agent")
    parser.add_argument("-t", "--target", help="Single target to scan")
    parser.add_argument("-c", "--config", default="config/config.json", help="Config file path")
    parser.add_argument("-l", "--list", help="File containing list of targets")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI features for this run")

    args = parser.parse_args()

    # Initialize AI-enhanced agent
    agent = AIReconAgent(config_path=args.config)

    # Override AI setting if requested
    if args.no_ai:
        agent.ai_enabled = False
        agent.logger.info("AI features disabled via command line")

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
