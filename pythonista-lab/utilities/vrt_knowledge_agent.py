#!/usr/bin/env python3
"""
Bugcrowd VRT Knowledge Agent
=============================

PURPOSE:
Transform the Bugcrowd Vulnerability Rating Taxonomy into a machine-readable
brain that helps you prioritize bug bounty hunting efforts.

REPLACES: Plasma physics knowledge modules
WITH: Security intelligence based on industry-standard VRT

BUGCROWD VRT:
https://bugcrowd.com/vulnerability-rating-taxonomy
Official taxonomy mapping vulnerability types to severity levels (P1-P5)

WHAT THIS DOES:
Instead of guessing "Is this a P1 or P4?", ask the agent:
- "What priority is SQL injection?"
- "What's the strategy for IDOR?"
- "Show me all P1 vulnerabilities"

The agent uses structured VRT data to give you authoritative answers.

LEARN → DO → TEACH:
1. Learn: Understand VRT categories and priority mapping
2. Do: Use this to prioritize which bugs to hunt first
3. Teach: Extend this with more VRT data, share improvements

USAGE:
    agent = ModularKnowledgeAgent()
    agent.ask("priority for sql_injection")
    agent.ask("strategy for idor")
    agent.ask("show p1 vulnerabilities")
"""

import re
from typing import Dict, List, Optional

# =========================
# TIER 1: VRT KNOWLEDGE MODULES
# =========================

VRT_CATEGORIES = {
    "server_side_injection": {
        "p1": [
            "sql_injection",
            "remote_code_execution",
            "command_injection",
            "xxe_injection",
            "template_injection"
        ],
        "p2": [
            "nosql_injection",
            "xpath_injection",
            "ldap_injection"
        ],
        "description": "Critical flaws allowing code execution or data exfiltration.",
        "impact": "Attacker can execute arbitrary code, read/modify database, compromise server.",
        "mitigation": "Parameterized queries, input validation, principle of least privilege."
    },

    "broken_access_control": {
        "p1": [
            "privilege_escalation_to_admin",
            "authentication_bypass_critical"
        ],
        "p2": [
            "idor_sensitive_info",
            "unauthorized_admin_access",
            "horizontal_privilege_escalation"
        ],
        "p3": [
            "idor_non_sensitive",
            "forced_browsing",
            "missing_function_level_access_control"
        ],
        "p4": [
            "url_redirection_open_redirect"
        ],
        "description": "Failures in enforcing what users are allowed to do.",
        "impact": "Unauthorized access to data, functions, or accounts.",
        "mitigation": "Implement proper authorization checks, use secure direct object references."
    },

    "sensitive_data_exposure": {
        "p2": [
            "hardcoded_secrets_in_public_repo",
            "cleartext_transmission_of_session_token"
        ],
        "p3": [
            "exif_geolocation_data_present",
            "cleartext_storage_of_sensitive_data",
            "missing_secure_flag_on_cookies"
        ],
        "p4": [
            "internal_ip_disclosure",
            "verbose_error_messages",
            "application_stack_trace",
            "software_version_disclosure"
        ],
        "p5": [
            "banner_grabbing",
            "directory_listing"
        ],
        "description": "Accidental leaks of private information or system details.",
        "impact": "Attackers learn sensitive data (credentials, PII, GPS location, system architecture).",
        "mitigation": "Encrypt data at rest and in transit, strip metadata, generic error messages."
    },

    "cross_site_scripting": {
        "p1": [
            "stored_xss_in_admin_panel"
        ],
        "p2": [
            "stored_xss",
            "dom_based_xss_with_sensitive_data_access"
        ],
        "p3": [
            "reflected_xss",
            "dom_based_xss"
        ],
        "p4": [
            "self_xss"
        ],
        "description": "Injection of malicious scripts into web pages viewed by other users.",
        "impact": "Session hijacking, credential theft, defacement, malware delivery.",
        "mitigation": "Output encoding, Content Security Policy, input validation."
    },

    "broken_authentication": {
        "p1": [
            "authentication_bypass_via_spoofing",
            "weak_password_requirements_allowing_bruteforce"
        ],
        "p2": [
            "session_fixation",
            "credential_stuffing_no_rate_limiting",
            "weak_password_reset"
        ],
        "p3": [
            "username_enumeration",
            "missing_2fa"
        ],
        "p4": [
            "logout_csrf",
            "remember_me_functionality_weak"
        ],
        "description": "Flaws in authentication mechanisms allowing account compromise.",
        "impact": "Account takeover, unauthorized access, identity theft.",
        "mitigation": "Strong password policies, MFA, rate limiting, secure session management."
    },

    "security_misconfiguration": {
        "p2": [
            "default_credentials",
            "admin_interface_publicly_accessible"
        ],
        "p3": [
            "missing_security_headers",
            "unnecessary_services_enabled",
            "cors_misconfiguration"
        ],
        "p4": [
            "verbose_server_headers",
            "http_methods_enabled"
        ],
        "p5": [
            "outdated_software_informational"
        ],
        "description": "Improper configuration of security settings.",
        "impact": "Increased attack surface, easier exploitation of other vulnerabilities.",
        "mitigation": "Secure defaults, hardening guides, regular audits, automated configuration scanning."
    },

    "server_security_misconfiguration": {
        "p1": [
            "remote_code_execution_via_misconfiguration"
        ],
        "p2": [
            "arbitrary_file_read",
            "directory_traversal"
        ],
        "p3": [
            "local_file_inclusion",
            "ssrf_internal_network_access"
        ],
        "p4": [
            "ssrf_limited_impact"
        ],
        "description": "Server-side misconfigurations leading to information disclosure or worse.",
        "impact": "File system access, internal network scanning, code execution.",
        "mitigation": "Restrict file access, validate URLs, network segmentation."
    }
}

# Mapping priority levels to impact descriptions
PRIORITY_LEVELS = {
    "p1": {
        "name": "Critical",
        "description": "Immediate threat to core systems/data. Exploitable remotely with severe impact.",
        "bounty_range": "$1,000 - $20,000+",
        "time_investment": "HIGH - Manually verify, create detailed PoC, thorough testing.",
        "example_impacts": [
            "Remote code execution",
            "Full database compromise",
            "Mass account takeover",
            "Complete authentication bypass"
        ]
    },
    "p2": {
        "name": "High",
        "description": "Significant risk requiring urgent fix. Major impact to security posture.",
        "bounty_range": "$500 - $5,000",
        "time_investment": "MEDIUM-HIGH - Verify manually, create PoC, test thoroughly.",
        "example_impacts": [
            "Sensitive data exposure (PII, credentials)",
            "Privilege escalation to sensitive roles",
            "Stored XSS in user-facing features",
            "Authentication bypass with limitations"
        ]
    },
    "p3": {
        "name": "Medium",
        "description": "Moderate impact with localized risk. Requires user interaction or specific conditions.",
        "bounty_range": "$100 - $1,000",
        "time_investment": "MEDIUM - Can semi-automate scanning, manual verification recommended.",
        "example_impacts": [
            "IDOR on non-sensitive data",
            "Reflected XSS",
            "EXIF GPS data leakage",
            "Missing security headers"
        ]
    },
    "p4": {
        "name": "Low",
        "description": "Minor security impact. Requires chaining with other bugs for significant impact.",
        "bounty_range": "$50 - $250",
        "time_investment": "LOW - Automate scanning, batch report if multiple instances.",
        "example_impacts": [
            "Internal IP disclosure",
            "Verbose error messages",
            "Open redirect with limited impact",
            "Self-XSS"
        ]
    },
    "p5": {
        "name": "Informational",
        "description": "Non-security flaw, out-of-scope, or requires unrealistic attack scenario.",
        "bounty_range": "Usually $0 (kudos only)",
        "time_investment": "MINIMAL - Report only if explicitly in scope.",
        "example_impacts": [
            "Banner grabbing",
            "Directory listing with no sensitive files",
            "Theoretical vulnerabilities with no real impact"
        ]
    }
}

# =========================
# TIER 2: SECURITY LOGIC MODELS
# =========================

class SecurityModels:
    """Executable security logic for bug bounty decision-making"""

    @staticmethod
    def calculate_priority(category: str, sub_vuln: str) -> Optional[str]:
        """
        Find the VRT priority for a specific vulnerability type.

        Args:
            category: VRT category (e.g., "server_side_injection")
            sub_vuln: Specific vulnerability (e.g., "sql_injection")

        Returns:
            str: Priority description or None if not found
        """
        if category not in VRT_CATEGORIES:
            return None

        cat_data = VRT_CATEGORIES[category]

        for level in ["p1", "p2", "p3", "p4", "p5"]:
            if sub_vuln in cat_data.get(level, []):
                priority_info = PRIORITY_LEVELS[level]
                return (
                    f"Priority: {level.upper()} ({priority_info['name']})\n"
                    f"Impact: {priority_info['description']}\n"
                    f"Bounty Range: {priority_info['bounty_range']}\n"
                    f"Time Investment: {priority_info['time_investment']}"
                )

        return None

    @staticmethod
    def get_hunting_strategy(priority_str: str) -> str:
        """
        Decide how much effort to spend based on priority.

        Args:
            priority_str: Priority identifier (e.g., "P1", "P2")

        Returns:
            str: Recommended hunting strategy
        """
        priority_str = priority_str.upper()

        if "P1" in priority_str:
            return (
                "🎯 STRATEGY: CRITICAL PRIORITY\n"
                "- Focus: Deep manual testing, dedicated time blocks\n"
                "- PoC: Comprehensive, demonstrating full impact\n"
                "- Report: Detailed writeup with remediation guidance\n"
                "- ROI: Highest bounties, worth significant time investment"
            )
        elif "P2" in priority_str:
            return (
                "🎯 STRATEGY: HIGH PRIORITY\n"
                "- Focus: Thorough manual testing with some automation\n"
                "- PoC: Clear demonstration of impact\n"
                "- Report: Professional writeup with reproduction steps\n"
                "- ROI: Good bounties, worth dedicated hunting time"
            )
        elif "P3" in priority_str:
            return (
                "🎯 STRATEGY: MEDIUM PRIORITY\n"
                "- Focus: Semi-automated scanning + manual verification\n"
                "- PoC: Simple proof of concept, clear steps\n"
                "- Report: Concise writeup with key details\n"
                "- ROI: Moderate bounties, balance automation with manual work"
            )
        elif "P4" in priority_str:
            return (
                "🎯 STRATEGY: LOW PRIORITY\n"
                "- Focus: Automated scanning, batch reporting\n"
                "- PoC: Screenshot or simple curl command\n"
                "- Report: Brief writeup, template-based\n"
                "- ROI: Small bounties, only worth it if automated or many instances"
            )
        else:  # P5
            return (
                "🎯 STRATEGY: INFORMATIONAL\n"
                "- Focus: Report ONLY if program explicitly accepts informational\n"
                "- PoC: Minimal evidence\n"
                "- Report: Very brief\n"
                "- ROI: Usually $0, skip unless program values these"
            )

    @staticmethod
    def get_all_vulnerabilities_by_priority(priority: str) -> List[str]:
        """
        Get all vulnerability types for a given priority level.

        Args:
            priority: Priority level (e.g., "p1", "p2")

        Returns:
            list: Vulnerability types at that priority
        """
        priority = priority.lower()
        all_vulns = []

        for category, data in VRT_CATEGORIES.items():
            if priority in data:
                vulns = data[priority]
                all_vulns.extend([f"{category} > {v}" for v in vulns])

        return all_vulns

    @staticmethod
    def get_category_info(category: str) -> Optional[Dict]:
        """
        Get full information about a VRT category.

        Args:
            category: Category name

        Returns:
            dict: Category data or None
        """
        return VRT_CATEGORIES.get(category)

# =========================
# TIER 3: QUERY RESOLVER
# =========================

class QueryResolver:
    """Natural language query parser for security questions"""

    def resolve_query(self, query: str) -> Dict[str, any]:
        """
        Parse natural language query into structured concepts.

        Args:
            query: Natural language question

        Returns:
            dict: Extracted concepts and intent
        """
        query_lower = query.lower()

        concepts = {
            "intent": None,
            "category": None,
            "vulnerability": None,
            "priority": None
        }

        # Intent detection
        if any(word in query_lower for word in ["priority", "severity", "level"]):
            concepts["intent"] = "get_priority"
        elif any(word in query_lower for word in ["strategy", "effort", "time", "how to hunt"]):
            concepts["intent"] = "get_strategy"
        elif "show" in query_lower or "list" in query_lower:
            concepts["intent"] = "list_vulnerabilities"
        elif "category" in query_lower or "info" in query_lower:
            concepts["intent"] = "get_category_info"

        # Extract priority level
        priority_match = re.search(r'\b(p[1-5])\b', query_lower)
        if priority_match:
            concepts["priority"] = priority_match.group(1)

        # Extract category
        for category in VRT_CATEGORIES.keys():
            if category.replace("_", " ") in query_lower or category in query_lower:
                concepts["category"] = category
                break

        # Extract specific vulnerability
        for category, data in VRT_CATEGORIES.items():
            for priority_level in ["p1", "p2", "p3", "p4", "p5"]:
                if priority_level in data:
                    for vuln in data[priority_level]:
                        if vuln.replace("_", " ") in query_lower or vuln in query_lower:
                            concepts["vulnerability"] = vuln
                            concepts["category"] = category
                            break

        return concepts

# =========================
# TIER 4: KNOWLEDGE AGENT
# =========================

class ModularKnowledgeAgent:
    """
    Security intelligence agent powered by Bugcrowd VRT.

    Replaces plasma physics knowledge with bug bounty intelligence.
    Answers questions about vulnerability priorities, hunting strategies,
    and VRT taxonomy.
    """

    def __init__(self):
        self.resolver = QueryResolver()
        self.models = SecurityModels()

    def ask(self, question: str) -> str:
        """
        Ask the agent a security question.

        Args:
            question: Natural language query

        Returns:
            str: Agent's response
        """
        concepts = self.resolver.resolve_query(question)

        # Handle different intents
        if concepts["intent"] == "get_priority":
            if concepts["vulnerability"] and concepts["category"]:
                result = self.models.calculate_priority(
                    concepts["category"],
                    concepts["vulnerability"]
                )
                if result:
                    return result
                return f"❌ Vulnerability '{concepts['vulnerability']}' not found in VRT data."

            elif concepts["vulnerability"]:
                # Search across all categories
                for category in VRT_CATEGORIES.keys():
                    result = self.models.calculate_priority(category, concepts["vulnerability"])
                    if result:
                        return f"Category: {category}\n{result}"
                return f"❌ Vulnerability '{concepts['vulnerability']}' not found."

        elif concepts["intent"] == "get_strategy":
            if concepts["priority"]:
                return self.models.get_hunting_strategy(concepts["priority"])
            return "❌ Please specify a priority level (P1-P5)"

        elif concepts["intent"] == "list_vulnerabilities":
            if concepts["priority"]:
                vulns = self.models.get_all_vulnerabilities_by_priority(concepts["priority"])
                if vulns:
                    priority_info = PRIORITY_LEVELS[concepts["priority"]]
                    response = (
                        f"\n🎯 {concepts['priority'].upper()} ({priority_info['name']}) VULNERABILITIES:\n"
                        f"Bounty Range: {priority_info['bounty_range']}\n\n"
                    )
                    for v in vulns:
                        response += f"  • {v}\n"
                    return response
                return f"❌ No vulnerabilities found for {concepts['priority']}"
            return "❌ Please specify a priority level (e.g., 'show p1 vulnerabilities')"

        elif concepts["intent"] == "get_category_info":
            if concepts["category"]:
                info = self.models.get_category_info(concepts["category"])
                if info:
                    response = f"\n📚 CATEGORY: {concepts['category'].upper()}\n\n"
                    response += f"Description: {info['description']}\n"
                    response += f"Impact: {info['impact']}\n"
                    response += f"Mitigation: {info['mitigation']}\n\n"
                    response += "Priority Breakdown:\n"
                    for level in ["p1", "p2", "p3", "p4", "p5"]:
                        if level in info:
                            response += f"  {level.upper()}: {len(info[level])} vulnerability types\n"
                    return response
                return f"❌ Category '{concepts['category']}' not found"
            return "❌ Please specify a category"

        # Default help message
        return self._get_help_message()

    def _get_help_message(self) -> str:
        """Return help message with example queries"""
        return """
🤖 VRT KNOWLEDGE AGENT - Help

EXAMPLE QUERIES:
  • "What priority is SQL injection?"
  • "Show me all P1 vulnerabilities"
  • "What's the strategy for P2?"
  • "Tell me about broken access control"
  • "Priority for IDOR sensitive info"
  • "List P3 vulnerabilities"

AVAILABLE CATEGORIES:
  • server_side_injection
  • broken_access_control
  • sensitive_data_exposure
  • cross_site_scripting
  • broken_authentication
  • security_misconfiguration
  • server_security_misconfiguration

Try asking a question!
        """

# =========================
# INTERACTIVE MODE
# =========================

def interactive_mode():
    """Run agent in interactive question-answering mode"""
    agent = ModularKnowledgeAgent()

    print("=" * 60)
    print("🔐 BUGCROWD VRT KNOWLEDGE AGENT")
    print("=" * 60)
    print(agent._get_help_message())
    print("=" * 60)
    print("\nType 'quit' to exit\n")

    while True:
        try:
            question = input("❓ Ask: ").strip()

            if question.lower() in ['quit', 'exit', 'q']:
                print("\n👋 Happy hunting!")
                break

            if not question:
                continue

            response = agent.ask(question)
            print(f"\n🤖 {response}\n")

        except KeyboardInterrupt:
            print("\n\n👋 Happy hunting!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}\n")


if __name__ == "__main__":
    # Run interactive mode when script is executed
    interactive_mode()
