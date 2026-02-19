#!/usr/bin/env python3
"""
Mobile Bug Report Generator
Quick bug report creation optimized for iPhone
Supports voice dictation and quick templates
"""

import sys
import json
from datetime import datetime
from pathlib import Path

# Bug report templates
TEMPLATES = {
    'xss': {
        'title': 'Cross-Site Scripting (XSS)',
        'severity': 'High',
        'type': 'Client-Side',
        'impact': 'Malicious JavaScript execution, session hijacking, data theft'
    },
    'idor': {
        'title': 'Insecure Direct Object Reference (IDOR)',
        'severity': 'High',
        'type': 'Authorization',
        'impact': 'Unauthorized access to other users data'
    },
    'ssrf': {
        'title': 'Server-Side Request Forgery (SSRF)',
        'severity': 'Critical',
        'type': 'Server-Side',
        'impact': 'Internal network access, cloud metadata exposure'
    },
    'sqli': {
        'title': 'SQL Injection',
        'severity': 'Critical',
        'type': 'Injection',
        'impact': 'Database compromise, data exfiltration'
    },
    'open_redirect': {
        'title': 'Open Redirect',
        'severity': 'Medium',
        'type': 'Redirect',
        'impact': 'Phishing attacks, credential theft'
    },
    'csrf': {
        'title': 'Cross-Site Request Forgery (CSRF)',
        'severity': 'Medium',
        'type': 'Session',
        'impact': 'Unauthorized actions on behalf of victim'
    }
}

class MobileReporter:
    """Mobile-optimized bug report generator"""

    def __init__(self):
        self.report_dir = Path.home() / 'Documents' / 'BugBounty' / 'reports'
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def list_templates(self):
        """Show available templates"""
        print("\n📋 Available Templates:\n")
        for i, (key, template) in enumerate(TEMPLATES.items(), 1):
            print(f"{i}. {key.upper()}: {template['title']} [{template['severity']}]")
        print()

    def select_template(self):
        """Interactive template selection"""
        self.list_templates()

        choice = input("Select template (number or name): ").strip().lower()

        # Try by number
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(TEMPLATES):
                return list(TEMPLATES.keys())[idx]
        except ValueError:
            pass

        # Try by name
        if choice in TEMPLATES:
            return choice

        print("❌ Invalid choice, using XSS template")
        return 'xss'

    def get_input(self, prompt, default=""):
        """Get user input with default value"""
        user_input = input(f"{prompt} [{default}]: ").strip()
        return user_input if user_input else default

    def generate_report(self, template_key, target, details):
        """Generate bug report from template"""
        template = TEMPLATES[template_key]

        report = f"""# {template['title']}

## Vulnerability Details

**Target**: {target}
**Severity**: {template['severity']}
**Type**: {template['type']}
**Discovered**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Reporter**: Mobile Hunter

## Description

{details.get('description', 'Vulnerability description here')}

## Impact

{template['impact']}

{details.get('additional_impact', '')}

## Steps to Reproduce

{details.get('steps', '1. Navigate to vulnerable endpoint\\n2. Execute payload\\n3. Observe results'}}

## Proof of Concept

```
{details.get('poc', 'PoC code here')}
```

## Affected URL(s)

- {details.get('url', target)}

## Screenshots

{details.get('screenshots', '- Screenshot 1: [Attach]\\n- Screenshot 2: [Attach]'}}

## Recommended Fix

{details.get('fix', 'Implement proper input validation and output encoding'}}

## CVSS Score

{details.get('cvss', 'TBD'}}

## References

- OWASP: https://owasp.org
- CWE: {details.get('cwe', 'TBD'}}

---

**Report generated from iPhone using Mobile Reporter**
"""
        return report

    def save_report(self, content, target, template_key):
        """Save report to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_target = target.replace('/', '_').replace(':', '_')
        filename = self.report_dir / f"{template_key}_{safe_target}_{timestamp}.md"

        filename.write_text(content)
        print(f"\n✅ Report saved: {filename.name}")
        return filename

    def quick_mode(self, template_key, target):
        """Quick report generation with minimal input"""
        print(f"\n🚀 Quick Report Mode: {TEMPLATES[template_key]['title']}\n")

        details = {
            'description': self.get_input("📝 Brief description"),
            'url': self.get_input("🔗 Vulnerable URL", target),
            'poc': self.get_input("💻 PoC payload"),
            'steps': "1. " + self.get_input("📍 Main step to reproduce")
        }

        report = self.generate_report(template_key, target, details)
        return report

    def full_mode(self, template_key, target):
        """Full report with detailed input"""
        print(f"\n📝 Full Report Mode: {TEMPLATES[template_key]['title']}\n")
        print("💡 Tip: Use voice dictation for faster input!\n")

        details = {
            'description': self.get_input("📝 Detailed description"),
            'url': self.get_input("🔗 Vulnerable URL", target),
            'poc': self.get_input("💻 Full PoC"),
            'steps': self.get_input("📍 Steps to reproduce"),
            'additional_impact': self.get_input("⚠️  Additional impact"),
            'fix': self.get_input("🔧 Recommended fix"),
            'cvss': self.get_input("📊 CVSS score (if known)"),
            'cwe': self.get_input("🔢 CWE number"),
            'screenshots': self.get_input("📸 Screenshot descriptions")
        }

        report = self.generate_report(template_key, target, details)
        return report


def main():
    """Main function"""
    print("\n📱 Mobile Bug Report Generator\n")

    reporter = MobileReporter()

    # Parse arguments
    if len(sys.argv) > 1:
        if '--list' in sys.argv:
            reporter.list_templates()
            return

        # Quick mode from command line
        template_key = sys.argv[1]
        target = sys.argv[2] if len(sys.argv) > 2 else input("🎯 Target domain: ")

        if template_key not in TEMPLATES:
            print(f"❌ Unknown template: {template_key}")
            reporter.list_templates()
            return
    else:
        # Interactive mode
        template_key = reporter.select_template()
        target = input("🎯 Target domain/URL: ").strip()

    if not target:
        print("❌ Target required!")
        sys.exit(1)

    # Choose mode
    print("\n⚡ Quick mode (basic) or 📝 Full mode?")
    mode = input("Enter 'q' for quick or 'f' for full [q]: ").strip().lower()

    if mode == 'f':
        report = reporter.full_mode(template_key, target)
    else:
        report = reporter.quick_mode(template_key, target)

    # Preview
    print("\n" + "="*50)
    print("📄 REPORT PREVIEW")
    print("="*50)
    print(report[:500] + "...\n")

    # Save
    if input("💾 Save this report? (y/n) [y]: ").strip().lower() != 'n':
        filename = reporter.save_report(report, target, template_key)
        print(f"\n✨ Report ready for submission!")
        print(f"📁 Location: {filename}")

    # Copy to clipboard (if available)
    try:
        import clipboard
        if input("\n📋 Copy to clipboard? (y/n) [n]: ").strip().lower() == 'y':
            clipboard.set(report)
            print("✅ Copied to clipboard!")
    except ImportError:
        pass

    print("\n🎯 Happy Hunting!\n")


if __name__ == "__main__":
    main()
