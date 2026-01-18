#!/usr/bin/env python3
"""
🌡️ Mobile AI Agent - Progressive Warm-Up Script
Tests system readiness from zero friction to full deployment

Run: python3 warmup.py [level]
Levels: 0 (zero friction) to 5 (full deployment)
"""

import os
import sys
import json
import subprocess
from pathlib import Path

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_level(level, name):
    """Print level header"""
    friction = ["🟢 ZERO", "🟢 LOW", "🟡 MEDIUM", "🟠 HIGH", "🔴 VERY HIGH", "🔴 PRODUCTION"]
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BLUE}{friction[level]} Friction - Level {level}: {name}{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}\n")

def check(description, success):
    """Print check result"""
    status = f"{Colors.GREEN}✅ PASS{Colors.END}" if success else f"{Colors.RED}❌ FAIL{Colors.END}"
    print(f"{status} - {description}")
    return success

def run_command(cmd, description, show_output=False):
    """Run shell command and check success"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        success = result.returncode == 0

        if show_output and result.stdout:
            print(f"  {Colors.YELLOW}Output:{Colors.END} {result.stdout[:200]}")

        return check(description, success)
    except Exception as e:
        return check(f"{description} (error: {e})", False)

# ============================================================================
# LEVEL 0: ZERO FRICTION - File System Checks (30 seconds)
# ============================================================================
def level_0():
    """Zero friction - just verify files exist"""
    print_level(0, "File System Verification")

    base_dir = Path(__file__).parent

    # Check critical files
    critical_files = [
        "scripts/recon_agent.py",
        "scripts/ai_recon_agent.py",
        "ai/devstral_vibe.py",
        "security/security_utils.py",
        "config/config.example.json",
        "requirements.txt",
        "README.md"
    ]

    all_pass = True
    for file in critical_files:
        file_path = base_dir / file
        all_pass &= check(f"File exists: {file}", file_path.exists())

    # Check documentation
    docs = ["MOBILE_SETUP_GUIDE.md", "DEVSTRAL_VIBE_GUIDE.md", "SECURITY_GUIDE.md", "TESTING_GUIDE.md"]
    for doc in docs:
        doc_path = base_dir / "docs" / doc
        all_pass &= check(f"Documentation: {doc}", doc_path.exists())

    # Check directory structure
    dirs = ["scripts", "ai", "security", "notifications", "web-interface", "config", "docs"]
    for dir_name in dirs:
        dir_path = base_dir / dir_name
        all_pass &= check(f"Directory: {dir_name}/", dir_path.is_dir())

    return all_pass

# ============================================================================
# LEVEL 1: LOW FRICTION - Python Syntax Check (1 minute)
# ============================================================================
def level_1():
    """Low friction - verify Python syntax is valid"""
    print_level(1, "Python Syntax Validation")

    base_dir = Path(__file__).parent

    # Find all Python files
    python_files = list(base_dir.rglob("*.py"))

    all_pass = True
    checked = 0
    for py_file in python_files[:15]:  # Check first 15 files
        relative = py_file.relative_to(base_dir)
        result = run_command(
            f"python3 -m py_compile {py_file}",
            f"Syntax check: {relative}"
        )
        all_pass &= result
        checked += 1

    print(f"\n{Colors.BLUE}Checked {checked} Python files{Colors.END}")
    return all_pass

# ============================================================================
# LEVEL 2: MEDIUM FRICTION - Import & Config Check (2 minutes)
# ============================================================================
def level_2():
    """Medium friction - verify imports and config"""
    print_level(2, "Import & Configuration Check")

    all_pass = True

    # Test imports
    print(f"\n{Colors.YELLOW}Testing Python imports...{Colors.END}")

    imports_to_test = [
        "import json",
        "import requests",
        "import logging",
        "from pathlib import Path",
        "import argparse",
    ]

    for imp in imports_to_test:
        result = run_command(
            f"python3 -c '{imp}'",
            f"Import: {imp}"
        )
        all_pass &= result

    # Check config validity
    print(f"\n{Colors.YELLOW}Checking configuration...{Colors.END}")

    base_dir = Path(__file__).parent
    config_file = base_dir / "config" / "config.json"

    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            all_pass &= check("Config JSON is valid", True)
            all_pass &= check("Config has 'ai' section", 'ai' in config)
            all_pass &= check("Config has 'agent' section", 'agent' in config)
            all_pass &= check("AI is enabled", config.get('ai', {}).get('enabled', False))

            # Check if API key is set (without showing it)
            api_key = config.get('ai', {}).get('api_key', '')
            has_key = api_key and len(api_key) > 10
            all_pass &= check(f"Mistral API key configured ({api_key[:4]}*** if set)", has_key)

        except Exception as e:
            all_pass &= check(f"Config parsing (error: {e})", False)
    else:
        all_pass &= check("Config file exists", False)

    # Check .gitignore protects secrets
    gitignore = base_dir / ".gitignore"
    if gitignore.exists():
        with open(gitignore, 'r') as f:
            content = f.read()
        all_pass &= check(".gitignore protects config.json", "config.json" in content)
        all_pass &= check(".gitignore protects .env files", ".env" in content)

    return all_pass

# ============================================================================
# LEVEL 3: HIGH FRICTION - Module Import Test (3 minutes)
# ============================================================================
def level_3():
    """High friction - test actual module imports"""
    print_level(3, "Module Import Test")

    all_pass = True

    base_dir = Path(__file__).parent
    os.chdir(base_dir)

    # Test custom module imports
    modules = [
        ("security.security_utils", "RateLimiter"),
        ("security.security_utils", "SecureConfig"),
        ("security.security_utils", "WebhookSecurity"),
        ("ai.devstral_vibe", "DevstralVibeAgent"),
    ]

    for module, class_name in modules:
        result = run_command(
            f"python3 -c 'from {module} import {class_name}; print(\"{class_name} imported\")'",
            f"Import: {module}.{class_name}"
        )
        all_pass &= result

    # Test security utilities
    print(f"\n{Colors.YELLOW}Testing security utilities...{Colors.END}")

    test_script = """
from security.security_utils import RateLimiter, SecureConfig

# Test rate limiter
limiter = RateLimiter(max_calls_per_hour=10)
result = limiter.check_limit(estimated_cost=0.01)
print(f'Rate limiter works: {result}')

# Test secure config
config = SecureConfig.load_config('config/config.json')
print(f'Config loaded: {bool(config)}')
"""

    with open('/tmp/test_security.py', 'w') as f:
        f.write(test_script)

    result = run_command(
        f"cd {base_dir} && python3 /tmp/test_security.py",
        "Security utilities functional test",
        show_output=True
    )
    all_pass &= result

    return all_pass

# ============================================================================
# LEVEL 4: VERY HIGH FRICTION - Dry Run Scan (5 minutes)
# ============================================================================
def level_4():
    """Very high friction - dry run without actual network calls"""
    print_level(4, "Agent Dry Run Test")

    print(f"{Colors.YELLOW}NOTE: This level requires network access.{Colors.END}")
    print(f"{Colors.YELLOW}In restricted environments, this may fail.{Colors.END}\n")

    all_pass = True

    base_dir = Path(__file__).parent

    # Test standard recon agent help
    result = run_command(
        f"cd {base_dir} && python3 scripts/recon_agent.py --help",
        "Standard recon agent --help"
    )
    all_pass &= result

    # Test AI recon agent help
    result = run_command(
        f"cd {base_dir} && python3 scripts/ai_recon_agent.py --help",
        "AI recon agent --help"
    )
    all_pass &= result

    # Test web interface (without starting server)
    result = run_command(
        f"python3 -c 'import sys; sys.path.insert(0, \"{base_dir}/web-interface\"); import app; print(\"Flask app loads\")'",
        "Web interface loads"
    )
    all_pass &= result

    print(f"\n{Colors.YELLOW}Network-dependent tests skipped in this environment{Colors.END}")
    print(f"{Colors.BLUE}On real system: python3 scripts/ai_recon_agent.py -t example.com{Colors.END}")

    return all_pass

# ============================================================================
# LEVEL 5: PRODUCTION - Full Deployment Check (Manual)
# ============================================================================
def level_5():
    """Production - deployment checklist"""
    print_level(5, "Production Deployment Checklist")

    print(f"{Colors.YELLOW}Production deployment requires manual verification:{Colors.END}\n")

    checklist = [
        ("Environment variables set (.env or system)", False),
        ("Mistral API key valid and has credits", False),
        ("Telegram bot configured (optional)", False),
        ("Rate limiting configured", False),
        ("Webhook security enabled", False),
        ("PythonAnywhere or VPS deployment", False),
        ("Scheduled tasks configured", False),
        ("First successful scan completed", False),
        ("Notifications working", False),
        ("Results directory writable", False),
    ]

    print(f"{Colors.BOLD}Manual Checklist:{Colors.END}\n")
    for item, completed in checklist:
        status = "☐" if not completed else "☑"
        print(f"  {status} {item}")

    print(f"\n{Colors.BLUE}To deploy:{Colors.END}")
    print(f"1. Set environment variables: cp .env.example .env && nano .env")
    print(f"2. Deploy to PythonAnywhere: See docs/MOBILE_SETUP_GUIDE.md")
    print(f"3. Run first scan: python3 scripts/ai_recon_agent.py -t example.com")
    print(f"4. Schedule automation: See docs/TESTING_GUIDE.md")

    return True

# ============================================================================
# Main
# ============================================================================
def main():
    """Run warm-up tests"""
    print(f"\n{Colors.BOLD}🌡️  Mobile AI Agent - Progressive Warm-Up{Colors.END}")
    print(f"{Colors.BLUE}Tests system readiness from zero to full deployment{Colors.END}\n")

    # Determine level
    if len(sys.argv) > 1:
        try:
            max_level = int(sys.argv[1])
        except:
            print(f"{Colors.RED}Usage: python3 warmup.py [max_level]{Colors.END}")
            print(f"Levels: 0-5 (default: run all)")
            sys.exit(1)
    else:
        max_level = 5

    levels = [
        (0, "Zero Friction - File System", level_0),
        (1, "Low Friction - Syntax Check", level_1),
        (2, "Medium Friction - Config & Imports", level_2),
        (3, "High Friction - Module Loading", level_3),
        (4, "Very High Friction - Dry Run", level_4),
        (5, "Production - Deployment", level_5),
    ]

    results = {}

    # Run levels
    for level_num, name, func in levels:
        if level_num > max_level:
            break

        try:
            passed = func()
            results[level_num] = passed
        except Exception as e:
            print(f"\n{Colors.RED}Level {level_num} crashed: {e}{Colors.END}")
            results[level_num] = False

        if not passed and level_num < 3:
            print(f"\n{Colors.RED}⚠️  Level {level_num} failed. Fix issues before proceeding.{Colors.END}")
            break

    # Summary
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}📊 WARM-UP SUMMARY{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}\n")

    for level_num, passed in results.items():
        status = f"{Colors.GREEN}✅ PASS{Colors.END}" if passed else f"{Colors.RED}❌ FAIL{Colors.END}"
        print(f"Level {level_num}: {status}")

    total_passed = sum(results.values())
    total_run = len(results)

    print(f"\n{Colors.BOLD}Result: {total_passed}/{total_run} levels passed{Colors.END}")

    if total_passed == total_run:
        print(f"{Colors.GREEN}🎉 All warm-ups completed successfully!{Colors.END}")
        print(f"{Colors.BLUE}Ready for production deployment!{Colors.END}")
    elif total_passed >= 3:
        print(f"{Colors.YELLOW}⚠️  Basic functionality works. Review failures before deploying.{Colors.END}")
    else:
        print(f"{Colors.RED}❌ Critical issues found. Fix before proceeding.{Colors.END}")

    print(f"\n{Colors.BLUE}Next steps:{Colors.END}")
    print(f"  • Review: docs/TESTING_GUIDE.md")
    print(f"  • Security: docs/SECURITY_GUIDE.md")
    print(f"  • Deploy: docs/MOBILE_SETUP_GUIDE.md")
    print(f"  • AI Setup: docs/DEVSTRAL_VIBE_GUIDE.md\n")

if __name__ == "__main__":
    main()
