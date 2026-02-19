# 🤖 Devstral CLI Integration

Natural language bug bounty automation using Devstral + iPhone tools.

## 🎯 The Power

Instead of remembering commands, just **talk**:

```bash
# Traditional way:
python quick_recon.py example.com
python header_analyzer.py https://example.com
python mobile_reporter.py xss example.com

# With Devstral:
python devstral_cli.py "scan example.com for bugs"
```

The LLM **figures out what to do** and **executes it**.

## ⚡ Quick Start

### 1. Get Mistral API Key

```bash
# Sign up at https://console.mistral.ai/
# Get your API key
export MISTRAL_API_KEY='your-key-here'

# Set your iPhone IP
export IPHONE_NODE='http://192.168.1.100:5000'
```

### 2. Start Your iPhone Node

```bash
# On iPhone (Pythonista/a-Shell):
python academy_node.py --port 5000
```

### 3. Run Devstral CLI

```bash
# Interactive mode:
python devstral_cli.py

# Quick command:
python devstral_cli.py "scan example.com for subdomains"
```

## 💬 Example Conversations

### Example 1: Quick Recon

```
You: scan example.com

🤖 Devstral: I'll scan example.com for subdomains.

🔧 Executing: scan_subdomains({'domain': 'example.com'})

Found 12 subdomains:
www.example.com
api.example.com
mail.example.com
...

🤖 Devstral: I found 12 subdomains. The most interesting ones are:
- api.example.com (potential API endpoints)
- admin.example.com (administrative interface)
- dev.example.com (development environment)

Want me to check security headers on any of these?
```

### Example 2: Security Check

```
You: check the security headers on https://example.com

🔧 Executing: check_security_headers({'url': 'https://example.com'})

Security Headers for https://example.com:
❌ Strict-Transport-Security: Missing
✅ X-Frame-Options: SAMEORIGIN
❌ Content-Security-Policy: Missing
✅ X-Content-Type-Options: nosniff

🤖 Devstral: The target is missing critical security headers:

MISSING:
- HSTS (Strict-Transport-Security) - Allows HTTP downgrade attacks
- CSP (Content-Security-Policy) - Vulnerable to XSS

This could be reported as a Low severity finding. Want me to create a bug report?
```

### Example 3: Bug Report Creation

```
You: yes, create a report for the missing CSP header

🔧 Executing: create_bug_report({
    'bug_type': 'missing_csp',
    'target': 'https://example.com',
    'description': 'Missing Content-Security-Policy header allows XSS attacks',
    'severity': 'medium'
})

📝 Bug Report Created:
# MISSING_CSP Vulnerability

**Target:** https://example.com
**Severity:** MEDIUM
**Date:** 2024-12-30

## Description
Missing Content-Security-Policy header allows XSS attacks
...

🤖 Devstral: Bug report created! It's saved on your iPhone in BugBounty/reports/
The report is ready to submit to the bug bounty platform.
```

### Example 4: Complex Workflow

```
You: I want to test api.example.com. What should I do?

🤖 Devstral: Let me help you test api.example.com. I'll:
1. Check security headers
2. Look for common API vulnerabilities
3. Suggest next steps

🔧 Executing: check_security_headers({'url': 'https://api.example.com'})

Results show missing CORS headers. Let me check if I can find any API documentation on GitHub...

🔧 Executing: fetch_github_tool({
    'repo': 'example/api-docs',
    'path': 'openapi.yaml'
})

🤖 Devstral: Based on the API documentation, here's what to test:

HIGH PRIORITY:
- /api/users endpoint - Test for IDOR
- /api/admin - Check for broken access control
- Authentication - Try common JWT vulnerabilities

MEDIUM PRIORITY:
- Rate limiting bypass
- API versioning issues

Want me to run any specific tests?
```

### Example 5: Tool Discovery

```
You: find me some XSS payloads from GitHub

🔧 Executing: fetch_github_tool({
    'repo': 'payloadbox/xss-payload-list',
    'path': 'README.md'
})

🤖 Devstral: I found a comprehensive XSS payload collection. Here are some useful ones:

BASIC:
<script>alert(1)</script>
<img src=x onerror=alert(1)>

BYPASS FILTERS:
<svg/onload=alert(1)>
javascript:alert(1)

Want me to save these to your iPhone for quick access?
```

## 🎯 Real-World Workflow

### Morning Routine

```bash
python devstral_cli.py "scan all my targets and summarize findings"
```

Devstral:
1. Reads your target list
2. Scans each domain
3. Checks for new subdomains
4. Compares with previous results
5. Summarizes changes
6. Suggests what to investigate

### Quick Testing

```bash
python devstral_cli.py "test example.com for common bugs"
```

Devstral decides:
- Check security headers
- Enumerate subdomains
- Test for open redirects
- Check for XSS in search
- Generate findings report

### Bug Submission

```bash
python devstral_cli.py "I found XSS in the search box at example.com, create a report"
```

Devstral:
- Creates properly formatted report
- Saves to iPhone
- Suggests CVSS score
- Provides submission checklist

## 🔧 Customization

### Add Your Own Tools

```python
# In devstral_cli.py, add to TOOLS:
{
    "type": "function",
    "function": {
        "name": "my_custom_tool",
        "description": "What it does",
        "parameters": {
            "type": "object",
            "properties": {
                "param": {"type": "string"}
            }
        }
    }
}

# Implement it:
def my_custom_tool(param: str) -> str:
    # Your logic
    return "result"

# Add to TOOL_MAP:
TOOL_MAP["my_custom_tool"] = my_custom_tool
```

### Custom System Prompt

```python
# Modify the system message for different behavior:
messages = [{
    "role": "system",
    "content": """You are an aggressive bug bounty hunter.
Always look for critical vulnerabilities first.
Be thorough and suggest creative testing approaches."""
}]
```

## 💡 Advanced Patterns

### Chain Multiple Tools

```
You: do a complete security audit of example.com

Devstral automatically:
1. Scans subdomains
2. Checks security headers on each
3. Fetches relevant tools from GitHub
4. Runs automated tests
5. Creates prioritized bug list
6. Generates comprehensive report
```

### Context Awareness

```
You: scan example.com

[10 subdomains found]

You: now check the admin one

Devstral remembers "admin.example.com" from previous scan
→ Checks security headers
→ Suggests admin-specific tests
```

### Learning from Your Style

```
You: create a report

Devstral uses your previous reports as templates
→ Matches your writing style
→ Uses your preferred format
→ Includes your typical recommendations
```

## 🚀 Power Features

### 1. Natural Language Tool Selection

```
"check if that site is secure" → security headers
"find subdomains" → subdomain scan
"make a report" → bug report creation
"get that XSS tool" → GitHub fetch
```

### 2. Intelligent Context

```
You: scan example.com
[Results shown]

You: check the API one
# Devstral knows "API one" = api.example.com
```

### 3. Multi-Step Workflows

```
You: test this target completely

Devstral creates a plan:
1. Reconnaissance
2. Vulnerability scanning
3. Manual testing suggestions
4. Report generation
```

### 4. Error Recovery

```
[Scan fails]

Devstral: The scan timed out. Let me try a smaller subdomain list first.
[Retries with optimized approach]
```

## 📊 Why This Works

**Traditional CLI:**
```bash
# You need to remember:
python quick_recon.py example.com --verbose
python header_analyzer.py https://example.com --output report.txt
python mobile_reporter.py xss example.com --severity high
```

**With Devstral:**
```
You: test example.com and report any bugs
```

Done. The LLM:
- ✅ Chooses the right tools
- ✅ Executes them in order
- ✅ Interprets results
- ✅ Suggests next steps
- ✅ Creates reports

## 🎯 When to Use This

**Perfect For:**
- ✅ Quick testing during commute
- ✅ Exploring new targets
- ✅ Automating routine checks
- ✅ Learning bug bounty
- ✅ Generating reports

**Not For:**
- ❌ Deep manual testing (you still need to do this)
- ❌ Replacing your expertise (it's an assistant)
- ❌ Finding 0-days (creative exploitation needs you)

## 🔒 Security Notes

- API key is for Devstral (Mistral AI)
- iPhone communication is local network
- No data sent to cloud (except LLM API calls)
- Tool execution happens on your iPhone
- You control what tools are available

## 🎓 Tips

**Be Specific:**
```
❌ "test this"
✅ "scan example.com for XSS and check security headers"
```

**Use Context:**
```
You: scan example.com
You: now test the admin subdomain  # Devstral remembers
```

**Ask for Suggestions:**
```
You: I found an API endpoint, what should I test?
```

**Learn from It:**
```
You: how would you test this for IDOR?
```

## 🚀 Next Level

### Autonomous Mode

```python
# Run continuously, checking targets
python devstral_cli.py --autonomous --targets targets.txt

# Devstral:
# - Monitors targets 24/7
# - Finds new subdomains automatically
# - Tests common vulnerabilities
# - Creates reports when bugs found
# - Notifies you of findings
```

### Team Integration

```python
# Share context across team
python devstral_cli.py --team-mode

# Learns from all team members
# Shares successful techniques
# Collaborative bug hunting
```

---

**This is the actual power of the system.** Not over-engineered infrastructure, but **practical AI automation** that makes bug bounty hunting faster and smarter! 🚀
