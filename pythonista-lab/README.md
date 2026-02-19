# 🐍 Pythonista Lab for Claude Code

Welcome to the Pythonista Lab - a comprehensive workspace for Python-based bug bounty hunting tools, experiments, and Claude Code integration examples.

## 🎯 Purpose

This lab serves as a playground for:
- **Learning Python** for security testing with Claude Code assistance
- **Building custom tools** for bug bounty hunting
- **Experimenting** with automation and scripting
- **Developing utilities** for vulnerability research
- **Testing Claude Code** capabilities with Python

## 📁 Directory Structure

```
pythonista-lab/
├── examples/          # Claude Code integration examples
├── utilities/         # Ready-to-use bug bounty utilities
├── experiments/       # Experimental scripts and PoCs
├── templates/         # Python script templates
└── README.md         # This file
```

## 🚀 Quick Start

### Desktop Setup
```bash
# Ensure Python 3.8+ is installed
python3 --version

# Install common dependencies
pip install requests beautifulsoup4 python-dotenv colorama dnspython
```

### 📱 iPhone Setup (NEW!)

**Option 1: a-Shell (Recommended)**
```bash
1. Install a-Shell from App Store (FREE)
2. Open a-Shell and install packages:
   pip install requests beautifulsoup4 dnspython colorama
3. Clone this repo:
   git clone https://github.com/Peekabot/Couch.Potato.git
4. Start hunting from your iPhone! 📱
```

**Option 2: Pythonista 3**
```bash
1. Install Pythonista 3 ($9.99)
2. Copy ios/pythonista/ scripts to Pythonista
3. Run directly from the app
```

See [ios/README.md](ios/README.md) for complete iPhone setup guide.

### Using with Claude Code

Claude Code can help you:
1. **Generate new scripts** - Ask Claude to create custom tools
2. **Debug existing code** - Get help fixing errors
3. **Optimize performance** - Improve script efficiency
4. **Add features** - Extend functionality
5. **Explain code** - Understand complex logic

## 🛠️ Available Utilities

### Reconnaissance Tools
- `subdomain_enum.py` - Subdomain enumeration
- `header_analyzer.py` - HTTP header security analysis
- `jwt_decoder.py` - JWT token decoder and analyzer

### 📱 iPhone Tools (NEW!)
- `ios/pythonista/quick_recon.py` - Mobile-optimized subdomain scanner
- `ios/pythonista/mobile_reporter.py` - Quick bug report generator for iPhone
- `ios/web-mobile/mobile_dashboard.py` - Touch-optimized web dashboard

**Run from iPhone:**
```bash
# Using a-Shell or Pythonista 3
python ios/pythonista/quick_recon.py example.com
python ios/pythonista/mobile_reporter.py xss target.com

# Mobile Web Dashboard
python ios/web-mobile/mobile_dashboard.py
# Then open Safari → localhost:8080
```

## 💡 Example Workflows

### 1. Create a New Tool with Claude
```
Ask Claude: "Create a Python script that checks for common security headers"
Claude will generate the script and explain usage
```

### 2. Enhance Existing Tool
```
Ask Claude: "Add rate limiting to the port scanner to avoid detection"
Claude will modify the code with proper implementation
```

### 3. Debug Issues
```
Ask Claude: "Why is my subdomain enumeration script timing out?"
Claude will analyze and suggest fixes
```

## 📚 Learning Resources

### Python for Bug Bounty
- [OWASP Python Security](https://owasp.org/www-project-python-security/)
- [Requests Documentation](https://docs.python-requests.org/)
- [BeautifulSoup Guide](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)

### Claude Code Tips
- Use clear, specific prompts
- Provide context about your testing environment
- Ask for explanations of complex code
- Request security best practices

## 🎓 Experiments Directory

Use the `experiments/` folder to:
- Test new vulnerability techniques
- Prototype automation ideas
- Learn Python security libraries
- Build custom exploit PoCs (for authorized testing only)

## 🔧 Common Patterns

### API Request Template
```python
import requests

def make_request(url, headers=None):
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response
    except requests.RequestException as e:
        print(f"Error: {e}")
        return None
```

### Concurrent Processing
```python
from concurrent.futures import ThreadPoolExecutor

def process_urls(urls):
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(check_url, urls)
    return list(results)
```

## ⚠️ Security & Ethics

- **Only test authorized targets**
- **Respect rate limits**
- **Never use for malicious purposes**
- **Follow responsible disclosure**
- **Sanitize data before sharing**

## 🎯 Project Ideas

- [ ] Build a custom reconnaissance framework
- [ ] Create automated XSS payload generator
- [ ] Develop API fuzzing tool
- [ ] Build SSRF vulnerability scanner
- [ ] Create report templating system
- [ ] Automate subdomain takeover detection

## 🤝 Using with Bug Bounty Workflow

1. **Develop tool** in pythonista-lab
2. **Test on authorized targets** from your bug bounty programs
3. **Document findings** in `/reports`
4. **Save PoC** in `/poc` if needed
5. **Update tracker** in `SUBMISSION_TRACKER.md`

## 📝 Best Practices

- **Version control**: Commit working versions frequently
- **Documentation**: Add docstrings and comments
- **Error handling**: Always handle exceptions gracefully
- **Testing**: Test scripts in safe environments first
- **Dependencies**: Track requirements in `requirements.txt`

## 📱 Mobile Bug Bounty (iPhone)

Hunt bugs from anywhere with your iPhone! Complete toolkit for iOS:

**Quick Links:**
- 📱 [iPhone Setup Guide](ios/README.md) - Complete guide for bug bounty on iPhone
- 🔗 [iOS Shortcuts Guide](ios/shortcuts/SHORTCUTS_GUIDE.md) - Automate workflows
- 📋 [Mobile Workflows](ios/WORKFLOWS.md) - Real-world hunting workflows
- 🌐 [Web Dashboard](ios/web-mobile/mobile_dashboard.py) - Touch-optimized interface

**Features:**
- ✅ Mobile-optimized Python tools
- ✅ iOS Shortcuts integration
- ✅ Touch-friendly web dashboard
- ✅ Voice dictation support
- ✅ iCloud sync
- ✅ Offline-capable
- ✅ Works with a-Shell, Pythonista, iSH

**Perfect for:**
- Commute hunting 🚇
- Travel testing ✈️
- Quick recon on the go
- Emergency bug submission
- Morning routine scans
- Weekend marathons

## 🚨 Troubleshooting

### Common Issues

**Import errors**
```bash
pip install -r requirements.txt
```

**Permission errors**
```bash
chmod +x script_name.py
```

**Rate limiting**
- Add delays between requests
- Use rotating proxies
- Implement exponential backoff

## 📊 Progress Tracking

Track your Python learning journey:
- [ ] Complete first Python tool
- [ ] Build 5 utility scripts
- [ ] Automate a full reconnaissance workflow
- [ ] Find vulnerability using custom tool
- [ ] Contribute tool to open source

## 🔗 Useful Libraries

| Library | Purpose | Installation |
|---------|---------|--------------|
| requests | HTTP requests | `pip install requests` |
| beautifulsoup4 | HTML parsing | `pip install beautifulsoup4` |
| selenium | Browser automation | `pip install selenium` |
| scapy | Packet manipulation | `pip install scapy` |
| paramiko | SSH operations | `pip install paramiko` |
| pyjwt | JWT handling | `pip install pyjwt` |
| colorama | Terminal colors | `pip install colorama` |
| python-dotenv | Environment vars | `pip install python-dotenv` |

---

**Happy Hacking! 🐍🔐**

> Remember: With great power comes great responsibility. Always hack ethically and within legal boundaries.
