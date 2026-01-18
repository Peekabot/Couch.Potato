# 📱 Mobile AI Recon Agent

> **AI-powered bug bounty reconnaissance 24/7, controlled entirely from your mobile device**

<p align="center">
  <img src="https://img.shields.io/badge/Platform-PythonAnywhere-blue" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.7+-green" alt="Python">
  <img src="https://img.shields.io/badge/Mobile-Friendly-brightgreen" alt="Mobile">
  <img src="https://img.shields.io/badge/AI-Powered-purple" alt="AI">
  <img src="https://img.shields.io/badge/Cost-Free-success" alt="Cost">
</p>

---

## 🚀 What is This?

A complete mobile-first automation system for bug bounty hunters with **AI-powered intelligence** (Mistral AI) that runs 24/7 in the cloud (no VPS needed!) and can be controlled entirely from your smartphone.

### Key Features

✅ **🤖 AI-Powered** - Mistral AI for intelligent target prioritization & analysis
✅ **Zero Infrastructure** - Runs on PythonAnywhere free tier
✅ **Mobile Control** - Web dashboard optimized for phones
✅ **24/7 Automation** - Scheduled reconnaissance scans
✅ **Real-time Notifications** - Telegram/Email alerts
✅ **Auto PoC Generation** - AI creates proof-of-concept exploits
✅ **GitHub Integration** - Auto-commit findings
✅ **No Root Required** - API-based tools for restricted environments

---

## 📋 Quick Start

### 5-Minute Setup (Standard Mode)

```bash
# 1. Clone repository
git clone https://github.com/Peekabot/Couch.Potato.git
cd Couch.Potato/mobile-ai-agent

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure
cp config/config.example.json config/config.json
nano config/config.json  # Edit with your settings

# 4. Run first scan
python3 scripts/recon_agent.py -t example.com

# 5. Start web interface (optional)
cd web-interface
python3 app.py
```

**That's it!** Your agent is now ready to scan.

### 🤖 AI-Enhanced Mode (Recommended)

```bash
# 1. Get Mistral API key (free tier available)
# Visit: https://console.mistral.ai

# 2. Enable AI in config
nano config/config.json
```

```json
{
  "ai": {
    "enabled": true,
    "mode": "api",
    "api_provider": "mistral",
    "api_key": "YOUR_MISTRAL_API_KEY"
  }
}
```

```bash
# 3. Run AI-enhanced scan
python3 scripts/ai_recon_agent.py -t example.com
```

**AI Features**:
- 🎯 Smart target prioritization
- 🔍 Intelligent vulnerability analysis
- ⚡ Automated PoC generation
- 📊 Enhanced professional reports
- 🧭 Next-step suggestions

→ [Read the full AI guide](docs/AI_INTEGRATION_GUIDE.md)

---

## 📱 Mobile Access

### Method 1: PythonAnywhere (Recommended)

1. **Sign up**: [pythonanywhere.com](https://www.pythonanywhere.com)
2. **Clone repo** in PythonAnywhere console
3. **Schedule task**: Tasks → Add scheduled task
4. **Access dashboard**: `https://yourusername.pythonanywhere.com`

### Method 2: Telegram Bot

Control your agent via Telegram commands:

```
/start_scan example.com
/status
/get_report
/add_target newsite.com
```

### Method 3: Direct API

```bash
# From Termux or iOS Shortcuts
curl -X POST https://yourusername.pythonanywhere.com/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

---

## 🏗️ Directory Structure

```
mobile-ai-agent/
├── docs/
│   ├── MOBILE_SETUP_GUIDE.md      # Comprehensive setup guide
│   └── AI_INTEGRATION_GUIDE.md     # AI integration guide 🤖
├── scripts/
│   ├── recon_agent.py             # Standard reconnaissance agent
│   ├── ai_recon_agent.py          # AI-enhanced agent 🤖
│   └── run_agent.sh               # Scheduler wrapper script
├── ai/
│   ├── devstral_vibe.py           # AI intelligence module 🤖
│   └── __init__.py
├── notifications/
│   ├── telegram_notify.py         # Telegram integration
│   └── email_notify.py            # Email notifications
├── web-interface/
│   ├── app.py                     # Flask web app
│   └── templates/
│       └── index.html             # Mobile-friendly dashboard
├── config/
│   └── config.example.json        # Configuration template (with AI settings)
├── results/                       # Scan outputs (auto-created)
├── logs/                          # Agent logs (auto-created)
├── requirements.txt               # Python dependencies
└── README.md                      # This file
```

---

## ⚙️ Configuration

### Basic Setup

Edit `config/config.json`:

```json
{
  "notification": {
    "telegram_enabled": true,
    "telegram_bot_token": "YOUR_BOT_TOKEN",
    "telegram_chat_id": "YOUR_CHAT_ID"
  },
  "targets": [
    "example.com",
    "testsite.com"
  ],
  "scan_interval_hours": 12
}
```

### Get Telegram Bot Token

1. Message `@BotFather` on Telegram
2. Send `/newbot`
3. Follow instructions
4. Copy token to config

### Get Chat ID

```bash
# Send a message to your bot, then run:
python3 notifications/telegram_notify.py YOUR_BOT_TOKEN get_updates
```

---

## 🤖 Usage

### Manual Scan

```bash
# Scan a single target
python3 scripts/recon_agent.py -t example.com

# Scan from file
python3 scripts/recon_agent.py -l targets.txt

# Scan all configured targets
python3 scripts/recon_agent.py
```

### Scheduled Scans (PythonAnywhere)

**Tasks** tab → Add:
- **Command**: `/home/USERNAME/Couch.Potato/mobile-ai-agent/scripts/run_agent.sh`
- **Time**: `03:00`
- **Frequency**: Daily

### Web Dashboard

```bash
cd web-interface
python3 app.py

# Access at: http://localhost:5000
# Or on PythonAnywhere: https://yourusername.pythonanywhere.com
```

---

## 📊 What Gets Scanned?

### Reconnaissance Phase

1. **Subdomain Enumeration**
   - crt.sh API
   - subfinder (if installed)
   - Custom wordlists

2. **Live Host Probing**
   - HTTP/HTTPS probing
   - Status code checking
   - Redirect following

3. **Technology Detection**
   - Server headers
   - Framework detection
   - Version disclosure

4. **Security Checks**
   - Missing security headers
   - CORS misconfigurations
   - Exposed sensitive files

### Output Format

```
results/
└── example_com/
    ├── all_subdomains.txt         # All discovered subdomains
    ├── live_hosts.txt             # Live HTTP/HTTPS hosts
    ├── findings.json              # Security findings
    └── report_20250118_120000.md  # Formatted report
```

---

## 🔔 Notifications

### Telegram Example

```
🔍 Scan Complete - example.com

📊 Results:
• Subdomains: 47
• Live Hosts: 23
• Findings: 5

🚨 Severity Breakdown:
• Critical: 0
• High: 1
• Medium: 4

⏰ Time: 2025-01-18 03:00:00
```

### Email Example

HTML-formatted report with attachments sent to your inbox.

---

## 🛠️ Advanced Features

### API Integration

For PythonAnywhere free tier (no system tools):

```json
{
  "api_keys": {
    "securitytrails": "YOUR_KEY",
    "shodan": "YOUR_KEY",
    "virustotal": "YOUR_KEY"
  }
}
```

### GitHub Auto-Commit

Automatically commit findings to GitHub:

```json
{
  "github": {
    "auto_commit": true,
    "repository": "username/bug-reports",
    "branch": "main",
    "token": "ghp_xxxxx"
  }
}
```

### Custom Scan Profiles

```json
{
  "profiles": {
    "light": ["subdomain_enum", "live_probe"],
    "medium": ["subdomain_enum", "live_probe", "basic_security"],
    "heavy": ["all_modules"]
  }
}
```

---

## 📱 Mobile Workflows

### Workflow 1: Morning Routine

1. ☕ Wake up
2. 📱 Check Telegram notification
3. 👀 Review findings
4. 🎯 Submit valid bugs

### Workflow 2: On-the-Go Scanning

1. 🚶 Find new program while commuting
2. 📱 Open PythonAnywhere mobile browser
3. ▶️ Start quick scan
4. 🔔 Get notification when done

### Workflow 3: Automated Discovery

1. 📝 Add targets to config
2. ⏰ Agent scans every 12 hours
3. 📊 Weekly summary via email
4. 💰 Profit!

---

## 🚨 Troubleshooting

### Agent Not Running

```bash
# Check logs
cat logs/recon_agent.log

# Test manually
python3 scripts/recon_agent.py -t test.com

# Verify config
python3 -c "import json; print(json.load(open('config/config.json')))"
```

### No Notifications

```bash
# Test Telegram
python3 notifications/telegram_notify.py YOUR_TOKEN YOUR_CHAT_ID "Test"

# Test Email
python3 notifications/email_notify.py your@email.com
```

### PythonAnywhere Limitations

**Cannot install**: nmap, masscan, nikto (require root)
**Can install**: Python packages via pip
**Workaround**: Use API-based alternatives

---

## 💡 Tips & Best Practices

### Performance

- ⚡ Limit concurrent scans to 3
- 🕐 Schedule during off-peak hours
- 💾 Clean old results regularly

### Security

- 🔐 Never commit config.json with tokens
- 🔑 Use app-specific passwords for email
- 🎯 Only scan authorized targets

### Cost Optimization

- 💰 Use free tier for light workloads
- 📊 Monitor CPU quota usage
- 🔄 Upgrade only if needed ($5/month)

---

## 📚 Documentation

- **[Complete Setup Guide](docs/MOBILE_SETUP_GUIDE.md)** - Detailed walkthrough
- **[🤖 Mistral AI AI Guide](docs/AI_INTEGRATION_GUIDE.md)** - AI features & setup ⭐ NEW
- **[API Reference](web-interface/README.md)** - Web API docs
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues

---

## 🤖 AI Features (Mistral AI)

### What the AI Does

**1. Smart Target Prioritization** 🎯
```
Input:  200 discovered subdomains
Output: "api.example.com (score: 9/10) - API endpoint, high-value target"
```

**2. Vulnerability Analysis** 🔍
```
Finding: Missing X-Frame-Options
AI:      "Exploitability: 6/10, Worth reporting: YES, Impact: Clickjacking on login"
```

**3. Automated PoC Generation** ⚡
```
AI generates complete proof-of-concept:
- Steps to reproduce
- Expected vs actual behavior
- Remediation recommendations
- Safety notes
```

**4. Professional Reports** 📊
```
Transforms technical output → Client-ready security report
```

**5. Next Steps** 🧭
```
AI: "Test the API at /v1/users for IDOR vulnerabilities"
```

### AI Mode Options

| Mode | Cost | Speed | Privacy | Setup |
|------|------|-------|---------|-------|
| **Mistral API** | ~$0.01/scan | Fast | Cloud | 1 minute |
| **Ollama (local)** | FREE | Medium | 100% private | 5 minutes |
| **HuggingFace** | FREE* | Slow | Cloud | 2 minutes |

\* Free tier has rate limits

→ **[Complete AI Setup Guide](docs/AI_INTEGRATION_GUIDE.md)**

---

## 🤝 Contributing

Found a bug or have an improvement?

1. Fork this repo
2. Create a branch: `git checkout -b feature/improvement`
3. Make changes and commit
4. Submit a pull request

---

## 📜 License

MIT License - See [LICENSE](../LICENSE)

---

## 🎯 Roadmap

- [x] ✅ AI-powered vulnerability analysis (Mistral AI)
- [x] ✅ Intelligent target prioritization
- [x] ✅ Automated PoC generation
- [ ] Telegram bot commands (in progress)
- [ ] Integration with bug bounty platforms (HackerOne, Bugcrowd APIs)
- [ ] Docker container for easy deployment
- [ ] Mobile app (iOS/Android)
- [ ] Real-time dashboard updates (WebSocket)
- [ ] Multi-agent AI reasoning (multiple models vote)
- [ ] Learning from successful bug reports

---

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is for authorized security testing only.

- ✅ Only scan targets you have permission to test
- ✅ Follow bug bounty program rules
- ✅ Respect rate limits and scopes
- ❌ Never scan unauthorized systems
- ❌ Don't use for malicious purposes

**Misuse of this tool may be illegal. Use responsibly.**

---

## 🙏 Credits

Built with ❤️ for the bug bounty community.

**Tools & Services**:
- [PythonAnywhere](https://www.pythonanywhere.com)
- [Telegram Bot API](https://core.telegram.org/bots)
- [Flask](https://flask.palletsprojects.com)
- [ProjectDiscovery](https://github.com/projectdiscovery)

**Special Thanks**:
- All bug bounty hunters sharing knowledge
- Open-source security tool developers

---

## 📞 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/Peekabot/Couch.Potato/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/Peekabot/Couch.Potato/discussions)
- 📧 **Email**: Open an issue instead

---

**Ready to hunt bugs from your phone?** 🐛📱

→ Start with the [Quick Start](#-quick-start)
→ Read the [Complete Guide](docs/MOBILE_SETUP_GUIDE.md)
→ Happy hunting! 🎯💰
