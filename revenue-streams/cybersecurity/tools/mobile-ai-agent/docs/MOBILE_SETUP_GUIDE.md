# 📱 Mobile-First AI Agent Setup Guide

> **Run and control AI-powered bug bounty automation entirely from your mobile device — no VPS needed!**

---

## 🎯 Overview

This guide enables you to run automated reconnaissance, vulnerability scanning, and monitoring agents 24/7, controlled entirely from your smartphone. Perfect for bug bounty hunters on the go.

### What You'll Get

✅ **24/7 automated reconnaissance** running in the cloud
✅ **Mobile-friendly web dashboard** for control & monitoring
✅ **Real-time notifications** via Telegram/Email
✅ **Zero server setup** — uses PythonAnywhere's free tier
✅ **GitHub integration** for task management
✅ **Automated report generation** and vulnerability tracking

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites
- Mobile phone (iOS/Android)
- GitHub account
- PythonAnywhere account (free tier)
- Telegram account (optional, for notifications)

### Step 1: Clone This Repository

From your mobile browser or using Termux (Android):

```bash
git clone https://github.com/Peekabot/Couch.Potato.git
cd Couch.Potato/mobile-ai-agent
```

### Step 2: Set Up PythonAnywhere

1. **Sign up** at [pythonanywhere.com](https://www.pythonanywhere.com)
2. **Open Console** → Start a Bash console
3. **Clone repo**:
   ```bash
   git clone https://github.com/Peekabot/Couch.Potato.git
   cd Couch.Potato/mobile-ai-agent
   ```
4. **Install dependencies**:
   ```bash
   pip3 install --user -r requirements.txt
   ```

### Step 3: Configure Your Agent

1. **Copy config template**:
   ```bash
   cp config/config.example.json config/config.json
   ```

2. **Edit config** (via PythonAnywhere web editor or mobile):
   ```json
   {
     "notification": {
       "telegram_bot_token": "YOUR_BOT_TOKEN",
       "telegram_chat_id": "YOUR_CHAT_ID"
     },
     "targets": [
       "example.com"
     ],
     "scan_interval_hours": 12
   }
   ```

### Step 4: Schedule Your Agent

In PythonAnywhere → **Tasks** tab:

1. **Add scheduled task**:
   - **Command**: `/home/YOURUSERNAME/Couch.Potato/mobile-ai-agent/scripts/run_agent.sh`
   - **Time**: `12:00` (or your preferred time)
   - **Frequency**: Daily

2. **Start first run** manually:
   ```bash
   cd /home/YOURUSERNAME/Couch.Potato/mobile-ai-agent
   python3 scripts/recon_agent.py
   ```

### Step 5: Access from Mobile

📱 **Web Dashboard**: `https://YOURUSERNAME.pythonanywhere.com`
📨 **Notifications**: Telegram bot sends updates
📊 **Logs**: PythonAnywhere → Files → `logs/`

---

## 🏗️ Architecture

```
┌─────────────────┐
│  Mobile Device  │
│   (Control)     │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────┐
│      PythonAnywhere Cloud       │
│  ┌───────────────────────────┐  │
│  │   Scheduled Tasks (Cron)  │  │
│  └───────────┬───────────────┘  │
│              ▼                   │
│  ┌───────────────────────────┐  │
│  │    Recon Agent Script     │  │
│  │  - Subdomain enumeration  │  │
│  │  - Port scanning          │  │
│  │  - Vuln detection         │  │
│  └───────────┬───────────────┘  │
│              ▼                   │
│  ┌───────────────────────────┐  │
│  │   Notification System     │  │
│  │  - Telegram alerts        │  │
│  │  - Email reports          │  │
│  └───────────┬───────────────┘  │
└──────────────┼───────────────────┘
               ▼
        ┌──────────────┐
        │   GitHub     │
        │  (Results)   │
        └──────────────┘
```

---

## 📋 Platform Comparison

| Platform | Mobile Access | Free Tier | Scheduling | GPU | Best For |
|----------|---------------|-----------|------------|-----|----------|
| **PythonAnywhere** | ✅ Excellent | 1 CPU | ✅ Cron | ❌ | Recon, scripts |
| **Replit** | ✅ Excellent | 0.5 CPU | ⚠️ Always-on (paid) | ❌ | Quick tests |
| **Google Colab** | ✅ Good | GPU/TPU | ❌ 12h limit | ✅ | ML models |
| **Paperspace** | ✅ Good | GPU | ✅ | ✅ | Heavy compute |
| **Termux (Local)** | ✅ Native | Phone CPU | ✅ Cron | ❌ | Offline work |

**Recommendation**: Start with **PythonAnywhere** for reliability and ease of mobile access.

---

## 🔧 Configuration Options

### Basic Configuration (`config/config.json`)

```json
{
  "agent": {
    "name": "BugBountyBot",
    "mode": "auto",
    "max_concurrent_scans": 3
  },
  "notification": {
    "telegram_enabled": true,
    "telegram_bot_token": "YOUR_BOT_TOKEN",
    "telegram_chat_id": "YOUR_CHAT_ID",
    "email_enabled": false,
    "email_to": "your@email.com"
  },
  "targets": [
    "*.example.com",
    "testsite.com"
  ],
  "scan_interval_hours": 12,
  "tools": {
    "subfinder": true,
    "httpx": true,
    "nuclei": true,
    "nmap": false
  },
  "github": {
    "auto_commit": true,
    "repository": "Peekabot/Couch.Potato",
    "branch": "main"
  }
}
```

### Advanced: Task Scheduling

**Multiple scans per day**:
```bash
# PythonAnywhere Tasks
00:00 - Morning recon
12:00 - Afternoon recon
18:00 - Evening recon
```

**Custom scan profiles**:
```json
{
  "profiles": {
    "light": ["subfinder", "httpx"],
    "medium": ["subfinder", "httpx", "nuclei"],
    "heavy": ["all_tools"]
  }
}
```

---

## 📱 Mobile Control Methods

### Method 1: PythonAnywhere Web Interface (Recommended)

**From Safari/Chrome on mobile**:

1. **Login**: `pythonanywhere.com` → Sign in
2. **Edit files**: Files tab → Navigate to scripts
3. **Run commands**: Consoles → New console
4. **View logs**: Files → `logs/` directory
5. **Manage tasks**: Tasks tab → Add/remove schedules

**Pros**: Full control, file editing, log viewing
**Cons**: Requires internet connection

### Method 2: Telegram Bot Control

Send commands to your bot:

```
/start_scan example.com
/status
/get_report
/stop
/add_target newsite.com
```

**Pros**: Quick mobile access, notifications included
**Cons**: Requires bot setup

### Method 3: GitHub-Based Control

**Push tasks via mobile GitHub app**:

1. Edit `targets.txt` in GitHub mobile app
2. PythonAnywhere pulls changes every hour
3. Agent automatically scans new targets

**Pros**: Version controlled, simple
**Cons**: Not real-time

### Method 4: Termux (Android) - Local Control

**Run directly on phone**:

```bash
# Install Termux from F-Droid
pkg install python git
git clone https://github.com/Peekabot/Couch.Potato.git
cd Couch.Potato/mobile-ai-agent
pip install -r requirements.txt
python scripts/recon_agent.py
```

**Pros**: Fully offline, no cloud needed
**Cons**: Drains battery, requires phone to stay on

---

## 🔔 Notification Setup

### Telegram Notifications (Recommended)

**Step 1: Create Bot**

1. Message `@BotFather` on Telegram
2. Send `/newbot`
3. Name your bot: `MyBugBountyBot`
4. Copy the **token**

**Step 2: Get Chat ID**

1. Message your bot: `/start`
2. Visit: `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. Find your **chat_id** in JSON response

**Step 3: Configure**

```json
{
  "notification": {
    "telegram_bot_token": "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz",
    "telegram_chat_id": "123456789"
  }
}
```

**What You'll Receive**:
- 🎯 New targets discovered
- 🚨 Vulnerabilities found
- ✅ Scan completion status
- 📊 Daily summary reports

### Email Notifications

**Using Gmail**:

```json
{
  "notification": {
    "email_enabled": true,
    "email_to": "your@gmail.com",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_user": "your@gmail.com",
    "smtp_password": "app_password"
  }
}
```

---

## 🤖 AI Agent Features

### 1. Automated Reconnaissance

**What it does**:
- Subdomain enumeration (subfinder, amass)
- Port scanning (nmap alternatives)
- Technology detection (httpx, wappalyzer)
- Screenshot capture
- Endpoint discovery

**Output**:
```
reports/
├── subdomains.txt
├── live_hosts.txt
├── open_ports.txt
├── technologies.json
└── screenshots/
```

### 2. Vulnerability Scanning

**What it does**:
- CVE detection (nuclei)
- Misconfiguration checks
- XSS/SQLi parameter fuzzing
- API endpoint testing
- CORS/CSP analysis

**Output**:
```
vulnerabilities/
├── nuclei_findings.json
├── xss_candidates.txt
├── sqli_candidates.txt
└── api_issues.json
```

### 3. Continuous Monitoring

**What it does**:
- Daily rescans of targets
- Diff detection (new subdomains)
- Change alerts
- Automated reporting

**Notification example**:
```
🚨 NEW FINDINGS - example.com

🎯 3 new subdomains discovered
🔓 1 potential vulnerability (SQLi)
📊 Report: github.com/Peekabot/Couch.Potato/reports/scan_2025-01-18.md
```

---

## 💡 Workflow Examples

### Workflow 1: Daily Automated Recon

**Setup** (one-time):
```bash
# PythonAnywhere scheduled task at 03:00 AM
python3 /home/username/Couch.Potato/mobile-ai-agent/scripts/recon_agent.py
```

**What happens**:
1. 🕐 3:00 AM: Agent wakes up
2. 🔍 Scans all targets in `config.json`
3. 📝 Generates reports
4. 💾 Commits to GitHub
5. 📱 Sends Telegram summary
6. 😴 Goes back to sleep

**Your part**:
- ☕ Wake up to Telegram notification
- 📖 Review findings on mobile
- 🎯 Submit bugs if found

### Workflow 2: On-Demand Scans

**From mobile browser**:
1. Open PythonAnywhere console
2. Run: `python3 scripts/recon_agent.py --target newsite.com`
3. Get Telegram notification when done

### Workflow 3: GitHub-Driven Automation

**From GitHub mobile app**:
1. Edit `targets.txt` → Add new domain
2. Commit changes
3. PythonAnywhere auto-pulls every hour
4. Agent scans new target automatically

---

## 🛠️ Advanced Usage

### Custom AI Models (Devstral Vibe Integration)

**For advanced users who want AI-powered decision making**:

```python
# scripts/ai_agent.py
from transformers import AutoModelForCausalLM, AutoTokenizer

# Load lightweight model (CPU-friendly)
model = AutoModelForCausalLM.from_pretrained("TheBloke/CodeLlama-7B-GGUF")
tokenizer = AutoTokenizer.from_pretrained("TheBloke/CodeLlama-7B-GGUF")

# AI decides what to scan next
prompt = f"Given these subdomains: {subdomains}, which should I prioritize?"
response = model.generate(tokenizer.encode(prompt))
```

**Note**: This requires PythonAnywhere paid tier or local Termux execution.

### API-Based Control

**Create a simple Flask API**:

```python
# scripts/api_server.py
from flask import Flask, request
app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def trigger_scan():
    target = request.json['target']
    # Trigger scan
    return {"status": "started", "target": target}
```

**Deploy on PythonAnywhere**:
- Web tab → Add new web app → Flask
- Access via: `https://yourusername.pythonanywhere.com/scan`

**Control from mobile**:
```bash
# Using Termux or Shortcuts app
curl -X POST https://yourusername.pythonanywhere.com/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

---

## 📊 Monitoring & Logs

### View Logs on Mobile

**PythonAnywhere**:
1. Files tab → `logs/recon_agent.log`
2. View in browser

**Telegram**:
- Agent sends log snippets on errors

**GitHub**:
- Automated commits include summary

### Log Format

```
[2025-01-18 03:00:01] INFO - Starting reconnaissance
[2025-01-18 03:00:15] INFO - Found 15 subdomains for example.com
[2025-01-18 03:01:30] WARNING - Timeout on port scan for sub.example.com
[2025-01-18 03:05:00] INFO - Scan complete. 3 findings.
[2025-01-18 03:05:10] INFO - Report saved: reports/2025-01-18_example.com.md
[2025-01-18 03:05:15] SUCCESS - Notification sent to Telegram
```

---

## 🚨 Troubleshooting

### Agent Not Running

**Check**:
1. PythonAnywhere Tasks → Verify schedule
2. Console → Run manually to see errors
3. Logs → Check for exceptions

**Common issues**:
- Missing API keys in config
- Tool not installed (run `install_tools.sh`)
- Network timeout (increase timeout in config)

### No Notifications

**Telegram**:
- Verify bot token: `curl https://api.telegram.org/bot<TOKEN>/getMe`
- Verify chat ID: Send `/start` to bot
- Check internet in PythonAnywhere console

**Email**:
- Use app-specific password for Gmail
- Check spam folder
- Verify SMTP settings

### Tools Not Found

**PythonAnywhere limitations**:
- ❌ Cannot install: nmap, masscan (require root)
- ✅ Can install: subfinder, httpx, nuclei, amass

**Workarounds**:
1. Use API-based alternatives (SecurityTrails, Shodan)
2. Run heavy tools locally on Termux
3. Use cloud alternatives (Censys, VirusTotal APIs)

---

## 💰 Cost Breakdown

### Free Tier (Recommended for Starting)

| Service | Free Tier | Limits |
|---------|-----------|--------|
| PythonAnywhere | 1 web app, 1 cron task | 512 MB disk, CPU quota |
| Telegram Bot | Unlimited | No limits |
| GitHub | Unlimited repos | Storage limits apply |
| Replit | Basic compute | Sleeps after inactivity |

**Total cost**: **$0/month** 🎉

### Paid Tier (For Power Users)

| Service | Cost | Benefits |
|---------|------|----------|
| PythonAnywhere Hacker | $5/month | More CPU, always-on, more tasks |
| Replit Cycles | $7/month | Always-on, more resources |
| DigitalOcean Droplet | $6/month | Full control, root access |

**Total cost**: **$5-7/month**

---

## 🎯 Next Steps

### Immediate (Today)
1. ✅ Sign up for PythonAnywhere
2. ✅ Create Telegram bot
3. ✅ Clone this repo
4. ✅ Run first manual scan

### This Week
1. ⏰ Set up scheduled tasks
2. 🎯 Add your bug bounty targets
3. 📱 Test mobile notifications
4. 📊 Review first automated report

### This Month
1. 🤖 Customize scan profiles
2. 🔧 Fine-tune notification rules
3. 📈 Track findings vs. time
4. 💰 Submit first bounty!

---

## 📚 Resources

### Documentation
- [PythonAnywhere Help](https://help.pythonanywhere.com/)
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [Subfinder Guide](https://github.com/projectdiscovery/subfinder)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)

### Community
- [Bug Bounty Forum](https://bugbountyforum.com/)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [PythonAnywhere Forums](https://www.pythonanywhere.com/forums/)

### Alternative Tools
- **Mobile IDEs**: Pythonista (iOS), Pydroid (Android)
- **Terminal emulators**: Termux (Android), iSH (iOS)
- **Cloud platforms**: Replit, Glitch, Render

---

## ⚠️ Legal & Ethics

**IMPORTANT**:
- ✅ Only scan targets you have permission to test
- ✅ Follow bug bounty program rules
- ✅ Respect rate limits and scopes
- ❌ Never scan unauthorized systems
- ❌ Don't DDoS or abuse resources

**This tool is for authorized security testing only.**

---

## 🤝 Contributing

Found a bug or have an improvement?

1. Fork this repo
2. Create a branch: `git checkout -b feature/improvement`
3. Make changes
4. Submit PR

---

## 📜 License

MIT License - See [LICENSE](../LICENSE)

---

## 🎉 Credits

Built with ❤️ by bug bounty hunters, for bug bounty hunters.

**Tools used**:
- ProjectDiscovery (subfinder, httpx, nuclei)
- PythonAnywhere
- Telegram Bot API

---

**Ready to automate your bug bounty hunting from your phone?**

→ Start with [Quick Start](#-quick-start-5-minutes)
→ Questions? Open an [issue](https://github.com/Peekabot/Couch.Potato/issues)
→ Happy hunting! 🐛💰
