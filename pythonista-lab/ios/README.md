# 📱 iPhone Bug Bounty Toolkit

Complete guide to conducting bug bounty hunting from your iPhone using Python, iOS Shortcuts, and mobile-optimized tools.

## 🎯 Why Hunt from iPhone?

- **Portability**: Hunt anywhere, anytime
- **Quick Recon**: Fast subdomain checks on the go
- **Report on the Fly**: Submit bugs immediately when found
- **Multi-tasking**: Test while commuting or traveling
- **Always Available**: Never miss a new program launch

## 📱 Recommended iOS Apps

### Essential Apps

| App | Purpose | Cost | Link |
|-----|---------|------|------|
| **a-Shell** | Full terminal with Python | Free | App Store |
| **Pythonista 3** | Python IDE for iOS | $9.99 | App Store |
| **iSH Shell** | Linux shell on iOS | Free | App Store |
| **Working Copy** | Git client | Free | App Store |
| **Shortcuts** | Automation (built-in) | Free | iOS |
| **Inspect Browser** | Web inspector | Free | App Store |

### Optional But Useful

- **Termius** - SSH client for server access
- **Code Editor** - Lightweight code editing
- **WebSSH** - Browser-based SSH
- **HTTPBot** - HTTP client testing
- **DNS Client** - DNS lookup tool

## 🚀 Quick Setup Guide

### 1. Install a-Shell (Recommended)

```bash
# a-Shell comes with Python 3.11 pre-installed
# Open a-Shell and run:
pip install requests beautifulsoup4 dnspython colorama

# Clone your bug bounty repo
git clone https://github.com/yourusername/Couch.Potato.git
cd Couch.Potato/pythonista-lab
```

### 2. Setup Pythonista 3 (Alternative)

```python
# In Pythonista, install StaSh (shell)
# Then install packages via StaSh:
import requests
exec(requests.get('https://bit.ly/get-stash').text)

# Install packages
pip install requests beautifulsoup4
```

### 3. Configure iOS Shortcuts

See `shortcuts/` directory for pre-built shortcuts you can import.

## 🛠️ Mobile-Optimized Tools

All tools in `pythonista/` are optimized for mobile:
- Touch-friendly output
- Minimal dependencies
- Fast execution
- Low bandwidth usage
- Mobile-formatted results

### Quick Recon Tool
```bash
python pythonista/quick_recon.py example.com
```

### Mobile Report Generator
```bash
python pythonista/mobile_reporter.py --bug xss --severity high
```

### URL Collector
```bash
python pythonista/url_grabber.py https://example.com
```

## 📲 iOS Shortcuts Integration

### Available Shortcuts

1. **Quick Domain Scan** - Instant subdomain enumeration
2. **Security Header Check** - Analyze headers for any URL
3. **JWT Decoder** - Decode tokens from clipboard
4. **Bug Report Creator** - Generate report templates
5. **Screenshot to Report** - Convert screenshots to bug evidence

### How to Import Shortcuts

1. Open Safari on iPhone
2. Navigate to `shortcuts/` in this repo
3. Tap on `.shortcut` file
4. Tap "Add Shortcut"
5. Customize as needed

## 🌐 Mobile Web Dashboard

For the ultimate mobile experience, run the web dashboard:

```bash
# On your iPhone (using a-Shell):
cd pythonista-lab/ios/web-mobile
python mobile_dashboard.py

# Then open in Safari:
# http://localhost:8080
```

Features:
- Touch-optimized UI
- Quick domain checks
- Header analysis
- JWT decoder
- Report templates
- Screenshot upload
- Dark mode support

## 📋 iPhone Bug Bounty Workflows

### Workflow 1: Quick Recon on the Go

```
1. Open a-Shell
2. Run: python ios/pythonista/quick_recon.py target.com
3. Review subdomains
4. Save interesting findings to Notes app
5. Follow up later on desktop
```

### Workflow 2: Testing While Commuting

```
1. Open mobile web dashboard
2. Enter target domain
3. Run automated checks:
   - Security headers
   - Subdomain enum
   - Common vulnerabilities
4. Screenshot interesting findings
5. Use Shortcut to create draft report
```

### Workflow 3: Immediate Bug Submission

```
1. Find vulnerability on mobile browser
2. Take screenshot
3. Run "Bug Report Creator" shortcut
4. Fill in template via voice dictation
5. Submit directly from iPhone
```

### Workflow 4: Cross-Device Sync

```
1. Start recon on iPhone (a-Shell)
2. Save results to iCloud/Working Copy
3. Continue on Mac/iPad
4. Submit from any device
```

## 🎯 Mobile-Specific Tips

### Battery Optimization
- Use airplane mode + WiFi for extended scans
- Enable low power mode
- Close background apps
- Use external battery pack

### Network Considerations
- Use WiFi when possible (faster, no data usage)
- VPN recommended for security
- Cellular data works but monitor usage
- Tether to laptop if needed

### Productivity Hacks
- Use Shortcuts for repetitive tasks
- Enable Siri for hands-free scanning
- Split View: Browser + a-Shell
- Picture-in-Picture for videos while testing
- Voice memos for quick note-taking

## 📱 a-Shell Specific Setup

### Install Required Packages

```bash
# In a-Shell terminal:
pkg install python
pip install --upgrade pip
pip install requests beautifulsoup4 dnspython colorama pyjwt

# Clone repo
cd ~/Documents
git clone [your-repo-url]
```

### Create Aliases

```bash
# Add to ~/.profile
alias bb='cd ~/Documents/Couch.Potato/pythonista-lab/ios/pythonista'
alias scan='python ~/Documents/Couch.Potato/pythonista-lab/ios/pythonista/quick_recon.py'
alias headers='python ~/Documents/Couch.Potato/pythonista-lab/utilities/header_analyzer.py'

# Reload
source ~/.profile
```

### Quick Commands

```bash
# Now you can use:
bb                    # Go to bug bounty dir
scan example.com      # Quick subdomain scan
headers example.com   # Check security headers
```

## 🔧 Pythonista 3 Specific Setup

### File Structure

```
Pythonista/
└── BugBounty/
    ├── quick_recon.py
    ├── mobile_reporter.py
    ├── url_grabber.py
    └── config.py
```

### Running Scripts

```python
# In Pythonista console:
import sys
sys.path.append('/BugBounty')

from quick_recon import scan_domain
scan_domain('example.com')
```

### UI Scripts

Pythonista supports iOS UI - see `pythonista/ui_tools/` for touch-based interfaces.

## 🌐 Remote Server Integration

### Connect to Your VPS

```bash
# In a-Shell or Termius:
ssh user@your-vps.com

# Run heavy tools on server
cd /opt/bug-bounty-tools
./massive_scan.sh target.com

# View results on iPhone
less results.txt
```

### Reverse Tunnel for Mobile Dashboard

```bash
# On VPS:
python mobile_dashboard.py --host 0.0.0.0 --port 8080

# Access from iPhone via SSH tunnel:
ssh -L 8080:localhost:8080 user@your-vps.com

# Open Safari: http://localhost:8080
```

## 📊 Mobile Reporting

### Quick Report Templates

Located in `pythonista/templates/`:
- `mobile_xss.md` - XSS findings
- `mobile_idor.md` - IDOR findings
- `mobile_ssrf.md` - SSRF findings
- `quick_note.md` - Quick findings

### Screenshot Management

```
1. Take screenshots of vulnerability
2. Use Shortcuts to:
   - Add to bug report folder
   - Auto-rename with timestamp
   - Upload to cloud storage
   - Attach to report template
```

## 🔐 Security on iPhone

### Best Practices

- ✅ Use strong passcode/Face ID
- ✅ Enable "Erase Data" after 10 failed attempts
- ✅ Use VPN for all bug bounty activities
- ✅ Don't store API keys in plain text
- ✅ Use iCloud Keychain for credentials
- ✅ Enable Find My iPhone
- ✅ Use encrypted note apps for sensitive findings

### Secure Storage

```python
# Use iOS Keychain (in Pythonista):
import keychain

# Store API key
keychain.set_password('bugbounty', 'api_key', 'your-key')

# Retrieve
api_key = keychain.get_password('bugbounty', 'api_key')
```

## 🎓 Learning Resources

### iPhone-Specific Tutorials

- [a-Shell Documentation](https://github.com/holzschu/a-shell)
- [Pythonista Forum](https://forum.omz-software.com/)
- [iOS Shortcuts Guide](https://support.apple.com/guide/shortcuts)
- [Mobile Bug Bounty Tips](https://www.bugcrowd.com/blog)

### Sample Workflows

See `workflows/` directory for complete example workflows including:
- Morning recon routine
- Lunchtime quick checks
- Evening report writing
- Weekend deep dives

## 🚨 Limitations & Workarounds

| Limitation | Workaround |
|------------|------------|
| No Nmap | Use online Nmap services or VPS |
| Limited CPU | Run heavy tasks on cloud server |
| Battery drain | Use external battery or plug in |
| Small screen | Use iPad or external monitor |
| No root access | Use cloud Linux VPS for advanced tools |
| App restrictions | Use web-based alternatives |

## 💡 Pro Tips

### Siri Integration

```
"Hey Siri, run Quick Domain Scan"
→ Opens shortcut → Asks for domain → Runs scan
```

### Widget Setup

Add Shortcuts widget to home screen:
- Quick Recon button
- Header Check button
- Report Generator button

### Automation

iOS Shortcuts can trigger:
- Daily recon scans
- Alert monitoring
- Report reminders
- Backup scripts

## 📈 Track Your Progress

### Mobile Stats Dashboard

```bash
python pythonista/stats_tracker.py
```

Shows:
- Scans run today
- Bugs found this week
- Bounties earned this month
- Active programs

## 🎯 Quick Reference

### Common Commands

```bash
# Quick recon
python quick_recon.py target.com

# Header check
python ../utilities/header_analyzer.py https://target.com

# JWT decode
python ../utilities/jwt_decoder.py <token>

# Generate report
python mobile_reporter.py --template xss

# Start web dashboard
python web-mobile/mobile_dashboard.py
```

### Shortcuts Quick Launch

- 📱 Tap widget → Select tool → Enter target → View results
- 🎤 "Hey Siri, check headers for example.com"
- 🔗 Share URL from Safari → Run security check

---

**Happy Mobile Hunting! 📱🔐**

> Remember: The best bug bounty hunter is the one who's always ready to hunt!
