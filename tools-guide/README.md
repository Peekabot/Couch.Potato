# 🔧 Bug Bounty Tools Familiarization

**Complete hands-on guides for every essential tool in your arsenal.**

---

## What's in This Directory

This directory contains comprehensive, practical guides for mastering the tools that professional bug bounty hunters use daily.

```
tools-guide/
├── BURP_SUITE_MASTERY.md      # The #1 essential tool (50% of success)
├── COMMAND_LINE_TOOLS.md       # Recon & enumeration tools
├── FUZZING_MASTERY.md          # Directory brute-forcing (ffuf/gobuster)
├── BROWSER_SETUP.md            # Professional browser configuration
└── README.md                   # This file
```

---

## Learning Path

### For Complete Beginners

**Week 1: Browser & Burp Suite**
```
Day 1-2: BROWSER_SETUP.md
- Set up Firefox/Chrome
- Install extensions
- Configure proxy
- Import Burp certificate

Day 3-7: BURP_SUITE_MASTERY.md
- Learn Proxy & Intercept
- Master Repeater (your best friend)
- Understand Intruder basics
- Complete all practice exercises
```

**Week 2: Command-Line Tools**
```
Day 8-10: COMMAND_LINE_TOOLS.md
- Install essential tools
- Practice subdomain enumeration
- Learn httpx for live detection
- Run waybackurls for historical data

Day 11-14: FUZZING_MASTERY.md
- Learn ffuf syntax
- Practice directory fuzzing
- Discover hidden endpoints
- Build custom wordlists
```

### For Intermediate Users

**Focus on:**
```
1. Burp Suite → Advanced features (Intruder, extensions)
2. Command-line → Tool chaining and automation
3. Fuzzing → Parameter discovery and complex filtering
4. Browser → Automation with Selenium
```

### For Advanced Users

**Level up:**
```
1. Write custom Burp extensions
2. Build automated recon pipelines
3. Create custom Nuclei templates
4. Develop tool integrations
```

---

## Quick Reference

### Most Important Tools (Start Here)

| Tool | Purpose | Priority | Guide |
|------|---------|----------|-------|
| **Burp Suite** | Intercept/modify HTTP | ⭐⭐⭐⭐⭐ | BURP_SUITE_MASTERY.md |
| **Firefox + Extensions** | Professional testing | ⭐⭐⭐⭐⭐ | BROWSER_SETUP.md |
| **Subfinder** | Subdomain enum | ⭐⭐⭐⭐ | COMMAND_LINE_TOOLS.md |
| **httpx** | Live host detection | ⭐⭐⭐⭐ | COMMAND_LINE_TOOLS.md |
| **ffuf** | Directory fuzzing | ⭐⭐⭐⭐ | FUZZING_MASTERY.md |

### Secondary Tools (Learn Next)

| Tool | Purpose | Priority | Guide |
|------|---------|----------|-------|
| **Nuclei** | Vulnerability scanning | ⭐⭐⭐ | COMMAND_LINE_TOOLS.md |
| **waybackurls** | Historical URLs | ⭐⭐⭐ | COMMAND_LINE_TOOLS.md |
| **gobuster** | Alternative fuzzer | ⭐⭐⭐ | FUZZING_MASTERY.md |
| **amass** | Deep enumeration | ⭐⭐ | COMMAND_LINE_TOOLS.md |
| **nmap** | Port scanning | ⭐⭐ | COMMAND_LINE_TOOLS.md |

---

## What Each Guide Covers

### 1. BURP_SUITE_MASTERY.md

**You'll learn:**
- ✅ Installation & CA certificate setup
- ✅ Proxy & Intercept (catch/modify requests)
- ✅ Repeater (test payloads 1000x)
- ✅ Intruder (automated fuzzing)
- ✅ Decoder (encode/decode data)
- ✅ Comparer (diff responses)
- ✅ Extensions (Autorize, Param Miner, etc.)
- ✅ Complete workflows for IDOR/XSS/SQLi
- ✅ Keyboard shortcuts
- ✅ Practice exercises

**Why it's #1:**
```
Burp Suite is 50% of bug bounty success.
Every professional hunter uses it.
Master this first before anything else.
```

### 2. COMMAND_LINE_TOOLS.md

**You'll learn:**
- ✅ Subfinder (subdomain enumeration)
- ✅ httpx (live host detection + tech detection)
- ✅ Nuclei (vulnerability scanning with templates)
- ✅ waybackurls (Wayback Machine URLs)
- ✅ gau (get all URLs from multiple sources)
- ✅ assetfinder (asset discovery)
- ✅ nmap (port scanning)
- ✅ amass (comprehensive OSINT)
- ✅ Tool chaining (combine tools for power)
- ✅ Real-world recon pipelines

**Why it matters:**
```
Manual recon finds 10% of attack surface.
Automated recon finds 90% of attack surface.
These tools are your reconnaissance army.
```

### 3. FUZZING_MASTERY.md

**You'll learn:**
- ✅ ffuf syntax & advanced filtering
- ✅ gobuster for simpler fuzzing
- ✅ Directory brute-forcing
- ✅ File discovery (.bak, .sql, .env)
- ✅ Parameter discovery
- ✅ Subdomain fuzzing
- ✅ Virtual host discovery
- ✅ POST data fuzzing
- ✅ SecLists wordlists
- ✅ Custom wordlist creation

**Why it matters:**
```
Hidden directories = hidden bugs.
/admin, /.git, /backup.sql = instant findings
Fuzzing reveals what browsing misses.
```

### 4. BROWSER_SETUP.md

**You'll learn:**
- ✅ Firefox vs Chrome for bug bounty
- ✅ Creating dedicated testing profiles
- ✅ Essential extensions (8 must-haves)
- ✅ Burp CA certificate installation
- ✅ Proxy configuration (FoxyProxy)
- ✅ WebRTC leak prevention
- ✅ Container tabs (multi-account testing)
- ✅ Developer tools setup
- ✅ Keyboard shortcuts
- ✅ Testing your complete setup

**Why it matters:**
```
Amateur: Stock browser, misses details
Professional: Configured browser, sees everything
Your browser is your primary interface.
```

---

## Installation Requirements

### Minimum Setup

```bash
# Operating System
Linux (Kali/Ubuntu recommended) or macOS

# Browser
Firefox or Chrome

# Core Tools
Burp Suite Community (FREE)
Go 1.19+ (for Go tools)
Python 3.8+ (for Python tools)

# Disk Space
10GB minimum (for tools + wordlists)

# RAM
8GB minimum, 16GB recommended
```

### Complete Installation Script

```bash
#!/bin/bash
# install_all_tools.sh

echo "[+] Installing Go tools..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/ffuf/ffuf@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/OJ/gobuster/v3@latest

echo "[+] Installing system tools..."
sudo apt install -y nmap amass

echo "[+] Installing SecLists..."
sudo apt install -y seclists
# OR: git clone https://github.com/danielmiessler/SecLists.git

echo "[+] Downloading Burp Suite..."
echo "Visit: https://portswigger.net/burp/communitydownload"

echo "[+] Done! Check each guide for detailed setup."
```

---

## Practice Challenges

### Challenge 1: Complete Beginner Setup (Week 1)

```
✅ Install Firefox with Bug Bounty profile
✅ Install all essential extensions
✅ Configure FoxyProxy for Burp
✅ Install Burp Suite Community
✅ Import Burp CA certificate
✅ Test setup on https://google.com
✅ See Google request in Burp HTTP history

Success criteria: No SSL errors, traffic in Burp
```

### Challenge 2: First Recon (Week 2)

```
Target: tesla.com (public program)

✅ Install subfinder, httpx, waybackurls
✅ Run: subfinder -d tesla.com -o subs.txt
✅ Run: cat subs.txt | httpx -o live.txt
✅ Run: waybackurls tesla.com > wayback.txt
✅ Find at least 50 subdomains
✅ Find at least 10 live hosts
✅ Extract parameters from wayback URLs

Success criteria: Organized recon data
```

### Challenge 3: First Fuzzing (Week 3)

```
Target: testphp.vulnweb.com (legal test site)

✅ Install ffuf and SecLists
✅ Fuzz directories: ffuf -u http://testphp.vulnweb.com/FUZZ
✅ Find hidden directories
✅ Test with file extensions: -e .php,.bak
✅ Discover at least 5 hidden endpoints

Success criteria: Found directories not visible on homepage
```

### Challenge 4: First IDOR Test (Week 4)

```
Target: Any site with user profiles

✅ Create 2 test accounts (User A, User B)
✅ Access User A's profile in Burp
✅ Send to Repeater
✅ Change user_id to User B's ID
✅ Test if you can access User B's data

Success criteria: Understand IDOR testing methodology
```

---

## Common Questions

### Q: Which tool should I learn first?

**A: Burp Suite.** It's non-negotiable. 50% of bug bounty is Burp Suite.

### Q: Do I need Burp Suite Professional?

**A: Not initially.** Start with Community. Upgrade after your first $1,000 in bounties.

### Q: Can I use Windows?

**A: Yes, but Linux is recommended.** Most tools work better on Linux. Use WSL2 or dual-boot.

### Q: Do I need all these tools?

**A: Not all at once.** Start with:
1. Burp Suite
2. Firefox + Extensions
3. Subfinder + httpx
4. ffuf

Add others as you level up.

### Q: How long to master these tools?

**A:**
- Basic proficiency: 2-4 weeks
- Intermediate: 2-3 months
- Advanced: 6-12 months
- Master: Ongoing (tools update constantly)

### Q: What if I have a Mac (like you mentioned)?

**A: Most tools work on Mac!**
```bash
# Install Homebrew first
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Then install Go
brew install go

# Then install tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# etc.

# Burp Suite works on Mac
# Firefox/Chrome work on Mac
# Python tools work on Mac

Your red/blue lab on Mac is perfect for practice!
```

---

## Troubleshooting

### "Command not found" errors

```bash
# Add Go bin to PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Or for Mac:
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc
```

### Burp certificate issues

```
1. Re-download certificate from http://burpsuite
2. Delete old certificate from browser
3. Re-import new one
4. Restart browser
```

### Tools running slow

```
1. Reduce threads: -t 10
2. Add rate limiting: -rate 50
3. Use smaller wordlists first
4. Run from VPS for heavy scans
```

---

## Next Steps

**After completing all guides:**

1. ✅ All practice challenges passed
2. ✅ Tools integrated into workflow
3. ✅ Can run recon in < 10 minutes
4. ✅ Comfortable with Burp Repeater
5. ✅ Can fuzz any target

**Then move to:**
- Apply to real bug bounty programs
- Use methodology guides (../methodology/)
- Start hunting for your first bug
- Track progress in SUBMISSION_TRACKER.md

---

## Additional Resources

### Official Documentation
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [ffuf GitHub](https://github.com/ffuf/ffuf)
- [ProjectDiscovery Tools](https://projectdiscovery.io/)

### Video Tutorials
- NahamSec: Burp Suite tutorials
- InsiderPhD: Tool deep-dives
- Stök: Beginner-friendly walkthroughs

### Practice Platforms
- PortSwigger Academy (Burp Suite labs)
- TryHackMe (Tool practice rooms)
- HackTheBox (Real-world scenarios)

---

**Tools are only as good as the person using them. Practice daily! 🔧**
