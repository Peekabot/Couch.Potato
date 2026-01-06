# 📱 iPhone Bug Bounty Workflows

Practical, real-world workflows for hunting bugs from your iPhone.

## 🌅 Morning Routine (15 minutes)

**Goal**: Start your day with fresh reconnaissance

### Workflow
```
1. Wake up, grab coffee ☕
2. Open a-Shell on iPhone
3. Run daily recon automation:
   $ cd ~/Couch.Potato/pythonista-lab/ios
   $ python pythonista/quick_recon.py target1.com
   $ python pythonista/quick_recon.py target2.com
4. Review results while eating breakfast
5. Screenshot interesting findings
6. Add to Notes app for later investigation
```

### iOS Shortcut Version
```
1. "Hey Siri, run morning recon"
2. Automation scans all targets from list
3. Results saved to iCloud
4. Notification when complete
5. Review in bed 😴
```

---

## 🚇 Commute Testing (30-60 minutes)

**Goal**: Productive bug hunting while traveling

### Workflow
```
1. Connect to mobile hotspot or train WiFi
2. Open mobile web dashboard:
   $ python ios/web-mobile/mobile_dashboard.py
3. Open Safari → localhost:8080
4. Add to Home Screen for app-like experience
5. Run quick tests:
   - Security header checks on new programs
   - Subdomain enumeration
   - JWT token analysis from yesterday's captures
6. Take screenshots of findings
7. Draft quick reports using voice dictation
```

### Pro Tips
- Download target lists before going underground
- Use airplane mode + WiFi for battery savings
- Voice memos for quick notes hands-free
- iPad for split-screen: browser + terminal

---

## 🍕 Lunch Break Hunt (20 minutes)

**Goal**: Quick wins during short breaks

### Workflow
```
1. Check bug bounty platforms for new programs
2. Run quick recon on new target:
   - Open Shortcuts widget
   - Tap "Quick Domain Scan"
   - Enter new domain
   - Review results
3. If interesting:
   - Save target to tracking list
   - Set reminder for evening deep dive
4. Check for easy wins:
   - Missing security headers
   - Robots.txt disclosure
   - Open directories
```

### Mobile Dashboard Version
```
1. Open dashboard from Home Screen
2. Switch to Headers tab
3. Paste new target URLs
4. Check all in 2 minutes
5. Screenshot findings
6. Back to lunch 🍕
```

---

## 🌃 Evening Deep Dive (1-2 hours)

**Goal**: Thorough testing on interesting targets

### Workflow
```
1. Review morning recon findings
2. Prioritize targets with most subdomains/live hosts
3. Connect iPhone to external monitor (if available)
4. SSH to VPS for heavy tooling:
   $ ssh hunter@your-vps.com
   $ cd /opt/tools
   $ ./full_scan.sh target.com
5. Monitor results on iPhone
6. Test findings manually in mobile Safari:
   - XSS in mobile browsers
   - IDOR on mobile APIs
   - Mobile-specific vulnerabilities
7. Create full report:
   $ python ios/pythonista/mobile_reporter.py xss target.com
8. Submit bug before bed
```

### Using Claude Code
```
1. Open Claude Code on iPhone
2. "Help me analyze this subdomain list for interesting targets"
3. "Generate an XSS payload for this parameter"
4. "Review this bug report for completeness"
5. "Suggest next steps for this vulnerability"
```

---

## 📸 Screenshot Management Workflow

**Goal**: Organize vulnerability evidence efficiently

### Workflow
```
1. Find vulnerability in Safari
2. Take screenshots:
   - Before state
   - Exploitation
   - After state/impact
3. Run "Save Bug Evidence" shortcut:
   - Auto-names with timestamp
   - Adds to Bug Bounty album
   - Saves to iCloud/BugBounty/Evidence
   - Tags with bug ID
4. Add to report:
   - Open mobile reporter
   - Reference screenshot filenames
   - Auto-embedded in markdown
```

---

## 🎯 Weekend Marathon (4-8 hours)

**Goal**: Deep research and complex vulnerability chains

### Setup
```
1. Connect iPhone to:
   - External monitor (USB-C to HDMI)
   - Bluetooth keyboard
   - External battery
2. Setup workspace:
   - Terminal on left
   - Browser on right
   - Notes app in slide over
3. VPN for privacy
4. Do Not Disturb mode
```

### Workflow
```
1. Choose high-value target
2. Complete recon phase:
   - Subdomain enumeration
   - Port scanning (via VPS)
   - Technology fingerprinting
   - Google dorking
3. Testing phase:
   - Test all findings methodically
   - Document everything in Notes
   - Screenshot all interesting behavior
4. Exploitation phase:
   - Develop PoCs on iPhone
   - Test payloads
   - Verify impact
5. Reporting phase:
   - Generate comprehensive reports
   - Attach all evidence
   - Submit to platform
6. Track in spreadsheet:
   - Update submission tracker
   - Add to statistics
```

---

## 🚨 Quick Response (New Program Alert)

**Goal**: Be first to submit on new programs

### Workflow
```
1. Get notification: "New program on HackerOne"
2. Immediate recon from iPhone:
   $ python ios/pythonista/quick_recon.py newprogram.com
3. While scanning:
   - Read program brief
   - Check scope
   - Note out-of-scope items
4. Quick wins:
   - Security headers
   - Common files (robots.txt, sitemap)
   - Subdomain takeovers
5. If found:
   - Quick report (10 minutes)
   - Submit immediately
   - Detail investigation later
```

---

## 🔄 Continuous Monitoring

**Goal**: Automated scanning of active targets

### Setup Automation
```
1. Create automation in Shortcuts:
   - Trigger: Daily at specific times
   - Action: Run recon script
   - Save: Results to iCloud
   - Notify: On completion

2. Targets list in iCloud:
   ~/BugBounty/targets.txt
   ```
   target1.com
   target2.com
   target3.com
   ```

3. Comparison script:
   - Compares today's results with yesterday
   - Highlights new subdomains
   - Alerts on changes
```

### Monitoring Workflow
```
1. Automation runs at 6 AM, 12 PM, 6 PM
2. Review notifications during breaks
3. Investigate new findings
4. Update tracking spreadsheet
5. Weekly summary report
```

---

## 🎓 Learning While Mobile

**Goal**: Improve skills during downtime

### Workflow
```
1. Read bug bounty write-ups:
   - Medium articles
   - HackerOne disclosed reports
   - YouTube videos (PIP mode)

2. Practice in mobile labs:
   - OWASP Juice Shop (cloud instance)
   - PortSwigger Academy
   - HackTheBox mobile-friendly challenges

3. Code review:
   - Clone vulnerable apps
   - Read source in Working Copy app
   - Identify bugs theoretically

4. Note-taking:
   - Save interesting techniques to Notes
   - Create payload library
   - Build checklists
```

---

## 🌐 Remote Server Workflow

**Goal**: Use iPhone as thin client to powerful VPS

### Setup
```
1. VPS with all tools installed
2. SSH keys on iPhone (Termius or a-Shell)
3. Tmux sessions for persistence
4. Automated scripts for common tasks
```

### Workflow
```
1. SSH from iPhone:
   $ ssh hunter@vps.com

2. Attach to tmux session:
   $ tmux attach -t bugbounty

3. Run heavy scans:
   $ nmap -A target.com > scan.txt &
   $ amass enum -d target.com > subdomains.txt &

4. Disconnect iPhone (scans continue)

5. Later, reconnect and check results:
   $ tmux attach
   $ cat scan.txt
   $ cat subdomains.txt

6. Transfer interesting files:
   $ scp vps:~/subdomains.txt ~/Documents/BugBounty/
```

---

## 💰 Bounty Tracking Workflow

**Goal**: Track progress and earnings

### Setup
```
Create tracking spreadsheet in Numbers/Excel:
- Columns: Date, Program, Bug Type, Severity, Status, Bounty
- Sync via iCloud
```

### Workflow
```
1. After each submission:
   - Add row to spreadsheet
   - Status: "Pending"
   - Set reminder for follow-up

2. On update:
   - Update status: "Triaged" / "Accepted" / "Duplicate"
   - Add bounty amount if paid
   - Calculate statistics

3. Weekly review:
   - Total submissions
   - Acceptance rate
   - Average bounty
   - Top bug types
   - Time investment vs earnings

4. Use stats for:
   - Setting goals
   - Identifying strengths
   - Improving weak areas
```

---

## 🛡️ OPSEC Workflow

**Goal**: Stay secure while hunting

### Best Practices
```
1. Always use VPN:
   - Especially on public WiFi
   - Hide your real IP from targets
   - Prevent ISP tracking

2. Secure storage:
   - Enable FileVault on iCloud
   - Use encrypted notes for credentials
   - Never commit API keys to repos

3. Clean up:
   - Clear Safari history after testing
   - Remove test payloads
   - Delete temporary files

4. Backup:
   - Daily iCloud backup
   - Weekly export to external storage
   - Keep reports in multiple locations
```

---

## 🎯 Platform-Specific Workflows

### HackerOne
```
1. Monitor inbox for new invites
2. Quick recon on new programs
3. Use mobile app for submissions
4. Track using their API
```

### Bugcrowd
```
1. RSS feed for new programs
2. Filter by reward range
3. Submit via web interface
4. Track manually in spreadsheet
```

### Intigriti
```
1. Email notifications
2. Focus on European targets
3. Use template from repo
4. Quick turnaround
```

---

## ⚡ Power User Tips

### Siri Commands
```
- "Hey Siri, scan example.com"
- "Hey Siri, check security headers for this URL"
- "Hey Siri, create XSS report"
- "Hey Siri, show my bug bounty stats"
```

### Widget Setup
```
Home Screen Layout:
- Row 1: Quick Scan, Headers, JWT Decode
- Row 2: Report Gen, Stats, Programs
- Tap widget → immediate execution
```

### Automation Ideas
```
- Auto-scan new programs
- Daily recon of favorites
- Weekly report backup
- Monthly statistics email
```

---

**Happy Mobile Hunting! 📱🔐**

> "The best bug bounty hunter is the one who's always ready"
