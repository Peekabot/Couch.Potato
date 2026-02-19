# 🔗 iOS Shortcuts for Bug Bounty

Complete guide to automating bug bounty workflows with iOS Shortcuts.

## 🎯 Overview

iOS Shortcuts can automate common bug bounty tasks:
- Quick domain scanning
- Security header checks
- JWT token decoding
- Report generation
- Screenshot management
- Evidence collection

## 📲 Quick Setup

### Method 1: Import Pre-built Shortcuts

1. Download `.shortcut` files from this directory
2. Open in Safari on iPhone
3. Tap "Add Shortcut"
4. Customize if needed

### Method 2: Build from Scratch

Follow the recipes below to create each shortcut manually.

## 🛠️ Essential Shortcuts

### 1. Quick Domain Scan

**Purpose**: Instant subdomain enumeration from anywhere

**How to Build**:

```
1. New Shortcut → Name: "Quick Domain Scan"

2. Add Actions:
   - Ask for Input → "Enter domain to scan"
   - Run Shell Script Over SSH →
     Server: your-server.com
     Script: python ~/quick_recon.py [Input]
   - Show Result

3. (Alternative for local):
   - Ask for Input
   - Run Shortcut → "Open a-Shell"
   - Run Script → pythonista-lab/ios/pythonista/quick_recon.py [Input]
```

**Usage**:
- Tap shortcut → Enter domain → View results
- Add to home screen widget for one-tap access
- Use Siri: "Hey Siri, scan domain"

---

### 2. Security Header Checker

**Purpose**: Analyze HTTP headers for any URL

**How to Build**:

```
1. New Shortcut → Name: "Check Security Headers"

2. Add Actions:
   - Get URLs from Input (allows share sheet)
   - If no input:
     - Ask for Input → "Enter URL"
   - Get Contents of URL
   - Get Headers from Response
   - Text →
     Security Headers Found:
     HSTS: [Get Value for Key "Strict-Transport-Security"]
     CSP: [Get Value for Key "Content-Security-Policy"]
     X-Frame: [Get Value for Key "X-Frame-Options"]
   - Show Result
   - Quick Look
```

**Usage**:
- Share any webpage → Run Shortcut
- Instant header analysis
- Great for testing on the fly

---

### 3. JWT Decoder

**Purpose**: Decode JWT tokens from clipboard

**How to Build**:

```
1. New Shortcut → Name: "Decode JWT"

2. Add Actions:
   - Get Clipboard
   - Split Text by "."
   - Get Item from List → Item 1 (Header)
   - Base64 Decode
   - Get JSON Value → All Keys
   - Format as Text
   - Set Variable: Header

   - (Repeat for Payload - Item 2)

   - Text →
     JWT Decoded:

     HEADER:
     [Header Variable]

     PAYLOAD:
     [Payload Variable]

   - Show Result
   - Quick Look
```

**Usage**:
- Copy JWT token
- Run shortcut
- View decoded header and payload

---

### 4. Bug Report Creator

**Purpose**: Generate bug report template quickly

**How to Build**:

```
1. New Shortcut → Name: "New Bug Report"

2. Add Actions:
   - Choose from Menu → "Bug Type"
     - XSS
     - IDOR
     - SSRF
     - SQL Injection
     - Open Redirect
     - CSRF

   - (For each option):
     - Ask for Input → "Target URL"
     - Ask for Input → "Brief Description"
     - Ask for Input → "PoC Steps"
     - Text →
       # [Bug Type] Report

       Target: [URL Input]
       Date: [Current Date]

       ## Description
       [Description Input]

       ## Steps to Reproduce
       [PoC Steps]

       ## Impact
       [Template Impact Text]

   - Save File →
     Destination: iCloud/BugBounty/Reports
     Filename: [Bug Type]_[Date]_report.md

   - Show Notification → "Report created!"
```

**Usage**:
- Tap shortcut
- Select bug type
- Fill in details (use voice!)
- Auto-saved to iCloud

---

### 5. Screenshot Evidence Collector

**Purpose**: Organize and timestamp vulnerability screenshots

**How to Build**:

```
1. New Shortcut → Name: "Save Bug Evidence"

2. Add Actions:
   - Get Latest Screenshots (or Get from Share Sheet)
   - Ask for Input → "Bug ID or Name"
   - Rename → [Input]_[Current Date]_evidence.png
   - Add to Album → "Bug Bounty Evidence"
   - Save to iCloud → BugBounty/Evidence/
   - Show Notification → "Evidence saved: [Input]"
```

**Usage**:
- Take screenshots of bug
- Run shortcut
- Enter bug identifier
- Auto-organized and timestamped

---

### 6. Program Tracker

**Purpose**: Track active bug bounty programs

**How to Build**:

```
1. New Shortcut → Name: "My Programs"

2. Add Actions:
   - Get file from iCloud → programs.json
   - Get Dictionary Value → "programs"
   - Repeat with Each:
     - Text →
       [Program Name]
       Status: [Active/Paused]
       Findings: [Count]
       Last Tested: [Date]
   - Choose from List
   - Get Details:
     - Show program scope
     - Show last findings
     - Open program URL
```

**Usage**:
- Quick view of active programs
- Track last testing dates
- Jump to program URLs

---

### 7. Daily Recon Routine

**Purpose**: Automated morning recon workflow

**How to Build**:

```
1. New Shortcut → Name: "Morning Recon"

2. Add Actions:
   - Get file → targets.txt
   - Split by New Lines
   - Repeat with Each:
     - Run Quick Domain Scan [Item]
     - Wait 5 seconds
   - Combine Results
   - Save to → recon_[Date].json
   - Send Email → "Daily recon complete"
   - (Optional) Create iOS Reminder for review
```

**Usage**:
- Run automatically via Automation
- Schedule for 7 AM daily
- Wake up to fresh recon data

---

### 8. Upload to HackerOne/Bugcrowd

**Purpose**: Quick draft submission via API

**How to Build**:

```
1. New Shortcut → Name: "Submit to Platform"

2. Add Actions:
   - Choose from Menu:
     - HackerOne
     - Bugcrowd
     - Intigriti

   - Get Report from iCloud
   - Parse markdown
   - Get API Key from Keychain
   - Make HTTP Request:
     URL: [Platform API Endpoint]
     Method: POST
     Headers:
       Authorization: Bearer [API Key]
     Body:
       title: [Report Title]
       description: [Report Description]
       severity: [Severity]

   - If Success:
     - Show Notification → "Submitted!"
     - Add to Tracking spreadsheet
```

**Usage**:
- Complete report on iPhone
- One-tap submission
- Auto-tracking

---

## 🎨 Advanced Shortcuts

### Multi-Tool Security Scan

Combines multiple tools in one workflow:

```
1. Get URL from Input
2. Run Security Header Check
3. Run Subdomain Scan
4. Check for common files (robots.txt, sitemap.xml)
5. Screenshot results
6. Create summary report
7. Save to iCloud
```

### Voice-Activated Bug Reporter

Use Siri to create reports hands-free:

```
"Hey Siri, report XSS bug"
→ Asks for target URL
→ Asks for description (use dictation)
→ Creates template
→ Saves to iCloud
```

### Automated Evidence Backup

Scheduled shortcut to backup findings:

```
1. Get all files from BugBounty folder
2. Create ZIP archive
3. Upload to cloud storage
4. Send confirmation email
5. Clean up old backups (>30 days)
```

## 🔧 Integration with a-Shell

### Running Python Scripts via Shortcuts

```
Shortcut Actions:
1. Text → "cd ~/Couch.Potato/pythonista-lab && python ios/pythonista/quick_recon.py [Domain]"
2. Open URL → ashell://[Base64 of command]
3. Wait for Return
4. Get Result
```

### SSH to Remote Server

```
1. Run Script Over SSH:
   Host: your-vps.com
   User: hunter
   Script: |
     cd /opt/tools
     python3 scanner.py --target [Input]
     cat results.txt
2. Show Result
```

## 📱 Widgets Setup

### Home Screen Widgets

Create quick-access buttons:

1. **Quick Scan Widget**
   - Small widget
   - Tapping opens domain input
   - Runs scan immediately

2. **Report Widget**
   - Shows count of pending reports
   - Tap to open reporter

3. **Stats Widget**
   - Displays today's scans
   - Shows active programs
   - Bounties earned this month

## 🔔 Automations

### Time-Based Automations

```
Automation: Daily at 7 AM
→ Run "Morning Recon"
→ Notification when complete
```

```
Automation: Daily at 9 PM
→ Backup all reports
→ Sync to cloud
```

### Event-Based Automations

```
Automation: When connected to "HomeWiFi"
→ Sync bug bounty repo
→ Update tools
```

```
Automation: When opening Safari
→ Check if on program scope
→ Enable header checker
```

## 🔐 Security Best Practices

### Storing API Keys

```
Use iCloud Keychain:
- Don't hardcode keys in shortcuts
- Use "Get from Keychain" action
- Enable Face ID for sensitive shortcuts
```

### Secure Data Handling

```
- Encrypt sensitive reports
- Use secure notes for credentials
- Enable "Erase Data" on device
- Don't share shortcuts with embedded secrets
```

## 📚 Shortcut Library

### Pre-Built Shortcuts (Coming Soon)

All shortcuts available as `.shortcut` files:

- `QuickDomainScan.shortcut`
- `SecurityHeaderCheck.shortcut`
- `JWTDecoder.shortcut`
- `BugReportCreator.shortcut`
- `EvidenceCollector.shortcut`
- `DailyRecon.shortcut`

### Installation

```
1. Download .shortcut file
2. Open in Safari (not Files app!)
3. Tap "Get Shortcut"
4. Review actions
5. Add to library
```

## 🎯 Pro Tips

### Siri Phrases

Set up custom phrases:
- "Scan this domain"
- "Check security headers"
- "Create bug report"
- "Save evidence"
- "Show my stats"

### Share Sheet Integration

Add shortcuts to share sheet for:
- URLs → Security check
- Screenshots → Evidence saver
- Text → Report generator

### Widget Stacks

Create smart stacks:
- Morning: Recon tools
- Afternoon: Testing tools
- Evening: Reporting tools

## 🐛 Troubleshooting

### Common Issues

**Shortcut won't run:**
- Check privacy settings
- Allow untrusted shortcuts
- Verify SSH keys

**API calls failing:**
- Check network connection
- Verify API keys
- Test endpoints manually

**a-Shell integration not working:**
- Update a-Shell to latest
- Check URL scheme support
- Try alternative method

## 📖 Resources

- [Apple Shortcuts User Guide](https://support.apple.com/guide/shortcuts)
- [a-Shell URL Schemes](https://github.com/holzschu/a-shell)
- [iOS Automation Reddit](https://reddit.com/r/shortcuts)

---

**Start automating your bug bounty workflow today! 🚀**
