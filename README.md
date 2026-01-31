# 🔐 Couch.Potato - Mobile Security Research & Bug Bounty Lab

**A mobile-first security research repository focused on iOS/Android app testing, bug bounty hunting, and vulnerability research.**

This repo contains methodologies, tools, scripts, and learning resources for finding and responsibly disclosing mobile security vulnerabilities.

**Why Mobile?** Higher bounties (1.5-2x web bugs), less competition, critical vulnerabilities. Hunt from your iPhone using Pythonista.

---

## 🎯 What's Here

### Mobile Security Methodologies
- **[Mobile App Testing](./methodology/MOBILE_APP_TESTING.md)** - **START HERE** - Complete iOS/Android testing workflow
  - Certificate pinning bypass (Frida, objection)
  - Local data storage inspection (SQLite, Keychain, SharedPreferences)
  - Runtime instrumentation with Frida
  - Deep link & URL scheme testing
  - Binary analysis (class-dump, APKTool, jadx)
- **[Reconnaissance](./methodology/RECONNAISSANCE.md)** - Systematic recon workflow (passive → active)
- **[Web Testing](./methodology/WEB_TESTING.md)** - Web application security testing
- **[API Testing](./methodology/API_TESTING.md)** - API security methodology (mobile APIs!)
- **[IDOR Deep Dive](./methodology/IDOR_DEEPDIVE.md)** - Insecure Direct Object Reference (common in mobile)
- **[SSRF Deep Dive](./methodology/SSRF_DEEPDIVE.md)** - Server-Side Request Forgery techniques
- **[Tools](./methodology/TOOLS.md)** - Essential security testing tools
- **[Learning Foundation](./methodology/LEARNING_FOUNDATION.md)** - Core concepts and learning path

### Report Templates
- **[Bugcrowd Template](./templates/BUGCROWD_TEMPLATE.md)** - Bugcrowd VRT-aligned report structure
- **[HackerOne Template](./templates/HACKERONE_TEMPLATE.md)** - HackerOne report format
- **[Intigriti Template](./templates/INTIGRITI_TEMPLATE.md)** - Intigriti submission format
- **[Generic Template](./templates/GENERIC_TEMPLATE.md)** - Universal bug report template

### Scripts & Tools
- **[recon.sh](./scripts/recon.sh)** - Automated reconnaissance script
- **[poc/](./poc/)** - Proof of concept exploits (educational)
- **[reports/](./reports/)** - Bug bounty report archive

### 📱 Pythonista Tools (Mobile-First Security Testing)
- **[Mobile App Testing Guide](./methodology/MOBILE_APP_TESTING.md)** - **ESSENTIAL** - Complete iOS/Android methodology
- **[GPS EXIF Scanner](./pythonista/gps_exif_scanner.py)** - Find GPS metadata leaks (P3/P4 Information Disclosure)
- **[Mobile API Interceptor](./pythonista/mobile_api_interceptor.py)** - Test IDOR, parameter tampering, auth bypass in mobile APIs
- **[VRT Knowledge Agent](./pythonista/vrt_knowledge_agent.py)** - Bugcrowd VRT decision-making assistant
- **[Pythonista Guide](./pythonista/README.md)** - Complete mobile bug bounty workflow

**Why Mobile-First?**
- **Higher bounties**: Mobile bugs pay 1.5-2x web vulnerabilities ($500-$10k range)
- **Less competition**: Fewer hunters test mobile (requires device, learning curve)
- **Critical bugs**: Certificate pinning bypass, insecure storage, hardcoded secrets = P2/P3 regularly
- **Hunt from iPhone**: Use Pythonista for on-device testing, no laptop required

**Mobile vs Web ROI**:
- Web IDOR: $100-$500 typical
- Mobile IDOR: $300-$1,000 typical
- Web XSS: $200-$800
- Mobile hardcoded API key: $500-$3,000
- Mobile insecure storage (PII): $1,000-$5,000

### Learning Resources
- **[Cyber Security Pathway](./docs/CYBER_SECURITY_PATHWAY.md)** - Complete guide: Learn → Do → Teach
  - PortSwigger Academy walkthrough
  - Bug bounty platform comparison
  - First bounty checklist (60-day plan)
  - Platform setup (HackerOne, Bugcrowd, Intigriti)
  - Military cyber skills translation

---

## 🚀 Quick Start (Mobile-First Approach)

### For Mobile Bug Bounty Hunters

**Path 1: iPhone Testing (Easiest Start)**

1. **Get Pythonista** ($9.99 from App Store)
   - Download: https://apps.apple.com/us/app/pythonista-3/id1085978097
   - Transfer scripts from this repo (AirDrop or iCloud)

2. **Test your first vulnerability**:
   - Run [GPS EXIF Scanner](./pythonista/gps_exif_scanner.py) on your photos
   - Understand what metadata your phone leaks
   - Find a bug bounty program with mobile apps
   - Upload photo → Download → Scan for GPS leak
   - If GPS present → Report using [Bugcrowd Template](./templates/BUGCROWD_TEMPLATE.md)

3. **Learn mobile API testing**:
   - Read [Mobile App Testing](./methodology/MOBILE_APP_TESTING.md) (Section: Traffic Interception)
   - Set up Burp Suite proxy on iPhone
   - Capture API traffic from mobile apps
   - Use [Mobile API Interceptor](./pythonista/mobile_api_interceptor.py) to test IDOR

**Path 2: iOS/Android App Testing (Higher ROI)**

1. **Set up mobile testing environment**:
   - **iOS**: iPhone (jailbroken optional), Mac for Xcode, Frida + objection
   - **Android**: Android device (rooted optional), ADB, APKTool, Frida + objection
   - Install Burp Suite for proxying traffic

2. **Follow comprehensive methodology**:
   - Read [Mobile App Testing Guide](./methodology/MOBILE_APP_TESTING.md) (ESSENTIAL)
   - Practice on DVIA (iOS) or InsecureBankv2 (Android) vulnerable apps
   - Learn certificate pinning bypass, binary analysis, runtime instrumentation

3. **Choose mobile programs**:
   - Sign up: [HackerOne](https://hackerone.com) | [Bugcrowd](https://bugcrowd.com)
   - Filter by "Mobile" in scope
   - Target: Fintech, banking, healthcare apps (higher bounties)
   - Read program scope carefully (iOS, Android, or both?)

4. **Hunt for mobile-specific bugs**:
   - **P2/P3 Low-Hanging Fruit**: Hardcoded API keys, insecure storage, certificate pinning bypass
   - Use VRT Agent: Ask "What priority is hardcoded secrets?"
   - Follow methodology for traffic interception, local storage inspection, deep link testing

5. **Write mobile bug reports**:
   - Use [Mobile Bug Report Template](./methodology/MOBILE_APP_TESTING.md#mobile-bug-report-template)
   - Include: Platform (iOS/Android), app version, device tested, tools used
   - Clear steps to reproduce with code/commands

**Path 3: Web Testing (Traditional Approach)**

1. **Learn the fundamentals**:
   - Read [Learning Foundation](./methodology/LEARNING_FOUNDATION.md)
   - Complete PortSwigger Academy "Apprentice" labs
   - Study OWASP Top 10

2. **Follow web methodology**:
   - [Reconnaissance](./methodology/RECONNAISSANCE.md) → [Web Testing](./methodology/WEB_TESTING.md)
   - Focus on IDOR, XSS, authentication bypass
   - Use [Bugcrowd Template](./templates/BUGCROWD_TEMPLATE.md) for reports

### For Security Researchers

1. **Study existing methodologies** in `methodology/`
2. **Practice on legal targets**:
   - [PortSwigger Labs](https://portswigger.net/web-security)
   - [HackerOne CTF](https://ctf.hacker101.com)
   - [DVWA](https://github.com/digininja/DVWA)
3. **Document your findings** using templates in `templates/`
4. **Share knowledge** - contribute improvements to methodologies

---

## 📚 Learning Path

**Complete Beginner (Weeks 1-4)**:
- [ ] Read [Learning Foundation](./methodology/LEARNING_FOUNDATION.md)
- [ ] Complete PortSwigger Academy: XSS, SQLi, Authentication
- [ ] Read OWASP Top 10
- [ ] Study 10 disclosed bug bounty reports

**First Bounty Hunt (Weeks 5-12)**:
- [ ] Choose beginner-friendly program
- [ ] Run full recon (passive + active)
- [ ] Test for IDOR, XSS, authentication bypass
- [ ] Submit first report using templates
- [ ] Goal: First accepted vulnerability report

**Building Momentum (Months 4-6)**:
- [ ] 10+ reports submitted, 3-5 accepted
- [ ] $500-$2,000 earned
- [ ] Expand to API testing, SSRF, business logic
- [ ] Develop program-specific expertise

---

## 🛠️ Tools & Setup

**Essential Free Tools**:
- **Burp Suite Community** - HTTP proxy, scanner, repeater
- **OWASP ZAP** - Alternative to Burp Suite
- **Amass** - Subdomain enumeration
- **Subfinder** - Fast subdomain discovery
- **ffuf** - Web fuzzer
- **waybackurls** - Wayback Machine URL extractor

**Paid Tools** (optional, after first bounties):
- Burp Suite Professional - $449/year
- Nuclei - Template-based scanner
- PentesterLab Pro - $20/month

**Learning Platforms**:
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - FREE
- [HackerOne CTF](https://ctf.hacker101.com) - FREE
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) - FREE

---

## 🔒 Ethics & Legal

**Always follow these rules**:

1. **Only test authorized targets**:
   - Bug bounty programs with clear scope
   - Intentionally vulnerable apps (PortSwigger, DVWA, etc.)
   - Your own systems

2. **Respect program scope**:
   - Read program policy 3 times before testing
   - Ask if something is unclear
   - Never test out-of-scope assets

3. **Responsible disclosure**:
   - Report vulnerabilities to program first
   - Allow reasonable time for fix (30-90 days)
   - Don't publish details until coordinated disclosure

4. **Never cause harm**:
   - No DoS attacks, data deletion, privilege escalation beyond PoC
   - Use read-only exploits when possible
   - Stop testing if you accidentally access sensitive data

**Consequence of violations**: Account bans, legal action, criminal charges. Stay ethical.

---

## 📊 Tracking Progress

Use **[SUBMISSION_TRACKER.md](./SUBMISSION_TRACKER.md)** to track:
- Programs hunted
- Reports submitted
- Acceptance rate
- Bounties earned
- Lessons learned

---

## 🎓 Resources

### Bug Bounty Platforms
- [HackerOne](https://hackerone.com) - Largest platform, public disclosure
- [Bugcrowd](https://bugcrowd.com) - Clear VRT, fast triage
- [Intigriti](https://intigriti.com) - European programs
- [YesWeHack](https://yeswehack.com) - French/EU programs

### Learning Resources
- [PortSwigger Academy](https://portswigger.net/web-security)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Bugcrowd University](https://bugcrowd.com/hackers/bugcrowd-university)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity) - Read disclosed reports

### Communities
- [Bug Bounty Forum](https://bugbountyforum.com)
- Reddit: r/bugbounty, r/netsec
- Twitter: Follow @NahamSec, @STOK, @InsiderPhD

---

## 🧪 Philosophy

This repo follows the **"Learn → Do → Teach"** framework:

1. **Learn**: Study methodologies, complete labs, read reports
2. **Do**: Hunt on real programs, submit findings, earn bounties
3. **Teach**: Share knowledge, improve methodologies, mentor others

Security research is about **substrate boundary analysis** - finding where systems fail to enforce trust boundaries. Every vulnerability is a boundary violation.

---

## 📝 Contributing

Improvements welcome:
- Found a better recon technique? Update `methodology/RECONNAISSANCE.md`
- Discovered a new tool? Add to `methodology/TOOLS.md`
- Better report template? Submit PR to `templates/`

---

## ⚠️ Disclaimer

**Educational purposes only.** This repository is for learning security research within legal boundaries. Unauthorized access to computer systems is illegal. Always obtain permission before testing.

The methodologies and tools here are provided "as-is" with no warranty. Use responsibly.

---

## 🏆 Success Metrics

**First Month**:
- [ ] 10+ PortSwigger labs completed
- [ ] First program chosen
- [ ] Recon completed on first target

**First Quarter**:
- [ ] 5+ reports submitted
- [ ] 1+ accepted vulnerability
- [ ] First bounty earned ($100-$500)

**First Year**:
- [ ] 50+ reports submitted
- [ ] 20+ accepted vulnerabilities
- [ ] $5,000+ earned in bounties
- [ ] Specialty developed (API, mobile, cloud, etc.)

---

**Happy hunting! 🎯**

*Learn one, do one, teach one.*
