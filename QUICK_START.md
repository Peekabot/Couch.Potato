# 🚀 Quick Start Guide

Get started with bug bounty hunting using this repository.

## First Time Setup

### 1. Choose a Platform

Start with one platform and expand later:
- **Intigriti** - European platform, good for beginners
- **HackerOne** - Largest platform, lots of programs
- **Bugcrowd** - Good variety of programs
- **YesWeHack** - European programs

### 2. Create Your Profile

- Sign up on chosen platform
- Complete your profile
- Read the platform guidelines
- Understand disclosure policies

### 3. Pick Your First Program

**For Beginners:**
- Choose programs marked "Easy" or "Beginner-friendly"
- Look for programs with clear scope
- Start with web applications
- Avoid programs with complex infrastructure

**Good Starting Programs:**
- Programs with wide scope
- Programs that accept informational reports
- Programs with active community
- Programs with recent payouts

---

## Your First Bug Hunt

### Step 1: Read the Program Brief

```markdown
✅ In-scope assets
✅ Out-of-scope assets
✅ Allowed testing methods
✅ Forbidden actions
✅ Reward table
✅ Response time SLA
```

### Step 2: Initial Reconnaissance

```bash
# Save target to variable
TARGET="example.com"

# Basic subdomain enumeration
subfinder -d $TARGET -o subs.txt
assetfinder --subs-only $TARGET >> subs.txt
cat subs.txt | sort -u > all_subs.txt

# Find live hosts
cat all_subs.txt | httprobe > live.txt

# Take screenshots
cat live.txt | aquatone
```

### Step 3: Manual Exploration

1. **Browse the application**
   - Create an account
   - Explore all features
   - Note interesting functionality
   - Map out the application

2. **Configure Burp Suite**
   - Set up proxy
   - Add target to scope
   - Start browsing through Burp
   - Review HTTP history

3. **Look for low-hanging fruit**
   - Missing security headers
   - Verbose error messages
   - Exposed .git directory
   - Default credentials
   - Information disclosure

### Step 4: Focused Testing

Pick ONE vulnerability type to focus on:

**For Beginners - Start Here:**
- IDOR (Insecure Direct Object References)
- Missing rate limiting
- Open redirects
- Information disclosure
- CSRF

**Intermediate:**
- XSS (Cross-Site Scripting)
- Authentication issues
- Authorization bypasses
- Business logic flaws

**Advanced:**
- SQL Injection
- SSRF
- XXE
- Deserialization
- RCE

### Step 5: Found Something? Verify!

Before reporting:
1. ✅ Reproduce the issue 3 times
2. ✅ Confirm it's a security issue
3. ✅ Check if it's in scope
4. ✅ Verify it's not a duplicate
5. ✅ Assess the impact
6. ✅ Create a clean PoC

---

## Writing Your First Report

### Use the Template

1. Copy the appropriate template:
   - Intigriti → `templates/INTIGRITI_TEMPLATE.md`
   - HackerOne → `templates/HACKERONE_TEMPLATE.md`
   - Bugcrowd → `templates/BUGCROWD_TEMPLATE.md`

2. Fill in ALL sections:
   ```markdown
   ✅ Clear title
   ✅ Summary
   ✅ Severity assessment
   ✅ Step-by-step reproduction
   ✅ Proof of Concept
   ✅ Impact analysis
   ✅ Suggested fix
   ✅ Screenshots/video
   ```

3. Save to `reports/[platform]/[program]/`

### Report Quality Checklist

- [ ] Title is clear and descriptive
- [ ] Steps are numbered and specific
- [ ] PoC actually works
- [ ] Impact is realistic (not exaggerated)
- [ ] Screenshots are clear
- [ ] No grammatical errors
- [ ] Professional tone
- [ ] Suggested fix included

---

## Tracking Your Submission

### 1. Add to Tracker

Open `SUBMISSION_TRACKER.md` and add:

```markdown
| INTG-2025-12-01 | 2025-12-30 | Intigriti | CompanyX | Medium | IDOR in user profile | Submitted | TBD | Awaiting triage |
```

### 2. Update Status

As the report progresses:
- **Triaged** → Platform confirmed receipt
- **Accepted** → Vulnerability validated
- **Fixed** → Company deployed fix
- **Paid** → Bounty received

### 3. Update Stats

Update the statistics in `README.md`:
- Total submissions
- Accepted reports
- Total earned
- Severity breakdown

---

## What to Expect

### Timeline

| Status | Typical Time |
|--------|--------------|
| Initial Response | 1-7 days |
| Triage | 3-14 days |
| Validation | 1-4 weeks |
| Fix Deployed | 2-12 weeks |
| Bounty Paid | After fix |

### Possible Outcomes

**✅ Accepted**
- Congrats! You found a valid bug
- Wait for bounty decision
- Update your tracker

**❌ Informative**
- Valid observation, but no security impact
- Still counts as experience
- Learn from feedback

**❌ Duplicate**
- Someone reported it first
- Not your fault
- Try a different angle

**❌ Not Applicable**
- Not a security issue
- Or outside scope
- Read feedback and learn

**❌ Spam**
- Report was low quality
- Avoid this at all costs
- Take time to write good reports

---

## Tips for Success

### DO ✅

1. **Read the scope carefully**
2. **Start with easy targets**
3. **Focus on quality over quantity**
4. **Be patient with responses**
5. **Learn from rejections**
6. **Network with other hunters**
7. **Keep learning new techniques**
8. **Document everything**

### DON'T ❌

1. **Test out of scope assets**
2. **Perform destructive testing**
3. **Access other users' data**
4. **Run automated scanners blindly**
5. **Spam programs with duplicates**
6. **Be rude to triage team**
7. **Publicly disclose early**
8. **Give up after first rejection**

---

## Learning Path

### Month 1: Foundations
- [ ] Learn web basics (HTTP, HTML, JS)
- [ ] Set up Burp Suite
- [ ] Complete PortSwigger Academy (free)
- [ ] Join a platform
- [ ] Pick your first program

### Month 2: First Bugs
- [ ] Focus on IDOR
- [ ] Test 3-5 programs
- [ ] Submit first report
- [ ] Learn from feedback

### Month 3: Expand Skills
- [ ] Learn XSS
- [ ] Learn CSRF
- [ ] Complete more labs
- [ ] Join community Discord

### Month 4-6: Intermediate
- [ ] SQL Injection
- [ ] Authentication testing
- [ ] API testing
- [ ] First bounty (hopefully!)

### Month 6+: Advanced
- [ ] SSRF, XXE
- [ ] Logic flaws
- [ ] Chaining vulnerabilities
- [ ] Mobile testing

---

## Resources to Learn

### Free Training
1. **PortSwigger Web Security Academy**
   - https://portswigger.net/web-security
   - Best free resource

2. **OWASP Top 10**
   - https://owasp.org/www-project-top-ten/

3. **HackerOne Hacktivity**
   - Read disclosed reports
   - Learn from others

### Practice Labs
1. **PortSwigger Labs** (Free)
2. **DVWA** (Damn Vulnerable Web App)
3. **bWAPP**
4. **WebGoat**

### Communities
1. **Twitter** - Follow bug bounty hunters
2. **Discord** - Join bug bounty servers
3. **Reddit** - r/bugbounty
4. **YouTube** - Nahamsec, Stök, InsiderPhD

---

## Common Beginner Mistakes

### 1. Not Reading Scope
```
❌ Testing main site when only subdomain is in scope
✅ Carefully read what's allowed
```

### 2. Low-Quality Reports
```
❌ "There's XSS on your site"
✅ Detailed steps, PoC, impact, fix
```

### 3. Unrealistic Impact
```
❌ "Self-XSS allows complete account takeover"
✅ Realistic impact assessment
```

### 4. Testing in Production Carelessly
```
❌ Creating 1000 test accounts
✅ Minimal, non-disruptive testing
```

### 5. Giving Up Too Early
```
❌ Quitting after first duplicate
✅ Learn, adapt, keep trying
```

---

## Your First Week Checklist

### Day 1-2
- [ ] Choose a platform
- [ ] Create profile
- [ ] Set up Burp Suite
- [ ] Read methodology docs in this repo

### Day 3-4
- [ ] Pick a program
- [ ] Read scope thoroughly
- [ ] Do reconnaissance
- [ ] Map the application

### Day 5-6
- [ ] Focus testing on one vuln type
- [ ] Look for IDOR
- [ ] Look for information disclosure
- [ ] Test authentication

### Day 7
- [ ] If found something: Write report
- [ ] If not: Analyze what you learned
- [ ] Update your notes
- [ ] Plan next steps

---

## Need Help?

### Stuck?
1. Review the methodology docs
2. Check PortSwigger Academy
3. Read disclosed reports
4. Ask in Discord communities

### No Bugs Found?
- Normal for beginners!
- Average: 10-20 programs before first bug
- Keep learning and trying
- Quality testing beats quantity

---

## Quick Commands Reference

```bash
# Subdomain enumeration
subfinder -d target.com -o subs.txt

# Find live hosts
cat subs.txt | httprobe

# Directory fuzzing
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Parameter discovery
arjun -u https://target.com/endpoint

# Technology detection
whatweb target.com

# Burp Suite
# Configure browser proxy to 127.0.0.1:8080
```

---

**Remember**: Everyone started as a beginner. The key is persistence, continuous learning, and ethical testing!

**Good luck on your bug bounty journey! 🚀**
