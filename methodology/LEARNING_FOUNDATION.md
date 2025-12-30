# 📚 The Learning Foundation

**The three-layer pyramid: Foundation (Learning) → Toolkit (Execution) → Strategy (Winning)**

---

## The Foundation (What to Learn)

### Layer 1: Networking & Anonymity

**Why it matters:** Professional OpSec + Bypass detection + Avoid IP bans

#### Essential Concepts

```
1. How Data Travels
   - HTTP/HTTPS request flow
   - DNS resolution
   - TCP/IP fundamentals
   - Proxy chains

2. VPNs & Privacy
   - How VPNs work
   - DNS leaks
   - WebRTC leaks
   - IPv6 leaks

3. Anonymity Best Practices
   - Separate testing environment
   - VPS for scanning
   - IP rotation
   - Browser fingerprinting
```

#### OpSec Checklist

```bash
# DNS Leak Test
# Visit: https://dnsleaktest.com

# WebRTC Leak Test
# Visit: https://browserleaks.com/webrtc

# Check for IPv6 leaks
curl -6 ifconfig.co

# Your setup should be:
✅ VPN active (Mullvad/ProtonVPN)
✅ DNS not leaking
✅ WebRTC disabled in browser
✅ Using VPS for heavy scans
✅ Separate browser profile for testing
```

---

### Layer 2: The "Hacker Bible"

**Essential Reading:**

#### 1. "Real-World Bug Hunting" by Peter Yaworski

**Why read it:**
- Teaches you HOW TO THINK, not just what to test
- Real bounty reports with reasoning
- Business logic focus
- From $0 to $30k+ journey

**Key Lessons:**
```
1. Think like an attacker
2. Question every assumption
3. Chain minor bugs into critical impact
4. Write reports that companies can't refuse
```

#### 2. "The Web Application Hacker's Handbook"

**Why read it:**
- Deep technical foundation
- Comprehensive methodology
- Every major vulnerability type
- Still relevant in 2025

#### 3. Online Resources

```
✅ PortSwigger Web Security Academy (FREE!)
   - Best hands-on learning
   - Certificate validates knowledge
   - Updated regularly

✅ OWASP Testing Guide
   - Industry standard methodology
   - Comprehensive coverage
   - Free and authoritative

✅ HackerOne Hacktivity
   - Real disclosed reports
   - Learn from successful hunters
   - See what companies pay for

✅ Jason Haddix's Methodology
   - "The Bug Hunter's Methodology" talk
   - Updated yearly
   - Industry gold standard
```

---

### Layer 3: OWASP Top 10

**Your Core Curriculum - These make up 80%+ of bounties**

#### OWASP Top 10 (2021 Edition)

```
1. Broken Access Control (⭐⭐⭐⭐⭐)
   - IDOR (Start here!)
   - Missing authorization
   - Directory traversal
   → Easiest to find, consistent payouts

2. Cryptographic Failures (⭐⭐⭐)
   - Sensitive data in transit
   - Weak encryption
   - Password storage issues
   → Medium difficulty, good impact

3. Injection (⭐⭐⭐⭐)
   - SQL Injection
   - Command Injection
   - LDAP, XPath, etc.
   → High impact, automated tools help

4. Insecure Design (⭐⭐⭐⭐⭐)
   - Business logic flaws
   - Missing rate limiting
   - Race conditions
   → Hardest to automate, biggest payouts

5. Security Misconfiguration (⭐⭐⭐⭐)
   - Default credentials
   - Directory listing
   - Verbose errors
   → Easy to find with recon

6. Vulnerable Components (⭐⭐⭐)
   - Outdated libraries
   - Known CVEs
   - Unpatched software
   → Tools help, but competition is high

7. Authentication Failures (⭐⭐⭐⭐)
   - Weak passwords
   - Session fixation
   - Credential stuffing
   → Good for beginners

8. Software/Data Integrity (⭐⭐⭐)
   - Insecure deserialization
   - Unsigned updates
   - CI/CD pipeline issues
   → Advanced, high impact

9. Logging/Monitoring Failures (⭐⭐)
   - Usually informational
   - Low bounties
   - Good for completeness

10. SSRF (⭐⭐⭐⭐⭐)
    - Access internal services
    - Cloud metadata theft
    - RCE potential
    → High value in cloud era
```

**Recommended Learning Order:**
```
Beginner:    IDOR → XSS → CSRF
Intermediate: SQLi → SSRF → XXE
Advanced:    Business Logic → Deserialization → RCE
```

---

### Layer 4: Build Before You Break

**You cannot effectively hack what you don't understand.**

#### Learn to Build

```javascript
// Example: Build a simple login system
// Then you'll understand how to break it

// Vulnerable code:
app.post('/login', (req, res) => {
    const query = `SELECT * FROM users WHERE username='${req.body.username}'`;
    // Now you understand WHY SQLi works
});

// Secure code:
app.post('/login', (req, res) => {
    const query = 'SELECT * FROM users WHERE username=?';
    db.query(query, [req.body.username]);
    // Now you understand HOW to fix it
});
```

#### What to Build

**1. Simple Web App**
```
Technology: Node.js + Express + SQLite
Features:
- User registration/login
- Profile management
- File upload
- Search functionality

Purpose: Intentionally make it vulnerable, then fix it
```

**2. API Service**
```
Technology: Python Flask + PostgreSQL
Features:
- REST API
- JWT authentication
- CRUD operations

Purpose: Learn API security by breaking your own
```

**3. Cloud Infrastructure**
```
Platform: AWS Free Tier
Components:
- EC2 instance
- S3 bucket
- Lambda function

Purpose: Understand cloud misconfigurations
```

#### Developer Assumptions (Where Bugs Live)

```
Common assumptions developers make:

❌ "Users will only send valid data"
   → Test: Invalid types, negative numbers, SQL injection

❌ "The client-side validation is enough"
   → Test: Bypass with Burp, tamper requests

❌ "Nobody will guess this URL"
   → Test: Directory brute-forcing, robots.txt

❌ "The ID is in the URL, but they can only access their own"
   → Test: IDOR

❌ "This endpoint is only called by our frontend"
   → Test: Direct API access, CSRF

❌ "The image upload only accepts images"
   → Test: Upload PHP file disguised as image

❌ "Rate limiting on the login is enough"
   → Test: Password reset, registration, other endpoints
```

---

## The Toolkit (How to Practice)

### Your Development Environment

**Minimum Setup:**
```
Hardware:
- Any laptop with 8GB+ RAM
- Decent internet connection

Software:
✅ Kali Linux (or Ubuntu + tools)
✅ Burp Suite Community (or Pro if serious)
✅ Firefox/Chrome with extensions
✅ Note-taking app (Obsidian/Notion/Cherrytree)

Optional:
- VPS for scanning (DigitalOcean $6/month)
- Burp Suite Pro ($449/year - worth it!)
- Cloud account (AWS Free Tier)
```

**Browser Setup:**
```
Extensions:
✅ FoxyProxy (proxy management)
✅ Wappalyzer (tech detection)
✅ Cookie-Editor (cookie manipulation)
✅ HackTools (hacker toolkit)

Settings:
✅ Disable WebRTC
✅ Import Burp CA certificate
✅ Separate profile for testing
```

---

### Muscle Memory: Hands-On Practice

**The progression that works:**

#### Phase 1: Theory (Week 1-2)
```
✅ PortSwigger Web Security Academy
   - Watch videos
   - Read explanations
   - Understand concepts

Time: 1-2 hours/day
```

#### Phase 2: Guided Labs (Week 3-6)
```
✅ PortSwigger Labs (FREE)
   - Apprentice level (easy)
   - Practitioner level (medium)
   - Expert level (hard)

✅ TryHackMe Rooms
   - OWASP Top 10
   - Web Fundamentals
   - Burp Suite rooms

Time: 2-3 hours/day
Goal: Complete 50+ labs
```

#### Phase 3: Realistic Practice (Week 7-12)
```
✅ HackTheBox
   - Start with "Easy" machines
   - Focus on web challenges
   - Join Discord for hints

✅ PentesterLab
   - Real-world scenarios
   - Professional-grade labs
   - Worth the subscription

Time: 3-4 hours/day
Goal: Root 10+ machines
```

#### Phase 4: Real Targets (Month 4+)
```
✅ Pick beginner-friendly program
   - Wide scope
   - Active payouts
   - Responsive triage

✅ Apply what you learned
   - Use same methodology
   - Take detailed notes
   - Don't expect immediate success

Time: 4-6 hours/day
Goal: First valid submission
```

---

### Reconnaissance: Jason Haddix's Methodology

**The Industry Standard Approach**

#### The Methodology (Simplified)

```
1. ASSET DISCOVERY
   ├─ Subdomain enumeration
   ├─ Cloud asset discovery
   ├─ Acquisitions and ASN discovery
   └─ Reverse WHOIS

2. SUBDOMAIN ENUMERATION
   ├─ Passive (crt.sh, VirusTotal, SecurityTrails)
   ├─ Active (Amass, Subfinder, DNSenum)
   ├─ Brute force (Sublist3r, custom wordlists)
   └─ Permutations (alterations)

3. SCREENING (ALIVE CHECK)
   ├─ httprobe/httpx
   ├─ Screenshots (Aquatone/EyeWitness)
   └─ Technology detection

4. VULNERABILITY DISCOVERY
   ├─ Automation (Nuclei, Jaeles)
   ├─ Manual testing (OWASP Top 10)
   ├─ JavaScript analysis (endpoints/secrets)
   └─ Parameter discovery

5. EXPLOITATION
   ├─ Validate findings
   ├─ Chain vulnerabilities
   ├─ Demonstrate impact
   └─ Report professionally
```

**Updated Yearly:** Watch Jason's DEFCON/BHIS talks for latest techniques

---

### Automation is an Assistant

**The Right Way to Use Tools:**

```python
# ❌ WRONG: Run all Nuclei templates blindly
nuclei -l huge_list.txt -t ~/nuclei-templates/

# ✅ RIGHT: Strategic, targeted scanning
# 1. Understand what you're testing
# 2. Use specific templates
# 3. Manually verify results

nuclei -l wordpress_sites.txt -t ~/nuclei-templates/vulnerabilities/wordpress/
# Then manually test interesting findings
```

**The Truth About Tools:**

```
Tools find the haystack (obvious bugs everyone sees)
Humans find the needle (unique bugs that pay)

Automated scanners:
✅ Good for: Initial recon, known CVEs, quick wins
❌ Bad for: Business logic, context-specific bugs, chaining

Your value: Thinking, not tool-running

Example:
- Scanner finds: 1000 endpoints
- You find: The ONE endpoint with broken authorization
- You get paid, scanner doesn't
```

---

## The Strategy (How to Get Paid)

### Depth Over Breadth

**Stop "Buffet Hunting"**

```
❌ Bad Approach:
- Day 1: Test Uber
- Day 2: Test Netflix
- Day 3: Test Facebook
- Day 4: Test Google
- Result: Surface-level testing, no bugs

✅ Good Approach:
- Week 1-4: Deep dive on Uber
  - Understand every feature
  - Map entire attack surface
  - Test business logic
  - Find overlooked bugs
- Result: 5+ valid bugs
```

**Pick ONE Massive Target:**

```
Criteria for choosing:
✅ Product you already use (familiar with features)
✅ Wide scope (more attack surface)
✅ Active program (recent payouts)
✅ Beginner-friendly (accepts low/medium severity)

Examples:
- Slack (if you use it daily)
- Shopify (if you know e-commerce)
- GitHub (if you're a developer)
```

**Go Deep:**

```
Week 1: User perspective
- Sign up
- Use every feature
- Understand user flows
- Note interesting functionality

Week 2: Recon
- Map all subdomains
- Find hidden endpoints
- Technology detection
- Historical data (Wayback)

Week 3-4: Testing
- OWASP Top 10
- Business logic
- Privilege escalation
- Feature-specific bugs

Week 5+: Chaining & Impact
- Chain minor bugs
- Demonstrate real impact
- Professional reports
```

---

### Focus on Business Impact

**The Question That Determines Bounty Amount:**

> "How could this lose the company money or leak sensitive data?"

#### Examples of Business Impact

**Low Impact ($0-$100):**
```
Bug: Information disclosure of public data
Impact: "I can see the company's public email"
Why low: No business harm
```

**Medium Impact ($500-$2,000):**
```
Bug: IDOR in user profiles
Impact: "I can access private emails of 100K users"
Why medium: Privacy violation, GDPR fine potential
```

**High Impact ($5,000-$10,000):**
```
Bug: Payment manipulation
Impact: "I can buy $1000 items for $1"
Why high: Direct financial loss + fraud potential
```

**Critical Impact ($10,000-$50,000):**
```
Bug: AWS credential leak via SSRF
Impact: "I can access S3 with all customer payment data"
Why critical: Massive data breach + regulatory fines
```

#### The Impact Formula

```
Impact = (Number of Users Affected) × (Sensitivity of Data) × (Ease of Exploitation)

Example 1:
- Affects: 1 user (you)
- Data: Email address
- Ease: Complex
= Low impact

Example 2:
- Affects: 10M users
- Data: Credit cards
- Ease: Single request
= Critical impact
```

---

### Chain Your Bugs

**Single Bug vs. Chain**

```
❌ Don't report:
"Information disclosure: /debug shows server version"
Bounty: $0 (informational)

✅ Do report:
1. Info disclosure shows old Apache version
2. Old Apache has known CVE
3. CVE leads to RCE
4. RCE gives access to database
5. Database has customer credit cards

Bounty: $20,000 (critical)
```

#### Chaining Examples

**Chain 1: XSS → Account Takeover**
```
1. Find Self-XSS in profile name (Info)
2. Find CSRF in profile update (Medium)
3. Chain: CSRF changes victim's name to XSS payload
4. Admin views profile → XSS fires → Session stolen
Impact: Admin account takeover (Critical)
```

**Chain 2: IDOR → Mass Data Leak**
```
1. Find IDOR in single user profile (Medium)
2. Find lack of rate limiting (Info)
3. Chain: Enumerate all 1M users automatically
4. Export entire user database
Impact: Mass data breach (Critical)
```

**Chain 3: Information Disclosure → Credential Compromise**
```
1. Find .git exposed (Low)
2. Download source code (Medium)
3. Find hardcoded AWS keys in code (High)
4. Access production S3 buckets (Critical)
Impact: Complete AWS compromise
```

---

### Human Error is the Key

**Where Humans Make Mistakes:**

#### 1. Reused Handles (De-anonymization)
```
Developer's Twitter: @johndoe123
Developer's GitHub: @johndoe123
Developer's Personal Site: johndoe123.dev

Leak: /api/internal/users/johndoe123
→ Now you know who to target for social engineering
```

#### 2. Metadata in Files
```
PDF invoice → Metadata shows internal server path
Image upload → EXIF data shows internal IP
Document → Creator field shows employee name
```

#### 3. Logic Errors in Checkout
```
❌ Assumption: "Users won't send negative quantity"
Test: {"quantity": -1, "price": 100}
Result: You get $100 credit instead of charge

❌ Assumption: "Discount can't exceed 100%"
Test: {"discount_percent": 150}
Result: Company pays you to buy

❌ Assumption: "Users can't modify the total"
Test: Intercept request, change total to $0.01
Result: Free purchase
```

#### 4. Copy-Paste Errors
```
// Developer copies authentication code
// Forgets to modify for new endpoint

GET /api/user/profile → Requires auth ✅
POST /api/admin/users → Forgot to require auth ❌
```

---

## 2025 Success Checklist

### ✅ Pick ONE Large Program

```
1. Visit HackerOne or Bugcrowd
2. Filter by:
   - "Paying bounties"
   - "Recently awarded"
   - "Wide scope"
3. Pick ONE you actually use
4. Commit to 30 days minimum
```

### ✅ Study as User First

```
Week 1 Task List:
- [ ] Sign up for the service
- [ ] Use every single feature
- [ ] Take notes on interesting functions
- [ ] Map out user flows
- [ ] Think: "Where would I hide data?"
- [ ] Think: "What actions are valuable?"
- [ ] Think: "What would I try to exploit?"
```

### ✅ Perform Recon

```bash
# Use the automated script
./scripts/recon.sh target.com

# Then manually:
- [ ] Review all subdomains
- [ ] Check for forgotten assets (dev, staging, old)
- [ ] Find JavaScript files
- [ ] Extract parameters
- [ ] Technology stack identification
```

### ✅ Test for Logic Flaws + OWASP

```
Manual Testing Checklist:
- [ ] IDOR on every ID parameter
- [ ] Price manipulation in checkout
- [ ] Coupon/voucher abuse
- [ ] Account enumeration
- [ ] Missing rate limiting
- [ ] CSRF on state-changing actions
- [ ] XSS in all input fields
- [ ] SQLi in search/filters
```

### ✅ Report with Business Impact

```markdown
Your Report Template:

## Title
[Specific, impactful title]

## Impact (LEAD WITH THIS)
An attacker can [specific action] which leads to [business harm].
This affects [X users] and could result in [financial/regulatory consequence].

## Steps to Reproduce
[Clear, numbered steps]

## Proof of Concept
[Working PoC with screenshots]

## Remediation
[How to fix it]

Business Impact Section:
- Estimated users affected: [number]
- Data sensitivity: [PII/Financial/Public]
- Regulatory risk: [GDPR/PCI-DSS/HIPAA]
- Financial impact: [Revenue loss/Fraud potential]
```

---

## Your 30-Day Action Plan

**Week 1: Foundation**
```
- [ ] Read this entire document
- [ ] Complete 10 PortSwigger labs
- [ ] Pick your target program
- [ ] Set up tools (Burp, VPN, note-taking)
```

**Week 2: Reconnaissance**
```
- [ ] Run recon script on target
- [ ] Manual exploration as user
- [ ] Map all interesting features
- [ ] Document technology stack
```

**Week 3-4: Testing**
```
- [ ] Test for IDOR everywhere
- [ ] Test business logic flaws
- [ ] Test OWASP Top 10
- [ ] Try chaining minor bugs
```

**Week 4: Reporting**
```
- [ ] If bug found: Write professional report
- [ ] If no bug: Analyze what you learned
- [ ] Update your methodology
- [ ] Continue with deeper testing
```

---

## Common Pitfalls to Avoid

```
❌ Pitfall 1: Tutorial Hell
Watching videos forever, never practicing
Fix: 80% practice, 20% learning

❌ Pitfall 2: Tool Dependency
Only running automated scanners
Fix: Tools find 20%, manual finds 80%

❌ Pitfall 3: Program Hopping
Testing new target every day
Fix: Commit to one target for 30 days

❌ Pitfall 4: Ignoring Business Logic
Only testing technical bugs
Fix: Think about what hurts the business

❌ Pitfall 5: Poor Reports
"XSS exists on your site"
Fix: Impact, PoC, remediation, professionalism
```

---

## Resources Summary

### Books
1. "Real-World Bug Hunting" - Peter Yaworski
2. "The Web Application Hacker's Handbook" - Stuttard & Pinto

### Free Training
1. PortSwigger Web Security Academy
2. OWASP Testing Guide
3. TryHackMe (Free rooms)

### Practice Platforms
1. PortSwigger Labs (Free)
2. HackTheBox (Free tier)
3. PentesterLab (Paid but worth it)

### Methodologies
1. Jason Haddix's Bug Bounty Methodology
2. OWASP Testing Guide
3. This repository's guides

### Communities
1. Twitter: Follow top hunters
2. Discord: Join bug bounty servers
3. Reddit: r/bugbounty

---

**The difference between hobbyist and professional is depth, business impact focus, and professional reporting.**

**Now stop reading and start practicing! 🚀**
