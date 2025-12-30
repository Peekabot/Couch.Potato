# 🎯 2025 Master Strategy

**The Complete Bug Bounty Methodology for Modern Hunters**

This document compresses the entire bug bounty journey into a master strategy, showing how tools (the engine), methods (the driver), and sources (the fuel) work together to produce results in the 2025 landscape.

---

## The Modern Hunter's Mindset

The modern hunter doesn't just "run tools." They follow a specific, logical progression designed to find the gaps that automation misses.

**Key Principle**: Automation finds the obvious. Your job is to find what others miss.

---

## Phase 1: Deep Recon (Asset Mapping)

**Goal**: Map the entire attack surface, including forgotten assets.

### Step 1: Subdomain Enumeration

```bash
# Use multiple tools for comprehensive coverage
amass enum -passive -d target.com -o amass.txt
subfinder -d target.com -o subfinder.txt
assetfinder --subs-only target.com > assetfinder.txt

# Combine and deduplicate
cat *.txt | sort -u > all_subdomains.txt
```

### Step 2: Find Live Hosts

```bash
# Check what's actually alive
cat all_subdomains.txt | httpx -o live_hosts.txt

# Get detailed info
cat live_hosts.txt | httpx -title -status-code -tech-detect -o live_detailed.txt
```

### Step 3: Historical Discovery

```bash
# Find old endpoints developers forgot about
waybackurls target.com | tee wayback.txt

# Find parameters from archived URLs
cat wayback.txt | grep "?" | cut -d "?" -f2 | cut -d "=" -f1 | sort -u > params.txt
```

### Step 4: Off-Grid Discovery

```bash
# Use Shodan to find "hidden" infrastructure
# Search: ssl:"target.com"
# Search: org:"Company Name"

# This finds:
# - Forgotten staging servers
# - Internal tools exposed
# - Legacy infrastructure
# - Cloud assets
```

**Pro Tip**: Don't just look for `target.com`. Look for:
- `staging.target.com`
- `dev.target.com`
- `api.target.com`
- `admin-panel.target.com`
- Legacy domains they acquired

---

## Phase 2: Discovery (Contextual Scanning)

**Goal**: Find hidden functionality and tech-specific vulnerabilities.

### Step 1: Technology Detection

```bash
# Detect technologies
cat live_hosts.txt | while read url; do
    whatweb $url
done

# Look for:
# - WordPress → Run WPScan
# - Drupal → Run Droopescan
# - APIs → GraphQL introspection
# - Cloud → S3 bucket enum
```

### Step 2: Contextual Nuclei Scanning

```bash
# Don't just run all templates blindly
# Be SPECIFIC based on tech stack

# For WordPress sites
nuclei -l wordpress_sites.txt -t ~/nuclei-templates/vulnerabilities/wordpress/

# For APIs
nuclei -l api_endpoints.txt -t ~/nuclei-templates/vulnerabilities/generic/

# For specific CVEs of detected versions
nuclei -l live_hosts.txt -t ~/nuclei-templates/cves/2024/
```

### Step 3: Directory Brute-Forcing

```bash
# FFUF for hidden directories
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Look specifically for:
# - /.git (exposed git repos)
# - /.env (environment files)
# - /admin (admin panels)
# - /api (undocumented APIs)
# - /backup (backup files)
# - /.aws (AWS credentials)

# Try bypassing 403s
ffuf -u https://target.com/admin/FUZZ -w wordlist.txt -H "X-Original-URL: /admin"
```

### Step 4: JavaScript Analysis

```bash
# Download all JS files
getallurls target.com | grep ".js$" | httpx -mc 200 -content-type -o js_files.txt

# Extract endpoints from JS
cat js_files.txt | while read url; do
    python3 linkfinder.py -i $url -o cli
done

# Look for:
# - API endpoints
# - Hidden parameters
# - Hardcoded credentials
# - Internal URLs
# - Debug code
```

**Pro Tip**: When you see a 403 Forbidden, try these bypasses:
```bash
# Path traversal
/admin → /admin/
/admin → /admin..;/
/admin → /./admin/./

# Custom headers
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
```

---

## Phase 3: Logic Testing (Human Intuition)

**This is where the big money is.** Business logic flaws that automation can't find.

### 1. Price Manipulation

```http
POST /checkout HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "item_id": "123",
  "price": 99.99,    ← Change to 0.01
  "quantity": 1
}
```

**Test:**
- Can you change price in request?
- Negative prices? (`-99.99`)
- Large discounts? (`discount: 100000`)
- Currency manipulation? (change USD to currency worth less)

### 2. Parameter Tampering (IDOR)

```http
GET /api/user/profile?user_id=123 HTTP/1.1

# Try changing to:
# user_id=124 (other user)
# user_id=1 (likely admin)
# user_id[]=123&user_id[]=124 (array)
# user_id=123&admin=true
```

**Test Every ID:**
- Order IDs
- User IDs
- Document IDs
- Invoice IDs
- Message IDs

### 3. Race Conditions

```python
# Can you use one coupon code twice by clicking fast?
import requests
import threading

def apply_coupon():
    requests.post("https://target.com/apply-coupon",
                  data={"code": "SAVE50"},
                  cookies={"session": "your_session"})

# Send 10 requests simultaneously
threads = []
for i in range(10):
    t = threading.Thread(target=apply_coupon)
    threads.append(t)
    t.start()
```

**Test for:**
- Multiple coupon applications
- Duplicate purchases with same payment
- Parallel transfers depleting same balance
- Concurrent vote/like submissions

### 4. Authentication/Authorization Bypass

```http
# Missing authorization checks
GET /api/admin/users HTTP/1.1
# No authentication header → Does it work?

# JWT manipulation
# Change role from "user" to "admin"
# Change user_id to admin's ID
# Try algorithm "none"

# Session fixation
# Use old session after logout
# Session from different user
```

### 5. Business Logic Examples

**E-commerce:**
- Apply multiple discounts that shouldn't stack
- Refer yourself for referral bonuses
- Return items but keep the refund
- Gift cards with more value than paid

**Social Media:**
- Follow private account then unfollow to see posts
- React to deleted content
- Message blocked users through API
- Vote/poll manipulation

**Banking/Finance:**
- Transfer more than account balance
- Overdraft without fees
- Exploit rounding errors
- Currency conversion arbitrage

**Pro Tip**: Think like a user trying to cheat the system. What would you try if you wanted free stuff?

---

## Phase 4: Chaining (Impact Amplification)

**Don't just report minor bugs. Chain them for maximum impact.**

### Example Chain 1: Info Leak → Account Takeover

```
1. Find information disclosure (/debug.log shows emails)
   Impact: Low ($100)

2. Use those emails to enumerate valid accounts
   Impact: Medium ($250)

3. Discover password reset doesn't rate limit
   Impact: Medium ($250)

4. Brute force password reset → Account takeover
   Impact: CRITICAL ($5,000)
```

### Example Chain 2: SSRF → RCE

```
1. Find SSRF in image upload
   Impact: Medium ($500)

2. Use SSRF to access AWS metadata
   http://169.254.169.254/latest/meta-data/iam/security-credentials/

3. Steal AWS credentials
   Impact: High ($2,000)

4. Use credentials to access S3 buckets
   Impact: CRITICAL ($10,000)
```

### Example Chain 3: XSS → Session Hijacking

```
1. Find Self-XSS in profile name
   Impact: Informational ($0)

2. Chain with CSRF to change victim's name to payload
   Impact: Medium ($500)

3. Admin views profile → XSS fires
   Impact: High ($2,000)

4. Steal admin session → Full account takeover
   Impact: CRITICAL ($5,000)
```

### Chaining Strategy

1. **Map the full attack path** before reporting
2. **Demonstrate real-world impact** with PoC
3. **Show how an attacker would exploit it** step-by-step
4. **Quantify the damage** (how many users affected, what data exposed)

---

## The Professional Toolkit (2025 Essentials)

| Category | Primary Tools | Pro Tip |
|----------|---------------|---------|
| **Proxy / Intercept** | Burp Suite Professional, Caido | Use Repeater to tweak and resend requests 100x to see how the server reacts |
| **Reconnaissance** | Amass, Subfinder, Shodan | Use Shodan to find servers that are "off-grid" but still part of the company |
| **Scanning** | Nuclei, SQLMap, Nmap | Write your own Nuclei templates for unique bugs you find; don't just use defaults |
| **Discovery** | FFUF, httpx, Waybackurls | Look for 403 (Forbidden) pages and try to bypass them with custom headers |
| **Privacy / OpSec** | Mullvad VPN, VPS (DigitalOcean) | Always run heavy scans from a VPS so your home IP doesn't get blacklisted |

### Why Burp Suite Professional?

The $449/year is worth it for:
- **Faster scanning** with parallelization
- **Bambdaa Collaborator** for SSRF/XXE testing (your own OOB server)
- **Active Scanner** finds low-hanging fruit automatically
- **Extensions** like Autorize, Param Miner, Turbo Intruder
- **Professional support** and updates

### OpSec Best Practices

```bash
# 1. Use a VPS for aggressive scanning
# DigitalOcean droplet ($6/month)

# 2. Route traffic through VPN
# Mullvad VPN (privacy-focused)

# 3. Separate testing environment
# Don't test from your home network
# Don't test from your work laptop

# 4. Rotate IPs for heavy scanning
# Use cloud providers
# Use proxy pools
```

---

## Sources & Continuous Learning

To stay competitive, you need to live where the information is fresh.

### The Platforms

**Tier 1 - Start Here:**
- **HackerOne**: Largest platform, most programs, beginner-friendly
- **Bugcrowd**: Great variety, good payouts, strong community
- **Intigriti**: European focus, quality programs, responsive triage

**Tier 2 - When You Level Up:**
- **Synack**: Invite-only, elite programs, higher payouts
- **YesWeHack**: European programs, professional hunters
- **Cobalt**: Pentesting-style, more structured

**Tier 3 - Specialized:**
- Direct programs (Google VRP, Meta, Apple)
- Company-specific programs

### The Write-ups

**Where to read disclosed reports:**

1. **HackerOne Hacktivity**
   - https://hackerone.com/hacktivity
   - Read 10 reports per day
   - Focus on your target tech stack

2. **Medium.com**
   - Search: "bug bounty writeup"
   - Follow: InfoSec Write-ups publication
   - Filter by recent (last 30 days)

3. **Twitter/X**
   - Follow hashtag: #bugbountytip
   - Follow top hunters
   - Real-time vulnerability trends

4. **GitHub**
   - Search: "bug bounty writeup"
   - Learn from PoC code
   - Study methodology

**How to Read Write-ups:**
1. Don't just read - **replicate**
2. Understand the **thought process**
3. Add to your **testing checklist**
4. Try on **your current target**

### The Community

**YouTube Channels:**
- **NahamSec**: Live recon, methodology, tool tutorials
- **Jason Haddix**: The Bug Hunter's Methodology (watch yearly)
- **Stök**: Beginner-friendly, motivational
- **InsiderPhD**: Beginner tutorials, vulnerability deep-dives
- **PwnFunction**: Animated security concepts

**Discord Servers:**
- NahamSec Discord
- Stök Discord
- Bug Bounty World
- InfoSec Community

**Twitter/X to Follow:**
- @NahamSec
- @jhaddix
- @stokfredrik
- @InsiderPhD
- @samwcyo
- @zseano
- @gregxsunday

### Learning Schedule

**Daily (30 min):**
- Read 3-5 disclosed reports
- Watch 1 YouTube tutorial
- Test 1 new technique on your target

**Weekly (2 hours):**
- Deep-dive into 1 vulnerability type
- Complete 1 PortSwigger lab
- Write up what you learned

**Monthly:**
- Review your rejected reports
- Update your methodology
- Try a completely new technique

---

## The 2025 Daily Workflow

### Morning Routine (1 hour)

```bash
# 1. Check your active reports
# - Any triage updates?
# - Any bounties paid?

# 2. Review new programs
# - New programs on your platform
# - Programs that just went public

# 3. Learning
# - Read 3 writeups
# - Note new techniques
```

### Active Hunting (3-4 hours)

```bash
# 1. Recon (30 min)
./recon.sh target.com

# 2. Contextual scanning (30 min)
# Based on what you found in recon

# 3. Manual testing (2-3 hours)
# Focus on business logic
# Test EVERY parameter
# Chain vulnerabilities

# 4. Documentation (30 min)
# If you find something, document immediately
# Don't wait until end of day
```

### Evening Review (30 min)

```bash
# 1. What did you test today?
# 2. What worked?
# 3. What didn't work?
# 4. What will you try tomorrow?
```

---

## Common Pitfalls in 2025

### ❌ Pitfall 1: Running Tools Blindly

```bash
# DON'T do this:
nuclei -l huge_list.txt -t ~/nuclei-templates/

# DO this:
# Understand the target first
# Run specific templates
# Analyze results before moving on
```

### ❌ Pitfall 2: Ignoring Low-Hanging Fruit

```
Many hunters skip "obvious" things:
- /.git exposed
- Default credentials
- Missing rate limiting
- CORS misconfig

These STILL get accepted and paid!
```

### ❌ Pitfall 3: Poor OpSec

```
Your IP gets banned because:
- Running aggressive scans from home
- Not respecting rate limits
- Testing production at peak hours
- Triggering WAF/IDS
```

### ❌ Pitfall 4: Not Reading Reports

```
You're missing out on:
- New techniques
- Program-specific quirks
- What triage teams accept/reject
- Impact justification examples
```

---

## Success Metrics

### Beginner (Months 1-3)
- ✅ 5+ submissions
- ✅ 1+ accepted report
- ✅ First bounty payment
- ✅ Understanding of OWASP Top 10

### Intermediate (Months 4-12)
- ✅ 50+ submissions
- ✅ 20+ accepted reports
- ✅ $5,000+ total earned
- ✅ Found one critical vulnerability

### Advanced (Year 2+)
- ✅ Consistent monthly income
- ✅ Known in the community
- ✅ Discovered 0-days
- ✅ Invited to private programs

---

## Your Action Plan for Tomorrow

### If You're Starting Out:
1. Pick ONE program on Intigriti/HackerOne
2. Run the Phase 1 recon commands
3. Find ONE interesting subdomain
4. Test it manually for IDOR
5. Even if you don't find anything, you practiced

### If You're Intermediate:
1. Review your last rejected report
2. Understand WHY it was rejected
3. Apply that lesson to current target
4. Focus on business logic flaws
5. Try chaining two minor bugs

### If You're Advanced:
1. Write your own Nuclei template
2. Build custom recon automation
3. Target harder programs
4. Mentor someone newer
5. Share knowledge (blog/Twitter)

---

## Next Steps

Now you can:

1. **Use the automated recon script** (see `/scripts/recon.sh`)
2. **Study specific vulnerabilities** (see `/methodology/IDOR_DEEPDIVE.md` and `SSRF_DEEPDIVE.md`)
3. **Practice on a live program** using this methodology
4. **Track your progress** in `SUBMISSION_TRACKER.md`

---

**Remember**: The difference between a $0 report and a $5,000 report is often just spending 2 more hours understanding the business logic.

**Good luck hunting! 🎯**
