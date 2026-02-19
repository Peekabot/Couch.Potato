# VDP vs Bug Bounty Platforms - Strategic Comparison

**Understanding the difference between free disclosure programs and paid bounty platforms.**

---

## 🎯 Quick Definitions

### **VDP (Vulnerability Disclosure Program)**
- **Policy**: "Report bugs responsibly, we won't sue you"
- **Reward**: Usually $0 (maybe swag, Hall of Fame)
- **Goal**: Protect company, avoid legal issues for researchers
- **Example**: security.txt, responsible disclosure policies

### **Bug Bounty Program**
- **Policy**: "Report bugs, get paid"
- **Reward**: $50 - $50,000+ depending on severity
- **Goal**: Incentivize security research
- **Platforms**: HackerOne, Bugcrowd, Intigriti, YesWeHack

---

## 📊 Platform-by-Platform Breakdown

### **HackerOne** (Largest Platform)

**Stats**:
- 3,000+ programs
- $100M+ paid to researchers
- Mix of paid bounties + VDPs

**Programs Types**:
- **Paid Bounty**: GitLab, Shopify, PayPal, Coinbase
- **VDP Only**: U.S. Dept of Defense, NASA, UK Ministry of Defence
- **Swag/Recognition**: Mozilla, Apache Foundation

**Average Bounties**:
- Critical: $2,500 - $10,000
- High: $500 - $2,500
- Medium: $200 - $500
- Low: $50 - $200

**Pros**:
- ✅ Most programs (largest selection)
- ✅ Best for beginners (many "Easy" programs)
- ✅ Public disclosure (learn from others)
- ✅ Good triage (fast responses)

**Cons**:
- ❌ High competition (duplicates common)
- ❌ Some programs pay very low ($50 for P3)
- ❌ Signal-to-noise ratio (many informational reports)

**Best For**: Beginners, learning from public reports, federal programs

---

### **Bugcrowd** (Clear VRT, Professional)

**Stats**:
- 1,000+ programs
- $50M+ paid
- Focus on quality over quantity

**Program Types**:
- **Paid Bounty**: Tesla, Mastercard, Western Union
- **VDP**: Some government/education programs
- **Points System**: Earn points → redeem for cash or swag

**Average Bounties**:
- P1 (Critical): $1,000 - $20,000
- P2 (High): $500 - $5,000
- P3 (Medium): $100 - $1,000
- P4 (Low): $50 - $250

**Pros**:
- ✅ Clear VRT (Vulnerability Rating Taxonomy)
- ✅ Professional triage teams
- ✅ Fast payouts (2-4 weeks typical)
- ✅ Lower competition than HackerOne

**Cons**:
- ❌ Fewer programs than HackerOne
- ❌ Less public disclosure (harder to learn)
- ❌ Stricter quality standards (more rejections)

**Best For**: Experienced researchers, mobile testing, VRT-focused approach

---

### **Intigriti** (European Focus)

**Stats**:
- 500+ programs
- Growing platform (smaller than H1/Bugcrowd)
- European + global programs

**Program Types**:
- **Paid Bounty**: European companies, crypto projects
- **VDP**: Some EU government programs

**Average Bounties**:
- Critical: €1,000 - €10,000
- High: €500 - €2,500
- Medium: €200 - €800
- Low: €50 - €200

**Pros**:
- ✅ Lower competition (fewer researchers)
- ✅ European programs (GDPR-focused companies)
- ✅ Fast triage (2-5 days typical)
- ✅ Good for crypto/blockchain programs

**Cons**:
- ❌ Smaller program selection
- ❌ Less documentation/learning resources
- ❌ Fewer "name brand" programs

**Best For**: European researchers, crypto/web3 security, lower competition

---

### **YesWeHack** (French/EU Platform)

**Stats**:
- 400+ programs
- French/European focus
- Some programs in French language

**Program Types**:
- **Paid Bounty**: European companies, French government
- **VDP**: EU public sector

**Average Bounties**:
- Similar to Intigriti (€50 - €10,000 range)

**Pros**:
- ✅ Very low competition (smallest of major platforms)
- ✅ Unique French/EU programs
- ✅ Good for bilingual researchers

**Cons**:
- ❌ Language barrier (some programs French-only)
- ❌ Smaller selection
- ❌ Less known in US market

**Best For**: French speakers, EU programs, niche opportunities

---

### **Synack** (Private, Invite-Only)

**Stats**:
- 100+ programs (all private)
- Vetted researchers only
- Application + background check required

**Program Types**:
- **Paid Bounty Only**: High-value targets (Fortune 500, government)

**Average Bounties**:
- Critical: $5,000 - $50,000
- High: $1,000 - $10,000
- Medium: $500 - $2,000

**Pros**:
- ✅ Highest bounties (top-tier programs)
- ✅ Zero competition (assigned targets)
- ✅ Direct client relationships
- ✅ SLA guarantees on payouts

**Cons**:
- ❌ Requires invitation (must apply)
- ❌ Background check required
- ❌ Limited program access (assigned, not choose)

**Best For**: Experienced researchers, military/government clearance holders

---

## 🆚 VDP vs Paid Bounty - Strategic Comparison

### **When to Hunt VDPs** (No Pay)

**Scenarios Where VDPs Make Sense**:

1. **Learning & Practice**
   - Building portfolio (first 5-10 reports)
   - Testing new techniques
   - Understanding triage process
   - Getting familiar with platforms

2. **Critical Bugs on Big Targets**
   - Found RCE on DoD systems → VDP but massive resume boost
   - NASA, FBI, etc. → No pay, but incredible reputation
   - Public recognition > $500 for career impact

3. **Low Time Investment**
   - Automated scanner found something (5 min work)
   - Drive-by finding (not worth paid program wait time)
   - Informational bugs (not eligible for bounty anyway)

4. **Ethical/Mission Alignment**
   - Government programs (patriotic duty)
   - Non-profits (good cause)
   - Open source projects (community contribution)

**VDP ROI Calculation**:
```
Time Spent: 2 hours
Payout: $0
Value: Resume line, reputation points, learning

Worth it IF:
- First 10 bugs (learning)
- Critical bug (reputation)
- <30 min time investment
```

---

### **When to Hunt Paid Bounties**

**Scenarios Where You SHOULD Get Paid**:

1. **Significant Time Investment**
   - Deep testing (8+ hours)
   - Complex exploitation
   - Custom tooling developed
   - Detailed report writing

2. **High-Impact Bugs**
   - P1/P2 vulnerabilities
   - Data breach potential
   - Account takeover
   - Financial impact

3. **You're Experienced**
   - After first 20-30 bugs
   - Established reputation
   - Reliable finding rate
   - Time is valuable

4. **Professional Researcher**
   - Bug bounty is income source
   - Not learning anymore (producing)
   - Need consistent payouts

**Paid Bounty ROI**:
```
Time Spent: 8 hours
Payout: $1,000 (P2 mobile bug)
Hourly Rate: $125/hour

Worth it IF:
- Consistent findings (not one-time luck)
- Clear scope (no wasted time)
- Fast triage (30-day SLA max)
```

---

## 📈 Major VDP Programs Worth Knowing

### **Government/Military VDPs**

| Program | Platform | Scope | Reputation Value |
|---------|----------|-------|------------------|
| **DoD Vulnerability Disclosure** | HackerOne | All DoD public systems | ⭐⭐⭐⭐⭐ Massive |
| **Hack the Pentagon** | HackerOne | Pentagon systems | ⭐⭐⭐⭐⭐ Huge |
| **Hack the Air Force** | HackerOne | USAF systems | ⭐⭐⭐⭐ Very High |
| **NASA VDP** | HackerOne | NASA public systems | ⭐⭐⭐⭐⭐ Incredible |
| **UK NCSC VDP** | HackerOne | UK gov systems | ⭐⭐⭐⭐ High |
| **FBI IC3 VDP** | HackerOne | FBI systems | ⭐⭐⭐⭐⭐ Massive |

**Why Hunt These**:
- Resume boost (DoD/NASA looks incredible)
- Security clearance advantage (if you have one)
- Patriotic duty (protect country)
- Less competition (require US residency sometimes)

**Caveats**:
- $0 payout
- Slow triage (government bureaucracy)
- Strict rules (federal systems)
- Background checks may be required

---

### **Big Tech VDPs** (Mixed)

| Company | Platform | Pays? | Average Bounty |
|---------|----------|-------|----------------|
| **Google** | Own platform | ✅ Yes | $3,133 avg |
| **Apple** | Own platform | ✅ Yes | $5,000 - $1M |
| **Microsoft** | MSRC | ✅ Yes | $500 - $250k |
| **Meta/Facebook** | Own platform | ✅ Yes | $500 - $40k |
| **Amazon** | Own platform | ✅ Yes | $100 - $10k |
| **Mozilla** | HackerOne | ⚠️ Swag only | $0 |
| **Apache** | Email | ❌ No | $0 |

**Strategy**:
- Google/Apple/Microsoft → Hunt these (high pay)
- Mozilla/Apache → Only if quick find (<30 min)

---

### **University/Education VDPs**

| Type | Example | Pays? | Worth It? |
|------|---------|-------|-----------|
| **Major Universities** | MIT, Stanford | ❌ No | Only if alumni |
| **EdTech Companies** | Coursera, Khan Academy | ⚠️ Sometimes | Check program |
| **Student Portals** | Various | ❌ No | Skip |

**Verdict**: Skip unless you have personal connection or it's a 5-min finding.

---

### **Open Source VDPs**

| Project | Platform | Pays? | Reputation Value |
|---------|----------|-------|------------------|
| **Linux Kernel** | Security list | ❌ No | ⭐⭐⭐⭐⭐ Legendary |
| **Node.js** | HackerOne | ✅ Yes (small) | ⭐⭐⭐⭐ High |
| **Ruby on Rails** | HackerOne | ✅ Yes (small) | ⭐⭐⭐⭐ High |
| **WordPress** | HackerOne | ⚠️ Swag | ⭐⭐⭐ Medium |
| **GitHub Actions** | GitHub | ✅ Yes | ⭐⭐⭐⭐ High |

**Strategy**: Hunt open source IF:
- You use the software (personal investment)
- Quick finding (<1 hour)
- Massive reputation gain (Linux, Node.js)

---

## 💰 Financial Reality Check

### **VDP Annual Earnings**: $0 - $500 (swag value)

**Typical VDP Hunter Profile**:
- 20 bugs reported
- 15 accepted
- 0 cash payouts
- 5 t-shirts, 3 Hall of Fame entries
- **Total value**: ~$200 (swag) + reputation

**Time investment**: 100 hours
**Effective hourly**: $2/hour (swag value only)

---

### **Paid Bounty Annual Earnings**: $5,000 - $100,000+

**Typical Part-Time Hunter (10 hrs/week)**:
- 50 bugs reported
- 20 accepted
- Average bounty: $500
- **Total earnings**: $10,000/year
- **Effective hourly**: $19/hour

**Typical Full-Time Hunter (40 hrs/week)**:
- 200 bugs reported
- 80 accepted
- Average bounty: $1,000
- **Total earnings**: $80,000/year
- **Effective hourly**: $38/hour

**Top 1% Hunter**:
- 500+ bugs reported
- 200+ accepted
- Average bounty: $2,500
- **Total earnings**: $500,000+/year
- **Effective hourly**: $250+/hour

---

## 🎯 Strategic Recommendation

### **Months 1-3** (Learning Phase)
```
70% VDP + 30% Paid Bounty

VDP Programs:
- DoD VDP (learn, build reputation)
- Easy HackerOne programs (practice)
- Open source (if you use it)

Paid Programs:
- "Easy" difficulty on HackerOne
- Bugcrowd P3/P4 targets (low competition)
- Mobile apps (higher pay, less competition)

Goal: 10-20 accepted bugs, learn triage process
```

### **Months 4-12** (Transition Phase)
```
30% VDP + 70% Paid Bounty

VDP Programs:
- Only if <30 min finding
- Only if massive reputation (NASA, DoD RCE)

Paid Programs:
- Focus on P2/P3 bugs ($500-$2,000 range)
- Specialize (mobile, API, cloud)
- Build relationships with programs

Goal: $500-$2,000/month consistent income
```

### **Year 2+** (Professional Phase)
```
10% VDP + 90% Paid Bounty

VDP Programs:
- Only drive-by findings
- Only if legendary reputation value

Paid Programs:
- Focus on P1/P2 ($1,000-$10,000 range)
- Private programs (Synack, invites)
- Consulting (leverage bounty reputation)

Goal: $5,000+/month, transition to full-time
```

---

## 📋 Decision Framework

**Should I hunt this VDP?**

```
IF (time < 30 min) → Yes (low opportunity cost)
IF (reputation > $500 value) → Yes (DoD, NASA, etc.)
IF (learning new technique) → Yes (educational value)
IF (first 10 bugs) → Yes (portfolio building)

ELSE → No, find a paid program instead
```

**Should I hunt this paid bounty?**

```
IF (avg bounty > $500) → Yes
IF (fast triage < 7 days) → Yes
IF (clear scope) → Yes
IF (match my specialty) → Yes

IF (avg bounty < $100) → Maybe (depends on time)
IF (slow triage > 30 days) → No (cash flow issues)
IF (unclear scope) → No (wasted time)
```

---

## 🎓 Platform Choice by Experience Level

### **Beginner** (0-20 bugs)
1. **HackerOne** (70%) - Most programs, public disclosure for learning
2. **DoD VDP** (20%) - Massive reputation, learn on fed systems
3. **Bugcrowd** (10%) - Start learning VRT

**Goal**: Learn, build portfolio, understand triage

---

### **Intermediate** (20-100 bugs)
1. **Bugcrowd** (50%) - Better bounties, less competition
2. **HackerOne** (30%) - Still good for mobile programs
3. **Intigriti** (20%) - Explore European programs

**Goal**: Consistent $500-$2,000/month income

---

### **Advanced** (100+ bugs)
1. **Synack** (40%) - Apply for private programs (highest pay)
2. **Bugcrowd** (30%) - Established relationships
3. **Direct Programs** (20%) - Company-run programs (Google, Apple)
4. **HackerOne** (10%) - Only high-value targets

**Goal**: $5,000+/month, full-time bug bounty career

---

## 💡 Bottom Line

**VDPs are valuable for:**
- ✅ Learning (first 10-20 bugs)
- ✅ Reputation (DoD, NASA, critical bugs)
- ✅ Quick finds (<30 min)
- ✅ Portfolio building

**Paid bounties are better for:**
- ✅ Consistent income
- ✅ Professional researchers
- ✅ Significant time investment
- ✅ High-impact bugs

**My recommendation**:
- **Start** with 70/30 VDP/Paid (learning)
- **Transition** to 30/70 VDP/Paid (building income)
- **Mature** to 10/90 VDP/Paid (professional)

**Never hunt a VDP if the same time could find a $500+ paid bug.**

Time is your most valuable asset. VDPs are resume builders, paid bounties are income builders. Know which you need right now.
