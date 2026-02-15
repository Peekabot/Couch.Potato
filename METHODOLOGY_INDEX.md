# 📚 Methodology Index
## Organized Bug Bounty Hunting Theories & Techniques

This index organizes all hunting methodologies in the repository into a coherent learning path, from foundation to advanced specialization.

---

## 📖 How to Use This Index

**For Absolute Beginners:**
1. Start with [Quick Start Guide](./QUICK_START.md)
2. Build foundation using [Learning Foundation](./methodology/LEARNING_FOUNDATION.md)
3. Follow the [2025 Master Strategy](./methodology/2025_MASTER_STRATEGY.md)

**For Intermediate Hunters:**
1. Master core techniques in [General Testing](#core-testing-methodologies)
2. Deep dive into specific vulnerabilities in [Vulnerability Deep Dives](#vulnerability-deep-dives)
3. Develop your workflow using [Tools & Automation](#tools--automation)

**For Advanced Hunters:**
1. Study [Advanced Attack Chains](#advanced-techniques)
2. Review [Platform-Specific Strategies](#platform-specific-guides)
3. Optimize with [Automation & Custom Tools](./methodology/TOOLS.md)

---

## 🎯 Learning Path Structure

```
Foundation Layer
    ├── Quick Start Guide
    └── Learning Foundation
            │
Core Testing Layer
    ├── Reconnaissance
    ├── Web Application Testing
    └── API Testing
            │
Specialization Layer
    ├── IDOR Deep Dive
    ├── SSRF Deep Dive
    └── [Future: XSS, SQLi, etc.]
            │
Strategy Layer
    └── 2025 Master Strategy
            │
Execution Layer
    ├── Tools & Automation
    └── Report Templates
```

---

## 📋 Complete Methodology Catalog

### **Foundation (Start Here)**

#### [Quick Start Guide](./QUICK_START.md)
**Purpose:** Get your first bug within 7 days
**Topics:**
- Platform selection and setup
- First program selection criteria
- Initial reconnaissance workflow
- Writing your first report
- Tracking submissions

**Best For:** Complete beginners, first-time hunters
**Time Investment:** 1-2 weeks
**Prerequisites:** None

---

#### [Learning Foundation](./methodology/LEARNING_FOUNDATION.md)
**Purpose:** Build the three-layer pyramid: Learning → Execution → Strategy
**Topics:**
- Networking & anonymity fundamentals
- Web application architecture
- Security concepts and common vulnerabilities
- OpSec best practices
- Essential skills roadmap

**Best For:** Understanding why techniques work, not just how
**Time Investment:** 2-4 weeks of study
**Prerequisites:** Basic computer literacy

---

### **Core Testing Methodologies**

#### [Reconnaissance](./methodology/RECONNAISSANCE.md)
**Purpose:** Map attack surface and discover forgotten assets
**Topics:**
- Subdomain enumeration techniques
- Asset discovery methods
- DNS reconnaissance
- Port scanning strategies
- Content discovery
- Technology fingerprinting

**Best For:** Every bug hunt (always start here)
**Time Investment:** 2-4 hours per target
**Prerequisites:** Basic command line knowledge

**Related:**
- Tools: subfinder, amass, httprobe, waybackurls
- Next: Web Testing or API Testing

---

#### [Web Application Testing](./methodology/WEB_TESTING.md)
**Purpose:** Systematic web app vulnerability discovery
**Topics:**
- Authentication & session testing
- Authorization bypass techniques
- Input validation vulnerabilities
- Business logic flaw identification
- Client-side security
- Information disclosure

**Best For:** Traditional web applications
**Time Investment:** 4-8 hours per application
**Prerequisites:** Reconnaissance, Burp Suite basics

**Related:**
- Deep Dives: IDOR, SSRF
- Tools: Burp Suite, browser dev tools

---

#### [API Testing](./methodology/API_TESTING.md)
**Purpose:** Find vulnerabilities in REST, GraphQL, and SOAP APIs
**Topics:**
- API discovery and enumeration
- Authentication testing (JWT, OAuth, API keys)
- Authorization flaws in APIs
- Rate limiting bypass
- Mass assignment vulnerabilities
- GraphQL-specific attacks

**Best For:** Modern SaaS applications, mobile backends
**Time Investment:** 3-6 hours per API
**Prerequisites:** Understanding HTTP, JSON/XML

**Related:**
- Tools: Postman, Burp Suite, Arjun
- Cross-reference: IDOR Deep Dive for API object references

---

### **Vulnerability Deep Dives**

#### [IDOR (Insecure Direct Object References)](./methodology/IDOR_DEEPDIVE.md)
**Purpose:** Master the most beginner-friendly high-impact vulnerability
**Topics:**
- IDOR fundamentals and identification
- Numeric ID manipulation
- UUID/GUID enumeration techniques
- Hashed/encoded ID attacks
- Body parameter IDOR
- Advanced chaining techniques

**Best For:** Your first serious vulnerability to master
**Time Investment:** 2-3 days to master
**Prerequisites:** Basic web testing knowledge

**Success Rate:** High (appears in 60%+ of applications)
**Typical Severity:** Medium to High

**Workflow:**
1. Complete reconnaissance
2. Map all object references (user IDs, document IDs, etc.)
3. Test access controls systematically
4. Chain with other vulnerabilities for critical impact

---

#### [SSRF (Server-Side Request Forgery)](./methodology/SSRF_DEEPDIVE.md)
**Purpose:** Find and exploit server-side request vulnerabilities
**Topics:**
- SSRF fundamentals and attack surface
- Internal service discovery
- Cloud metadata exploitation (AWS, GCP, Azure)
- Bypass techniques for filters
- Blind SSRF detection
- SSRF to RCE chains

**Best For:** Intermediate to advanced hunters
**Time Investment:** 1-2 weeks to master
**Prerequisites:** Networking knowledge, web testing

**Success Rate:** Medium (requires specific functionality)
**Typical Severity:** High to Critical

**Workflow:**
1. Identify URL input points
2. Test for internal network access
3. Enumerate cloud metadata endpoints
4. Chain with other vulnerabilities
5. Demonstrate business impact

---

### **Strategy Layer**

#### [2025 Master Strategy](./methodology/2025_MASTER_STRATEGY.md)
**Purpose:** Complete methodology integrating all techniques
**Topics:**
- Modern hunter's mindset
- Phase 1: Deep Recon (Asset Mapping)
- Phase 2: Systematic Scanning
- Phase 3: Manual Exploitation
- Phase 4: Chain Discovery
- Automation vs manual balance
- Time management and prioritization

**Best For:** Developing your personal hunting methodology
**Time Investment:** Reference document for every hunt
**Prerequisites:** Familiarity with core techniques

**Philosophy:**
> "Automation finds the obvious. Your job is to find what others miss."

**Workflow Integration:**
1. Deep recon → Asset mapping
2. Automated scanning → Low-hanging fruit
3. Manual testing → Unique vulnerabilities
4. Chaining → Critical findings

---

### **Tools & Automation**

#### [Tools Reference](./methodology/TOOLS.md)
**Purpose:** Master the hunter's toolkit
**Topics:**
- Reconnaissance tools (subfinder, amass, httpx)
- Scanning tools (nuclei, ffuf, nikto)
- Exploitation frameworks (Burp Suite, SQLmap)
- Helper tools (waybackurls, gau, arjun)
- Custom automation scripts
- Tool chaining techniques

**Best For:** Building efficient hunting workflows
**Time Investment:** Ongoing (learn tools as needed)
**Prerequisites:** Command line proficiency

**Organization:**
- By phase: Recon → Scan → Exploit → Report
- By target: Web → API → Mobile → Cloud
- By skill level: Beginner → Intermediate → Advanced

---

## 🎯 Learning Paths by Goal

### Path 1: First Bug in 30 Days
```
Week 1: Quick Start Guide + Learning Foundation
Week 2: Reconnaissance + Web Testing fundamentals
Week 3: IDOR Deep Dive (complete mastery)
Week 4: Test 5-10 programs, submit first reports
```

**Expected Outcome:** 1-3 valid findings
**Focus:** Quality over quantity, build confidence

---

### Path 2: Consistent Income (3-6 Months)
```
Month 1: Master Foundation + IDOR + Basic XSS
Month 2: API Testing + SSRF basics
Month 3: Authentication & Authorization in depth
Month 4: Business logic flaws + chaining
Month 5: SQL Injection + advanced techniques
Month 6: Specialize in your strength area
```

**Expected Outcome:** 10-20 valid bugs, 5-10 paid bounties
**Focus:** Develop 2-3 signature techniques

---

### Path 3: Advanced Hunter (6-12 Months)
```
Foundation: Complete all core methodologies
Specialization: Master 2025 Master Strategy
Advanced: SSRF chains, deserialization, RCE
Automation: Custom tools for unique attack surface
Research: Discover new vulnerability classes
```

**Expected Outcome:** Critical findings, high bounties, recognition
**Focus:** Innovation and depth over breadth

---

## 🔄 Cross-Reference Matrix

| If Testing... | Start With... | Then Reference... | Tools Needed... |
|---------------|---------------|-------------------|-----------------|
| **New Target** | Reconnaissance | 2025 Master Strategy | subfinder, httpx |
| **Web App** | Web Testing | IDOR, SSRF Deep Dives | Burp Suite |
| **REST API** | API Testing | IDOR Deep Dive | Postman, Arjun |
| **GraphQL** | API Testing | Injection techniques | GraphQL tools |
| **Auth System** | Web Testing | IDOR, session attacks | Burp, JWT tools |
| **File Upload** | Web Testing | SSRF, RCE research | Burp, file tools |
| **URL Parameters** | SSRF Deep Dive | Web Testing | Burp Collaborator |

---

## 📊 Vulnerability Priority Matrix

### High Success Rate + High Impact = Start Here
1. **IDOR** - 60% occurrence rate, Medium-High severity
2. **Authentication Bypass** - 40% occurrence, High severity
3. **Authorization Flaws** - 50% occurrence, Medium-High severity

### Medium Success Rate + Critical Impact = Worth Deep Diving
1. **SSRF** - 20% occurrence, High-Critical severity
2. **SQL Injection** - 15% occurrence, Critical severity
3. **XXE** - 10% occurrence, High severity

### Lower Success Rate + Requires Chaining = Advanced
1. **Deserialization** - 5% occurrence, Critical severity
2. **RCE** - 3% occurrence, Critical severity
3. **Blind vulnerabilities** - Variable, requires creativity

---

## 🛠️ Platform-Specific Guides

### Report Templates by Platform
- [Intigriti Template](./templates/INTIGRITI_TEMPLATE.md)
- [HackerOne Template](./templates/HACKERONE_TEMPLATE.md)
- [Bugcrowd Template](./templates/BUGCROWD_TEMPLATE.md)
- [Generic Template](./templates/GENERIC_TEMPLATE.md)

### Submission Tracking
- [Submission Tracker](./SUBMISSION_TRACKER.md)
- Update after every submission
- Track metrics for continuous improvement

---

## 📈 Continuous Improvement Framework

### After Each Hunt (Win or Lose)

**What Worked:**
- Which methodology phase found the bug?
- Which tools were most effective?
- What unique approach did you try?

**What Didn't Work:**
- Which techniques yielded no results?
- Where did you waste time?
- What assumptions were wrong?

**What to Learn:**
- Which methodology doc to re-read?
- Which tools to learn better?
- Which vulnerability type to study?

**Process:**
1. Log findings in hunt notes
2. Update personal methodology
3. Adjust tool workflow
4. Plan next hunt improvements

---

## 🎓 Study Schedule (Self-Paced)

### Daily (30-60 minutes)
- Read one methodology section
- Complete one PortSwigger lab
- Review one disclosed report

### Weekly (10-20 hours)
- Test 2-3 programs actively
- Deep dive one vulnerability type
- Update your notes and findings

### Monthly Review
- Assess what you've learned
- Update your success rate
- Adjust focus areas
- Set new goals

---

## 🔗 Document Relationships

```
QUICK_START.md
    ├── Links to: LEARNING_FOUNDATION.md
    ├── References: RECONNAISSANCE.md
    └── Uses: Templates (for first report)

LEARNING_FOUNDATION.md
    ├── Prerequisite for: All testing methodologies
    └── Informs: TOOLS.md

2025_MASTER_STRATEGY.md
    ├── Integrates: All core methodologies
    ├── References: RECONNAISSANCE.md, WEB_TESTING.md, API_TESTING.md
    └── Applies: IDOR_DEEPDIVE.md, SSRF_DEEPDIVE.md

RECONNAISSANCE.md
    ├── First step of: All hunts
    ├── Feeds into: WEB_TESTING.md, API_TESTING.md
    └── Uses: TOOLS.md

WEB_TESTING.md
    ├── Requires: RECONNAISSANCE.md
    ├── Deep dives: IDOR_DEEPDIVE.md, SSRF_DEEPDIVE.md
    └── Tools: TOOLS.md

API_TESTING.md
    ├── Requires: RECONNAISSANCE.md
    ├── Shares techniques: IDOR_DEEPDIVE.md
    └── Tools: TOOLS.md (API-specific)

IDOR_DEEPDIVE.md
    ├── Applied in: WEB_TESTING.md, API_TESTING.md
    └── Beginner-friendly entry point

SSRF_DEEPDIVE.md
    ├── Applied in: WEB_TESTING.md, API_TESTING.md
    └── Intermediate to advanced

TOOLS.md
    ├── Referenced by: All testing methodologies
    └── Organized by: Phase and target type
```

---

## 💡 Quick Navigation

**I want to...**

- **Start from zero** → [Quick Start](./QUICK_START.md)
- **Understand fundamentals** → [Learning Foundation](./methodology/LEARNING_FOUNDATION.md)
- **Find my first bug** → [IDOR Deep Dive](./methodology/IDOR_DEEPDIVE.md)
- **Test a web app** → [Web Testing](./methodology/WEB_TESTING.md)
- **Test an API** → [API Testing](./methodology/API_TESTING.md)
- **Map a target** → [Reconnaissance](./methodology/RECONNAISSANCE.md)
- **Develop my strategy** → [2025 Master Strategy](./methodology/2025_MASTER_STRATEGY.md)
- **Learn tools** → [Tools Reference](./methodology/TOOLS.md)
- **Write a report** → [Templates](./templates/)
- **Track submissions** → [Submission Tracker](./SUBMISSION_TRACKER.md)

---

## 📝 Contributing to Your Methodology

As you hunt, add to this knowledge base:

### New Vulnerability Deep Dive Template
```markdown
methodology/
    └── [VULN_TYPE]_DEEPDIVE.md
        ├── Fundamentals
        ├── Attack Surface Identification
        ├── Testing Methodology
        ├── Bypass Techniques
        ├── Chaining Opportunities
        └── Real-World Examples
```

### Hunt Report Template (Personal Notes)
```markdown
personal_notes/hunts/
    └── [PROGRAM]_[DATE].md
        ├── Target Information
        ├── Reconnaissance Findings
        ├── Testing Notes
        ├── Vulnerabilities Found
        ├── Lessons Learned
        └── Time Investment
```

---

## 🎯 Success Metrics

Track your progress against these methodologies:

| Metric | Beginner Goal | Intermediate Goal | Advanced Goal |
|--------|---------------|-------------------|---------------|
| **Methodologies Mastered** | 3-4 | 6-7 | All + Custom |
| **Valid Submissions** | 1-5 | 10-30 | 30+ |
| **Paid Bounties** | 1-3 | 5-15 | 15+ |
| **Average Severity** | Low-Medium | Medium-High | High-Critical |
| **Unique Techniques** | 0-1 | 2-3 | 5+ |

---

## 🚀 Next Steps

1. **Assess your current level** using the learning paths above
2. **Pick your starting methodology** based on goals
3. **Set up tracking** using SUBMISSION_TRACKER.md
4. **Start hunting** following the methodologies
5. **Update this index** with your own insights

---

**Remember:** These methodologies are living documents. Update them as you learn, discover new techniques, and develop your unique hunting style.

**Your bug bounty journey is a marathon, not a sprint. Master the fundamentals, develop your methodology, and the bugs will follow.**

---

*Last Updated: 2026-02-01*
*Repository: Peekabot/Couch.Potato*
*Branch: claude/organize-theories-242Pe*
