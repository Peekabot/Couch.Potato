# 🚀 Quick Start - 5 Minutes to Testing

**From installation to finding vulnerabilities in 5 minutes.**

---

## What You're Getting

This repository gives you:
- ⚛️ **Substrate Boundary Analyzer** - Predicts bugs from API structure
- 🧪 **Practice Lab** - 7 vulnerabilities to learn on safely
- 🤖 **Automated Tester** - Confirms all 7 bugs automatically
- 📊 **Payload Generator** - Creates Burp Suite requests
- 📚 **Complete Methodology** - Theory to bounty payment

**Time to first vulnerability:** 5 minutes

---

## Step 1: Install (1 minute)

```bash
# Install Python dependencies
pip3 install requests colorama pyjwt pyperclip
```

---

## Step 2: Test Practice Lab (2 minutes)

```bash
# Terminal 1: Start the vulnerable web app
cd ~/Couch.Potato/lab-setup
python3 vulnerable-app.py

# Terminal 2: Run automated tester
cd ~/Couch.Potato/lab-setup
python3 test_all_vulnerabilities.py
```

**Expected output:**
```
[✓] VULNERABLE: SQL Injection successful!
[✓] VULNERABLE: IDOR successful!
[✓] VULNERABLE: XSS successful!
[✓] VULNERABLE: JWT Manipulation successful!
[✓] VULNERABLE: Path Traversal successful!
[✓] VULNERABLE: Price Manipulation successful!

Vulnerable: 7
Secured: 0
```

✅ **You now have a working practice environment with 7 bugs to learn on.**

---

## Step 3: Run Substrate Analyzer (1 minute)

```bash
cd ~/Couch.Potato/scripts

# Analyze the example API
python3 substrate_analyzer.py --openapi example-api-spec.json
```

**Expected output:**
```
[+] Substrate Boundary Analyzer
[+] Finding exploits through structural analysis

[*] Identified 9 irreversible operations
[*] Detected 27 boundary gaps
[!] 21 CRITICAL predictions - test immediately!
```

✅ **The analyzer found 21 CRITICAL vulnerabilities in 15 seconds.**

---

## Step 4: Generate Burp Payloads (1 minute)

```bash
# Generate test payloads
python3 burp_payload_generator.py substrate_analysis_report.txt --output payloads.txt

# View them
head -30 payloads.txt
```

**You'll see:**
```
POST /checkout HTTP/1.1
Host: api.target.com
Content-Type: application/json

{
  "total": 0.01
}
```

✅ **Ready-to-use HTTP requests for Burp Suite testing.**

---

## ✅ Setup Complete!

**You now have:**

1. ✅ Working practice lab (7 vulnerabilities)
2. ✅ Automated vulnerability tester
3. ✅ Substrate boundary analyzer
4. ✅ Burp payload generator

**Total time:** ~5 minutes

---

## What's Next?

### Beginner Path (Learn Fundamentals)

**Day 1-2: Practice Lab**
```bash
# Read the beginner guide
open methodology/SUBSTRATE_WORKFLOW.md  # Section: "Practice Lab for Complete Beginners"

# Install Burp Suite Community
# https://portswigger.net/burp/communitydownload

# Manually exploit each of the 7 bugs
# Learn how exploitation works
```

**Day 3-4: Understand Substrate Framework**
```bash
# Read the theory
open methodology/advanced/SUBSTRATE_BOUNDARY_ANALYSIS.md

# Key concept:
# "Exploits concentrate where irreversible state changes
#  separate from validation across trust boundaries"

# Run analyzer, understand predictions
python3 substrate_analyzer.py --openapi example-api-spec.json --verbose
```

**Day 5-7: First Real Target**
```bash
# Pick bug bounty program with public API
# Get their OpenAPI spec
# Run substrate analyzer
# Test top 3 CRITICAL predictions
# Submit first report
```

### Intermediate Path (Start Hunting)

**Week 1:**
```bash
# Analyze 5 real API specs
# Generate payloads for each
# Test CRITICAL predictions
# Submit 1-2 reports
```

**Week 2-4:**
```bash
# Scale to 10+ programs
# Build custom helpers
# Track success rate
# Refine workflow
```

---

## Common Issues

### "Can't connect to http://127.0.0.1:5000"

**Fix:** Start vulnerable-app.py first
```bash
cd lab-setup
python3 vulnerable-app.py
```

### "Module not found"

**Fix:** Install dependencies
```bash
pip3 install requests colorama pyjwt pyperclip
```

### "Permission denied"

**Fix:** Make scripts executable
```bash
chmod +x lab-setup/test_all_vulnerabilities.py
chmod +x scripts/*.py
```

---

## File Roadmap

```
~/Couch.Potato/
│
├── QUICK_START.md                ← This file (5-min setup)
├── QUICK_DEMO.md                 ← 5-min walkthrough
├── AUTOMATION_GUIDE.md           ← Full automation guide
│
├── lab-setup/                    ← Practice environment
│   ├── vulnerable-app.py         ← Intentional bugs
│   └── test_all_vulnerabilities.py  ← Automated tester
│
├── scripts/                      ← Core tools
│   ├── substrate_analyzer.py     ← Vulnerability predictor
│   ├── burp_payload_generator.py ← Payload generator
│   └── example-api-spec.json     ← Example with 21 bugs
│
├── methodology/                  ← Learning resources
│   ├── SUBSTRATE_WORKFLOW.md     ← Complete workflow
│   ├── 2025_MASTER_STRATEGY.md   ← Full methodology
│   └── advanced/
│       └── SUBSTRATE_BOUNDARY_ANALYSIS.md  ← Theory
│
└── templates/                    ← Report templates
    ├── INTIGRITI_TEMPLATE.md
    ├── HACKERONE_TEMPLATE.md
    └── BUGCROWD_TEMPLATE.md
```

---

## Your First Hour

**Minute 0-5: Setup**
```bash
pip3 install requests colorama pyjwt pyperclip
```

**Minute 5-15: Practice Lab**
```bash
cd lab-setup
python3 vulnerable-app.py &
python3 test_all_vulnerabilities.py
```

**Minute 15-30: Read Beginner Guide**
```
Open: methodology/SUBSTRATE_WORKFLOW.md
Section: "Practice Lab for Complete Beginners"
Learn: How each vulnerability works
```

**Minute 30-45: Manual Testing**
```
Install Burp Suite
Configure browser proxy
Manually exploit SQL injection
Compare with automated test
```

**Minute 45-55: Substrate Analysis**
```bash
cd scripts
python3 substrate_analyzer.py --openapi example-api-spec.json
python3 burp_payload_generator.py substrate_analysis_report.txt
```

**Minute 55-60: Plan Next Steps**
```
Pick first real target
Read 3 HackerOne reports
Set goals for week 1
```

---

## Success Checkpoints

**After 5 minutes:**
- ✅ All tools installed and working
- ✅ Practice lab running
- ✅ 7 vulnerabilities found automatically

**After 1 day:**
- ✅ Manually exploited 2-3 bugs in Burp
- ✅ Understand substrate framework basics
- ✅ Read 5-10 real bug reports

**After 1 week:**
- ✅ Exploited all 7 practice lab bugs
- ✅ Analyzed 3 real API specs
- ✅ Tested 10+ predictions manually
- ✅ Submitted first report

**After 1 month:**
- ✅ 5+ valid submissions
- ✅ First bounty payment
- ✅ Personal workflow established

---

## The Framework in 60 Seconds

**Traditional scanning:**
```
❌ Pattern matching (XSS signatures, SQLi patterns)
❌ Finds what everyone else finds
❌ High false positive rate
```

**Substrate boundary analysis:**
```
✅ Structural prediction
✅ Maps irreversible operations (charge, delete, grant)
✅ Finds validation gaps
✅ Calculates exploit potential (ΔS*)
✅ Predicts novel vulnerability classes
```

**Example:**

```python
# E-commerce checkout endpoint
POST /checkout
{
  "total": 99.99  # ← Client sets price
}

# Substrate analysis detects:
# 1. Irreversible operation: charge_customer()
# 2. Validation gap: Price from client, not recalculated
# 3. ΔS* calculation: Impact=10, Cost=0.5 → CRITICAL
# 4. Prediction: Price manipulation vulnerability
# 5. Test case: {"total": 0.01}
```

**Traditional scanner:** Might miss this (no XSS/SQLi signature)
**Substrate analyzer:** Predicts it from structure

**This is the difference.**

---

## Ready?

**Right now:**

```bash
cd ~/Couch.Potato/lab-setup
python3 vulnerable-app.py
```

**Then:**

```bash
# New terminal
cd ~/Couch.Potato/lab-setup
python3 test_all_vulnerabilities.py
```

**Watch it find 7 bugs in 10 seconds.**

Then learn to find them manually. Then use substrate analysis on real targets.

---

## Resources

- **Beginner Guide:** [methodology/SUBSTRATE_WORKFLOW.md](methodology/SUBSTRATE_WORKFLOW.md)
- **Full Theory:** [methodology/advanced/SUBSTRATE_BOUNDARY_ANALYSIS.md](methodology/advanced/SUBSTRATE_BOUNDARY_ANALYSIS.md)
- **Automation:** [AUTOMATION_GUIDE.md](AUTOMATION_GUIDE.md)
- **5-Min Demo:** [QUICK_DEMO.md](QUICK_DEMO.md)
- **Tools:** [tools-guide/README.md](tools-guide/README.md)
- **Complete Methodology:** [methodology/2025_MASTER_STRATEGY.md](methodology/2025_MASTER_STRATEGY.md)

---

**This is not pattern matching. This is structural prediction.** ⚛️

**Ship it.** 🚀
