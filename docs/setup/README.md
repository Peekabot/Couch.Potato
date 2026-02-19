# 🧪 Lab Setup - Practice Environment

**Safe, local environment for practicing bug bounty techniques before testing real targets.**

---

## Quick Start (2 Minutes)

### Option 1: Run the Vulnerable Python App (Easiest)

```bash
# 1. Install Flask
pip3 install flask pyjwt

# 2. Run the app
python3 vulnerable-app.py

# 3. Open browser
open http://localhost:5000

# ✅ Done! Start practicing!
```

### Option 2: Docker-Based Labs (More Options)

```bash
# 1. Install Docker (if not installed)
brew install --cask docker

# 2. Start Docker app
open -a Docker

# 3. Run DVWA
docker run -d -p 80:80 vulnerables/web-dvwa

# 4. Access
open http://localhost

# Default credentials: admin / password
```

---

## What's in This Directory

```
lab-setup/
├── README.md                  # This file
├── RED_VS_BLUE_LAB.md        # Complete lab setup guide
├── vulnerable-app.py          # Ready-to-run vulnerable app
└── practice-exercises.md      # Hands-on exercises (coming)
```

---

## The Vulnerable Practice App

**What it includes:**

1. ✅ **SQL Injection** - Login bypass, database extraction
2. ✅ **XSS (Cross-Site Scripting)** - Reflected XSS in search
3. ✅ **IDOR** - Access other users' profiles
4. ✅ **Path Traversal** - Read arbitrary files
5. ✅ **Weak JWT** - Tamper with tokens
6. ✅ **SSRF** - Access internal endpoints
7. ✅ **File Upload** - Bypass validation

**Each vulnerability includes:**
- Description
- Example payloads
- Hints for testing
- Links back to methodology

---

## Practice Workflow

### 1. Start the App

```bash
python3 vulnerable-app.py
```

### 2. Open Burp Suite

```bash
# Start Burp
# Enable FoxyProxy in browser
# Browse to http://localhost:5000
```

### 3. Pick a Vulnerability

```
Start with: SQL Injection (easiest)
Then: IDOR (second easiest)
Then: XSS
Then: Advanced (SSRF, JWT, etc.)
```

### 4. Test It

```
1. Try the vulnerability manually
2. Intercept with Burp
3. Send to Repeater
4. Test 10+ payloads
5. Document what works
```

### 5. Understand the Fix

```
1. Look at the vulnerable code
2. Research the proper fix
3. Understand WHY it's vulnerable
4. Learn the secure pattern
```

---

## Example Practice Session

### SQL Injection Practice (30 minutes)

```bash
# 1. Start app
python3 vulnerable-app.py

# 2. Go to login page
http://localhost:5000/login

# 3. Try basic injection
Username: admin' OR '1'='1
Password: anything

# 4. Success! You bypassed login

# 5. Now use Burp Repeater
- Intercept the login request
- Send to Repeater
- Try these payloads:
  - admin'--
  - admin' OR '1'='1'--
  - ' UNION SELECT 1,2,3,4,5,6--

# 6. Document findings
- Which payloads worked?
- What data did you extract?
- How would you fix this?
```

---

## Recommended Learning Order

### Week 1: Basics
```
Day 1-2: SQL Injection
Day 3-4: IDOR
Day 5-6: XSS
Day 7: Review and document
```

### Week 2: Intermediate
```
Day 8-9: Path Traversal
Day 10-11: File Upload
Day 12-14: CSRF, weak sessions
```

### Week 3: Advanced
```
Day 15-16: JWT tampering
Day 17-18: SSRF
Day 19-21: Chaining vulnerabilities
```

---

## For Your Mac Environment

Since you're on Mac with Python:

```bash
# Everything works on Mac!

# 1. Python 3 (pre-installed on modern Macs)
python3 --version

# 2. Install Flask
pip3 install flask pyjwt

# 3. Run vulnerable app
python3 vulnerable-app.py

# 4. Docker (optional)
brew install --cask docker

# 5. Burp Suite (download)
# Works perfectly on Mac
https://portswigger.net/burp/communitydownload

# 6. Firefox with extensions
# All extensions work on Mac
```

---

## Safety Reminders

### ✅ SAFE:
- Running on localhost (127.0.0.1)
- Testing with Burp Suite
- Breaking the vulnerable app
- Learning and experimenting
- Documenting findings

### ❌ UNSAFE:
- Exposing to internet (0.0.0.0)
- Using in production
- Testing on real websites
- Sharing the app publicly
- Assuming this is secure code

---

## Troubleshooting

### "Module not found"

```bash
pip3 install flask pyjwt
# Or: python3 -m pip install flask pyjwt
```

### "Address already in use"

```bash
# Port 5000 is used
# Kill existing process:
lsof -ti:5000 | xargs kill -9

# Or change port in vulnerable-app.py:
app.run(debug=True, host='127.0.0.1', port=5001)
```

### "Permission denied"

```bash
# Make script executable
chmod +x vulnerable-app.py
```

### Docker issues

```bash
# Make sure Docker app is running
open -a Docker

# Wait for Docker to fully start
# Then try docker commands
```

---

## Next Steps

**After practicing on lab:**

1. ✅ Found all 7 vulnerabilities
2. ✅ Comfortable with Burp Suite
3. ✅ Understand how to fix each bug

**Then:**
- Review methodology guides
- Pick a real bug bounty program
- Apply same techniques (authorized!)
- Submit your first report

---

## Resources

**In this repository:**
- [Complete Lab Guide](./RED_VS_BLUE_LAB.md) - All lab options
- [Burp Suite Guide](../tools-guide/BURP_SUITE_MASTERY.md) - Tool mastery
- [IDOR Guide](../methodology/IDOR_DEEPDIVE.md) - Methodology
- [SSRF Guide](../methodology/SSRF_DEEPDIVE.md) - Advanced techniques

**External:**
- PortSwigger Academy - Free labs
- OWASP WebGoat - Guided lessons
- TryHackMe - Beginner-friendly

---

**Your lab is your safe space to learn. Break things! 🔨**
