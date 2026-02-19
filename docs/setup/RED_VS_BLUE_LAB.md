# 🧪 Red vs Blue Cybersecurity Lab Setup

**Practice bug bounty techniques safely on your own vulnerable applications before testing real targets.**

---

## Why You Need a Practice Lab

```
❌ DON'T: Learn by testing production systems
   - You might break something
   - You might get banned
   - You're learning on someone else's system

✅ DO: Practice on vulnerable apps locally
   - Break things safely
   - Learn at your own pace
   - Understand BOTH attack and defense
   - Build confidence before real targets
```

**Red Team (Attacker):** You find vulnerabilities
**Blue Team (Defender):** You understand how to fix them

**This dual perspective makes you a BETTER bug bounty hunter!**

---

## Lab Setup for Mac (Your Environment)

### Prerequisites

```bash
# Check you have these installed:
python3 --version   # Should be 3.8+
docker --version    # For containerized apps
brew --version      # Homebrew package manager

# If missing Docker:
brew install --cask docker
# Open Docker.app to start it
```

---

## Option 1: Docker-Based Lab (Recommended)

**Advantages:**
- Clean, isolated
- Easy to reset
- Multiple apps simultaneously
- No system pollution

### 1.1 DVWA (Damn Vulnerable Web Application)

**What it teaches:** SQL injection, XSS, CSRF, file upload, more

```bash
# Pull and run DVWA
docker run -d -p 80:80 vulnerables/web-dvwa

# Access at: http://localhost
# Default credentials: admin / password

# Setup:
# 1. Click "Create / Reset Database"
# 2. Login with admin/password
# 3. Set Security Level to "Low"
# 4. Start practicing!
```

**Practice with it:**
```bash
# Test SQL injection
http://localhost/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit

# Test XSS
http://localhost/vulnerabilities/xss_r/?name=<script>alert(1)</script>

# Use Burp Suite to intercept and modify!
```

### 1.2 WebGoat (OWASP Training App)

**What it teaches:** Complete OWASP Top 10 with guided lessons

```bash
# Run WebGoat
docker run -d -p 8080:8080 -p 9090:9090 webgoat/webgoat

# Access at: http://localhost:8080/WebGoat
# Register a new account
```

**Features:**
- Guided lessons for each vulnerability
- Hints when stuck
- Progress tracking
- Realistic scenarios

### 1.3 Juice Shop (Modern Vulnerable App)

**What it teaches:** Modern web app vulnerabilities, OWASP Top 10

```bash
# Run Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# Access at: http://localhost:3000
```

**Features:**
- Modern JavaScript/Angular app
- 100+ challenges
- Realistic e-commerce site
- API endpoints to test
- Score tracking

### 1.4 Mutillidae II

**What it teaches:** All major vulnerability types

```bash
# Run Mutillidae
docker run -d -p 8888:80 citizenstig/nowasp

# Access at: http://localhost:8888
```

**Features:**
- Extensive vulnerability coverage
- Hints system
- Video tutorials
- Both beginner and advanced

---

## Option 2: Python-Based Vulnerable Apps (For Your Python Setup)

### 2.1 Damn Small Vulnerable Web (Python/Flask)

**Create your own vulnerable app:**

```python
# vulnerable_app.py
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Vulnerable to SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # VULNERABLE: No parameterization
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        # This would execute: SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='anything'

        return f"Query: {query}"

    return '''
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password"><br>
            <input type="submit">
        </form>
    '''

# Vulnerable to XSS
@app.route('/search')
def search():
    query = request.args.get('q', '')

    # VULNERABLE: No escaping
    return render_template_string(f"<h1>Results for: {query}</h1>")
    # Test: http://localhost:5000/search?q=<script>alert(1)</script>

# Vulnerable to IDOR
users = {
    '1': {'name': 'Admin', 'email': 'admin@test.com', 'ssn': '123-45-6789'},
    '2': {'name': 'User', 'email': 'user@test.com', 'ssn': '987-65-4321'}
}

@app.route('/profile/<user_id>')
def profile(user_id):
    # VULNERABLE: No authorization check
    return users.get(user_id, 'User not found')
    # Test: Change user_id in URL

# Vulnerable to Path Traversal
@app.route('/file')
def get_file():
    filename = request.args.get('name', 'default.txt')

    # VULNERABLE: No sanitization
    with open(filename, 'r') as f:
        return f.read()
    # Test: ?name=../../etc/passwd

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

**Run it:**
```bash
pip install flask
python vulnerable_app.py

# Access at: http://localhost:5000
```

**Practice on it:**
```bash
# SQL Injection
curl -d "username=admin' OR '1'='1&password=anything" http://localhost:5000/login

# XSS
curl "http://localhost:5000/search?q=<script>alert(1)</script>"

# IDOR
curl http://localhost:5000/profile/1  # Your profile
curl http://localhost:5000/profile/2  # Other user's profile!

# Path Traversal
curl "http://localhost:5000/file?name=../../etc/passwd"
```

### 2.2 Build Your Own API

**Vulnerable REST API for practice:**

```python
# vulnerable_api.py
from flask import Flask, request, jsonify
import jwt
import datetime

app = Flask(__name__)
SECRET_KEY = "weak_secret"  # VULNERABLE: Weak secret

# Vulnerable JWT
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if username == 'admin' and password == 'admin':
        token = jwt.encode({
            'user': username,
            'role': 'user',  # Try changing to 'admin' in JWT
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, SECRET_KEY, algorithm='HS256')

        return jsonify({'token': token})

    return jsonify({'error': 'Invalid credentials'}), 401

# Vulnerable authorization
@app.route('/admin', methods=['GET'])
def admin():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

        # VULNERABLE: Trusts role in JWT
        if payload.get('role') == 'admin':
            return jsonify({'secret': 'FLAG{admin_access}'})

        return jsonify({'error': 'Not admin'}), 403
    except:
        return jsonify({'error': 'Invalid token'}), 401

# Vulnerable to SSRF
@app.route('/fetch', methods=['POST'])
def fetch_url():
    url = request.json.get('url')

    # VULNERABLE: No URL validation
    import requests
    response = requests.get(url)
    return jsonify({'content': response.text})
    # Test: {"url": "http://localhost:5000/admin"}

# Mass assignment vulnerability
users_db = {}

@app.route('/register', methods=['POST'])
def register():
    user_data = request.json

    # VULNERABLE: Accepts all fields
    user_id = len(users_db) + 1
    users_db[user_id] = user_data  # Try adding "role": "admin"

    return jsonify({'user_id': user_id, 'data': user_data})

if __name__ == '__main__':
    app.run(debug=True, port=5001)
```

**Test it:**
```bash
python vulnerable_api.py

# Get JWT token
curl -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Decode JWT at jwt.io
# Change "role": "user" to "role": "admin"
# Re-encode with same secret
# Access admin endpoint

# Test SSRF
curl -X POST http://localhost:5001/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:5001/admin"}'

# Test mass assignment
curl -X POST http://localhost:5001/register \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","role":"admin"}'
```

---

## Option 3: Complete Lab Environment (Docker Compose)

**All vulnerable apps at once:**

```yaml
# docker-compose.yml
version: '3'

services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "80:80"

  webgoat:
    image: webgoat/webgoat
    ports:
      - "8080:8080"
      - "9090:9090"

  juice-shop:
    image: bkimminich/juice-shop
    ports:
      - "3000:3000"

  mutillidae:
    image: citizenstig/nowasp
    ports:
      - "8888:80"
```

**Run all at once:**
```bash
docker-compose up -d

# Access:
# DVWA: http://localhost
# WebGoat: http://localhost:8080/WebGoat
# Juice Shop: http://localhost:3000
# Mutillidae: http://localhost:8888

# Stop all:
docker-compose down
```

---

## Practice Exercises for Your Lab

### Exercise 1: SQL Injection (DVWA)

```
Target: http://localhost/vulnerabilities/sqli/

1. Test basic injection:
   ID: 1' OR '1'='1

2. Extract database:
   ID: 1' UNION SELECT user, password FROM users--

3. Use Burp Repeater:
   - Intercept request
   - Send to Repeater
   - Test 10+ payloads
   - Document what works

✅ Success: Extract all user passwords
```

### Exercise 2: XSS (Juice Shop)

```
Target: http://localhost:3000

1. Find search functionality
2. Test reflected XSS:
   <script>alert(document.domain)</script>

3. Test stored XSS in comments:
   <img src=x onerror=alert(1)>

4. Use HackTools extension for payloads

✅ Success: Get XSS to execute in another "user's" browser
```

### Exercise 3: IDOR (Your Python App)

```
Target: http://localhost:5000/profile/1

1. Access your profile (user_id=1)
2. Use Burp Repeater
3. Change to user_id=2
4. Observe you see other user's data
5. Try user_id=0, -1, 999
6. Document all findings

✅ Success: Access all user profiles
```

### Exercise 4: JWT Tampering (Your API)

```
Target: http://localhost:5001

1. Login and get JWT
2. Decode at jwt.io
3. Change "role": "user" to "role": "admin"
4. Re-encode with secret "weak_secret"
5. Use modified JWT to access /admin

✅ Success: Access admin endpoint with forged JWT
```

### Exercise 5: Directory Fuzzing

```
Target: http://localhost (DVWA)

1. Use ffuf:
   ffuf -u http://localhost/FUZZ -w /path/to/wordlist.txt

2. Find hidden directories
3. Try common files:
   - config.php
   - backup.sql
   - .git

4. Document findings

✅ Success: Find 10+ hidden endpoints
```

---

## Blue Team Practice (Fixing Vulnerabilities)

**After finding each vulnerability, FIX IT:**

### Fix SQL Injection

```python
# BEFORE (Vulnerable)
query = f"SELECT * FROM users WHERE username='{username}'"

# AFTER (Secure)
import sqlite3
cursor.execute("SELECT * FROM users WHERE username=?", (username,))
```

### Fix XSS

```python
# BEFORE (Vulnerable)
return f"<h1>Results for: {query}</h1>"

# AFTER (Secure)
from flask import escape
return f"<h1>Results for: {escape(query)}</h1>"
```

### Fix IDOR

```python
# BEFORE (Vulnerable)
@app.route('/profile/<user_id>')
def profile(user_id):
    return users.get(user_id)

# AFTER (Secure)
from flask_login import current_user

@app.route('/profile/<user_id>')
def profile(user_id):
    if current_user.id != user_id:
        return "Unauthorized", 403
    return users.get(user_id)
```

### Fix JWT Tampering

```python
# BEFORE (Vulnerable)
SECRET_KEY = "weak_secret"

# AFTER (Secure)
import secrets
SECRET_KEY = secrets.token_hex(32)  # Strong random secret

# Also verify signature properly
payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'], verify=True)
```

---

## Lab Management

### Reset Lab When Needed

```bash
# Docker apps
docker stop $(docker ps -aq)
docker rm $(docker ps -aq)
docker-compose up -d

# Python apps
# Just restart the script
```

### Save Your Findings

```bash
# Create lab notes directory
mkdir -p lab-notes

# Document each finding
echo "SQL Injection in DVWA login" > lab-notes/sqli-dvwa.md
echo "Payload: 1' OR '1'='1" >> lab-notes/sqli-dvwa.md
```

### Progress Tracking

```markdown
# lab-progress.md

## Completed
- [x] SQL Injection basics (DVWA)
- [x] XSS reflected (Juice Shop)
- [x] IDOR enumeration (Custom app)

## In Progress
- [ ] JWT tampering (Custom API)
- [ ] SSRF exploitation (Custom API)

## To Do
- [ ] File upload bypass
- [ ] XXE injection
- [ ] CSRF attacks
```

---

## Recommended Learning Path

### Week 1: Setup & SQL Injection
```
Day 1: Set up Docker + DVWA
Day 2-3: SQL injection (all DVWA levels)
Day 4-5: SQL injection in WebGoat
Day 6-7: Build your own vulnerable SQL app
```

### Week 2: XSS
```
Day 8-9: Reflected XSS (DVWA)
Day 10-11: Stored XSS (Juice Shop)
Day 12-13: DOM XSS (Mutillidae)
Day 14: Build vulnerable XSS scenarios
```

### Week 3: Access Control
```
Day 15-16: IDOR (custom apps)
Day 17-18: Privilege escalation
Day 19-20: JWT tampering
Day 21: Mass assignment
```

### Week 4: Advanced
```
Day 22-23: SSRF
Day 24-25: XXE
Day 26-27: Deserialization
Day 28-30: Chaining vulnerabilities
```

---

## Safety Tips

### ✅ DO:
- Run labs locally only
- Practice on isolated network
- Document everything
- Learn to fix, not just break
- Reset labs between sessions

### ❌ DON'T:
- Expose lab to internet
- Use production databases
- Test techniques on real sites
- Share credentials from labs
- Assume lab = production

---

## Next Steps

**After mastering your lab:**

1. ✅ Completed 50+ challenges across platforms
2. ✅ Can exploit all OWASP Top 10
3. ✅ Understand how to fix each vulnerability
4. ✅ Confident with Burp Suite

**Then:**
- Apply same techniques to real bug bounty programs
- Start with beginner-friendly programs
- Use your lab to reproduce findings
- Build PoCs safely before reporting

---

**Your lab is your safe space to break things and learn. Use it! 🧪**
