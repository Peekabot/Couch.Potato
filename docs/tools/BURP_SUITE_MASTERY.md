# 🔧 Burp Suite Mastery Guide

**The #1 essential tool for bug bounty hunting. Master this and you're 50% of the way there.**

---

## Why Burp Suite?

```
Burp Suite is your:
✅ Intercepting proxy (see/modify ALL traffic)
✅ Request repeater (test payloads 1000x)
✅ Scanner (find low-hanging fruit)
✅ Intruder (automated fuzzing)
✅ Decoder/Encoder (base64, URL, hex, etc.)
✅ Comparer (diff responses)
✅ Sequencer (test session tokens)

Bottom line: You NEED this tool.
```

**Community vs Professional:**
- **Community (FREE)**: Good for learning, missing key features
- **Professional ($449/year)**: Worth it if serious about bug bounty
  - Faster scanning (parallelization)
  - Collaborator (out-of-band testing for SSRF/XXE)
  - Active Scanner (automated vulnerability detection)
  - Extensions (unlimited)

**For beginners**: Start with Community, upgrade when you earn your first $1,000.

---

## Installation & Initial Setup

### 1. Download & Install

```bash
# Visit: https://portswigger.net/burp/communitydownload

# Linux installation:
chmod +x burpsuite_community_linux_*.sh
./burpsuite_community_linux_*.sh

# Or use package manager:
sudo apt install burpsuite  # Kali Linux
```

### 2. First Launch

```
1. Accept the terms
2. Choose "Temporary project" (or "New project" for Pro)
3. Click "Start Burp"
4. You'll see the dashboard
```

### 3. Configure Browser

**Firefox Setup (Recommended):**

```
1. Install FoxyProxy extension
   Firefox Add-ons → Search "FoxyProxy Standard"

2. Configure proxy:
   - Title: Burp Suite
   - Proxy Type: HTTP
   - Proxy IP: 127.0.0.1
   - Port: 8080

3. Enable proxy through FoxyProxy icon
```

**Chrome Setup:**

```
1. Install FoxyProxy extension from Chrome Web Store

2. Same configuration:
   - IP: 127.0.0.1
   - Port: 8080
```

### 4. Install CA Certificate

**Critical step - without this, HTTPS won't work!**

```
1. With proxy enabled, visit: http://burpsuite

2. Click "CA Certificate" (top-right)

3. Firefox:
   - Settings → Privacy & Security → Certificates
   - View Certificates → Import
   - Select downloaded certificate
   - Trust for identifying websites

4. Chrome/Linux:
   sudo cp ~/Downloads/cacert.der /usr/local/share/ca-certificates/burp.crt
   sudo update-ca-certificates

5. Test: Visit https://google.com
   - Should see traffic in Burp HTTP history
```

---

## Burp Suite Interface Tour

### Main Tabs

```
Dashboard      → Overview, tasks, event log
Target         → Site map, scope definition
Proxy          → Intercept and modify requests
Intruder       → Automated attacks (fuzzing)
Repeater       → Manual request modification
Decoder        → Encode/decode data
Comparer       → Compare requests/responses
Sequencer      → Analyze randomness (Pro)
Extensions     → Add functionality
```

---

## Feature 1: Proxy & Intercept

**The foundation of everything.**

### Basic Interception

**1. Enable Intercept**
```
Proxy tab → Intercept → Intercept is on (button should be orange)
```

**2. Make a Request**
```
In browser: Visit http://testphp.vulnweb.com/login.php
In Burp: Request is caught, waiting for action
```

**3. Read the Request**
```http
POST /login.php HTTP/1.1
Host: testphp.vulnweb.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

username=admin&password=test123
```

**4. Modify the Request**
```http
# Change parameters:
username=admin' OR '1'='1&password=anything

# Add headers:
X-Forwarded-For: 127.0.0.1

# Change method:
GET /login.php?username=admin&password=test HTTP/1.1
```

**5. Forward or Drop**
```
Forward → Send modified request
Drop → Discard request
```

### HTTP History

**View all requests:**
```
Proxy → HTTP history

Columns show:
- # (request number)
- Host
- Method
- URL
- Params (?)
- Status
- Length
- MIME type
```

**Filter useful requests:**
```
Right-click on request → Add to scope
Filter bar → Show only in-scope items
```

### WebSocket History

**For real-time applications:**
```
Proxy → WebSockets history

Shows:
- WebSocket connections
- Messages sent/received
- Can intercept and modify messages
```

---

## Feature 2: Repeater (Your Best Friend)

**Modify and resend requests infinitely. This is where you'll spend 80% of your time.**

### Basic Usage

**1. Send to Repeater**
```
HTTP history → Right-click request → Send to Repeater
(Or: Ctrl+R)
```

**2. Modify & Send**
```
Left panel: Edit the request
Click "Send"
Right panel: See the response
```

**3. Organize Tabs**
```
Right-click tab → Rename tab
Example: "Login - SQLi Test"
Example: "Profile - IDOR Test"
```

### Practical Example: Testing for IDOR

**Original Request:**
```http
GET /api/user/profile?user_id=123 HTTP/1.1
Host: target.com
Cookie: session=abc123

Response:
{"id": 123, "name": "Your Name", "email": "you@example.com"}
```

**Test in Repeater:**
```http
# Test 1: Change user_id to 124
GET /api/user/profile?user_id=124 HTTP/1.1

Send → Check if you see someone else's profile

# Test 2: Try user_id=1 (potential admin)
GET /api/user/profile?user_id=1 HTTP/1.1

Send → Check response

# Test 3: Try negative ID
GET /api/user/profile?user_id=-1 HTTP/1.1

# Test 4: Try very large ID
GET /api/user/profile?user_id=999999999 HTTP/1.1

# Test 5: Array manipulation
GET /api/user/profile?user_id[]=123&user_id[]=124 HTTP/1.1
```

### Practical Example: Testing for SQLi

**Original Login Request:**
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=test123
```

**Test payloads in Repeater:**
```http
# Test 1: Basic SQLi
username=admin'&password=test

# Test 2: OR injection
username=admin' OR '1'='1&password=anything

# Test 3: Comment out
username=admin'--&password=anything

# Test 4: UNION injection
username=admin' UNION SELECT NULL--&password=test

# Watch responses for:
# - SQL error messages
# - Different response lengths
# - Successful login
# - Different response times
```

### Repeater Tips

**Compare Responses:**
```
1. Send request → Note response
2. Modify request → Send again
3. Right-click in response → Request/Response → Compare
4. See differences highlighted
```

**Response Rendering:**
```
Response tabs:
- Raw: See actual HTTP response
- Render: See how browser would display it
- Hex: Binary data
```

**Keyboard Shortcuts:**
```
Ctrl+R    → Send to Repeater
Ctrl+I    → Send to Intruder
Ctrl+Space → Send request
Ctrl+U    → URL encode selection
Ctrl+Shift+U → URL decode selection
```

---

## Feature 3: Intruder (Automated Fuzzing)

**Automate testing with wordlists.**

### Attack Types

**1. Sniper** (One payload position at a time)
```
Best for: Testing single parameter with multiple values

Example:
GET /user?id=§123§

Payloads: 1, 2, 3, 4, 5
Results in:
- GET /user?id=1
- GET /user?id=2
- GET /user?id=3
...
```

**2. Battering Ram** (Same payload in all positions)
```
Best for: Username = password scenarios

Example:
username=§admin§&password=§admin§

Payloads: admin, user, test
Results in:
- username=admin&password=admin
- username=user&password=user
- username=test&password=test
```

**3. Pitchfork** (Multiple payloads, parallel)
```
Best for: Credential stuffing with username:password pairs

Example:
username=§admin§&password=§pass123§

Payload Set 1: admin, user, test
Payload Set 2: pass123, password, 12345

Results in:
- username=admin&password=pass123
- username=user&password=password
- username=test&password=12345
```

**4. Cluster Bomb** (All combinations)
```
Best for: Brute force with all combinations

Example:
username=§admin§&password=§pass§

Payload Set 1: admin, user
Payload Set 2: 123, 456

Results in:
- username=admin&password=123
- username=admin&password=456
- username=user&password=123
- username=user&password=456
```

### Practical Example: IDOR Enumeration

**Setup:**
```
1. Send request to Intruder (Ctrl+I)
2. Clear all positions (Clear § button)
3. Highlight the ID parameter
4. Click "Add §" button
```

**Request:**
```http
GET /api/user/profile?user_id=§123§ HTTP/1.1
Host: target.com
Cookie: session=your_token
```

**Configure Payload:**
```
Payloads tab:
- Payload type: Numbers
- From: 1
- To: 1000
- Step: 1

Start attack
```

**Analyze Results:**
```
Sort by:
- Status code (look for 200 vs 403)
- Length (different lengths = different users)

Flag interesting:
- Right-click → Add comment
- Mark rows with different responses
```

### Practical Example: Directory Fuzzing

**Request:**
```http
GET /§admin§ HTTP/1.1
Host: target.com
```

**Payload:**
```
Payloads tab:
- Payload type: Simple list
- Load: /usr/share/seclists/Discovery/Web-Content/common.txt

OR paste:
admin
login
dashboard
api
backup
config
.git
.env
```

**Grep - Match:**
```
Options tab → Grep - Match → Add

Add phrases to flag:
- "403 Forbidden"
- "200 OK"
- "admin"
- "login"
```

**Start attack and review results**

---

## Feature 4: Decoder & Comparer

### Decoder

**Quickly encode/decode data**

**Common Uses:**
```
Base64 encode: Encode payloads
Base64 decode: Decode tokens/cookies
URL encode: Prepare for URL parameters
URL decode: Read encoded data
HTML encode: XSS payload encoding
Hex: Binary data analysis
```

**Example: Decode JWT Token**
```
1. Copy JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

2. Decoder tab → Paste in top text area

3. Decode as: Base64
   First part: {"alg":"HS256","typ":"JWT"}

4. Decode second part (payload):
   {"sub":"1234567890","name":"John Doe","iat":1516239022}
```

**Smart Decode:**
```
Paste encoded text
Click "Smart decode"
Burp tries all encodings automatically
```

### Comparer

**Find differences between requests/responses**

**Use Cases:**
```
1. Compare successful vs failed login
2. Compare regular user vs admin response
3. Compare before/after parameter tampering
4. Compare different error messages
```

**Example: Find IDOR**
```
1. Request User 123's profile → Copy response
2. Request User 124's profile → Copy response
3. Comparer → Paste both responses
4. Click "Compare"
5. Different data highlighted = IDOR confirmed!
```

---

## Feature 5: Target Scope

**Focus on what matters, ignore noise.**

### Define Scope

**Method 1: Manual**
```
Target tab → Scope → Add

Protocol: https
Host: target.com
File: ^/api/.*
```

**Method 2: From Proxy History**
```
HTTP history → Right-click target → Add to scope
```

### Filter by Scope

**Proxy History:**
```
Filter bar → Show only in-scope items
```

**Site Map:**
```
Target → Site map
Shows hierarchical view of in-scope targets
```

### Exclude from Scope

**Ignore noisy domains:**
```
Target → Scope → Exclude from scope

Add:
- google-analytics.com
- facebook.com
- doubleclick.net
- All third-party tracking
```

---

## Feature 6: Extensions (BApp Store)

**Supercharge Burp with community extensions**

### Essential Extensions

**1. Autorize** (Authorization Testing)
```
Extender → BApp Store → Search "Autorize" → Install

Use case: Test if User A can access User B's resources
Setup:
1. Configure User A's session
2. Browse as User A
3. Switch to User B's session
4. Autorize auto-replays requests with User B's session
5. Flags authorization failures
```

**2. Logger++** (Advanced Logging)
```
Better than HTTP history
Columns: Regex extraction, custom filters
Export to CSV for analysis
```

**3. Param Miner** (Find Hidden Parameters)
```
Discovers:
- Hidden parameters
- Cache poisoning
- Header injection points

Right-click request → Extensions → Param Miner → Guess params
```

**4. Turbo Intruder** (Fast Attacks)
```
Python-based Intruder replacement
Much faster than built-in Intruder
Used for race conditions
```

**5. HTTP Request Smuggler**
```
Detect HTTP request smuggling
Automated testing
Critical vulnerability finder
```

**6. JS Link Finder**
```
Extract endpoints from JavaScript
Passive scanner integration
Finds hidden APIs
```

**7. Retire.js** (Vulnerable JS Libraries)
```
Identifies outdated JavaScript libraries
Shows known CVEs
Quick wins for reports
```

---

## Burp Suite Workflows

### Workflow 1: First-Time Testing a Target

```
1. Define Scope
   Target → Scope → Add target.com

2. Browse Normally
   - Login
   - Use all features
   - Click everything

3. Review Site Map
   Target → Site map
   See all discovered endpoints

4. Review Interesting Requests
   Proxy → HTTP history
   Filter: Scope only
   Look for:
   - API endpoints (/api/*)
   - Parameters (?id=, ?user=)
   - Admin paths (/admin, /dashboard)

5. Send Interesting Requests to Repeater
   Right-click → Send to Repeater

6. Manual Testing
   Use Repeater to test each finding
```

### Workflow 2: Testing for IDOR

```
1. Find Request with ID Parameter
   Example: GET /api/user/123

2. Send to Repeater (Ctrl+R)

3. Test Different IDs
   - Your ID → 200 OK (baseline)
   - Other ID (124) → Should be 403, but is it?
   - Admin ID (1) → Can you access admin?

4. If IDOR Found:
   - Send to Intruder
   - Enumerate all users (1-10000)
   - Document in notes
   - Screenshot for report

5. Test Bypass Techniques
   - Change HTTP method (GET → POST)
   - Add parameter (admin=true)
   - Array injection ([id]=123)
```

### Workflow 3: Testing for XSS

```
1. Find Input Fields
   Search, comments, profile fields

2. Send to Repeater

3. Test Payloads
   <script>alert(1)</script>
   <img src=x onerror=alert(1)>
   <svg onload=alert(1)>

4. Check Response
   Render tab → Does alert fire?
   Raw tab → Is input reflected?

5. If Filtered, Try Bypass
   <ScRiPt>alert(1)</sCriPt>
   <img src=x onerror="alert(1)">
   <svg/onload=alert(1)>

6. Document Working Payload
```

### Workflow 4: Testing API with Intruder

```
1. Capture API Request
   POST /api/user/create

2. Send to Intruder (Ctrl+I)

3. Set Payload Positions
   Mark parameters to fuzz

4. Load Wordlist or Generate
   Payload type: Numbers or Simple list

5. Configure Options
   Grep - Match: "error", "success", "created"

6. Start Attack

7. Analyze Results
   Sort by status code, length
   Find anomalies
```

---

## Pro Tips & Shortcuts

### Keyboard Shortcuts

```
Ctrl+R        → Send to Repeater
Ctrl+I        → Send to Intruder
Ctrl+Shift+B  → Send to Comparer
Ctrl+E        → Send to Decoder
Ctrl+T        → New tab in Repeater
Ctrl+W        → Close tab
Ctrl+Space    → Send request (Repeater)
Ctrl+F        → Find in current view
Ctrl+U        → URL encode selection
Ctrl+Shift+U  → URL decode selection
```

### Search Everything

```
Ctrl+F in any tab

Search for:
- "password" → Find password fields
- "api" → Find API endpoints
- "admin" → Find admin functionality
- "token" → Find auth tokens
- ".js" → Find JavaScript files
```

### Match & Replace (Auto-Modify)

```
Proxy → Options → Match and Replace

Use cases:
1. Auto-add header to all requests:
   Type: Request header
   Match: ^Host.*
   Replace: Host: $0\r\nX-Forwarded-For: 127.0.0.1

2. Auto-change User-Agent:
   Type: Request header
   Match: ^User-Agent:.*
   Replace: User-Agent: CustomAgent/1.0

3. Remove security headers:
   Type: Response header
   Match: ^X-Frame-Options:.*
   Replace: [empty]
```

### Save State

```
Burp → Project → Save copy
Saves:
- Target scope
- HTTP history
- Repeater tabs
- Intruder configs

Load later to continue work
```

---

## Common Beginner Mistakes

### ❌ Mistake 1: Not Using Repeater Enough
```
Problem: Making changes in browser, hard to reproduce
Solution: Send to Repeater, test there, much faster
```

### ❌ Mistake 2: Forgetting to Turn Off Intercept
```
Problem: Browser hangs because Burp is intercepting
Solution: Always check "Intercept is off" when browsing normally
```

### ❌ Mistake 3: Not Defining Scope
```
Problem: HTTP history full of analytics, ads, noise
Solution: Define scope first, filter to scope only
```

### ❌ Mistake 4: Not Taking Notes
```
Problem: Forget what you tested, duplicate work
Solution: Right-click request → Add comment
         Use Repeater tab names
```

### ❌ Mistake 5: Using Intruder Too Slow
```
Problem: Community Edition throttles Intruder
Solution: Manual testing in Repeater faster
         Or upgrade to Professional
```

---

## Practice Exercises

### Exercise 1: Setup Challenge
```
1. Install Burp Suite
2. Configure Firefox with FoxyProxy
3. Install CA certificate
4. Visit https://google.com
5. Verify you see traffic in HTTP history
✅ Success: You see Google request in Burp
```

### Exercise 2: Intercept & Modify
```
Target: http://testphp.vulnweb.com/

1. Enable intercept
2. Submit login form
3. Intercept request
4. Change username to: admin' OR '1'='1
5. Forward request
6. Observe response

✅ Success: You modified a request
```

### Exercise 3: Repeater Practice
```
Target: http://testphp.vulnweb.com/artists.php?artist=1

1. Send to Repeater
2. Change artist=1 to artist=2
3. Send and compare responses
4. Try artist=999
5. Try artist=-1
6. Try artist=1' OR '1'='1

✅ Success: You tested 5+ payloads in Repeater
```

### Exercise 4: Intruder Fuzzing
```
Target: http://testphp.vulnweb.com/artists.php?artist=§1§

1. Send to Intruder
2. Configure: Numbers 1-100
3. Start attack
4. Sort by Length
5. Find differences

✅ Success: You enumerated 100 artists
```

---

## Next Steps

**After mastering Burp Suite:**
1. ✅ Complete all practice exercises
2. ✅ Test on PortSwigger Academy labs with Burp
3. ✅ Use Burp on your first real target
4. ✅ Read: "The Burp Suite Handbook" (PortSwigger)
5. ✅ Consider upgrading to Professional

**Your Burp Mastery Checklist:**
- [ ] Can intercept and modify requests
- [ ] Comfortable using Repeater for testing
- [ ] Can configure and run Intruder attacks
- [ ] Understand Decoder for encoding/decoding
- [ ] Can define and filter by scope
- [ ] Installed 3+ useful extensions
- [ ] Know keyboard shortcuts
- [ ] Can save/load project state

---

**Burp Suite is 50% of bug bounty success. Master it and you're halfway to your first bounty! 🎯**
