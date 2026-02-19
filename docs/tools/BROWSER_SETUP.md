# 🌐 Professional Browser Setup for Bug Bounty

**Your browser is your primary interface to web applications. Set it up like a professional.**

---

## Why Browser Setup Matters

```
Amateur setup: Stock browser, no extensions, no proxy
Result: Miss 50% of vulnerabilities

Professional setup: Dedicated browser, essential extensions, always proxied
Result: See EVERYTHING, test efficiently
```

---

## Step 1: Choose Your Browser

### Firefox (Recommended for Bug Bounty)

**Pros:**
- ✅ Better privacy controls
- ✅ Easier proxy configuration
- ✅ Better extension support for security
- ✅ Native container tabs
- ✅ No Google tracking

**Cons:**
- ❌ Slightly slower than Chrome
- ❌ Some sites optimized for Chrome

### Chrome/Chromium

**Pros:**
- ✅ Faster performance
- ✅ Better DevTools
- ✅ Most sites optimized for it

**Cons:**
- ❌ Google tracking
- ❌ Less privacy-focused
- ❌ Proxy setup more complex

**Recommendation: Use both**
```
Primary: Firefox (for testing through Burp)
Secondary: Chrome (for sites that break in Firefox)
```

---

## Step 2: Create Dedicated Testing Profile

### Firefox Profile Setup

```bash
# Launch Firefox Profile Manager
firefox -P

# Create new profile:
# Name: "BugBounty"
# Directory: ~/.mozilla/firefox/bugbounty.profile

# Start Firefox with this profile
firefox -P BugBounty
```

**Why separate profile?**
```
Personal browsing: Cookies, sessions, history
Testing profile: Clean slate, only test accounts
```

### Chrome Profile Setup

```bash
# Create new profile through Chrome UI
# Settings → Manage profiles → Add profile

# Name: Bug Bounty
# Icon: Shield or lock
```

---

## Step 3: Essential Extensions

### 🔧 FoxyProxy Standard (Firefox) / Proxy SwitchyOmega (Chrome)

**Purpose:** Easy proxy switching

**Firefox Installation:**
```
1. Firefox Add-ons → Search "FoxyProxy Standard"
2. Add to Firefox
```

**Configuration:**
```
1. Click FoxyProxy icon
2. Options
3. Add New Proxy:
   Title: Burp Suite
   Type: HTTP
   Proxy IP: 127.0.0.1
   Port: 8080

4. Add pattern:
   Pattern: *
   Type: Wildcard
```

**Usage:**
```
FoxyProxy icon → Select "Burp Suite"
All traffic now goes through Burp
```

### 🔍 Wappalyzer

**Purpose:** Detect technologies on websites

**What it shows:**
- Web frameworks (React, Vue, Angular)
- Server software (nginx, Apache)
- CMS (WordPress, Drupal)
- Analytics (Google Analytics)
- Libraries (jQuery, Bootstrap)

**Why it matters:**
```
See WordPress → Run WPScan
See outdated jQuery → Check for known CVEs
See Apache 2.4.1 → Search for vulnerabilities
```

**Installation:**
```
Firefox/Chrome Add-ons → "Wappalyzer" → Install
```

**Usage:**
```
Visit any site → Click Wappalyzer icon
Shows all detected technologies
```

### 🍪 Cookie-Editor

**Purpose:** View/edit/delete cookies easily

**Use cases:**
- Test session fixation
- Modify session tokens
- Delete specific cookies
- Export cookies for tools

**Installation:**
```
Firefox/Chrome Add-ons → "Cookie-Editor" → Install
```

**Usage:**
```
Click cookie icon → See all cookies
Double-click to edit
Delete unwanted cookies
Export as JSON
```

### 🛠️ HackTools

**Purpose:** All-in-one hacker toolkit in browser

**Features:**
- XSS payloads
- SQL injection payloads
- Reverse shells
- Encode/decode
- Password generation
- Hash generator

**Installation:**
```
Chrome/Firefox → "HackTools" → Install
```

**Usage:**
```
Click extension icon
Select payload type
Copy → Paste → Test
```

### 🔐 BuiltWith

**Purpose:** Deep technology profiler (like Wappalyzer but more detailed)

**Shows:**
- E-commerce platform
- Payment processors
- CDN used
- Hosting provider
- Historical technology changes

**Installation:**
```
Chrome/Firefox → "BuiltWith" → Install
```

### 📋 Clear Cache

**Purpose:** Quick cache clearing for testing

**Why needed:**
```
Testing XSS? Clear cache.
Testing CSRF? Clear cache.
Getting weird results? Clear cache.
```

**Installation:**
```
Firefox/Chrome → "Clear Cache" → Install
```

### 🎨 User-Agent Switcher

**Purpose:** Change user agent string

**Use cases:**
- Test mobile vs desktop views
- Bypass user-agent filtering
- Test for different browser bugs

**Installation:**
```
Firefox/Chrome → "User-Agent Switcher" → Install
```

### 🚫 uBlock Origin

**Purpose:** Block ads/trackers (cleaner testing)

**Why for bug bounty:**
```
Blocks noise: Ads, analytics, tracking
Faster loading: Only target site loads
Cleaner traffic: Only test traffic in Burp
```

**Installation:**
```
Firefox/Chrome → "uBlock Origin" → Install
```

**Configuration for testing:**
```
Click icon → Dashboard → Filter lists
Enable: All ad/tracker lists
Disable on trusted test sites if needed
```

### 📖 JSONView / JSON Formatter

**Purpose:** Pretty-print JSON responses

**Why needed:**
```
Ugly: {"id":123,"name":"test","email":"test@example.com","ssn":"123-45-6789"}

Pretty:
{
  "id": 123,
  "name": "test",
  "email": "test@example.com",
  "ssn": "123-45-6789"  ← Easy to spot sensitive data!
}
```

**Installation:**
```
Firefox → "JSONView"
Chrome → "JSON Formatter"
```

---

## Step 4: Browser Settings Configuration

### Firefox Security Settings

```
Settings → Privacy & Security

✅ Enhanced Tracking Protection: Strict
✅ Send "Do Not Track": Always
✅ Delete cookies on close: OFF (for testing)
✅ HTTPS-Only Mode: Enable
❌ Firefox Data Collection: Disable all
```

### Disable WebRTC (Prevents IP Leaks)

**Firefox:**
```
1. Type in address bar: about:config
2. Accept warning
3. Search: media.peerconnection.enabled
4. Set to: false
```

**Chrome:**
```
Install: "WebRTC Leak Prevent" extension
```

**Test WebRTC leak:**
```
Visit: https://browserleaks.com/webrtc
Should NOT show your real IP if VPN is on
```

### Developer Tools Configuration

**Firefox DevTools:**
```
F12 → Settings (gear icon)

✅ Enable persistent logs
✅ Disable HTTP cache (when DevTools open)
✅ Show browser styles
✅ Enable custom formatters
```

**Chrome DevTools:**
```
F12 → Settings (gear icon)

✅ Disable cache (when DevTools open)
✅ Preserve log
✅ Show user agent shadow DOM
```

---

## Step 5: Import Burp CA Certificate

**Critical for HTTPS testing!**

### Firefox

```bash
1. Start Burp Suite
2. In Firefox (with proxy enabled):
   Visit: http://burpsuite
3. Click "CA Certificate" (top-right)
4. Save file: cacert.der

5. Firefox Settings → Privacy & Security → Certificates
6. View Certificates → Import
7. Select cacert.der
8. Check: "Trust this CA to identify websites"
9. OK

10. Test: Visit https://google.com
    Should see traffic in Burp HTTP history
```

### Chrome/Mac

```bash
# macOS
1. Download cacert.der from http://burpsuite
2. Open Keychain Access
3. File → Import Items
4. Select cacert.der
5. Double-click certificate
6. Trust → When using this certificate: Always Trust

# Or command line:
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Downloads/cacert.der
```

### Linux (Chrome/Chromium)

```bash
# Convert to .crt
openssl x509 -inform DER -in cacert.der -out burp.crt

# Copy to trusted certificates
sudo cp burp.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Restart Chrome
```

---

## Step 6: Container Tabs (Firefox Multi-Account Containers)

**Purpose:** Separate different sessions/accounts

**Installation:**
```
Firefox Add-ons → "Multi-Account Containers" → Install
```

**Use cases:**
```
Container 1: User Account
Container 2: Admin Account
Container 3: Test Account

Test IDOR: Switch between containers
Test privilege escalation: Different permissions
```

**Setup:**
```
1. Install extension
2. Create containers:
   - User (Blue)
   - Admin (Red)
   - Test (Green)

3. Right-click link → Open in container
4. Each container has separate cookies/sessions
```

---

## Step 7: Bookmarks for Quick Access

**Create bookmarklets for common tasks:**

### Base64 Decoder Bookmarklet

```javascript
javascript:(function(){var s=prompt('Enter Base64:');alert(atob(s));})();
```

### URL Decoder Bookmarklet

```javascript
javascript:(function(){var s=prompt('Enter URL:');alert(decodeURIComponent(s));})();
```

### View Cookies Bookmarklet

```javascript
javascript:alert(document.cookie);
```

### How to Add:
```
1. Create new bookmark
2. Name: "Base64 Decode"
3. URL: [paste javascript code]
4. Save to bookmarks toolbar
5. Click when needed
```

---

## Step 8: Keyboard Shortcuts

### Essential Firefox Shortcuts

```
Ctrl+Shift+K → Web Console
Ctrl+Shift+I → Inspector (DevTools)
Ctrl+Shift+E → Network Monitor
Ctrl+Shift+M → Responsive Design Mode (mobile view)
Ctrl+U → View Page Source
Ctrl+Shift+C → Element Picker
F12 → Toggle DevTools
```

### Essential Chrome Shortcuts

```
Ctrl+Shift+J → Console
Ctrl+Shift+I → DevTools
Ctrl+Shift+C → Element Inspector
Ctrl+U → View Source
Ctrl+Shift+M → Device Toolbar (mobile)
F12 → Toggle DevTools
```

### Custom Shortcuts

**Firefox:**
```
about:config → search "key"
Customize shortcuts via extensions
```

---

## Step 9: Browser Profile Checklist

**Your Bug Bounty browser should have:**

### Extensions Checklist
- [ ] FoxyProxy/SwitchyOmega (proxy)
- [ ] Wappalyzer (tech detection)
- [ ] Cookie-Editor (cookie manipulation)
- [ ] HackTools (payloads)
- [ ] uBlock Origin (ad blocking)
- [ ] JSONView/Formatter (JSON pretty-print)
- [ ] WebRTC Leak Prevent (privacy)
- [ ] User-Agent Switcher (spoofing)

### Settings Checklist
- [ ] Burp CA certificate installed
- [ ] Proxy configured (127.0.0.1:8080)
- [ ] WebRTC disabled
- [ ] HTTPS-Only mode enabled
- [ ] DevTools persistent logs enabled
- [ ] Separate testing profile created

### Optional Power User
- [ ] Container tabs (Firefox)
- [ ] Custom bookmarklets
- [ ] Keyboard shortcuts memorized
- [ ] Custom CSS for DevTools

---

## Step 10: Testing Your Setup

### Quick Test Checklist

**1. Proxy Test**
```
Enable FoxyProxy → Burp Suite
Visit: https://google.com
Check: Burp HTTP history shows request
✅ Pass: Request appears
❌ Fail: Check proxy settings
```

**2. HTTPS Test**
```
Visit: https://github.com
Check: No certificate warnings
✅ Pass: Site loads normally
❌ Fail: Reinstall Burp CA certificate
```

**3. Extension Test**
```
Visit: https://wordpress.com
Click: Wappalyzer icon
Check: Shows "WordPress" detected
✅ Pass: Extension working
```

**4. Cookie Test**
```
Visit any site
Click: Cookie-Editor icon
Check: Cookies displayed
✅ Pass: Can see and edit cookies
```

**5. WebRTC Leak Test**
```
Enable: VPN
Visit: https://browserleaks.com/webrtc
Check: Real IP not shown
✅ Pass: WebRTC disabled
❌ Fail: Disable WebRTC
```

---

## Common Issues & Fixes

### Issue: "Certificate not trusted"

**Fix:**
```
1. Re-download Burp CA cert
2. Delete old certificate from browser
3. Re-import new certificate
4. Restart browser
```

### Issue: "Proxy not working"

**Fix:**
```
1. Check Burp is running
2. Verify proxy settings: 127.0.0.1:8080
3. Check FoxyProxy is enabled
4. Restart browser
```

### Issue: "Extensions not working"

**Fix:**
```
1. Disable all extensions
2. Enable one by one
3. Find conflicting extension
4. Keep only essential ones
```

### Issue: "Slow browsing through proxy"

**Fix:**
```
1. Burp → Proxy → Options
2. Increase: Maximum concurrent requests
3. Or: Disable Burp intercept when not testing
```

---

## Advanced Setup (Optional)

### Browser Automation with Selenium (Python)

**For automated testing:**

```python
# macOS/Python setup
from selenium import webdriver
from selenium.webdriver.common.proxy import Proxy, ProxyType

# Configure proxy
proxy = Proxy()
proxy.proxy_type = ProxyType.MANUAL
proxy.http_proxy = "127.0.0.1:8080"
proxy.ssl_proxy = "127.0.0.1:8080"

# Setup Firefox with proxy
firefox_options = webdriver.FirefoxOptions()
firefox_options.proxy = proxy

driver = webdriver.Firefox(options=firefox_options)
driver.get("https://target.com")

# Now all traffic goes through Burp!
```

### Multiple Browser Profiles Script

```bash
#!/bin/bash
# launch-testing-browser.sh

# Firefox with Burp proxy
firefox -P BugBounty -no-remote &

# Chrome with proxy
google-chrome --profile-directory="BugBounty" \
  --proxy-server="127.0.0.1:8080" &
```

---

## Your Browser Setup Workflow

### Daily Startup Routine

```
1. Start Burp Suite
2. Start VPN (if using)
3. Launch Firefox (Bug Bounty profile)
4. Enable FoxyProxy → Burp Suite
5. Open target site
6. Start testing!
```

### When Switching Targets

```
1. Clear cache (Ctrl+Shift+Del)
2. Clear cookies (Cookie-Editor)
3. Clear Burp history (optional)
4. Start fresh session
```

### When Finishing Session

```
1. Save Burp project (if Pro)
2. Export cookies (if needed)
3. Screenshot findings
4. Disable FoxyProxy
5. Close browser
```

---

## Practice Exercise

### Complete Browser Setup Challenge

```
Task: Set up complete professional browser

1. [ ] Install Firefox
2. [ ] Create "BugBounty" profile
3. [ ] Install all 8 essential extensions
4. [ ] Configure proxy (127.0.0.1:8080)
5. [ ] Install Burp CA certificate
6. [ ] Disable WebRTC
7. [ ] Test setup on https://google.com
8. [ ] Verify in Burp HTTP history

✅ Success: You see Google request in Burp with no SSL errors
```

---

## Next Steps

**After browser setup:**
1. ✅ Complete setup challenge above
2. ✅ Test each extension on a live site
3. ✅ Practice switching proxy on/off
4. ✅ Learn keyboard shortcuts
5. ✅ Integrate with your workflow

---

**A professional browser setup is like a fighter's gloves - essential for the work ahead! 🥊**
