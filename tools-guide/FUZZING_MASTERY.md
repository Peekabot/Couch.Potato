# 🔨 Fuzzing Mastery: ffuf & gobuster

**Directory brute-forcing and parameter discovery - find hidden endpoints that manual browsing misses.**

---

## What is Fuzzing?

**Fuzzing** = Automated testing with wordlists to find:
- Hidden directories (`/admin`, `/backup`)
- Files (`config.php`, `.git`, `.env`)
- Parameters (`?id=`, `?debug=`)
- Subdomains (`admin.target.com`)
- Virtual hosts

**Why fuzz?**
```
Manual browsing finds: 10% of endpoints
Fuzzing finds: 90% of hidden endpoints

Example:
- You see: /login, /dashboard, /profile
- Fuzzing finds: /admin, /api, /.git, /backup.sql
```

---

## Tool Comparison

| Feature | ffuf | gobuster | Preference |
|---------|------|----------|------------|
| Speed | ⚡⚡⚡⚡⚡ | ⚡⚡⚡⚡ | ffuf |
| Flexibility | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ffuf |
| Ease of use | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | gobuster |
| Filtering | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ffuf |
| Output | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ffuf |

**Recommendation: Learn both, prefer ffuf for power, gobuster for simplicity.**

---

## Part 1: ffuf (Fuzz Faster U Fool)

### Installation

```bash
# Go install
go install github.com/ffuf/ffuf@latest

# Or apt
sudo apt install ffuf

# Verify
ffuf -V
```

### Basic Directory Fuzzing

```bash
# Basic usage
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt

# FUZZ = placeholder for wordlist entries
# -u = URL
# -w = wordlist
```

**Example:**
```bash
ffuf -u https://testphp.vulnweb.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Output:
admin                   [Status: 301, Size: 234]
login                   [Status: 200, Size: 1532]
backup                  [Status: 403, Size: 276]
```

### File Fuzzing

```bash
# Fuzz for files with extensions
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.txt,.bak,.sql,.zip

# This tests:
# /admin
# /admin.php
# /admin.txt
# /admin.bak
# etc.
```

### Recursion

```bash
# Recursive fuzzing
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion

# Depth limit
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# Example:
# Finds /admin → then fuzzes /admin/FUZZ → finds /admin/users → fuzzes /admin/users/FUZZ
```

### Filtering Results

**By Status Code:**
```bash
# Match specific codes
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302

# Filter out codes
ffuf -u https://target.com/FUZZ -w wordlist.txt -fc 404,403
```

**By Response Size:**
```bash
# Filter by size (remove false positives)
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 1234

# Match specific size
ffuf -u https://target.com/FUZZ -w wordlist.txt -ms 5000

# Filter size range
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 1000-2000
```

**By Response Words:**
```bash
# Filter by word count
ffuf -u https://target.com/FUZZ -w wordlist.txt -fw 10

# Match word count
ffuf -u https://target.com/FUZZ -w wordlist.txt -mw 50
```

**By Response Lines:**
```bash
# Filter by line count
ffuf -u https://target.com/FUZZ -w wordlist.txt -fl 20
```

**By Regex:**
```bash
# Match regex in response
ffuf -u https://target.com/FUZZ -w wordlist.txt -mr "admin"

# Filter regex
ffuf -u https://target.com/FUZZ -w wordlist.txt -fr "404 Not Found"
```

### Multiple Fuzzing Positions

**Two positions:**
```bash
# Fuzz directory AND file
ffuf -u https://target.com/FUZZ1/FUZZ2 \
  -w dirs.txt:FUZZ1 \
  -w files.txt:FUZZ2

# Example requests:
# /admin/users
# /api/config
# /backup/database
```

**POST data fuzzing:**
```bash
# Fuzz POST parameters
ffuf -u https://target.com/login \
  -X POST \
  -d "username=FUZZ&password=admin" \
  -w usernames.txt

# Fuzz both username and password
ffuf -u https://target.com/login \
  -X POST \
  -d "username=FUZZUSER&password=FUZZPASS" \
  -w users.txt:FUZZUSER \
  -w passwords.txt:FUZZPASS \
  -mode clusterbomb
```

### Header Fuzzing

```bash
# Fuzz custom header
ffuf -u https://target.com/admin \
  -w wordlist.txt \
  -H "X-Forwarded-For: FUZZ"

# Fuzz Host header (virtual host discovery)
ffuf -u http://target.com \
  -w vhosts.txt \
  -H "Host: FUZZ.target.com"

# Multiple headers
ffuf -u https://target.com/api \
  -w tokens.txt \
  -H "Authorization: Bearer FUZZ"
```

### Parameter Discovery

```bash
# GET parameter fuzzing
ffuf -u "https://target.com/api?FUZZ=test" -w params.txt

# Common parameters to test
# id, user_id, page, search, query, debug, admin, key, token
```

### Subdomain Fuzzing

```bash
# Subdomain enumeration via ffuf
ffuf -u https://FUZZ.target.com -w subdomains.txt

# With Host header
ffuf -u http://target.com -w subdomains.txt -H "Host: FUZZ.target.com"
```

### Speed & Performance

```bash
# Threads (default 40)
ffuf -u https://target.com/FUZZ -w wordlist.txt -t 100

# Rate limit (requests per second)
ffuf -u https://target.com/FUZZ -w wordlist.txt -rate 50

# Timeout
ffuf -u https://target.com/FUZZ -w wordlist.txt -timeout 10
```

### Output Options

```bash
# Simple output
ffuf -u https://target.com/FUZZ -w wordlist.txt -o results.txt

# JSON output
ffuf -u https://target.com/FUZZ -w wordlist.txt -o results.json -of json

# CSV output
ffuf -u https://target.com/FUZZ -w wordlist.txt -o results.csv -of csv

# HTML report
ffuf -u https://target.com/FUZZ -w wordlist.txt -o report.html -of html

# Silent mode (only results)
ffuf -u https://target.com/FUZZ -w wordlist.txt -s
```

### Real-World Examples

**Example 1: Find Admin Panels**
```bash
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302,403 \
  -fc 404 \
  -o admin_scan.json

# Looking for:
# /admin, /administrator, /wp-admin, /phpmyadmin, /cpanel
```

**Example 2: Find Backup Files**
```bash
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .bak,.backup,.old,.sql,.zip,.tar.gz \
  -mc 200 \
  -o backups.txt

# Looking for:
# backup.zip, database.sql, config.php.bak
```

**Example 3: API Endpoint Discovery**
```bash
ffuf -u https://target.com/api/FUZZ \
  -w api-endpoints.txt \
  -mc 200,401,403 \
  -fc 404 \
  -H "Content-Type: application/json"

# Looking for:
# /api/users, /api/admin, /api/internal
```

**Example 4: Parameter Discovery**
```bash
# Find hidden parameters
ffuf -u "https://target.com/search?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 \
  -fs 1234  # Filter default size

# Looking for:
# ?debug=, ?admin=, ?id=, ?user=
```

**Example 5: Bypass 403 Forbidden**
```bash
# Try different paths to bypass
ffuf -u https://target.com/admin/FUZZ \
  -w bypass-403.txt \
  -mc 200

# bypass-403.txt contains:
# .
# ..
# %2e
# ..;/
# /./
```

### Advanced Filtering Strategy

**Auto-Calibration:**
```bash
# ffuf can auto-filter based on common response
ffuf -u https://target.com/FUZZ \
  -w huge_wordlist.txt \
  -ac  # Auto-calibrate (filters common false positives)
```

**Complex Filtering:**
```bash
# Combine multiple filters
ffuf -u https://target.com/FUZZ \
  -w wordlist.txt \
  -fc 404 \           # Filter 404s
  -fs 1234,5678 \     # Filter specific sizes
  -fw 10 \            # Filter 10 words
  -fr "Not Found"     # Filter "Not Found" in body
```

---

## Part 2: gobuster

**Simpler syntax, great for beginners.**

### Installation

```bash
sudo apt install gobuster
# OR
go install github.com/OJ/gobuster/v3@latest
```

### Directory Fuzzing

```bash
# Basic directory scan
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt

# With extensions
gobuster dir -u https://target.com -w wordlist.txt -x php,txt,html

# Show length
gobuster dir -u https://target.com -w wordlist.txt -l

# Specific status codes
gobuster dir -u https://target.com -w wordlist.txt -s "200,301,302"

# Exclude status codes
gobuster dir -u https://target.com -w wordlist.txt -b "404,403"
```

### DNS Subdomain Enumeration

```bash
# Subdomain fuzzing
gobuster dns -d target.com -w subdomains.txt

# Show IPs
gobuster dns -d target.com -w subdomains.txt -i

# Wildcard detection
gobuster dns -d target.com -w subdomains.txt -w wildcard
```

### Virtual Host Discovery

```bash
# Vhost enumeration
gobuster vhost -u https://target.com -w vhosts.txt

# Append domain
gobuster vhost -u https://target.com -w vhosts.txt --append-domain
```

### Speed & Threads

```bash
# Threads (default 10)
gobuster dir -u https://target.com -w wordlist.txt -t 50

# Timeout
gobuster dir -u https://target.com -w wordlist.txt --timeout 10s
```

### Output

```bash
# Save output
gobuster dir -u https://target.com -w wordlist.txt -o results.txt

# Quiet mode
gobuster dir -u https://target.com -w wordlist.txt -q

# No status output
gobuster dir -u https://target.com -w wordlist.txt -z
```

### Real-World Examples

**Example 1: Quick Directory Scan**
```bash
gobuster dir \
  -u https://target.com \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,html \
  -b 404 \
  -o gobuster_results.txt
```

**Example 2: Subdomain Discovery**
```bash
gobuster dns \
  -d target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -i \
  -o subdomains.txt
```

**Example 3: Virtual Host Discovery**
```bash
gobuster vhost \
  -u http://target.com \
  -w /usr/share/seclists/Discovery/DNS/namelist.txt \
  --append-domain
```

---

## Wordlists - Your Ammunition

### Essential Wordlists (SecLists)

```bash
# Install SecLists
sudo apt install seclists
# OR
git clone https://github.com/danielmiessler/SecLists.git
```

### Common Directories

```bash
# Small (quick scan)
/usr/share/seclists/Discovery/Web-Content/common.txt

# Medium (balanced)
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Large (comprehensive)
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
```

### Files

```bash
# Common files
/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt

# Backup files
/usr/share/seclists/Discovery/Web-Content/backup-files.txt
```

### Subdomains

```bash
# Top 1 million
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

# Small list
/usr/share/seclists/Discovery/DNS/namelist.txt
```

### Parameters

```bash
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```

### Custom Wordlist Creation

```bash
# Extract words from website
cewl https://target.com -d 2 -m 5 -w custom_wordlist.txt

# Combine multiple wordlists
cat wordlist1.txt wordlist2.txt | sort -u > combined.txt

# Add common prefixes/suffixes
# admin → admin, admin1, admin2, admin-old, admin-new
```

---

## Comparison: ffuf vs gobuster

**Use ffuf when:**
- Need advanced filtering
- Fuzzing POST data
- Fuzzing headers/parameters
- Want JSON/HTML output
- Need maximum speed

**Use gobuster when:**
- Learning fuzzing basics
- Simple directory scan needed
- DNS/vhost enumeration
- Prefer simpler syntax

**Real-World Usage:**
```
80% of hunters use ffuf
20% use gobuster
Best practice: Learn both, default to ffuf
```

---

## Practical Workflow

### Complete Fuzzing Workflow

```bash
#!/bin/bash
# comprehensive_fuzz.sh

TARGET=$1

echo "[+] Quick directory scan..."
ffuf -u https://$TARGET/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302,403 \
  -fc 404 \
  -o quick_dirs.json \
  -of json

echo "[+] Deep directory scan..."
ffuf -u https://$TARGET/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,403 \
  -fc 404 \
  -recursion \
  -recursion-depth 2 \
  -o deep_dirs.json \
  -of json

echo "[+] File discovery..."
ffuf -u https://$TARGET/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .php,.txt,.bak,.backup,.old,.sql,.zip \
  -mc 200 \
  -o files.json \
  -of json

echo "[+] Parameter discovery..."
ffuf -u "https://$TARGET/search?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 \
  -fs 1234 \
  -o params.json \
  -of json

echo "[+] Done! Check *_json files for results."
```

---

## Tips & Best Practices

### 1. Start Small, Go Big

```bash
# Start with small wordlist
ffuf -u https://target.com/FUZZ -w common.txt

# If nothing found, try medium
ffuf -u https://target.com/FUZZ -w medium.txt

# Last resort: big wordlist (may take hours)
ffuf -u https://target.com/FUZZ -w big.txt
```

### 2. Always Filter 404s

```bash
# Bad: See thousands of 404s
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Good: Filter them out
ffuf -u https://target.com/FUZZ -w wordlist.txt -fc 404
```

### 3. Use Auto-Calibration

```bash
# Let ffuf figure out false positives
ffuf -u https://target.com/FUZZ -w wordlist.txt -ac
```

### 4. Save Your Results

```bash
# JSON for programmatic parsing
ffuf -u https://target.com/FUZZ -w wordlist.txt -o results.json -of json

# Can grep JSON later
cat results.json | jq '.results[] | select(.status==200)'
```

### 5. Respect Rate Limits

```bash
# Don't DOS the target
ffuf -u https://target.com/FUZZ -w wordlist.txt -rate 50 -t 20
```

### 6. Combine with Other Tools

```bash
# Find directories, then scan with Nuclei
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200 -s | \
  awk '{print "https://target.com/"$1}' | \
  nuclei -severity high
```

---

## Common Pitfalls

### ❌ Pitfall 1: Not Filtering False Positives

```bash
# Problem: Everything returns 200 with same size
# Solution: Filter by size
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 1234
```

### ❌ Pitfall 2: Using Tiny Wordlists

```bash
# Bad: Only 100 words
ffuf -u https://target.com/FUZZ -w tiny.txt

# Good: At least medium wordlist
ffuf -u https://target.com/FUZZ -w raft-medium-directories.txt
```

### ❌ Pitfall 3: Ignoring 403 Forbidden

```bash
# Don't ignore 403s - they indicate something is there!
# Include them in results
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403
```

### ❌ Pitfall 4: Not Testing Extensions

```bash
# Don't just test /admin
# Also test /admin.php, /admin.html, /admin.asp
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.html,.asp
```

---

## Practice Exercises

### Exercise 1: Basic Directory Fuzzing

```bash
# Task: Find hidden directories on testphp.vulnweb.com
ffuf -u http://testphp.vulnweb.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -fc 404

✅ Success: You find /admin, /images, /categories
```

### Exercise 2: File Discovery

```bash
# Task: Find backup files
ffuf -u http://testphp.vulnweb.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e .bak,.backup,.old,.sql

✅ Success: You find config.php.bak or similar
```

### Exercise 3: Parameter Discovery

```bash
# Task: Find hidden parameters
ffuf -u "http://testphp.vulnweb.com/artists.php?FUZZ=1" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 \
  -ac

✅ Success: You discover working parameters
```

---

## Next Steps

**After mastering fuzzing:**
1. ✅ Complete all practice exercises
2. ✅ Fuzz your first real target
3. ✅ Build custom wordlists for specific targets
4. ✅ Combine fuzzing with other recon tools
5. ✅ Automate fuzzing in your recon pipeline

**Your Fuzzing Checklist:**
- [ ] Understand ffuf basic syntax
- [ ] Can filter by status/size/words
- [ ] Know how to fuzz POST data
- [ ] Can discover parameters
- [ ] Know when to use gobuster vs ffuf
- [ ] Have SecLists installed
- [ ] Can create custom wordlists

---

**Fuzzing reveals the 90% of the application that manual browsing misses. Master it! 🔨**
