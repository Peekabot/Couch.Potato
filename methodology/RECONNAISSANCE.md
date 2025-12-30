# 🔍 Reconnaissance Methodology

Comprehensive guide for reconnaissance phase of bug bounty hunting.

## Table of Contents
1. [Passive Reconnaissance](#passive-reconnaissance)
2. [Active Reconnaissance](#active-reconnaissance)
3. [Asset Discovery](#asset-discovery)
4. [Technology Identification](#technology-identification)
5. [Attack Surface Mapping](#attack-surface-mapping)

---

## Passive Reconnaissance

### 1. Program Scope Review
- [ ] Read program policy thoroughly
- [ ] Note in-scope assets
- [ ] Note out-of-scope assets
- [ ] Understand rules of engagement
- [ ] Check allowed testing methods
- [ ] Review reward table

### 2. OSINT (Open Source Intelligence)

#### Domain Information
```bash
# Whois lookup
whois target.com

# DNS records
dig target.com ANY
nslookup -type=any target.com

# Reverse IP lookup
# Use tools like ViewDNS.info or SecurityTrails
```

#### Subdomain Enumeration (Passive)
```bash
# Using online databases
# - crt.sh (Certificate Transparency)
# - VirusTotal
# - SecurityTrails
# - Shodan

# Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Amass (passive mode)
amass enum -passive -d target.com
```

#### Google Dorking
```
site:target.com
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:upload
site:target.com intext:"index of"
site:target.com ext:php
site:target.com ext:asp
```

#### GitHub/GitLab Reconnaissance
```bash
# Search for organization repos
# Look for:
# - API keys
# - Credentials
# - Internal URLs
# - Configuration files
# - Comments with TODOs
# - Deprecated endpoints

# GitHub dorking
"target.com" password
"target.com" api_key
"target.com" secret
"target.com" token
```

#### Social Media Intelligence
- [ ] LinkedIn (employees, tech stack)
- [ ] Twitter (announcements, tech mentions)
- [ ] Facebook
- [ ] Job postings (tech stack requirements)

#### Wayback Machine
```bash
# Check archived versions
# Tool: waybackurls
waybackurls target.com | tee wayback_urls.txt

# Look for:
# - Old endpoints
# - Removed features
# - Deprecated APIs
# - Parameter names
```

---

## Active Reconnaissance

### 1. Subdomain Enumeration (Active)

```bash
# Subfinder
subfinder -d target.com -o subdomains.txt

# Assetfinder
assetfinder --subs-only target.com

# Amass (active mode)
amass enum -active -d target.com -o amass_results.txt

# Sublist3r
sublist3r -d target.com -o sublist3r_results.txt

# Combine and deduplicate
cat *.txt | sort -u > all_subdomains.txt
```

### 2. Live Host Detection

```bash
# Check which hosts are alive
# httprobe
cat all_subdomains.txt | httprobe | tee live_hosts.txt

# httpx
cat all_subdomains.txt | httpx -o live_hosts.txt
```

### 3. Port Scanning

```bash
# Nmap (be careful - check program rules!)
nmap -sV -sC -oA nmap_scan target.com

# Masscan (faster but noisier)
masscan -p1-65535 --rate=1000 target.com

# Naabu
naabu -host target.com -o ports.txt
```

### 4. Web Screenshot Tool

```bash
# Aquatone
cat live_hosts.txt | aquatone

# EyeWitness
eyewitness --web -f live_hosts.txt
```

---

## Asset Discovery

### 1. DNS Enumeration

```bash
# DNSRecon
dnsrecon -d target.com

# Fierce
fierce --domain target.com

# DNS zone transfer (rarely works)
dig axfr @ns1.target.com target.com
```

### 2. IP Range Discovery

```bash
# ASN lookup
whois -h whois.radb.net -- '-i origin AS15169' | grep -Eo "([0-9.]+){4}/[0-9]+"

# Amass
amass intel -asn 15169
```

### 3. S3 Bucket Discovery

```bash
# Look for S3 buckets
# Format: bucketname.s3.amazonaws.com
# Common names: company, company-prod, company-dev, etc.

# Tools:
# - S3Scanner
# - bucket_finder
# - slurp
```

### 4. Cloud Asset Discovery

```bash
# Azure
# Format: *.azurewebsites.net, *.blob.core.windows.net

# GCP
# Format: *.appspot.com, storage.googleapis.com

# DigitalOcean
# Format: *.digitaloceanspaces.com
```

---

## Technology Identification

### 1. Web Technology Detection

```bash
# Wappalyzer (browser extension or CLI)
wappalyzer target.com

# WhatWeb
whatweb target.com

# BuiltWith
# Visit builtwith.com

# Netcraft
# Visit netcraft.com
```

### 2. Framework Identification

```bash
# Check headers, cookies, error pages
# Common indicators:
# - Set-Cookie: PHPSESSID (PHP)
# - X-Powered-By: ASP.NET
# - Server: Apache/Nginx

curl -I https://target.com
```

### 3. CMS Detection

```bash
# WordPress
# - /wp-admin/
# - /wp-content/
# - /wp-includes/

# Drupal
# - /node/
# - /sites/

# Joomla
# - /administrator/

# WPScan (for WordPress)
wpscan --url https://target.com
```

### 4. JavaScript Analysis

```bash
# Download all JS files
# Use tools like:
# - getJS
# - linkfinder

# Analyze for:
# - API endpoints
# - Hidden parameters
# - Comments
# - Credentials
# - API keys

# LinkFinder
python linkfinder.py -i https://target.com -o output.html
```

---

## Attack Surface Mapping

### 1. Content Discovery

```bash
# Gobuster
gobuster dir -u https://target.com -w /path/to/wordlist.txt

# Dirsearch
dirsearch -u https://target.com -e php,asp,aspx,jsp

# Ffuf
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Feroxbuster (recursive)
feroxbuster -u https://target.com -w wordlist.txt
```

### 2. Parameter Discovery

```bash
# Arjun
arjun -u https://target.com/endpoint

# Param Miner (Burp extension)
# ParamSpider
paramspider -d target.com
```

### 3. API Endpoint Discovery

```bash
# Check common paths:
# /api/
# /v1/
# /v2/
# /rest/
# /graphql
# /swagger.json
# /api-docs

# Kiterunner
kr scan target.com -w routes.kite
```

### 4. Mobile Application Recon

```bash
# For mobile apps:
# - Decompile APK/IPA
# - Extract endpoints from code
# - Analyze API calls
# - Check for hardcoded secrets

# APKTool (Android)
apktool d application.apk

# MobSF (automated)
# Run mobile app through Mobile Security Framework
```

---

## Recon Automation Scripts

### Quick Recon Script
```bash
#!/bin/bash
domain=$1

echo "[+] Starting recon on $domain"

# Subdomain enumeration
subfinder -d $domain -o subdomains.txt
assetfinder --subs-only $domain >> subdomains.txt
cat subdomains.txt | sort -u > all_subs.txt

# Live hosts
cat all_subs.txt | httprobe > live_hosts.txt

# Screenshots
cat live_hosts.txt | aquatone

# Tech detection
cat live_hosts.txt | while read url; do
    echo "Checking $url"
    whatweb $url >> tech_stack.txt
done

echo "[+] Recon complete!"
```

---

## Recon Checklist

### Initial Phase
- [ ] Read program scope
- [ ] Gather all domains/IPs in scope
- [ ] Enumerate subdomains
- [ ] Identify live hosts
- [ ] Take screenshots
- [ ] Identify technologies

### Deep Dive
- [ ] Content discovery
- [ ] API enumeration
- [ ] Parameter discovery
- [ ] GitHub/GitLab search
- [ ] Google dorking
- [ ] Wayback Machine analysis

### Documentation
- [ ] Create asset inventory
- [ ] Note interesting endpoints
- [ ] Document technologies used
- [ ] Map authentication flows
- [ ] Identify user roles

---

## Tools List

### Essential
- Subfinder, Assetfinder, Amass
- httprobe, httpx
- Burp Suite
- Nuclei
- Nmap

### Nice to Have
- Aquatone, EyeWitness
- ffuf, gobuster
- WhatWeb, Wappalyzer
- GitDorker
- Waybackurls

---

## Resources

- [Nahamsec Recon Guide](https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackerOne Methodology](https://www.hackerone.com/ethical-hacker/bug-bounty-methodology)

---

**Remember**: Always stay within scope and follow program rules!
