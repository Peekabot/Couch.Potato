# 💻 Command-Line Tools Mastery

**Essential recon and testing tools that every bug bounty hunter needs to know.**

---

## Tool Installation

### Kali Linux (Pre-installed)

Most tools come pre-installed on Kali Linux. If missing:

```bash
sudo apt update
sudo apt install subfinder httpx nuclei nmap gobuster
```

### Ubuntu/Debian

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Go (required for many tools)
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/tomnomnom/httprobe@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/waybackurls@latest
```

---

## 1. Subfinder - Subdomain Enumeration

**What it does:** Finds subdomains using passive sources (no direct scanning).

### Basic Usage

```bash
# Simple scan
subfinder -d target.com

# Save to file
subfinder -d target.com -o subdomains.txt

# Silent mode (only results)
subfinder -d target.com -silent

# Multiple domains
subfinder -dL domains.txt -o all_subdomains.txt
```

### Advanced Usage

```bash
# Use all sources (slower but thorough)
subfinder -d target.com -all

# Specific sources only
subfinder -d target.com -sources censys,virustotal

# Exclude specific sources
subfinder -d target.com -exclude-sources waybackarchive

# Recursive subdomain discovery
subfinder -d target.com -recursive

# With API keys for better results
# Create config: ~/.config/subfinder/provider-config.yaml
# Add API keys from:
# - Shodan (shodan.io)
# - Censys (censys.io)
# - VirusTotal (virustotal.com)
# - SecurityTrails (securitytrails.com)
```

### Config File Example

```yaml
# ~/.config/subfinder/provider-config.yaml
shodan: ["YOUR_SHODAN_API_KEY"]
censys: ["YOUR_CENSYS_API_ID:YOUR_CENSYS_API_SECRET"]
virustotal: ["YOUR_VIRUSTOTAL_API_KEY"]
securitytrails: ["YOUR_SECURITYTRAILS_API_KEY"]
```

### Real-World Example

```bash
# Comprehensive subdomain enumeration
subfinder -d target.com -all -recursive -silent -o subs.txt

# Output example:
api.target.com
dev.target.com
staging.target.com
admin.target.com
mail.target.com
```

---

## 2. httpx - HTTP Toolkit

**What it does:** Probes for working HTTP/HTTPS servers, extracts useful information.

### Basic Usage

```bash
# Check if hosts are alive
cat subdomains.txt | httpx

# Save alive hosts
cat subdomains.txt | httpx -o live.txt

# Silent mode
cat subdomains.txt | httpx -silent
```

### Advanced Features

```bash
# Get status codes
cat subdomains.txt | httpx -status-code

# Get response titles
cat subdomains.txt | httpx -title

# Technology detection
cat subdomains.txt | httpx -tech-detect

# Get response length
cat subdomains.txt | httpx -content-length

# Full chain (all info)
cat subdomains.txt | httpx -title -status-code -tech-detect -content-length

# Follow redirects
cat subdomains.txt | httpx -follow-redirects

# Custom timeout
cat subdomains.txt | httpx -timeout 10

# Probe specific ports
cat subdomains.txt | httpx -ports 80,443,8080,8443
```

### Match/Filter Responses

```bash
# Match status codes
cat subdomains.txt | httpx -mc 200,301,302

# Filter out status codes
cat subdomains.txt | httpx -fc 404,403

# Match response size
cat subdomains.txt | httpx -ml 1000

# Match regex in response
cat subdomains.txt | httpx -match-regex "admin"

# Filter regex
cat subdomains.txt | httpx -filter-regex "403 Forbidden"
```

### Save Full Responses

```bash
# Save response bodies
cat subdomains.txt | httpx -response-body -o responses/

# Take screenshots (requires Chrome/Chromium)
cat subdomains.txt | httpx -screenshot -srd screenshots/
```

### Real-World Workflow

```bash
# Complete recon pipeline
subfinder -d target.com -silent | \
  httpx -title -status-code -tech-detect -silent | \
  tee alive_hosts.txt

# Output example:
https://api.target.com [200] [API Gateway] [nginx/1.18.0]
https://admin.target.com [403] [Admin Panel] [Apache/2.4.41]
```

---

## 3. Nuclei - Vulnerability Scanner

**What it does:** Template-based vulnerability scanning. Fast and accurate.

### Setup

```bash
# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Update templates
nuclei -update-templates
```

### Basic Usage

```bash
# Scan single target
nuclei -u https://target.com

# Scan from list
nuclei -l targets.txt

# Silent mode (only findings)
nuclei -u https://target.com -silent

# Specific severity
nuclei -u https://target.com -severity critical,high
```

### Template Selection

```bash
# All CVE templates
nuclei -u https://target.com -t ~/nuclei-templates/cves/

# Specific technology
nuclei -u https://target.com -t ~/nuclei-templates/technologies/wordpress/

# Specific vulnerability type
nuclei -u https://target.com -t ~/nuclei-templates/vulnerabilities/

# Custom template
nuclei -u https://target.com -t my-template.yaml

# Multiple templates
nuclei -u https://target.com -t cves/,technologies/,vulnerabilities/
```

### Filter by Tags

```bash
# WordPress sites
nuclei -l sites.txt -tags wordpress

# XSS templates
nuclei -l sites.txt -tags xss

# SQL injection
nuclei -l sites.txt -tags sqli

# Multiple tags
nuclei -l sites.txt -tags wordpress,joomla,drupal
```

### Filter by Severity

```bash
# Critical only
nuclei -l sites.txt -severity critical

# High and critical
nuclei -l sites.txt -severity critical,high

# Exclude info
nuclei -l sites.txt -exclude-severity info
```

### Output Options

```bash
# JSON output
nuclei -u https://target.com -json -o results.json

# Markdown report
nuclei -u https://target.com -markdown-export report.md

# Save only matched templates
nuclei -u https://target.com -o findings.txt
```

### Rate Limiting (Be Respectful!)

```bash
# Limit requests per second
nuclei -u https://target.com -rate-limit 10

# Bulk size
nuclei -l sites.txt -bulk-size 10

# Timeout
nuclei -u https://target.com -timeout 10
```

### Real-World Example

```bash
# Comprehensive scan
cat live_hosts.txt | nuclei \
  -severity critical,high,medium \
  -exclude-tags dos \
  -rate-limit 50 \
  -o nuclei_findings.txt

# Technology-specific scan
cat wordpress_sites.txt | nuclei \
  -t ~/nuclei-templates/vulnerabilities/wordpress/ \
  -severity high,critical \
  -silent
```

### Custom Template Example

```yaml
# my-custom-check.yaml
id: custom-admin-panel

info:
  name: Admin Panel Detection
  author: you
  severity: info
  description: Detects exposed admin panels

requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/administrator"
      - "{{BaseURL}}/wp-admin"

    matchers:
      - type: status
        status:
          - 200

# Use it:
nuclei -u https://target.com -t my-custom-check.yaml
```

---

## 4. waybackurls - Historical URL Discovery

**What it does:** Fetches URLs from Wayback Machine for a domain.

### Basic Usage

```bash
# Get all archived URLs
waybackurls target.com

# Save to file
waybackurls target.com > wayback.txt

# Multiple domains
cat domains.txt | waybackurls > all_wayback.txt
```

### Filter Useful URLs

```bash
# Only JavaScript files
waybackurls target.com | grep "\.js$"

# Only parameters
waybackurls target.com | grep "?"

# Exclude images
waybackurls target.com | grep -v -E "\.(jpg|png|gif|css|svg)$"

# Only API endpoints
waybackurls target.com | grep "/api/"
```

### Extract Parameters

```bash
# Get unique parameters
waybackurls target.com | \
  grep "?" | \
  cut -d "?" -f2 | \
  cut -d "=" -f1 | \
  sort -u > params.txt

# Output example:
id
user_id
search
query
page
```

### Real-World Workflow

```bash
# Find interesting historical endpoints
waybackurls target.com | \
  grep -E "\.(js|json|xml|config|env|bak|sql)$" | \
  sort -u > interesting_files.txt

# Find old API endpoints
waybackurls target.com | \
  grep "/api/" | \
  sort -u > api_endpoints.txt
```

---

## 5. gau - Get All URLs

**What it does:** Similar to waybackurls but uses multiple sources.

### Installation

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

### Basic Usage

```bash
# Get URLs from all sources
gau target.com

# Save to file
gau target.com > urls.txt

# Silent mode
gau target.com --silent

# Specific providers
gau target.com --providers wayback,commoncrawl

# Blacklist
gau target.com --blacklist png,jpg,gif,css
```

### Filter by Date

```bash
# URLs from specific time period
gau target.com --from 202301 --to 202312
```

### Real-World Example

```bash
# Comprehensive URL collection
gau target.com | \
  grep -E "\.js$|/api/|\.json$" | \
  sort -u > all_interesting_urls.txt
```

---

## 6. assetfinder - Asset Discovery

**What it does:** Finds domains and subdomains related to a target.

### Basic Usage

```bash
# Find subdomains
assetfinder target.com

# Only subdomains
assetfinder --subs-only target.com

# Save to file
assetfinder --subs-only target.com > subs.txt
```

---

## 7. nmap - Network Scanner

**What it does:** Port scanning, service detection, OS fingerprinting.

### ⚠️ Warning
```
Nmap is NOISY. Only use on authorized targets.
Check program rules before using.
Consider using from VPS, not home IP.
```

### Basic Usage

```bash
# Quick scan (top 1000 ports)
nmap target.com

# All ports
nmap -p- target.com

# Specific ports
nmap -p 80,443,8080,8443 target.com

# Service version detection
nmap -sV target.com

# OS detection
nmap -O target.com
```

### Common Scan Types

```bash
# TCP SYN scan (default, fast)
nmap -sS target.com

# TCP connect scan (no root needed)
nmap -sT target.com

# UDP scan
nmap -sU target.com

# No ping (useful if ICMP blocked)
nmap -Pn target.com
```

### NSE Scripts (Powerful!)

```bash
# Default scripts + version detection
nmap -sC -sV target.com

# Vulnerability scripts
nmap --script vuln target.com

# HTTP enumeration
nmap --script http-enum target.com

# Specific script
nmap --script http-title target.com
```

### Output Formats

```bash
# Normal output
nmap target.com -oN scan.txt

# XML output
nmap target.com -oX scan.xml

# Grepable output
nmap target.com -oG scan.grep

# All formats
nmap target.com -oA scan
```

### Real-World Example

```bash
# Comprehensive scan
nmap -sV -sC -p- -T4 --open -oA full_scan target.com

# Web service enumeration
nmap -p 80,443,8080,8443 --script http-enum,http-title target.com
```

---

## 8. amass - In-Depth Enumeration

**What it does:** Comprehensive OSINT and network mapping.

### Installation

```bash
sudo apt install amass  # Kali/Debian
# OR
go install -v github.com/OWASP/Amass/v3/...@master
```

### Basic Usage

```bash
# Passive enumeration (safe, no scanning)
amass enum -passive -d target.com

# Active enumeration (may be detected)
amass enum -active -d target.com

# Save output
amass enum -d target.com -o amass_results.txt
```

### Advanced Usage

```bash
# With all techniques
amass enum -d target.com -active -brute -w /usr/share/wordlists/subdomains.txt

# ASN enumeration
amass intel -asn 15169  # Google's ASN

# Company reverse WHOIS
amass intel -whois -d target.com
```

### Config File

```ini
# ~/.config/amass/config.ini
[data_sources.AlienVault]
[data_sources.AlienVault.Credentials]
apikey = YOUR_API_KEY

[data_sources.Shodan]
[data_sources.Shodan.Credentials]
apikey = YOUR_SHODAN_KEY
```

---

## Tool Chaining - The Power Move

### Complete Recon Pipeline

```bash
#!/bin/bash
# complete_recon.sh

DOMAIN=$1

echo "[+] Subdomain enumeration..."
subfinder -d $DOMAIN -silent | \
  assetfinder --subs-only $DOMAIN | \
  sort -u > all_subs.txt

echo "[+] Finding live hosts..."
cat all_subs.txt | httpx -silent -title -status-code > live.txt

echo "[+] Historical URLs..."
cat all_subs.txt | waybackurls | sort -u > wayback.txt

echo "[+] Parameter extraction..."
cat wayback.txt | grep "?" | cut -d "?" -f2 | cut -d "=" -f1 | sort -u > params.txt

echo "[+] JavaScript files..."
cat wayback.txt | grep "\.js$" | httpx -mc 200 -silent > js_files.txt

echo "[+] Nuclei scanning..."
cat live.txt | cut -d " " -f1 | nuclei -severity critical,high -silent -o findings.txt

echo "[+] Done! Results:"
echo "Subdomains: $(wc -l < all_subs.txt)"
echo "Live hosts: $(wc -l < live.txt)"
echo "Parameters: $(wc -l < params.txt)"
echo "Findings: $(wc -l < findings.txt)"
```

### Usage

```bash
chmod +x complete_recon.sh
./complete_recon.sh target.com
```

---

## Quick Reference Cheat Sheet

```bash
# SUBDOMAIN ENUMERATION
subfinder -d target.com -silent -o subs.txt
assetfinder --subs-only target.com >> subs.txt
amass enum -passive -d target.com -o amass.txt

# LIVE HOST DETECTION
cat subs.txt | httpx -silent -o live.txt
cat subs.txt | httprobe > alive.txt

# HISTORICAL DATA
waybackurls target.com > wayback.txt
gau target.com > gau_urls.txt

# VULNERABILITY SCANNING
nuclei -l live.txt -severity critical,high
nmap -sV -sC target.com -oA scan

# FILTERING
grep "\.js$"           # JavaScript files
grep "?"               # URLs with parameters
grep "/api/"           # API endpoints
grep -v "\.(jpg|png)"  # Exclude images

# COMBINING
subfinder -d target.com -silent | httpx -silent | nuclei -severity high
```

---

## Practical Exercises

### Exercise 1: Basic Subdomain Enum

```bash
# Task: Find all subdomains for tesla.com (public program)
subfinder -d tesla.com -silent > tesla_subs.txt

# Count results
wc -l tesla_subs.txt

✅ Success: You have a list of Tesla subdomains
```

### Exercise 2: Find Live Hosts

```bash
# Task: Check which subdomains are alive
cat tesla_subs.txt | httpx -silent -title -status-code > tesla_live.txt

# Review results
cat tesla_live.txt

✅ Success: You found working web servers
```

### Exercise 3: Historical Discovery

```bash
# Task: Find old URLs that might still work
waybackurls tesla.com | grep "\.js$" | sort -u > tesla_js.txt

✅ Success: You found JavaScript files to analyze
```

### Exercise 4: Full Pipeline

```bash
# Task: Complete recon on hackerone.com
subfinder -d hackerone.com -silent | \
  httpx -silent -title -status-code | \
  tee h1_live.txt

waybackurls hackerone.com | grep "?" > h1_params.txt

✅ Success: You performed multi-tool recon
```

---

## Tips & Best Practices

### 1. Always Save Output

```bash
# Bad: Output to terminal only
subfinder -d target.com

# Good: Save for later analysis
subfinder -d target.com -o subs.txt
```

### 2. Use Silent Mode in Pipelines

```bash
# Cleaner output
subfinder -d target.com -silent | httpx -silent
```

### 3. Respect Rate Limits

```bash
# Nuclei with rate limiting
nuclei -l sites.txt -rate-limit 50
```

### 4. Organize Your Output

```bash
# Create organized structure
mkdir -p recon/$DOMAIN
cd recon/$DOMAIN
subfinder -d $DOMAIN -o subdomains.txt
```

### 5. Use from VPS for Heavy Scans

```bash
# Your home IP for light recon
subfinder -d target.com

# VPS for aggressive scanning
ssh vps "nmap -sV -sC target.com"
```

---

## Troubleshooting

### Issue: "Command not found"

```bash
# Check if in PATH
which subfinder

# If not found, add to PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Issue: API rate limits

```bash
# Add API keys to configs
# Subfinder: ~/.config/subfinder/provider-config.yaml
# Amass: ~/.config/amass/config.ini
```

### Issue: Permissions error

```bash
# Some tools need root
sudo nmap -sS target.com

# Some don't
nmap -sT target.com  # No root needed
```

---

**Master these command-line tools and your recon will be 10x faster than manual browsing! 🚀**
