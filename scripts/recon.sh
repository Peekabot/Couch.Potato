#!/bin/bash

# Bug Bounty Recon Automation Script
# Based on 2025 Master Strategy
# Usage: ./recon.sh target.com

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║         Bug Bounty Recon Automation v1.0              ║"
echo "║              2025 Master Strategy                     ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if domain is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}[!] Usage: $0 <target.com>${NC}"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR="recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"

# Create output directory
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR" || exit

echo -e "${GREEN}[+] Starting recon on: $DOMAIN${NC}"
echo -e "${GREEN}[+] Output directory: $OUTPUT_DIR${NC}"
echo ""

# Function to check if a tool exists
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[!] $1 is not installed. Skipping...${NC}"
        return 1
    fi
    return 0
}

# =============================================================================
# PHASE 1: SUBDOMAIN ENUMERATION
# =============================================================================

echo -e "${YELLOW}[*] Phase 1: Subdomain Enumeration${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Subfinder
if check_tool "subfinder"; then
    echo -e "${BLUE}[>] Running Subfinder...${NC}"
    subfinder -d "$DOMAIN" -silent -o subfinder.txt
    echo -e "${GREEN}[✓] Subfinder found $(wc -l < subfinder.txt) subdomains${NC}"
fi

# Assetfinder
if check_tool "assetfinder"; then
    echo -e "${BLUE}[>] Running Assetfinder...${NC}"
    assetfinder --subs-only "$DOMAIN" > assetfinder.txt
    echo -e "${GREEN}[✓] Assetfinder found $(wc -l < assetfinder.txt) subdomains${NC}"
fi

# Amass (passive mode - slower but thorough)
if check_tool "amass"; then
    echo -e "${BLUE}[>] Running Amass (passive)...${NC}"
    echo -e "${YELLOW}[!] This may take a while...${NC}"
    amass enum -passive -d "$DOMAIN" -o amass.txt 2>/dev/null
    echo -e "${GREEN}[✓] Amass found $(wc -l < amass.txt) subdomains${NC}"
fi

# Combine and deduplicate
echo -e "${BLUE}[>] Combining and deduplicating results...${NC}"
cat *.txt 2>/dev/null | sort -u > all_subdomains.txt
TOTAL_SUBS=$(wc -l < all_subdomains.txt)
echo -e "${GREEN}[✓] Total unique subdomains: $TOTAL_SUBS${NC}"
echo ""

# =============================================================================
# PHASE 2: LIVE HOST DETECTION
# =============================================================================

echo -e "${YELLOW}[*] Phase 2: Live Host Detection${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# httpx for live hosts
if check_tool "httpx"; then
    echo -e "${BLUE}[>] Checking for live hosts with httpx...${NC}"
    cat all_subdomains.txt | httpx -silent -o live_hosts.txt
    LIVE_COUNT=$(wc -l < live_hosts.txt)
    echo -e "${GREEN}[✓] Found $LIVE_COUNT live hosts${NC}"

    # Get detailed info
    echo -e "${BLUE}[>] Getting detailed information...${NC}"
    cat live_hosts.txt | httpx -silent -title -status-code -tech-detect -o live_detailed.txt
    echo -e "${GREEN}[✓] Detailed info saved to live_detailed.txt${NC}"
else
    # Fallback to httprobe
    if check_tool "httprobe"; then
        echo -e "${BLUE}[>] Checking for live hosts with httprobe...${NC}"
        cat all_subdomains.txt | httprobe > live_hosts.txt
        LIVE_COUNT=$(wc -l < live_hosts.txt)
        echo -e "${GREEN}[✓] Found $LIVE_COUNT live hosts${NC}"
    fi
fi
echo ""

# =============================================================================
# PHASE 3: WAYBACK MACHINE (HISTORICAL URLS)
# =============================================================================

echo -e "${YELLOW}[*] Phase 3: Historical URL Discovery${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if check_tool "waybackurls"; then
    echo -e "${BLUE}[>] Fetching URLs from Wayback Machine...${NC}"
    cat all_subdomains.txt | waybackurls > wayback_urls.txt
    WAYBACK_COUNT=$(wc -l < wayback_urls.txt)
    echo -e "${GREEN}[✓] Found $WAYBACK_COUNT historical URLs${NC}"

    # Extract parameters
    echo -e "${BLUE}[>] Extracting parameters...${NC}"
    cat wayback_urls.txt | grep "?" | cut -d "?" -f2 | cut -d "=" -f1 | sort -u > parameters.txt
    PARAM_COUNT=$(wc -l < parameters.txt)
    echo -e "${GREEN}[✓] Found $PARAM_COUNT unique parameters${NC}"

    # Find interesting endpoints
    echo -e "${BLUE}[>] Finding interesting endpoints...${NC}"
    cat wayback_urls.txt | grep -E "\.(js|json|xml|conf|config|env|bak|sql|db)$" | sort -u > interesting_files.txt
    echo -e "${GREEN}[✓] Found $(wc -l < interesting_files.txt) interesting files${NC}"
fi
echo ""

# =============================================================================
# PHASE 4: JAVASCRIPT FILE DISCOVERY
# =============================================================================

echo -e "${YELLOW}[*] Phase 4: JavaScript Discovery${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "wayback_urls.txt" ]; then
    echo -e "${BLUE}[>] Extracting JavaScript files...${NC}"
    cat wayback_urls.txt | grep "\.js$" | sort -u > js_files.txt
    JS_COUNT=$(wc -l < js_files.txt)
    echo -e "${GREEN}[✓] Found $JS_COUNT JavaScript files${NC}"
fi
echo ""

# =============================================================================
# PHASE 5: TECHNOLOGY DETECTION
# =============================================================================

echo -e "${YELLOW}[*] Phase 5: Technology Detection${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if check_tool "whatweb" && [ -f "live_hosts.txt" ]; then
    echo -e "${BLUE}[>] Detecting technologies with WhatWeb...${NC}"
    cat live_hosts.txt | head -20 | while read url; do
        whatweb -a 3 "$url" >> technology_stack.txt 2>/dev/null
    done
    echo -e "${GREEN}[✓] Technology detection complete${NC}"
fi
echo ""

# =============================================================================
# PHASE 6: PORT SCANNING (OPTIONAL - BE CAREFUL)
# =============================================================================

read -p "$(echo -e ${YELLOW}Do you want to perform port scanning? This can be noisy. [y/N]: ${NC})" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}[*] Phase 6: Port Scanning${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if check_tool "naabu"; then
        echo -e "${BLUE}[>] Scanning ports with naabu...${NC}"
        cat all_subdomains.txt | head -50 | naabu -silent -o ports.txt
        echo -e "${GREEN}[✓] Port scan complete${NC}"
    fi
fi
echo ""

# =============================================================================
# PHASE 7: SCREENSHOTS (OPTIONAL)
# =============================================================================

read -p "$(echo -e ${YELLOW}Take screenshots of live hosts? This may take time. [y/N]: ${NC})" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}[*] Phase 7: Screenshots${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if check_tool "gowitness" && [ -f "live_hosts.txt" ]; then
        echo -e "${BLUE}[>] Taking screenshots with gowitness...${NC}"
        mkdir -p screenshots
        gowitness file -f live_hosts.txt -P screenshots/ 2>/dev/null
        echo -e "${GREEN}[✓] Screenshots saved to screenshots/${NC}"
    fi
fi
echo ""

# =============================================================================
# GENERATE SUMMARY REPORT
# =============================================================================

echo -e "${YELLOW}[*] Generating Summary Report${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cat > SUMMARY.md <<EOF
# Recon Summary for $DOMAIN
**Date**: $(date)

## Statistics

| Metric | Count |
|--------|-------|
| Total Subdomains | $(wc -l < all_subdomains.txt 2>/dev/null || echo "0") |
| Live Hosts | $(wc -l < live_hosts.txt 2>/dev/null || echo "0") |
| Historical URLs | $(wc -l < wayback_urls.txt 2>/dev/null || echo "0") |
| Unique Parameters | $(wc -l < parameters.txt 2>/dev/null || echo "0") |
| JavaScript Files | $(wc -l < js_files.txt 2>/dev/null || echo "0") |
| Interesting Files | $(wc -l < interesting_files.txt 2>/dev/null || echo "0") |

## Files Generated

- \`all_subdomains.txt\` - All discovered subdomains
- \`live_hosts.txt\` - Live HTTP/HTTPS hosts
- \`live_detailed.txt\` - Detailed info (title, status, tech)
- \`wayback_urls.txt\` - Historical URLs from Wayback Machine
- \`parameters.txt\` - Unique parameters found
- \`js_files.txt\` - JavaScript files
- \`interesting_files.txt\` - Config, backup, and sensitive files
- \`technology_stack.txt\` - Detected technologies

## Next Steps

1. **Review live_detailed.txt** for interesting technologies
2. **Check interesting_files.txt** for exposed configs
3. **Test parameters.txt** for injection vulnerabilities
4. **Analyze js_files.txt** for API endpoints and secrets
5. **Run focused scans** based on detected technologies

## Quick Wins to Look For

- [ ] Exposed \`.git\` directories
- [ ] Default credentials on admin panels
- [ ] Backup files (.bak, .sql, .zip)
- [ ] API documentation (/swagger.json, /api-docs)
- [ ] Staging/dev environments
- [ ] Information disclosure in error messages

## Contextual Scanning Commands

Based on findings, run:

\`\`\`bash
# If WordPress found
wpscan --url <wordpress_url> --api-token <token>

# Directory fuzzing
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Parameter fuzzing
ffuf -u https://target.com/endpoint?FUZZ=value -w params.txt

# Nuclei scanning
nuclei -l live_hosts.txt -t ~/nuclei-templates/
\`\`\`

---
Generated by Bug Bounty Recon Script v1.0
EOF

echo -e "${GREEN}[✓] Summary report saved to SUMMARY.md${NC}"
echo ""

# =============================================================================
# FINAL OUTPUT
# =============================================================================

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║            Recon Complete! 🎯                         ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BLUE}Results saved in: $OUTPUT_DIR${NC}"
echo -e "${BLUE}Read SUMMARY.md for next steps${NC}"
echo ""

# Show top live hosts
if [ -f "live_hosts.txt" ] && [ $(wc -l < live_hosts.txt) -gt 0 ]; then
    echo -e "${YELLOW}[*] Top 10 Live Hosts:${NC}"
    head -10 live_hosts.txt | nl
    echo ""
fi

# Show interesting files
if [ -f "interesting_files.txt" ] && [ $(wc -l < interesting_files.txt) -gt 0 ]; then
    echo -e "${YELLOW}[*] Interesting Files Found:${NC}"
    head -10 interesting_files.txt | nl
    echo ""
fi

echo -e "${GREEN}[+] Happy Hunting! 🐛${NC}"
