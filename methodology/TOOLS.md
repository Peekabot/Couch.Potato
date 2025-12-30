# 🛠️ Bug Bounty Tools

Essential tools for bug bounty hunting.

## Reconnaissance Tools

### Subdomain Enumeration
| Tool | Description | Command |
|------|-------------|---------|
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Fast subdomain discovery | `subfinder -d target.com` |
| [Assetfinder](https://github.com/tomnomnom/assetfinder) | Find domains and subdomains | `assetfinder --subs-only target.com` |
| [Amass](https://github.com/OWASP/Amass) | In-depth DNS enumeration | `amass enum -d target.com` |
| [Sublist3r](https://github.com/aboul3la/Sublist3r) | Multiple source subdomain enum | `sublist3r -d target.com` |

### Content Discovery
| Tool | Description | Command |
|------|-------------|---------|
| [ffuf](https://github.com/ffuf/ffuf) | Fast web fuzzer | `ffuf -u https://target.com/FUZZ -w wordlist.txt` |
| [Gobuster](https://github.com/OJ/gobuster) | Directory/file brute-forcer | `gobuster dir -u https://target.com -w wordlist.txt` |
| [Dirsearch](https://github.com/maurosoria/dirsearch) | Web path scanner | `dirsearch -u https://target.com` |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | Recursive content discovery | `feroxbuster -u https://target.com` |

### Live Host Detection
| Tool | Description | Command |
|------|-------------|---------|
| [httprobe](https://github.com/tomnomnom/httprobe) | Probe for working HTTP/HTTPS | `cat domains.txt \| httprobe` |
| [httpx](https://github.com/projectdiscovery/httpx) | Fast HTTP toolkit | `cat domains.txt \| httpx` |

---

## Vulnerability Scanning

### Web Scanners
| Tool | Description | Use Case |
|------|-------------|----------|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Template-based scanner | General vulnerability scanning |
| [Nikto](https://github.com/sullo/nikto) | Web server scanner | Server misconfigurations |
| [WPScan](https://github.com/wpscanteam/wpscan) | WordPress scanner | WordPress vulnerabilities |
| [Joomscan](https://github.com/OWASP/joomscan) | Joomla scanner | Joomla vulnerabilities |

### Network Scanners
| Tool | Description | Command |
|------|-------------|---------|
| [Nmap](https://nmap.org/) | Port scanner | `nmap -sV -sC target.com` |
| [Masscan](https://github.com/robertdavidgraham/masscan) | Fast port scanner | `masscan -p1-65535 target.com` |
| [Naabu](https://github.com/projectdiscovery/naabu) | Fast port scanner | `naabu -host target.com` |

---

## Manual Testing Tools

### Interception Proxies
| Tool | Description | Cost |
|------|-------------|------|
| [Burp Suite](https://portswigger.net/burp) | #1 web testing tool | Free/Pro $449/year |
| [OWASP ZAP](https://www.zaproxy.org/) | Free alternative to Burp | Free |
| [Caido](https://caido.io/) | Modern proxy tool | Free/Pro |
| [mitmproxy](https://mitmproxy.org/) | CLI proxy tool | Free |

### Browser Extensions
| Extension | Purpose |
|-----------|---------|
| [Wappalyzer](https://www.wappalyzer.com/) | Technology detection |
| [Cookie-Editor](https://cookie-editor.cgagnier.ca/) | Cookie manipulation |
| [HackTools](https://github.com/LasCC/Hack-Tools) | Hacker toolkit |
| [FoxyProxy](https://getfoxyproxy.org/) | Proxy management |
| [DotGit](https://github.com/davtur19/DotGit) | Find exposed .git |

---

## Specialized Tools

### XSS
| Tool | Description |
|------|-------------|
| [XSStrike](https://github.com/s0md3v/XSStrike) | XSS detection suite |
| [Dalfox](https://github.com/hahwul/dalfox) | Fast XSS scanner |
| [XSSer](https://github.com/epsylon/xsser) | Automated XSS testing |

### SQL Injection
| Tool | Description |
|------|-------------|
| [SQLMap](https://github.com/sqlmapproject/sqlmap) | Automated SQLi tool |
| [NoSQLMap](https://github.com/codingo/NoSQLMap) | NoSQL injection tool |

### SSRF
| Tool | Description |
|------|-------------|
| [SSRFmap](https://github.com/swisskyrepo/SSRFmap) | SSRF testing |
| [Gopherus](https://github.com/tarunkant/Gopherus) | Gopher protocol exploitation |

### Authentication
| Tool | Description |
|------|-------------|
| [jwt_tool](https://github.com/ticarpi/jwt_tool) | JWT testing toolkit |
| [Hydra](https://github.com/vanhauser-thc/thc-hydra) | Login brute-forcer |

### API Testing
| Tool | Description |
|------|-------------|
| [Postman](https://www.postman.com/) | API testing platform |
| [Insomnia](https://insomnia.rest/) | REST client |
| [Arjun](https://github.com/s0md3v/Arjun) | HTTP parameter discovery |
| [Kiterunner](https://github.com/assetnote/kiterunner) | API endpoint discovery |

---

## Automation & Frameworks

### Recon Automation
| Tool | Description |
|------|-------------|
| [ReconFTW](https://github.com/six2dez/reconftw) | All-in-one recon automation |
| [Sudomy](https://github.com/screetsec/Sudomy) | Subdomain enumeration framework |
| [Garud](https://github.com/R0X4R/Garud) | Automated recon framework |

### Vulnerability Frameworks
| Tool | Description |
|------|-------------|
| [Metasploit](https://www.metasploit.com/) | Penetration testing framework |
| [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) | Community templates |

---

## Utility Tools

### URL Manipulation
| Tool | Description |
|------|-------------|
| [unfurl](https://github.com/tomnomnom/unfurl) | URL parser |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Wayback Machine URLs |
| [gau](https://github.com/lc/gau) | Get all URLs |
| [uro](https://github.com/s0md3v/uro) | URL deduplication |

### Parameter Tools
| Tool | Description |
|------|-------------|
| [ParamSpider](https://github.com/devanshbatham/ParamSpider) | Find parameters |
| [x8](https://github.com/Sh1Yo/x8) | Hidden parameters discovery |

### JavaScript Analysis
| Tool | Description |
|------|-------------|
| [LinkFinder](https://github.com/GerbenJavado/LinkFinder) | Endpoint discovery in JS |
| [JSParser](https://github.com/nahamsec/JSParser) | Parse JS files |
| [getJS](https://github.com/003random/getJS) | Download JS files |
| [Retire.js](https://retirejs.github.io/retire.js/) | Find vulnerable JS libraries |

### Screenshots
| Tool | Description |
|------|-------------|
| [Aquatone](https://github.com/michenriksen/aquatone) | Screenshot tool |
| [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) | Screenshot + report |
| [Gowitness](https://github.com/sensepost/gowitness) | Fast screenshots |

---

## Mobile Testing

| Tool | Description |
|------|-------------|
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Mobile security framework |
| [Objection](https://github.com/sensepost/objection) | Runtime mobile exploration |
| [Frida](https://frida.re/) | Dynamic instrumentation |
| [APKTool](https://ibotpeaches.github.io/Apktool/) | APK decompiler |

---

## Cloud Security

| Tool | Purpose |
|------|---------|
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Multi-cloud security audit |
| [CloudBrute](https://github.com/0xsha/CloudBrute) | Cloud enumeration |
| [S3Scanner](https://github.com/sa7mon/S3Scanner) | S3 bucket scanner |
| [cloud_enum](https://github.com/initstring/cloud_enum) | Cloud asset discovery |

---

## Wordlists

| Wordlist | Source |
|----------|--------|
| SecLists | https://github.com/danielmiessler/SecLists |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| FuzzDB | https://github.com/fuzzdb-project/fuzzdb |
| Bo0oM Fuzz | https://github.com/Bo0oM/fuzz.txt |

### Common Wordlists
```bash
# Subdomains
/usr/share/seclists/Discovery/DNS/

# Directories
/usr/share/seclists/Discovery/Web-Content/

# Parameters
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Passwords
/usr/share/seclists/Passwords/
```

---

## Setup & Installation

### Kali Linux (Pre-installed)
Most tools come pre-installed on Kali Linux.

### Manual Installation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Essential tools
sudo apt install -y nmap gobuster sqlmap nikto wpscan

# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/ffuf/ffuf@latest

# Python tools
pip install arjun
pip install sqlmap
```

---

## Burp Suite Extensions

### Essential Extensions
- **Autorize** - Authorization testing
- **Param Miner** - Parameter discovery
- **Turbo Intruder** - Fast attacks
- **Logger++** - Advanced logging
- **HTTP Request Smuggler** - Request smuggling
- **Active Scan++** - Enhanced scanning
- **JS Link Finder** - JavaScript endpoint discovery
- **Retire.js** - Vulnerable JS detection

---

## Tool Configuration

### Burp Suite Setup
1. Install Burp Suite Community/Pro
2. Configure browser proxy (127.0.0.1:8080)
3. Install CA certificate
4. Install extensions (BApp Store)
5. Configure scope

### Browser Setup
1. Install Firefox/Chrome
2. Install extensions
3. Configure FoxyProxy
4. Import Burp CA certificate
5. Disable auto-updates during testing

---

## Cloud-Based Tools

| Service | Purpose |
|---------|---------|
| [Shodan](https://www.shodan.io/) | Internet-wide scanning |
| [Censys](https://censys.io/) | Internet intelligence |
| [SecurityTrails](https://securitytrails.com/) | Domain/DNS intelligence |
| [VirusTotal](https://www.virustotal.com/) | File/URL analysis |
| [URLScan](https://urlscan.io/) | URL scanner |

---

## Learning Resources

### Practice Platforms
- PortSwigger Web Security Academy
- HackTheBox
- TryHackMe
- PentesterLab
- DVWA (Damn Vulnerable Web App)

### Tool Documentation
- Read the official docs for each tool
- Check GitHub repositories for examples
- Follow tool creators on Twitter
- Join Discord communities

---

## Tips

1. **Start Simple**: Master Burp Suite before complex automation
2. **Automate Recon**: Use scripts to save time
3. **Stay Updated**: Tools update frequently
4. **Combine Tools**: Use multiple tools for better coverage
5. **Manual > Automated**: Always verify automated findings
6. **Responsible Use**: Only use on authorized targets

---

**Remember**: Tools are only as good as the person using them. Understanding the vulnerability is more important than running automated tools.
