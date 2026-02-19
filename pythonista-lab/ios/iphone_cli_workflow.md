# iPhone-Only Bug Bounty Workflow
## iSH + Pythonista + SSH Bridge Architecture

**Goal**: Replace desktop CLI tools (grep, curl, nmap) with iPhone-native workflow using iSH for UNIX tools, Pythonista for automation, and SSH to remote machines for heavy compute.

**Why this works**: iPhone becomes orchestration layer, remote machines (Mac/Windows) handle CPU-intensive tasks, all accessible from iPhone in bed/commute/anywhere.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                   iPhone                         │
├─────────────────────────────────────────────────┤
│  Safari                                          │
│  ├─ View HTML reports                           │
│  ├─ Interact with target sites                  │
│  └─ Copy URLs/data to clipboard                 │
├─────────────────────────────────────────────────┤
│  iSH (Alpine Linux CLI)                         │
│  ├─ grep, curl, jq, sed, awk                   │
│  ├─ nmap, masscan, subfinder                    │
│  ├─ git, ssh, python3                           │
│  └─ Generate reports → Share to Pythonista      │
├─────────────────────────────────────────────────┤
│  Pythonista (Automation Layer)                   │
│  ├─ Parse iSH output                            │
│  ├─ SSH to remote machines                      │
│  ├─ Format results as HTML                      │
│  └─ Open in Safari for viewing                  │
├─────────────────────────────────────────────────┤
│  Shortcuts (Glue)                                │
│  ├─ Share iSH → Pythonista                     │
│  ├─ Clipboard → Pythonista → Safari            │
│  └─ Automate common workflows                   │
└─────────────────────────────────────────────────┘
                    ↓ SSH
┌─────────────────────────────────────────────────┐
│            Remote Machines                       │
├─────────────────────────────────────────────────┤
│  MacBook (macOS)                                 │
│  ├─ Burp Suite, Frida, objection                │
│  ├─ Heavy binary analysis (Hopper, IDA)         │
│  ├─ APK/IPA extraction and decompilation        │
│  └─ Long-running scans (nmap -p-)               │
├─────────────────────────────────────────────────┤
│  Windows PC                                      │
│  ├─ Windows-specific tools                      │
│  ├─ Visual Studio Code (remote editing)         │
│  └─ Additional compute for parallel scans       │
└─────────────────────────────────────────────────┘
```

---

## 🔧 Setup Guide

### Part 1: iSH Installation & Configuration

**Install iSH** (Free from App Store):
- Download: https://apps.apple.com/app/ish-shell/id1436902243
- Open iSH → You have Alpine Linux shell on iPhone

**Essential Tools Installation**:
```bash
# Update package manager
apk update

# Core CLI tools
apk add curl wget git openssh

# Text processing
apk add grep sed awk jq

# Network tools (lightweight)
apk add nmap nmap-scripts bind-tools

# Python for scripting
apk add python3 py3-pip

# Optional: Faster alternatives
apk add ripgrep fd bat  # Modern grep/find/cat
```

**Install Bug Bounty Tools**:
```bash
# Go (for Go-based security tools)
apk add go

# Install subfinder (subdomain enumeration)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install httpx (HTTP toolkit)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install nuclei (vulnerability scanner)
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Add Go binaries to PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.ashrc
source ~/.ashrc
```

**Configure SSH for Remote Access**:
```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "iphone-ish"

# Copy public key (you'll add this to remote machines)
cat ~/.ssh/id_ed25519.pub
```

---

### Part 2: Remote Machine Setup

**On MacBook**:
```bash
# Enable SSH (if not already)
sudo systemsetup -setremotelogin on

# Add iPhone's public key to authorized_keys
mkdir -p ~/.ssh
echo "[paste iPhone public key]" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Find Mac's local IP
ifconfig | grep "inet " | grep -v 127.0.0.1

# Test from iSH:
# ssh user@192.168.1.X
```

**On Windows PC**:
```powershell
# Install OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Add iPhone public key
# In PowerShell:
# notepad C:\Users\YourUser\.ssh\authorized_keys
# Paste iPhone public key, save

# Find Windows local IP
ipconfig
```

---

### Part 3: Pythonista SSH Bridge Scripts

Create these scripts in Pythonista to SSH from iPhone to remote machines.

**File**: `ssh_bridge.py`
```python
#!/usr/bin/env python3
"""
SSH Bridge - Execute commands on remote machines from iPhone

Usage:
    from ssh_bridge import SSHBridge

    mac = SSHBridge('user@192.168.1.10')
    result = mac.run('nmap -p 80,443 target.com')
    print(result)
"""

import paramiko
import io
import sys

class SSHBridge:
    """Execute commands on remote machines via SSH"""

    def __init__(self, host, port=22, key_file=None):
        """
        Initialize SSH connection.

        Args:
            host: user@hostname or IP
            port: SSH port (default 22)
            key_file: Path to private key (default ~/.ssh/id_rsa)
        """
        self.host = host
        self.port = port

        # Parse user@host
        if '@' in host:
            self.user, self.hostname = host.split('@')
        else:
            self.user = 'root'
            self.hostname = host

        # SSH key location
        if key_file is None:
            import os
            key_file = os.path.expanduser('~/.ssh/id_rsa')

        self.key = paramiko.RSAKey.from_private_key_file(key_file)
        self.client = None

    def connect(self):
        """Establish SSH connection"""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.client.connect(
            hostname=self.hostname,
            port=self.port,
            username=self.user,
            pkey=self.key
        )

    def run(self, command, timeout=300):
        """
        Execute command on remote machine.

        Args:
            command: Shell command to execute
            timeout: Command timeout in seconds

        Returns:
            dict: {'stdout': '...', 'stderr': '...', 'exit_code': 0}
        """
        if not self.client:
            self.connect()

        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)

        result = {
            'stdout': stdout.read().decode('utf-8'),
            'stderr': stderr.read().decode('utf-8'),
            'exit_code': stdout.channel.recv_exit_status()
        }

        return result

    def run_background(self, command):
        """
        Start long-running command in background (tmux/screen).
        Returns immediately, check results later.
        """
        bg_cmd = f'nohup {command} > /tmp/bg_output.txt 2>&1 &'
        return self.run(bg_cmd)

    def get_background_output(self):
        """Retrieve output from background command"""
        return self.run('cat /tmp/bg_output.txt')

    def upload_file(self, local_path, remote_path):
        """Upload file to remote machine"""
        if not self.client:
            self.connect()

        sftp = self.client.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()

    def download_file(self, remote_path, local_path):
        """Download file from remote machine"""
        if not self.client:
            self.connect()

        sftp = self.client.open_sftp()
        sftp.get(remote_path, local_path)
        sftp.close()

    def close(self):
        """Close SSH connection"""
        if self.client:
            self.client.close()


# =========================
# CONVENIENCE FUNCTIONS
# =========================

def run_on_mac(command):
    """Quick helper: Run command on MacBook"""
    mac = SSHBridge('user@192.168.1.10')  # Update with your Mac IP
    result = mac.run(command)
    mac.close()
    return result['stdout']

def run_on_windows(command):
    """Quick helper: Run command on Windows PC"""
    win = SSHBridge('user@192.168.1.20')  # Update with your Windows IP
    result = win.run(command)
    win.close()
    return result['stdout']

def run_on_best_host(command):
    """
    Automatically choose best host for command type.

    - iOS/Mac tools → Mac
    - Windows tools → Windows
    - Generic → Mac (default)
    """
    # Detect command type
    if any(tool in command for tool in ['apktool', 'jadx', 'adb']):
        # Android tools (could be on either, default Mac)
        return run_on_mac(command)
    elif any(tool in command for tool in ['frida', 'objection', 'class-dump']):
        # iOS tools (Mac only)
        return run_on_mac(command)
    elif any(tool in command for tool in ['burp', 'hopper', 'ida']):
        # Mac GUI tools
        print("⚠️  This requires GUI on Mac. Run manually.")
        return None
    else:
        # Default to Mac
        return run_on_mac(command)


# =========================
# EXAMPLE USAGE
# =========================

if __name__ == '__main__':
    # Example 1: Simple command
    mac = SSHBridge('user@mac.local')
    result = mac.run('ls -la')
    print(result['stdout'])
    mac.close()

    # Example 2: Nmap scan (background)
    mac = SSHBridge('user@mac.local')
    mac.run_background('nmap -p- target.com -oN /tmp/nmap_full.txt')
    print("Scan started in background. Check later with:")
    print("mac.get_background_output()")

    # Example 3: Quick helpers
    output = run_on_mac('whoami')
    print(f"Running as: {output}")
```

---

### Part 4: iSH → Pythonista → Safari Workflow

**Scenario**: Find subdomains, scan for open ports, generate HTML report

**Step 1: In iSH** (Reconnaissance)
```bash
# Find subdomains
subfinder -d target.com -o /tmp/subdomains.txt

# Check which are alive
cat /tmp/subdomains.txt | httpx -status-code -title -o /tmp/alive.txt

# Save results to share with Pythonista
cp /tmp/alive.txt ~/Documents/
```

**Step 2: Share to Pythonista**
```
In iSH:
- Long press on "alive.txt" in Files app
- Share → Run Pythonista Script
- Select "process_recon.py"
```

**Step 3: In Pythonista** (`process_recon.py`)
```python
#!/usr/bin/env python3
"""
Process iSH reconnaissance output and generate HTML report
"""

import sys
import os
import webbrowser
from ssh_bridge import run_on_mac

def process_recon_file(input_file):
    """
    Take iSH output, run additional scans via SSH,
    generate HTML report, open in Safari.
    """

    # Read iSH results
    with open(input_file, 'r') as f:
        alive_hosts = [line.strip() for line in f if line.strip()]

    print(f"📊 Processing {len(alive_hosts)} alive hosts...")

    # For each host, run deeper scan on Mac
    results = []
    for host in alive_hosts[:5]:  # Limit to first 5 for speed
        print(f"🔍 Scanning {host} on remote Mac...")

        # Run nmap on Mac (faster than iPhone)
        nmap_cmd = f'nmap -sV -p 80,443,8080,8443 {host}'
        scan_result = run_on_mac(nmap_cmd)

        results.append({
            'host': host,
            'nmap': scan_result
        })

    # Generate HTML report
    html = generate_html_report(results)

    # Save to Files app
    report_path = os.path.expanduser('~/Documents/recon_report.html')
    with open(report_path, 'w') as f:
        f.write(html)

    print(f"✅ Report saved: {report_path}")

    # Open in Safari
    webbrowser.open(f'file://{report_path}')


def generate_html_report(results):
    """Generate styled HTML report"""

    html = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            background: #1e1e1e;
            color: #e0e0e0;
            padding: 20px;
            max-width: 900px;
            margin: 0 auto;
        }
        h1 { color: #00ff00; border-bottom: 2px solid #00ff00; }
        .host-card {
            background: #2d2d2d;
            border-left: 4px solid #00ff00;
            padding: 15px;
            margin: 20px 0;
            border-radius: 8px;
        }
        .host-card h2 { margin-top: 0; color: #00aaff; }
        pre {
            background: #1a1a1a;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 12px;
        }
        .timestamp {
            color: #888;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <h1>🔍 Reconnaissance Report</h1>
    <p class="timestamp">Generated from iPhone iSH + Pythonista</p>
'''

    for result in results:
        html += f'''
    <div class="host-card">
        <h2>{result['host']}</h2>
        <h3>Nmap Scan Results</h3>
        <pre>{result['nmap']}</pre>
    </div>
'''

    html += '''
</body>
</html>
'''

    return html


if __name__ == '__main__':
    # Get input file (from share sheet or argument)
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        # Default to Documents folder
        input_file = os.path.expanduser('~/Documents/alive.txt')

    if os.path.exists(input_file):
        process_recon_file(input_file)
    else:
        print(f"❌ File not found: {input_file}")
        print("Usage: Share file from iSH to Pythonista")
```

---

## 📋 Complete Workflows

### Workflow 1: Subdomain Enumeration → Port Scan → Report

**In iSH**:
```bash
#!/bin/sh
# recon.sh - iPhone reconnaissance workflow

TARGET="target.com"

echo "🔍 Finding subdomains for $TARGET..."
subfinder -d $TARGET -silent | tee /tmp/subs.txt

echo "✅ Checking which are alive..."
cat /tmp/subs.txt | httpx -silent -status-code | tee /tmp/alive.txt

echo "📊 Results:"
wc -l /tmp/alive.txt

# Copy to Pythonista
cp /tmp/alive.txt ~/Documents/recon_input.txt

echo "✅ Ready for Pythonista processing!"
echo "   Run: process_recon.py"
```

**In Pythonista**: Run `process_recon.py` (from above)

**Result**: HTML report opens in Safari with:
- All alive subdomains
- Nmap scan results (from Mac)
- Formatted for mobile viewing

---

### Workflow 2: Mobile API Testing

**In iSH** (Capture traffic from Burp):
```bash
# Export requests from Burp → Save as HTTP files
# Transfer to iPhone via AirDrop or iCloud

# Extract endpoints
grep "^POST\|^GET" burp_export.txt | awk '{print $2}' > /tmp/endpoints.txt

# Extract auth tokens
grep "Authorization:" burp_export.txt | cut -d' ' -f2- > /tmp/tokens.txt
```

**In Pythonista**:
```python
from mobile_api_interceptor import MobileAPITester

# Read endpoints from iSH
with open('/tmp/endpoints.txt') as f:
    endpoints = [line.strip() for line in f]

# Read token
with open('/tmp/tokens.txt') as f:
    token = f.read().strip()

# Test each endpoint for IDOR
api = MobileAPITester('https://api.target.com', token)
for endpoint in endpoints:
    if '{id}' in endpoint or '{user_id}' in endpoint:
        # Extract param name
        param = endpoint.split('{')[1].split('}')[0]
        api.test_idor(endpoint, param, test_ids=[1,2,3,100,101])
```

---

### Workflow 3: Binary Analysis (iOS App)

**On Mac** (via SSH from Pythonista):
```python
from ssh_bridge import SSHBridge

mac = SSHBridge('user@mac.local')

# Extract IPA (if you have it on Mac)
mac.run('unzip -q app.ipa -d /tmp/app_extracted')

# Run class-dump
result = mac.run('class-dump /tmp/app_extracted/Payload/App.app/App')

# Search for interesting classes
interesting = [line for line in result['stdout'].split('\n')
               if 'password' in line.lower() or 'secret' in line.lower()]

print('\n'.join(interesting))

# Download binary for local analysis
mac.download_file('/tmp/app_extracted/Payload/App.app/App',
                  '~/Documents/app_binary')

mac.close()
```

---

### Workflow 4: Continuous Monitoring

**In iSH** (Run in tmux):
```bash
# Install tmux
apk add tmux

# Start persistent session
tmux new -s monitoring

# Run continuous subdomain discovery
while true; do
    subfinder -d target.com -silent | \
    sort -u | \
    diff - /tmp/known_subs.txt | \
    grep "^>" | \
    tee -a /tmp/new_subs.txt

    # Update known subs
    cat /tmp/new_subs.txt >> /tmp/known_subs.txt
    sort -u /tmp/known_subs.txt -o /tmp/known_subs.txt

    # Sleep 1 hour
    sleep 3600
done

# Detach: Ctrl+B, then D
# Reattach later: tmux attach -t monitoring
```

**In Pythonista** (Check results):
```python
import os

# Read new discoveries
with open('/tmp/new_subs.txt') as f:
    new_subs = [line.strip() for line in f if line.strip()]

if new_subs:
    print(f"🚨 {len(new_subs)} new subdomains discovered!")

    # Send notification (using iOS Notifications)
    import notification
    notification.schedule('New Subdomains', len(new_subs), 'sound')
```

---

## 🔄 Data Flow Patterns

### Pattern 1: iSH → Pythonista → Safari
```
iSH (recon) → Files app → Pythonista (process) → HTML → Safari (view)
```

### Pattern 2: Pythonista → SSH → iSH
```
Pythonista (trigger) → SSH to Mac (heavy scan) → Results to iSH (parse)
```

### Pattern 3: Safari → Pythonista → iSH → Mac
```
Safari (copy URL) → Pythonista (parse) → iSH (recon) → Mac (nmap) → Report
```

---

## 🎯 Advantages of This Setup

**vs Desktop**:
- ✅ Hunt from anywhere (bed, commute, coffee shop)
- ✅ Always-connected (cellular data, no WiFi needed)
- ✅ Notifications (get alerts when scans complete)
- ✅ Touch interface for quick actions

**vs Laptop**:
- ✅ Lighter (iPhone in pocket vs MacBook in bag)
- ✅ Longer battery (iPhone 12+ hours)
- ✅ Instant on (no boot time)

**vs Cloud VPS**:
- ✅ Local network access (test home network, IoT devices)
- ✅ No monthly costs (use existing Mac/PC)
- ✅ Faster (local network vs internet latency)

---

## 📚 Recommended Tools by Layer

### iSH (Reconnaissance)
- `subfinder` - Subdomain enumeration
- `httpx` - HTTP toolkit
- `nuclei` - Vulnerability scanner
- `ffuf` - Web fuzzer
- `jq` - JSON processor

### Pythonista (Automation)
- `ssh_bridge.py` - Remote command execution
- `mobile_api_interceptor.py` - API testing
- `gps_exif_scanner.py` - EXIF analysis
- `vrt_knowledge_agent.py` - Decision making

### Remote Mac (Heavy Lifting)
- Burp Suite Professional
- Frida + objection
- Hopper Disassembler
- Xcode + class-dump
- Nmap with all scripts

### Remote Windows (Windows Tools)
- IDA Pro
- Windows-specific tooling
- Parallel scanning capacity

---

## 🚀 Getting Started (15 Minutes)

1. **Install iSH** (5 min)
   ```
   App Store → iSH → Install
   Open iSH → apk update && apk add curl git python3
   ```

2. **Setup SSH** (5 min)
   ```
   ssh-keygen -t ed25519
   cat ~/.ssh/id_ed25519.pub  # Copy this

   On Mac: echo "[paste key]" >> ~/.ssh/authorized_keys
   ```

3. **Test Connection** (2 min)
   ```
   ssh user@192.168.1.X  # Your Mac IP
   whoami  # Should work!
   ```

4. **Install Pythonista Tools** (3 min)
   ```
   Download from repo:
   - ssh_bridge.py
   - process_recon.py
   - mobile_api_interceptor.py
   ```

5. **First Workflow** (Try it!)
   ```bash
   # In iSH
   curl -s https://example.com | grep -o 'https://[^"]*' > /tmp/urls.txt

   # In Pythonista
   with open('/tmp/urls.txt') as f:
       urls = f.read()
   print(urls)
   ```

---

**You now have a complete iPhone-only bug bounty workstation!** 📱💻🎯

*Use iSH for reconnaissance, Pythonista for automation, SSH for heavy lifting, and Safari for visualization.*
