# 🚀 Academy Integration Quick Start

Get your iPhone connected to The Academy orchestrator in 5 minutes.

## ⚡ Quick Setup

### 1. Start Academy Node on iPhone

```bash
# In Pythonista or a-Shell:
cd ~/Couch.Potato/pythonista-lab/ios/pythonista
python academy_node.py --host 0.0.0.0 --port 5000
```

You should see:
```
╔═══════════════════════════════════════╗
║  🎓 Academy Node - Pythonista        ║
╚═══════════════════════════════════════╝

📱 Device: iPhone/iPad
🐍 Platform: Pythonista
🌐 Server: http://0.0.0.0:5000

Available Capabilities:
✅ GitHub Integration
✅ Mobile Recon
✅ Report Generator
✅ File Management

🎯 Ready to serve The Academy!
```

### 2. Test Connection

```bash
# From orchestrator machine:
curl http://<iphone-ip>:5000/health

# Should return:
{
  "status": "healthy",
  "node": "pythonista",
  "capabilities": {
    "github": true,
    "recon": true,
    "reporter": true,
    "file_ops": true
  }
}
```

### 3. Get Secret Key

The nodes communicate using HMAC signatures. Make sure your orchestrator and Academy node use the same secret key.

**In academy_node.py:**
```python
SECRET_KEY = b'5fb9c5db0e37d58bf7ef8e86070d545199b587756ed0026330854ab4a023274e'
```

**In orchestrator:**
```python
SECRET_KEY = b'5fb9c5db0e37d58bf7ef8e86070d545199b587756ed0026330854ab4a023274e'
```

⚠️ **Change this in production!**

### 4. Test File Write

```python
# From orchestrator:
import hmac
import hashlib
import json
import requests

SECRET_KEY = b'5fb9c5db0e37d58bf7ef8e86070d545199b587756ed0026330854ab4a023274e'

payload = {
    'path': 'BugBounty/test.txt',
    'content': 'Hello from The Academy!',
    'append': False
}

payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
signature = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).hexdigest()

headers = {
    'X-Academy-Signature': signature,
    'Content-Type': 'application/json'
}

response = requests.post(
    'http://<iphone-ip>:5000/write_file',
    headers=headers,
    json=payload
)

print(response.json())
# {'success': True, 'message': 'File written successfully', ...}
```

### 5. Verify on iPhone

Open Files app on iPhone → On My iPhone → Pythonista → Documents → BugBounty → test.txt

You should see: "Hello from The Academy!"

## 📱 Available Endpoints

### File Operations (Require Signature)

```bash
POST /write_file
POST /read_file
POST /list_files
POST /delete_file
```

### GitHub Operations

```bash
POST /github_fetch_file
POST /github_list_dir
POST /github_clone_repo
POST /github_search_code
```

### Bug Bounty Tools

```bash
POST /recon
POST /report
```

### System

```bash
GET /health
GET /capabilities
GET /api/ping
```

## 🎯 Common Tasks

### Write a Bug Report

```python
payload = {
    'path': 'BugBounty/reports/xss_example_com.md',
    'content': '''# XSS Vulnerability

Target: https://example.com
Severity: High

## Description
Reflected XSS in search parameter...
'''
}

# Sign and send (use helper function from above)
```

### Fetch Code from GitHub

```python
payload = {
    'repo': 'Peekabot/Couch.Potato',
    'path': 'pythonista-lab/utilities/header_analyzer.py',
    'branch': 'main'
}

response = requests.post(
    'http://<iphone-ip>:5000/github_fetch_file',
    json=payload
)

code = response.json()['content']
print(code)
```

### Run Recon

```python
payload = {
    'domain': 'example.com',
    'verbose': False
}

response = requests.post(
    'http://<iphone-ip>:5000/recon',
    json=payload
)

results = response.json()
print(f"Found {results['count']} subdomains")
```

### List Files

```python
payload = {
    'path': 'BugBounty/reports',
    'pattern': '*.md'
}

# Sign payload
payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
signature = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).hexdigest()

headers = {'X-Academy-Signature': signature, 'Content-Type': 'application/json'}

response = requests.post(
    'http://<iphone-ip>:5000/list_files',
    headers=headers,
    json=payload
)

files = response.json()['files']
for f in files:
    print(f"{f['name']} ({f['size']} bytes)")
```

## 🔐 Security Checklist

- [ ] Change SECRET_KEY from default
- [ ] Use HTTPS in production (or VPN)
- [ ] Whitelist allowed IP addresses
- [ ] Monitor access logs
- [ ] Rotate keys regularly
- [ ] Use environment variables for secrets

## 🐛 Troubleshooting

### Connection Refused

- Check iPhone IP address: Settings → WiFi → Info (i) → IP Address
- Ensure iPhone and orchestrator are on same network
- Check firewall settings
- Verify port 5000 is accessible

### Invalid Signature

```python
# Ensure SECRET_KEY matches exactly
# Check payload is sorted before signing
payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')

# Verify signature calculation
import hmac, hashlib
sig = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).hexdigest()
print(f"Signature: {sig}")
```

### Path Errors

```python
# All paths are relative to Documents directory
# ✅ Good: 'BugBounty/reports/finding.md'
# ❌ Bad: '/Users/username/Documents/BugBounty/reports/finding.md'

# Paths cannot escape Documents directory
# ❌ Bad: '../../../etc/passwd'
```

### Module Not Found

```bash
# Install dependencies in Pythonista/a-Shell:
pip install requests flask dnspython colorama
```

## 🎓 Next Steps

1. **Read the full guide**: [ACADEMY_ORCHESTRATOR_INTEGRATION.md](ACADEMY_ORCHESTRATOR_INTEGRATION.md)
2. **Setup iSH daemon**: [ISH_INTEGRATION.md](ISH_INTEGRATION.md)
3. **Configure GitHub**: [GITHUB_INTEGRATION.md](GITHUB_INTEGRATION.md)
4. **Learn workflows**: [WORKFLOWS.md](WORKFLOWS.md)

## 📚 Example Orchestrator Code

### Complete Helper Functions

```python
# academy_client.py
import hmac
import hashlib
import json
import requests

class AcademyClient:
    """Client for communicating with Academy nodes"""

    def __init__(self, node_address: str, secret_key: bytes):
        self.node_address = node_address
        self.secret_key = secret_key

    def _sign(self, payload: dict) -> str:
        """Generate HMAC signature"""
        payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
        return hmac.new(self.secret_key, payload_bytes, hashlib.sha256).hexdigest()

    def _request(self, endpoint: str, payload: dict, signed: bool = True) -> dict:
        """Make request to Academy node"""
        headers = {'Content-Type': 'application/json'}

        if signed:
            signature = self._sign(payload)
            headers['X-Academy-Signature'] = signature

        try:
            response = requests.post(
                f'{self.node_address}{endpoint}',
                headers=headers,
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def write_file(self, path: str, content: str, append: bool = False) -> dict:
        """Write file to node"""
        return self._request('/write_file', {
            'path': path,
            'content': content,
            'append': append
        })

    def read_file(self, path: str) -> dict:
        """Read file from node"""
        return self._request('/read_file', {'path': path})

    def list_files(self, path: str = '', pattern: str = '*') -> dict:
        """List files on node"""
        return self._request('/list_files', {'path': path, 'pattern': pattern})

    def github_fetch(self, repo: str, path: str, branch: str = 'main') -> dict:
        """Fetch file from GitHub"""
        return self._request('/github_fetch_file', {
            'repo': repo,
            'path': path,
            'branch': branch
        }, signed=False)

    def run_recon(self, domain: str, verbose: bool = False) -> dict:
        """Run recon on domain"""
        return self._request('/recon', {
            'domain': domain,
            'verbose': verbose
        }, signed=False)

# Usage:
client = AcademyClient(
    'http://192.168.1.100:5000',
    b'your-secret-key-here'
)

# Write a bug report
result = client.write_file(
    'BugBounty/reports/xss_finding.md',
    '# XSS Vulnerability\n\n...'
)

# Read it back
content = client.read_file('BugBounty/reports/xss_finding.md')
print(content['content'])

# List all reports
files = client.list_files('BugBounty/reports', '*.md')
for f in files['files']:
    print(f['name'])
```

## 🎯 Success!

You're now ready to use The Academy with your iPhone! The orchestrator can autonomously:
- ✅ Write bug reports to iPhone
- ✅ Read files for analysis
- ✅ Fetch code from GitHub
- ✅ Run recon scans
- ✅ Generate reports
- ✅ Manage files across network

**Happy autonomous bug hunting! 🎓📱🔐**
