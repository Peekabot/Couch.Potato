# 🐚 iSH Integration for Bug Bounty

Complete guide to using iSH daemon for spawning disposable tasks on iPhone.

## 🎯 Overview

The iSH daemon provides:
- **Shell command execution** from Pythonista/Academy
- **Background task spawning** for long-running jobs
- **Secure communication** via HMAC signatures
- **Task logging** and result tracking
- **Automatic cleanup** of old files

## 🚀 Quick Start

### 1. Install iSH

```
1. Install iSH from App Store (FREE)
2. Open iSH
3. Install Python:
   apk add python3 py3-pip
```

### 2. Start the Daemon

```bash
# In iSH terminal:
cd ~/SharedWithiSH
python3 ish_daemon.py --daemon

# Or run in tmux for persistence:
tmux new -d -s ish_daemon 'python3 ~/SharedWithiSH/ish_daemon.py --daemon'
```

### 3. Send Tasks from Pythonista

```python
# In Pythonista:
import requests
import json

# Send command to daemon
task = {
    "task_id": "scan_001",
    "command": "nmap -sV example.com",
    "type": "async",
    "hmac_signature": "<calculated_signature>"
}

# Write to shared inbox
with open('/path/to/SharedWithiSH/inbox/scan_001.json', 'w') as f:
    json.dump(task, f)

# Wait for result in outbox
```

## 📱 Using with Academy Node

### Add iSH Endpoint to academy_node.py

```python
@app.route('/ish_execute', methods=['POST'])
def ish_execute():
    """
    Execute command in iSH daemon

    POST /ish_execute
    {
        "command": "nmap -sV example.com",
        "type": "sync",  # or "async"
        "timeout": 30
    }
    """
    data = request.get_json()
    command = data.get('command')
    task_type = data.get('type', 'sync')
    timeout = data.get('timeout', 30)

    if not command:
        return jsonify({'error': 'command required'}), 400

    try:
        # Import daemon utilities
        from ish_daemon import send_task, wait_for_result

        # Send task
        task_id = send_task(command, task_type, timeout)

        if task_type == 'sync':
            # Wait for result
            result = wait_for_result(task_id, timeout)
            return jsonify(result)
        else:
            # Return task ID for async
            return jsonify({
                'success': True,
                'task_id': task_id,
                'status': 'running'
            })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

## 🛠️ Use Cases

### 1. Network Scanning

```python
# From Pythonista/Academy:
POST /ish_execute
{
    "command": "nmap -sn 192.168.1.0/24",
    "type": "async"
}

# iSH runs nmap in background
# Results saved to log file
```

### 2. Long-Running Recon

```python
# Subdomain brute force
POST /ish_execute
{
    "command": "subfinder -d example.com -o /tmp/subdomains.txt",
    "type": "async"
}

# Later, fetch results:
POST /ish_execute
{
    "command": "cat /tmp/subdomains.txt",
    "type": "sync"
}
```

### 3. Git Operations

```python
# Clone a repo in iSH
POST /ish_execute
{
    "command": "git clone https://github.com/user/repo /tmp/repo",
    "type": "async"
}

# Later, read files
POST /ish_execute
{
    "command": "cat /tmp/repo/script.py",
    "type": "sync"
}
```

### 4. Install and Run Tools

```python
# Install tool
POST /ish_execute
{
    "command": "pip3 install sqlmap",
    "type": "async"
}

# Run tool
POST /ish_execute
{
    "command": "sqlmap -u 'http://example.com?id=1' --batch",
    "type": "async"
}
```

## 🔐 Security

### HMAC Signature Verification

```python
import hmac
import hashlib
import json

SECRET_KEY = b'5fb9c5db0e37d58bf7ef8e86070d545199b587756ed0026330854ab4a023274e'

def sign_task(task: dict) -> str:
    """Generate HMAC signature for task"""
    signature = hmac.new(
        SECRET_KEY,
        json.dumps(task, sort_keys=True).encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return signature

# Use it:
task = {
    'task_id': 'task_001',
    'command': 'ls -la',
    'timestamp': time.time()
}

task['hmac_signature'] = sign_task(task)
```

### Change the Secret Key!

```python
# Generate new secret:
import secrets
new_secret = secrets.token_hex(32)
print(new_secret)

# Update in both:
# - ish_daemon.py: SECRET_KEY
# - academy_node.py: SECRET_KEY
```

## 📊 Monitoring Tasks

### Check Daemon Status

```bash
# In iSH:
tail -f ~/SharedWithiSH/task_log.jsonl
```

### View Running Background Tasks

```bash
# List log files
ls -lh ~/SharedWithiSH/*.log

# View specific task output
tail -f ~/SharedWithiSH/task_abc123.log
```

### Task History

```python
# Read task log
import json
from pathlib import Path

log_file = Path.home() / 'SharedWithiSH' / 'task_log.jsonl'

for line in log_file.read_text().splitlines():
    task = json.loads(line)
    print(f"[{task['timestamp']}] {task['task_id']}: {task['status']}")
```

## 🎓 Academy Orchestrator Integration

### Add iSH as a Tool

```python
# In orchestrator:
TOOLS = {
    "execute_shell": {
        "description": "Execute shell command in iSH on iPhone",
        "parameters": {
            "command": "Shell command to execute",
            "async": "Run in background (true/false)",
            "timeout": "Command timeout in seconds"
        },
        "endpoint": "http://iphone.local:5000/ish_execute"
    }
}
```

### LLM Tool Definition

```python
ISH_TOOL = {
    "name": "execute_shell",
    "description": """
    Execute a shell command in iSH Linux environment on iPhone.
    Useful for:
    - Running Linux tools (nmap, git, curl, etc.)
    - Installing packages (apk, pip)
    - File operations
    - Network scanning
    - Background tasks
    """,
    "input_schema": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Shell command to execute"
            },
            "async": {
                "type": "boolean",
                "description": "Run in background",
                "default": False
            }
        },
        "required": ["command"]
    }
}
```

### Example Orchestrator Usage

```python
# LLM decides to scan network
agent_response = {
    "tool": "execute_shell",
    "params": {
        "command": "nmap -sV example.com",
        "async": True
    }
}

# Orchestrator executes
result = requests.post(
    'http://iphone.local:5000/ish_execute',
    json={
        'command': 'nmap -sV example.com',
        'type': 'async'
    }
)

# Store task_id for later retrieval
task_id = result.json()['task_id']
```

## 🔧 Advanced Usage

### Chained Commands

```python
# Run multiple commands in sequence
command = """
cd /tmp && \
git clone https://github.com/user/repo && \
cd repo && \
python3 scan.py example.com > results.txt && \
cat results.txt
"""

POST /ish_execute
{
    "command": command,
    "type": "async"
}
```

### Environment Variables

```python
# Set environment for command
command = "GITHUB_TOKEN=xxx python3 sync_repo.py"

POST /ish_execute
{
    "command": command,
    "type": "sync"
}
```

### Scheduled Tasks

```python
# Use iOS Shortcuts to trigger periodic tasks
# Shortcut runs every hour:
import requests

requests.post(
    'http://localhost:5000/ish_execute',
    json={
        'command': 'python3 /root/daily_recon.py',
        'type': 'async'
    }
)
```

## 📚 Examples

### Example 1: Install and Run Tool

```python
# Install
send_task("apk add nmap", task_type='sync')

# Verify
result = wait_for_result(task_id)
print(result['result']['stdout'])

# Use
scan_task_id = send_task("nmap -sV target.com", task_type='async')

# Check later
time.sleep(60)
result = wait_for_result(scan_task_id, timeout=120)
```

### Example 2: Git Workflow

```python
# Clone repo
clone_id = send_task(
    "git clone https://github.com/user/bugbounty-tools /tmp/tools",
    task_type='async'
)

# Wait for clone
time.sleep(10)

# Run tool from repo
tool_id = send_task(
    "python3 /tmp/tools/scanner.py example.com",
    task_type='sync',
    timeout=60
)

# Get results
result = wait_for_result(tool_id, timeout=60)
print(result['result']['stdout'])
```

### Example 3: Monitoring Background Task

```python
# Start long task
task_id = send_task(
    "subfinder -d example.com -o /tmp/subs.txt",
    task_type='async'
)

# Check progress (read log file)
while True:
    log_check = send_task(f"cat /tmp/{task_id}.log", task_type='sync')
    log_result = wait_for_result(log_check)

    print(log_result['result']['stdout'])

    # Check if complete
    done_check = send_task(f"test -f /tmp/subs.txt && echo done", task_type='sync')
    if 'done' in wait_for_result(done_check)['result']['stdout']:
        break

    time.sleep(5)

# Get final results
final = send_task("cat /tmp/subs.txt", task_type='sync')
subdomains = wait_for_result(final)['result']['stdout']
```

## 🐛 Troubleshooting

### Daemon not responding
```bash
# Check if running
ps aux | grep ish_daemon

# Restart
tmux kill-session -t ish_daemon
tmux new -d -s ish_daemon 'python3 ~/SharedWithiSH/ish_daemon.py --daemon'
```

### Tasks timing out
```python
# Increase timeout
POST /ish_execute
{
    "command": "long_running_command",
    "type": "async",  # Use async for long tasks
    "timeout": 300
}
```

### Signature errors
```python
# Verify SECRET_KEY matches in:
# - ish_daemon.py
# - academy_node.py (if using)
# - Any client sending tasks
```

## 🎯 Best Practices

1. **Use async for long tasks** - Prevents timeouts
2. **Monitor log files** - Track background task progress
3. **Clean up temp files** - Daemon auto-cleans after 24h
4. **Use absolute paths** - Avoid cwd issues
5. **Error handling** - Check stderr in results
6. **Resource limits** - iSH has limited CPU/memory

---

**Now you have a full Linux environment on your iPhone for bug bounty! 🐚📱**
