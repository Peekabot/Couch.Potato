# 🐙 GitHub Integration for Pythonista Bug Bounty

Complete guide to integrating GitHub with your iPhone bug bounty workflow using Pythonista.

## 🎯 Overview

This integration allows you to:
- **Fetch code** from GitHub repositories
- **Sync your bug bounty repo** to iPhone
- **Download tools** from other researchers
- **Read and analyze** code on the go
- **Integrate with The Academy** orchestrator

## 🚀 Quick Start

### 1. Install Dependencies

```python
# In Pythonista or a-Shell:
pip install requests
```

### 2. Setup GitHub Token (Recommended)

```python
# Store your token securely
import keychain

# Save token (one-time setup)
keychain.set_password('github', 'token', 'your_github_token_here')

# Use in scripts
token = keychain.get_password('github', 'token')
```

**Get a GitHub Token:**
1. Go to https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Select scopes: `repo`, `read:org`
4. Copy the token

### 3. Basic Usage

```python
from github_client import GitHubClient

# Initialize client
client = GitHubClient(token='your_token')  # or leave empty for public repos

# Fetch a file
file_data = client.get_file('owner/repo', 'path/to/file.py')
print(file_data['decoded_content'])

# List directory
items = client.list_directory('owner/repo', 'scripts')
for item in items:
    print(f"{item['type']}: {item['name']}")

# Clone repository
client.clone_repo('owner/repo', '/path/to/save', include_patterns=['*.py'])
```

## 📱 Using with Academy Node

### Start the Academy Node

```python
# In Pythonista:
python academy_node.py --port 5000
```

### Available Endpoints

#### Fetch File from GitHub

```bash
POST http://localhost:5000/github_fetch_file
{
    "repo": "Peekabot/Couch.Potato",
    "path": "pythonista-lab/utilities/header_analyzer.py",
    "branch": "main"
}
```

Response:
```json
{
    "success": true,
    "content": "#!/usr/bin/env python3...",
    "name": "header_analyzer.py",
    "size": 5432,
    "url": "https://github.com/..."
}
```

#### List Directory

```bash
POST http://localhost:5000/github_list_dir
{
    "repo": "Peekabot/Couch.Potato",
    "path": "pythonista-lab/utilities"
}
```

#### Clone Repository

```bash
POST http://localhost:5000/github_clone_repo
{
    "repo": "Peekabot/Couch.Potato",
    "local_dir": "/path/to/save",
    "patterns": ["*.py", "*.md"]
}
```

#### Search Code

```bash
POST http://localhost:5000/github_search_code
{
    "query": "subdomain enumeration",
    "repo": "Peekabot/Couch.Potato"
}
```

## 🛠️ Bug Bounty Workflows

### Workflow 1: Sync Your Bug Bounty Repo

```python
from github_client import BugBountyGitHub

# Initialize with your repo
bb = BugBountyGitHub('Peekabot/Couch.Potato', token='your_token')

# Sync everything
bb.sync_reports()      # Download all reports
bb.fetch_templates()   # Get report templates
bb.fetch_scripts()     # Download Python tools

print("✅ Repository synced to iPhone!")
```

### Workflow 2: Download a Specific Tool

```python
from github_client import GitHubClient

client = GitHubClient(token='your_token')

# Download a tool from another researcher
client.download_tool(
    'projectdiscovery/nuclei-templates',
    local_dir='/path/to/save',
    tool_name='http'
)
```

### Workflow 3: Daily Sync Automation

```python
#!/usr/bin/env python3
"""
Daily sync script - run via iOS Shortcuts automation
"""
from github_client import BugBountyGitHub
import keychain

# Get token from keychain
token = keychain.get_password('github', 'token')

# Sync repo
bb = BugBountyGitHub('Peekabot/Couch.Potato', token)

# Check for updates
updates = bb.check_for_updates()
print(f"Last updated: {updates['last_updated']}")

# Sync if needed
bb.sync_reports()
bb.fetch_scripts()

print("✅ Daily sync complete!")
```

### Workflow 4: Fetch Latest Tool Version

```python
from github_client import BugBountyGitHub

bb = BugBountyGitHub('Peekabot/Couch.Potato', token='your_token')

# Get latest version of a tool
tool_path = bb.get_latest_tool('pythonista-lab/utilities/header_analyzer.py')

# Run it immediately
import subprocess
subprocess.run(['python', str(tool_path), 'https://example.com'])
```

## 🎓 Academy Orchestrator Integration

### Setup

```python
# In your orchestrator's tools configuration:

TOOLS = {
    "read_github_file": {
        "description": "Fetch and read a file from GitHub repository",
        "parameters": {
            "repo": "Repository in format owner/repo",
            "path": "File path in repository",
            "branch": "Branch name (default: main)"
        },
        "endpoint": "http://iphone.local:5000/github_fetch_file"
    },

    "search_github_code": {
        "description": "Search for code in GitHub repositories",
        "parameters": {
            "query": "Search query",
            "repo": "Optional: limit to specific repository"
        },
        "endpoint": "http://iphone.local:5000/github_search_code"
    },

    "clone_github_repo": {
        "description": "Clone a repository (download files)",
        "parameters": {
            "repo": "Repository to clone",
            "local_dir": "Local directory",
            "patterns": "File patterns to include (e.g., ['*.py'])"
        },
        "endpoint": "http://iphone.local:5000/github_clone_repo"
    }
}
```

### Example Orchestrator Action

```python
def execute_agent_action(action, params):
    """Execute action through Academy nodes"""

    if action == "read_github_file":
        # Call Pythonista node
        response = requests.post(
            'http://iphone.local:5000/github_fetch_file',
            json={
                'repo': params['repo'],
                'path': params['path'],
                'branch': params.get('branch', 'main')
            }
        )

        if response.ok:
            data = response.json()
            return {
                'success': True,
                'content': data['content'],
                'file': data['name']
            }

    # ... other actions
```

### LLM Tool Definition

```python
GITHUB_TOOL = {
    "name": "read_github_file",
    "description": """
    Fetch and read a file from a GitHub repository.
    Useful for:
    - Reading bug bounty tool source code
    - Fetching report templates
    - Analyzing security scripts
    - Getting the latest version of utilities
    """,
    "input_schema": {
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository in format 'owner/repo'"
            },
            "path": {
                "type": "string",
                "description": "Path to file in repository"
            },
            "branch": {
                "type": "string",
                "description": "Branch name",
                "default": "main"
            }
        },
        "required": ["repo", "path"]
    }
}
```

## 🔐 Security Best Practices

### Token Storage

```python
# ✅ GOOD: Use keychain
import keychain
token = keychain.get_password('github', 'token')

# ❌ BAD: Hardcode in scripts
token = "ghp_xxxxxxxxxxxx"  # Never do this!

# ✅ GOOD: Environment variable (if using a-Shell)
import os
token = os.environ.get('GITHUB_TOKEN')
```

### Token Permissions

Only grant necessary scopes:
- **Public repos only**: No token needed
- **Private repos**: `repo` scope
- **Organizations**: `read:org`
- **Avoid**: `admin`, `delete_repo`, etc.

### Secure Communication

```python
# Always use HTTPS (handled automatically by requests)
client = GitHubClient(token)  # Uses https://api.github.com

# For local Academy node, use authentication
# (Add token validation in academy_node.py if needed)
```

## 📊 Advanced Usage

### Custom Clone with Filtering

```python
from github_client import GitHubClient
from pathlib import Path

client = GitHubClient(token='your_token')

# Clone only specific file types
client.clone_repo(
    'Peekabot/Couch.Potato',
    Path('/path/to/save'),
    include_patterns=['*.py', '*.md', '*.json']
)

# This saves bandwidth and storage on iPhone!
```

### Batch Operations

```python
from github_client import BugBountyGitHub

bb = BugBountyGitHub('Peekabot/Couch.Potato', token='your_token')

# Fetch multiple tools
tools = [
    'pythonista-lab/utilities/header_analyzer.py',
    'pythonista-lab/utilities/subdomain_enum.py',
    'pythonista-lab/utilities/jwt_decoder.py'
]

for tool in tools:
    local_file = bb.get_latest_tool(tool)
    print(f"✅ Downloaded: {local_file.name}")
```

### Search and Download

```python
from github_client import GitHubClient

client = GitHubClient(token='your_token')

# Search for XSS payloads
results = client.search_code('XSS payload', repo='payloadbox/xss-payload-list')

# Download interesting files
for result in results[:5]:
    client.save_file_locally(
        result['repository'],
        result['path'],
        f"/tmp/{result['name']}"
    )
```

## 🎯 iOS Shortcuts Integration

### Shortcut: Fetch Tool from GitHub

```
Shortcut Actions:
1. Text → "Enter GitHub repo:"
2. Ask for Input → Save as "repo"
3. Text → "Enter file path:"
4. Ask for Input → Save as "path"
5. Get Contents of URL:
   URL: http://localhost:5000/github_fetch_file
   Method: POST
   Headers: Content-Type: application/json
   Body: {"repo": "[repo]", "path": "[path]"}
6. Get Dictionary Value → "content"
7. Save to File → ~/Documents/BugBounty/Tools/[filename]
8. Show Notification → "Tool downloaded!"
```

### Shortcut: Daily Repo Sync

```
Shortcut Actions:
1. Run Python Script → daily_sync.py
2. Wait for Return
3. Show Notification → "Bug bounty repo synced!"
```

## 📚 Examples

### Example 1: Read a Tool's Source

```python
from github_client import GitHubClient

client = GitHubClient()

# Read header analyzer source
file_data = client.get_file(
    'Peekabot/Couch.Potato',
    'pythonista-lab/utilities/header_analyzer.py'
)

# Analyze the code
code = file_data['decoded_content']
print(f"Lines: {len(code.splitlines())}")
print(f"Size: {file_data['size']} bytes")
```

### Example 2: Find Tools for Subdomain Enumeration

```python
from github_client import GitHubClient

client = GitHubClient(token='your_token')

# Search GitHub
results = client.search_code('subdomain enumeration python')

# Filter for Python files
for result in results:
    if result['name'].endswith('.py'):
        print(f"📄 {result['name']}")
        print(f"   {result['repository']}")
        print(f"   {result['url']}\n")
```

### Example 3: Mirror Your Bug Bounty Repo

```python
from github_client import GitHubClient
from pathlib import Path

client = GitHubClient(token='your_token')

# Full mirror (careful on mobile - bandwidth!)
local_mirror = Path.home() / 'Documents' / 'BugBounty' / 'Mirror'

client.clone_repo(
    'Peekabot/Couch.Potato',
    local_mirror,
    include_patterns=['*.py', '*.md', '*.txt', '*.json']
)

print(f"✅ Repository mirrored to {local_mirror}")
```

## 🐛 Troubleshooting

### "401 Unauthorized"
- Check your GitHub token
- Verify token hasn't expired
- Ensure token has correct scopes

### "404 Not Found"
- Verify repository name (owner/repo)
- Check file path spelling
- Ensure branch name is correct

### "Rate limit exceeded"
- GitHub API has rate limits
- Authenticated requests: 5,000/hour
- Unauthenticated: 60/hour
- Wait or use token for higher limit

### Import errors
```python
# Install dependencies
pip install requests

# Verify installation
import requests
print(requests.__version__)
```

## 📖 API Reference

See `github_client.py` for complete API documentation.

### GitHubClient Methods

- `get_file(repo, path, branch)` - Fetch file content
- `list_directory(repo, path, branch)` - List directory
- `clone_repo(repo, local_dir, branch, patterns)` - Clone repository
- `search_code(query, repo)` - Search for code
- `get_repo_info(repo)` - Get repository metadata

### BugBountyGitHub Methods

- `sync_reports()` - Sync bug reports
- `fetch_templates()` - Download templates
- `fetch_scripts()` - Download scripts
- `get_latest_tool(path)` - Get specific tool
- `check_for_updates()` - Check for updates

---

**Now you can access your entire bug bounty toolkit from your iPhone! 🐙📱**
