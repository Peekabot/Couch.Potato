# 🏰 Mind Castle Installation Guide

This guide will set up your complete Mind Castle environment with the Utility Belt, making all ritual functions available in your IPython REPL.

---

## Quick Install (Recommended)

For **iPhone + iSH + Pythonista** users:

```bash
# 1. Install IPython (if not already installed)
pip install ipython

# 2. Create IPython startup directory
mkdir -p ~/.ipython/profile_default/startup/

# 3. Copy the Utility Belt to IPython startup
cp ~/Couch.Potato/.pythonrc.py ~/.ipython/profile_default/startup/00-startup.py

# 4. Launch IPython
ipython
```

You should see the welcome banner:
```
╔════════════════════════════════════════════════╗
║  🧪 Welcome to the Alchemist's Lab (IPython)  ║
║                                                ║
║  Your Utility Belt is equipped:               ║
║    • scribe()         - Save session history  ║
║    • eye()            - View memory           ║
║    • brew(data)       - Transform data        ║
║    ...                                         ║
╚════════════════════════════════════════════════╝
```

---

## Alternative: Standard Python Setup

If you want the Utility Belt available in standard Python (not just IPython):

```bash
# Add to your .bashrc or .profile
echo "export PYTHONSTARTUP=~/Couch.Potato/.pythonrc.py" >> ~/.bashrc
source ~/.bashrc

# Launch standard Python
python
```

**Note:** Some IPython-specific features (like `scribe()`, `obj?`, `%magic` commands) won't work in standard Python, but basic functions like `hunt_idor()`, `brew()`, and `hunt_secrets()` will work fine.

---

## Verify Installation

Launch IPython and test:

```python
# 1. Check if functions are loaded
>>> help_castle()
# Should display command reference

# 2. Test navigation
>>> map_castle()
# Should show castle layout

# 3. Test the armory
>>> armory()
# Should show your weapons

# 4. Test a hunting tool
>>> hunt_secrets("AKIAIOSFODNN7EXAMPLE this is a test")
# Should detect AWS key
```

---

## Pythonista Setup (iPhone)

For Pythonista on iPhone:

### Option 1: Launch Script
Create a new file in Pythonista called `lab.py`:

```python
# lab.py - Launch the Alchemist's Lab
import sys
sys.path.insert(0, '/path/to/Couch.Potato')

# Load Utility Belt
exec(open('/path/to/Couch.Potato/.pythonrc.py').read())

print("\n🧪 Alchemist's Lab ready!")
print("Try: map_castle(), armory(), hunt_idor(), etc.")
```

Run this script whenever you want to start a hunting session.

### Option 2: Import in Console
In Pythonista console:

```python
import sys
sys.path.insert(0, '/path/to/Couch.Potato')
exec(open('/path/to/Couch.Potato/.pythonrc.py').read())
```

### Option 3: Add to Site Packages
```bash
# In Pythonista's Files app
# Copy .pythonrc.py to: site-packages-3/pythonrc.py

# Then in any Pythonista script:
import pythonrc
```

---

## iSH Setup (iPhone Linux)

For iSH terminal on iPhone:

```bash
# 1. Install Python and IPython
apk add python3 py3-pip
pip3 install ipython requests

# 2. Clone this repo (if not already)
cd ~
git clone https://github.com/YourUsername/Couch.Potato.git

# 3. Install Utility Belt
mkdir -p ~/.ipython/profile_default/startup/
cp ~/Couch.Potato/.pythonrc.py ~/.ipython/profile_default/startup/00-startup.py

# 4. Launch IPython
ipython
```

---

## Testing Your Setup

### Test 1: Basic Functions
```python
>>> eye()  # View memory
>>> map_castle()  # Show layout
>>> armory()  # List weapons
```

### Test 2: Data Transformation
```python
>>> brew('{"user_id": 123, "email": "test@example.com"}')
# Should pretty-print JSON

>>> brew('aGVsbG8gd29ybGQ=', 'base64')
# Should output: hello world
```

### Test 3: Hunting Tools
```python
>>> hunt_secrets('My API key is AKIAIOSFODNN7EXAMPLE and password is "secret123"')
# Should detect AWS key and password

>>> # Note: hunt_idor() requires a real target to test
```

### Test 4: Session Saving
```python
>>> x = 42
>>> y = "test"
>>> scribe('test_session.py')
# Should save to test_session.py
```

---

## Customization

### Add Your Own Functions

Edit `.pythonrc.py` and add custom functions:

```python
def my_custom_hunt():
    """Your custom hunting logic."""
    print("🎯 Custom hunt activated!")
    # Your code here...

# Add to welcome banner if desired
```

### Create Custom Aliases

In IPython, create persistent aliases:

```python
# In IPython
%alias scan hunt_idor
%alias secrets hunt_secrets

# Save aliases
%store scan
%store secrets
```

Now you can use:
```python
>>> scan 'https://api.target.com' '/users/{id}' range(1, 100)
>>> secrets some_text
```

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'requests'"
```bash
pip install requests
```

### "scribe() doesn't work"
- Make sure you're using IPython, not standard Python
- Standard Python doesn't have `%magic` commands

### "Utility Belt functions not available"
Check if the file was loaded:
```python
>>> import sys
>>> print(sys.path)
# Should include ~/.ipython/profile_default/startup/

# Manually load if needed:
>>> exec(open('/path/to/.pythonrc.py').read())
```

### "armory() says 'Armory not found'"
Update the path in `.pythonrc.py`:
```python
# Edit this section in .pythonrc.py
possible_paths = [
    Path.home() / 'Couch.Potato' / 'pythonista',
    Path('/your/actual/path/to/Couch.Potato/pythonista'),
    Path.cwd() / 'pythonista',
]
```

---

## What's Next?

### 1. Read the Master Scroll
```bash
cat ~/Couch.Potato/MASTER_SCROLL.md
```
Complete guide to the Mind Castle architecture.

### 2. Read the IPython Power Ladder
```bash
cat ~/Couch.Potato/methodology/IPYTHON_POWER_LADDER.md
```
Learn how to progress from passive REPL use to active automation.

### 3. Start Hunting
```python
>>> armory()  # See your weapons
>>> from mobile_api_interceptor import APITester
>>> tester = APITester('https://api.target.com', 'your_token')
>>> vulns = tester.test_idor('/users/{id}', range(1, 100))
```

### 4. Build More Weapons
Add new tools to `~/Couch.Potato/pythonista/` and they'll appear in your armory.

---

## Quick Reference

**Most-Used Commands:**
```python
# Navigation
map_castle()              # Show layout
armory()                  # Go to tools
library()                 # Go to docs

# Hunting
hunt_idor(url, endpoint, range)
hunt_secrets(text)
hunt_endpoints(url)

# Inspection
dir(obj)                  # Properties
obj?                      # Documentation
eye()                     # Memory

# Data
brew(data)                # Pretty JSON
brew(data, 'base64')      # Decode base64
brew(data, 'url')         # URL decode

# Session
scribe()                  # Save history
```

**Get Help:**
```python
>>> help_castle()         # Full command reference
>>> function_name?        # Help for specific function
```

---

## Pro Tips

### 1. Create Bookmarks
```python
# In IPython
%bookmark armory ~/Couch.Potato/pythonista
%bookmark targets ~/bug_bounty_targets

# Quick navigation
%cd -b armory
%cd -b targets
```

### 2. Auto-load Weapons
Add to `00-startup.py`:
```python
# Auto-import common tools
try:
    from mobile_api_interceptor import APITester
    from ssh_bridge import SSHBridge
    print("⚔️ Weapons auto-loaded!")
except:
    pass
```

### 3. Create Hunt Templates
```python
# Save common hunt patterns
def hunt_mobile_app(target_url):
    """Standard mobile app hunt pattern."""
    tester = APITester(target_url)

    # IDOR
    idor_vulns = tester.test_idor('/users/{id}', range(1, 1000))

    # Auth bypass
    auth_vulns = tester.test_auth_bypass(['/admin', '/api/internal'])

    # Endpoints
    endpoints = hunt_endpoints(target_url)

    return {
        'idor': idor_vulns,
        'auth_bypass': auth_vulns,
        'endpoints': endpoints
    }
```

---

**The Castle is ready. Time to hunt.** 🏰⚔️
