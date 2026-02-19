# 🏰 IPython Roguelike Configuration Guide

Transform your IPython REPL into a legendary roguelike experience with auto-equipped artifacts, Vi keybindings, and persistent magic!

## 🎯 What You Get

- 🗡️ **Vi Mode Always On** - Your vim muscle memory works everywhere
- 🛡️ **Auto-Equipped Inventory** - Natas utilities loaded on boot
- 💾 **%store Magic** - Variables survive session crashes
- 🔄 **Autoreload** - Modules refresh automatically during development
- 🐛 **Auto-PDB** - Debugger triggers on exceptions (Save State!)
- 🎨 **Custom %natas Magic** - One-liner level reconnaissance
- 🎮 **Navigation Aliases** - Quick directory shortcuts

## ⚡ Quick Installation

### Option 1: System-Wide (Recommended)

```bash
# In iSH terminal (NOT in IPython):
ipython profile create

# Copy the roguelike config:
cp ~/Documents/Couch.Potato/pythonista-lab/ios/a-shell/ipython_config.py \
   ~/.ipython/profile_default/ipython_config.py

# Now every IPython session is enchanted!
ipython
```

You'll see:
```
╔═══════════════════════════════════════════════════════════════╗
║                   🗡️  IPython Roguelike Mode  🛡️                ║
╚═══════════════════════════════════════════════════════════════╝

    Vi Mode: ✅ Enabled (ESC to command mode, i to insert)
    Auto-PDB: ✅ Enabled (Exceptions trigger debugger)
    Autoreload: ✅ Enabled (Modules refresh on change)

🗡️  IPython Roguelike Loadout equipped!
📦 Artifacts: probe, reveal_vial, sling_payload, scout_room, scribe
⚡ Quick: natas_auth, natas_url, quick_scout, quick_run

In [1]:
```

### Option 2: Test First (Without Installing)

```bash
# Test the config without installing:
cd ~/Documents/Couch.Potato/pythonista-lab/ios/a-shell
ipython --config=ipython_config.py
```

## 🗡️ Path 1: The Vim Cloak - Automated Vi Mode

### What Is It?

IPython supports Vi keybindings, turning your REPL into a vim-like editor. But normally you have to enable it manually every time:

```python
# Old way (manual, every session):
In [1]: %config TerminalInteractiveShell.editing_mode = 'vi'
```

Our config **automatically enables this** on every boot!

### Vi Mode Cheat Sheet

**Command Mode (press ESC):**
```
h j k l          - Move cursor left/down/up/right
w b              - Jump word forward/backward
0 $              - Jump to start/end of line
dd               - Delete line
yy               - Yank (copy) line
p                - Paste
/text            - Search forward for text
n N              - Next/previous search result
u                - Undo
Ctrl-R           - Redo
i a              - Insert before/after cursor
A                - Insert at end of line
```

**Insert Mode (press i, a, A, etc):**
```
Type normally    - Enter text
ESC              - Return to command mode
```

### Why It's Powerful

```python
# Example: Editing multi-line commands

In [1]: for subdomain in ['www', 'api', 'dev']:  # Type this, realize you made a mistake
   ...:     url = natas_url(subdomain)  # Oops, this is wrong!

# In command mode (ESC):
# - Press 'k' to go up to line 1
# - Press 'w' to jump to 'subdomain'
# - Press 'ciw' (change inner word) and type the correct text
# - Press ESC, then 'j' to go back down
# - Press 'A' to append at end of line
```

This is **way faster** than using arrow keys!

## 🗺️ Path 2: Mapping the Dungeon - IPython Navigation

### The Problem: Where Am I?

In plain Python REPL, you can't easily:
- See current directory
- List files
- Run shell commands
- Navigate folders

IPython solves this with **magic commands** and **shell escapes**!

### Basic Navigation Magics

```python
# Print working directory
In [1]: %pwd
Out[1]: '/root'

# Change directory
In [2]: %cd ~/Documents/Couch.Potato/pythonista-lab
/root/Documents/Couch.Potato/pythonista-lab

In [3]: %pwd
Out[3]: '/root/Documents/Couch.Potato/pythonista-lab'

# List files (IPython magic)
In [4]: %ls
ios/  utilities/  requirements.txt  README.md

# List files with details (shell escape)
In [5]: !ls -lah
total 24K
drwxr-xr-x  4 root root 4.0K Feb  1 12:00 .
drwxr-xr-x  3 root root 4.0K Feb  1 12:00 ..
drwxr-xr-x  8 root root 4.0K Feb  1 12:00 ios
drwxr-xr-x  2 root root 4.0K Feb  1 12:00 utilities
```

### Shell Escapes: The ! Prefix

**Any command prefixed with `!` runs in the shell:**

```python
# Run any shell command
In [6]: !pwd
/root/Documents/Couch.Potato/pythonista-lab

# Find files
In [7]: !find . -name "*.py" | head -5
./utilities/header_analyzer.py
./utilities/jwt_decoder.py
./ios/devstral_cli.py
./ios/pythonista/quick_recon.py
./ios/pythonista/mobile_reporter.py

# Check if file exists
In [8]: !test -f inventory.py && echo "Found!" || echo "Missing!"
Missing!

In [9]: !test -f ios/a-shell/inventory.py && echo "Found!" || echo "Missing!"
Found!

# Capture output into Python variable!
In [10]: files = !ls ios/
In [11]: files
Out[11]: ['ACADEMY_ORCHESTRATOR_INTEGRATION.md',
          'DEVSTRAL_INTEGRATION.md',
          'GITHUB_INTEGRATION.md',
          ...]
```

### Custom Aliases (Pre-Configured)

Our config includes shortcuts:

```python
# Jump to your docs directory
In [1]: %docs
/root/Documents/Couch.Potato/pythonista-lab

# Jump to Natas tools
In [2]: %natas
/root/Documents/Couch.Potato/pythonista-lab/ios/a-shell

# List all files including hidden
In [3]: %la

# Long listing
In [4]: %ll
```

### Pro Tip: Combine with Python!

```python
# Get list of Python files
In [1]: py_files = !find . -name "*.py"

# Filter in Python
In [2]: natas_files = [f for f in py_files if 'natas' in f.lower()]

# Check each file
In [3]: for f in natas_files:
   ...:     size = !wc -l {f}
   ...:     print(f"{f}: {size[0]}")
```

## 📜 Path 3: Advanced Scrolls - The %store Magic

### The Problem: Lost Variables

Normally when you exit Python, everything is lost:

```python
In [1]: auth = natas_auth(9, 'W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl')
In [2]: findings = quick_scout(9, 'W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl')
In [3]: exit()

# Later...
$ ipython
In [1]: auth  # ❌ ERROR: NameError: name 'auth' is not defined
```

### The Solution: %store

**Store variables between sessions:**

```python
# First session - reconnaissance
In [1]: auth = natas_auth(9, 'W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl')

In [2]: findings = quick_scout(9, 'W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl')
🗺️  [Scouting Room]...
💬 HTML Comments:
   For security reasons, we now filter on certain characters

In [3]: %store auth
Stored 'auth' (tuple)

In [4]: %store findings
Stored 'findings' (dict)

In [5]: exit()
```

**Later (even after reboot!):**

```python
$ ipython

In [1]: %store -r auth

In [2]: auth
Out[2]: ('natas9', 'W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl')

In [3]: %store -r findings

In [4]: findings['comments']
Out[4]: ['For security reasons, we now filter on certain characters']

# Now continue your attack!
In [5]: bullets = forge_bullets('cat /etc/natas_webpass/natas10', wrapper='grep')
```

### %store Commands

```python
# Store a variable
%store var_name

# Restore a specific variable
%store -r var_name

# Restore ALL stored variables
%store -r

# List all stored variables
%store

# Delete a stored variable
%store -d var_name

# Clear all stored variables
%store -z
```

### Perfect for CTF Workflows!

```python
# Store credentials for each level
In [1]: natas9_pass = 'W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl'
In [2]: %store natas9_pass

In [3]: natas10_pass = 'D44EcsFkLxPIkAAKLosx8z3hxX1Z4MCE'
In [4]: %store natas10_pass

# Even store payloads that worked!
In [5]: working_payload = '.* /etc/natas_webpass/natas11 #'
In [6]: %store working_payload

# List everything you've saved
In [7]: %store
Stored variables:
natas9_pass  -> 'W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl'
natas10_pass -> 'D44EcsFkLxPIkAAKLosx8z3hxX1Z4MCE'
working_payload -> '.* /etc/natas_webpass/natas11 #'
```

## 🎮 Bonus: Custom %natas Magic

Our config includes a **custom magic command** for instant reconnaissance!

```python
# One-liner to scout a level
In [1]: %natas 9 W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl
🗺️  Scouting Natas Level 9...
[Scout results...]

✅ Stored 'auth' and 'findings' in namespace
📝 Use: sling_payload(natas_url(9), auth, '<payload>')

# Now 'auth' and 'findings' are ready to use!
In [2]: auth
Out[2]: ('natas9', 'W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl')

In [3]: findings['forms']
Out[3]: [{'action': '', 'method': 'POST', ...}]

# Attack!
In [4]: bullets = forge_bullets('cat /etc/natas_webpass/natas10')
In [5]: result = sling_payload(natas_url(9), auth, bullets[0])
```

## 🔧 Other Powerful IPython Features

### 1. Auto-PDB (Already Enabled!)

When code crashes, you automatically enter the debugger:

```python
In [1]: def buggy():
   ...:     x = [1, 2, 3]
   ...:     return x[10]  # Index error!

In [2]: buggy()
---------------------------------------------------------------------------
IndexError                                Traceback (most recent call last)
...
IndexError: list index out of range

> /root/<ipython-input-1-...>(3)buggy()
      1 def buggy():
      2     x = [1, 2, 3]
----> 3     return x[10]

ipdb> x  # Inspect variables!
[1, 2, 3]

ipdb> len(x)
3

ipdb> quit  # Exit debugger
```

### 2. Autoreload (Already Enabled!)

When you edit `inventory.py`, it automatically reloads:

```python
In [1]: from inventory import probe

In [2]: probe('http://example.com')  # Works

# [Edit inventory.py in another window, add print statement to probe()]

In [3]: probe('http://example.com')  # Automatically uses new code!
```

### 3. Introspection with ? and ??

```python
# Get help on any object
In [1]: probe?
Signature: probe(url, auth=None, params=None, data=None, method='GET', headers=None)
Docstring: Resilient HTTP request with error handling

# See the SOURCE CODE
In [2]: probe??
Source:
@cloak_of_resilience
def probe(url, auth=None, params=None, data=None, method='GET', headers=None):
    """Resilient HTTP request with error handling"""
    response = requests.request(
        method=method,
        url=url,
        auth=auth,
        ...
```

### 4. Benchmarking with %timeit

```python
In [1]: %timeit reveal_vial('aGVsbG8=')
1000 loops, best of 5: 234 µs per loop

In [2]: %timeit brew_vial('hello')
10000 loops, best of 5: 89.2 µs per loop
```

### 5. History Navigation

```python
# Search history with Ctrl-R (in Vi mode: ESC then /)
# Or view history:
In [1]: %history
   1: auth = natas_auth(9, 'pass')
   2: findings = quick_scout(9, 'pass')
   3: bullets = forge_bullets('cat /etc/natas_webpass/natas10')
   4: %history

# Replay a command from history
In [2]: %recall 2  # Runs line 2 again

# Save history to macro
In [3]: %macro attack 2-4  # Save lines 2-4 as 'attack' macro
In [4]: attack  # Run the macro!
```

## 🎯 Complete Workflow Example

Here's a complete Natas level using all the IPython powers:

```python
# Start IPython (inventory auto-loads!)
$ ipython

╔═══════════════════════════════════════════════════════════════╗
║                   🗡️  IPython Roguelike Mode  🛡️                ║
╚═══════════════════════════════════════════════════════════════╝

🗡️  IPython Roguelike Loadout equipped!

# Check if we have stored password
In [1]: %store
Stored variables:
natas8_pass -> 'a6bYe9PGz...'

# Restore it
In [2]: %store -r natas8_pass

# Quick scout using custom magic
In [3]: %natas 8 {natas8_pass}
🗺️  Scouting Natas Level 8...
✅ Stored 'auth' and 'findings' in namespace

# Analyze findings
In [4]: findings['forms'][0]['inputs']
Out[4]: [{'name': 'encodedSecret', 'type': 'text'}]

# Found encoded secret in page source (via manual inspection)
In [5]: encoded = '3d3d516343746d4d6d6c315669563362'

# Use the Potion!
In [6]: secret = reveal_vial(encoded, mode='natas8')
🧪 [Natas 8 Potion]: oubWYf2kBq

# Get the password
In [7]: probe(natas_url(8), auth, data={'encodedSecret': secret, 'submit': 'Submit'})
# [Response shows: "Access granted. The password for natas9 is W0mM..."]

# Extract loot
In [8]: result = _  # _ is previous output in IPython!
In [9]: loot = extract_loot(result.text)
💰 [Loot Found]: 1 items
   W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl

# Journal it
In [10]: scribe(8, loot[0], 'Natas8 encoding: reverse -> hex -> base64')
📖 [Scribed to Journal]: Level 8

# Store for next session
In [11]: natas9_pass = loot[0]
In [12]: %store natas9_pass
Stored 'natas9_pass' (str)

# Check your stored arsenal
In [13]: %store
Stored variables:
natas8_pass  -> 'a6bYe9PGz...'
natas9_pass  -> 'W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl'
```

## 🎨 Customization

### Add Your Own Aliases

Edit the config file and add to `c.AliasManager.user_aliases`:

```python
c.AliasManager.user_aliases = [
    # Existing...
    ('ll', 'ls -lah'),

    # Add your own:
    ('bb', 'cd ~/Documents/BugBounty'),
    ('journal', 'cat ~/Documents/BugBounty/natas_journal.md'),
    ('targets', 'cat ~/Documents/BugBounty/targets.txt'),
]
```

### Add Auto-Imports

Add to `c.InteractiveShellApp.exec_lines`:

```python
c.InteractiveShellApp.exec_lines = [
    # Existing...
    '%pdb on',
    'import os',

    # Add your favorites:
    'import base64',
    'import hashlib',
    'from urllib.parse import quote, unquote',
]
```

### Create Your Own Magics

Add to the custom magics section:

```python
@register_line_magic
def b64(line):
    """Quick base64 encode/decode

    Usage:
        %b64 encode hello
        %b64 decode aGVsbG8=
    """
    parts = line.split(maxsplit=1)
    if len(parts) != 2:
        print("Usage: %b64 encode|decode <data>")
        return

    mode, data = parts

    if mode == 'encode':
        import base64
        result = base64.b64encode(data.encode()).decode()
        print(result)
    elif mode == 'decode':
        import base64
        result = base64.b64decode(data).decode()
        print(result)
    else:
        print("Mode must be 'encode' or 'decode'")
```

## 🏆 IPython Quick Reference

Press `%quickref` in IPython for the full reference, or here are the essentials:

```
NAVIGATION:
  %cd <dir>          Change directory
  %pwd               Print working directory
  %ls                List files
  !command           Run shell command

PERSISTENCE:
  %store var         Save variable
  %store -r var      Restore variable
  %store             List stored

INTROSPECTION:
  obj?               Get help
  obj??              View source
  %timeit code       Benchmark
  %history           Show history

EDITING:
  %edit              Open $EDITOR
  %macro name n1-n2  Save lines as macro

DEBUGGING:
  %pdb               Toggle auto-debugger
  %debug             Debug last exception

MAGIC:
  %magic             List all magics
  %quickref          Quick reference
```

## 🚀 Ready to Conquer the Dungeon!

Your IPython is now a **legendary roguelike interface**:

✅ Vi Mode always on
✅ Natas inventory auto-loaded
✅ Variables survive crashes with %store
✅ Modules auto-reload during dev
✅ Debugger catches exceptions
✅ Custom %natas magic for quick recon
✅ Shell integration with !commands

Every time you boot IPython, you're **fully equipped** and ready to dive into the next level! 🗡️🛡️🧪

**May your exploits be legendary!** 🏰
