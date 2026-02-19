# 🏰 The Master Scroll: Mind Castle System Administration

**What is this?** A formal implementation of the Method of Loci (Memory Palace technique) for security testing and bug bounty hunting. By mapping abstract technical concepts to physical archetypes, we leverage how the human brain evolved to remember spatial and physical information.

**Why it works:** Your brain remembers "I grabbed the GPS Scanner from the armory and cast it at the image upload endpoint" better than "I imported gps_exif_scanner and called analyze_image() on the POST /upload route."

**Core Principle:** Keep yourself in Flow State at 2 AM during a Natas level by thinking in archetypes, not implementation details.

---

## 🏰 The Castle Layout

Standing at the gates (the shell prompt `$`), you see the following rooms:

| Room | Technical Equivalent | Purpose | Key Actions |
|------|---------------------|---------|-------------|
| **The Gatehouse** | `~/.profile` or `~/.bashrc` | Entry rituals; sets the stage | Source aliases, set PATH, welcome banner |
| **The Armory** | `~/Couch.Potato/pythonista/` | Where Weapons (scripts) hang | Grab tools for the hunt |
| **The Alchemist's Lab** | IPython REPL | Transform raw data into knowledge | Brew potions (parse JSON, decode base64) |
| **The Library** | `pydoc`, `?`, `??` in IPython | Consult ancient scrolls (documentation) | Read source code, check function signatures |
| **The Ritual Circle** | IPython magic commands | Cast spells (automation) | `%run`, `%timeit`, `%pdb`, `%store` |
| **The Scrying Pool** | Safari / Chrome | Watch the world react to spells | View HTML responses, inspect network traffic |
| **The War Room** | `~/reports/` | Plan campaigns, track victories | Write bug reports, track bounties |
| **The Treasury** | `~/loot/` | Store captured secrets | API keys, credentials, sensitive data |

---

## ⚔️ The Armory: Your Weapons

Each tool is a **Weapon** with RPG-style stats. When you enter the Armory (`cd ~/Couch.Potato/pythonista`), you see:

### 🔍 GPS EXIF Scanner
**Class:** Information Disclosure Detector
**Rarity:** Uncommon
**Damage:** P3/P4 (Low-Medium severity)
**Range:** Image upload endpoints
**Special Ability:** Reveals hidden GPS coordinates in EXIF metadata

**Equip:**
```python
from gps_exif_scanner import analyze_image
```

**Attack Pattern:**
1. Target mobile app with image upload
2. Upload test image with GPS metadata
3. Download uploaded image from server
4. Cast scanner: `analyze_image(downloaded_image)`
5. If GPS present → 🚨 Vulnerability Found!

**Bounty Range:** $100-$500 (Information Disclosure)

**Best Used Against:**
- Social media apps
- Real estate platforms
- Dating apps
- Photo sharing services

---

### 🗡️ Mobile API Interceptor
**Class:** Multi-Target Exploit Tool
**Rarity:** Rare
**Damage:** P1-P3 (High-Critical severity)
**Range:** RESTful APIs, mobile backends
**Special Ability:** Tests IDOR, auth bypass, parameter tampering simultaneously

**Equip:**
```python
from mobile_api_interceptor import APITester
tester = APITester('https://api.target.com', auth_token='abc123')
```

**Attack Patterns:**

**Pattern 1: IDOR Slash**
```python
vulns = tester.test_idor('/users/{id}', range(1, 1000))
# Damage: $300-$1,000 per vulnerability
```

**Pattern 2: Auth Bypass Strike**
```python
vulns = tester.test_auth_bypass(['/admin', '/api/internal', '/payments'])
# Damage: $1,000-$5,000 (P1/P2)
```

**Pattern 3: Parameter Poison**
```python
vulns = tester.test_parameter_tampering('/checkout', {'user_id': 123, 'price': 99.99})
# Damage: $500-$3,000 (Logic flaw)
```

**Combo Attack:** Chain IDOR → Auth Bypass → Parameter Tampering for critical findings

**Bounty Range:** $300-$5,000

**Best Used Against:**
- E-commerce APIs
- Banking/fintech apps
- SaaS platforms
- Healthcare portals

---

### 🌉 SSH Bridge
**Class:** Orchestration Artifact
**Rarity:** Epic
**Damage:** N/A (Support tool)
**Range:** Remote machines (Mac, Windows, Linux)
**Special Ability:** Summons remote compute power from your iPhone

**Equip:**
```python
from ssh_bridge import SSHBridge
mac = SSHBridge('192.168.1.100', 'username', 'password')
```

**Ritual Patterns:**

**Ritual 1: Remote Command**
```python
result = mac.run('nmap -sV target.com')
# Invokes heavy scan on Mac while you stay mobile
```

**Ritual 2: Background Summon**
```python
mac.run_background('sqlmap -u "http://target.com?id=1" --batch')
# Starts long-running exploit while you sleep
```

**Ritual 3: File Retrieval**
```python
mac.run('cat /tmp/scan_results.txt')
# Brings knowledge back to your iPhone
```

**Strategic Value:** Turns your iPhone into a remote control for a distributed hacking fleet

**Best Used For:**
- Heavy port scans (nmap)
- Binary analysis (Ghidra, radare2)
- Burp Suite interception (Mac)
- Long-running fuzzing operations

---

### 📚 VRT Knowledge Agent
**Class:** Decision Engine
**Rarity:** Legendary
**Damage:** N/A (Intelligence tool)
**Range:** All vulnerability types
**Special Ability:** Instantly calculates priority and bounty range using Bugcrowd VRT taxonomy

**Equip:**
```python
from vrt_knowledge_agent import calculate_priority, get_vrt_categories
```

**Consult the Oracle:**
```python
priority = calculate_priority('broken_access_control', 'idor')
# Returns: "Priority: P2 (High)\nBounty Range: $500-$5,000\n..."

categories = get_vrt_categories()
# Shows all 50+ vulnerability types organized by category
```

**Strategic Use:** Before spending 2 hours testing for XSS (P3, $100-$500), check if auth bypass (P1, $1,000-$10,000) is possible. Hunt high-value targets first.

**Combo with Mobile API Interceptor:**
```python
# Find vulnerabilities
vulns = tester.test_idor('/users/{id}', range(1, 1000))

# Calculate priority
priority = calculate_priority('broken_access_control', 'idor')

# Decide: Worth reporting?
if 'P1' in priority or 'P2' in priority:
    print("🎯 High-value target! Write report immediately.")
```

---

## 🧪 The Alchemist's Lab: Brewing Potions (IPython REPL)

The Lab is where you **transform raw data** (HTTP responses, binary blobs, encoded strings) into **knowledge** (vulnerabilities, secrets, attack vectors).

### Standard Potions (Built-in Magic)

| Potion | Incantation | Effect |
|--------|-------------|--------|
| **Inspection Draught** | `dir(obj)` | Reveals all properties of mysterious objects |
| **Wisdom Scroll** | `obj?` | Summons documentation and type info |
| **Source Vision** | `obj??` | Reveals the actual source code |
| **Memory Mirror** | `%whos` | Shows everything currently in your cauldron |
| **Time Sight** | `%timeit code` | Measures how fast a spell executes |
| **Debug Cloak** | `%pdb` | Activates post-mortem debugging when spells fail |
| **History Tome** | `%history` | Shows your last 100 incantations |
| **Save Scroll** | `%save filename 1-10` | Writes your last 10 commands to a file |
| **Store Amulet** | `%store variable` | Persists variables between sessions |

### Custom Potions (Your Utility Belt)

See `.pythonrc.py` below for your personal toolkit.

---

## 🔮 The Ritual Circle: Magic Commands

These are the **spells** you cast in IPython. They're more powerful than regular Python because they bend reality (the interpreter).

### Offensive Spells (Exploitation)

```python
# Fireball: Run an exploit script
%run exploit_idor.py

# Chain Lightning: Execute multiple scripts in sequence
%run recon.py
%run scan.py
%run exploit.py

# Scrying: Monitor variables as script runs
%run -d script.py  # Debug mode

# Time Warp: Measure exploit speed
%timeit test_idor('/users/{id}', range(1, 1000))
```

### Defensive Spells (Debugging)

```python
# Shield: Activate automatic debugger on errors
%pdb on

# Healing: Fix broken state
%reset  # Clear all variables (nuclear option)
%reset_selective pattern  # Clear only matching variables

# Resurrection: Return to last safe state
%store -r  # Restore all saved variables
```

### Utility Spells (Productivity)

```python
# Teleport: Change directories
%cd ~/Couch.Potato/pythonista

# Summon: Load environment variables
%env API_KEY=abc123

# Bookmark: Save location for quick return
%bookmark armory ~/Couch.Potato/pythonista
%cd -b armory  # Teleport back instantly

# Macro: Record spell sequence
%macro my_macro 1-5  # Saves lines 1-5 as reusable macro
my_macro  # Cast the macro
```

---

## 🛡️ The Utility Belt (.pythonrc.py)

These functions are **always equipped** when you enter the Lab. They're part of your permanent loadout.

**Location:** `~/.pythonrc.py` (for standalone Python) or `~/.ipython/profile_default/startup/00-startup.py` (for IPython)

```python
# ~/.pythonrc.py - The Utility Belt

import sys, os, json
from pathlib import Path

# ═══════════════════════════════════════════════════
# 📖 THE SCRIBE - Session Management
# ═══════════════════════════════════════════════════

def scribe(filename="last_session.py"):
    """Saves your recent IPython history to a file.

    Usage:
        >>> scribe()  # Saves last 20 lines to last_session.py
        >>> scribe('my_exploit.py')  # Custom filename
    """
    try:
        from IPython import get_ipython
        get_ipython().run_line_magic('save', f'-a {filename} -r 1-20')
        print(f"📖 Session scribed to {filename}")
    except:
        print("❌ Scribe only works in IPython")


# ═══════════════════════════════════════════════════
# 👁️ THE EYE - Memory Inspection
# ═══════════════════════════════════════════════════

def eye():
    """Shows all variables in memory (cleaner than %whos).

    Usage:
        >>> api_key = "secret123"
        >>> response = requests.get("...")
        >>> eye()

    Output:
        api_key        str      10 chars
        response       Response 200 OK
    """
    try:
        from IPython import get_ipython
        get_ipython().run_line_magic('whos', '')
    except:
        # Fallback for non-IPython
        for name, obj in globals().items():
            if not name.startswith('_'):
                print(f"{name:20s} {type(obj).__name__}")


# ═══════════════════════════════════════════════════
# 🧪 THE ALCHEMIST - Data Transformation
# ═══════════════════════════════════════════════════

def brew(data, format='json'):
    """Transform raw data into readable form.

    Usage:
        >>> raw = '{"user_id": 123, "email": "test@example.com"}'
        >>> brew(raw)  # Pretty-prints JSON

        >>> brew(b'aGVsbG8gd29ybGQ=', format='base64')  # Decodes base64
    """
    if format == 'json':
        if isinstance(data, str):
            data = json.loads(data)
        print(json.dumps(data, indent=2, sort_keys=True))

    elif format == 'base64':
        import base64
        if isinstance(data, str):
            data = data.encode()
        decoded = base64.b64decode(data)
        print(decoded.decode('utf-8', errors='ignore'))

    elif format == 'hex':
        if isinstance(data, str):
            data = data.encode()
        print(data.hex())

    elif format == 'url':
        from urllib.parse import unquote
        print(unquote(data))


# ═══════════════════════════════════════════════════
# 🎯 THE HUNTER - Quick Vulnerability Tests
# ═══════════════════════════════════════════════════

def hunt_idor(base_url, endpoint, id_range):
    """Quick IDOR test from the REPL.

    Usage:
        >>> hunt_idor('https://api.target.com', '/users/{id}', range(100, 110))
        ✅ ID 103: ACCESSIBLE (200 OK)
        ✅ ID 107: ACCESSIBLE (200 OK)
        Found 2 vulnerable IDs
    """
    import requests

    vulnerable = []

    for user_id in id_range:
        url = f"{base_url}{endpoint}".replace('{id}', str(user_id))
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                print(f"✅ ID {user_id}: ACCESSIBLE (200 OK)")
                vulnerable.append(user_id)
            else:
                print(f"❌ ID {user_id}: {r.status_code}")
        except Exception as e:
            print(f"⚠️ ID {user_id}: ERROR - {e}")

    print(f"\nFound {len(vulnerable)} vulnerable IDs")
    return vulnerable


def hunt_secrets(text):
    """Scan text for common secrets (API keys, tokens, passwords).

    Usage:
        >>> response_body = requests.get('https://target.com/config.js').text
        >>> hunt_secrets(response_body)
        🚨 Found potential API key: AKIA...
    """
    import re

    patterns = {
        'AWS Key': r'AKIA[0-9A-Z]{16}',
        'Generic API Key': r'api[_-]?key["\s:=]+[A-Za-z0-9]{20,}',
        'GitHub Token': r'ghp_[A-Za-z0-9]{36}',
        'JWT': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        'Private Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    }

    found = []

    for name, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            for match in matches:
                print(f"🚨 Found potential {name}: {match[:20]}...")
                found.append((name, match))

    if not found:
        print("✅ No obvious secrets found")

    return found


# ═══════════════════════════════════════════════════
# 🗺️ THE CARTOGRAPHER - Navigation
# ═══════════════════════════════════════════════════

def map_castle():
    """Show the Mind Castle directory structure.

    Usage:
        >>> map_castle()
    """
    castle_map = """
    🏰 Mind Castle Layout

    The Gatehouse:    ~/.profile, ~/.bashrc
    The Armory:       ~/Couch.Potato/pythonista/
    The Library:      ~/Couch.Potato/methodology/
    The War Room:     ~/Couch.Potato/reports/
    The Treasury:     ~/Couch.Potato/loot/
    The Scrying Pool: Safari / Chrome (outside the castle)

    Current Location: {cwd}
    """.format(cwd=os.getcwd())

    print(castle_map)


def armory():
    """Quick teleport to the Armory and list weapons.

    Usage:
        >>> armory()
    """
    armory_path = Path.home() / 'Couch.Potato' / 'pythonista'

    if armory_path.exists():
        os.chdir(armory_path)
        print("⚔️ Entered the Armory\n")
        print("Available weapons:")
        for weapon in armory_path.glob('*.py'):
            print(f"  • {weapon.name}")
    else:
        print(f"❌ Armory not found at {armory_path}")


# ═══════════════════════════════════════════════════
# 🎪 INITIALIZATION
# ═══════════════════════════════════════════════════

def welcome():
    """Display welcome banner when entering the Lab."""
    banner = """
    ╔════════════════════════════════════════════════╗
    ║  🧪 Welcome to the Alchemist's Lab (IPython)  ║
    ║                                                ║
    ║  Your Utility Belt is equipped:               ║
    ║    • scribe()      - Save session history     ║
    ║    • eye()         - View memory              ║
    ║    • brew()        - Transform data           ║
    ║    • hunt_idor()   - Quick IDOR test          ║
    ║    • hunt_secrets()- Scan for secrets         ║
    ║    • map_castle()  - Show directory map       ║
    ║    • armory()      - Teleport to tools        ║
    ║                                                ║
    ║  Cast 'map_castle()' to see the layout        ║
    ╚════════════════════════════════════════════════╝
    """
    print(banner)

# Auto-run welcome banner
try:
    from IPython import get_ipython
    if get_ipython():
        welcome()
except:
    pass
```

**Installation:**
```bash
# For IPython (recommended)
mkdir -p ~/.ipython/profile_default/startup/
cp .pythonrc.py ~/.ipython/profile_default/startup/00-startup.py

# For standard Python
echo "PYTHONSTARTUP=~/.pythonrc.py" >> ~/.bashrc
source ~/.bashrc
```

---

## 🎯 Combat Scenarios: Mind Castle in Action

### Scenario 1: The "Identify Scroll" Ritual
**Problem:** You received a weird response from `requests.get()` and don't know what it is.

**Without Mind Castle (Cognitive overload):**
```python
>>> r = requests.get('https://api.target.com/users/123')
>>> # Uh... what is this object? Let me Google "python requests response methods"
>>> # Opens browser, reads docs, comes back 5 minutes later having forgotten context
```

**With Mind Castle (Flow state maintained):**
```python
>>> r = requests.get('https://api.target.com/users/123')
>>> dir(r)  # The Inspection Draught - see its properties
>>> r?      # The Wisdom Scroll - summon documentation
>>> r.json? # Check specific method
>>> brew(r.text)  # Transform to readable JSON
```
**Mental model:** "I found a mysterious loot item. Let me use my Identify Scroll on it." No context switching, no browser tabs, no cognitive load.

---

### Scenario 2: The 2 AM IDOR Hunt
**Problem:** Testing 1000 user IDs manually is soul-crushing.

**Without Mind Castle:**
```python
# Typing the same thing 1000 times
>>> requests.get('https://api.target.com/users/123').status_code
>>> requests.get('https://api.target.com/users/124').status_code
>>> # Zzzzz...
```

**With Mind Castle:**
```python
>>> hunt_idor('https://api.target.com', '/users/{id}', range(100, 1100))
# Your Utility Belt function does the grinding
# Mental model: "I'm casting Chain Lightning across all IDs"
```

**Even Better - Grab the right weapon from the Armory:**
```python
>>> armory()  # Teleport to armory
>>> from mobile_api_interceptor import APITester
>>> tester = APITester('https://api.target.com', 'token123')
>>> vulns = tester.test_idor('/users/{id}', range(100, 1100))
# Now you're wielding a legendary weapon, not casting basic spells
```

---

### Scenario 3: The Remote Heavy Scan
**Problem:** Need to run `nmap` on 1000 ports, but you're on your iPhone at a coffee shop.

**Without Mind Castle:**
```python
# Thinking: "Ugh, I need to SSH into my Mac, start nmap, then... how do I get the results back?"
# 10 minutes of manual SSH, command typing, forgetting to redirect output, etc.
```

**With Mind Castle:**
```python
>>> from ssh_bridge import SSHBridge
>>> mac = SSHBridge('192.168.1.100', 'username', 'password')
>>> mac.run_background('nmap -p- target.com -oN /tmp/nmap_results.txt')
>>> # Mental model: "I'm summoning my remote golem to do heavy lifting while I sip coffee"
>>> # 30 minutes later...
>>> results = mac.run('cat /tmp/nmap_results.txt')
>>> print(results['stdout'])
```

**Bonus - Save the results:**
```python
>>> scribe('target_nmap_session.py')  # Save the whole ritual for future use
```

---

## 🎮 Mind Castle → NetHack Mod Mapping

Your roguelike game already exists in this framework:

| NetHack Element | Mind Castle Equivalent | Real Tool |
|-----------------|------------------------|-----------|
| **Character Class** | Your role in the Lab | Mobile Hacker, API Hacker, Web Hacker |
| **Dungeon Level** | Bug bounty program | HackerOne (3000 levels), Bugcrowd (1000 levels) |
| **Weapon** | Script in Armory | `mobile_api_interceptor.py`, `gps_exif_scanner.py` |
| **Spell** | IPython magic command | `%run`, `%timeit`, `%pdb` |
| **Potion** | Utility Belt function | `brew()`, `hunt_idor()`, `hunt_secrets()` |
| **Scroll** | Documentation | `?`, `??`, `pydoc` |
| **Monster** | Vulnerability type | IDOR, XSS, SQLi, Auth Bypass |
| **Loot** | Bug bounty payment | $100 (P4) to $10,000 (P1) |
| **Death** | Account ban | Out-of-scope testing, duplicate report |
| **Save Point** | `%store` variable | Persist state between sessions |
| **Resurrection** | `%store -r` | Restore saved state |
| **Experience Points** | Reputation on platforms | HackerOne rank, Bugcrowd points |
| **Level Up** | Progression on IPython Power Ladder | Level 1 (Explorer) → Level 5 (Orchestrator) |

---

## 🧠 The Cognitive Science Behind It

### Why the Mind Castle Works

**1. Spatial Memory is Ancient**
- Humans evolved for 200,000 years navigating physical spaces
- You can remember 100+ items in a house you lived in 10 years ago
- Your brain has dedicated hardware (hippocampus) for spatial navigation

**2. Abstract Memory is Recent**
- Reading/writing: ~5,000 years old
- Programming: ~80 years old
- Your brain treats abstract concepts as "extra work"

**3. The Method of Loci Exploit**
- Map abstract concepts (HTTP requests) onto spatial locations (Armory)
- Your ancient brain does the heavy lifting
- Reduces cognitive load, maintains flow state

### Real-World Evidence

**Ancient Greek Orators:**
- Used Memory Palaces to memorize 3-hour speeches
- "I walk through my house, and at each room I find the next section of my speech"

**Competitive Memory Athletes:**
- Memorize 1000+ random digits using Memory Palaces
- "The first digit is a cat sitting in my bedroom, the second is a dog in my kitchen..."

**Your Bug Bounty Castle:**
- "When I need IDOR testing, I walk to the Armory and grab the API Interceptor"
- "When I find a weird response, I go to the Library and consult the scrolls (??)"
- "When I need remote compute, I use the SSH Bridge to summon my Mac golem"

---

## 🏆 The Ultimate Goal: Flow State at Scale

**Without Mind Castle:**
- Cognitive overhead: "What was that command again? Let me check the docs..."
- Context switching: Browser tabs, Stack Overflow, scattered tools
- Mental fatigue: Decision paralysis, analysis paralysis
- Result: 2 hours → 1 vulnerability found → $200 bounty → $100/hour

**With Mind Castle:**
- Muscle memory: "I need IDOR testing, I grab my weapon from the Armory"
- Single environment: Everything in IPython, no context switching
- Flow state: 2 AM bug hunting feels like playing a roguelike game
- Result: 2 hours → 5 vulnerabilities found → $2,000 bounty → $1,000/hour

**The Castle isn't goofy. It's cognitive performance enhancement.**

---

## 📜 Quick Reference Card

Print this and tape it to your monitor:

```
╔═══════════════════════════════════════════════════════════════╗
║                  🏰 MIND CASTLE QUICK REF                     ║
╠═══════════════════════════════════════════════════════════════╣
║ NAVIGATION                                                    ║
║   armory()           → Teleport to ~/pythonista/              ║
║   map_castle()       → Show directory layout                  ║
║   %bookmark name     → Save location                          ║
║   %cd -b name        → Return to bookmark                     ║
╠═══════════════════════════════════════════════════════════════╣
║ INSPECTION RITUALS                                            ║
║   dir(obj)           → See all properties                     ║
║   obj?               → Read documentation                     ║
║   obj??              → View source code                       ║
║   eye()              → Show all variables in memory           ║
╠═══════════════════════════════════════════════════════════════╣
║ DATA TRANSFORMATION                                           ║
║   brew(data)         → Pretty-print JSON                      ║
║   brew(data, 'base64') → Decode base64                        ║
║   brew(data, 'url')  → URL decode                             ║
╠═══════════════════════════════════════════════════════════════╣
║ QUICK ATTACKS                                                 ║
║   hunt_idor(url, endpoint, range) → Fast IDOR test           ║
║   hunt_secrets(text) → Scan for API keys/tokens              ║
╠═══════════════════════════════════════════════════════════════╣
║ SESSION MANAGEMENT                                            ║
║   scribe()           → Save last 20 lines to file             ║
║   %store var         → Persist variable across sessions       ║
║   %store -r          → Restore all saved variables            ║
║   %history           → View command history                   ║
╠═══════════════════════════════════════════════════════════════╣
║ WEAPONS (from Armory)                                         ║
║   mobile_api_interceptor → IDOR, auth bypass, param tamper   ║
║   gps_exif_scanner       → GPS metadata disclosure           ║
║   ssh_bridge             → Remote Mac/Windows orchestration  ║
║   vrt_knowledge_agent    → Priority + bounty calculation     ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## 🎯 Next Steps

**Level Up Your Castle:**

1. **Install the Utility Belt**
   ```bash
   mkdir -p ~/.ipython/profile_default/startup/
   cp .pythonrc.py ~/.ipython/profile_default/startup/00-startup.py
   ```

2. **Organize the Armory**
   ```bash
   cd ~/Couch.Potato/pythonista
   # All your weapons are already here!
   ```

3. **Create the War Room** (optional)
   ```bash
   mkdir -p ~/Couch.Potato/reports
   mkdir -p ~/Couch.Potato/loot
   ```

4. **Practice the Rituals**
   - Open IPython
   - Run `map_castle()` to orient yourself
   - Run `armory()` to see your weapons
   - Pick a VDP program and start hunting

5. **Build Muscle Memory**
   - Day 1-7: Use `hunt_idor()` utility function
   - Day 8-14: Graduate to `mobile_api_interceptor` weapon
   - Day 15-30: Add `ssh_bridge` for remote orchestration
   - Day 31+: You're thinking in the Castle naturally

**The goal:** When you close your eyes at 2 AM during a bug hunt, you see yourself walking through the Castle, not staring at code. That's when you know you've mastered the Method of Loci for hacking.

---

*"The difference between a junior and senior hacker isn't technical skill—it's cognitive architecture. Juniors think in commands. Seniors think in systems. Masters think in castles."*
