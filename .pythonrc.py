#!/usr/bin/env python3
"""
🏰 The Utility Belt - Mind Castle Functions

Install:
    # For IPython (recommended):
    mkdir -p ~/.ipython/profile_default/startup/
    cp .pythonrc.py ~/.ipython/profile_default/startup/00-startup.py

    # For standard Python:
    echo "PYTHONSTARTUP=~/Couch.Potato/.pythonrc.py" >> ~/.bashrc
    source ~/.bashrc

Usage:
    These functions are automatically available in your IPython REPL.
    Just open IPython and start using them!
"""

import sys
import os
import json
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════════
# 📖 THE SCRIBE - Session Management
# ═══════════════════════════════════════════════════════════════════════════

def scribe(filename="last_session.py"):
    """Saves your recent IPython history to a file.

    Usage:
        >>> scribe()  # Saves last 20 lines to last_session.py
        >>> scribe('my_exploit.py')  # Custom filename

    Example:
        >>> hunt_idor('https://api.target.com', '/users/{id}', range(100, 110))
        >>> scribe('target_idor_test.py')  # Save the session
    """
    try:
        from IPython import get_ipython
        ip = get_ipython()
        if ip:
            ip.run_line_magic('save', f'-a {filename} -r 1-20')
            print(f"📖 Session scribed to {filename}")
        else:
            print("❌ Not running in IPython")
    except ImportError:
        print("❌ Scribe only works in IPython")


# ═══════════════════════════════════════════════════════════════════════════
# 👁️ THE EYE - Memory Inspection
# ═══════════════════════════════════════════════════════════════════════════

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
        ip = get_ipython()
        if ip:
            ip.run_line_magic('whos', '')
        else:
            _eye_fallback()
    except ImportError:
        _eye_fallback()


def _eye_fallback():
    """Fallback eye() implementation for non-IPython."""
    print(f"{'Variable':<20} {'Type':<15} {'Value'}")
    print("=" * 60)
    for name, obj in globals().items():
        if not name.startswith('_') and name not in ['In', 'Out']:
            value_repr = repr(obj)
            if len(value_repr) > 30:
                value_repr = value_repr[:27] + "..."
            print(f"{name:<20} {type(obj).__name__:<15} {value_repr}")


# ═══════════════════════════════════════════════════════════════════════════
# 🧪 THE ALCHEMIST - Data Transformation
# ═══════════════════════════════════════════════════════════════════════════

def brew(data, format='json'):
    """Transform raw data into readable form.

    Usage:
        >>> raw = '{"user_id": 123, "email": "test@example.com"}'
        >>> brew(raw)  # Pretty-prints JSON

        >>> brew(b'aGVsbG8gd29ybGQ=', format='base64')  # Decodes base64

        >>> brew('Hello%20World', format='url')  # URL decode

        >>> brew(b'\\x48\\x65\\x6c\\x6c\\x6f', format='hex')  # Hex to string

    Formats:
        - 'json': Pretty-print JSON (default)
        - 'base64': Decode base64
        - 'hex': Display as hex or decode from hex
        - 'url': URL decode
    """
    if format == 'json':
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError as e:
                print(f"❌ Invalid JSON: {e}")
                return
        print(json.dumps(data, indent=2, sort_keys=True))

    elif format == 'base64':
        import base64
        if isinstance(data, str):
            data = data.encode()
        try:
            decoded = base64.b64decode(data)
            print(decoded.decode('utf-8', errors='ignore'))
        except Exception as e:
            print(f"❌ Base64 decode failed: {e}")

    elif format == 'hex':
        if isinstance(data, str):
            # Try to decode from hex string
            try:
                data = bytes.fromhex(data.replace('\\x', '').replace(' ', ''))
                print(data.decode('utf-8', errors='ignore'))
            except:
                # If that fails, encode to hex
                print(data.encode().hex())
        else:
            print(data.hex())

    elif format == 'url':
        from urllib.parse import unquote
        print(unquote(data))

    else:
        print(f"❌ Unknown format: {format}")
        print("Available formats: json, base64, hex, url")


# ═══════════════════════════════════════════════════════════════════════════
# 🎯 THE HUNTER - Quick Vulnerability Tests
# ═══════════════════════════════════════════════════════════════════════════

def hunt_idor(base_url, endpoint, id_range, auth_token=None):
    """Quick IDOR test from the REPL.

    Usage:
        >>> hunt_idor('https://api.target.com', '/users/{id}', range(100, 110))
        ✅ ID 103: ACCESSIBLE (200 OK)
        ✅ ID 107: ACCESSIBLE (200 OK)
        Found 2 vulnerable IDs

        >>> hunt_idor('https://api.target.com', '/users/{id}', range(100, 110),
        ...           auth_token='Bearer abc123')

    Args:
        base_url: Base URL of the API
        endpoint: Endpoint with {id} placeholder
        id_range: Range or list of IDs to test
        auth_token: Optional auth token (will be added as Authorization header)

    Returns:
        List of vulnerable IDs
    """
    try:
        import requests
    except ImportError:
        print("❌ requests library not installed. Run: pip install requests")
        return []

    vulnerable = []
    headers = {}
    if auth_token:
        if not auth_token.startswith('Bearer '):
            auth_token = f'Bearer {auth_token}'
        headers['Authorization'] = auth_token

    print(f"🎯 Testing {len(list(id_range))} IDs on {endpoint}...\n")

    for user_id in id_range:
        url = f"{base_url}{endpoint}".replace('{id}', str(user_id))
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                print(f"✅ ID {user_id}: ACCESSIBLE (200 OK)")
                vulnerable.append(user_id)
            elif r.status_code == 401:
                print(f"🔒 ID {user_id}: UNAUTHORIZED (need auth)")
            elif r.status_code == 403:
                print(f"🚫 ID {user_id}: FORBIDDEN (auth worked, but access denied)")
            elif r.status_code == 404:
                print(f"❌ ID {user_id}: NOT FOUND")
            else:
                print(f"⚠️  ID {user_id}: {r.status_code}")
        except requests.exceptions.Timeout:
            print(f"⏱️  ID {user_id}: TIMEOUT")
        except Exception as e:
            print(f"⚠️  ID {user_id}: ERROR - {e}")

    print(f"\n🎯 Found {len(vulnerable)} vulnerable IDs")
    if vulnerable:
        print(f"📝 Vulnerable IDs: {vulnerable}")

    return vulnerable


def hunt_secrets(text):
    """Scan text for common secrets (API keys, tokens, passwords).

    Usage:
        >>> response_body = requests.get('https://target.com/config.js').text
        >>> hunt_secrets(response_body)
        🚨 Found potential API key: AKIA...

        >>> with open('app.js', 'r') as f:
        ...     hunt_secrets(f.read())

    Detects:
        - AWS Keys (AKIA...)
        - Generic API keys
        - GitHub tokens (ghp_...)
        - JWT tokens
        - Private keys (-----BEGIN...)
        - Slack tokens (xoxb-...)
        - Passwords in common formats

    Returns:
        List of (secret_type, secret_value) tuples
    """
    import re

    patterns = {
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': r'aws(.{0,20})?["\'][0-9a-zA-Z/+]{40}["\']',
        'Generic API Key': r'api[_-]?key["\s:=]+[A-Za-z0-9]{20,}',
        'GitHub Token': r'ghp_[A-Za-z0-9]{36}',
        'GitHub OAuth': r'gho_[A-Za-z0-9]{36}',
        'JWT Token': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        'RSA Private Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        'Slack Token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
        'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
        'Password (common)': r'password["\s:=]+["\'][^"\']{8,}["\']',
        'Bearer Token': r'Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    }

    found = []

    for name, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            for match in matches:
                # Truncate long secrets for display
                display_match = match if len(match) < 50 else match[:47] + "..."
                print(f"🚨 Found potential {name}: {display_match}")
                found.append((name, match))

    if not found:
        print("✅ No obvious secrets found")
    else:
        print(f"\n🎯 Total: {len(found)} potential secrets found")

    return found


def hunt_endpoints(url):
    """Quick recon: find common API endpoints and admin panels.

    Usage:
        >>> hunt_endpoints('https://api.target.com')
        ✅ Found: /api/v1/users
        ✅ Found: /admin
        ❌ Not found: /api/v1/internal

    Returns:
        List of discovered endpoints
    """
    try:
        import requests
    except ImportError:
        print("❌ requests library not installed. Run: pip install requests")
        return []

    common_endpoints = [
        '/api/v1/users',
        '/api/v2/users',
        '/api/users',
        '/users',
        '/admin',
        '/api/admin',
        '/api/internal',
        '/api/debug',
        '/api/config',
        '/api/settings',
        '/.env',
        '/config.json',
        '/swagger.json',
        '/api-docs',
        '/graphql',
        '/api/graphql',
    ]

    found = []

    print(f"🔍 Scanning {url} for common endpoints...\n")

    for endpoint in common_endpoints:
        test_url = f"{url.rstrip('/')}{endpoint}"
        try:
            r = requests.get(test_url, timeout=3)
            if r.status_code == 200:
                print(f"✅ Found ({r.status_code}): {endpoint}")
                found.append(endpoint)
            elif r.status_code in [401, 403]:
                print(f"🔒 Protected ({r.status_code}): {endpoint}")
                found.append(endpoint)
            else:
                print(f"❌ Not found ({r.status_code}): {endpoint}")
        except requests.exceptions.Timeout:
            print(f"⏱️  Timeout: {endpoint}")
        except Exception as e:
            print(f"⚠️  Error on {endpoint}: {e}")

    print(f"\n🎯 Found {len(found)} endpoints")
    return found


# ═══════════════════════════════════════════════════════════════════════════
# 🗺️ THE CARTOGRAPHER - Navigation
# ═══════════════════════════════════════════════════════════════════════════

def map_castle():
    """Show the Mind Castle directory structure.

    Usage:
        >>> map_castle()
    """
    castle_map = """
    ╔═══════════════════════════════════════════════════════════╗
    ║              🏰 Mind Castle Layout                        ║
    ╠═══════════════════════════════════════════════════════════╣
    ║ The Gatehouse:    ~/.profile, ~/.bashrc                  ║
    ║ The Armory:       ~/Couch.Potato/pythonista/             ║
    ║ The Library:      ~/Couch.Potato/methodology/            ║
    ║ The War Room:     ~/Couch.Potato/reports/                ║
    ║ The Treasury:     ~/Couch.Potato/loot/                   ║
    ║ The Scrying Pool: Safari / Chrome (outside the castle)   ║
    ╠═══════════════════════════════════════════════════════════╣
    ║ Current Location: {cwd:<39} ║
    ╚═══════════════════════════════════════════════════════════╝
    """.format(cwd=os.getcwd())

    print(castle_map)


def armory():
    """Quick teleport to the Armory and list weapons.

    Usage:
        >>> armory()
        ⚔️ Entered the Armory

        Available weapons:
          • mobile_api_interceptor.py
          • gps_exif_scanner.py
          • ssh_bridge.py
          • vrt_knowledge_agent.py
    """
    # Try multiple possible locations
    possible_paths = [
        Path.home() / 'Couch.Potato' / 'pythonista',
        Path('/home/user/Couch.Potato/pythonista'),
        Path.cwd() / 'pythonista',
    ]

    armory_path = None
    for path in possible_paths:
        if path.exists():
            armory_path = path
            break

    if armory_path:
        os.chdir(armory_path)
        print("⚔️ Entered the Armory\n")
        print("Available weapons:")
        weapons = list(armory_path.glob('*.py'))
        if weapons:
            for weapon in sorted(weapons):
                if weapon.name != '__init__.py':
                    print(f"  • {weapon.name}")
        else:
            print("  (No weapons found - create some tools!)")
    else:
        print("❌ Armory not found. Searched:")
        for path in possible_paths:
            print(f"  • {path}")


def library():
    """Quick teleport to the Library (methodology docs).

    Usage:
        >>> library()
    """
    possible_paths = [
        Path.home() / 'Couch.Potato' / 'methodology',
        Path('/home/user/Couch.Potato/methodology'),
        Path.cwd() / 'methodology',
    ]

    library_path = None
    for path in possible_paths:
        if path.exists():
            library_path = path
            break

    if library_path:
        os.chdir(library_path)
        print("📚 Entered the Library\n")
        print("Available scrolls:")
        scrolls = list(library_path.glob('*.md'))
        if scrolls:
            for scroll in sorted(scrolls):
                print(f"  • {scroll.name}")
        else:
            print("  (No scrolls found)")
    else:
        print("❌ Library not found")


# ═══════════════════════════════════════════════════════════════════════════
# 🎪 INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════

def welcome():
    """Display welcome banner when entering the Lab."""
    banner = """
    ╔════════════════════════════════════════════════╗
    ║  🧪 Welcome to the Alchemist's Lab (IPython)  ║
    ║                                                ║
    ║  Your Utility Belt is equipped:               ║
    ║    • scribe()         - Save session history  ║
    ║    • eye()            - View memory           ║
    ║    • brew(data)       - Transform data        ║
    ║    • hunt_idor()      - Quick IDOR test       ║
    ║    • hunt_secrets()   - Scan for secrets      ║
    ║    • hunt_endpoints() - Find API endpoints    ║
    ║    • map_castle()     - Show directory map    ║
    ║    • armory()         - Teleport to tools     ║
    ║    • library()        - Teleport to docs      ║
    ║                                                ║
    ║  Cast 'map_castle()' to see the layout        ║
    ║  Cast 'armory()' to see your weapons          ║
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


# ═══════════════════════════════════════════════════════════════════════════
# 🔧 HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def help_castle():
    """Show all Mind Castle commands with examples.

    Usage:
        >>> help_castle()
    """
    help_text = """
    🏰 MIND CASTLE COMMAND REFERENCE

    ═══════════════════════════════════════════════════════════════
    NAVIGATION
    ═══════════════════════════════════════════════════════════════
    map_castle()          → Show castle layout and current location
    armory()              → Teleport to tools directory
    library()             → Teleport to methodology docs

    ═══════════════════════════════════════════════════════════════
    INSPECTION RITUALS
    ═══════════════════════════════════════════════════════════════
    dir(obj)              → See all properties of an object
    obj?                  → Read documentation (IPython)
    obj??                 → View source code (IPython)
    eye()                 → Show all variables in memory

    ═══════════════════════════════════════════════════════════════
    DATA TRANSFORMATION
    ═══════════════════════════════════════════════════════════════
    brew(data)            → Pretty-print JSON
    brew(data, 'base64')  → Decode base64
    brew(data, 'hex')     → Hex encode/decode
    brew(data, 'url')     → URL decode

    ═══════════════════════════════════════════════════════════════
    HUNTING TOOLS
    ═══════════════════════════════════════════════════════════════
    hunt_idor(url, '/api/{id}', range(1, 100))
        → Test for IDOR vulnerabilities

    hunt_secrets(text)
        → Scan text for API keys, tokens, passwords

    hunt_endpoints('https://api.target.com')
        → Discover common API endpoints

    ═══════════════════════════════════════════════════════════════
    SESSION MANAGEMENT
    ═══════════════════════════════════════════════════════════════
    scribe()              → Save last 20 commands to file
    scribe('test.py')     → Save to specific file
    %store var            → Persist variable across sessions (IPython)
    %store -r             → Restore saved variables (IPython)

    ═══════════════════════════════════════════════════════════════
    For full documentation, read MASTER_SCROLL.md
    ═══════════════════════════════════════════════════════════════
    """
    print(help_text)


# Alias for discoverability
def castle():
    """Shortcut for map_castle()"""
    map_castle()
