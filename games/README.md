# 🎮 Bug Bounty Dungeon

**A roguelike that teaches security research through play.**

Win by **finding bugs in the game itself**.

---

## What Is This?

A text-based dungeon crawler with **intentional vulnerabilities**.

Traditional roguelikes teach you to kill monsters.
This teaches you to **break systems**.

**Two victory conditions:**
1. ❌ Reach the treasure vault (boring)
2. ✅ Find and exploit 3+ bugs (real victory)

---

## Quick Start

```bash
cd ~/Couch.Potato/games
python3 bug_bounty_dungeon.py
```

**Commands:**
- `north`, `south`, `east`, `west` - Move
- `look` - Examine room
- `buy` - Trade with merchant
- `train` - Increase strength
- `save` / `load` - Save game
- `help` - Show commands

**Hints:**
- The source code is intentionally simple
- Save files are plain JSON
- Hidden commands exist
- Think adversarially

---

## The Bugs (5 Intentional Vulnerabilities)

### Bug #1: Price Manipulation

**Security concept:** Trust boundary violation

**What it is:**
```python
# The merchant trusts your gold value
if self.player.gold >= price:
    self.player.gold -= price
```

**How to exploit:**
1. Save the game
2. Edit `bug_bounty_dungeon_save.json`
3. Set `"gold": -999`
4. Load game
5. Buy expensive items with negative gold

**Real-world analog:**
```http
POST /checkout
{
  "total": 0.01  ← Client sets price
}
```

This is **exactly** what substrate analyzer finds.

---

### Bug #2: IDOR (Insecure Direct Object Reference)

**Security concept:** Missing authorization check

**What it is:**
```python
def goto(self, room_id_str):
    # No authorization check!
    room_id = int(room_id_str)
    self.player.room_id = room_id
```

**How to exploit:**
```
> goto 99
```

Directly access Room 99 (Admin Vault) without normal progression.

**Real-world analog:**
```http
GET /api/users/1/profile   ← Your profile
GET /api/users/2/profile   ← Admin's profile (IDOR)
```

---

### Bug #3: Command Injection

**Security concept:** Improper input parsing

**What it is:**
```python
# Semicolon splits commands
if ';' in cmd:
    for part in cmd.split(';'):
        self.execute_single_command(part)
```

**How to exploit:**
```
> move north;goto 99;buy
```

Execute multiple commands at once.

**Real-world analog:**
```bash
# OS command injection
system("ping " + user_input)

# User provides: "8.8.8.8; cat /etc/passwd"
```

---

### Bug #4: Save File Tampering

**Security concept:** Data integrity failure

**What it is:**
```python
# No signature or integrity check
with open('save.json', 'r') as f:
    data = json.load(f)
    # Trusts everything
```

**How to exploit:**
1. Save game
2. Edit JSON file:
```json
{
  "player": {
    "level": 99,
    "gold": 99999,
    "room_id": 3
  }
}
```
3. Load game
4. Instant win

**Real-world analog:**
- JWT manipulation (weak secret)
- Cookie tampering
- Client-side validation only

---

### Bug #5: Integer Overflow

**Security concept:** Numeric overflow

**What it is:**
```python
# No upper bound check
self.player.strength += 100

if self.player.strength > 10000:
    self.player.strength = -1  # Overflow
```

**How to exploit:**
```
> train
> train
> train
...
(repeat until strength wraps to negative)
```

**Real-world analog:**
```c
// Integer overflow in C
uint8_t value = 255;
value += 1;  // Wraps to 0
```

---

## How This Teaches Bug Bounty Skills

### Skill 1: Reading Systems as Machines

**In game:** Understand how commands affect state
**In real life:** Understand how API calls mutate database

### Skill 2: Trust Boundary Analysis

**In game:** Merchant trusts player's gold value
**In real life:** Server trusts client-supplied price

This IS substrate boundary analysis.

### Skill 3: Edge Case Exploitation

**In game:** Negative gold, room ID 99
**In real life:** Negative prices, hidden API endpoints

### Skill 4: State Manipulation

**In game:** Edit save file to change state
**In real life:** Edit JWT to change role

### Skill 5: Reading Source Code

**In game:** Find hidden `goto` command
**In real life:** Audit API code for vulnerabilities

---

## Progression Path

### Phase 1: Play Normally

Try to reach Room 3 (Treasure Vault) by leveling up.

**You'll realize:** This takes too long.

### Phase 2: Explore

Try different commands. Read the source code.

**You'll find:** Hidden commands, exploitable logic.

### Phase 3: Exploit

Use bugs to win faster.

**You'll learn:** Breaking systems is more effective than playing by the rules.

### Phase 4: Understand

Map game bugs to real security concepts.

**You'll realize:** This is how real bug bounties work.

---

## How This Maps to Real Bug Bounties

| Game Mechanic | Real Security Concept | Substrate Framework |
|---------------|----------------------|---------------------|
| Merchant prices | API price parameters | Trust boundary violation |
| Room access | API authorization | Missing access control |
| Command parsing | Input handling | Injection vulnerabilities |
| Save files | Session/state storage | Data integrity |
| Strength overflow | Numeric limits | Integer overflow |

**The game IS the methodology.**

---

## Advanced Challenges

### Challenge 1: Find All 5 Bugs

Can you discover all intentional vulnerabilities?

### Challenge 2: Win in < 10 Turns

Use bugs to reach victory condition in minimal moves.

### Challenge 3: Chain Exploits

Combine multiple bugs for maximum impact.

**Example chain:**
```
1. Edit save file (Bug #4) to set gold = 999999
2. Load game
3. Buy Level Up Scroll (Bug #1 - price manipulation)
4. Use 'goto 3' (Bug #2 - IDOR) to reach treasure
```

### Challenge 4: Read the Source

Find the bugs by auditing `bug_bounty_dungeon.py`.

This is **exactly** what you do in real bug bounties.

---

## What's Next?

After beating this game:

1. ✅ You understand substrate thinking
2. ✅ You've practiced exploit mindset
3. ✅ You can read code for vulnerabilities

**Now apply it to real targets:**

```bash
cd ~/Couch.Potato/scripts

# Analyze real API
python3 substrate_analyzer.py --openapi target-api.json

# Same bugs, different substrate
```

The game taught you the **pattern**.
The analyzer finds it in **real APIs**.

---

## For Course Students

**This game is Module 0 of the Bug Bounty Course.**

**Before learning tools:**
1. Play this game
2. Find 3+ bugs
3. Understand why they exist

**Then move to:**
- Substrate Boundary Analysis (theory)
- Practice Lab (real web app)
- Real bug bounty programs

**The game teaches thinking.**
**The tools teach application.**

---

## Technical Details

**Implementation:**
- Pure Python 3
- No external dependencies
- ~400 LOC total
- Readable, auditable code
- JSON save files

**Design philosophy:**
- Small functions (<60 LOC)
- Clear variable names
- No async magic
- Intentional simplicity

**This matches the Couch.Potato doctrine.**

---

## Bug Reports (Meta)

Found a bug that's NOT intentional?

**That's even better.**

Document it like a real bug bounty report:
1. Steps to reproduce
2. Expected behavior
3. Actual behavior
4. Security impact

Then submit a pull request.

---

## Credits

Built to demonstrate substrate boundary analysis:
> "Exploits concentrate where irreversible state changes
> are separated from their validation constraints
> across a trust gradient."

**This game proves it.**

---

## Files

```
games/
├── bug_bounty_dungeon.py      ← The game
├── README.md                   ← This file
└── bug_bounty_dungeon_save.json  ← Save file (created on first save)
```

---

**This is not pattern matching. This is structural thinking.** ⚛️

**Play it. Break it. Learn from it.** 🎮
