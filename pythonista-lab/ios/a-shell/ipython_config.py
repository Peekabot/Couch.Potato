#!/usr/bin/env python3
"""
IPython Roguelike Configuration
================================
The legendary IPython profile - automatically equips your artifacts on boot!

Installation:
    ipython profile create
    cp ipython_config.py ~/.ipython/profile_default/ipython_config.py

Or for testing:
    ipython --config=ipython_config.py
"""

c = get_config()  # noqa: F821

# ==============================================================================
# THE VIM CLOAK - Vi Editing Mode
# ==============================================================================
# Your fingers know the ancient ways. Why betray them in the REPL?

c.TerminalInteractiveShell.editing_mode = 'vi'

# Show Vi mode indicator in prompt
c.TerminalInteractiveShell.prompt_includes_vi_mode = True

# ==============================================================================
# AUTO-EQUIP INVENTORY - Load Roguelike Utilities
# ==============================================================================
# Automatically import the Natas loadout when IPython starts

c.InteractiveShellApp.exec_lines = [
    # Enable automatic debugger on exceptions (Save State before boss fight!)
    '%pdb on',

    # Essential imports
    'import os',
    'import sys',
    'import json',
    'from pathlib import Path',

    # Auto-load the Roguelike Inventory
    '''
import sys
from pathlib import Path
inventory_dir = Path.home() / "Documents" / "Couch.Potato" / "pythonista-lab" / "ios" / "a-shell"
if inventory_dir.exists():
    sys.path.insert(0, str(inventory_dir))
    try:
        from inventory import *
        print("\\n🗡️  IPython Roguelike Loadout equipped!")
        print("📦 Artifacts: probe, reveal_vial, sling_payload, scout_room, scribe")
        print("⚡ Quick: natas_auth, natas_url, quick_scout, quick_run\\n")
    except ImportError as e:
        print(f"⚠️  Could not auto-equip inventory: {e}")
    ''',
]

# ==============================================================================
# MAGIC ALIASES - Quick Navigation Scrolls
# ==============================================================================
# IPython already has ! for shell commands, but these are shortcuts

c.AliasManager.user_aliases = [
    ('ll', 'ls -lah'),
    ('la', 'ls -A'),
    ('docs', 'cd ~/Documents/Couch.Potato/pythonista-lab'),
    ('natas', 'cd ~/Documents/Couch.Potato/pythonista-lab/ios/a-shell'),
]

# ==============================================================================
# AUTORELOAD - Keep Spells Fresh
# ==============================================================================
# Automatically reload modules when they change (great for development)

c.InteractiveShellApp.extensions = ['autoreload']
c.InteractiveShellApp.exec_lines.append('%autoreload 2')

# ==============================================================================
# PERSISTENT STORAGE - The %store Artifact
# ==============================================================================
# Variables survive even if your session crashes!
#
# Usage:
#   >>> auth = natas_auth(9, 'password')
#   >>> %store auth
#   >>> exit()
#
#   [Later, in new IPython session]
#   >>> %store -r auth
#   >>> auth
#   ('natas9', 'password')

# Already enabled by default, but let's document it
# Use: %store var_name        - Store variable
#      %store -r var_name     - Restore variable
#      %store -d var_name     - Delete stored variable
#      %store                 - List all stored variables

# ==============================================================================
# TERMINAL COLORS - Dungeon Aesthetics
# ==============================================================================

c.TerminalInteractiveShell.highlighting_style = 'monokai'
c.TerminalInteractiveShell.true_color = True

# ==============================================================================
# HISTORY - The Chronicler's Journal
# ==============================================================================

c.HistoryManager.hist_file = '~/.ipython/profile_default/history.sqlite'
c.HistoryAccessor.hist_file = '~/.ipython/profile_default/history.sqlite'

# Keep a LOT of history (10,000 commands)
c.HistoryManager.db_cache_size = 10000

# ==============================================================================
# STARTUP MESSAGE
# ==============================================================================

c.TerminalInteractiveShell.banner1 = '''
╔═══════════════════════════════════════════════════════════════╗
║                   🗡️  IPython Roguelike Mode  🛡️                ║
╚═══════════════════════════════════════════════════════════════╝

    Vi Mode: ✅ Enabled (ESC to command mode, i to insert)
    Auto-PDB: ✅ Enabled (Exceptions trigger debugger)
    Autoreload: ✅ Enabled (Modules refresh on change)

    🎮 Navigation Magics:
       %cd ~/path          - Change directory
       %pwd                - Print working directory
       %ls                 - List files
       !command            - Run any shell command

    💾 Persistence Magics:
       %store var          - Save variable for next session
       %store -r var       - Restore saved variable
       %store              - List all stored variables

    🔍 Introspection Magics:
       ?obj                - Get help on object
       obj?                - Same as above
       obj??               - View source code
       %timeit code        - Benchmark code
       %prun code          - Profile code

    📊 Useful Magics:
       %history            - Show command history
       %macro name n1-n2   - Save lines n1-n2 as macro
       %edit               - Open editor
       %reset              - Clear namespace

    Type %quickref for IPython quick reference
'''

# ==============================================================================
# ADVANCED: CUSTOM MAGICS
# ==============================================================================

c.InteractiveShellApp.exec_lines.append('''
# Custom magic: %natas - Quick start a Natas level
from IPython.core.magic import register_line_magic

@register_line_magic
def natas(line):
    """Quick reconnaissance for a Natas level

    Usage:
        %natas 9 password_here
    """
    parts = line.split()
    if len(parts) != 2:
        print("Usage: %natas <level> <password>")
        return

    level = int(parts[0])
    password = parts[1]

    # Import if not already available
    try:
        from inventory import quick_scout, natas_auth, natas_url
    except ImportError:
        print("⚠️  Inventory not loaded. Run: from inventory import *")
        return

    print(f"🗺️  Scouting Natas Level {level}...")
    findings = quick_scout(level, password)

    # Also store auth for reuse
    auth = natas_auth(level, password)
    get_ipython().user_ns['auth'] = auth
    get_ipython().user_ns['findings'] = findings

    print(f"\\n✅ Stored 'auth' and 'findings' in namespace")
    print(f"📝 Use: sling_payload(natas_url({level}), auth, '<payload>')")

# Delete the decorator to avoid cluttering namespace
del register_line_magic
''')

# ==============================================================================
# SAFETY - Confirm Dangerous Operations
# ==============================================================================

c.TerminalInteractiveShell.confirm_exit = False  # Don't confirm on Ctrl-D (we're warriors!)

# ==============================================================================
# PERFORMANCE
# ==============================================================================

# Cache for faster startup
c.InteractiveShell.cache_size = 1000

# ==============================================================================
# The configuration is complete, adventurer. May your REPL sessions be legendary!
# ==============================================================================
