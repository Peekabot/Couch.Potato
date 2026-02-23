"""
setup.py - Peekabot Environment Setup
Run this first to prepare iSH or Pythonista for development.

iSH:
    python3 setup.py

Pythonista StaSh:
    python setup.py
"""

import sys
import os
import subprocess


def run(cmd: str):
    print(f"$ {cmd}")
    os.system(cmd)


def setup_ish():
    """Install system packages and Python dependencies in iSH."""
    packages = [
        "apk update",
        "apk add python3 py3-pip git vim curl",
        "pip3 install flask requests",
    ]
    for cmd in packages:
        run(cmd)

    # Create local config from example if not present
    config_example = os.path.join(os.path.dirname(__file__), "shared", "config.example.py")
    config_target = os.path.join(os.path.dirname(__file__), "shared", "config.py")
    if not os.path.exists(config_target) and os.path.exists(config_example):
        import shutil
        shutil.copy(config_example, config_target)
        print(f"Created {config_target} - edit it to add your API keys.")

    print("\niSH setup complete.")
    print("Next steps:")
    print("  1. Edit shared/config.py with your settings.")
    print("  2. cd ish/server && python3 flask_api.py")


def setup_pythonista():
    """Print setup instructions for Pythonista."""
    print(
        """
Pythonista Setup
================

1. Install StaSh (built-in shell for Pythonista) if not already installed:
   Open Pythonista console and run:
       import requests as r; exec(r.get('https://bit.ly/get-stash').text)

2. In StaSh, install dependencies:
       pip install requests

3. Clone this repo (if you haven't):
       git clone https://github.com/Peekabot/Couch.Potato.git

4. Copy shared/config.example.py to shared/config.py and fill in your values.

5. Open pythonista/ios_automations/lead_capture.py and tap Run.
"""
    )


def detect_environment() -> str:
    """Return 'ish', 'pythonista', or 'other'."""
    try:
        import console  # noqa: F401 - Pythonista-only module
        return "pythonista"
    except ImportError:
        pass

    if os.path.exists("/etc/ish-release"):
        return "ish"

    # Fallback: check uname
    try:
        uname = os.uname().sysname.lower()
        if "ish" in uname:
            return "ish"
    except AttributeError:
        pass

    return "other"


def main():
    env = detect_environment()
    print(f"Detected environment: {env}")

    if env == "ish":
        setup_ish()
    elif env == "pythonista":
        setup_pythonista()
    else:
        print("Unknown environment. Please follow the manual setup in SETUP_GUIDE.md.")


if __name__ == "__main__":
    main()
