"""
Shortcut Integration - Pythonista iOS Automation
Receive data from iOS Shortcuts app via x-callback-url / appex,
process it, and optionally call back to the Shortcuts workflow.

Usage example in iOS Shortcuts:
  1. Add a "Run Script over SSH" or "Run Pythonista Script" action.
  2. Pass text/URL as sys.argv[1].
  3. The result is printed to stdout and available in Shortcuts.

Run this in Pythonista (via a Shortcuts "Run Script" action or manually).
"""

import sys
import json


def handle_input(raw: str) -> dict:
    """
    Process text received from iOS Shortcuts.
    Returns a dict that will be JSON-encoded back to the Shortcut.
    """
    result = {
        "original": raw,
        "length": len(raw),
        "word_count": len(raw.split()),
        "upper": raw.upper(),
    }

    # Try to parse as JSON for structured data
    try:
        parsed = json.loads(raw)
        result["parsed"] = parsed
    except (json.JSONDecodeError, TypeError):
        pass

    return result


def main():
    if len(sys.argv) < 2:
        # Running interactively in Pythonista — use a sample payload
        raw = "Hello from iOS Shortcuts!"
    else:
        raw = sys.argv[1]

    output = handle_input(raw)
    # Shortcuts reads stdout when the script finishes
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
