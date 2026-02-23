"""
Clipboard Tools - Pythonista iOS Automation
Utilities for reading, writing, and transforming iOS clipboard content.
Run this in Pythonista on iPhone/iPad.
"""

import clipboard
import webbrowser


def get_text():
    """Return current clipboard text, or empty string."""
    return clipboard.get() or ""


def set_text(text: str):
    """Write text to the clipboard."""
    clipboard.set(text)


def transform(func):
    """Apply a transformation function to the current clipboard text."""
    current = get_text()
    result = func(current)
    set_text(result)
    return result


# --- Ready-to-use transformations ---

def to_uppercase():
    return transform(str.upper)


def to_lowercase():
    return transform(str.lower)


def strip_whitespace():
    return transform(str.strip)


def url_encode():
    import urllib.parse
    return transform(urllib.parse.quote)


def url_decode():
    import urllib.parse
    return transform(urllib.parse.unquote)


def to_json_pretty():
    import json
    def pretty(text):
        try:
            return json.dumps(json.loads(text), indent=2)
        except json.JSONDecodeError:
            return text  # leave unchanged if not valid JSON
    return transform(pretty)


def open_url():
    """Open the URL currently on the clipboard in Safari."""
    url = get_text().strip()
    if url.startswith("http"):
        webbrowser.open(url)
    else:
        print(f"Not a URL: {url!r}")


if __name__ == "__main__":
    # Quick demo: print current clipboard content
    content = get_text()
    print(f"Clipboard ({len(content)} chars):\n{content[:200]}")
