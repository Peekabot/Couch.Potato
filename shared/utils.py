"""
Shared Utilities
Common helpers used by both the Pythonista (iOS) and iSH environments.
"""

import json
import datetime
import hashlib
import os


# ---------------------------------------------------------------------------
# Date / time
# ---------------------------------------------------------------------------

def utcnow_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.datetime.utcnow().isoformat()


def local_now_str(fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Return the current local time as a formatted string."""
    return datetime.datetime.now().strftime(fmt)


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def safe_json_loads(text: str, default=None):
    """Parse JSON; return `default` on any error."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return default


def safe_json_dumps(obj, **kwargs) -> str:
    """Serialize to JSON with sensible defaults."""
    return json.dumps(obj, ensure_ascii=False, default=str, **kwargs)


def truncate(text: str, max_len: int = 80, suffix: str = "...") -> str:
    """Truncate `text` to at most `max_len` characters."""
    if len(text) <= max_len:
        return text
    return text[: max_len - len(suffix)] + suffix


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def md5_file(path: str) -> str:
    """Return the MD5 hex-digest of a file."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_dir(path: str):
    """Create directory (and parents) if it doesn't exist."""
    os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------

def is_pythonista() -> bool:
    """True when running inside the Pythonista iOS app."""
    try:
        import console  # noqa: F401
        return True
    except ImportError:
        return False


def is_ish() -> bool:
    """Heuristic: True when running inside iSH on iOS."""
    return os.path.exists("/etc/ish-release") or "ish" in os.uname().sysname.lower()
