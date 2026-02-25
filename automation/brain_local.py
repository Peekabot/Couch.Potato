#!/usr/bin/env python3
"""
Ollama Integration — Local AI Brain

Drop-in replacement for brain.py when running without an Anthropic API key.
Talks to Ollama at localhost:11434.

Same async API as brain.py so agent_runner.py can use either transparently.

Usage:
    ollama serve                        # start server
    ollama pull qwen3:4b                # pull a model
    python3 -c "import brain_local; ..." # use it

To test:
    python3 automation/brain_local.py
"""

import json
import asyncio
import urllib.request
import urllib.error
from typing import Optional

OLLAMA_BASE  = "http://localhost:11434"
DEFAULT_MODEL = "qwen3:4b"


def _post(path: str, payload: dict, timeout: int = 120) -> dict:
    """Blocking HTTP POST to Ollama."""
    body = json.dumps(payload).encode()
    req  = urllib.request.Request(
        f"{OLLAMA_BASE}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


async def ask_ollama(
    prompt: str,
    system: Optional[str] = None,
    model: str = DEFAULT_MODEL,
) -> str:
    """
    General-purpose Ollama query. Matches brain.ask_claude signature.
    Runs the blocking urllib call in a thread so it doesn't block the event loop.
    """
    payload = {
        "model":  model,
        "stream": False,
    }
    if system:
        payload["system"] = system
    payload["prompt"] = prompt

    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _post, "/api/generate", payload)
    return result.get("response", "")


# Mirrors of brain.py's named helpers — same signatures, Ollama underneath.

async def ask_claude(
    prompt: str,
    system: Optional[str] = None,
    max_tokens: int = 1024,          # ignored by Ollama, kept for API compat
) -> str:
    """Alias so brain_local is a transparent drop-in for brain."""
    return await ask_ollama(prompt, system=system)


async def triage_alert(alert: str) -> str:
    system = """You are a security alert triage specialist. Analyze the alert and provide:
1. SEVERITY: Critical/High/Medium/Low/Info
2. CATEGORY: Type of issue (XSS, SQLi, IDOR, etc.)
3. VALIDITY: Likely valid / Needs verification / Likely false positive
4. ACTION: Recommended next steps
5. PRIORITY: Immediate / Soon / Backlog

Be concise and actionable."""
    return await ask_ollama(f"Triage this alert:\n\n{alert}", system=system)


async def analyze_recon(data: str) -> str:
    system = """You are a recon analysis specialist. Identify high-value targets,
flag potential vulnerabilities, and suggest specific next steps. Be concise."""
    return await ask_ollama(f"Analyze this recon output:\n\n{data}", system=system)


def is_available(model: str = DEFAULT_MODEL) -> bool:
    """Return True if Ollama is reachable and the model is pulled."""
    try:
        req = urllib.request.Request(f"{OLLAMA_BASE}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as r:
            tags  = json.loads(r.read())
            names = [m["name"] for m in tags.get("models", [])]
            # Accept prefix match — "qwen3:4b" matches "qwen3:4b" or "qwen3:4b-..."
            return any(n.startswith(model.split(":")[0]) for n in names)
    except Exception:
        return False


# ─── QUICK TEST ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    async def test():
        if not is_available():
            print(f"Ollama not available at {OLLAMA_BASE}")
            print("Start it with:  ollama serve")
            print(f"Pull a model:   ollama pull {DEFAULT_MODEL}")
            return

        print(f"Ollama ready — model: {DEFAULT_MODEL}")
        print("Asking a question...")
        result = await ask_ollama("In one sentence: what is a bug bounty?")
        print(f"Answer: {result}")

    asyncio.run(test())
