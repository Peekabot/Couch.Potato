"""
BabyAGI MCP Server

Autonomous task decomposition loop using:
- FastMCP for tool exposure
- CrewAI for multi-agent execution (Researcher + Writer)
- Ollama for local LLM inference

Usage:
    python babyagi_mcp.py

Then connect via MCP client and call:
    babyagi_start(objective="Your goal here", max_iter=3)
    babyagi_status(verbose=true)
    babyagi_stop()
"""

import json
import re
import time
import threading
from collections import deque
from typing import Optional

from pydantic import BaseModel, Field, ConfigDict
from mcp.server.fastmcp import FastMCP
from crewai import Agent, Task, Crew, Process, LLM
from ollama import Client as OllamaClient
import litellm

# ── config ───────────────────────────────────────────────

OLLAMA_URL   = "http://ollama:11434"
ORCHESTRATOR = "qwen3:4b"
RESEARCHER   = "codestral:latest"
WRITER       = "gemma3:4b"

# Timeout config - local inference can be slow on first load
REQUEST_TIMEOUT = 1800  # 30 minutes (Ollama model loading + slow inference)

mcp           = FastMCP("babyagi_mcp")
ollama_client = OllamaClient(host=OLLAMA_URL)

# Set global LiteLLM timeout (fallback if per-call doesn't stick)
litellm.request_timeout = REQUEST_TIMEOUT

# ── LLM factory — ollama/ prefix + /v1 + dummy key + timeout ──

def make_llm(model: str) -> LLM:
    return LLM(
        model=f"ollama/{model}",
        base_url=f"{OLLAMA_URL}/v1",
        api_key="ollama",
        temperature=0.1,  # Lower = slightly faster, less variance
        request_timeout=REQUEST_TIMEOUT  # Override 600s default
    )

orchestrator_llm = make_llm(ORCHESTRATOR)
researcher_llm   = make_llm(RESEARCHER)
writer_llm       = make_llm(WRITER)

# ── status ───────────────────────────────────────────────

_status: dict = {
    "running": None,
    "done": [],
    "queued": [],
    "results": {},
    "active": False
}
_thread: Optional[threading.Thread] = None

# ── warmup ───────────────────────────────────────────────

def warmup_models(models: list[str] = None) -> dict:
    """
    Warm up Ollama models by loading them into memory.
    First inference after container restart can take 20-90+ seconds.
    Call this before running tasks to avoid timeouts.
    """
    if models is None:
        models = [ORCHESTRATOR, RESEARCHER, WRITER]

    results = {}
    for model in models:
        try:
            print(f"[WARMUP] Loading {model}...")
            start = time.time()
            resp = ollama_client.chat(
                model=model,
                messages=[{"role": "user", "content": "Say 'ready' in one word."}],
                options={"temperature": 0.0, "num_predict": 5}
            )
            elapsed = time.time() - start
            results[model] = {
                "status": "loaded",
                "response": resp["message"]["content"].strip(),
                "load_time_seconds": round(elapsed, 2)
            }
            print(f"[WARMUP] {model} ready in {elapsed:.1f}s")
        except Exception as e:
            results[model] = {"status": "error", "error": str(e)}
            print(f"[WARMUP] {model} failed: {e}")

    return results


# ── helpers ──────────────────────────────────────────────

def extract_json(text: str) -> list:
    """Extract JSON array from LLM output, handling markdown code blocks."""
    text = re.sub(r'^```json?\s*|\s*```$', '', text.strip(), flags=re.MULTILINE | re.IGNORECASE)
    match = re.search(r'\[.*\]', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError as e:
            print(f"⚠️  JSON fail: {e} → {text[:180]}")
    return []


def stream_collect(prompt: str) -> str:
    """Stream response from orchestrator and collect full output."""
    buf = []
    for chunk in ollama_client.chat(
        model=ORCHESTRATOR,
        messages=[{"role": "user", "content": prompt}],
        stream=True,
    ):
        buf.append(chunk["message"]["content"])
    return "".join(buf)


def run_crew(task: str, context: str) -> str:
    """Execute a task using CrewAI with Researcher + Writer agents."""
    researcher = Agent(
        role="Researcher",
        goal="Find key facts",
        backstory="Concise.",
        llm=researcher_llm,
        verbose=False
    )
    writer = Agent(
        role="Writer",
        goal="Summarise into prose",
        backstory="Clear, dev-friendly.",
        llm=writer_llm,
        verbose=False
    )

    task1 = Task(
        description=f"Research: {task}\nContext: {context}",
        expected_output="3 bullet facts.",
        agent=researcher
    )
    task2 = Task(
        description="Summarise into 2 sentences.",
        expected_output="2-sentence summary.",
        agent=writer,
        context=[task1]
    )

    crew = Crew(
        agents=[researcher, writer],
        tasks=[task1, task2],
        process=Process.sequential,
        verbose=False
    )

    result = str(crew.kickoff())
    time.sleep(1)  # Rate limiting
    return result


def _run_loop(objective: str, max_iter: int):
    """Main BabyAGI loop - runs in background thread."""
    _status.update(active=True, done=[], queued=[], results={}, running=None)

    # Seed initial tasks
    seed_prompt = (
        f"Objective: {objective}\n\n"
        "You MUST respond with ONLY a valid JSON array of strings, nothing else. "
        "No explanation, no prose, no code block.\n"
        'Example exactly like this:\n["First task", "Second task", "Third task"]\n\n'
        "Now generate 3 starter tasks:"
    )
    raw = stream_collect(seed_prompt)
    print("[DEBUG] Raw seed output:", raw[:300])

    tasks = deque(enumerate(extract_json(raw), 1))
    print("[DEBUG] Extracted tasks:", list(tasks))
    counter = len(tasks) + 1
    _status["queued"] = [t for _, t in tasks]

    if not tasks:
        print("⚠️  No tasks seeded")
        _status["active"] = False
        return

    # Main execution loop
    for i in range(max_iter):
        if not tasks or not _status["active"]:
            break

        tid, task = tasks.popleft()
        _status.update(running=task, queued=[t for _, t in tasks])

        # Execute task with CrewAI
        result = run_crew(task, json.dumps(_status["results"]))
        _status["results"][task] = result
        _status["done"].append(task)
        _status["running"] = None

        # Generate follow-up tasks
        followup_prompt = (
            f"Objective: {objective}\n"
            f"Completed task: {task}\n"
            f"Its result: {result}\n\n"
            "You MUST respond with ONLY a valid JSON array of strings, nothing else. "
            "No explanation, no prose.\n"
            'Example exactly like this:\n["Next logical task", "Another follow-up task"]\n\n'
            "Now generate 2 new tasks:"
        )
        raw2 = stream_collect(followup_prompt)
        print("[DEBUG] Raw follow-up output:", raw2[:300])

        for t in extract_json(raw2)[:2]:
            tasks.append((counter, t))
            _status["queued"].append(t)
            counter += 1

    _status["active"] = False


# ── input models ─────────────────────────────────────────

class StartInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    objective: str = Field(..., description="High-level goal for BabyAGI", min_length=5)
    max_iter: int = Field(default=3, description="Max iterations", ge=1, le=10)


class EmptyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verbose: bool = Field(default=False, description="Include full result text")


# ── tools ─────────────────────────────────────────────────

@mcp.tool(
    name="babyagi_start",
    annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False
    }
)
async def babyagi_start(params: StartInput) -> str:
    """Start the BabyAGI loop in a background thread. Returns immediately."""
    global _thread
    if _status["active"]:
        return json.dumps({"error": "Already running. Call babyagi_stop first."})

    _thread = threading.Thread(
        target=_run_loop,
        args=(params.objective, params.max_iter),
        daemon=True
    )
    _thread.start()

    return json.dumps({
        "status": "started",
        "objective": params.objective,
        "max_iter": params.max_iter
    })


@mcp.tool(
    name="babyagi_status",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def babyagi_status(params: EmptyInput) -> str:
    """Poll running/done/queued. Pass verbose=true for full results."""
    out = {k: _status[k] for k in ("active", "running", "done", "queued")}
    if params.verbose:
        out["results"] = _status["results"]
    return json.dumps(out, indent=2)


@mcp.tool(
    name="babyagi_stop",
    annotations={
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False
    }
)
async def babyagi_stop(params: EmptyInput) -> str:
    """Gracefully stop after current task finishes."""
    _status["active"] = False
    return json.dumps({"status": "stop requested"})


@mcp.tool(
    name="ollama_check",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def ollama_check(params: EmptyInput) -> str:
    """Verify Ollama is reachable and list available models."""
    try:
        models = ollama_client.list()
        running = ollama_client.ps()
        return json.dumps({
            "models": [m["model"] for m in models.get("models", [])],
            "running": str(running)
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool(
    name="ollama_warmup",
    annotations={
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
async def ollama_warmup(params: EmptyInput) -> str:
    """
    Warm up all models before running tasks.

    IMPORTANT: Call this after container restart or model idle time.
    First inference loads models into RAM (20-90+ seconds per model).
    Without warmup, babyagi_start may timeout on first call.
    """
    results = warmup_models()
    return json.dumps(results, indent=2)


if __name__ == "__main__":
    mcp.run(transport="streamable_http", port=8000)
