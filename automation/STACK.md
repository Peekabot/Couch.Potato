# Minimal AI Automation Stack

A lean, first-principles automation stack for bug bounty workflows, alert triage, and AI-driven decision making.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         HOSTINGER VPS                          │
│                    (Cheap/Lightweight Server)                   │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │                                                           │ │
│  │  ┌─────────────┐    ┌─────────────┐    ┌──────────────┐  │ │
│  │  │   CLAUDE    │◄──►│  TELEGRAM   │◄──►│   IPYTHON    │  │ │
│  │  │   (Brain)   │    │  (Actuator) │    │  (Cockpit)   │  │ │
│  │  └──────┬──────┘    └─────────────┘    └──────────────┘  │ │
│  │         │                                                 │ │
│  │         ▼                                                 │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │              AUTOMATION WORKFLOWS                   │ │ │
│  │  │  • Recon parsing    • Alert triage                 │ │ │
│  │  │  • Scan analysis    • Report drafting              │ │ │
│  │  │  • Target discovery • Decision automation          │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  │                                                           │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Components

| Component | Role | Why |
|-----------|------|-----|
| **Hostinger** | Hosting | Cheap VPS (~$3-5/mo), enough for Python + API calls |
| **Claude** | Brain | Reasoning, parsing, triage, text analysis, decision-making |
| **Telegram** | Interface | Push notifications, commands, portable, no client needed |
| **IPython** | Cockpit | Live debugging, patching, inspection, experimentation |

## What You Can Do

- **Automate recon triage** - Feed subdomain/port scan results, get prioritized targets
- **Alert parsing** - Ingest raw alerts, let Claude categorize and escalate
- **Report drafting** - Input findings, get structured vulnerability reports
- **Live debugging** - IPython gives you a REPL into your running system
- **Mobile control** - Trigger workflows, get updates, all via Telegram

## Files

```
automation/
├── STACK.md              # This doc
├── DEPLOY.md             # Hostinger deployment guide
├── bot.py                # Telegram bot (commands + notifications)
├── brain.py              # Claude API integration
├── babyagi_mcp.py        # Autonomous task loop (MCP server)
├── config.example.env    # Environment template
├── requirements.txt      # Python dependencies
├── workflows/            # Automation workflows
│   ├── recon_triage.py   # Parse and prioritize recon output
│   └── alert_handler.py  # Triage incoming alerts
└── notebooks/
    └── cockpit.ipynb     # IPython maintenance notebook
```

## BabyAGI MCP Server (Advanced)

For autonomous task decomposition, there's also `babyagi_mcp.py` - a Model Context Protocol server that:

1. Takes a high-level objective
2. Uses an orchestrator LLM to decompose into tasks
3. Executes each task with a CrewAI crew (Researcher + Writer agents)
4. Generates follow-up tasks based on results
5. Loops until objective is complete or max iterations hit

**Architecture:**
```
┌─────────────────────────────────────────────────┐
│               BabyAGI MCP Server                │
│  ┌───────────┐   ┌───────────┐   ┌───────────┐ │
│  │ Qwen 3 4B │──▶│ Codestral │──▶│ Gemma 3 4B│ │
│  │Orchestrate│   │ Research  │   │  Write    │ │
│  └───────────┘   └───────────┘   └───────────┘ │
│         │              │               │        │
│         ▼              ▼               ▼        │
│  ┌─────────────────────────────────────────┐   │
│  │           Ollama (Local LLMs)           │   │
│  └─────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

**Usage:**
```bash
# Start the MCP server
python babyagi_mcp.py

# From any MCP client:
babyagi_start(objective="Enumerate attack surface for target.com", max_iter=5)
babyagi_status(verbose=true)
babyagi_stop()
```

**Tools exposed:**
| Tool | Description |
|------|-------------|
| `babyagi_start` | Start autonomous loop with objective |
| `babyagi_status` | Check running/done/queued tasks |
| `babyagi_stop` | Graceful shutdown |
| `ollama_check` | Verify Ollama + list models |

**Requirements:** Ollama running with `qwen3:4b`, `codestral:latest`, `gemma3:4b` pulled.

## Quick Start

```bash
# 1. Clone and setup
cd automation
cp config.example.env .env
pip install -r requirements.txt

# 2. Configure (edit .env)
# - ANTHROPIC_API_KEY
# - TELEGRAM_BOT_TOKEN
# - TELEGRAM_CHAT_ID

# 3. Run the bot
python bot.py

# 4. For maintenance, launch IPython
jupyter notebook notebooks/cockpit.ipynb
```

## Cost Breakdown

| Item | Cost/Month |
|------|------------|
| Hostinger VPS | ~$4 |
| Claude API | Pay-per-use (~$5-20 depending on volume) |
| Telegram | Free |
| **Total** | **~$10-25/mo** |

## Philosophy

> "Do stuff without spinning up a heavy stack or overcomplicating deployment."

This stack is:
- **Minimal** - 4 components, no Kubernetes, no containers, no over-engineering
- **Cheap** - Under $25/mo for full AI automation
- **Portable** - Control from anywhere via Telegram
- **Hackable** - IPython lets you patch and experiment live
- **First-principles** - You understand every piece, no magic
