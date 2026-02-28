# Wolf Barbell Bot

A complete financial operating system combining:
- **Jordan Belfort's** core allocation philosophy (80%+ in boring indexes)
- **Michael Burry's** opportunistic signals (GME insider floors, AI capex bubbles)
- **Real-world friction simulation** (slippage, partial fills, emotional tax)

## System Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  GME Insider    │     │  Burry Capex    │     │  Monte Carlo    │
│  Floor Tracker  │ ──▶ │  Sensor         │ ──▶ │  Simulator      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        └───────────────┬───────┴───────────────┬───────┘
                        ▼                       ▼
              ┌─────────────────────┐  ┌─────────────────────┐
              │  Reality Bridge     │  │ One-Share Emotional │
              │  (Friction Sim)     │  │ Tracker             │
              └─────────────────────┘  └─────────────────────┘
                        │                       │
                        └───────────┬───────────┘
                                    ▼
                    ┌─────────────────────────────┐
                    │  Barbell Rebalancer         │
                    │  (Approval + Execution)     │
                    └─────────────────────────────┘
```

## Files Included

- `gme-insider-tracker.json` - n8n workflow for SEC Form 4 alerts
- `burry-capex-sensor.json` - AI spending vs cash flow monitor
- `reality-bridge.json` - Simulates real trading friction
- `one-share-emotion.json` - Live money trainer
- `barbell-rebalancer.json` - Capital allocator with Telegram approval
- `monte-carlo-engine.json` - Probabilistic market simulator
- `setup-instructions.md` - How to deploy in n8n

## Quick Start

1. Import JSON files into n8n
2. Set up Telegram bot
3. Add API keys (TwelveData, Polygon, Alpaca)
4. Configure Google Sheets
5. Start with paper mode first

## Warning

This is not financial advice. These workflows are tools for observation and discipline. Always start with one share before scaling.
