#!/usr/bin/env python3
"""
Alert Handler Workflow
Receives alerts from various sources, triages them, and routes appropriately.
"""

import asyncio
import json
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from enum import Enum

sys.path.insert(0, str(Path(__file__).parent.parent))
from brain import triage_alert, ask_claude


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class TriageResult:
    severity: Severity
    category: str
    is_valid: bool
    action: str
    priority: str
    raw_analysis: str


async def handle_alert(alert_text: str) -> TriageResult:
    """
    Process an alert through Claude triage.
    Returns structured triage result.
    """
    analysis = await triage_alert(alert_text)

    # Parse the response (Claude returns structured text)
    severity = Severity.MEDIUM  # default
    category = "unknown"
    is_valid = True
    action = "Review manually"
    priority = "Soon"

    # Simple parsing of Claude's response
    lines = analysis.lower()
    if "critical" in lines:
        severity = Severity.CRITICAL
    elif "high" in lines:
        severity = Severity.HIGH
    elif "low" in lines:
        severity = Severity.LOW
    elif "info" in lines:
        severity = Severity.INFO

    if "false positive" in lines:
        is_valid = False
    if "immediate" in lines:
        priority = "Immediate"
    elif "backlog" in lines:
        priority = "Backlog"

    return TriageResult(
        severity=severity,
        category=category,
        is_valid=is_valid,
        action=action,
        priority=priority,
        raw_analysis=analysis
    )


async def batch_triage(alerts: list[str]) -> list[TriageResult]:
    """
    Triage multiple alerts concurrently.
    """
    tasks = [handle_alert(alert) for alert in alerts]
    return await asyncio.gather(*tasks)


async def should_notify(result: TriageResult) -> bool:
    """
    Determine if this alert warrants immediate notification.
    """
    return (
        result.severity in [Severity.CRITICAL, Severity.HIGH]
        and result.is_valid
        and result.priority == "Immediate"
    )


def format_for_telegram(result: TriageResult, alert_preview: str = "") -> str:
    """
    Format triage result for Telegram notification.
    """
    emoji = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🟢",
        Severity.INFO: "ℹ️"
    }

    return f"""{emoji[result.severity]} *{result.severity.value.upper()}*

{alert_preview[:200]}...

Priority: {result.priority}
Valid: {'Yes' if result.is_valid else 'Likely FP'}
Action: {result.action}"""


# Webhook handler for integrations
async def webhook_handler(payload: dict) -> dict:
    """
    Handle incoming webhooks from monitoring tools.
    Expects JSON with 'alert' or 'message' field.
    """
    alert_text = payload.get("alert") or payload.get("message") or str(payload)
    result = await handle_alert(alert_text)

    return {
        "severity": result.severity.value,
        "valid": result.is_valid,
        "priority": result.priority,
        "analysis": result.raw_analysis,
        "notify": await should_notify(result)
    }


# CLI interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Triage security alerts")
    parser.add_argument("alert", nargs="?", help="Alert text to triage")
    parser.add_argument("--file", "-f", help="File containing alert")
    parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    async def main():
        if args.file:
            with open(args.file, 'r') as f:
                alert_text = f.read()
        elif args.alert:
            alert_text = args.alert
        else:
            print("Reading from stdin...")
            alert_text = sys.stdin.read()

        result = await handle_alert(alert_text)

        if args.json:
            output = {
                "severity": result.severity.value,
                "category": result.category,
                "valid": result.is_valid,
                "action": result.action,
                "priority": result.priority,
                "analysis": result.raw_analysis
            }
            print(json.dumps(output, indent=2))
        else:
            print(result.raw_analysis)

    asyncio.run(main())
