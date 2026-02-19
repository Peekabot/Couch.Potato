#!/usr/bin/env python3
"""
Claude Integration - The Brain
Handles all AI reasoning, parsing, triage, and decision-making.
"""

import os
import anthropic
from typing import Optional

# Initialize client
client = anthropic.AsyncAnthropic(
    api_key=os.getenv("ANTHROPIC_API_KEY")
)

MODEL = "claude-sonnet-4-20250514"  # Fast and capable
MAX_TOKENS = 1024


async def ask_claude(
    prompt: str,
    system: Optional[str] = None,
    max_tokens: int = MAX_TOKENS
) -> str:
    """
    General-purpose Claude query.
    """
    try:
        message = await client.messages.create(
            model=MODEL,
            max_tokens=max_tokens,
            system=system or "You are a helpful assistant for bug bounty hunting and security research.",
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text
    except Exception as e:
        return f"Error: {str(e)}"


async def triage_alert(alert: str) -> str:
    """
    Triage a security alert or finding.
    Returns severity, category, and recommended action.
    """
    system = """You are a security alert triage specialist. Analyze the alert and provide:
1. SEVERITY: Critical/High/Medium/Low/Info
2. CATEGORY: Type of issue (XSS, SQLi, IDOR, etc.)
3. VALIDITY: Likely valid / Needs verification / Likely false positive
4. ACTION: Recommended next steps
5. PRIORITY: Immediate / Soon / Backlog

Be concise and actionable."""

    return await ask_claude(
        f"Triage this alert:\n\n{alert}",
        system=system
    )


async def analyze_recon(data: str) -> str:
    """
    Analyze reconnaissance output (subdomains, ports, endpoints).
    Prioritize interesting targets.
    """
    system = """You are a recon analysis specialist. Analyze the provided reconnaissance data and:
1. Identify HIGH-VALUE targets (admin panels, APIs, dev/staging, interesting services)
2. Flag POTENTIAL vulnerabilities or misconfigurations
3. Prioritize what to investigate first
4. Suggest specific next steps for each interesting finding

Format as a prioritized list. Be specific and actionable."""

    return await ask_claude(
        f"Analyze this recon output:\n\n{data}",
        system=system,
        max_tokens=2048
    )


async def draft_report(
    vuln_type: str,
    target: str,
    description: str,
    impact: str,
    steps: str
) -> str:
    """
    Draft a vulnerability report from raw findings.
    """
    system = """You are a bug bounty report writer. Create a professional, clear vulnerability report.
Include:
- Clear title
- Severity assessment
- Detailed description
- Step-by-step reproduction
- Impact analysis
- Remediation suggestions

Write for a technical audience. Be precise."""

    prompt = f"""Draft a vulnerability report:
Type: {vuln_type}
Target: {target}
Description: {description}
Impact: {impact}
Steps to reproduce: {steps}"""

    return await ask_claude(prompt, system=system, max_tokens=2048)


async def parse_output(output: str, tool: str) -> str:
    """
    Parse tool output (nmap, ffuf, nuclei, etc.) into structured findings.
    """
    system = f"""You are parsing output from {tool}. Extract:
1. Key findings (hosts, ports, vulnerabilities, endpoints)
2. Anything unusual or interesting
3. Potential security issues
4. Recommended follow-up actions

Output as structured, scannable text."""

    return await ask_claude(
        f"Parse this {tool} output:\n\n{output}",
        system=system
    )


# Quick test
if __name__ == "__main__":
    import asyncio

    async def test():
        result = await ask_claude("What's the most common bug bounty vulnerability type?")
        print(result)

    asyncio.run(test())
