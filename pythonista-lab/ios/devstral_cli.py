#!/usr/bin/env python3
"""
Devstral Bug Bounty CLI
Natural language bug bounty automation using Devstral + iPhone tools
Simple, practical, powerful.
"""

import os
import sys
import json
import requests
from pathlib import Path

# Configuration
DEVSTRAL_API_KEY = os.getenv('MISTRAL_API_KEY', '')
DEVSTRAL_URL = "https://api.mistral.ai/v1/chat/completions"
DEVSTRAL_MODEL = "codestral-latest"  # or "mistral-small-latest"
IPHONE_URL = os.getenv('IPHONE_NODE', 'http://192.168.1.100:5000')

# Tools available to Devstral
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "scan_subdomains",
            "description": "Scan for subdomains of a target domain using iPhone",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain"}
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_security_headers",
            "description": "Check security headers of a URL",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "create_bug_report",
            "description": "Create a bug report and save to iPhone",
            "parameters": {
                "type": "object",
                "properties": {
                    "bug_type": {"type": "string", "description": "Type of bug (xss, idor, ssrf, etc.)"},
                    "target": {"type": "string", "description": "Target URL or domain"},
                    "description": {"type": "string", "description": "Bug description"},
                    "severity": {"type": "string", "description": "Severity (low, medium, high, critical)"}
                },
                "required": ["bug_type", "target", "description"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_github_tool",
            "description": "Fetch a security tool from GitHub via iPhone",
            "parameters": {
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "description": "Repository (owner/repo)"},
                    "path": {"type": "string", "description": "File path in repo"}
                },
                "required": ["repo", "path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell_command",
            "description": "Execute a shell command via iSH on iPhone",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute"}
                },
                "required": ["command"]
            }
        }
    }
]


# Tool implementations
def scan_subdomains(domain: str) -> str:
    """Scan for subdomains via iPhone"""
    try:
        response = requests.post(
            f"{IPHONE_URL}/recon",
            json={"domain": domain, "verbose": False},
            timeout=60
        )
        data = response.json()
        if data.get('success'):
            return f"Found {data['count']} subdomains:\n" + "\n".join(data['subdomains'][:10])
        return f"Error: {data.get('error', 'Unknown error')}"
    except Exception as e:
        return f"Failed to scan: {e}"


def check_security_headers(url: str) -> str:
    """Check security headers"""
    # Simple implementation - in real use, call iPhone's header analyzer
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        checks = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', '❌ Missing'),
            'X-Frame-Options': headers.get('X-Frame-Options', '❌ Missing'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', '❌ Missing'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', '❌ Missing'),
        }

        result = f"Security Headers for {url}:\n"
        for header, value in checks.items():
            status = "✅" if value != '❌ Missing' else "❌"
            result += f"{status} {header}: {value}\n"

        return result
    except Exception as e:
        return f"Failed to check headers: {e}"


def create_bug_report(bug_type: str, target: str, description: str, severity: str = "medium") -> str:
    """Create bug report via iPhone"""
    report_content = f"""# {bug_type.upper()} Vulnerability

**Target:** {target}
**Severity:** {severity.upper()}
**Date:** {__import__('datetime').datetime.now().strftime('%Y-%m-%d')}

## Description

{description}

## Steps to Reproduce

1. Navigate to {target}
2. [Add specific steps]

## Impact

[Describe the impact]

## Recommendation

[Add remediation steps]

---
*Generated by Devstral CLI*
"""

    try:
        # This would use the write_file endpoint with HMAC signature
        # For simplicity, showing the concept
        print(f"\n📝 Bug Report Created:\n{report_content}")
        return f"Bug report created for {bug_type} on {target}"
    except Exception as e:
        return f"Failed to create report: {e}"


def fetch_github_tool(repo: str, path: str) -> str:
    """Fetch tool from GitHub via iPhone"""
    try:
        response = requests.post(
            f"{IPHONE_URL}/github_fetch_file",
            json={"repo": repo, "path": path},
            timeout=30
        )
        data = response.json()
        if data.get('success'):
            return f"Fetched {data['name']} ({data['size']} bytes)\n{data['content'][:200]}..."
        return f"Error: {data.get('error', 'Unknown error')}"
    except Exception as e:
        return f"Failed to fetch: {e}"


def run_shell_command(command: str) -> str:
    """Execute shell command via iSH"""
    # Would integrate with iSH daemon
    return f"Executed: {command}\n[Output would appear here]"


# Tool dispatcher
TOOL_MAP = {
    "scan_subdomains": scan_subdomains,
    "check_security_headers": check_security_headers,
    "create_bug_report": create_bug_report,
    "fetch_github_tool": fetch_github_tool,
    "run_shell_command": run_shell_command,
}


def call_devstral(messages: list, tools: list = None) -> dict:
    """Call Devstral API"""
    headers = {
        "Authorization": f"Bearer {DEVSTRAL_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": DEVSTRAL_MODEL,
        "messages": messages,
        "temperature": 0.7,
    }

    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"

    response = requests.post(DEVSTRAL_URL, headers=headers, json=payload, timeout=60)
    return response.json()


def execute_tool_call(tool_call) -> str:
    """Execute a tool call from Devstral"""
    function_name = tool_call.function.name
    arguments = json.loads(tool_call.function.arguments)

    print(f"\n🔧 Executing: {function_name}({arguments})")

    if function_name in TOOL_MAP:
        result = TOOL_MAP[function_name](**arguments)
        return result

    return f"Unknown tool: {function_name}"


def chat_loop():
    """Interactive chat loop with Devstral"""
    messages = [
        {
            "role": "system",
            "content": """You are a bug bounty assistant with access to iPhone-based security tools.

Available tools:
- scan_subdomains: Find subdomains of a target
- check_security_headers: Analyze HTTP security headers
- create_bug_report: Generate bug reports
- fetch_github_tool: Download security tools from GitHub
- run_shell_command: Execute shell commands via iSH

When a user asks to test a domain, use the appropriate tools to help them.
Be concise and practical. Focus on actionable bug bounty work."""
        }
    ]

    print("🤖 Devstral Bug Bounty CLI")
    print("=" * 50)
    print("Natural language bug bounty automation")
    print("Type 'quit' to exit\n")

    while True:
        try:
            user_input = input("You: ").strip()

            if user_input.lower() in ['quit', 'exit', 'q']:
                break

            if not user_input:
                continue

            # Add user message
            messages.append({"role": "user", "content": user_input})

            # Call Devstral
            print("\n🤖 Devstral: Thinking...")
            response = call_devstral(messages, tools=TOOLS)

            assistant_message = response['choices'][0]['message']
            messages.append(assistant_message)

            # Handle tool calls
            if assistant_message.get('tool_calls'):
                for tool_call in assistant_message['tool_calls']:
                    result = execute_tool_call(tool_call)

                    # Add tool result to conversation
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result
                    })

                # Get final response after tool execution
                final_response = call_devstral(messages)
                final_message = final_response['choices'][0]['message']
                messages.append(final_message)

                print(f"\n🤖 Devstral: {final_message['content']}\n")
            else:
                print(f"\n🤖 Devstral: {assistant_message['content']}\n")

        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}\n")


def quick_command(command: str):
    """Execute a single command non-interactively"""
    messages = [
        {"role": "system", "content": "You are a bug bounty assistant. Be concise."},
        {"role": "user", "content": command}
    ]

    response = call_devstral(messages, tools=TOOLS)
    assistant_message = response['choices'][0]['message']

    # Handle tool calls
    if assistant_message.get('tool_calls'):
        for tool_call in assistant_message['tool_calls']:
            result = execute_tool_call(tool_call)
            print(f"\n{result}\n")
    else:
        print(f"\n{assistant_message['content']}\n")


def main():
    """Main entry point"""
    if not DEVSTRAL_API_KEY:
        print("❌ Error: MISTRAL_API_KEY environment variable not set")
        print("Get your key from: https://console.mistral.ai/")
        sys.exit(1)

    # Check if running a quick command
    if len(sys.argv) > 1:
        command = ' '.join(sys.argv[1:])
        quick_command(command)
    else:
        chat_loop()


if __name__ == "__main__":
    main()
