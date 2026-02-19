#!/usr/bin/env python3
"""
Recon Triage Workflow
Parses reconnaissance output and prioritizes targets for manual review.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from brain import analyze_recon, parse_output


async def triage_subdomain_file(filepath: str) -> str:
    """
    Read a file of subdomains and analyze them.
    """
    with open(filepath, 'r') as f:
        subdomains = f.read()

    return await analyze_recon(subdomains)


async def triage_nmap_output(filepath: str) -> str:
    """
    Parse and analyze nmap scan results.
    """
    with open(filepath, 'r') as f:
        output = f.read()

    return await parse_output(output, "nmap")


async def triage_ffuf_output(filepath: str) -> str:
    """
    Parse and analyze ffuf directory brute results.
    """
    with open(filepath, 'r') as f:
        output = f.read()

    return await parse_output(output, "ffuf")


async def quick_triage(data: str, data_type: str = "generic") -> str:
    """
    Quick triage of any recon data.

    data_type options: subdomains, ports, endpoints, generic
    """
    tool_map = {
        "subdomains": "subdomain enumeration",
        "ports": "port scan",
        "endpoints": "endpoint discovery",
        "generic": "reconnaissance"
    }

    tool_desc = tool_map.get(data_type, "reconnaissance")
    return await parse_output(data, tool_desc)


# CLI interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Triage recon output")
    parser.add_argument("file", help="File containing recon output")
    parser.add_argument(
        "--type", "-t",
        choices=["subdomains", "nmap", "ffuf", "generic"],
        default="generic",
        help="Type of recon data"
    )

    args = parser.parse_args()

    async def main():
        if args.type == "subdomains":
            result = await triage_subdomain_file(args.file)
        elif args.type == "nmap":
            result = await triage_nmap_output(args.file)
        elif args.type == "ffuf":
            result = await triage_ffuf_output(args.file)
        else:
            with open(args.file, 'r') as f:
                data = f.read()
            result = await quick_triage(data)

        print(result)

    asyncio.run(main())
