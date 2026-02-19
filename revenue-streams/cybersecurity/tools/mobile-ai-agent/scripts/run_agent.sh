#!/bin/bash
# Simple runner script for PythonAnywhere scheduled tasks

cd "$(dirname "$0")/.."
python3 scripts/recon_agent.py "$@"
