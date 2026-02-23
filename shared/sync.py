"""
Sync Helper - Shared Script
Push or pull changes to/from the Peekabot GitHub remote.
Works in both Pythonista (via StaSh) and iSH.

Usage:
    python3 sync.py push [message]
    python3 sync.py pull
"""

import subprocess
import sys


def run(cmd: str, check: bool = True) -> bool:
    """Run a shell command, return True on success."""
    print(f"$ {cmd}")
    result = subprocess.run(cmd, shell=True)
    if check and result.returncode != 0:
        print(f"Command failed (exit {result.returncode}): {cmd}")
        return False
    return True


def git_push(message: str = "Auto-sync from mobile"):
    """Stage all changes, commit, and push to origin."""
    run("git add -A")
    run(f'git commit -m "{message}"', check=False)  # OK if nothing to commit
    run("git push origin HEAD")


def git_pull():
    """Pull the latest changes from the tracked remote branch."""
    run("git pull --rebase origin HEAD")


def main():
    if len(sys.argv) < 2:
        print("Usage: sync.py push [message] | pull")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "push":
        message = " ".join(sys.argv[2:]) or "Auto-sync from mobile"
        git_push(message)
    elif command == "pull":
        git_pull()
    else:
        print(f"Unknown command: {command!r}. Use 'push' or 'pull'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
