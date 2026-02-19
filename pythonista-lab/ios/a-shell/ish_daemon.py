#!/usr/bin/env python3
"""
iSH Daemon for Bug Bounty Tasks
Runs in iSH to handle shell commands from Pythonista/Academy
Spawns disposable tasks and manages background jobs
"""

import os
import sys
import json
import hmac
import hashlib
import subprocess
import time
from pathlib import Path
from datetime import datetime
import threading

# Configuration
SECRET_KEY = b'5fb9c5db0e37d58bf7ef8e86070d545199b587756ed0026330854ab4a023274e'
SHARED_PATH = Path.home() / "SharedWithiSH"
INBOX = SHARED_PATH / "inbox"
OUTBOX = SHARED_PATH / "outbox"
TASK_LOG = SHARED_PATH / "task_log.jsonl"

# Ensure directories exist
INBOX.mkdir(parents=True, exist_ok=True)
OUTBOX.mkdir(parents=True, exist_ok=True)


def verify_signature(task: dict) -> bool:
    """Verify HMAC signature for security"""
    signature = task.get('hmac_signature', '')
    task_copy = {k: v for k, v in task.items() if k != 'hmac_signature'}

    expected = hmac.new(
        SECRET_KEY,
        json.dumps(task_copy, sort_keys=True).encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected)


def execute_command(command: str, timeout: int = 30) -> dict:
    """
    Execute shell command and return results

    Args:
        command: Shell command to execute
        timeout: Command timeout in seconds

    Returns:
        Dict with stdout, stderr, return_code
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'return_code': result.returncode,
            'success': result.returncode == 0
        }

    except subprocess.TimeoutExpired:
        return {
            'stdout': '',
            'stderr': f'Command timed out after {timeout}s',
            'return_code': -1,
            'success': False
        }
    except Exception as e:
        return {
            'stdout': '',
            'stderr': str(e),
            'return_code': -1,
            'success': False
        }


def spawn_background_task(command: str, task_id: str) -> dict:
    """
    Spawn a background task that runs independently

    Args:
        command: Command to run in background
        task_id: Unique task identifier

    Returns:
        Dict with task info
    """
    log_file = SHARED_PATH / f"{task_id}.log"

    # Write background task script
    script = f"""#!/bin/sh
{{
    {command}
}} > {log_file} 2>&1
"""

    script_file = SHARED_PATH / f"{task_id}.sh"
    script_file.write_text(script)
    script_file.chmod(0o755)

    # Start in background
    subprocess.Popen(
        ['/bin/sh', str(script_file)],
        start_new_session=True
    )

    return {
        'task_id': task_id,
        'status': 'running',
        'log_file': str(log_file),
        'message': f'Background task {task_id} started'
    }


def process_task(task_file: Path) -> None:
    """
    Process a single task from inbox

    Args:
        task_file: Path to task JSON file
    """
    try:
        # Read task
        task = json.loads(task_file.read_text())

        # Verify signature
        if not verify_signature(task):
            result = {
                'status': 'failed',
                'error': 'Invalid signature',
                'task_id': task.get('task_id', 'unknown')
            }
            write_result(task, result)
            task_file.unlink()
            return

        task_id = task['task_id']
        command = task['command']
        task_type = task.get('type', 'sync')  # sync or async

        print(f"[{datetime.now()}] Processing {task_id}: {command[:50]}...")

        # Execute based on type
        if task_type == 'async' or task.get('background', False):
            # Background task
            result = spawn_background_task(command, task_id)
        else:
            # Synchronous execution
            timeout = task.get('timeout', 30)
            exec_result = execute_command(command, timeout)

            result = {
                'status': 'completed' if exec_result['success'] else 'failed',
                'task_id': task_id,
                'result': exec_result,
                'timestamp': time.time()
            }

        # Write result
        write_result(task, result)

        # Log task
        log_task(task, result)

        # Clean up
        task_file.unlink()

    except Exception as e:
        print(f"Error processing {task_file}: {e}")
        try:
            task = json.loads(task_file.read_text())
            result = {
                'status': 'error',
                'error': str(e),
                'task_id': task.get('task_id', 'unknown')
            }
            write_result(task, result)
        except:
            pass
        task_file.unlink()


def write_result(task: dict, result: dict) -> None:
    """Write task result to outbox"""
    task_id = task.get('task_id', 'unknown')
    result_file = OUTBOX / f"{task_id}.json"
    result_file.write_text(json.dumps(result, indent=2))


def log_task(task: dict, result: dict) -> None:
    """Log task execution to log file"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'task_id': task.get('task_id'),
        'command': task.get('command'),
        'status': result.get('status'),
        'success': result.get('result', {}).get('success', False)
    }

    with open(TASK_LOG, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')


def cleanup_old_files(max_age_hours: int = 24) -> None:
    """Clean up old log files and results"""
    cutoff = time.time() - (max_age_hours * 3600)

    for path in [INBOX, OUTBOX, SHARED_PATH]:
        for file in path.glob('*.json'):
            if file.stat().st_mtime < cutoff:
                file.unlink()

        for file in path.glob('*.log'):
            if file.stat().st_mtime < cutoff:
                file.unlink()


def daemon_loop():
    """Main daemon loop - monitors inbox for tasks"""
    print(f"""
╔═══════════════════════════════════════╗
║  🔧 iSH Daemon - Bug Bounty Tasks    ║
╚═══════════════════════════════════════╝

📂 Inbox:  {INBOX}
📤 Outbox: {OUTBOX}
📊 Log:    {TASK_LOG}

🎯 Daemon started - monitoring for tasks...
""")

    # Cleanup thread
    def periodic_cleanup():
        while True:
            time.sleep(3600)  # Every hour
            cleanup_old_files()

    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()

    # Main loop
    last_check = time.time()

    while True:
        try:
            # Check for new tasks
            tasks = sorted(INBOX.glob('*.json'))

            for task_file in tasks:
                # Avoid processing files being written
                if time.time() - task_file.stat().st_mtime < 0.5:
                    continue

                process_task(task_file)

            # Periodic status (every 5 minutes)
            if time.time() - last_check > 300:
                processed = sum(1 for _ in OUTBOX.glob('*.json'))
                print(f"[{datetime.now()}] Status: {processed} tasks processed")
                last_check = time.time()

            # Sleep briefly
            time.sleep(0.5)

        except KeyboardInterrupt:
            print("\n🛑 Daemon stopping...")
            break
        except Exception as e:
            print(f"Error in daemon loop: {e}")
            time.sleep(1)


# ===================================================================
# CLI TOOLS
# ===================================================================

def send_task(command: str, task_type: str = 'sync', timeout: int = 30) -> str:
    """
    Send a task to the daemon

    Args:
        command: Shell command to execute
        task_type: 'sync' or 'async'
        timeout: Command timeout

    Returns:
        Task ID
    """
    import uuid

    task_id = f"task_{uuid.uuid4().hex[:8]}"

    task = {
        'task_id': task_id,
        'command': command,
        'type': task_type,
        'timeout': timeout,
        'timestamp': time.time()
    }

    # Sign task
    signature = hmac.new(
        SECRET_KEY,
        json.dumps(task, sort_keys=True).encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    task['hmac_signature'] = signature

    # Write to inbox
    task_file = INBOX / f"{task_id}.json"
    task_file.write_text(json.dumps(task, indent=2))

    # Touch trigger
    (SHARED_PATH / '.trigger').touch()

    return task_id


def wait_for_result(task_id: str, timeout: int = 30) -> dict:
    """
    Wait for task result

    Args:
        task_id: Task identifier
        timeout: How long to wait

    Returns:
        Task result dict
    """
    result_file = OUTBOX / f"{task_id}.json"
    start = time.time()

    while time.time() - start < timeout:
        if result_file.exists():
            result = json.loads(result_file.read_text())
            result_file.unlink()  # Clean up
            return result

        time.sleep(0.2)

    return {'status': 'timeout', 'error': 'Task timed out'}


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='iSH Daemon for Bug Bounty')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    parser.add_argument('--send', type=str, help='Send command to daemon')
    parser.add_argument('--async', dest='async_mode', action='store_true', help='Run command in background')
    parser.add_argument('--wait', action='store_true', help='Wait for result')

    args = parser.parse_args()

    if args.daemon:
        # Run daemon
        daemon_loop()

    elif args.send:
        # Send command
        task_type = 'async' if args.async_mode else 'sync'
        task_id = send_task(args.send, task_type)

        print(f"📤 Task sent: {task_id}")

        if args.wait and task_type == 'sync':
            print("⏳ Waiting for result...")
            result = wait_for_result(task_id)

            if result.get('status') == 'completed':
                print("\n✅ Success!")
                print(result['result']['stdout'])
                if result['result']['stderr']:
                    print(f"⚠️  Errors:\n{result['result']['stderr']}")
            else:
                print(f"\n❌ Failed: {result.get('error', 'Unknown error')}")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
