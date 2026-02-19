#!/usr/bin/env python3
"""
SSH Bridge for iPhone → Remote Machines
========================================

Execute commands on Mac/Windows from iPhone (iSH or Pythonista).

REQUIREMENTS:
- pip install paramiko (in Pythonista or iSH)
- SSH key setup (ssh-keygen on iPhone, add public key to remote ~/.ssh/authorized_keys)

USAGE:
    from ssh_bridge import SSHBridge, run_on_mac, run_on_windows

    # Simple usage
    output = run_on_mac('ls -la')
    print(output)

    # Advanced usage
    mac = SSHBridge('user@192.168.1.10')
    result = mac.run('nmap -p 80,443,8080 target.com')
    print(result['stdout'])

    # Background tasks
    mac.run_background('nmap -p- target.com -oN /tmp/full_scan.txt')
    # ... do other work ...
    output = mac.get_background_output()

SETUP:
    1. On iPhone (iSH):
       ssh-keygen -t ed25519 -C "iphone"
       cat ~/.ssh/id_ed25519.pub  # Copy this

    2. On Mac:
       echo "[paste public key]" >> ~/.ssh/authorized_keys
       chmod 600 ~/.ssh/authorized_keys

    3. Test:
       ssh user@mac-ip
"""

import sys
import os

try:
    import paramiko
except ImportError:
    print("❌ paramiko not installed")
    print("Install with: pip install paramiko")
    print("In iSH: apk add py3-pip && pip3 install paramiko")
    print("In Pythonista: Install 'StaSH' then: pip install paramiko")
    sys.exit(1)


class SSHBridge:
    """
    SSH connection manager for executing remote commands from iPhone.

    Supports:
    - Command execution (sync and async)
    - File upload/download (SFTP)
    - Background task execution
    - Connection pooling
    """

    def __init__(self, host, port=22, key_file=None, password=None):
        """
        Initialize SSH connection.

        Args:
            host: user@hostname or IP (e.g., "user@192.168.1.10")
            port: SSH port (default 22)
            key_file: Path to private key (default: auto-detect)
            password: Password if not using key auth
        """
        self.host = host
        self.port = port
        self.password = password

        # Parse user@host
        if '@' in host:
            self.user, self.hostname = host.split('@', 1)
        else:
            self.user = os.getenv('USER', 'root')
            self.hostname = host

        # Auto-detect SSH key location
        if key_file is None:
            # Try common locations
            possible_keys = [
                os.path.expanduser('~/.ssh/id_ed25519'),
                os.path.expanduser('~/.ssh/id_rsa'),
                os.path.expanduser('~/.ssh/id_ecdsa'),
            ]
            for key_path in possible_keys:
                if os.path.exists(key_path):
                    key_file = key_path
                    break

        self.key_file = key_file
        self.key = None

        # Load SSH key if found
        if self.key_file and os.path.exists(self.key_file):
            try:
                # Try different key types
                for key_class in [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey]:
                    try:
                        self.key = key_class.from_private_key_file(self.key_file)
                        break
                    except:
                        continue
            except Exception as e:
                print(f"⚠️  Could not load key {self.key_file}: {e}")

        self.client = None
        self._connected = False

    def connect(self):
        """
        Establish SSH connection.

        Returns:
            bool: True if connected successfully
        """
        if self._connected:
            return True

        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                'hostname': self.hostname,
                'port': self.port,
                'username': self.user,
                'timeout': 10
            }

            # Use key auth if available, otherwise password
            if self.key:
                connect_kwargs['pkey'] = self.key
            elif self.password:
                connect_kwargs['password'] = self.password
            else:
                raise ValueError("No authentication method provided (need key or password)")

            self.client.connect(**connect_kwargs)
            self._connected = True
            return True

        except Exception as e:
            print(f"❌ SSH connection failed: {e}")
            return False

    def run(self, command, timeout=300, silent=False):
        """
        Execute command on remote machine.

        Args:
            command: Shell command to execute
            timeout: Command timeout in seconds (default 300)
            silent: If True, don't print errors

        Returns:
            dict: {
                'stdout': str,
                'stderr': str,
                'exit_code': int,
                'success': bool
            }
        """
        if not self._connected:
            if not self.connect():
                return {
                    'stdout': '',
                    'stderr': 'Failed to connect',
                    'exit_code': -1,
                    'success': False
                }

        try:
            stdin, stdout, stderr = self.client.exec_command(
                command,
                timeout=timeout,
                get_pty=False
            )

            stdout_data = stdout.read().decode('utf-8', errors='ignore')
            stderr_data = stderr.read().decode('utf-8', errors='ignore')
            exit_code = stdout.channel.recv_exit_status()

            result = {
                'stdout': stdout_data,
                'stderr': stderr_data,
                'exit_code': exit_code,
                'success': exit_code == 0
            }

            if not silent and stderr_data and exit_code != 0:
                print(f"⚠️  Command stderr:\n{stderr_data}")

            return result

        except Exception as e:
            if not silent:
                print(f"❌ Command execution error: {e}")
            return {
                'stdout': '',
                'stderr': str(e),
                'exit_code': -1,
                'success': False
            }

    def run_background(self, command, output_file='/tmp/bg_output.txt'):
        """
        Start long-running command in background (nohup).

        The command runs detached and outputs to a file.
        Use get_background_output() to retrieve results later.

        Args:
            command: Command to run
            output_file: Where to save output (default /tmp/bg_output.txt)

        Returns:
            dict: Result of starting the background command
        """
        bg_cmd = f'nohup {command} > {output_file} 2>&1 &'
        result = self.run(bg_cmd)

        if result['success']:
            print(f"✅ Background task started")
            print(f"   Output will be saved to: {output_file}")
            print(f"   Retrieve with: bridge.get_background_output('{output_file}')")
        else:
            print(f"❌ Failed to start background task")

        return result

    def get_background_output(self, output_file='/tmp/bg_output.txt'):
        """
        Retrieve output from background command.

        Args:
            output_file: File where background output was saved

        Returns:
            str: Contents of output file
        """
        result = self.run(f'cat {output_file}')
        if result['success']:
            return result['stdout']
        else:
            return f"Error reading {output_file}: {result['stderr']}"

    def check_background_running(self, pattern):
        """
        Check if background process is still running.

        Args:
            pattern: grep pattern to find process (e.g., "nmap")

        Returns:
            bool: True if process found
        """
        result = self.run(f'ps aux | grep "{pattern}" | grep -v grep')
        return bool(result['stdout'].strip())

    def upload_file(self, local_path, remote_path):
        """
        Upload file to remote machine via SFTP.

        Args:
            local_path: Local file path
            remote_path: Remote destination path

        Returns:
            bool: True if successful
        """
        if not self._connected:
            if not self.connect():
                return False

        try:
            sftp = self.client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            print(f"✅ Uploaded: {local_path} → {remote_path}")
            return True

        except Exception as e:
            print(f"❌ Upload failed: {e}")
            return False

    def download_file(self, remote_path, local_path):
        """
        Download file from remote machine via SFTP.

        Args:
            remote_path: Remote file path
            local_path: Local destination path

        Returns:
            bool: True if successful
        """
        if not self._connected:
            if not self.connect():
                return False

        try:
            sftp = self.client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            print(f"✅ Downloaded: {remote_path} → {local_path}")
            return True

        except Exception as e:
            print(f"❌ Download failed: {e}")
            return False

    def interactive_shell(self):
        """
        Open interactive shell session (experimental).

        Warning: Limited support in Pythonista due to no real TTY.
        Better to use individual run() commands.
        """
        if not self._connected:
            if not self.connect():
                return

        print("Interactive shell mode (type 'exit' to quit)")
        print("=" * 50)

        channel = self.client.invoke_shell()

        while True:
            try:
                command = input("$ ")
                if command.strip() == 'exit':
                    break

                channel.send(command + '\n')

                # Read output (with timeout)
                import time
                time.sleep(0.5)

                if channel.recv_ready():
                    output = channel.recv(4096).decode('utf-8')
                    print(output, end='')

            except KeyboardInterrupt:
                break

        channel.close()

    def close(self):
        """Close SSH connection"""
        if self.client:
            self.client.close()
            self._connected = False


# =========================
# CONVENIENCE FUNCTIONS
# =========================

# Configure your remote machines here
MAC_HOST = os.getenv('MAC_HOST', 'user@192.168.1.10')
WINDOWS_HOST = os.getenv('WINDOWS_HOST', 'user@192.168.1.20')

def run_on_mac(command, timeout=300):
    """
    Quick helper: Run command on MacBook

    Args:
        command: Shell command
        timeout: Timeout in seconds

    Returns:
        str: stdout from command
    """
    mac = SSHBridge(MAC_HOST)
    result = mac.run(command, timeout=timeout)
    mac.close()

    if result['success']:
        return result['stdout']
    else:
        return f"Error: {result['stderr']}"

def run_on_windows(command, timeout=300):
    """
    Quick helper: Run command on Windows PC

    Args:
        command: PowerShell command
        timeout: Timeout in seconds

    Returns:
        str: stdout from command
    """
    win = SSHBridge(WINDOWS_HOST)
    result = win.run(command, timeout=timeout)
    win.close()

    if result['success']:
        return result['stdout']
    else:
        return f"Error: {result['stderr']}"

def run_on_best_host(command):
    """
    Automatically choose best host for command type.

    Detection logic:
    - iOS/Mac tools (frida, class-dump, etc.) → Mac
    - Android tools (apktool, jadx, adb) → Mac (default)
    - Cross-platform (nmap, curl, etc.) → Mac

    Args:
        command: Shell command

    Returns:
        str: stdout from command
    """
    # iOS-specific tools → Mac only
    if any(tool in command for tool in ['frida', 'objection', 'class-dump', 'codesign', 'xcodebuild']):
        return run_on_mac(command)

    # Android tools → Could be either, default Mac
    elif any(tool in command for tool in ['apktool', 'jadx', 'adb', 'd2j-dex2jar']):
        return run_on_mac(command)

    # Windows-specific
    elif any(tool in command.lower() for tool in ['powershell', 'wmi', 'netsh']):
        return run_on_windows(command)

    # Default to Mac for security tools
    else:
        return run_on_mac(command)


# =========================
# MULTI-HOST EXECUTION
# =========================

def run_on_all_hosts(command):
    """
    Run same command on all configured hosts in parallel.

    Returns:
        dict: {'mac': result, 'windows': result}
    """
    from threading import Thread

    results = {}

    def run_mac():
        results['mac'] = run_on_mac(command)

    def run_win():
        results['windows'] = run_on_windows(command)

    # Start threads
    t_mac = Thread(target=run_mac)
    t_win = Thread(target=run_win)

    t_mac.start()
    t_win.start()

    # Wait for completion
    t_mac.join()
    t_win.join()

    return results


# =========================
# EXAMPLE USAGE & TESTS
# =========================

def test_connection():
    """Test SSH connection to configured hosts"""
    print("🧪 Testing SSH connections...\n")

    # Test Mac
    print(f"📱 Testing Mac ({MAC_HOST})...")
    mac_output = run_on_mac('echo "Hello from Mac"; whoami; sw_vers')
    print(mac_output)
    print()

    # Test Windows
    print(f"💻 Testing Windows ({WINDOWS_HOST})...")
    win_output = run_on_windows('echo "Hello from Windows" && whoami && ver')
    print(win_output)
    print()

def example_background_scan():
    """Example: Start nmap scan in background"""
    mac = SSHBridge(MAC_HOST)

    # Start long scan
    mac.run_background('nmap -p- -T4 scanme.nmap.org -oN /tmp/nmap_scan.txt')

    # Check if running
    if mac.check_background_running('nmap'):
        print("✅ Nmap is running in background")

    # Later, retrieve results
    # output = mac.get_background_output('/tmp/nmap_scan.txt')
    # print(output)

    mac.close()

def example_file_transfer():
    """Example: Upload and download files"""
    mac = SSHBridge(MAC_HOST)

    # Upload local file to Mac
    mac.upload_file('/tmp/local_file.txt', '/tmp/remote_file.txt')

    # Download from Mac to iPhone
    mac.download_file('/tmp/remote_file.txt', '/tmp/downloaded.txt')

    mac.close()


if __name__ == '__main__':
    print("=" * 60)
    print("SSH Bridge - iPhone → Remote Machines")
    print("=" * 60)
    print()

    # Configure your hosts
    print("📝 Configure your remote hosts:")
    print(f"   export MAC_HOST='user@192.168.1.10'")
    print(f"   export WINDOWS_HOST='user@192.168.1.20'")
    print()

    # Run tests
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == 'test':
            test_connection()
        elif sys.argv[1] == 'example':
            print("Running examples...")
            example_background_scan()
    else:
        print("Usage:")
        print("  python ssh_bridge.py test      # Test connections")
        print("  python ssh_bridge.py example   # Run examples")
        print()
        print("Or import in your scripts:")
        print("  from ssh_bridge import run_on_mac, run_on_windows")
