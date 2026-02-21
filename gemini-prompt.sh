#!/usr/bin/env bash
# Gemini Static File Drive — Bash Prompt
# Source this in your .bashrc:  source ~/Couch.Potato/gemini-prompt.sh
#
# Shows: [gemini status] user@host:path $
# Gemini server root: ~/Documents (or $GEMINI_ROOT)

GEMINI_ROOT="${GEMINI_ROOT:-$HOME/Documents}"
GEMINI_PORT="${GEMINI_PORT:-1965}"

# Colors
_c_reset='\[\e[0m\]'
_c_green='\[\e[38;5;82m\]'
_c_yellow='\[\e[38;5;220m\]'
_c_blue='\[\e[38;5;39m\]'
_c_red='\[\e[38;5;196m\]'
_c_gray='\[\e[38;5;244m\]'
_c_cyan='\[\e[38;5;51m\]'

# Check if Gemini server is listening on GEMINI_PORT
_gemini_status() {
    if ss -tlnp 2>/dev/null | grep -q ":${GEMINI_PORT}" || \
       netstat -tlnp 2>/dev/null | grep -q ":${GEMINI_PORT}"; then
        echo "gem:ON"
    else
        echo "gem:--"
    fi
}

# Get Tailscale IP if connected
_tailscale_ip() {
    local ip
    ip=$(tailscale ip -4 2>/dev/null)
    if [ -n "$ip" ]; then
        echo "ts:${ip}"
    else
        echo ""
    fi
}

# Shorten path — show ~/Documents as @docs, shorten deep paths
_short_path() {
    local p="${PWD}"
    # Replace $GEMINI_ROOT with @docs
    p="${p/#$GEMINI_ROOT/@docs}"
    # Replace $HOME with ~
    p="${p/#$HOME/~}"
    # If still long, trim middle
    if [ ${#p} -gt 30 ]; then
        p="…${p: -27}"
    fi
    echo "$p"
}

_build_prompt() {
    local status=$?
    local gem_status ts_ip short_path

    gem_status=$(_gemini_status)
    ts_ip=$(_tailscale_ip)
    short_path=$(_short_path)

    # Gemini status badge
    if [[ "$gem_status" == "gem:ON" ]]; then
        local gem_badge="${_c_green}[${gem_status}]${_c_reset}"
    else
        local gem_badge="${_c_gray}[${gem_status}]${_c_reset}"
    fi

    # Tailscale badge (only shown if connected)
    local ts_badge=""
    if [ -n "$ts_ip" ]; then
        ts_badge=" ${_c_cyan}[${ts_ip}]${_c_reset}"
    fi

    # Prompt color: red if last command failed, blue otherwise
    if [ $status -ne 0 ]; then
        local prompt_char="${_c_red}\$${_c_reset}"
    else
        local prompt_char="${_c_blue}\$${_c_reset}"
    fi

    PS1="${gem_badge}${ts_badge} ${_c_yellow}\u@\h${_c_reset}:${_c_blue}${short_path}${_c_reset} ${prompt_char} "
}

PROMPT_COMMAND="_build_prompt"

# Helper: start a simple Gemini static file server (Python, TLS self-signed)
gemini-serve() {
    local root="${1:-$GEMINI_ROOT}"
    echo "Starting Gemini static server on port ${GEMINI_PORT}"
    echo "Root: ${root}"
    python3 - "$root" "$GEMINI_PORT" <<'PYEOF'
import sys, ssl, socket, pathlib, mimetypes, threading

root = pathlib.Path(sys.argv[1]).expanduser().resolve()
port = int(sys.argv[2])

# Generate self-signed cert if needed
import subprocess, os, tempfile
certdir = pathlib.Path.home() / ".gemini"
certdir.mkdir(exist_ok=True)
cert_file = certdir / "cert.pem"
key_file  = certdir / "key.pem"
if not cert_file.exists():
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key_file), "-out", str(cert_file),
        "-days", "3650", "-nodes", "-subj", "/CN=localhost"
    ], check=True, capture_output=True)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert_file, key_file)

def handle(conn, addr):
    try:
        data = b""
        while not data.endswith(b"\r\n"):
            data += conn.recv(1024)
        url = data.decode().strip()
        # Strip gemini://host
        path = url.split("//", 1)[-1].split("/", 1)[-1] if "//" in url else url
        path = path.lstrip("/") or "index.gmi"
        target = (root / path).resolve()
        if not str(target).startswith(str(root)):
            conn.sendall(b"51 Not found\r\n")
            return
        if target.is_dir():
            target = target / "index.gmi"
        if not target.exists():
            conn.sendall(b"51 Not found\r\n")
            return
        mime = "text/gemini; charset=utf-8" if target.suffix == ".gmi" else \
               (mimetypes.guess_type(str(target))[0] or "application/octet-stream")
        conn.sendall(f"20 {mime}\r\n".encode())
        conn.sendall(target.read_bytes())
    except Exception as e:
        try: conn.sendall(b"40 Temporary failure\r\n")
        except: pass
    finally:
        conn.close()

with socket.socket(socket.AF_INET6 if socket.has_ipv6 else socket.AF_INET) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))
    sock.listen(8)
    with ctx.wrap_socket(sock, server_side=True) as ssock:
        print(f"Serving {root} on gemini://localhost:{port}")
        while True:
            try:
                conn, addr = ssock.accept()
                threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
            except KeyboardInterrupt:
                print("\nStopped.")
                break
PYEOF
}

# Helper: show what's in Documents root
gemini-ls() {
    echo "Gemini root: ${GEMINI_ROOT}"
    ls -lh "${GEMINI_ROOT}" 2>/dev/null || echo "(directory not found — mkdir -p ${GEMINI_ROOT})"
}
