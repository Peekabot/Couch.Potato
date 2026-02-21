#!/usr/bin/env bash
# Gemini @Documents bash prompt
# Install: echo 'source ~/Documents/gemini-prompt.sh' >> ~/.bashrc

GEMINI_ROOT="${GEMINI_ROOT:-$HOME/Documents}"
GEMINI_PORT="${GEMINI_PORT:-1965}"

_g(){ ss -tlnp 2>/dev/null | grep -q ":$GEMINI_PORT" && echo "◆" || echo "◇"; }
_t(){ tailscale ip -4 2>/dev/null; }
_p(){
  local p="${PWD/#$GEMINI_ROOT/@docs}"
  p="${p/#$HOME/~}"
  [ ${#p} -gt 28 ] && p="…${p: -25}"
  echo "$p"
}

_prompt(){
  local s=$? g t
  g=$(_g); t=$(_t)
  local R='\[\e[0m\]' GN='\[\e[32m\]' GY='\[\e[90m\]' CY='\[\e[36m\]' YL='\[\e[33m\]' BL='\[\e[34m\]' RD='\[\e[31m\]'
  local gem="${GN}${g}${R}" ts=""
  [ "$g" = "◇" ] && gem="${GY}${g}${R}"
  [ -n "$t" ] && ts=" ${CY}${t}${R}"
  local sym="${BL}\$${R}"; [ $s -ne 0 ] && sym="${RD}\$${R}"
  PS1="${gem}${ts} ${YL}\u${R}:${BL}$(_p)${R} ${sym} "
}
PROMPT_COMMAND="_prompt"

gemini-serve(){
  local root="${1:-$GEMINI_ROOT}"
  echo "gemini://localhost:$GEMINI_PORT  root=$root"
  python3 - "$root" "$GEMINI_PORT" <<'PY'
import sys,ssl,socket,pathlib,mimetypes,threading,subprocess
root=pathlib.Path(sys.argv[1]).expanduser().resolve()
port=int(sys.argv[2])
d=pathlib.Path.home()/".gemini"; d.mkdir(exist_ok=True)
c,k=d/"cert.pem",d/"key.pem"
if not c.exists():
    subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-keyout",str(k),
        "-out",str(c),"-days","3650","-nodes","-subj","/CN=localhost"],
        check=True,capture_output=True)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(c,k)
def handle(conn,_):
    try:
        data=b""
        while not data.endswith(b"\r\n"): data+=conn.recv(1024)
        url=data.decode().strip()
        p=(url.split("//",1)[-1].split("/",1)[-1] if "//" in url else url).lstrip("/"or"index.gmi")
        t=(root/p).resolve()
        if not str(t).startswith(str(root)) or not t.exists():
            conn.sendall(b"51 Not found\r\n"); return
        if t.is_dir(): t=t/"index.gmi"
        m="text/gemini; charset=utf-8" if t.suffix==".gmi" else(mimetypes.guess_type(str(t))[0]or"application/octet-stream")
        conn.sendall(f"20 {m}\r\n".encode()); conn.sendall(t.read_bytes())
    except: conn.sendall(b"40 Error\r\n")
    finally: conn.close()
with socket.socket() as s:
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("",port)); s.listen(8)
    with ctx.wrap_socket(s,server_side=True) as ss:
        print(f"serving {root}"); [threading.Thread(target=handle,args=ss.accept(),daemon=True).start() for _ in iter(int,1)]
PY
}

gemini-ls(){ ls -lh "$GEMINI_ROOT" 2>/dev/null || echo "mkdir -p $GEMINI_ROOT"; }
