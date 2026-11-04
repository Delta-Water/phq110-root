#!/data/data/com.termux/files/usr/bin/python3
"""rootx — 唯一的 root 执行入口，强制串行。

后端优先级：
  1. rootgate（AF_UNIX，线程池，EPIPE 安全）        —— 稳，日常都用它
  2. rootd  （tcp 127.0.0.1:10369，单线程，脆弱）  —— 只在 rootgate 不在时用，且必须串行

串行保证：flock($HOME/zd_chan/root.lock)，同一时刻只有一个 root 调用在飞。
这是为了不再把 rootd 弄死（rootd 是单线程 accept，并发客户端会让它挂）。

用法：
  rootx.py 'id'
  rootx.py --timeout 300 'ls /data/data | wc -l'
  rootx.py --status
"""
import fcntl
import json
import os
import socket
import subprocess
import sys
import time

HOME = os.path.expanduser("~")
LOCK = os.path.join(HOME, "zd_chan", "root.lock")
MUX = os.environ.get("ROOTMUX_SOCK") or os.path.join(HOME, "zd_chan", "rootmux.sock")
GATE = os.environ.get("ROOTGATE_SOCK") or os.path.join(HOME, "zd_chan", "rootgate.sock")
RGKEY = os.path.join(HOME, "zd_chan", "rg.key")
RGPORT = int(os.environ.get("ROOTGATE_PORT") or 10370)
GATECLI = os.path.join(HOME, "bin", "rootgate_client.py")
SECRET = os.path.join(HOME, "zd_secret")
CLIENT = os.path.join(HOME, "termux_uid0.py")


def rg_alive():
    """rootgate（toybox nc，uid0）活着吗 —— 最稳的后端，优先用"""
    try:
        key = open(RGKEY).read().strip()
    except OSError:
        return False
    if not _port_open(RGPORT):
        return False
    try:
        p = subprocess.run([sys.executable, GATECLI, "--key=" + key,
                            "--port", str(RGPORT), "--timeout", "10", "echo ok"],
                           capture_output=True, text=True, timeout=20)
        return "ok" in (p.stdout or "")
    except Exception:
        return False


def _ping(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(path)
        s.sendall(b'{"cmd":"ping"}\n')
        d = s.recv(4096)
        return bool(d) and b'"ok":true' in d.replace(b' ', b'')
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def gate_alive():
    """返回 'rootgate' / 'rootmux' / None"""
    if rg_alive():
        return "rootgate"
    if os.path.exists(MUX) and _ping(MUX):
        return "rootmux"
    if os.path.exists(GATE) and _ping(GATE):
        return "rootgate-sock"
    return None


def _call(path, req, timeout=180):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            ch = s.recv(65536)
            if not ch:
                break
            buf += ch
        return json.loads(buf.split(b"\n", 1)[0])
    finally:
        try:
            s.close()
        except Exception:
            pass


def run_gate(backend, cmd, timeout):
    if backend == "rootgate":
        key = open(RGKEY).read().strip()
        p = subprocess.run([sys.executable, GATECLI, "--key=" + key,
                            "--port", str(RGPORT), "--timeout", str(timeout), cmd],
                           capture_output=True, text=True, timeout=timeout + 20)
        return p.returncode, p.stdout or "", p.stderr or ""
    if backend == "rootmux":
        r = _call(MUX, {"cmd": "run", "cmdline": cmd, "timeout": timeout},
                  timeout=timeout + 30)
    else:
        r = _call(GATE, {"cmd": "run", "argv": ["/system/bin/sh", "-c", cmd],
                         "timeout": timeout, "cwd": "/"}, timeout=timeout + 30)
    if not r.get("ok"):
        raise RuntimeError(r.get("err") or "%s error" % backend)
    return r.get("status", r.get("rc", 0)), r.get("out") or "", r.get("err") or ""


def run_rootd(cmd, timeout):
    p = subprocess.run([sys.executable, CLIENT, "--chan=tcp", "--port=10369",
                        "--secret-file=" + SECRET, "sh", cmd],
                       capture_output=True, text=True, timeout=timeout + 20)
    out = p.stdout
    # 去掉客户端自己的 [ts] 前缀日志行，保留远端输出
    keep = [l for l in out.splitlines()
            if not l.startswith(("[", "GATE|", "IDENT|", "RES|"))]
    return p.returncode, "\n".join(keep) + ("\n" if keep else ""), p.stderr


def main(argv):
    timeout, status_only = 120.0, False
    rest = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--status":
            status_only = True
            i += 1
        elif a.startswith("--timeout"):
            if "=" in a:
                timeout = float(a.split("=", 1)[1]); i += 1
            else:
                timeout = float(argv[i + 1]); i += 2
        else:
            rest = argv[i:]
            break
    os.makedirs(os.path.dirname(LOCK), exist_ok=True)
    lf = open(LOCK, "w")
    fcntl.flock(lf, fcntl.LOCK_EX)          # 串行闸门；阻塞等待
    try:
        alive = gate_alive()
        if status_only:
            print("backend=%s rootd_port=%s conns_budget=32" % (
                alive or "NONE",
                "open" if _port_open(10369) else "closed"))
            return 0 if alive else 1
        if not rest:
            print("nothing to run", file=sys.stderr)
            return 2
        cmd = " ".join(rest)
        if alive:
            backend = alive
            rc, out, err = run_gate(alive, cmd, timeout)
        else:
            backend = "rootd"
            rc, out, err = run_rootd(cmd, timeout)
        sys.stdout.write(out)
        if err.strip():
            sys.stderr.write(err)
        if os.environ.get("ROOTX_VERBOSE"):
            sys.stderr.write("[rootx backend=%s rc=%s]\n" % (backend, rc))
        return rc if isinstance(rc, int) else 1
    finally:
        fcntl.flock(lf, fcntl.LOCK_UN)
        lf.close()


def _port_open(port):
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except Exception:
        return False
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
