#!/data/data/com.termux/files/usr/bin/python3
"""rootmux — 用**一条**长连接复用 rootd，把连接预算从「每次命令 1 条」变成「每个 boot 1 条」。

为什么需要：rootd 有内部预算 `--max-conn=32`（glx 硬编码）——**连接数用尽就 break 退出**，
`ROOTD|IDLE_TIMEOUT` 也是同族机制。我上次就是连着调了 30 来次，把预算烧完，rootd 按设计退出，
我却误判成「并发把它弄死了」（源码里其实 `signal(SIGPIPE, SIG_IGN)` + MSG_NOSIGNAL，写不炸）。

做法：本进程在 Termux 侧（uid 10369），持一条到 rootd 的 TCP 连接，对外提供本地
`AF_UNIX` socket（0600），每条请求在**同一条**连接上发一个 X 帧。整 boot 只花 1 条预算。

协议（每行一个 JSON）：
  {"cmd":"ping"}                                   -> {"ok":true,"srv_uid":0,"conns":1}
  {"cmd":"run","cmdline":"id","timeout":30}        -> {"ok":true,"status":0,"out":"..."}
"""
import json
import os
import socket
import sys
import threading
import time

HOME = os.path.expanduser("~")
SOCK = os.environ.get("ROOTMUX_SOCK") or os.path.join(HOME, "zd_chan", "rootmux.sock")
SECRET = os.path.join(HOME, "zd_secret")
PORT = int(os.environ.get("ROOTMUX_PORT") or 10369)
HOST = "127.0.0.1"
MAX_CONN_BUDGET = 32          # glx 传给 rootd 的 --max-conn
LOGP = os.path.join(HOME, ".hermes", "logs", "rootmux.log")

sys.path.insert(0, HOME)
import termux_uid0 as zu  # noqa: E402


def log(msg):
    try:
        os.makedirs(os.path.dirname(LOGP), exist_ok=True)
        with open(LOGP, "a") as f:
            f.write("%s %s\n" % (time.strftime("%H:%M:%S"), msg))
    except Exception:
        pass


class Mux:
    def __init__(self):
        self.lock = threading.Lock()        # rootd 是单线程的，RPC 必须串行
        self.chan = None
        self.conns = 0
        self.dead = True

    def connect(self):
        secret = zu.read_secret(SECRET) if hasattr(zu, "read_secret") else None
        if secret is None:
            raw = open(SECRET, "rb").read().strip()
            secret = bytes.fromhex(raw.decode()) if len(raw) >= 64 else raw
        ch = zu.TcpChan(HOST, PORT, secret, timeout=30)
        self.conns += 1
        ok, txt = ch.gate(0)
        if not ok:
            raise RuntimeError("gate failed: %s" % txt)
        ok, ident = ch.identify(0)
        if not ok:
            raise RuntimeError("identify failed: %s" % ident)
        self.chan = ch
        self.dead = False
        log("connected conns=%d %s" % (self.conns, ident[:90]))

    def ensure(self):
        if self.chan is None or self.dead:
            if self.conns >= MAX_CONN_BUDGET - 3:
                raise RuntimeError("连接预算将尽 (conns=%d/%d)，别再重连"
                                   % (self.conns, MAX_CONN_BUDGET))
            self.connect()

    def run(self, cmdline, timeout=120):
        with self.lock:
            self.ensure()
            try:
                self.chan.sock.settimeout(timeout + 15)
                st, body = self.chan.rpc(ord("X"),
                                         zu.argv_block(["/system/bin/sh", "-c", cmdline]))
                return {"ok": True, "status": st,
                        "out": (body or b"").decode("utf-8", "replace")}
            except Exception as e:
                self.dead = True
                log("rpc error: %s: %s" % (type(e).__name__, e))
                return {"ok": False, "err": "%s: %s" % (type(e).__name__, e)}

    def ping(self):
        with self.lock:
            self.ensure()
            return {"ok": True, "srv_uid": 0, "conns": self.conns,
                    "budget": MAX_CONN_BUDGET}


MUX = Mux()


def serve_client(conn):
    try:
        buf = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    req = json.loads(line)
                except Exception as e:
                    resp = {"ok": False, "err": "bad json: %s" % e}
                else:
                    c = req.get("cmd")
                    if c == "ping":
                        try:
                            resp = MUX.ping()
                        except Exception as e:
                            resp = {"ok": False, "err": str(e)}
                    elif c == "run":
                        resp = MUX.run(req.get("cmdline") or "",
                                       float(req.get("timeout") or 120))
                    else:
                        resp = {"ok": False, "err": "unknown cmd %r" % c}
                try:
                    conn.sendall((json.dumps(resp) + "\n").encode())
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    os.umask(0o077)
    d = os.path.dirname(SOCK)
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o700)
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK)
    os.chmod(SOCK, 0o600)
    srv.listen(64)
    log("listen %s" % SOCK)
    try:
        MUX.connect()
    except Exception as e:
        log("initial connect failed (will retry on demand): %s" % e)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            time.sleep(0.2)
            continue
        threading.Thread(target=serve_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
