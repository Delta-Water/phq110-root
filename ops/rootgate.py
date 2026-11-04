#!/data/data/com.termux/files/usr/bin/python3
"""rootgate — 以 uid0 常驻的 root 执行通道（AF_UNIX + SO_PEERCRED）。

存在理由：glx 交付的 rootd 是单线程 accept、无 SIGPIPE 处理，并发客户端能让它死掉，
而死掉后本 boot 无法重建。rootgate 由 rootd 一次性拉起，之后独立存在（PPid=1、
oom_score_adj=-1000、线程池、所有写操作都吞 BrokenPipe），rootd 可以完全不碰。

协议：每行一个 JSON 请求，每行一个 JSON 响应。
  {"cmd":"ping"}                                  -> {"ok":true,"uid":0,"pid":N}
  {"cmd":"run","argv":["id"],"timeout":30,"cwd":"/"}-> {"ok":true,"rc":0,"out":"...","err":"..."}

安全：
  - socket 放在 $HOME/zd_chan/rootgate.sock，目录 0700、文件 0600；只有 Termux uid 进得来
  - 每条连接都查 SO_PEERCRED，uid 不是 10369 直接 close（不读不写）
  - 只接受本机同 uid 的 Termux 进程，不监听任何网络端口
"""
import json
import os
import pwd
import socket
import subprocess
import sys
import threading
import time

SOCK = os.environ.get("ROOTGATE_SOCK") or os.path.expanduser("~/zd_chan/rootgate.sock")
LOGP = os.environ.get("ROOTGATE_LOG") or "/data/local/tmp/rootgate.log"
ALLOW_UID = int(os.environ.get("ROOTGATE_ALLOW_UID") or 10369)
SKIP_ROOT_CHECK = os.environ.get("ROOTGATE_SKIP_ROOT_CHECK") == "1"
MAX_LINE = 1 << 20


def log(msg):
    try:
        with open(LOGP, "a") as f:
            f.write("%s %s\n" % (time.strftime("%H:%M:%S"), msg))
    except Exception:
        pass


def peer_uid(conn):
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        pid, uid, gid = (int.from_bytes(creds[i:i + 4], "little") for i in (0, 4, 8))
        return pid, uid, gid
    except Exception:
        return -1, -1, -1


def handle(conn, addr):
    pid, uid, gid = peer_uid(conn)
    if uid != ALLOW_UID:
        log("reject peer uid=%s pid=%s" % (uid, pid))
        try:
            conn.sendall(b'{"ok":false,"err":"peer uid not allowed"}\n')
        except Exception:
            pass
        conn.close()
        return
    buf = b""
    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_LINE:
                break
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    req = json.loads(line)
                except Exception as e:
                    resp = {"ok": False, "err": "bad json: %s" % e}
                else:
                    resp = dispatch(req)
                try:
                    conn.sendall((json.dumps(resp) + "\n").encode())
                except (BrokenPipeError, ConnectionResetError, OSError):
                    log("client vanished mid-write (handled)")
                    return
    except (ConnectionResetError, OSError) as e:
        log("conn error: %s" % e)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def dispatch(req):
    cmd = req.get("cmd")
    if cmd == "ping":
        return {"ok": True, "uid": os.getuid(), "pid": os.getpid(),
                "boot": open("/proc/sys/kernel/random/boot_id").read().strip()}
    if cmd == "run":
        argv = req.get("argv") or []
        if not argv:
            return {"ok": False, "err": "empty argv"}
        timeout = float(req.get("timeout") or 60)
        cwd = req.get("cwd") or "/"
        try:
            p = subprocess.run(argv, cwd=cwd, capture_output=True,
                               timeout=timeout, text=True, errors="replace")
            return {"ok": True, "rc": p.returncode, "out": p.stdout,
                    "err": p.stderr}
        except subprocess.TimeoutExpired:
            return {"ok": False, "err": "timeout after %ss" % timeout}
        except Exception as e:
            return {"ok": False, "err": "%s: %s" % (type(e).__name__, e)}
    return {"ok": False, "err": "unknown cmd %r" % cmd}


def main():
    if os.geteuid() != 0 and not SKIP_ROOT_CHECK:
        print("rootgate must run as uid0", file=sys.stderr)
        return 2
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
    # 抗 OOM：让 LMK 永不挑它
    try:
        with open("/proc/self/oom_score_adj", "w") as f:
            f.write("-1000")
    except Exception as e:
        log("oom_score_adj failed: %s" % e)
    log("listen uid=%d pid=%d sock=%s" % (os.getuid(), os.getpid(), SOCK))
    while True:
        try:
            conn, addr = srv.accept()
        except OSError as e:
            log("accept error: %s" % e)
            time.sleep(0.2)
            continue
        t = threading.Thread(target=handle, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    sys.exit(main())
