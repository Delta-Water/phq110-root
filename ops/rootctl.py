#!/data/data/com.termux/files/usr/bin/python3
"""rootctl — rootgate 客户端。

用法：
  rootctl.py ping
  rootctl.py run id
  rootctl.py run --timeout 120 --cwd /data sh -c 'ls /data/data | wc -l'
  rootctl.py sh 'id; cat /proc/uptime'      # 等价于 run /system/bin/sh -c CMD
  rootctl.py status                          # 通道活着吗（退出码 0/1，便于 watchdog 用）

环境变量：ROOTGATE_SOCK 覆盖 socket 路径。
"""
import json
import os
import socket
import sys

SOCK = os.environ.get("ROOTGATE_SOCK") or os.path.expanduser("~/zd_chan/rootgate.sock")


def call(req, sock_path=SOCK, timeout=120):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        if not buf.strip():
            raise RuntimeError("empty response")
        return json.loads(buf.split(b"\n", 1)[0])
    finally:
        try:
            s.close()
        except Exception:
            pass


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    sub = argv[0]
    if sub == "status":
        try:
            r = call({"cmd": "ping"}, timeout=5)
            print("OK uid=%s pid=%s boot=%s" % (r.get("uid"), r.get("pid"), r.get("boot")))
            return 0
        except Exception as e:
            print("DOWN %s: %s" % (type(e).__name__, e))
            return 1
    if sub == "ping":
        print(json.dumps(call({"cmd": "ping"}, timeout=5), ensure_ascii=False))
        return 0
    if sub in ("run", "sh"):
        timeout, cwd, rest = 120.0, "/", argv[1:]
        if sub == "sh":
            rest = ["/system/bin/sh", "-c", " ".join(rest)]
        else:
            while rest and rest[0].startswith("--"):
                k, _, v = rest[0].partition("=")
                if k == "--timeout":
                    timeout = float(v or rest[1])
                    rest = rest[1:] if not v else rest
                elif k == "--cwd":
                    cwd = v or rest[1]
                    rest = rest[1:] if not v else rest
                else:
                    break
                rest = rest[1:]
        if not rest:
            print("nothing to run", file=sys.stderr)
            return 2
        r = call({"cmd": "run", "argv": rest, "timeout": timeout, "cwd": cwd},
                 timeout=timeout + 15)
        if not r.get("ok"):
            print("ERR %s" % r.get("err"), file=sys.stderr)
            return 3
        sys.stdout.write(r.get("out") or "")
        if r.get("err"):
            sys.stderr.write(r["err"])
        return int(r.get("rc") or 0)
    print("unknown subcommand %r" % sub, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
