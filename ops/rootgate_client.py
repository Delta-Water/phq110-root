#!/data/data/com.termux/files/usr/bin/python3
"""rootgate_client — 连 rootgate.sh 起的 toybox-nc 通道，跑一条命令。

用法:
  rootgate_client.py --key=KEY 'id; cat /proc/uptime'
  rootgate_client.py --key=KEY --port=10370 --timeout=60 'ls /data/data | wc -l'

协议: 发送 "<KEY>\\n<命令>\\necho __RG_END__\\n" 然后 shutdown(SHUT_WR)，读到 EOF。
"""
import argparse
import socket
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=10370)
    ap.add_argument("--timeout", type=float, default=60)
    ap.add_argument("cmd", nargs="+")
    a = ap.parse_args()

    cmd = " ".join(a.cmd).rstrip("\n")
    payload = "%s\n%s\necho __RG_END__\n" % (a.key, cmd)

    s = socket.create_connection((a.host, a.port), a.timeout)
    s.settimeout(a.timeout)
    try:
        s.sendall(payload.encode())
        s.shutdown(socket.SHUT_WR)
        buf = b""
        while True:
            try:
                ch = s.recv(65536)
            except socket.timeout:
                break
            if not ch:
                break
            buf += ch
    finally:
        s.close()

    out = buf.decode("utf-8", "replace")
    if "__RG_END__" not in out and not out.strip():
        print("empty response — 密钥不对或通道未起", file=sys.stderr)
        return 4
    out = out.split("__RG_END__", 1)[0]
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
