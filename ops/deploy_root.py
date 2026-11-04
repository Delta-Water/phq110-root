#!/data/data/com.termux/files/usr/bin/python3
"""deploy_root — glx 跑完后的**唯一一步**：用 rootd 的一条连接，把 uid0 的 rootgate 常驻起来。

为什么这么设计：rootd 寿命不可靠（实测 1~5 分钟、随 adb pty 一起去），所以不能拿它当日常通道。
rootgate 是 `toybox nc -L`（root 身份、仅 127.0.0.1、首行密钥），`setsid` 脱离后与 rootd 无关，
rootd 死了它照样在。

整流程只花 rootd **1 条连接预算**（总预算 32）。

用法: python3 ~/bin/deploy_root.py [端口=10370]
"""
import os
import socket
import subprocess
import sys
import time

HOME = os.path.expanduser("~")
KEYF = os.path.join(HOME, "zd_chan", "rg.key")
CLIENT = os.path.join(HOME, "termux_uid0.py")
GATECLI = os.path.join(HOME, "bin", "rootgate_client.py")
RG = "/data/local/tmp/rootgate.sh"
PORT = sys.argv[1] if len(sys.argv) > 1 else "10370"


def step(msg):
    print("[deploy] %s" % msg, flush=True)


def port_open(p, host="127.0.0.1"):
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((host, int(p)))
        return True
    except Exception:
        return False
    finally:
        s.close()


def main():
    if not port_open(10369):
        step("rootd 不在（10369 closed）——先跑 glx，别重启")
        return 2

    key = os.urandom(18).hex()          # 36 hex 字符，仅本 boot 有效
    os.makedirs(os.path.dirname(KEYF), exist_ok=True)
    os.umask(0o077)
    with open(KEYF, "w") as f:
        f.write(key)
    os.chmod(KEYF, 0o600)
    step("生成密钥 %s…（存 %s，0600）" % (key[:6], KEYF))

    cmd = ("cd /data/local/tmp && setsid nohup %s %s '%s' "
           ">/dev/null 2>&1 </dev/null & sleep 1; echo launched" % (RG, PORT, key))
    step("用 1 条 rootd 连接启动 rootgate …")
    p = subprocess.run([sys.executable, CLIENT, "--chan=tcp", "--port=10369",
                        "--secret-file=" + os.path.join(HOME, "zd_secret"),
                        "sh", cmd],
                       capture_output=True, text=True, timeout=90)
    tail = [l for l in (p.stdout + p.stderr).splitlines()
            if not l.startswith(("[", "GATE|", "IDENT|", "RES|"))]
    print("\n".join(tail[-4:]))

    for i in range(10):
        if port_open(PORT):
            break
        time.sleep(0.5)
    else:
        step("rootgate 没起来（端口 %s 未监听）——看 /data/local/tmp 下日志" % PORT)
        return 3
    step("rootgate 已监听 127.0.0.1:%s" % PORT)

    p = subprocess.run([sys.executable, GATECLI, "--key=" + key, "--port", PORT,
                        "id; cat /proc/self/attr/current; echo rc=$?"],
                       capture_output=True, text=True, timeout=60)
    out = (p.stdout + p.stderr).strip()
    step("验证输出：\n%s" % out)
    if "uid=0" in out:
        step("OK —— 之后一律用 `python3 ~/bin/rootx.py '<cmd>'`，rootd 可以放着不管了")
        return 0
    step("通道起来了但身份不对，检查 rootgate.sh 是否以 uid0 启动")
    return 4


if __name__ == "__main__":
    sys.exit(main())
