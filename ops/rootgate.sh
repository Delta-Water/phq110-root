#!/system/bin/sh
# rootgate.sh — 以 uid0 常驻的 root shell 通道（toybox nc，仅 127.0.0.1）
# 由已有 uid0 的终端（如 MT 管理器的 Shizuku 终端）执行：
#     /data/local/tmp/rootgate.sh [PORT]
# 首行必须发密钥（脚本会把密钥打印出来）；密钥每 boot 自动轮换，root:root 0600。
PORT="${1:-10370}"
GIVEN_KEY="${2:-}"
KEYF=/data/local/tmp/rg.key

if [ "$(id -u)" != "0" ]; then
  echo "need uid0 (now $(id -u))" >&2
  exit 1
fi

if [ -n "$GIVEN_KEY" ]; then
  KEY="$GIVEN_KEY"                      # 由 Termux 侧生成并传入，不落盘
else
  if [ ! -s "$KEYF" ]; then
    umask 077
    toybox head -c 24 /dev/urandom | toybox base64 > "$KEYF"
    chmod 600 "$KEYF"
    chown 0:0 "$KEYF" 2>/dev/null
  fi
  KEY=$(toybox cat "$KEYF")
fi

echo "ROOTGATE|LISTEN|127.0.0.1:$PORT|uid=$(id -u)|ctx=$(cat /proc/self/attr/current 2>/dev/null)"
echo "KEY=$KEY"
echo "client: python3 ~/bin/rootgate_client.py --key='$KEY' 'id'"

# 每条连接：先读密钥行，校验通过后把剩余输入交给非交互 sh；否则退出 7
exec toybox nc -L -s 127.0.0.1 -p "$PORT" /system/bin/sh -c "IFS= read -r k; [ \"\$k\" = \"$KEY\" ] && exec /system/bin/sh || exit 7"
