#!/data/data/com.termux/files/usr/bin/bash
# 用 rootd 一次性把 rootgate 拉起并脱离（setsid + nohup），之后 rootd 可以完全不碰。
# 用法: bash ~/bin/rootgate_install.sh
set -u
H=/data/data/com.termux/files/home
PY=$H/../files/usr/bin/python3
SOCK=$H/zd_chan/rootgate.sock
LOG=/data/local/tmp/rootgate.log

echo "== 1. rootd 还在吗 =="
SCR=${TMPDIR:-$H/.hermes/cache/scratch}
mkdir -p "$SCR"
if ! python3 "$H/bin/rootx.py" --status >"$SCR/rs.$$" 2>&1; then :; fi
cat "$SCR/rs.$$" 2>/dev/null; rm -f "$SCR/rs.$$"

echo "== 2. 探 shell 域能否执行 Termux 的 python3 =="
probe=$(python3 "$H/bin/rootx.py" "/data/data/com.termux/files/usr/bin/python3 -c 'import sys;print(\"py-ok\",sys.version.split()[0])'" 2>&1)
echo "$probe"
case "$probe" in
  *py-ok*) echo "  -> 可以直接跑 rootgate" ;;
  *) echo "  -> 执行被拒（SELinux app_data_file exec）；rootgate 方案不可用，退回「rootd 串行」模式"
     exit 3 ;;
esac

echo "== 3. 拉起 rootgate（sid 独立、脱离 rootd）=="
python3 "$H/bin/rootx.py" "cd $H && setsid nohup /data/data/com.termux/files/usr/bin/python3 bin/rootgate.py >>$LOG 2>&1 </dev/null & sleep 1; echo launched" 2>&1 | tail -3

echo "== 4. 等 socket 并验证 =="
for i in $(seq 1 10); do
  if [ -S "$SOCK" ]; then break; fi
  sleep 0.5
done
ls -l "$SOCK" 2>&1
python3 "$H/bin/rootctl.py" ping 2>&1
rc=$?
echo "== 5. rootd 现在可以放着不动了（不要去 kill、不要并发）=="
exit $rc
