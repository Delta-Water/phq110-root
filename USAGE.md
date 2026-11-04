# 使用手册：从零跑通 + Termux 客户端 + Shizuku 授权 + 故障排查

> 全部命令都可整段粘贴。尖括号是占位符，按你的现场值替换：
> `<NN>` = 本次轮次标签（任意整数，只用于文件名/日志，不参与逻辑）；
> `<PORT>` = TCP 端口（本链 10369）；`<ROOTD_PID>` / `<pid>` = rootd 的 pid。
> **不要按名字 `rootd` 去 `ps` 过滤**：rootd 是 glx fork 出来的内嵌进程（无 exec），
> 它的 `comm` 仍是父进程名（实测 `glx_p11n`），见 §1.6 的认定方法（uid=0 + PPid=1 + 10369 LISTEN）；
> `<door>` = §5.1 表里的失败门名；`<hex-secret>` = secret 的 64 个十六进制字符；
> `<执行开始时的 threadtime>` = 执行 glx 那一刻的 `MM-DD HH:MM:SS.mmm`（收尾 `logcat -T` 用）；
> `<you>` = 你的 Windows 用户名（拼 WSL 里的 `/mnt/c/Users/<you>/...` 路径用）；
> `<SERIAL>` = `adb devices` 第一列；**只有一台设备时可省略**，多设备时每条 adb 命令都加 `-s <SERIAL>`。
> 红线：**一个 boot 只跑一次 glx**；不写分区；不 kill rootd/shizuku；armed 后不写 `/dev/pmsg0`。

---

## 0. 前置条件清单（先逐条确认）

| 项 | 要求 | 怎么查 |
|---|---|---|
| 设备 | OPPO PHQ110（OP5613），Android 14 / C.53，内核 5.4.254-qgki | `adb shell getprop ro.product.device` / `uname -a` |
| adb | 设备状态 `device`，shell 身份 `uid=2000`、`u:r:shell:s0` | `adb devices` / `adb shell id` / `adb shell cat /proc/self/attr/current` |
| SELinux | `Enforcing` | `adb shell getenforce` |
| boot 状态 | **未武装**：`/proc/kallsyms` 与 `/sys/fs/pstore` 对 shell 都不可读 | 见 §1.1 |
| 磁盘 | `/data/local/tmp` 可写、可执行 | push 后 `chmod 755` + 跑 `--selftest` 可选 |
| Termux | 已安装；有 python3；HOME 可写 | `termux-info` / `python3 -V` |

> `/proc/kallsyms` 对 shell 可读 ⇒ 本 boot 已被 per-SID permissive 武装过 ⇒ **不要跑 glx**，
> 让人类正常重启手机，回到干净 boot。

---

## 1. 电脑侧：一次完整运行（权威命令序列）

### 1.1 只读前置（任一不满足即停，不要 push）

```bash
adb devices

adb shell cat /proc/sys/kernel/random/boot_id
# 记录新值；必须与你的「已消耗 boot 列表」不同。同一 boot 绝不跑第二次。

adb shell uptime
adb shell getenforce
# 必须 Enforcing

adb shell cat /proc/self/attr/current
# 必须 u:r:shell:s0

adb shell 'head -1 /proc/kallsyms 2>&1; echo kallsyms_rc=$?'
adb shell 'ls /sys/fs/pstore 2>&1; echo pstore_rc=$?'
# 两个都必须被拒（Permission denied / EACCES / rc!=0）。
# 若任一可读 ⇒ 本 boot 已武装 ⇒ 立即停。

adb shell 'ps -A -o USER,PID,PPID,NAME,ARGS | grep -E "glx_p11n|shizuku_server" || true'
adb shell 'cat /proc/net/tcp | grep -i 2881 || true'
# 新 boot 不应有残留。若有：先记录并停（不要 kill，见 RISKS §4）。
# 注意：rootd 的 comm 不是 "rootd" 而是父进程名（实测 glx_p11n / glx_p11n.r<NN>），
#       所以这里 grep 的是 glx_p11n*；"有 rootd 这个名字"不是判据，"看不见 rootd" 也不是故障。
#       确认存活请按 §1.6 的四条（uid=0 / PPid=1 / 10369 LISTEN / exe+cmdline）。
```

### 1.2 Termux 侧准备（可先做，避免执行窗口里手忙脚乱）

在 Termux 里粘贴：

```bash
mkdir -p ~/zd_chan && chmod 700 ~/zd_chan
[ -f ~/zd_secret ] || python3 -c "import os;open(os.path.expanduser('~/zd_secret'),'w').write(os.urandom(32).hex())"
chmod 600 ~/zd_secret
wc -c ~/zd_secret            # 期望 64
stat -c '%a %u' ~/zd_secret  # 期望 600 10369
cp /data/local/tmp/termux_uid0.py ~/termux_uid0.py 2>/dev/null || true
chmod 755 ~/termux_uid0.py
sha256sum ~/termux_uid0.py   # 期望 cb218432…（见 ARTIFACTS.md）
```

> secret 也可以不预建：glx 会在缺失时**以 uid 10369 身份**创建一个 0600、64 hex 的文件。
> 但手工预建更可控；两者都满足门禁时会被复用。

### 1.3 push 与设备端复核（不改动设备已有文件）

```bash
adb push build/glx_p11n /data/local/tmp/glx_p11n.r<NN>
adb push tools/termux_uid0.py /data/local/tmp/termux_uid0.py
# 若 Termux 读不了 /data/local/tmp（不同 ROM 的 SELinux 差异，inferred），改用：
#   adb push tools/termux_uid0.py /sdcard/Download/termux_uid0.py
#   Termux: termux-setup-storage && cp ~/storage/downloads/termux_uid0.py ~/
adb shell sync
adb shell chmod 755 /data/local/tmp/glx_p11n.r<NN>
adb shell sha256sum /data/local/tmp/glx_p11n.r<NN>
adb shell stat -c '%s %a' /data/local/tmp/glx_p11n.r<NN>
# 必须：90b9e66b0122fc94bb4decba731359fa4b6e7e828654cfdb603fd448106549e4
#       1007336 755
```

### 1.4 唯一一次执行（必须真 pty）

```bash
adb shell -t -t 'cd /data/local/tmp && ./glx_p11n.r<NN> --mode device --round <NN> \
  --stop-after=shzlaunch --shz-after-deliver --deliver-fork \
  --zd=tcp --zd-port=10369 --zd-client-selftest; echo GLX_SHELL_EXIT=$?'
```

**为什么必须 `-t -t`**：没有真实 pty 时 stdout 是全缓冲，panic/abort 前最后几行会丢，
而这几行正是定位失败门的关键。

参数取舍：

| 参数 | 说明 |
|---|---|
| `--mode device` | 真机后端（QEMU 后端是 `/proc/glctl`，本目录不提供该模块） |
| `--round <NN>` | 只是标签，用于日志/文件名；每次换新值 |
| `--stop-after=shzlaunch` | 跑到「启动 Shizuku 并验证」为止；`shzcheck` 只做只读验证、不 fork |
| `--shz-after-deliver` | 先完成交付腿再跑 stage3 |
| `--deliver-fork` | rootd 用 fork（无 exec）⇒ 保留 uid0 + 全部 cap 集合 |
| `--zd=tcp --zd-port=10369` | 本链的正式交付通道。`--zd=file` 是**另一种启动模式**（rootd 用 `~/zd_chan` 下的请求/响应文件，目录 0700），必须在 glx 启动时选中；已用 tcp 启动的 rootd **不能**事后切成 file，所以 file 不是本链的兜底（client 侧 `--chan=file` 只在 rootd `--zd=file` 时才有意义）。`--zd` 的完整取值是 `legacy`（旧的 abstract unix socket）/`tcp`/`file`/`auto` |
| `--zd=auto`（源码里存在、**本链不用**，标 **未验证**） | 若完全不写 `--zd=...` 且给了 `--deliver-fork`，glx 会**自动**进入 auto。选择规则：先 `sendto(127.0.0.1:9, 1 字节 UDP)` 探测 IP 出站——返回 1 ⇒ TCP 可用；但**只有 `--zd-port` 已显式给定**才选 tcp，否则退回 file（日志 `ZD channel auto: TCP is reachable but --zd-port was not pinned ... -> file channel`）；sendto 失败（设备 IP 出站被 REJECT）⇒ 直接 file（file 就是 IP-REJECT 兜底）。对应日志：`ZD_IP_PROBE sendto(127.0.0.1:9)=... -> tcp-eligible|IP REJECTED` 与 `ZD channel auto-selected: tcp|file`。**本交付的两台干净 boot 命例都显式写了 `--zd=tcp --zd-port=10369`，auto 分支没有在真机上验证过**——要复现交付形态就不要依赖 auto |
| `--zd-client-selftest` | 用 uid 10369 形态的内置客户端验证 secret/身份/3 条 REPL。**不要**和 Termux 端 `termux_accept.sh` 同时用（单线程 accept 会抢） |
| **不要** `--no-ambient` | 这是 fork-only 降级档；stage3 需 ambient 才能让 exec 子进程保留 caps |

### 1.5 逐阶段判据（不要只看 `RESULT=PASS`）

**Phase A（uid0 成立）**：

- `EXIT=0`；`RES|FAIL` 计数 = 0；`GLX|CHAIN_OK shots=<N>`，其中**设计账本 N=13，但实际 N 可能 ≥13**：
  某发静默 no-op 被检测到并重发（每发最多 3 次）时多发 1 发，已见 `shots=14`。
  判据请看 `shots >= 13` 且 `SHOT` 标签链完整，**不要用固定 `13` 卡判据**；
- **如何核对射击数（唯一正确读法）**：实际发数 = `GLX|SHOT <n> DEV w8 ...` 行里 `<n>` 的**最大值**
  （每发真实 GhostLock 写都会 `g_shots++` 并打一行，重发也算一发）。`CHAIN_OK shots=N` 与
  `STOP_AFTER=...|PASS ... shots=N` 都是同一个 `g_shots`，因此判据是
  **`max(SHOT n)` ≥ 13 且 `CHAIN_OK shots` ≤ `max(SHOT n)`**（正常应当相等），
  **不要**把这两个数与「设计账本 13」做等值比较；
- **不要把 `readback_verification=1` 当成「多发了一发回读」的证据**：run 末的
  `SHOTLEDGER[chain] not gated (... readback_verification=1 shots=13)` 是本链的**预期形态**。
  prearm 路径在 `glx_p11n.c:3446` 无条件 `g_ledger_off=1`（武装改用 file 类行为 oracle，
  账本降为 advisory），而 cap 写的校验用的是用户态 `capget(2)`/`prctl(2)` oracle、
  **不发 GhostLock 回读**。真正的 +1 发只来自静默 no-op 重发。所以：
  (a) 看到 `not gated` / `readback_verification=1` **不是失败**；
  (b) **不能用这个标志反推回读次数**；(c) 发数一律按上一条的 `max(SHOT n)` 读；
- `SETID_GATE` rc=0；`SETIDS_PRECHECK sealed=1 threads=1`；
- `SETIDS setresgid(0,0,0) rc=0`、`setresuid(0,0,0) rc=0`；
- `V8_IDS` 六个 id 全 0；`V8_DOMAIN ctx=u:r:shell:s0`；
- `V8_CAP_EFF/CAP_BSET ⊇ 0xc6`；ambient 档 `V8_CAP_INH/CAP_AMB ⊇ 0xc6`；
- `PERMSET_FORENSICS` 以 uid0 读通 0600 文件（rc=0）。

**Phase B（交付腿成立）**：

- `GLX|ROOTD_LISTEN|PASS|...|uid=0|euid=0|ppid_after_exit=1`；
- `GLX|DELIVER|...|port=10369|...|exec=NO`；
- `GLX|ZD_SECRET|POST_LISTEN|...|termux_readable=1`；
- `GLX|ZDCONNECT|PASS`、`GLX|ZD_UID|PASS ... uid=0`、`GLX|ZD_REPL|SUMMARY|n=3|ok=3`；
- `GLX|ZD_PERSIST|...|KEEP=1`。

**stage3（Shizuku，服务端）**：

- `GLX|STAGE3_INIT|mode=starter|uid=0|euid=0|apk=...`；
- `GLX|STAGE3_MAIN|PASS|pid=...|ctx=u:r:shell:s0`；
- `GLX|STAGE3_BINDER|PASS|json=/data/user_de/0/com.android.shell/shizuku.json|size=...`；
- `GLX|SHZ_AFTER_DELIVER|PASS rc=0`；
- `GLX|STOP_AFTER=shzlaunch|PASS round=... shots=13 uid=0 delivery=verified stage3=ran`。

### 1.6 收尾独立取证（**新开** adb shell，不信程序自述）

```bash
adb shell getenforce                      # 必须仍是 Enforcing
adb shell cat /proc/sys/kernel/random/boot_id   # 必须与执行前相同
adb shell 'ps -A -o USER,PID,PPID,NAME,ARGS | grep -E "glx_p11n|shizuku_server" || true'
adb shell 'cat /proc/net/tcp | grep -i 2881 || true'    # 期望 ...:2881 st=0A uid=0

# 对 ps 得到的 rootd pid：
adb shell 'cat /proc/<ROOTD_PID>/status | grep -E "^(Uid|Gid|CapEff|CapAmb|CapPrm|CapInh|Threads)"'
adb shell 'cat /proc/<ROOTD_PID>/attr/current'
adb shell 'tr "\0" " " < /proc/<ROOTD_PID>/cmdline; echo'
# 注意：不要用 `readlink /proc/<pid>/exe` 判 uid0 进程——adb shell(uid2000) 读它会被拒
# （EACCES/EPERM），这不是链路失败。rootd 是 fork 出来的内嵌 rootd_main（无 exec），
# 其 comm 仍是父进程名（实测 glx_p11n；若推送文件名更长，则是该文件名的前 15 个字符）；
# exe 身份只能标 inferred，真要读就从 uid0 上下文读：
#   python3 ~/termux_uid0.py ... sh 'readlink /proc/<pid>/exe'

# 对 shizuku_server pid 做同样取证；它的 exe 可用 ps 的 NAME/ARGS 或 cmdline 观察
```

**怎么认定 rootd 还活着（四条全满足，缺一条就不能说「rootd 在」）**：

1. `Uid:` / `Gid:` 全 `0`（`/proc/<pid>/status`）；
2. `PPid: 1`（glx 退出后由 init 收养；glx 运行期间是 glx 的 pid）；
3. `/proc/net/tcp` 里 `127.0.0.1:10369`（十六进制 `:2881`）`st=0A`、`uid=0`；
4. `cmdline` / `ps` 的 `NAME,ARGS` 显示它其实是 glx 那个二进制（`/data/local/tmp/glx_p11n.r<NN>`，无 exec），
   外加端到端一条：Termux `termux_uid0.py ... id` 返回 `uid=0`。

> **不要用 comm 名判断 rootd 是否存活。** rootd 从不调用 `prctl(PR_SET_NAME)`，`/proc/<pid>/comm`
> 继承父进程名（实测 `glx_p11n`；任务名最多 15 字符），所以：
> `grep rootd` / `pgrep rootd` / `ps | grep -w rootd` **一定找不到**——那是漏判，不是「rootd 死了」；
> 反过来 glx 自己（未退出时）与 rootd **同名**，只按 comm 也会把 glx 主进程误当成 rootd。
> 认定一律按上面四条。

窗口内 AVC 证据（可选，注意 events buffer）：

```bash
adb logcat -b all -d -T '<执行开始时的 threadtime>' | grep -i 'avc: denied' | head
```

> 统计窗口很重要：默认 `logcat` 读到的是 main buffer，AVC 在 events buffer；
> 用 `-b all -T '<执行开始时的 threadtime>'` 才能得到「真空 vs 0 条」的可靠结论。

### 1.7 如果你用自动化编排脚本（可选）

本目录不提供编排脚本；但外部编排（例如 agent 自写的 run_once/conf 驱动）在本链形态下有三处**会稳定出现**的伪失败，不要据此判定链路失败：

1. **主跑不返回 → HOST_EXIT=124**：`--deliver-fork` 下 rootd 继承 glx 的 stdout/pty，`adb shell -t -t` 在设备侧已经打印 `GLX_SHELL_EXIT=0` 之后仍可能不返回（rootd 一直持有这个 pty），编排器的超时（如 900s）会杀掉它并记 124。判据：**看到 `GLX_SHELL_EXIT=` 就说明主跑已完成**；124 应按 SKIP/忽略处理，而不是 FAIL；收尾再新开一条 adb shell 独立取证。
2. **发数账本差 1，以及 `not gated` / `readback_verification=1`**：
   - 本链 run 末固定打印 `SHOTLEDGER[chain] not gated (... readback_verification=1 shots=<N>)`——这是**预期形态，不是失败**。
     原因（源码可见）：prearm 路径在 `glx_p11n.c:3446` 无条件 `g_ledger_off=1` 把账本降为 advisory；
     而且账本的期望表是 16 个名字（含 3 个 p11e 之后不再发出的 PERM 阶段），本链实际只打出 13 个 tag，
     所以它**从不**做等值门。**不要用 `readback_verification` 反推「多了一发回读」**——
     cap 写是用 `capget(2)`/`prctl(2)` 校验的，不发 GhostLock 回读。
   - 真正的 +1 发只来自静默 no-op 重发。因此编排器若把「设计账本 13」与 `CHAIN_OK shots`（可能是 14）做等值比较，
     就会报 `pa_shots_total` 失败。**正确判据**：以 `GLX|SHOT <n> DEV w8` 的 `max(n)` 为实际发数，
     要求 `max(n) >= 13` 且 `CHAIN_OK shots` ≤ `max(n)`（正常相等），不要和 13 等值比、也不要拿 tag 数比。
3. **按 comm 找 rootd → 永远找不到**：rootd 的 `comm` 是父进程名（实测 `glx_p11n`），不是 `rootd`。
   `pgrep rootd` / `grep -w rootd` 返回空是**判据写错了**，不是链路失败。按 §1.6 的四条认定
   （uid=0 / PPid=1 / 10369 `st=0A uid=0` / cmdline=glx_p11n*+Termux `id` 端到端）。

另外两个宿主侧固定坑：

- **WSL 里 adb 必须显式给路径**：宿主只装了 `adb.exe` 时，编排器要在 WSL 里 `export ADB_BIN=/mnt/c/Users/<you>/AppData/Local/Android/Sdk/platform-tools/adb.exe`，否则 preflight 直接 `adb: No such file or directory`。
- **设备名不要重复加轮次后缀**：conf 里的 `DEVICE_NAME` 若已含轮次（如 `glx_p11n`），不要再拼 `.r<NN>`，否则会变成 `glx_p11n.r807.r807`。

最后：**任何编排器的 VERDICT 都不能替代设备侧锚点与独立 adb shell 取证**。本链的权威判据只有 §1.5 / §1.6 里的日志锚点与进程态。

---

## 2. Termux 侧客户端：`termux_uid0.py`

### 2.1 通道

| `--chan` | 需要什么 | 说明 |
|---|---|---|
| `tcp`（本链默认交付通道） | `--port=10369` | 首行 `ZD1 <hex-secret>\n` → `OK\n`，之后是帧 |
| `file` | rootd 必须用 `--zd=file` 启动；`--dir` 默认 `~/zd_chan`（0700） | 请求/响应文件 `zd.glx10.req` / `zd.glx10.resp`；**本链的 rootd 是 TCP-only，file 不是备用通道** |
| `unix` | rootd 用 legacy abstract socket；`--name`、`--allow-uid` | 旧的 legacy 客户端形态，不是本交付通道 |

公共参数：`--secret-file`（默认 `~/zd_secret`）、`--expect-uid`（默认 0，身份门）、
`--timeout`（默认 60s）、`--sh`（默认 `/system/bin/sh`）、`--vr`（默认 `/data/system/entropy.dat`）。

### 2.2 子命令

```bash
# 身份（最常用的“我还活着吗/是不是 uid0”）
python3 ~/termux_uid0.py --chan=tcp --port=10369 --secret-file="$HOME/zd_secret" id
# → uid=0 euid=0 gid=0 pid=<ROOTD_PID> ctx=u:r:shell:s0

# 全量自检：G / I / R(entropy) / X / F4k / P / reconnect
python3 ~/termux_uid0.py --chan=tcp --port=10369 --secret-file="$HOME/zd_secret" selftest
# → SUMMARY|PASS|fails=0

# 读文件（stdout 只放 payload；诊断上 stderr）
python3 ~/termux_uid0.py --chan=tcp --port=10369 --secret-file="$HOME/zd_secret" \
  --out ~/entropy.dat read /data/system/entropy.dat

# 执行 shell（“X” 帧：/system/bin/sh -c）
python3 ~/termux_uid0.py --chan=tcp --port=10369 --secret-file="$HOME/zd_secret" \
  sh 'id; cat /proc/self/attr/current'

# 直接 exec argv（不经过 shell）
python3 ~/termux_uid0.py --chan=tcp --port=10369 --secret-file="$HOME/zd_secret" \
  exec /system/bin/id

# 交互 REPL：一行 = 一条 /system/bin/sh -c；!quit 退出
python3 ~/termux_uid0.py --chan=tcp --port=10369 --secret-file="$HOME/zd_secret" repl

# 预备/探活（救援用法：先起它、再跑 glx；p11n 已内置 --zd-client-selftest，一般不需要）
python3 ~/termux_uid0.py --chan=tcp --port=10369 --secret-file="$HOME/zd_secret" --wait=120 wait
```

> 上面是常用子命令。脚本的完整参数以 `python3 tools/termux_uid0.py --help` 为准，
> 另有 `--dir/--tag/--req/--resp/--host/--name/--allow-uid/--no-pty/--no-reconnect`
> 等（file/unix 通道与调试用）；`wait` 子命令等价于「重试连接直到成功再打印 id」。

### 2.3 协议帧与退出码（给要写新客户端的 agent）

```text
TCP   : "ZD1 <hex-secret>\n"  ->  "OK\n"
frame : request  = u8 type | u32 le len | payload
        response = u8 status(0 ok / 1 err / 4 denied) | u32 le len | payload
types : G=probe  I=id  R=path\0  X=argv(\0...\0\0)  F=argv+stdin  P=argv+pty stdin  Q=quit
```

客户端退出码：`0 PASS / 1 FAIL / 2 usage / 3 secret/config / 4 connect或鉴权 / 5 身份门不匹配`。

### 2.4 R / X / F / P 四类操作与「无 W」边界（**必读**）

| 帧 | 语义 | 能否写文件 |
|---|---|---|
| `R` | 读一个路径（rootd 以 uid0 + `CAP_DAC_OVERRIDE/READ_SEARCH` 打开） | **只读** |
| `X` | exec 一个 argv（无 stdin） | 子进程可以写——但受限 |
| `F` | exec + 把 stdin 管道给子进程 | 同上 |
| `P` | exec + pty | 同上 |
| `G` | 探针（活否） | 不做事 |
| `Q` | 关闭连接 | — |

- **rootd 协议里没有 `W` 帧**，daemon 本身**不提供任意文件写接口**。
- 需要写受保护路径时，只能走 `X/F/P` 让 **ambient 档 exec 子进程**去写。子进程
  `CapEff/CapAmb ⊇ 0xc6`，但**仍受 DAC 与 SELinux 约束**：这不是「任意内核写」，也不是
  「绕过全部策略」。
- `--no-ambient` 档下 exec 子进程的 `CapEff=0`（C.53 `SECURE_NOROOT`），**写不了**受保护路径；
  只能 fork 出来的 daemon 自己（无 exec）带 caps。要「可写的 uid0 shell」必须 ambient。

### 2.5 `--idle=86400` 与保活

- glx 启动 rootd 时硬编码 `--idle=86400`（**24 小时**；p11m 时代是 300 秒）。
  `idle` 语义：`poll()` 在这个秒数内没有任何新连接 ⇒ daemon 打印 `ROOTD|IDLE_TIMEOUT|86400` 并退出。
- 保活（**非必需**，但长期使用建议）：

> ⚠️ **不要用「每 60 秒 ping 一次」的循环喂 `idle`。** 每次 ping 花掉 1 条
> `--max-conn` 预算，32 分钟就把 daemon 自己送走 —— 这正是现场踩过的坑。
> 正解是**根本不保 rootd**：把它当跳板，跑完立刻部署常驻 `rootgate`，
> 之后走 `rootx.py`，见 [`ops/OPS.md`](ops/OPS.md)。

暂时不想部署 rootgate 时，退而求其次的做法是**只占 1 条长连接**，而不是反复重连：

```bash
nohup python3 ~/bin/rootmux.py >/dev/null 2>&1 &   # 整个 boot 只用 1 条预算
python3 ~/bin/rootx.py 'id'                          # 自动走 rootmux
```

- 另外两个更早的自愿退出源：`--max-conn=32` 用尽、认证失败 `authfail>=3`。
  也就是说：**不要用错误 secret 反复重试**，那会把 daemon 弄死（本 boot 的 uid0 就没了）。

### 2.6 并发与通道限制

- rootd 是**单线程 accept**：不要同时跑两个客户端；不要在一个客户端还连着时再跑
  `--zd-client-selftest`。
- `--zd-client-selftest` **只支持 TCP**；file 档会去连 port=0 而失败，不能当交付腿证据。
- file 通道的 tag 固定 `glx10`，同一 Termux 目录跨 boot 复用文件名；客户端用随机 `reqid`
  防陈旧响应，但仍不建议并发。

---

## 3. Shizuku root 模式与 rish 授权

### 3.1 服务端（**observed**）

当 glx 打印 `STAGE3_BINDER|PASS` 后，`shizuku_server` 已以 uid0 运行
（`CapEff=CapAmb=0xc6`、ctx `u:r:shell:s0`），并已通过 binder 向受支持 app 分发。

**判据只能用下面这条替代证据链**（`--shz-after-deliver` 形态）：

```text
STAGE3_INIT|mode=starter|uid=0
  → STAGE3_EXEC|pid=...
  → STAGE3_MAIN|PASS|pid=...|ctx=u:r:shell:s0
  → STAGE3_BINDER|PASS|json=/data/user_de/0/com.android.shell/shizuku.json|size=N
  → SHZ_AFTER_DELIVER|PASS rc=0
  + 进程态：shizuku_server uid=0 / CapAmb⊇0xc6 / cmdline=shizuku_server / PPid=1
  + （可选）logcat `binder_sample[...shizuku_server...]`、`am_proc_start[...shizuku...]`
```

**不要**在这个形态下等 `AndroidRuntime / RuntimeInit / Calling main entry / send binder /
attachApplication` 这些 logcat 行：starter fork 出来的 `app_process` 的 stderr 被父进程管道接走，
不落 logcat（实测 0 行）。那些行只在「直接在 pty 上跑 app_process」的形态可得（见 CHANGELOG p11i），
不是本链的判据。

### 3.2 Manager 侧（人类动作）

1. 打开 **Shizuku Manager**（`moe.shizuku.privileged.api`）；
2. 确认服务状态为「运行中 / root 模式」（本交付只保证 server 以 uid0 启动，
   **Manager 的 UI 文案与授权动作没有自动化证据**）；
3. 在「授权应用」里给目标 app 打开 root 权限；
4. 受支持 app 内使用 `rish` 执行命令。

### 3.3 rish 验收（**未验证 / 人类待验**）

```bash
# 在已授权的 app 的 rish 环境里执行
rish -c 'id'
# 期望看到 uid=0(root) ...；把原始输出回传
```

> 本仓库**不宣称** app 侧提权已完成。已知证据只到「server uid0 + binder 投递 +
> `shizuku.json` 落盘（packages 的 `flags=2` 解读为 root 授权属 **inferred**）」。
>
> 另：`adb shell`(uid2000) 读不到 uid0 进程的 `/proc/<pid>/exe`，所以
> `shizuku_server` 的 exe 身份（`/system/bin/app_process64`）只能标 **inferred**
> （由 comm/cmdline/父进程 argv 推断），不是 observed。

---

## 4. 撤销 / 收尾

| 目标 | 做法 |
|---|---|
| 最彻底（推荐） | 人类**正常重启手机**（不是 fastboot/EDL）。内存态的一切全部消失，Enforcing 恢复 |
| 只关 TCP 通道 | 仅能**从 uid0 上下文** `kill -9 <rootd pid>`（例如 `termux_uid0.py sh 'kill -9 <pid>'`）。`adb shell`（uid2000）会 `EPERM` |
| 撤掉 per-SID permissive | **没有办法**在不重启的情况下完整撤销；杀进程不会撤销内存里的 map。只能冷启动 |
| 恢复 Enforcing | 本链正常情况下 `enforcing` 全程=1，不需要恢复。若异常变成 0 且 shell 写 `/sys/fs/selinux/enforce` 被拒 ⇒ 告知人类重启 |

---

## 5. 故障排查表

### 5.1 glx 失败门（`GLX|ZD|FAIL_GATE|<door>|...`）

| 观察 | 含义 | 下一步 |
|---|---|---|
| `SECRET_FILE` | secret 缺失/太短/不是 0600/属主≠10369 | Termux 里 `ls -l ~/zd_secret`；`chmod 600`；确认属主是 Termux；**换新 boot** 再跑 |
| `NO_LISTEN_TIMEOUT` | 10s 内没看到 `ROOTD|LISTENING` | 看它上面的 `ROOTD|FATAL/ABORT`：secret 载入、`bind EADDRINUSE`（上次残留）、策略问题 |
| `NO_LISTEN_DAEMON_EXITED` | daemon 在 LISTEN 前退出 | 看退出码：`10`=断言 abort（`--soft-assert` 下不应出现）、`11`=secret 载入、`2`=bind、`3`=listen |
| `NO_LISTEN_STDOUT_EOF` / `NO_LISTEN_IO_ERROR` | daemon 关了 stdout / 管道错误 | 同上，`ROOTD|*` 行里有原因 |
| `LISTEN_UID_NOT_ROOT` | 监听者不是 uid0 | fail-closed；不要用；排查 SETIDS/rootd uid |
| `CLIENT_HANDSHAKE` | daemon 活着，但 uid10369 探针失败 | 看 `ZDCONNECT/ZD_SECRET/ZD_UID` 行；daemon **不会被杀**，可稍后用 Termux 补连 |
| `DELIVERY_FAIL` 但已有 `ROOTD_LISTEN` | 后续取证失败 | rootd 仍在（`ZD_PERSIST`）；Termux 兜底可用，本 boot 不算白费 |
| Phase A 期间 panic / 自复位 | 读链/武装残留 | 记录 `sys.boot.reason` 与最后一行锚点；需要新的冷启动 |

### 5.2 Termux 客户端错误

| 现象 | 原因 | 处理 |
|---|---|---|
| `FAIL: cannot read secret ...`（exit 3） | 路径不存在/不可读 | 确认 `--secret-file` 指向 Termux home 下的 0600 文件 |
| `FAIL: secret too short`（exit 3） | 文件 <32 字节 | 重新生成（64 hex = 32 字节） |
| `Connection refused`（exit 4） | 10369 没在监听：rootd 死了/没起来/端口不对 | 先 `id` 探活；若刚跑完 glx，看 `ROOTD_LISTEN`/`ZD_PERSIST` 行 |
| 连上但 `DENY` / 很快断开（exit 4） | secret 不匹配 | 确认 Termux 读的是 rootd 用的那一份；**别反复试**（3 次错误 daemon 自杀） |
| exit 5 `identity is not uid=0` | 假 server / 对端不是 uid0 rootd | 不要继续；检查 10369 是否被别的进程占用 |
| `selftest` 个别 FAIL | 可能是 DAC/SELinux 与预期不同 | 看 `RES|...` 的具体行；`vr_read_0600` 失败通常意味着 uid/cap 不对 |
| `file` 通道失败 | rootd 不是 `--zd=file`，或 `~/zd_chan` 不存在/权限不对 | 本链用 TCP；要 file 需 glx 用 `--zd=file` 且目录 0700 |
| 响应错位/陈旧 | 并发客户端或旧 resp 文件 | 只跑一个客户端；删掉旧的 `~/zd_chan/zd.glx10.resp`（这是 Termux home 内文件，非用户数据） |

### 5.3 设备侧异常

| 现象 | 含义 | 处理 |
|---|---|---|
| 执行后 `/proc/kallsyms` 变可读 | per-SID permissive 已生效（正常） | 本 boot 已武装，**不可再跑 glx** |
| 10369 已 `LISTEN` 但连不上 | SELinux/DAC 或 uid 不对 | 用 adb 只读取证（`/proc/net/tcp`、`/proc/<pid>/status`） |
| `bind EADDRINUSE` | 上一次运行残留/端口被占 | **不要在同一 boot 重跑**；冷启动 |
| 设备自动重启 | panic（`panic_on_oops=1`） | 记录 `sys.boot.reason`；本 boot 结束，冷启动后重来 |
| 收尾时 `getenforce=Permissive` | 异常（本链不应发生） | 通知人类**立即重启**恢复 Enforcing；重启前不要继续跑命令 |
| `ps`/`pgrep` 里找不到叫 `rootd` 的进程 | **正常**（rootd 的 `comm` 是父进程名 `glx_p11n*`） | 不是故障；按 §1.6 四条认定（uid=0 / PPid=1 / 10369 `st=0A uid=0` / cmdline+Termux `id`） |
| run 末出现 `SHOTLEDGER[chain] not gated ... readback_verification=1` | **正常**（prearm 路径把账本降为 advisory，cap 写用用户态 oracle，不发回读） | 不是失败；发数只看 `max(SHOT n)`（§1.5/§1.7） |

---

## 6. 一页式“最小可用”检查单

- [ ] boot 干净（kallsyms/pstore 被拒）
- [ ] Enforcing / shell 域 / 无残留（残留按 `glx_p11n*` + `10369 LISTEN` 查，不是按 `rootd` 名字）
- [ ] push 后设备端 sha256 = `90b9e66b…549e4`，size `1007336`，mode 755
- [ ] Termux：`~/zd_secret` 0600、属主 Termux、64 字节；`~/termux_uid0.py` 755
- [ ] `adb shell -t -t ... --stop-after=shzlaunch ... --zd-client-selftest` 单跑一次
- [ ] Phase A 判据逐条 PASS（`max(SHOT n)` ≥ 13、0 FAIL、uid0、cap、ctx、enforcing=1；
      `not gated` / `readback_verification=1` 属正常）
- [ ] Phase B 判据逐条 PASS（ROOTD_LISTEN/uid0、ZD_REPL n=3、POST_LISTEN readable）
- [ ] stage3 判据（STAGE3_MAIN/BINDER）或明确记录失败原因
- [ ] 收尾：boot_id 不变、Enforcing=1、10369 `st=0A uid=0`、rootd uid=0+PPid=1（**不看 comm**）、无 panic
- [ ] Termux `id` → `uid=0 ... ctx=u:r:shell:s0`
- [ ] 记录本 boot_id 到「已消耗列表」；本 boot 不再跑 glx
