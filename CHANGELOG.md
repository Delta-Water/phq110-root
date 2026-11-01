# CHANGELOG：p3 → p11n 的演进与每次真机失败的确切原因

> 只记录**能落到证据上**的版本。没有形成独立构建的编号（如 p8）不列。
> 所有「失败」都写明：在哪一阶段、看到什么、根因是什么、下一版怎么改。
> 版本谱系（本交付只对最后一版负责）：
>
> ```
> p3 → p4 → p5 → p6 → p7 → p9 → p10 → p11 → p11d → p11e → p11f → p11g
>    → p11h → p11i → (p11j / rdfix) → p11k → p11m → p11n
> ```

---

## 0. 先看发数口径的演变（很容易踩坑）

不同版本的「发数」不是同一个东西：

| 口径 | 含义 |
|---|---|
| 8 | 链关键发：5 读（R1..R5）+ 3 cap 写（WC1..WC3） |
| 11 | `do_chain` 运行期账本：再加 R3C 身份读 + N9/N9V（旧全局 permissive 路径） |
| 13 | 交付账本：再加 N10/N10V（旧路径的 enforcing 恢复/回读） |
| 15/16 | p10 引入 WC4/WC5（inheritable/ambient）后的口径 |
| **13（当前 p11n 设计账本）** | 6 读 + **2 武装写** + 5 cap 写；legacy PERM 块 0 发（武装前移） |
| **13 或 14（p11n 实际）** | 某发静默 no-op 被检测到并重发时 +1（第二台干净 boot 实测 14） |

**以日志里的 `GLX|SHOT n` 行数、`GLX|CHAIN_OK shots=N`、以及 run 末的
`STOP_AFTER=...|PASS ... shots=N` 为准**；判据用 `shots >= 13`，不要写死 13。不要拿旧文档的数字对账。

---

## 1. 版本逐条

### p3 — sendmmsg 假 waiter 填充

- **目的**：去掉早期 `pselect6` 栈喷洒，改成由受害者线程 T 自己发两条
  `sendmmsg(AF_INET/UDP)` 把伪 waiter/伪 lock 字段铺到 T 的内核栈
  （`stack_base+0x3C80..0x3C98`、`0x3CA0..0x3CD0`）。
- **关键点**：唯一不可控 8 字节 `0x3C98..0x3CA0`（`pi_tree.__rb_parent_color`，强制 `0x80`）
  不覆盖链要用的字段；每发都断言 `sendmmsg()==1`，否则 `SPRAY_DOMAIN_LOST` 干净中止。
- **结果**：QEMU 模型逐字节 PASS；真机后续版本沿用。
- **证据**：源码首页注释明确标注 p3 的「sendmmsg fake-waiter fill」方案与两段填充地址。

### p4 — cred 原地字段改写（取代 cred 指针交换）

- **背景失败**：早期方案交换 `task->real_cred/cred`（指向 `init_cred` 或伪造 cred）
  ⇒ 见 `RISKS.md` §2.3：kernel 域破坏交付腿 + 静态对象被释放 ⇒ panic。
- **改动**：只改 `cred` 内部字段，**SID 保持 `u:r:shell:s0`**；发现写原语的非零 value
  会附带第二次写 `*(value)=target-8`，因此 cap 值取「可控内核指针」`V` 而不是字面量。
- **同期失败（真机）**：`cred+0x04/0x0c/0x14/0x1c` 的**零值写**在真机上第一发就导致
  SIGKILL + 约 1 分钟后复位（两个独立 boot 都复现）。⇒ 后续版本全面禁用零值写。

### p5 — 九项补丁（P1..P9）与「静默错误」防护

从真机取证里总结出的 9 条：

| 项 | 内容 |
|---|---|
| P1 | 受害者线程身份 nonce（`prctl(PR_SET_NAME)`）+ R3C 比对 + R2 CPU 断言 |
| P2 | `shotlog_verify` 变成门（`RES`），`VR_TARGET_UNKNOWN` 不再算 PASS |
| P3 | post-exec 探针额外断言 `cap_permitted >= 0x6` |
| P4 | P0 移进自己的 pmsg 页（不再在 `__log_buf`/dmesg 留痕） |
| P5 | L1/N10 失败路径重新用合法路径恢复 enforcing，并打印 `enforce=` |
| P6 | `W_PRE` 拒绝非 8 对齐 cred：4 mod 8 会让主写落到 `target-4`，把 `V` 高半字写进 `cap_effective`，而每一发都「成功」 |
| P7 | 明确 `V` 的 offset 语义与 cap 半径 |
| P8 | 统一发账本（链关键 vs 运行期 vs 交付） |
| P9 | 保留 post-exec VR 探针；execve 后不「修」caps |

### p6 — N9 全局 permissive 与「副写毁掉 selinux_state」

- **做了什么**：用一发 `w8(p0+8, A_state+1)` 把 `enforcing` 写成 0（N9），在 permissive 窗口里
  做 `setresgid/setresuid`，再用合法 `selinuxfs` 写回 1（N10）。
- **真机失败（决定性）**：N9 的 8 字节**副写** `*(A_state+1)=p0` 把 `enforcing` 起的 7 个字节
  一次性写坏（`checkreqprot`/`initialized`/`policycap`），随后 panic。
- **定位手段**：`--stop-after={caps,n9,shamn9,restore,l1,forensics}` 逐档停止，确认
  「读链 + 3 发 cap 写不 panic，panic 只在 N9 及之后」；由此把 N9 的目标地址候选后移
  （如 `selinux_state-8`）做过验证，但真正解决是后来的 per-SID 方案。
- **遗留价值**：`--perm-fallback=n9` 仍在代码里作为兜底，但**不是交付路径**。

### p7 — 合并「真机验证过的写链」+ 交付腿 + 三项工程修复

- **A**：写链只保留 WC1..WC3（值 `V`，永不 0）+ N9 + SETIDS + N9V；**删除**早前
  早期分支的 4 发零值 cred 写（真机必崩）。
- **B**：交付腿（`--deliver-exec`、C1 `POST=` 二次连接、统一超时预算、P1 有界重试、A/B 列）。
- **C**（三项工程修复）：
  1. `reader_stop()`：所有退出路径都 STOP+waitpid+close `@glx-shell-454`，并给 reader 子进程
     `PR_SET_PDEATHSIG=SIGKILL`——此前残留 orphan listener 会让下一次 `bind` 失败；
  2. `dev_solve_D_checked()`：范围/对齐/段校验 + 两次独立采样窗口一致 + 重试 ≤5；
     错误的 D 只能导致安全中止，不会向错地址发 shot；
  3. 顺序固定为 `N9 → SETIDS → N9V 读 → L1 load → N10`，且 N10 的读回是
     GhostLock 读 `selinux_state[1]`（`sel_read_enforce`），不是 selinuxfs 文件。

### p9 — 交付 argv/env 契约

- 明确 `--deliver-exec` 的 `execve(path, {path, "--audit-log=...", NULL}, NULL)`
  形态：默认白名单 10369、`envp=NULL`；`HANDOFF_PRE` 是 rootd 自身启动断言的**真子集**。
- 后续 p10+ 的 fork 交付腿沿用同一契约（只是不再 exec）。

### p10 — 合并交付腿（WC4/WC5、secret、fallback）

- 新增 **WC4 `cap_inheritable` / WC5 `cap_ambient`**：C.53 的 adb-shell cred 带
  `SECURE_NOROOT`，execve 后 `pP'=pE'=pA'`（ambient），只写 `cap_bset` 会导致
  exec 子进程 `CapEff=0`（真机 run7 的失败）。
- 新增：secret 以 **uid 10369** 降权创建（root 子进程没有 `CAP_CHOWN`，Termux 又不能在
  `/data/local/tmp` 建文件）；`--perm-fallback=n9`；`--perm-force`。
- **真机失败（两次 run 都在这些软件缺陷上 abort）**：
  1. **PERM 成功后掉进 `perm_n9_fallback` 标签**：该标签第一条就是「没有
     `--perm-fallback=n9` 就拒绝」⇒ `SETIDS/setresuid` 从未执行；
  2. 静默 no-op 写被当成硬失败直接 abort（其实应重发）；
  3. 缺少「本 boot 已武装」的第三态（`--perm-armed`），同一 boot 二次验证无从下手。
- 这些都在 p11 修掉。

### p11 — 三项最小修复 + 进程内 uid0 取证

1. PERM 成功路径**跳到 `perm_fallback_done`**（不再落入 n9 标签）；
2. WC1..WC5 改成「写→校验→重发 ≤3」；静默 no-op 不再 abort；
3. 新增 `--perm-armed` 第三态：回读 `node==X && highbit==W` + fake node 内容，
   匹配就跳过两发武装写直接 SETIDS；不匹配干净中止。
- 另加 `PERMSET_FORENSICS`：在 SETIDS 之后、任何 stop 退出之前，以 uid0 读 0600
  `system:system` 文件（默认 `/data/system/entropy.dat`）并 sha256。

### p11d — secret 供给

- `zd_secret_provision()`：fork 子进程 `PR_SET_KEEPCAPS` → `setresgid/setresuid(10369)`
  → 从 `/dev/urandom` 取 32 字节 → 写 64 hex、`O_EXCL`、0600。
- 目的：secret 属主必须是 Termux；否则 Termux 读不到、而其它 app 可能读到。

### p11e — 武装前移到 cap 写之前（run44 的 EPERM）

- **真机失败**：p11d 在 cap 写之前做了 **PERM_PRE 这一发**，它本身会 `sched_setattr` ⇒
  `capable(CAP_SYS_NICE)` ⇒ SELinux `avc_has_perm_noaudit(sid,sid,SECCLASS_CAPABILITY,...)`
  在**空 map** 上把节点缓存成硬拒；等 map 武装后，`setresgid` 仍 EACCES → EPERM → 复位。
- **修复**：**先武装（PERMNODE+PERM_HI），再写 capability**。这样第一次
  capability 判定就带 `AVD_FLAGS_PERMISSIVE`，之后全是 cache hit。
- 同时明确：武装的证明**不能**用 capability 类探针（会污染缓存），只能用全新 file 类 oracle。

### p11f — Phase B 证据的「假阳性负控」

- **问题**：p11f 的两个「负控」断言基于错误路径假设：
  1. `/data/system/dropbox` 是**目录**（`drwx------ system:system`），uid0 + DAC caps
     下 `open()` 成功、`read()` 返回 `-EISDIR(-21)`——这不是 `-EACCES`，也不是 SELinux 判决；
  2. `/init` 在本 build 是 `root:shell 0750` 的**符号链接**，shell 身份本来就能读。
- 结果：这两条断言会把正常行为误判成策略泄漏。
- p11g 删掉它们，改成真正的 pre/post A/B。

### p11g — 替换为 pre/post A/B + 身份不变量

- A）同一路径的前后对照：在 cred 改写**之前** fork 的 reader 子进程（uid2000/shell）读
  VR 目标得到 `-13 EACCES`；cred 改写后 uid0 进程打开并读取同一文件成功。
- B）身份/姿态只用 `capget(2)`/`prctl(2)` 读（**不用 GhostLock read_window**，因为它会副写
  `A-8`）：ctx 仍 `u:r:shell:s0`、enforcing=1、`CapEff⊇0xC6`、`CapBnd⊇0xC6` 且无高于
  `CAP_LAST_CAP` 的位、securebits 与 pre 基线一致。
- rootd 的 negctl 断言也按同一 DAC 口径修正（missing / 目录 / 因 DAC caps 可读 ⇒ SKIP 或 PASS）。

### p11h — R3′ 读链 pivot 静默 no-op（真机失败）

- **现场**：干净 boot（`03e3d065…`）上 `SHOT4` 的 `R3P_PTRACER` 失败。逐字节看：
  `ptracer_cred == rq->curr`、`real_cred == rq->next`——读到的**正好是 R2 的窗口**。
- **根因**：`read_window(A)` 的注入写是**静默 no-op**（返回 0、目标未变），`data` 仍指向
  上一个窗口 ⇒ 陈旧读。
- **排除**：地址推导没错、读窗没截断、pmsg 锚定与该成功 run 完全一致。
- **修复（p11j/rdfix）**：同一目标连读两次必须一致；不一致在同一 round 重读 ≤3 次；
  写前重置 fake node `next=0`；耗尽干净中止。修好后作为 `p11m_pre` 合并进 p11m。

### p11i — stage3：Shizuku root server

- 新增 `shz_launch.c/.h` + `shz_env_snapshot.h`：
  - `auto` 模式：有可读 `lib/arm64/libshizuku.so` 就用 **starter**（否则直接 exec
    `/system/bin/app_process`）；
  - 用 init 环境（`BOOTCLASSPATH` 等）fork+exec；
  - 验证 `shizuku_server` uid=0、`CapEff/CapAmb⊇0xc6`、ctx 仍 shell；
  - 退出码契约 0/3/4/5/6/7/9/10/11。
- 真机（未武装 boot，uid2000）单独实测了「直接 exec app_process + 自拼 argv/env」形态：
  能走到 `RuntimeInit → Calling main entry → starting server → send binder → attachApplication`，
  证明 argv/env 契约成立（不是 root 提权，只是形态验证）。
  **注意**：这组 logcat 锚点只属于「直接在 pty 上跑 app_process」的实测形态；p11n 的
  `--shz-after-deliver`（starter）形态拿不到它们（starter 的 stderr 走父进程管道），
  该形态的判据见 `ARCHITECTURE.md` §9 与 `USAGE.md` §3.1。

### p11j / rdfix — 读链修复（见 p11h）

- 产物是「p11i + 读链修复」；随后以 `p11m_pre` 形式 rebase 到 p11i，再与 p11k 合并。

### p11k — SETIDS 的 NPTL setxid 广播复位（真机失败）

- **现场**：panic 发生在 `setgroups(0)` 成功之后、`setresgid` 之前；watcher 证明 panic 前一刻
  进程仍是 uid2000 / `CapEff=0` / 未提交 cred ⇒ 「写坏 cred」解释不成立。
- **根因（离线指令级裁定）**：glibc 的 `setresgid/setresuid` 在多线程时会走 NPTL `setxid` 广播
  （`tgkill(SIGSETXID)` 给每个线程）。该信号打断仍停在 GhostLock PI futex 上的辅助线程，
  使 `remove_waiter → rt_mutex_adjust_prio_chain` 解引用被 sendmmsg 模板改过的
  `task->pi_blocked_on / waiter->lock` 槽并 `put/free` 残留 `pi_state` ⇒ 复位。
- **修复**：
  1. 用 **raw syscall**：`setresgid` = svc **149**、`setresuid` = svc **147**（无广播）；
  2. 增加 fail-closed 前置门 `SETIDS_PRECHECK`：要求 `sealed==1 && Threads==1`，
     否则 0 后发、干净中止；
  3. 顺序保证：`seal → SETID_GATE → SETIDS`，seal 之后不再有任何 shot。
- 读链/武装/交付腿/stage3 逐字节未动。

### p11m — 合并 p11k + rdfix，Phase B 交付腿的一行 bug（真机失败）

- **现场（round 71）**：Phase A 全绿（15 发 0 失败、uid0 + `CapEff⊇0xC6`、进程内读到 0600 文件、
  Enforcing 全程 1、无 panic、行为 oracle 从 DENIED 翻为 READABLE）；Phase B 已经打印
  `DELIVER ... pid=...`（说明看到了 `ROOTD|LISTENING`），下一行却是 `DELIVERY_FAIL`，`EXIT=2`。
- **根因**：`zd_spawn_verify()` 只在 `poll() > 0` 时才评估成功条件：
  ```c
  pr = poll(&pp, 1, 200);
  if (pr <= 0) continue;                  /* 超时就跳过整个判定 */
  ...
  if (have_listen && (allows>=1 || now-tseen>=1)) { rc = 0; break; }
  ```
  真实 daemon 打印一次 `ROOTD|LISTENING` 后**保持静默**（等客户端），于是后续 poll 全部超时，
  判定永远不执行 ⇒ 10s 到期 ⇒ `rc=-1`，**并把一个完全可用的 uid0 daemon 杀掉了**。
- 影响：内置 10369 客户端自检与 stage3 都被短路；一个干净 boot 被浪费（虽然 Phase A 的
  uid0 已成立，但 rootd 被杀后本 boot 无法重建）。

### p11n — 修复交付腿（**本交付版本**）

改动（只动交付腿，其它逐字节不变）：

1. **每轮都评估成功条件**（poll 成功/超时/EINTR/短读/EAGAIN 一律评估）：
   `have_listen && (allows>=1 || now-tseen>=1s)` ⇒ `rc=0`，**daemon 保留**；
2. **一旦 `ROOTD|LISTENING uid=0` 成立，永不杀 daemon**；非 root 监听者 fail-closed
   （`LISTEN_UID_NOT_ROOT`）；
3. 每个超时都打印具体失败门：
   `NO_LISTEN_TIMEOUT / NO_LISTEN_DAEMON_EXITED / NO_LISTEN_STDOUT_EOF /
   NO_LISTEN_IO_ERROR / LISTEN_UID_NOT_ROOT / SECRET_FILE / CLIENT_HANDSHAKE`；
4. secret 从「警告」变成**门**：size ≥32、mode 0600、属主 == 客户端 uid（默认 10369）；
   0644 直接 `SECRET_GATE=FAIL`；
5. rootd 以 `--soft-assert`（启动断言只打印证据、不阻止 LISTEN）+ `--idle=86400`
   （从 300s 提到 24h，避免人类 Termux 操作慢于 5 分钟导致白耗 boot）；
6. 一旦 LISTENING，客户端自检 / stage3 / 取证失败**绝不**杀 rootd；它被 init 收养（ppid=1）
   继续 10369 LISTEN，Termux 仍可取 uid0；
7. rootd 读写/select/poll 与 10369 客户端的同族 EINTR/HUP 修复；
8. 读链/武装/SETIDS/stage3 argv 常量**逐字节未动**（结构门 179/179、stage3 diff 34/34）。

**真机结果（observed）**：

- 干净 boot `173a1ef0…`：单次全链成功，`shots=13`、`RES|PASS=52`、`RES|FAIL=0`、
  窗口内 0 条 `avc: denied`、无 panic、boot_id 不变、Enforcing=1；
  `ROOTD_LISTEN|PASS|pid=20638|port=10369|uid=0|euid=0|ppid_after_exit=1`；
  `ZD_REPL|SUMMARY|n=3|ok=3`；`STAGE3_BINDER|PASS`；
  Termux 侧 `termux_uid0.py ... id` → `uid=0 euid=0 gid=0 pid=20638 ctx=u:r:shell:s0`。
- 另一干净 boot `58b276d2…`：同二进制再次全链成功 ⇒ 冷启动可复现性成立。
  该次 `CHAIN_OK shots=14`（一发静默 no-op 重发）、Enforcing 全程=1、boot_id 未变、
  无 kernel_panic、rootd pid 18591 与 shizuku_server pid 18623 均 uid0 / `u:r:shell:s0` / PPid=1。
- 该 boot 的编排记录里有两个**编排器伪失败**（不是链路失败）：`HOST_EXIT=124`
  （`--deliver-fork` 下 rootd 持有 pty，`adb shell -t -t` 不返回）与 `pa_shots_total`
  （13 vs 14 的记账口径）。读法与处置见 `USAGE.md` §1.7 / `RISKS.md` §4.1。

---

## 2. 失败原因速查表

| 版本/阶段 | 真机现象 | 根因 | 修复 |
|---|---|---|---|
| p4 时代 | 第一发零值 cred 写 ⇒ SIGKILL + 约 1min 复位（两个 boot） | 零值写在目标板上不可用（副写/内核语义） | 禁用零值写；uid/gid 改用 `setres*` 系统调用 |
| p5/P6 | 4 mod 8 目标：每发都「成功」但 `cap_effective` 是高半字 | 主写落到 `target-4`，`V` 高半字进相邻字段 | `W_PRE` 直接拒绝 4 mod 8 |
| p6 | N9 之后 panic | N9 的副写把 `enforcing` 起 7 字节（`checkreqprot/initialized/policycap`）写坏 | 逐档 `--stop-after` 定位；最终改为 per-SID permissive，不再写 `state+1` |
| p10 | 两次 run 在 PERM 后 abort，SETIDS 从未执行 | PERM 成功路径误入 `perm_n9_fallback` 标签 | p11 修 ①：`goto perm_fallback_done` |
| p10 | 静默 no-op 被当硬失败 | 写成功返回但目标未变 | p11 修 ②：写→校验→重发 ≤3 |
| p11d→p11e | `setresgid` EPERM → 复位（run44） | 第一次 `capable(CAP_SYS_NICE)` 在空 map 上被缓存成硬拒 | 武装前移到 cap 写之前；file 类 oracle 证明 |
| p11f | 「负控」误报策略泄漏 | `/data/system/dropbox` 是目录（EISDIR）；`/init` 是可读符号链接 | p11g 删除错误断言，改 A/B + 身份不变量 |
| p11h | `R3P_PTRACER` 读到 R2 的窗口 | `read_window` 注入写静默 no-op ⇒ 陈旧读 | p11j/rdfix：双读一致 + 重读 ≤3 + `next=0` 重置 |
| p11i→p11k | `setgroups(0)` 成功后、`setresgid` 前 panic | glibc NPTL `setxid` 广播打断 GhostLock PI 线程 | raw svc 149/147 + `sealed&&Threads==1` 门 |
| p11m | Phase B `DELIVERY_FAIL/EXIT=2`，可用的 uid0 daemon 被杀 | `zd_spawn_verify` 只在 poll 成功时评估，静默 daemon 导致漏判 | p11n：每轮评估 + 永不杀 LISTENING daemon |
| p11n | 成功；但武装阶段仍存在**未统计**的静默失败/panic | per-SID 缓存语义 + pmsg 页残留 | 未解决，见 `RISKS.md` §2.4 |

---

## 3. 本交付没有做的事（不要脑补）

- 没有实现 keeper/re-spawn；rootd 死了本 boot 就没了。
- 没有把 TCP 换成 unix socket；loopback 仍不是信任边界（见 `RISKS.md` §1）。
- 没有统计 per-SID 武装成功率；也没有把 panic 概率定量。
- 没有验证 Shizuku app 侧 `rish`。
- 没有做多用户/工作资料适配。
- 没有改任何分区、没有持久化 root。
