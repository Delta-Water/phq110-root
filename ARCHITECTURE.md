# 架构与 13 发链路

> 本文回答：**每一发打哪里、那个地址/偏移从哪来、成功判据是什么、失败会长什么样**。
> 字段标注沿用 `AGENTS.md` §1 的三档约定。
> 代码位置均指本目录 `src/glx_p11n.c`（行号可能随版本漂移，用函数名/锚点字符串定位）。

---

## 1. 起点与终点

```
adb shell（uid=2000, u:r:shell:s0, Enforcing, 无 seccomp）
   │  glx_p11n --mode device
   ├─ S0：只读前置 + 求 D(slide) + 求 pmsg vmap + delta 门（本链默认不需要 load policy）
   ├─ 读链 6 发：定位 task_struct → cred → selinux_state
   ├─ 武装 2 发：per-SID permissive（只放行 shell type 的 capability 判定）
   ├─ cap 写 5 发：cred+0x30/0x38/0x40/0x28/0x48 := V
   ├─ SETID_GATE（setgroups(0)）→ SETIDS（raw setresgid/setresuid 0）
   ├─ 自证：uid/euid/gid/egid/fsuid/fsgid 全 0、CapEff⊇0xc6、ctx 仍 u:r:shell:s0、enforcing=1
   ├─ Phase B：fork 内置 rootd（uid0）→ 监听 127.0.0.1:10369 → secret 握手 → 3 条 REPL
   └─ stage3（可选）：fork+exec Shizuku starter → shizuku_server(uid0) → binder 分发
```

**终点的边界**：进程内 uid0 + 可读 0600 受保护文件 + 一个 uid0 daemon + 一个 uid0 的
Shizuku server。**没有**持久化、**没有**任意内核写（8 字节写原语用完即封）、**没有**任意文件写
（rootd 无 W 帧）。

---

## 2. 写原语（GhostLock / CVE-2026-43499）

### 2.1 机理（inferred，来自离线 QEMU 复现 + C.53 反汇编）

1. 三个线程用 `FUTEX_LOCK_PI` / `FUTEX_WAIT_REQUEUE_PI` / `FUTEX_CMP_REQUEUE_PI`
   构造 `O→B`、`O→C→T` 死锁环；`rt_mutex_start_proxy_lock()` 走 FULL 链返回 `-EDEADLK` 后，
   `remove_waiter()` 只清 current 的 `pi_blocked_on`，**受害者线程 T 的 `pi_blocked_on`
   仍指向其内核栈上的 `rt_mutex_waiter`**（QEMU 实测偏移：16 KB 栈内 `stack_base+0x3bb8`）。
2. T 返回用户态后，用 T 自己发出的两条 `sendmmsg(AF_INET/UDP)` 把伪 waiter/伪 lock 的字段
   铺到 T 的栈槽：`used_address` 的 memcpy 落到 `stack_base+0x3C80..0x3C98`，
   `import_iovec` 的 iovstack 拷贝落到 `0x3CA0..0x3CD0`；唯一不可控 8 字节
   `0x3C98..0x3CA0`（`pi_tree.__rb_parent_color`，被强制为 `0x80`）不与链消费的字段重叠。
3. 主线程对该 T 调 `sched_setattr(SCHED_OTHER↔SCHED_BATCH)` → `rt_mutex_adjust_prio_chain`
   → `rt_mutex_dequeue` → `rb_erase_cached` → `__rb_erase_augmented` case-1 →
   `__rb_change_child`，产生一次受控 8 字节写 `*(target) = value`。

C.53 指令级证据（离线反汇编）：`rb_erase+0x74` 是 `str x10, [x9]`，其中
`child = node->rb_right = value`。因此：

- **`value != 0` 时还会产生第二次 8 字节写：`*(value) = target - 8`**；
- `value == 0` 才是「单次干净写」；
- 目标必须 8 字节对齐；`target % 8 == 4` 时主写实际落在 `target-4`，会把 `V` 的高半字
  写进相邻字段（曾被误判为「成功」），本构建用 `W_PRE` 直接拒绝 4 mod 8 的 `cred`。

### 2.2 真机上的两个经验性失败面（observed）

| 现象 | 说明 |
|---|---|
| **静默 no-op** | 写返回 0 但目标未变（首次实现与个别 shot 都出现过）。本构建对 cap/武装写做「写→校验→重发（≤3 次）」：cap 用**用户态 `capget`/`prctl` oracle**（不发 GhostLock 回读），武装用**整轮重发 + file 类行为 oracle**。重发本身是一发新的 GhostLock 写，所以**实际发数会 >13**（第二台干净 boot 上见到 `CHAIN_OK shots=14`），且 per-shot 账本被置为 advisory。 |
| **同样形态可能失败/panic** | 武装阶段曾在干净 boot 上失败一次、panic 一次、成功一次（成功率未统计）。因此同一 boot 严禁重跑全链。 |

### 2.3 用到的「读」原语：`read_window(A)`

`read_window(A)` 并不是独立漏洞，而是把写原语当「指针注入」用：

1. 找到 `/proc/sys/net/ipv4/tcp_mem` 的 `ctl_table` 表项地址 `P.ent`（链接期常量
   `D_TCP_ENT + D`），其 `data` 指针槽在 `P.ent+8`；
2. 用一发 GhostLock 把 `A-8` 写进 `data` 槽；
3. 读 `/proc/sys/net/ipv4/tcp_mem`，内核的 show handler 从 `data` 指向的地址拷数，
   `parse_proc_nums()` 还原出 **`A` 起的 16 字节**。

**副作用（关键失败面）**：这一发的第二次写是 `*(A-8) = P.ent`。也就是说
**每读一次 `A`，就会把 8 字节写坏 `A-8`**。因此：

- 不能读 `cred+0x38`（会毁掉 `cred+0x30` 的 cap_permitted）；
- 不能读 `permissive_map.highbit`（会毁掉 `permissive_map.node`）；
- 读 `selinux_state` 会覆盖它前面的 8 字节（被接受，但不是「无副作用」，写新代码时要注意）。

**陈旧窗口**：若那一发写是静默 no-op，`data` 仍指向上一次的地址，读出来的是上一窗口的字节。
表现为 `R3'` 读到 `ptracer_cred == rq->curr`、`real_cred == rq->next`（task 指针而非 cred）。
检测器：同一目标连读两次必须一致；`R3P` 判据要求 `ptracer_cred` 为 0 或 cred-like，
**不允许是 task 指针**。

---

## 3. 地址与偏移从哪来

### 3.1 链接期常量（设备特定，来自 C.53 `System.map` / vmlinux 符号）

`profile_device()` 里加 slide `D`：

| 宏 | 链接期值 | 符号/含义 |
|---|---|---|
| `D_TEXT` | `0xffffffc010080000` | `_text` 附近（D 的唯一性校验实际用 `LINK_STEXT/LINK_ETEXT` 区间；`D_TEXT` 只作日志/参考） |
| `D_INIT_CRED` | `0xffffffc012c7edb0` | `init_cred`（本链拒绝写它，仅作 `cred == &init_cred` 防护） |
| `D_INIT_TASK` | `0xffffffc012c71700` | `init_task`（参考） |
| `D_STATE` | `0xffffffc012eee000` | `selinux_state` |
| `D_PCO` | `0xffffffc012bb0078` | `&__per_cpu_offset[0]` |
| `D_RUNQUEUES` | `0xffffffc0128a8c80` | `runqueues` |
| `D_TCP_ENT` | `0xffffffc012c6c720` | `tcp_mem` 的 `ctl_table` 表项 |
| `D_OOPS_CXT` | `0xffffffc012bd8928` | 仅 QEMU 后端用于取 pmsg ground truth |
| `PERM_SS_LINK` | `0xffffffc0132072b0` | System.map `b selinux_ss`（静态对象） |

### 3.2 结构体偏移（跨 build 通用方法 + 本机实测校验）

| 宏 | 值 | 来源与校验 |
|---|---|---|
| `D_OFF_REAL` | `0x800` | 5.4.254 `task_struct->real_cred`；R3′ 同时读 `+0x800` 与 `+0x808` |
| `D_OFF_CRED` | `0x808` | `task_struct->cred`；`QEMU` 符号/offset oracle + 真机 R3′/R4 一致性 |
| `D_OFF_COMM` | `0x818` | `task_struct->comm`（16 字节）；用于身份门 R3C |
| `D_OFF_PTRACER` | `0x7f8` | `task_struct->ptracer_cred`；判据「0 或 cred-like」 |
| `D_RQ_CURR` | `0x8d8` | `struct rq->curr`；R2 由 `runqueues + off + per_cpu_offset[cpu]` 得到 |
| `D_CRED_EUID` | `0x14` | `struct cred` 的 euid/egid 对 + `fsuid/fsgid` 对（16 字节一次读） |
| `CRED_OFF_UID_GID` | `0x04` | uid/gid 对（本链**不写**，只做结构校验） |
| `CRED_OFF_SUID_SGID` | `0x0c` | suid/sgid 对（不写） |
| `CRED_OFF_EUID_EGID` | `0x14` | euid/egid（R4 校验为 2000） |
| `CRED_OFF_FSUID_FSGID` | `0x1c` | fsuid/fsgid |
| `CRED_OFF_CAP_INH` | `0x28` | `cap_inheritable`（WC4） |
| `CRED_OFF_CAP_PERM` | `0x30` | `cap_permitted`（WC1，`setresuid` 时被重算到 effective） |
| `CRED_OFF_CAP_EFF` | `0x38` | `cap_effective`（WC2） |
| `CRED_OFF_CAP_BSET` | `0x40` | `cap_bset`（WC3，exec 边界靠它） |
| `CRED_OFF_CAP_AMB` | `0x48` | `cap_ambient`（WC5） |

> 源码里有 `_Static_assert` 锁住这些偏移；改源文件时若结构体定义漂移，编译会直接失败。

### 3.3 `D`（KASLR slide）的求解（observed）

`dev_solve_D()`：

1. `perf_event_open` 采本进程内核 IP（`PERF_SAMPLE_IP|TID|REGS_INTR`，Ring 64 页；
   `perf_event_paranoid=-1`、SELinux 对 shell 放行 perf），采样窗口 3 秒；
2. 在 `[0x1000000000, 0x3000000000)` 内按 `0x200000` 步长找唯一 `k`，使所有内核 IP
   `ip-k ∈ [LINK_STEXT, LINK_ETEXT) = [0xffffffc010081000, 0xffffffc0118b0000)`；
3. 候选必须通过 `d_candidate_valid()`（范围/对齐/段），且**两个独立采样窗口结果一致**，
   最多 5 次尝试；不一致就干净中止，**不会向错误地址发 shot**。

本次成功 boot 实测：`D = 0x13c2c00000`（**设备特定，每次冷启动可能变，不要写死**）。

### 3.4 pmsg 页（写原语的「弹药库」，observed）

- `/dev/pmsg0` 是 `0222` 的 ramoops `persistent_ram`，数据区 `PMSG_DATA_LEN = 0xFFFF4`；
- vmap 基址按 **1 MB 对齐**取得：真机走 perf 泄漏（`__arch_copy_from_user` 路径，`S0_PMSG_VMAP`），
  QEMU 走 `/proc/pmsgctl` 的 `MPRZFIELDS`；
- 布局（相对 `base`）：
  - `base+0x2000`：fake `rt_mutex`（`PMSG_OBJ_OFF`；数据偏移 `0x1FF4`，8 字节对齐），
    整个环用 0 填充——全零页是合法 `rt_mutex`（trylock 成功、空 waiters、owner=NULL）；
  - `base+0x100`：fake `ebitmap_node`（`PERM_NODE_VMAP_OFF`，数据偏移 `0xF4`，按环索引回绕）；
  - `base+0x3000`：`permissive_map.highbit` 的写值 `W`（低 32 位即 highbit）；
  - `base+0x830C6`：cap 值 `V`（见 §5）；`V` 的副写落在这一页内，每次 shot 前重新清零。

`obj` 锚定经验：`base & ~0xFFFFF` + `0x2000`（曾因用 `write-head+0x80000` 而不稳）。

---

## 4. 13 发逐发说明（observed：本次成功 run 的实打地址）

> **设计账本 = 13 发**（6 读 + 2 武装写 + 5 cap 写）；这里的「发数」指**设计上的** GhostLock
> 写次数，不是日志里 `shots=` 的绝对值：某一发静默 no-op 被检测到并重发时，`GLX|CHAIN_OK shots`
> 会变成 14（第二台干净 boot 上就是 14）。所以判据是 `shots >= 13`、`SHOT` 标签链完整、
> `RES|FAIL=0`，**不要用固定 13 卡判据**。也**不要**把早期 15/16 发的口径套上来。
> 表中「目标」地址示例来自某次 boot（`D = 0x13c2c00000`），**每 boot 都会变**。

| # | 标签 | 目的 | 写入目标 / 读取地址 | 地址与偏移来源 | 成功判据 | 失败面 |
|---:|---|---|---|---|---|---|
| 1 | `R1` | 证明 `D` 正确，并拿到 per-CPU 偏移 | 读 `A_pco = D_PCO + D`（`__per_cpu_offset[0..1]`） | `D_PCO` 来自 System.map；`D` 现场求解 | `pco[0]/pco[1]` 都页对齐且步长合法（`pco_pair_ok`） | 错误 D 会得到 `0x2c257/0x4237e` 这类伪值；重试 ≤5 后干净 `CHAIN_ABORT`，绝不向错地址发 shot |
| 2 | `R2` | 拿到受害者线程 T 的 `task_struct` | 读 `A_rq + 0x8d8 + per_cpu_offset[cpu]`（`rq->curr`） | `D_RUNQUEUES`/`D_RQ_CURR` + `R1` 的 per-CPU 偏移 | 返回值是内核指针、对齐合法、且不等于 `rq->next`；前置 `R2_CPU_PIN` 要求该 CPU 是 T 的 CPU 且不是主线程 CPU | 主线程在 pin 与检查之间迁移 → 重试 ≤5；仍不满足则中止（0 发 cred 写） |
| 3 | `R3P` | 拿到 `cred` 指针，并检测「陈旧读窗口」 | 读 `task+0x7f8`：`b[0]=ptracer_cred`，`b[8]=real_cred`（`+0x800`） | `D_OFF_PTRACER`/`D_OFF_REAL` | `ptracer_cred` 为 0 或 cred-like；**若是 task 指针 ⇒ 陈旧窗口** | 陈旧窗口（上一发的静默 no-op）会让这里读到 `R2` 的窗口；`r3p_decide()` 判负即中止（这正是某版 `p11h` 真机失败的原因，见 CHANGELOG） |
| 4 | `R3C` | 身份门：确认 T 是我们命名过的受害者线程 | 读 `task+0x818`（`comm`，16 字节） | `D_OFF_COMM`；名称是主线程用 `prctl(PR_SET_NAME)` 设的随机 nonce | `comm` 必须等于 nonce（不是「非空即可」） | 读窗陈旧/读错任务 → 重试 ≤5 后 fail-closed 中止，**在任何 cred 写之前** |
| 5 | `R4` | 确认 `cred` 指针确实是本进程的 cred | 读 `cred+0x14`（euid/egid、fsuid/fsgid） | `D_CRED_EUID` | 两个 64 位字都等于 `uid | uid<<32`（uid=2000） | 不符 → 中止；说明 `cred` 指针错或结构偏移变 |
| 6 | `R5` | 记录 SELinux 初始状态，作为后续判据基线 | 读 `A_state = D_STATE + D`（`selinux_state` 前 16 字节） | `D_STATE` | `disabled=0`、`enforcing=1`、`checkreqprot=0`、`initialized` bit0=1 | 任一不符 → 中止（设备状态不符合本链前提） |
| 7 | `PERMNODE` | 武装：把 `permissive_map.node` 指向我们的 fake ebitmap node | 写 `*(selinux_ss + 0x1D0) = X`，`X = vmap_base + 0x100` | `PERM_SS_LINK`（System.map `b selinux_ss`）；`selinux_ss+0x08` 内嵌 `policydb`，`policydb+0x1C8` 是 `permissive_map` ⇒ 绝对偏移 `ss+0x1D0`（node）/`ss+0x1D8`（highbit） | 本发本身不做回读；同一 round 内紧跟 `PERM_HI` 后用**全新的 file 类行为 oracle** 判定整轮武装成功；此时 highbit 仍为 0 ⇒ 完全惰性 | 静默 no-op；若两发都未落地就进入 cap 写，第一次 `capable(CAP_SYS_NICE)` 会在空 map 上把 `(shell,shell,SECCLASS_CAPABILITY)` 缓存成硬拒绝 ⇒ 后续 `setresgid` EPERM。本构建用「整轮重试 ≤3 + 每轮换一个全新 (tsid,tclass) oracle」兜底 |
| 8 | `PERM_HI` | 激活 per-SID permissive | 写 `*(selinux_ss + 0x1D8) = W`，`W = vmap_base + 0x3000`（低 32 位是 highbit） | 同上 | 行为 oracle：`/proc/kallsyms`（其次 `/proc/sys/kernel/kptr_restrict`、`/proc/sys/kernel/panic_on_oops`）由 `EACCES` 翻成可读；`enforcing` 仍 =1 | ① 静默 no-op（同上）；②「已缓存硬拒节点不翻转」——见 §6；③ 该阶段真机出现过 panic（未统计原因/概率） |
| 9 | `WC1_cap_perm` | 写 `cap_permitted`：为了让 `setresuid` 时 `cap_emulate_setxuid` 把 effective 重算成 `V` | 写 `cred+0x30 = V` | `CRED_OFF_CAP_PERM` | 写后用 **`capget(2)` 用户态 oracle** 校验 `cap_permitted` 低 32 位等于 `V`（不发 GhostLock 读）；随后 `WC_CAPS` 检查 `cap_effective & 0xc6 == 0xc6` | 静默 no-op → 同一发重发 ≤3 次；耗尽 → 中止；`cred%8==4` 直接拒绝 |
| 10 | `WC2_cap_eff` | 写 `cap_effective`：让 `CAP_DAC_OVERRIDE/READ_SEARCH/SETGID/SETUID` 立即可用 | 写 `cred+0x38 = V` | `CRED_OFF_CAP_EFF` | `capget` oracle：effective 低 32 位 == `V`，含 `0xc6` | 同上 |
| 11 | `WC3_cap_bset` | 写 `cap_bset`：execve 边界用 `pP' = cap_bset | cap_inheritable` 重算 | 写 `cred+0x40 = V` | `CRED_OFF_CAP_BSET` | `prctl(PR_CAPBSET_READ)` oracle：`cap_bset & 0xc6 == 0xc6` | 同上 |
| 12 | `WC4_cap_inh` | 写 `cap_inheritable`：ambient 档必需（`pA' ⊆ pP' & pI`） | 写 `cred+0x28 = V` | `CRED_OFF_CAP_INH` | `capget` oracle：inheritable 低 32 位 == `V` | `--no-ambient` 时不发此发（fork-only 档，14 发口径）；ambient 档失败 → 中止 |
| 13 | `WC5_cap_amb` | 写 `cap_ambient`：让 execve 后子进程仍保留 `CapEff=0xc6` | 写 `cred+0x48 = V` | `CRED_OFF_CAP_AMB` | `prctl(PR_CAP_AMBIENT_IS_SET)` oracle：`cap_ambient & 0xc6 == 0xc6`；exec 子进程 `CapEff/CapPrm/CapInh/CapAmb ⊇ 0xc6` | C.53 的 adb-shell cred 带 `SECURE_NOROOT`，`cap_bprm_set_creds()` 跳过 `handle_privileged_root()`，exec 后 `pP'=pE'=pA'`；若 `cap_ambient` 没写成，exec 子进程 `CapEff=0`（这正是早期某版的真机失败） |

**为什么 `V` 不是字面量 `0x6/0xc6`**（inferred + 真机验证的后果）：

- 写原语要求 `value` 非零时还能被内核当指针解引用（副写 `*(value)=target-8`）。
  把 `0x6` 当 value 会写地址 `0x7` → 翻译错误 → oops → `panic_on_oops=1` 自复位（约 5 秒）。
- 于是取 `V = vmap_base + 0x2000 + 0x810C6 = base + 0x830C6`：
  - `V % 8 == 6` ⇒ 低位的 bit1/bit2（`CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH`）天然为 1；
  - 低 32 位 `0x830C6 = 0x80000 + 0x2000 + 0x1000 + 0xC6`：bit13（`CAP_NET_RAW`）来自
    `obj` 偏移 `0x2000`，bit12（`CAP_NET_ADMIN`）来自 `+0x1000`（两者本链都不依赖）；
  - `+0x80000` 带来 bit19（`CAP_SYS_PTRACE`，这是「若 NPTL 广播没送到 T，后续 `sched_setattr(T)`
    仍能通过 `ptrace_may_access()`」的保险位，属**hedge**，不是必要项）；
  - 真实依赖只有 bit1/2/6/7（`0xC6`）；其余位在 shell 域里仍被 SELinux 逐次把关。
  - `V` 的高 32 位来自 vmalloc 高半部；`CAP_LAST_CAP=37`，高位被忽略。

**为什么还要写 `cap_permitted`**：`setresuid` 从 2000 到 0 会触发
`cap_emulate_setxuid()` 把 `cap_effective := cap_permitted`；不写 `+0x30` 就会在 `setresuid`
那一刻丢掉所有 capability（早期版本的失败原因）。

**为什么 cap 写不能用 GhostLock 回读**（observed 失败）：`read_window(A)` 的副写是
`*(A-8) = tcp_mem_entry`。若用 GhostLock 回读 `cred+0x38`，副写会直接破坏
`cred+0x30`（cap_permitted）；回读 `cred+0x40` 会破坏 `cred+0x38`（cap_effective）。
某次真机就因此看到 `cap_effective = ctl_table_addr-8`。所以本构建的 cap 写校验**只用
用户态 `capget(2)`/`prctl(2)` oracle，不发 GhostLock 读**——这也让「写→校验→重发」不会
把相邻字段写坏。同理，`permissive_map.highbit` 也不能用 GhostLock 读回（会破坏
`permissive_map.node`），所以武装的证明只能用 file 类行为 oracle。

---

## 5. 发后收口：seal / purge / quiesce（observed）

发完最后一发立即：

1. **seal**：`dev_write8` 进入守卫态（再调用返回 `-7`），之后不再有任何 `sched_setattr/futex/pthread` 工作；
2. **purge**：把 fake lock 在 pmsg 页里重新清零（`rb_leftmost=0` ⇒ 走良性分支，`node->next` 保持 0）；
3. **quiesce**：join/kill 所有辅助线程，要求 `Threads==1`。

判据：`RES|PASS|QUIESCE_TASKS|threads=1 after the final shot`。

**为什么必须收口**：`glibc` 的 `setresgid/setresuid` 在有多个线程时会走 NPTL `setxid` 广播
（`tgkill(SIGSETXID)` 到每个线程）。这个信号会打断仍停在 GhostLock PI futex 上的辅助线程，
让 `remove_waiter → rt_mutex_adjust_prio_chain` 解引用被 sendmmsg 模板改写过的
`task->pi_blocked_on / waiter->lock` 槽，`put/free` 残留 `pi_state` ⇒ 复位。
本构建因此：

- 用 **raw syscall** `setresgid`(svc 149) / `setresuid`(svc 147) 而不是 glibc wrapper（无广播）；
- 在此之前做 `SETIDS_PRECHECK`：要求 `sealed==1 && Threads==1`，否则 **0 后发、干净中止**
  （`--allow-mt-setids` 可覆盖，但不建议）。

---

## 6. per-SID permissive 的机制与「静默失败」根因

（inferred，离线指令级裁定 + 真机行为 oracle 验证）

- 判定不是每次 `deny` 都动态发生：`security_compute_av()` 在建 AVC 节点时按
  `scontext->type` 查 `policydb->permissive_map`，把 `AVD_FLAGS_PERMISSIVE` 写进 `avd.flags`，
  **随 `avc_node` 缓存**；`avc_denied()` 只读缓存的 `avd.flags`。
- 因此：**在武装之前就已经被缓存为「硬拒绝」的节点，武装后不会翻转**。
  这是为什么：
  - 必须在任何 `capable(CAP_SYS_NICE)` 之前武装（每发 GhostLock 都要 `sched_setattr`，
    它本身就会做 `capable(CAP_SYS_NICE)`，且 AVC key 只有 `(ssid,tsid,tclass)`）；
  - 武装的证明只能用**全新的 file 类 oracle**（每个 `(tsid,tclass)` 一个 boot 只能用一次），
    绝不能用 capability 类探针（第一次 capability 判定会把节点缓存死）。
- 武装写本身可能静默 no-op；若没重发就进入 cap 写，第一次 capability 判定就在空 map 上被缓存，
  之后 `setgroups/setresgid` 全部 EPERM（某次真机失败的确切原因）。
- 本构建的兜底：整轮（PERMNODE+PERM_HI）重试 ≤3；每轮换一个 oracle；耗尽则在任何 cap 写之前
  干净中止。已知仍会出现 panic（原因未完全定死，概率未统计）。

`permissive_map` 结构：

```
selinux_ss (静态对象, System.map `b selinux_ss`)
  +0x00  struct sidtab *sidtab
  +0x08  struct policydb（内嵌）
            +0x1C8  permissive_map.node      ⇒ 绝对 ss+0x1D0
            +0x1D0  permissive_map.highbit   ⇒ 绝对 ss+0x1D8
```

fake ebitmap node 内容（在 pmsg 页 `base+0x100`）：

```
+0x00  next      = 0                    （链终止）
+0x08  maps[0..5]= 1 << 56              （shell type 1464；startbit=1408 ⇒ bit 56）
+0x38  startbit  = 1408
```

`untrusted_app_27`（type 1498，bit 90）在本交付里**不**设为 permissive
（`PERM_UA27_PERMISSIVE 0`），保持「zero-delta」：只给 shell 域开口子，Termux 应用域仍 Enforcing。

---

## 7. SETIDS 与身份不变量（observed）

```
SETID_GATE: setgroups(0, NULL)  —— 与 setresgid 完全相同的 capable(CAP_SETGID) 路径
  rc==0 才继续；非 0 则 0 后发、干净中止（避免「EPERM 后自复位」）
SETIDS_PRECHECK: sealed==1 && Threads==1
SETIDS: raw setresgid(0,0,0) / setresuid(0,0,0) / setfsgid(0) / setfsuid(0)
```

判据（都不依赖程序自己的 RESULT 行）：

- `V8_IDS`：uid/euid/gid/egid/fsuid/fsgid 全 0；
- `V8_DOMAIN`：`/proc/self/attr/current == u:r:shell:s0`；
- `V8_CAP_EFF/BSET`：`capget`/`prctl` 看到 `⊇ 0xc6`；
- `V8_CAP_INH/AMB`：ambient 档 `⊇ 0xc6`；
- `PERMSET_FORENSICS`：以 uid0 **在本进程内** `stat/open/read/sha256` 一个 0600 的
  `system:system` 文件（默认 `/data/system/entropy.dat`），shell 原本 `-EACCES`。

> 注意：`entropy.dat` 的 **sha256 是设备特定值**，会随设备状态变化。本次 runs 见过
> `594d670b…`，而早期记录是 `789a3e95…`。**只把它当「能读通」的证据，不要把它当固定指纹**。

---

## 8. 交付腿 Phase B：rootd（observed）

- **不是 exec**：`--deliver-fork` 让子进程直接调用内嵌的 `rootd_main()`（没有 bprm，
  所以 uid0 与所有 cap 集合原样保留）。
- **secret 门**（fail-closed）：路径默认 `/data/data/com.termux/files/home/zd_secret`；
  要求 size ≥32、mode `0600`、属主 == `--zd-secret-uid`（默认 10369）。
  - 若文件不存在：glx 用一个**临时降权到 uid 10369 的 fork 子进程**创建
    （`/dev/urandom` 32 字节 → 64 hex，`O_EXCL`，0600）——这样属主天然是 Termux，
    root 子进程没有 `CAP_CHOWN` 也能交付。
  - 若存在但权限/属主不对：打印 `GLX|ZD|SECRET_GATE=FAIL` 并**拒绝继续**。
- **监听**：`--listen=tcp --port=10369`（`SO_REUSEADDR`；`bind 127.0.0.1`）。
- **父进程侧验证**（p11n 的关键修复）：每轮 `poll(200ms)` 后都评估成功条件
  `have_listen && (allows>=1 || now-tseen>=1s)`；真实 daemon 只打印一次 `ROOTD|LISTENING`
  然后保持静默，旧版只在 `poll>0` 时评估 ⇒ 超时误判 ⇒ 杀掉可用 daemon。
- **一旦 LISTENING 成立，永不 kill**：之后客户端自检/stage3/取证失败都只打印
  `GLX|ZD_PERSIST|...|KEEP=1`，daemon 由 init 收养（`ppid=1`）继续监听。
- 关键证据行：
  - `GLX|ROOTD_LISTEN|PASS|pid=...|port=10369|uid=0|euid=0|ppid_after_exit=1|chan=tcp`
  - `GLX|DELIVER|chan=tcp|child_pid=...|ppid_after_exit=1|port=10369|...|exec=NO|...|revoke=kill -9 ...`
  - `GLX|ZD_SECRET|POST_LISTEN|...|mode=0600|uid=10369|termux_readable=1`
  - `GLX|ZD_UID|PASS|... uid=0 euid=0 gid=0 pid=... ctx=u:r:shell:s0`
  - `GLX|ZD_REPL|SUMMARY|n=3|ok=3|want=3`
- **进程身份取证限制**：rootd 是 fork 出来的内嵌 `rootd_main()`（无 exec），`comm` 仍是父进程名；
  `adb shell`(uid2000) 读 uid0 进程的 `/proc/<pid>/exe` 会被拒（EACCES），所以「exe 仍是 glx_p11n」
  只能标 **inferred**。可靠证据是 `Uid=0`、`/proc/<pid>/attr/current=u:r:shell:s0`、
  `/proc/net/tcp` 的 10369 `st=0A uid=0`、以及 secret 文件的属主/权限。
- **daemon 内部限制**：`--idle=86400`（24h，不是 p11m 的 300s）、`--max-conn=32`、
  `authfail>=3` 退出、`--soft-assert`（启动断言只打印证据、不阻止 LISTEN）、`--dac-caps`。
  非法 secret 的连接会被 DENY 并计数；3 次错误后 daemon 自行退出（fail-closed）。

---

## 9. stage3：Shizuku root（服务端 observed；app 侧 rish 未验证）

`shz_run()`（`src/shz_launch.c`）：

1. 自动发现 Shizuku APK（`moe.shizuku.privileged.api`）与 `lib/arm64/libshizuku.so`；
2. 选择模式：`auto` = 有可读 `libshizuku.so` 就用 **starter**，否则直接 exec
   `/system/bin/app_process`；
3. 用 Shizuku 启动所需的 init 环境（`BOOTCLASSPATH` 等；见 `shz_env_snapshot.h`）fork+exec；
4. 验证新进程 `comm == shizuku_server`、uid=0、`CapEff/CapAmb ⊇ 0xc6`、ctx 仍 `u:r:shell:s0`；
5. 锚点：
   `GLX|STAGE3_INIT|mode=starter|uid=0|euid=0|apk=...` →
   `GLX|STAGE3_EXEC|pid=...` → `GLX|STAGE3_MAIN|PASS|pid=...` →
   `GLX|STAGE3_BINDER|PASS|json=/data/user_de/0/com.android.shell/shizuku.json|size=...` →
   `GLX|SHZ_AFTER_DELIVER|PASS rc=0`。

退出码契约（`shz_launch.h`）：`0 ok / 3 env / 4 fork / 5 exec / 6 uid / 7 apk / 9 kill-old /
10 SELinux / 11 verify`。`STAGE3_MAIN|FAIL` 或 `STAGE3_BINDER|UNKNOWN` **只是 stage3 的诊断**，
不影响 `ROOTD_LISTEN`/`ZD_PERSIST` 的有效性——Termux 仍可用 uid0 daemon。

> **判据形态（重要）**：`--shz-after-deliver` 形态下，starter fork 的 `app_process` 的 stderr
> 被父进程管道接走，**不会**出现在 logcat；因此不要等 `AndroidRuntime / RuntimeInit /
> Calling main entry / send binder / attachApplication` 这些行。可用替代证据链是
> `STAGE3_INIT → STAGE3_EXEC → STAGE3_MAIN|PASS+ctx → STAGE3_BINDER|PASS(json size)`，
> 再加进程态（`shizuku_server` uid0 / `CapAmb⊇0xc6` / `cmdline=shizuku_server` / `PPid=1`）
> 与（可选）`binder_sample` / `am_proc_start`。那些 RuntimeInit 行只在「直接在 pty 上跑
> app_process」的形态可得（见 CHANGELOG p11i），不是本链判据。

**未验证**：Shizuku Manager 授权 root 后，受支持 app 内 `rish -c 'id'` 的真实提权结果。
本仓库只有 server 侧 uid0 + binder 投递 + `shizuku.json` 落盘的证据。

---

## 10. keeper / Termux 交付腿的现状

| 项 | 状态 |
|---|---|
| Termux 客户端 `termux_uid0.py` | **已交付**，宿主协议测试全过；真机上用于 `id` 与 `selftest` 成功（observed） |
| `termux_accept.sh` | p11m 时代写的重验收脚本（含 10s 救援等待）；p11n 修好 poll 后**不再必需**。若使用，注意它会与 `--zd-client-selftest` 抢单线程 accept |
| keeper / re-spawn | **未实施**。离线裁定：三条前提（exec 后 uid0+caps⊇0xC6、SELinux 仍 shell 域、per-SID permissive 无需 load policy）原理成立，但现役二进制内没有 keeper 代码；要落地需下次冷启动上机的新构建 |
| unix socket + 0600 改进 | **未实施**（见 RISKS §1） |

---

## 11. 「设备特定值」vs「跨 build 通用方法」（重要）

| 设备特定 / 每次冷启动要重采 | 跨 build 通用的方法 |
|---|---|
| KASLR slide `D`（本次 `0x13c2c00000`） | 用 perf 内核 IP + `[LINK_STEXT, LINK_ETEXT)` 唯一候选 + 双窗口一致求解 D |
| 链接期常量：`D_STATE`/`D_PCO`/`D_RUNQUEUES`/`D_TCP_ENT`/`D_INIT_CRED`/`PERM_SS_LINK` 等 | 「符号名 → 链接期地址 + D」的换算方式；结构体偏移用 `_Static_assert` 锁定 |
| pmsg vmap base（本次 `0xffffffc010f00000`；1 MB 对齐） | `/dev/pmsg0` + perf 泄漏/`pmsgctl` 取 vmap，`obj=base+0x2000`、node=`base+0x100`、highbit=`base+0x3000` |
| `task_struct`/`cred` 的实际地址、`stack_base` | 偏移 +0x800/+0x808/+0x818/+0x7f8/+0x8d8、cred +0x14/+0x28/+0x30/+0x38/+0x40/+0x48；栈槽 `stack_base+0x3bb8` / 填充 `+0x3C80..0x3CD0` |
| `/data/system/entropy.dat` 的 sha256/内容 | 「uid0 + DAC_OVERRIDE 才能读的 0600 system:system 文件」这一判据形态 |
| boot_id、uptime、pid | 前置只读检查与「一 boot 一次」纪律 |
