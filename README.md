# PHQ110 内存态 root

> 在 **OPPO PHQ110**（Android 14 / C.53 / 内核 5.4.254-qgki）上，从一条普通的 `adb shell`
> 出发，用 **CVE-2026-43499（GhostLock）** 取得 **uid0**。
>
> 不刷机、不解锁 bootloader、不写任何分区、不动用户数据。
> **代价是：它只活在内存里，重启即消失。**

这不是一个 App，也不是一个刷机包。它是一份**可审计的研究快照**：一个 1 MB 的静态
aarch64 二进制、配套源码、一个 Termux 客户端，以及把每个地址、每个偏移、每次失败都写清楚的文档。

---

## 它到底做到了什么

从 `uid=2000 / u:r:shell:s0`（adb shell 的默认身份，几乎什么都不能干）出发，在一次运行里：

| 阶段 | 结果 | 证据等级 |
|---|---|---|
| **A. 内存态 uid0** | 进程的 uid/euid/gid 全变 0，`CapEff ⊇ 0xc6`，**SELinux 域仍是 `u:r:shell:s0`**、`enforcing` 全程 = 1 | 真机实测（两次独立冷启动） |
| **B. 可用的 root 通道** | fork 出 uid0 的 `rootd` 监听 `127.0.0.1:10369`，用 32 字节 secret 鉴权 | 真机实测 |
| **C. 手机侧取得 root** | Termux 里 `termux_uid0.py ... id` → `uid=0 ... ctx=u:r:shell:s0` | 真机实测 |
| **D. Shizuku 以 root 运行** | `shizuku_server` 以 uid0 启动、binder 投递完成、`shizuku.json` 落盘 | 真机实测（服务端） |
| **E. App 侧 `rish` 真能提权?** | **没有验证** | 待人类在已授权 app 里实测 |

最反直觉的一点是 **SELinux 没有被关掉**。`enforcing` 始终是 1，我们只是让 SELinux 对
`shell` 这一个域在 capability 判定上「按 permissive 处理」——把 `policydb->permissive_map`
指向一页伪造的 ebitmap。整台机器对其它所有应用仍然是强制的；Termux 所在的
`untrusted_app_27` 域**没有**开这个口子。

---

## 原理，六句话

```
adb shell (uid 2000, shell 域, Enforcing)
  │
  ├─ ① 6 发「读」  把内核当内存读写器：找到本进程的 task_struct → cred → selinux_state
  ├─ ② 2 发「写」  把 permissive_map 指向 pmsg 页里的 fake ebitmap（只放行 shell 域）
  ├─ ③ 5 发「写」  把 cred 里 5 个 capability 字段改成受控值 V
  ├─ ④ setresgid/setresuid(0,0,0)   ← 此刻 enforcing 仍=1，但 shell 域已被放行
  ├─ ⑤ fork rootd（不走 exec，所以 uid0 与 caps 原样保留）→ 127.0.0.1:10369
  └─ ⑥ 可选 fork+exec Shizuku starter → shizuku_server 以 uid0 运行
```

1. **漏洞**：CVE-2026-43499（内部代号 GhostLock）。三线程 PI-futex 死锁环让受害者线程的内核栈上
   留下一个悬挂的 `rt_mutex_waiter`；随后 `sched_setattr` 触发 `rb_erase`，得到一次**受控的 8 字节写**。
2. **读**也是写：把目标地址 −8 写进 `tcp_mem` 的 `data` 槽，再读 `/proc/.../tcp_mem` ——
   内核替我们把那 16 字节拷出来。副作用是每次读都会写坏 `目标−8`。
3. **为什么 cap 值长成 `base+0x830C6` 这种怪样子**：写原语的 value 不能是 0（零值写会直接
   把进程打死）；非零 value 还会被内核当指针解引用做第二次写。所以 cap 值必须是个
   「既含 `0xC6` 位、又是个合法内核指针」的东西。
4. **为什么不能改 cred 指针**：换成 `&init_cred` 会让 SID 变成 `u:r:kernel:s0`（交付腿直接失效），
   而且静态对象被 `put_cred` 释放必然 panic。只能**原地改字段**。
5. **为什么 `KASLR` 不是问题**：每个 boot 用 `perf_event_open` 采内核 IP 现场解出 slide `D`，
   两次独立采样一致才继续，否则**干净中止**（绝不向错误地址开火）。
6. **为什么一个 boot 只能跑一次**：第一次运行会在内核里留下指向 pmsg 页的 `permissive_map`，
   页里的 fake 结构会被第二次运行踩坏。要重来就正常重启手机。

完整推导、每一发的目标地址与来源、每一发的成功判据与失败面，都在 [`ARCHITECTURE.md`](ARCHITECTURE.md)。

---

## 怎么用

### 你需要

- 一台 **OPPO PHQ110**（`OP5613`），Android 14 / 版本 `C.53`，内核 `5.4.254` —— 所有链接期
  常量都是这台机器这个 build 的，**换机型/换 build 直接不能用**；
- 可用的 `adb`；
- 手机上装好的 **Termux**（带 `python3`）；
- 一个**干净的 boot**：`Enforcing`、shell 域、`/proc/kallsyms` 与 `/sys/fs/pstore` 对 shell 不可读。

### 三步

```bash
# 1) 前置只读检查：任何一项不对就停，不要 push
adb shell getenforce                          # 必须 Enforcing
adb shell cat /proc/self/attr/current          # 必须 u:r:shell:s0
adb shell 'head -1 /proc/kallsyms; echo rc=$?' # 必须被拒（能读 = 本 boot 已被武装过）

# 2) 推上去 + 复核指纹
adb push build/glx_p11n /data/local/tmp/glx_p11n.r<NN>
adb shell chmod 755 /data/local/tmp/glx_p11n.r<NN>
adb shell sha256sum /data/local/tmp/glx_p11n.r<NN>
#   期望 90b9e66b0122fc94bb4decba731359fa4b6e7e828654cfdb603fd448106549e4

# 3) 跑一次（必须真 pty，否则崩溃前的日志会被吞掉）
adb shell -t -t 'cd /data/local/tmp && ./glx_p11n.r<NN> --mode device --round <NN> \
  --stop-after=shzlaunch --shz-after-deliver --deliver-fork \
  --zd=tcp --zd-port=10369 --zd-client-selftest; echo GLX_SHELL_EXIT=$?'
```

跑完在 Termux 里：

```bash
python3 ~/termux_uid0.py --chan=tcp --port=10369 --secret-file="$HOME/zd_secret" id
# → uid=0 euid=0 gid=0 pid=<rootd pid> ctx=u:r:shell:s0
```

`<NN>` 只是个轮次标签（进文件名和日志，不参与逻辑），随便给个整数。
**每个 boot 只跑一次**；想再来一遍就正常重启手机（不是 fastboot，也不是 9008/EDL）。

完整的参数解释、逐阶段判据、Termux 客户端全部子命令、故障排查表 → [`USAGE.md`](USAGE.md)。

---

## 它有多「轻」

| | |
|---|---|
| 写分区 | **零**。不碰 `boot`/`system`/`vendor`/`userdata`，不 remount |
| 持久化 | **零**。重启即全部恢复 |
| 改用户数据 | **零** |
| 第三方依赖 | **零**。单个静态二进制，无动态库、无 `su`、无 Magisk |
| 最坏结果 | 内核 oops → `panic_on_oops=1` 让手机自动重启，约 5 秒，数据无恙 |

代价是另一面：**rootd 一死，这次 boot 的 uid0 就永久没了**，只能再重启一次。
没有任何 keeper / 自我重生机制（设计过，没实现）。

---

## 安全边界：请认真读这一段

`rootd` 监听的是 **TCP** `127.0.0.1:10369`。在 Android 上，**loopback 不是信任边界**——
任何一个有 `INTERNET` 权限的 App 都能连上它。

唯一的门是 `/data/data/com.termux/files/home/zd_secret`
（64 个十六进制字符 = 32 字节随机值，权限 `0600`，属主是 Termux 的 uid）：

- **这个 secret 泄露 = 把 uid0 送给全机所有应用。** 不要 `cat`、不要截图、不要放进日志或云同步。
- 认证失败累计 3 次，daemon 会自杀（fail-closed）——所以**别拿错的 secret 反复试**。
- 想彻底解决这个问题，应该换成 `AF_UNIX` socket + 目录 0600 + `SO_PEERCRED`。
  **这个改进没有做**，当前交付就是 TCP + secret。

`rootd` 的协议里也**没有写文件的操作**（帧类型 `G/I/R/X/F/P/Q`，没有 `W`）：
它自己能读文件、能 exec，但不是一个「任意文件写入器」。

---

## 目录里有什么

```
phq110-root/
├── README.md             ← 你正在读的（人类入口）
├── AGENTS.md             ← 给 AI agent 的入口：规则、红线、完整上下文
├── ARCHITECTURE.md       13 发链路逐发拆解：打哪里、地址哪来的、怎么算成功、失败长什么样
├── USAGE.md              上机手册：命令、协议、保活、Shizuku 授权、故障排查
├── BUILD.md              怎么从源码重编（交叉编译、静态 ET_EXEC、双编译一致）
├── ARTIFACTS.md          每个文件的大小 + sha256 + 部署路径 + 完整性清单
├── RISKS.md              风险、未验证项、操作红线、事故处置矩阵
├── CHANGELOG.md          p3 → p11n 的演进，以及每一次真机失败的确切根因
├── DEFECTS.md            一次独立验收发现的 14 项文档缺陷与处置
├── ACCEPTANCE.md         一页式验收结论
├── build/glx_p11n        真机验证过的二进制（1007336 B）
├── src/                  主程序 + 内嵌 rootd + Shizuku 启动器（C）
├── tools/                Termux 客户端（Python）与重验收脚本（sh）
└── build.sh              一键重编（Linux/WSL）
```

**建议阅读顺序**：本文件 → `ARCHITECTURE.md` §4（那 13 发到底在干什么）→ `RISKS.md`
（上机前的红线）→ 真要用再翻 `USAGE.md`。

---

## 版本演进：每一次失败都留了证据

这个项目最有价值的部分可能不是「它成功了」，而是 `CHANGELOG.md` 里那一串**有根因的失败**：

| 版本 | 在真机上发生了什么 | 根因 |
|---|---|---|
| p4 | 第一次零值 cred 写 → 进程被 SIGKILL、约 1 分钟后复位 | 目标板上零值写不可用 |
| p6 | 写入 `enforcing` 后 panic | 8 字节写的**副写**把相邻 7 字节一起写坏 |
| p10 | Phase A 全绿却 abort，`setresuid` 从没执行 | 成功路径跳错了标签 |
| p11e | `setresgid` EPERM → 复位 | 第一次 capability 判定在**空 map** 上被缓存成硬拒绝 |
| p11h | 读到的 cred 其实是上一个窗口的 task 指针 | 注入写静默 no-op → 陈旧读 |
| p11k | `setgroups` 成功后、`setresgid` 前 panic | glibc 的 NPTL `setxid` 广播打断了 PI-futex 线程 |
| p11m | Phase B 报失败，还**杀掉了一个完全可用的 daemon** | `poll()` 只在有事件时判定，静默 daemon 永远等不到 |
| **p11n** | **两次干净 boot 全链成功** | 修掉上面那条 poll 漏判 |

两个成功样本：`shots=13`（boot `173a1ef0…`）与 `shots=14`（boot `58b276d2…`，
其中一发静默 no-op 被检测到后重发）。所以判据是 `shots >= 13`，不是写死 13。

---

## 明确没有做的事

不把这些写成「已完成」，是这个项目的基本纪律：

- ❌ **app 侧 `rish` 提权** —— 只有服务端证据，没有 `rish -c 'id'` 的原始输出；
- ❌ **keeper / 自动重生** —— rootd 被杀就没了，二进制里没有这段代码；
- ❌ **UDS + `SO_PEERCRED`** —— 只有设计建议，没有实现；
- ❌ **per-SID 武装的成功率** —— 已知有静默失败、有 panic、有成功，但**没有统计**；
- ❌ **多用户 / 工作资料** —— Termux 的 uid 不一定还是 10369，这条路没走过；
- ❌ **换工具链重编出同 sha256** —— 未验证（原始工具链版本没记录）；
- ❌ **其它机型 / 其它 build** —— 所有链接期常量都是 C.53/PHQ110 专用的。

---

## 免责声明

这是一份**针对自己设备的、一次性的安全研究记录**。它在设计上就避开了所有持久化手段，
但「在内核里制造一个受控写」这件事本身是有风险的：**它可以让手机 panic 重启**，
在未验证的 build 上更可能造成不可预期的结果。

如果你不是这台设备的主人，或者你不清楚 `fastboot flash`、EDL、`remount` 这些词意味着什么——
**请只读文档，不要执行。** 项目里所有红线都写在 [`RISKS.md`](RISKS.md) §5。
