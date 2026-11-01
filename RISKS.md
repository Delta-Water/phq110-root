# 风险、未验证项与操作红线

> 本文件是「上线前必须知道」的集合。**不要把这里标为未验证的东西写成已完成。**

---

## 1. 安全风险：loopback 不是信任边界（**最高优先级**）

### 1.1 事实

`rootd` 绑定 `127.0.0.1:10369`（TCP）。在 Android 上：

- 任何持有 `INTERNET` 权限的应用都能 `connect(127.0.0.1:10369)`；
- `127.0.0.1` **不是**隔离边界，也不是「只有 Termux 能连」。

当前唯一鉴权：连接首行 `ZD1 <hex-secret>\n`，其中 secret 是
`/data/data/com.termux/files/home/zd_secret`（默认）：

| 属性 | 值 |
|---|---|
| 长度 | 64 个十六进制字符 = 32 字节随机（`/dev/urandom`） |
| 权限 | `0600` |
| 属主 | Termux uid（通常 **10369**） |
| 鉴权失败 | 单次连接 DENY 并关闭；累计 3 次 ⇒ daemon 自行退出（fail-closed，但也意味着本 boot 的 uid0 通道被耗掉） |

### 1.2 后果

**secret 一旦泄露（被 `cat`、截图、写进日志、复制到 `/sdcard`、备份、云同步），
或被人为改成弱口令，等于把 uid0 交给全机应用**：任何 app 连上后都能用 `X/F/P` 帧以
uid0 + `CapEff 0xc6` + `u:r:shell:s0` 执行命令（仍受 SELinux/DAC 限制，但已经远超普通 app）。

### 1.3 必须遵守

- secret 只放 Termux 私有目录；不打印、不日志、不进版本库（本仓库也没有它的值）。
- 不要用 `--zd-secret-uid` 指到非 Termux uid，除非你明确知道那意味着谁可读。
- 不要在多用户/工作资料里复用同一个 secret。
- 设备上出现陌生进程连 10369 时，按「已泄露」处理：冷启动，重新生成 secret。

### 1.4 改进建议（**未实施**）

优先方案：**改用 `AF_UNIX` 文件系统 socket + 0600**：

- socket 文件放在 Termux home（`0700` 目录）下，路径不可被其它 app 访问；
- rootd 用 `SO_PEERCRED` 校验对端 uid（白名单 10369，fail-closed）；
- 仍然保留 ≥32B secret 作为纵深（防同 uid 的其它 Termux 进程/被劫持脚本）。

次要方案：TCP 上再叠一层非对称/一次性 token、或绑定前随机端口并只通过 Termux 侧文件传递。

**以上都只是建议**：当前交付的 rootd 是 TCP + secret，没有 UDS 实现。

### 1.5 其它暴露面

- `termux_uid0.py` 的 stdout 只放 payload，诊断走 stderr——不要把 stderr 重定向进日志后到处传
  （里面会有路径/pid，虽无 secret，但会暴露攻击面）。
- Shizuku Manager 的 root 授权等同于把 uid0 分发给被授权 app；授权列表要最小化。

---

## 2. 四个「为什么不能这样做」的失败面

### 2.1 为什么不能用零值写

- 写原语的非零 `value` 会附带第二次写 `*(value) = target - 8`。把字面量 `0` 当 value 看似
  「单次干净写」，但真机上**第一发零值写就会导致进程 SIGKILL、约 1 分钟后内核复位**
  （两次不同 boot 都复现）；QEMU 里同类形态则表现为**静默 no-op**（返回 0、目标未变）。
- 因此本构建**全面禁止零值写**：uid/gid 不靠写 `cred+0x04/0x0c/0x14/0x1c`，而是靠
  `setresgid/setresuid(0,0,0)` 系统调用；capability 写用非零受控值 `V`。
- `4 mod 8` 的目标也被禁止：主写会落到 `target-4`，把 `V` 的高半字写进相邻字段，
  而每一发都「返回成功」——最危险的静默错误。

### 2.2 为什么同一个 boot 不能重跑 glx

- 第一次运行会在内核里留下 **per-SID permissive 的已武装 map**（指向 pmsg 页里的 fake
  ebitmap node）。第二次运行的 `PERM_PRE` 会看到 `node != 0 / highbit != 0`，
  按设计**干净中止**（除非 `--perm-force/--perm-armed`）。
- 但经验上：**在已武装的 boot 上重跑全链出现过 panic**；而且 pmsg 环页里残留的
  fake `rt_mutex`/PI 残留会让第二次的读/写窗口不可预测。
- 所以纪律是硬性的：**一个 boot 一次全链**。要重来 ⇒ 人类正常冷启动（不是 bootloader/9008）。

### 2.3 为什么「kernel 域方案」不行

早期备选是把 `task->real_cred/cred` 直接换成 `&init_cred`（或改 cred 指针）。离线指令级裁定
+ QEMU 验证给出两条否决理由：

1. **SID 变 `u:r:kernel:s0`**：交付腿需要「uid0 + shell 域」。kernel 域既不能 accept
   一个 shell 标签的 listener，也不能被 `untrusted_app_27` 正常 connect；
   `setcon` 回 shell 也救不回来（域转换与策略限制）。
2. **引用计数/释放**：`init_cred` 是静态 `.data` 对象；`cred` 的 usage 递减会走到
   `put_cred_rcu`，对静态对象做 slab 释放 ⇒ 必然 panic。

结论：只能在**原地**改 cred 的字段，**不能动 `task->real_cred/cred` 指针**，也不能碰
`init_cred`。本构建还有 `W_PRE`：`cred == &init_cred` 直接拒绝。

### 2.4 为什么 per-SID 武装会静默失败（甚至 panic）

- permissive 判定**不是每次 deny 动态发生**：`security_compute_av()` 在建 AVC 节点时按
  `scontext->type` 查 `permissive_map`，把 `AVD_FLAGS_PERMISSIVE` 写进 `avd.flags`，
  随后 **随 `avc_node` 缓存**；`avc_denied()` 只读缓存标志。**武装前已缓存的硬拒节点不会翻转。**
- 两个直接后果：
  1. 必须在任何 capability 判定之前武装（每发 GhostLock 都要 `sched_setattr`，
     它本身会做 `capable(CAP_SYS_NICE)`，把 `(shell,shell,SECCLASS_CAPABILITY)` 缓存死）；
  2. 证明武装只能用**全新的 file 类 oracle**，绝不能用 capability 类探针；同一
     `(tsid,tclass)` 一个 boot 只能用一次。
- 武装写本身可能静默 no-op；若不重发就进入 cap 写，第一次 capability 判定在空 map 上被缓存
  ⇒ `setgroups/setresgid` 全部 EPERM。
- 兜底：整轮重试 ≤3、每轮换 oracle、耗尽则在任何 cap 写前干净中止。
- **仍未解决**：真机上出现过一次武装静默失败、一次干净 boot 单发 panic、一次成功；
  **成功率与影响因素未统计**（这是当前最大的不确定性）。

---

## 3. 未验证 / 未实施清单（禁止写成已完成）

| 项 | 状态 | 说明 |
|---|---|---|
| Shizuku app 侧 `rish` 实际提权 | **未验证** | 只有 server uid0 + binder 投递 + `shizuku.json` 落盘（`flags=2` 解读也是 inferred） |
| keeper / 自动 re-spawn | **未实施** | rootd 被杀/OOM/崩溃后，本 boot 的 uid0 永久丢失；重新构建需新 boot 上机 |
| per-SID 武装成功率 | **未统计** | 已知失败/panic/成功各出现；不要宣称 100% |
| unix socket + 0600 改进 | **未实施** | 见 §1.4 |
| 多用户 / 工作资料 | **未验证** | Termux uid 可能不是 10369；需预建 secret 并给 glx 传 `--zd-secret-file/--zd-dir` |
| file 通道作为交付通道 | **未验证（本链不用）** | rootd 是 TCP-only；`termux_uid0.py --chan=file` 只有在 rootd `--zd=file` 时才有意义 |
| `--perm-force`（同 boot 重武装） | **不建议 / 未验证** | 代码支持但会绕过 `PERM_PRE` 的干净检查；与「一 boot 一次」冲突 |
| `--allow-mt-setids` | **不建议 / 未验证** | 会绕过 `Threads==1` 门，重新引入 NPTL setxid 广播风险 |
| `--no-ambient` 档 | **已实现但非交付档** | fork-only；exec 子进程 `CapEff=0`，写不了受保护路径 |
| QEMU 后端可复现 | **不是交付范围** | 需要 `gl_rw.ko`/`/proc/glctl`，本目录不提供 |
| 跨工具链字节级可复现 | **未验证** | 见 BUILD.md §2 |
| 其它机型/其它 build | **未验证** | 所有链接期常量都是 C.53/PHQ110 特定 |

---

## 4. 运行期风险与运维纪律

| # | 风险 | 影响 | 纪律 |
|---:|---|---|---|
| 1 | 已武装 boot 重跑 glx | panic / 自复位 | 一 boot 一次；重来必须冷启动 |
| 2 | 向 `/dev/pmsg0` 写入（任何进程/脚本） | fake ebitmap node 住在这个 **0222 世界可写**页里；第三方写可覆盖 `next/startbit` ⇒ SID≥1792 的 AVC miss 野读 ⇒ `panic_on_oops=1` 自复位 | armed 后禁止任何 `/dev/pmsg0` 写；也禁止 unbind/卸载 ramoops 驱动 |
| 3 | 杀掉 rootd / shizuku_server | 立刻永久失去本 boot 的 uid0 通道（且不能在本 boot 重建） | 不要杀；要收尾就冷启动 |
| 4 | rootd 空闲/连接数/认证失败退出 | `--idle=86400`、`--max-conn=32`、`authfail>=3` 都会让 daemon 退出 | 长期用要保活（每 60s 一条 `id`）；不要用错 secret 反复试 |
| 5 | 收尾时 `Enforcing=0` | 全机应用互读风险 | 本链正常情况下 enforcing 恒 1；异常就通知人类**立即重启**，重启前别继续跑命令 |
| 6 | 窗口内其它 `app_process` SIGABRT | 曾观察到与本链无关的 aborts | 若 starter/server 都健康，不要误判为本链失败；记录证据给规划者 |
| 7 | `entropy.dat` 内容/哈希会变 | 把固定 sha 当判据会误报 | 只判「uid0 能读通」；sha 仅作现场记录 |
| 8 | 设备特定值（D/vmap/task 地址）变化 | 硬编码会写错地址 → oops/panic | 一律现场求解；`S0_*` 失败就干净中止，不要手填 |
| 9 | 多客户端并发 | 单线程 accept 抢连接、响应错位 | 一次只跑一个客户端；不要与 `--zd-client-selftest` 同时跑 Termux 脚本 |
| 10 | 把 root 当持久 root | 误判能力边界 | 冷启动即恢复；每次需要 root 都要重新走一遍（并消耗一个干净 boot） |

### 4.1 证据纪律（本链实测踩过的坑，必须写进任何自动化报告）

| 坑 | 现象 | 正确读法 |
|---|---|---|
| **编排器伪失败 1：主跑不返回** | `--deliver-fork` 下 rootd 继承 glx 的 pty/stdout，设备侧已打印 `GLX_SHELL_EXIT=0`，但 `adb shell -t -t` 一直不返回，编排器超时记 `HOST_EXIT=124` | `GLX_SHELL_EXIT=` 一出现即主跑完成；124 记 SKIP，不当 FAIL；另开 adb shell 做独立取证 |
| **编排器伪失败 2：发数差 1** | `SHOTLEDGER[chain]` tag 数 13，`CHAIN_OK shots` 可能 14（静默 no-op 重发） | 判据用 `shots >= 13`、`max(summary) <= max(SHOT)`；不要写死 13 |
| **stage3 锚点形态** | `--shz-after-deliver` 形态下 logcat 里没有 `AndroidRuntime/RuntimeInit/Calling main entry/attachApplication`（starter 的 stderr 走父进程管道） | 用 `STAGE3_INIT→STAGE3_EXEC→STAGE3_MAIN→STAGE3_BINDER` + 进程态（uid0/CapAmb/cmdline/PPid=1）+ 可选 `binder_sample`/`am_proc_start` |
| **uid0 进程 exe 读不到** | `adb shell`(uid2000) `readlink /proc/<pid>/exe` 被拒（EACCES/EPERM） | 这不是失败；exe 身份只能标 **inferred**，要读就从 uid0 上下文读 |
| **WSL 里没有 adb** | 宿主只有 `adb.exe`，WSL 里直接 `adb` 报 `No such file or directory` | `export ADB_BIN=/mnt/c/Users/<you>/AppData/Local/Android/Sdk/platform-tools/adb.exe`（`<you>` = 你的 Windows 用户名） |

**冷启动可复现性（observed）**：同一 `glx_p11n` 在两个独立干净 boot 上都全链成功——
`173a1ef0`（`shots=13`、rootd pid 20638 / shizuku_server 20671）与
`58b276d2`（`shots=14`、rootd pid 18591 / shizuku_server 18623）；两次都是
Enforcing 全程=1、boot_id 未变、无 kernel_panic、rootd 与 shizuku_server 均 uid0/PPid=1。

---

## 5. 操作红线（任何 agent 都必须遵守）

**禁止**：

- 对引导链/分区做任何刷写或擦除（`fastboot` 的 flash / -w、EDL/9008 的任何写操作）；
- 改 `/system` `/vendor` `/product` 等 dm-verity 只读分区；`mount -o remount,rw`；
- 对用户数据做删除、清空或格式化（含恢复出厂/双清、userdata/metadata 分区写）；
- 写 boot/init_boot/vbmeta/dtbo/xbl/abl 等引导链分区；
- 用官方解锁/官方 root/刷机流程获取 root；
- 在未取得明确授权的执行类操作前「先跑了再说」（本项目的上机执行已由人类授权，
  但**新环境/新设备需要重新确认授权**）。

**允许（在授权范围内）**：

- `adb push` 到 `/data/local/tmp`、`adb shell` 执行 exploit、设备自行 panic 重启
  （约 5 秒，内存态全恢复）；
- 纯离线：反汇编、源码审计、重编、宿主测试；
- 在 Termux 里运行客户端/验收脚本。

**停止条件**：

- 收尾时 `Enforcing != 1` ⇒ 立即停并通知人类重启；
- 连续失败且原因不明 ⇒ 记录证据、停，不要在同一 boot 反复试；
- 设备 adb 掉线超过数分钟且未自动恢复 ⇒ 停，等人类。

---

## 6. 事故处置矩阵

| 事故 | 立即动作 | 后续 |
|---|---|---|
| panic / 设备自动重启 | 记录 `sys.boot.reason`、最后一行锚点、执行窗口 | 冷启动后重来；同一二进制除非定位到 bug 否则不要改 |
| 执行中 adb 断 | 等待 1–2 分钟看是否自恢复（panic 后约 5s 重启） | 设备重启 ⇒ 本 boot 结束；adb 恢复后只做只读取证 |
| rootd 已死 / 10369 不监听 | 确认 `ps`/`/proc/net/tcp` | 本 boot 无法恢复；冷启动 |
| `Enforcing=0` | 停止一切设备写入 | 通知人类立即重启恢复 |
| secret 疑似泄露 | 冷启动；重新生成 secret | 改用 UDS（未实施）或至少缩短生命周期 |
| 误写了 `/dev/pmsg0` | 立即停止后续 shell 命令 | 很可能已 panic；冷启动，不要尝试修补 |

---

## 7. 给规划者的开放问题（未解决线索）

1. **per-SID 武装的失败/panic 概率**：需要设计低风险统计方法（成本是干净 boot）。
2. **keeper/re-spawn**：需要下一次冷启动上新构建；三条前提已离线裁定可行，但二进制无代码。
3. **UDS + SO_PEERCRED**：把交付通道从「loopback + secret」换成「文件系统 socket + 0600」，
   可彻底消除「任何 app 都能连」的面。
4. **stage3 与 Shizuku 版本耦合**：argv/env 常量依赖 Shizuku 13.6.0 的 `libshizuku.so`；
   升级 Shizuku 后需要重新核对。
5. **多用户/工作资料**：Termux uid 非 10369 时的 secret 属主与目录。
