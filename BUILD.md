# 构建：从本目录源码重编 `glx_p11n`

> 所有命令都在 Linux/WSL 下执行（Windows 原生路径不可用，因为需要 `aarch64-linux-gnu-gcc`
> 与 `unshare`）。构建是**纯离线**操作，不需要设备。

---

## 1. 产物

| 项 | 值 |
|---|---|
| 输出 | `build/glx_p11n` |
| 大小 | `1007336` 字节 |
| sha256 | `90b9e66b0122fc94bb4decba731359fa4b6e7e828654cfdb603fd448106549e4` |
| 架构 | ELF64 **AArch64**，`ET_EXEC`，**静态**（无 `PT_INTERP`、无 `PT_DYNAMIC`） |
| 入口 | `0x403980`（仅供参考，随源码变化） |
| 组成 | 主程序 + 内嵌 `rootd_zd.c`（用 `-Dmain=rootd_main` 重命名后链接进同一个二进制） |

**只需要 push 这一个文件**：交付腿的 daemon 是 fork 出来的内嵌 `rootd_main()`，不是外部程序。

---

## 2. 工具链

| 工具 | 用途 | 备注 |
|---|---|---|
| `aarch64-linux-gnu-gcc` | 交叉编译 aarch64 静态可执行 | Ubuntu 包 `gcc-aarch64-linux-gnu` |
| `gcc` | 仅用于原始构建环境里的宿主测试（UT / E2E host） | 本交付不附带这些测试源码，见 §5 |
| `python3` | 结构门/ELF 检查、stage3 常量 diff（原始环境） | 本目录 `build.sh` 只用它做 ELF 解析 |
| `unshare` | 原始环境里以 uid0 + 新 user/pid namespace 跑 UT | 非本交付必需 |
| `sha256sum` / `cmp` / `stat` | 指纹与双编译比较 | 标准 coreutils |

原始构建环境的工具链**具体版本没有被记录**。因此：

- **observed**：原始主机上两次编译产物逐字节一致；
- **inferred / 未验证**：换一台机器/换一个 gcc 小版本，可能得到不同的 sha256
  （静态链接的 libc/启动代码会变）。要证明「与交付二进制完全一致」，必须使用同一工具链；
  否则只要求 §4 的 ELF 契约与功能门通过。
- **`build.sh` 的平台状态**：它是 POSIX `sh` 脚本，面向 Linux/WSL。**从未在 Windows 原生环境
  执行过**（Windows 没有 `aarch64-linux-gnu-gcc`，也没有 POSIX `sh`）；本次文档验收只做了
  `sh -n build.sh` 语法检查（rc=0），**没有**在本机跑完整交叉编译 ⇒ 「在本目录重编出同 sha256
  的二进制」仍是 **未验证**。

---

## 3. 源文件职责

| 文件 | 作用 | 改动风险 |
|---|---|---|
| `src/glx_p11n.c` | 主程序：S0/读链/武装/cap 写/SETIDS/交付腿/stage3 调度 | **最高**：地址/偏移/顺序/发数都在这里 |
| `src/rootd_zd.c` | uid0 daemon：`--listen=tcp|file|unix`、secret 鉴权、帧协议 `G/I/R/X/F/P/Q`、`--idle/--max-conn/--soft-assert/--dac-caps` | 中：协议与鉴权语义 |
| `src/shz_launch.c` + `.h` | Shizuku starter/app_process 启动器与退出码契约 | 中：argv/env 常量必须与设备实测一致 |
| `src/shz_env_snapshot.h` | Shizuku 启动所需的 init 环境（BOOTCLASSPATH 等）快照 | 高：改错会导致 stage3 直接失败 |
| `src/dtable.h` / `src/qtable.h` | **QEMU 后端**的符号/候选地址表；真机后端不用 | 低（但仍被编译进二进制，改大改小会影响 sha） |

编译关系（关键点）：

```bash
# 1) rootd 作为“库”编进来：把 main 改名
aarch64-linux-gnu-gcc -static -O2 -Dmain=rootd_main -c src/rootd_zd.c -o build/rootd_zd_main.o

# 2) 主程序 + stage3 启动器 + rootd 对象
aarch64-linux-gnu-gcc -static -O2 -pthread \
    -o build/glx_p11n src/glx_p11n.c src/shz_launch.c build/rootd_zd_main.o
```

> 少 `-Dmain=rootd_main` 会得到 `multiple definition of main`；少 `-pthread` 会在
  futex/线程相关符号上失败；不 `-static` 会产生 `PT_INTERP`，在设备上可能无法按预期执行。

---

## 4. 本目录自带的一键构建（`build.sh`）

```bash
cd D:/Work/Workspace/Projects/RE/phq110-root   # 在 WSL 里用 /mnt/d/... 或复制到 Linux 侧
sh ./build.sh
```

`build.sh` 逐步做：

1. 打印工具链版本；
2. 对 7 个源文件做 `sha256sum`（用于确认源码未被改动）；
3. 编译 `rootd_zd.o`；
4. **编译两次** 并 `cmp`：`GLX_P11N_REBUILD_IDENTICAL` / `..._DIFF`；
5. 用 Python 解析 ELF 并断言：
   - `e_type == ET_EXEC(2)`；
   - `e_machine == AArch64(0xB7)`；
   - 没有 `PT_INTERP(3)`、没有 `PT_DYNAMIC(2)`；
6. 打印最终 sha256 与大小。

> 若第 4 步出现 `DIFF` 但第 5 步 `ELF_CONTRACT=PASS`，说明工具链不同（不是源码损坏）——
> 先按 `ARTIFACTS.md` 比对源码 sha256，再决定是否接受新产物。**上机前必须重新做一次
> `--selftest`/低风险验证，不要直接把新产物当已验证二进制。**

---

## 5. 原始构建的完整门禁（observed，供审查参考）

交付二进制的原始构建还跑过以下门（测试源码不在本交付目录内，故 `build.sh` 不包含）：

| 门 | 结果 |
|---|---|
| 两次编译逐字节一致 | PASS（`cmp` 相同） |
| 宿主 UT（普通用户） | 96/96 PASS |
| 宿主 UT（uid0 + 新 user/pid namespace） | 131/131 PASS |
| fork 交付 E2E | 10/10 PASS，含「LISTENING 后保持静默」的真实 daemon 形态 |
| 结构/安全门 | 179/179 PASS |
| stage3 常量表逐字符串 diff | 34/34 PASS |
| patch dry-run（相对上一版源码） | `PATCH_DRYRUN_OK`，应用后三文件与当前源码逐字节相同 |

这些数字属于**原始构建环境**的 observed；本交付目录不能一键复跑它们。

---

## 6. 编译期自检（源码里的 `_Static_assert`）

源码用静态断言锁住关键不变量，编译失败通常意味着「结构体偏移/常量漂移」，**不要绕过**：

- `cred` 的 id 对偏移必须是 `0x04/0x0c/0x14/0x1c`；
- `cap_effective/cap_bset` 必须是 `0x38/0x40`，cap 写必须是 5 发、不得是零值写；
- `V = base + 0x830C6` 必须 `%8==6`（DAC 位）、必须含 bit1/2、必须不含 bit3（`CAP_FOWNER`）、
  副写必须留在自己的 pmsg 页内；
- `permissive_map` 的 shell/UA27 bit 必须落在第一个 ebitmap node 内；
- 发账本：完整链 16 个 tag（6 读 + 5 cap 写 + 5 PERM 阶段）；`--no-ambient` 14 个 tag。

> 注意：**设计上的**运行期发数是 13（6 读 + 2 武装写 + 5 cap 写），因为 p11e 之后
> per-SID 武装被前移到 cap 写之前，legacy PERM 块 0 发；发账本 tag 数 ≠ 实际 GhostLock 发数。
> 而实际 `GLX|CHAIN_OK shots=N` 可能是 13 **或 14**：某发静默 no-op 被检测到后重发会多发 1 发
> （第二台干净 boot 上实测为 14）。因此以 `shots >= 13`、`GLX|SHOT n` 标签链完整、
> `RES|FAIL=0` 为准，**不要写死 13**。

---

## 7. 修改代码时的检查清单

- [ ] 只改必要的最小面；**不要**改读链/武装/cap 写/stage3 argv 常量，除非你有真机复现能力；
- [ ] 每个关键地址/偏移都在注释里写来源（符号名/反汇编/哪次真机验证），保持本项目文档的
      「可审计」风格；
- [ ] 改完 `build.sh` 双编译 + ELF 契约 + 源码 sha256 记录；
- [ ] 若改了 `glx_p11n.c`/`rootd_zd.c`/`shz_launch.c`，**必须**重新上机验证；
      旧的 sha256 在本项目里等同于「已真机验证」的凭证，换 sha 就作废；
- [ ] 注意「一个 boot 只跑一次」：开发迭代必须准备冷启动节奏。

---

## 8. 常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| `multiple definition of 'main'` | 忘了 `-Dmain=rootd_main` | 按 §3 重编 |
| `undefined reference to pthread_*` | 少了 `-pthread` | 加上 |
| `PT_INTERP` 存在 / 设备上 `No such file or directory` | 没有 `-static`，或用了动态 libc | 用 `-static` 重新编 |
| `_Static_assert failed "..."` | 源码/头文件被改动导致常量漂移 | 不要绕过；核对改了什么 |
| 重编后 sha256 不同 | 工具链不同 | 先比对源码 sha256；接受新产物前重做上机验证 |
| 想验证交付二进制没被替换 | — | 用 `ARTIFACTS.md` 的 sha256 清单逐项核对 |
