# 产物清单、来源与部署

> 全部 sha256 都是对本目录**实际文件**重新计算的结果（Size 单位：字节）。
> 任何一项对不上 ⇒ 文件被改动过 ⇒ 不要上机，先查来源。

---

## 1. 产物总表

| 相对路径 | 大小 | sha256 | 作用 |
|---|---:|---|---|
| `build/glx_p11n` | 1007336 | `90b9e66b0122fc94bb4decba731359fa4b6e7e828654cfdb603fd448106549e4` | **真机验证过的最终二进制**（AArch64 静态 ET_EXEC；内嵌 rootd） |
| `src/glx_p11n.c` | 322011 | `d9cce444bb21a7e4c455430797d30f137e297074bec117f617695c25f4ef20dd` | 主程序源码 |
| `src/rootd_zd.c` | 48187 | `af17fa999772ed32016cb631e1e01bb976ae2df13a29f59f73f8faee747a501b` | uid0 daemon 源码 |
| `src/shz_launch.c` | 30079 | `9ea90f82baa1e6965d2a92010817ec1f12809c19e69abffe464f08bc962cc965` | Shizuku 启动器源码 |
| `src/shz_launch.h` | 2691 | `ecbf2d317c37a9d078842677bfd248582160b5113072653a682953ea302dfb1f` | stage3 常量/退出码契约 |
| `src/shz_env_snapshot.h` | 5770 | `80f3e7048810ea6c00e3bcdd933bcd2d8d18305802a75547c44312975a710a8f` | init 环境快照 |
| `src/dtable.h` | 3998 | `1695561fcc5f7b546ca177bf5bc08205d21c27a224af207adb87d25aba665de0` | QEMU 后端符号表 |
| `src/qtable.h` | 3238 | `5b988d7c654775a374a6a799fe6fb5e19858e8c37d43d38ffb5066d4c99497da` | QEMU 后端候选项表 |
| `tools/termux_uid0.py` | 18178 | `cb218432aa7c7caee5a3d5d74074df72e4c815130a439cdfa26dd4dec53eea7d` | Termux 侧客户端 |
| `tools/termux_accept.sh` | 17851 | `af7b219e6c6989e40e6a61aea773845b6f59f230d02e25ac5e0921df01be3599` | 重验收脚本（p11m 时代；p11n 下可选） |
| `build.sh` | 2641 | `aa7a001d86fa1a94efc28f8212e0c7ec3ac7274882393a3ffd51bee68f0f25f2` | 自包含重建脚本（Linux/WSL；未在 Windows 原生执行过） |

**不在本目录里的东西（不要找）**：

- `zd_secret`：设备上生成，见 §4；仓库里永远不应有它的值。
- `policy_delta.bin` / `v3_delta.bin`：本链默认**不需要** load policy；
  二进制里保留了 delta 门的代码路径与常量，但成功命例走的是 per-SID permissive（0 发 load）。
- Shizuku APK / `libshizuku.so`：来自设备已安装的 Shizuku 13.6.0；本项目不分发第三方二进制。

---

## 2. 构建来源

| 项 | 说明 |
|---|---|
| 编译器 | `aarch64-linux-gnu-gcc -static -O2 -pthread` |
| rootd 编入方式 | `aarch64-linux-gnu-gcc -static -O2 -Dmain=rootd_main -c src/rootd_zd.c` |
| 链接输入 | `src/glx_p11n.c` + `src/shz_launch.c` + `rootd_zd_main.o`（+ 头文件） |
| 构建脚本 | 本目录 `build.sh`（可复现的简化版） |
| 原始构建门禁 | 双编译逐字节一致、UT 96/96 + 131/131、fork E2E 10/10、结构门 179/179、stage3 diff 34/34（详见 `BUILD.md` §5） |
| 版本字符串 | 二进制内含 `glx-2.15 (glx_p11n/... delivery-leg fix ...)`，可用 `strings build/glx_p11n | grep glx-2.15` 核对。串里的 `i775/i766` 等是**历史构建目录代号**（标记这版由哪个补丁合并而来），对使用者没有任何含义，忽略即可 |

版本谱系：`glx_p11i`（stage3）→ `glx_p11k`（raw SETIDS 加固）→ `glx_p11m`
（合并读链修复 + p11k）→ **`glx_p11n`**（修交付腿 poll 漏判）。逐版原因见 `CHANGELOG.md`。

---

## 3. ELF 契约（已在本目录产物上实测）

```text
e_type    = ET_EXEC (0x2)
e_machine = AArch64 (0xB7)
e_entry   = 0x403980
PT_INTERP = absent
PT_DYNAMIC= absent
```

程序头（供参考）：

```text
PH0 LOAD   R E  0x400000   filesz 0xc7151   align 0x10000
PH1 LOAD   RW   0x4db430   filesz 0x66b0    memsz 0x5bd5b0  align 0x10000
PH2 NOTE
PH3 TLS
PH4 GNU_STACK  RW
PH5 GNU_RELRO
```

复核命令（任意平台，用 Python）：

```bash
python3 - build/glx_p11n <<'PY'
import struct,sys
d=open(sys.argv[1],'rb').read()
t,m,_,e,ph,_,_,_,pes,pn,*_=struct.unpack_from("<HHIQQQIHHHHHH",d,16)
k=[struct.unpack_from("<I",d,ph+i*pes)[0] for i in range(pn)]
print(hex(t),hex(m),hex(e),k)
print("PASS" if (t==2 and m==0xB7 and 3 not in k and 2 not in k) else "FAIL")
PY
```

---

## 4. 设备部署路径

| 文件 | 设备路径 | 权限/属主 | 说明 |
|---|---|---|---|
| `build/glx_p11n` | `/data/local/tmp/glx_p11n.r<NN>` | `755`，shell 属主即可 | 用<b>新文件名</b>，不覆盖设备上已有文件 |
| `tools/termux_uid0.py` | `/data/local/tmp/termux_uid0.py`（中转）→ `~/termux_uid0.py` | 中转 644 即可；Termux home 下 `755` | 必须在 Termux home 里执行；不要从 `/data/local/tmp` 直接跑（那是 shell 域目录） |
| `zd_secret` | `/data/data/com.termux/files/home/zd_secret` | `0600`，属主 Termux（通常 uid **10369**），64 字节 hex | **由 glx 自动创建**（降权到 10369 的 fork 子进程）或用户在 Termux 手工创建 |
| Shizuku APK | `/data/app/.../moe.shizuku.privileged.api-*/base.apk` | 系统安装态 | stage3 自动发现 |
| `libshizuku.so` | APK 内 `lib/arm64/libshizuku.so` | — | starter 模式使用；可读则 auto 选 starter |

### 4.1 宿主侧 → 设备

```bash
adb push build/glx_p11n /data/local/tmp/glx_p11n.r<NN>
adb push tools/termux_uid0.py /data/local/tmp/termux_uid0.py
adb shell sync
adb shell chmod 755 /data/local/tmp/glx_p11n.r<NN>
```

### 4.2 设备端复核（**必须**）

```bash
adb shell sha256sum /data/local/tmp/glx_p11n.r<NN>
adb shell stat -c '%s %a' /data/local/tmp/glx_p11n.r<NN>
# 期望：
#   90b9e66b0122fc94bb4decba731359fa4b6e7e828654cfdb603fd448106549e4
#   1007336 755
```

### 4.3 Termux 侧复核

```bash
sha256sum ~/termux_uid0.py
# 期望：cb218432aa7c7caee5a3d5d74074df72e4c815130a439cdfa26dd4dec53eea7d
stat -c '%s %a %u' ~/zd_secret
# 期望：64 600 10369
```

### 4.4 Windows 侧复核（可选）

```powershell
certutil -hashfile .\build\glx_p11n SHA256
# 或
python -c "import hashlib;print(hashlib.sha256(open(r'build/glx_p11n','rb').read()).hexdigest())"
```

---

## 5. 设备上“本次运行”的现场指纹（示例，**每 boot 会变**）

以下来自一次成功 run（boot `173a1ef0-…`，`D = 0x13c2c00000`），只用于说明「什么样的值算正常」，
**不要当固定指纹硬编码**：

| 项 | 示例值 |
|---|---|
| `D`（KASLR slide） | `0x13c2c00000` |
| pmsg vmap base | `0xffffffc010f00000`（1 MB 对齐） |
| fake rt_mutex (`obj`) | `base+0x2000 = 0xffffffc010f02000` |
| fake ebitmap node (`X`) | `base+0x100 = 0xffffffc010f00100` |
| highbit 写值 (`W`) | `base+0x3000 = 0xffffffc010f03000` |
| cap 值 (`V`) | `base+0x830C6 = 0xffffffc010f830c6` |
| rootd | pid `20638`、PPid `1`、uid 0、`CapEff=CapAmb=0xffffffc010f830c6`、`u:r:shell:s0` |
| shizuku_server | pid `20671`、PPid `1`、uid 0、`CapEff=CapAmb=0xffffffc010f830c6`、18 线程 |
| 提交日志行 | `GLX|STOP_AFTER=shzlaunch|PASS round=784 shots=13 uid=0 euid=0 delivery=verified stage3=ran` |
| 计数 | `RES|PASS=52`、`RES|FAIL=0`、`CHAIN_OK shots=13`、窗口内 `avc: denied`=0 |

> `shots` 是**实际** GhostLock 写次数：设计账本 13；若某发静默 no-op 被重发，会多 1 发。
> 另一台干净 boot（`58b276d2-…`）就是 `CHAIN_OK shots=14`，其余判据一致（Enforcing 全程=1、
> boot_id 未变、无 kernel_panic、rootd pid 18591 与 shizuku_server pid 18623 均 uid0、
> ctx `u:r:shell:s0`、PPid=1），因此**冷启动可复现性成立**；判据用 `shots >= 13`，不要写死 13。

另一个独立 boot（`58b276d2-…`）也全链成功，细节见上一条注（`shots=14`；rootd pid 18591 /
shizuku_server pid 18623，均 uid0、PPid=1）；数值不同属正常。

`/data/system/entropy.dat` 的 sha256 是**设备特定且会变**的：见过 `594d670b…`（某次 run）
与早期记录的 `789a3e95…`。它只用于证明「uid0 能读通一个 0600 system:system 文件」，
**不是链路的固定指纹**。

---

## 6. 完整性检查清单（上机前 30 秒）

- [ ] `build/glx_p11n` sha256/size 与 §1 一致
- [ ] `src/*.c/*.h` 的 sha256 与 §1 一致（防止有人改了源码没重编）
- [ ] 设备端 sha256/size 与宿主一致
- [ ] `termux_uid0.py` sha256 与 §1 一致
- [ ] `zd_secret`：64 字节、0600、属主 Termux
- [ ] boot 干净（kallsyms/pstore 被拒）、Enforcing、无残留 rootd
