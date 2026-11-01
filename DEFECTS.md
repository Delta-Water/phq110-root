# DEFECTS — 交付文档独立验收记录

> 视角：**没有任何上下文的读者**（另一个 agent）。818 只做离线文档验收：
> 不碰设备、不 `adb`/`push`、不执行 exploit、不改二进制、不动 `src/` 与 `tools/`。
> 全部发现都在本目录的 md 里就地修订；没有改一行代码、没有重新构建。
>
> 说明：本文是审计记录，为了说明「哪些内部代号不该出现在正文」，会引用少量历史构建目录代号；
> 它们只在本文件出现，正文（7 份主文档）里已全部清除或就地解释。

## 0. 方法与范围

- 对照基准：`D:\Work\Workspace\AGENTS.md`（已逐条读）与其指向的
  `docs\PROJECT_DOCUMENTATION_STANDARD.md`。
- 7 份主文档：README / ARCHITECTURE / USAGE / BUILD / ARTIFACTS / RISKS / CHANGELOG，
  外加 `build.sh`、`src/*`（只读）、`tools/*`（只读）。
- 校验手段：源码/常量逐条 grep、产物 sha256+字节重算、ELF 程序头解析、
  文档内 shell 代码块抽出来跑 `bash -n`、`termux_uid0.py` 做 `py_compile`/AST、
  占位符与内部代号全文扫描。

## 1. 发现项与处置

| ID | 严重度 | 位置 | 发现 | 处置 | 证据 |
|---|---|---|---|---|---|
| F01 | 高 | README §3.1 期望输出 | 把交付腿锚点写成 `RES\|PASS\|ROOTD_LISTEN...`，源码里没有这种形态；真机是 `GLX\|ROOTD_LISTEN\|PASS\|pid=...` | 已改为源码实际会打印的完整锚点链（ROOTD_LISTEN/DELIVER/ZD_SECRET/ZDCONNECT/ZD_UID/ZD_REPL/STAGE3_*/SHZ_AFTER_DELIVER/STOP_AFTER/ZD_PERSIST/GLX_SHELL_EXIT） | `glx_p11n.c:5631-5668,5917,5950,7009`；`shz_launch.c` 的 STAGE3_* |
| F02 | 高 | BUILD §6、ARCH §4、USAGE §1.5、ARTIFACTS §5、README §1、CHANGELOG §0 | 「实际发数=13」写死。第二台干净 boot 实测 `CHAIN_OK shots=14`（静默 no-op 被检测后重发；每次 `w8()` 都 `g_shots++`，重发也算一发；具体哪一发看 `SHOT n` 行） | 全部放宽为「设计账本 13；实际 ≥13（见过 14）；判据用 `shots >= 13`、`RES|FAIL=0`、SHOT 标签链完整」 | `glx_p11n.c:1685`（每发 `g_shots++`）、`:3446`（prearm 路径把账本置 advisory）、`:3732-3764`（cap 写静默 no-op 重发）；运行记录见 `RISKS.md` §4.1 |
| F03 | 高 | USAGE §1.6、ARCH §8 | 让 `adb shell`(uid2000) 用 `readlink /proc/<pid>/exe` 判 uid0 进程，实测会被拒（EACCES/EPERM） | 改为 `cmdline` + `/proc/pid/status` + `attr/current`；明确 exe 身份只能标 inferred，要读就从 uid0 上下文读 | 真机观察“shell 无法 readlink uid0 进程 exe”；`rootd` 为 fork 无 exec，`comm` 继承父名 |
| F04 | 高 | USAGE §3.1/§3.3、ARCH §9、CHANGELOG p11i | 本链 `--shz-after-deliver`（starter）形态拿不到 `AndroidRuntime/RuntimeInit/Calling main entry/attachApplication` 的 logcat 行（starter 的 stderr 走父进程管道） | 三处都写清：本形态只能用 `STAGE3_INIT→EXEC→MAIN|PASS+ctx→BINDER|PASS(json)` + 进程态（uid0/CapAmb/cmdline/PPid=1）+ 可选 `binder_sample`/`am_proc_start`；RuntimeInit 行只属「直接 pty 跑 app_process」形态 | 该 boot 窗口内 `grep AndroidRuntime/rikka` 均为 0；`shz_launch.c:704-830` 为管道接走子进程 stderr |
| F05 | 中 | USAGE §1.4 vs §2.1 / RISKS §3 | §1.4 说 `file` 是「兜底通道」，§2.1 说「rootd 是 TCP-only，file 不是备用通道」，自相矛盾 | 统一：`--zd=file` 是**另一种启动模式**，必须在 glx 启动时选中；已用 tcp 启动的 rootd 不能事后切 file | `glx_p11n.c:5532-5535`（`--listen=file` 在启动时二选一）、`rootd_zd.c:1276-1281` |
| F06 | 中 | README §3、USAGE 文首 | README 用 `<NN>`/`<rootd pid>` 却没定义；USAGE 只定义 `<NN>/<PORT>/<ROOTD_PID>`，`<door>/<pid>/<hex-secret>/<you>/<SERIAL>` 未定义（原式里根本没有 SERIAL 的多设备说明） | 两处都补占位符图例，并加「多设备时所有 adb 命令加 `-s <SERIAL>`」 | 全文扫描 `<...>` 词表 |
| F07 | 中 | ARTIFACTS §1/§2 | 缺 `build.sh` 指纹；二进制版本串里出现 `i775/i766` 等历史代号而未解释（读者会 grep 到） | 增 `build.sh` 2641B / `aa7a001d…`；注明版本串里的代号只是历史构建目录名、无外部含义 | 本目录重算；`strings` 命中 `glx-2.15 (glx_p11n/i775 = ...)` |
| F08 | 中 | BUILD §2 | 没有明确「build.sh 没在 Windows 原生执行过」 | 显式写：面向 Linux/WSL；从未在 Windows 原生执行；本次只做 `sh -n`（rc=0），未跑完整交叉编译 ⇒ 重编同 sha256 属未验证 | 本机 `sh -n build.sh` rc=0；无 `aarch64-linux-gnu-gcc` |
| F09 | 中 | README 文首/§2/§6 | 未按 `PROJECT_DOCUMENTATION_STANDARD.md` 给状态标签与依赖说明；缺项目级 `AGENTS.md` | README 增加 `snapshot` 状态、依赖、`AGENTS.md` 入口；新增项目级 `AGENTS.md`（继承工作区规则 + 项目红线/命令） | 工作区标准原文 |
| F10 | 低 | ARCH §2.1 | 「`+0x1000` 带来 bit12/13」不精确：bit13 来自 `obj` 偏移 `0x2000` | 改为 `低32位 0x830C6 = 0x80000+0x2000+0x1000+0xC6`，bit13←0x2000、bit12←0x1000 | `glx_p11n.c:347-349,418-419,432` |
| F11 | 低 | ARCH §3.1 | 说 `D_TEXT` 「用于校验 D」；实际唯一性校验用 `LINK_STEXT/LINK_ETEXT` | 改为「仅日志/参考」 | `glx_p11n.c:204,224-225,2023` |
| F12 | 低 | ARCH §2.2 | 把武装写描述成「写→回读→重发」；实际武装是「整轮重发 + file 类行为 oracle」（不做 GhostLock 回读） | 按实现改写（cap 用 capget/prctl oracle；武装用行为 oracle；重发计一发） | `glx_p11n.c:3416-3478,3637-3760` |
| F13 | 低 | USAGE §2.2 | 只列 6 个子命令；脚本实际还有 `wait`，另有 `--dir/--tag/--req/--resp/--host/--name/--allow-uid/--no-pty/--no-reconnect` | 补 `wait` 示例与「完整参数见 `--help`」 | `termux_uid0.py:456-509` |
| F14 | 低 | USAGE §1.6 | 收尾取证只给了 uid0 进程的读法，没有断言「读不到 u0 进程 exe 时不算失败」 | 已在 F03 同一处注明 | 同 F03 |

## 2. 已核对且**未发现**问题的项（只记录结论）

1. **产物指纹**：`build/glx_p11n` 1007336B / `90b9e66b0122fc94bb4decba731359fa4b6e7e828654cfdb603fd448106549e4`；
   7 个 `src` + 2 个 `tools` 的 size/sha256 与 `ARTIFACTS.md` §1 逐项一致（`build.sh` 见 F07）。
2. **ELF 契约**：`e_type=0x2(ET_EXEC)`、`e_machine=0xB7(AArch64)`、`e_entry=0x403980`、
   无 `PT_INTERP(3)`、无 `PT_DYNAMIC(2)`；`PH0 filesz=0xc7151`、`PH1 vaddr=0x4db430/filesz=0x66b0/memsz=0x5bd5b0` 与文档一致。
3. **常量/行号溯源**：`D_TEXT/D_INIT_CRED/D_INIT_TASK/D_STATE/D_PCO/D_RUNQUEUES/D_TCP_ENT/PERM_SS_LINK`、
   `task` 偏移 `0x800/0x808/0x818/0x7f8/0x8d8`、cred 偏移 `0x04/0x0c/0x14/0x1c/0x28/0x30/0x38/0x40/0x48`、
   `V=base+0x830C6`（δ=0x810C6）、`A-8` 副写、`PERM_NODE_OFF=0x1D0`/`PERM_HIGHBIT_OFF=0x1D8`、
   shell type 1464/bit56/startbit1408、UA27 1498/bit90/默认关、
   `--idle=86400`（`glx_p11n.c:5541`）、`--max-conn=32`（`:5542`）、`authfail>=3`（`rootd_zd.c:98,1039`）、
   rootd 退出码 2/3/10/11、`ZD1 <hex>\n`→`OK\n`、帧类型 `G/I/R/X/F/P/Q`、状态 0/1/4 —— 全部与源码一致。
4. **设计发账本**：6 读（R1/R2/R3P/R3C/R4/R5）+ 2 武装写（PERMNODE/PERM_HI）+ 5 cap 写（WC1..WC5）= 13；
   与 `glx_p11n.c:385-406,4216-4330,3424-3444,4447-4485` 对得上（F02 只涉及“实际值可能 >13”）。
5. **命令可执行性**：USAGE/README/BUILD/ARTIFACTS 里所有 shell 代码块抽出后 `bash -n` 全部 rc=0；
   `sh -n build.sh` rc=0；`python -m py_compile tools/termux_uid0.py` 通过；
   `adb shell -t -t` 拼写、`/proc/net/tcp` 的 `2881`(=10369)、设备端 `sha256sum/stat -c '%s %a'` 期望值均正确。
6. **三档标注覆盖**：`rish`、`keeper/re-spawn`、per-SID 武装成功率、unix socket 改造、
   `build.sh` 未在 Windows 执行 —— 五项均明确标为 未验证/未实施/未统计/未在 Windows 执行，
   没有任何一项被写成已完成。
7. **自包含性**：7 份 md 全文 0 处出现 `i775/i771/i807/i764/…` 这类构建目录号或 `fact NNN`、
   `harness` 等内部代号（版本串里的代号已在 ARTIFACTS 解释）。

## 3. 仍需人类 / 主 agent 确认（离线无法盖章）

1. **goal 804 的收尾盖章**：只能由人类/主 agent 做，本文档不代替。
2. **Shizuku app 侧 `rish`**：仍需人类在已授权 app 里跑 `rish -c 'id'` 并回传原始输出。
3. **keeper / re-spawn、UDS+0600、多用户适配**：设计/建议，均未实施。
4. **per-SID 武装成功率**：未统计（已知失败/panic/成功各有样本）。
5. **换工具链重编是否得到同 sha256**：未验证。

## 4. 复现本文的检查（离线即可）

```bash
# 1) 产物指纹
python -c "import hashlib;d=open('build/glx_p11n','rb').read();print(len(d),hashlib.sha256(d).hexdigest())"
# 2) ELF 契约（任意平台 Python）
python - <<'PY'
import struct
d=open('build/glx_p11n','rb').read()
t,m,_,e,ph,_,_,_,pes,pn=struct.unpack_from('<HHIQQQIHHHHHH',d,16)[:10]
k=[struct.unpack_from('<I',d,ph+i*pes)[0] for i in range(pn)]
print(hex(t),hex(m),hex(e),k); print('PASS' if (t==2 and m==0xB7 and 2 not in k and 3 not in k) else 'FAIL')
PY
# 3) 文档里的 shell 块语法（有 bash 的机器）
#    把代码块抽出来 -> bash -n
# 4) 客户端语法（不写 __pycache__，避免往交付目录里加文件）
python -c "import ast;ast.parse(open('tools/termux_uid0.py',encoding='utf-8').read());print('AST OK')"
```
