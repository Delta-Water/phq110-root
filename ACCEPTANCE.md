# ACCEPTANCE — 一页式验收结论

> 对象：`D:\Work\Workspace\Projects\RE\phq110-root` 交付集（7 份主文档 + `build.sh` +
> 10 份产物：1 个二进制 + 7 个源码/头文件 + 2 个 Termux 脚本）。
> 方式：**纯离线**的「无上下文读者」独立验收（不碰设备、不 `adb`/`push`、不执行 exploit、
> 不改二进制、不动 `src/` 与 `tools/`）。逐项细节见 `DEFECTS.md`。
>
> **文档结构后记（2026-11-01）**：验收当时只有一份 `README.md`，它面向的是「无上下文的 AI
> agent」。之后按移交要求做了拆分：那份 agent 向内容整体迁入 `AGENTS.md`，`README.md` 改为
> 面向人类的总览。本文与 `DEFECTS.md` 保留验收当时的事实与措辞，只把跨文档指针更新到新位置。

## 结论

**文档级验收：PASS。** 共发现 14 项文档缺陷（0 项阻塞），全部已就地修订或补说明；
产物与源码**未被改动**，sha256/字节数与 `ARTIFACTS.md` 完全一致。**没有任何一项未验证能力
被写成已完成。**

## 已验证（本目录内可复核）

| 维度 | 结论 |
|---|---|
| 产物完整性 | `build/glx_p11n` = 1007336 B / `90b9e66b…549e4`；7 个 `src` + 2 个 `tools` + `build.sh` 的 size/sha256 全部与 `ARTIFACTS.md` 一致 |
| ELF 契约 | ET_EXEC、AArch64、无 `PT_INTERP`/`PT_DYNAMIC`、`e_entry=0x403980`、程序头与文档一致 |
| 常量/行号溯源 | 所有链接期常量、task/cred 偏移、`--idle=86400`、`--max-conn=32`、`authfail>=3`、`V=base+0x830C6`、`A-8` 副写、per-SID 位图布局，均能在 `src/` 中逐条命中 |
| 命令可执行性 | 文档内全部 shell 块 `bash -n` 通过；`sh -n build.sh` 通过；`termux_uid0.py` 语法通过；占位符 `<NN>/<PORT>/<ROOTD_PID>/<door>/<pid>/<hex-secret>` 均已定义 |
| 三档标注 | `rish`、`keeper/re-spawn`、per-SID 武装成功率、UDS 改造、`build.sh` 未在 Windows 执行——五项均明确标为未验证/未实施/未统计 |
| 自包含性 | 主文档 0 处内部构建目录号/`fact NNN`/`harness` 代号；版本串里的代号已解释 |
| 工作区规范 | 已逐条对照 `AGENTS.md` 与 `PROJECT_DOCUMENTATION_STANDARD.md`，差异在 `AGENTS.md` §11 明示；新增项目级 `AGENTS.md` |

## 本次修订的重点（读者最容易踩的四个坑）

1. 成功判据**不能**只看编排器的 VERDICT：`--deliver-fork` 下 rootd 持有 pty 会让
   `adb shell -t -t` 不返回（HOST_EXIT=124，应按 SKIP），且发数可能是 14（静默 no-op 重发）。
   以设备侧锚点 + 独立 adb shell 取证为准（`USAGE.md` §1.7、`RISKS.md` §4.1）。
2. stage3 在 `--shz-after-deliver` 形态**没有** RuntimeInit/attachApplication 的 logcat 行；
   只能用 `STAGE3_*` + 进程态（`USAGE.md` §3.1、`ARCHITECTURE.md` §9）。
3. `adb shell`(uid2000) 读不到 uid0 进程的 `/proc/<pid>/exe`；exe 身份标 inferred。
4. 设计发数是 13，实际 `CHAIN_OK shots` 可能是 13 或 14；判据用 `shots >= 13`。

## 离线无法证明、必须人类/主 agent 确认

1. **goal 804 收尾盖章**：只能由人类/主 agent 做。
2. **Shizuku app 侧 `rish -c 'id'`**：需要人类在已授权 app 里实跑并回传输出。
3. keeper/re-spawn、UDS+0600、多用户适配：设计存在，未实施。
4. per-SID 武装成功率：未统计。
5. 换工具链重编是否得到同 sha256：未验证。

## 给下一位 agent 的最短路径

1. 读 `AGENTS.md`（agent 入口）→ `ARCHITECTURE.md` §4 → `USAGE.md` → `RISKS.md`；
   面向人类的概述看 `README.md`。
2. 上机前 30 秒：核对 `ARTIFACTS.md` §6 清单（sha256/字节/boot 干净）。
3. 任何「要不要重跑 / 能不能再跑一次 / 能不能 kill」的问题，先看 `RISKS.md` §2 与 §4。
