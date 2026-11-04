# OPS.md — Termux 侧运维层（部署 / 保活 / 唯一入口）

> **状态标注：本节全部为 observed（本机真机实跑），但不属于 p11n 交付快照。**
>
> `build/` 与 `src/` 一个字节都没动；这一层是 p11n 验收**之后**在真机上补的运维代码，
> 用来补上 `AGENTS.md` §1 状态表里标「未实施」的两项：keeper/re-spawn 与
> unix socket 替代 TCP。目标是让下一个接手的人不必重走一遍踩坑。

---

## 0. 为什么需要这一层

glx 交付的 `rootd` 有三条实际限制，全部是现场踩出来的：

1. **寿命不可靠（1~5 分钟）**：`rootd` 随 `adb shell -t -t` 那条 pty 走，pty 一断它就没了。
   用它当日常通道，等于每隔几分钟丢一次 root。
2. **连接预算 32 条**：glx 传给 rootd 的 `--max-conn=32` 是硬编码，**用满就自己 break 退出**。
   当时连着调了三十来次把预算烧完，`rootd` 按设计退出，却被误判成「并发把它弄死了」。
   `USAGE.md` 里关于并发的描述需要按这条读：源码里有 `signal(SIGPIPE, SIG_IGN)` +
   `MSG_NOSIGNAL`，写本身不会炸；**真正会死的是连接数和 pty**。
3. **本 boot 不可重建**：glx 每个 boot 只能跑一次，rootd 一死本 boot 就结束。

结论：**rootd 只能当跳板，不能当日常通道。** 部署完 rootgate 之后，rootd 可以完全不管。

---

## 1. 结构：一次部署，整 boot 复用

```text
glx 跑通（本 boot 唯一一次）
  └─ deploy_root.py      用 rootd 的 1 条连接，把 uid0 的 rootgate setsid 脱离
        └─ rootgate 常驻（PPid=1、不依赖 pty、不占 rootd 剩余预算）
              └─ rootx.py '<cmd>'     日常唯一入口（flock 串行）
```

整条流程只花 rootd **1 条**预算（32 里的 1）。之后所有命令走 rootgate，
rootd 死不死都不影响。

---

## 2. 文件清单

| 文件 | 作用 | 依赖 |
|---|---|---|
| `rootx.py` | **唯一入口**。自动选后端、flock 串行、统一 timeout | 下面任意一个后端 |
| `deploy_root.py` | 一步部署：生成密钥 → 用 1 条 rootd 连接拉起 rootgate → 验 uid0 | `termux_uid0.py`、`rootgate_client.py` |
| `rootgate.sh` | 设备侧通道模板：`toybox nc -L`，仅 127.0.0.1，首行校验密钥 | 以 uid0 执行 |
| `rootgate_client.py` | 连 nc 通道跑一条命令（发 KEY → 命令 → `echo __RG_END__`） | 无 |
| `rootctl.py` | 调 AF_UNIX 形态 rootgate 的客户端（`ping` / `status` / `run` / `sh`） | `rootgate.py` |
| `rootmux.py` | 用**一条**长连接复用 rootd，把连接预算从「每命令 1 条」变成「每 boot 1 条」 | `termux_uid0.py` |
| `rootgate.py` | 另一形态的 rootgate：AF_UNIX + `SO_PEERCRED` 校验对端 uid，线程池 | 以 uid0 执行 |
| `rootgate_install.sh` | 拉起 `rootgate.py`（含「shell 域能否 exec Termux python3」的前置探测） | `rootx.py`、`rootctl.py` |

日常路径只需要前四个。后三个是加固形态与兜底，设备上的 `SECOND` 通道。

---

## 3. 冷启动后的部署步骤

前提：本 boot 的 glx 已经跑通（`USAGE.md` §5 那一套），且 `10369` 在听。

```bash
# 1) 确认 rootd 在（0 = 端口在听）
python3 -c "import socket;s=socket.socket();s.settimeout(2);print(s.connect_ex(('127.0.0.1',10369)))"

# 2) 宿主侧把通道模板推进去（一次性）
adb push ops/rootgate.sh /data/local/tmp/rootgate.sh
adb shell chmod 755 /data/local/tmp/rootgate.sh

# 3) Termux 侧就位
mkdir -p ~/bin ~/zd_chan && chmod 700 ~/zd_chan
cp ops/rootx.py ops/deploy_root.py ops/rootgate_client.py ops/rootctl.py ~/bin/
chmod 700 ~/bin/*.py
cp tools/termux_uid0.py ~/termux_uid0.py && chmod 700 ~/termux_uid0.py

# 4) 一步部署
python3 ~/bin/deploy_root.py 10370
```

期望输出形状：

```text
ROOTGATE|LISTEN|127.0.0.1:10370|uid=0|ctx=u:r:shell:s0
rootgate 已监听 127.0.0.1:10370
uid=0 euid=0 gid=0 ...
OK —— 之后一律用 `python3 ~/bin/rootx.py '<cmd>'`，rootd 可以放着不管了
```

之后日常只有两条命令：

```bash
python3 ~/bin/rootx.py --status      # 看后端/端口，退出码 0=活
python3 ~/bin/rootx.py 'id'
```

---

## 4. 密钥：两条通道、两把密钥、每 boot 轮换

| 通道 | 密钥位置 | 生成方 | 校验方 |
|---|---|---|---|
| rootd → Termux | `~/zd_secret`（0600） | glx 首次创建 | rootd 的 GATE 帧 |
| Termux → rootgate | `~/zd_chan/rg.key`（0600） | `deploy_root.py`（`os.urandom(18).hex()`，36 字符） | `rootgate.sh` 首行比较，不匹配 `exit 7` |

- 两把密钥互不复用；rootgate 的密钥**每 boot 重新生成**，不跨 boot 存活。
- 密钥值**不进仓库、不进日志、不进截图**（与 `AGENTS.md` §9 同一条规则）。
- `rootgate.sh` 支持把密钥作为第 2 个参数传入（不落盘），也支持自己生成到
  `/data/local/tmp/rg.key`（0600、root:root）。

---

## 5. `rootx.py` 的后端选择顺序

```text
1. rootgate        toybox nc @ 127.0.0.1:10370   首行密钥校验      —— 最稳
2. rootmux         AF_UNIX sock                  复用 1 条 rootd 连接
3. rootgate.sock   AF_UNIX + SO_PEERCRED         uid 不符直接 close
4. rootd 直连      tcp 127.0.0.1:10369           单线程，必须串行
```

`flock($HOME/zd_chan/root.lock)` 保证同一时刻只有一个 root 调用在飞，
这是为了不再把 rootd 的预算一次烧掉。

`--status` 会打印当前后端和 10369 端口状态，退出码 0 表示有可用后端。

---

## 6. 与 `AGENTS.md` §1 状态表的关系

| 项 | p11n 文档写的 | 现状 |
|---|---|---|
| keeper / 自动 re-spawn | **未实施** | **本地已实施**：rootgate 由 rootd 拉起后 PPid=1、脱离 pty，rootd 死不影响 |
| unix socket 替代 TCP | **未实施** | **本地已实施**：`rootgate.py` 用 AF_UNIX + `SO_PEERCRED`，不监听任何网络端口 |
| 多用户 / 工作资料 | 未验证 | 仍为未验证（`ALLOW_UID` 单值） |
| 同一 boot 二次 glx | 禁止 | 禁止不变 |

---

## 7. 换机器要改的两处

| 位置 | 默认值 | 说明 |
|---|---|---|
| `rootgate.py` 的 `ALLOW_UID` | `10369` | 改成目标 Termux 的 `id -u`；支持 `ROOTGATE_ALLOW_UID` 覆盖 |
| `rootmux.py` 的 `LOGP` | `~/.hermes/logs/rootmux.log` | 换到 `~/zd_chan/rootmux.log` 更干净 |

其余路径（`~/zd_chan/…`、`~/zd_secret`、`~/termux_uid0.py`）与 Termux 的
`/data/data/com.termux/files/home` 强绑定，属于本机形态，不用改。

---

## 8. 红线（与 `AGENTS.md` §2 一致，重申）

- 一个 boot 只跑一次 glx；失败就走人类正常冷启动，不碰 fastboot / EDL。
- 不 kill rootgate / rootd；armed 之后不向 `/dev/pmsg0` 写。
- 写操作、提权执行需人类明确授权。
- 本目录不含任何密钥值。
