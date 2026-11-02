# BASELINE — 链路可用基线

> 这份文件只做一件事：记录**这套 exploit / root 通道在某一个具体固件上能跑通**的指纹。
> 以后系统一更新，先拿这里的值对比，就能判断链会不会被打断，不必真跑一遍再发现 panic。
> 最后更新：2026-11-02 09:00 CST（boot_id `a3d32fe1`，uptime 7:26）

## 1. 设备指纹（实测）

| 项 | 值 |
|---|---|
| 型号 | `PHQ110` |
| 构建指纹 | `OPPO/PHQ110/OP5613:14/UKQ1.230924.001/T.24cf3cc-3e39b-e7f4b:user/release-keys` |
| 版本串 | `PHQ110_14.0.0.3000(CN01)` |
| Android | `14` |
| 内核 | `5.4.254-qgki-g0651f17b1c29` |
| 安全补丁级别 | `2026-07-01` |
| boot_id | `a3d32fe1-b2a5-4fea-aee8-ae11abb98311` |

**注意**：仓库其他文档（ARCHITECTURE / AGENTS）写的设备版本是 `C.53`，与实测的
`14.0.0.3000(CN01)` 不一致。以本文件实测值为准；`C.53` 那套偏移在本机上未验证。
仅型号 + 内核串一致、版本串不一致时，**不要默认偏移可直接复用**。

## 2. 当前链路状态（本 boot）

- 漏洞：`CVE-2026-43499`（GhostLock，rtmutex PI-futex UAF）
- 通道：`rootd`(一次性) → `rootgate`(toybox nc，127.0.0.1:10370，首行密钥) → `rootx.py`
- 实测：`python3 ~/bin/rootx.py 'id'` → `uid=0(root)`，rootgate 连续存活 6h+
- 本 boot 已消耗：1 次 glx 执行；rootd 仅用于拉起 rootgate

## 3. 为什么不能随便更新

1. **漏洞已修**：GhostLock 2026-04-18 上报、04-20 上游修复、05-04 backport、07-07 公开披露。
   本机补丁级别 `2026-07-01` 仍可利用，说明 OPPO 这个 5.4 分支**没有合并该 backport**。
2. **链是 device-specific**：硬编码内核地址与结构体偏移。内核串一变（哪怕只换 build 号），
   读链的 6 发和写链的 7 发全部需要重新推导。
3. 结论：**冻结 OTA**。若某次更新同时带上内核变化 + 该 backport，链直接失效且不可软恢复。

## 4. 更新前的最小复检（只读，不消耗 glx）

```bash
getprop ro.build.display.id          # 对比 §1 版本串
uname -r                             # 对比 §1 内核串
getprop ro.build.version.security_patch   # 对比 §1 补丁级别
cat /proc/sys/kernel/random/boot_id  # 换过 = 新 boot
```

判断规则：

- 三项全同 → 链大概率仍可用（同 boot 例外，见 AGENTS §「每 boot 只跑一次」）
- 内核串变 → 视为不可用，需重新推导偏移
- 补丁级别跨过 2026-05 → 先确认 GhostLock backport 是否合并，别直接跑

## 5. 赏金定位（避免重复投入）

- `CVE-2026-43499` 已公开，NebuSec 已获 kernelCTF 奖励；已知 CVE 的机型移植不属于新发现，
  主流 VRP / 厂商 SRRC 不收。
- 本项目的复用价值在**通道框架**（rootd → rootgate → rootx，连接复用、免重启），
  与具体 CVE 解耦；换新漏洞时只需替换 exploit 层。
