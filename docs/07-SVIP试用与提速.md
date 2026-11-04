# 07 · "试用 SVIP 几十秒"是怎么实现的：为什么会提示、为什么会提速

> 现象：下载慢的时候客户端会弹一个"免费体验 SVIP 提速"的提示，点了确实快，但只快几十秒就掉回原速。
>
> 本文回答三个问题：**① 提示从哪来 ② 提速到底改了什么 ③ 为什么只有几十秒，时间由谁定。**
> 地址均为 `kernel.dll` 的 RVA。证据分级 ✅/🟡/⚪ 沿用前几篇。

---

## 0. 三句话结论

1. **提示是"概率 + 阈值"双控的营销逻辑**，文案和门槛全部写在客户端明文配置里
   （`speeduptip_speed_limit=51200`、`enable_p2pspeedupguide_percent=10`、`vip_experience_guide_times=2` …），
   而"你能不能真的提速"由**服务端**回一个 `can_speedup` / `TryVipToken` 决定。✅
2. **提速的实现不是"把速度上限调高一点"，而是把限速器的四个令牌桶 rate 全部钉到 `0x1F400000` = 524 288 000 B/s**
   ——也就是**500 MB/s，事实上等于"解除限速"**。✅（`0xe2fb0` 逐条可读）
3. **时长不在客户端**：客户端只做"置位→钉桶 / 复位→按快照还原"，几十秒后由服务端（或下一次 flag 刷新）
   把 flag 打回 0，于是**瞬间回到原来的速率**——不是慢慢降，是"台阶式"掉回去。✅

---

## 1. 提示是怎么触发的

### 1.1 客户端侧的门槛（全部是明文配置，来自 `YunLogic.dll`）

| key | 值 | 作用 |
|---|---|---|
| `speeduptip_speed_limit` | **51200** | 当前速度 < 50 KiB/s 才有"提速提示"的资格 |
| `p2pspeeduptip_nonsvip_speed_limit` | **102400** | 非 SVIP 的 P2P 提速提示阈值（100 KiB/s） |
| `p2pspeeduptip_svip_speed_limit` | **204800** | SVIP 的阈值（200 KiB/s） |
| `enable_p2pspeedupguide_percent` | **10** | ★ **只有 10% 的会话会弹**（灰度/随机） |
| `enable_p2pspeedupguide_percent_v2` | **100** | v2 版本 100%（全量） |
| `max_speedup_guide_tip_close_count` | **2** | 同一用户最多被打断 2 次 |
| `auto_show_title_game_dlg_after_speedup_tip_close_millisecond` | 5000 | 提示关闭 5 s 后接别的弹窗（营销串联） |
| `vip_experience_guide_times` | **2** | ★ **每天 2 次体验机会** |
| `vip_experience_guide_speed` | **6** | 体验档位（6 → 6 MB/s 级） |
| `vip_experience_guide_percent` | 200 | 体验提示的触发百分比 |
| `vip_experience_speed_percent` | **60** | ★ 体验只给**会员速度的 60%** |
| `vip_experience_guide_way` | 1 | 提示样式（1=弹窗） |
| `speedup_file_size` / `_v2` | 52428800 / 1048576 | 文件太小就不值得提速（50 MiB / 1 MiB） |
| `p2pspeedup_min_file_size` | 62914560 | P2P 提速最小文件 60 MiB |

**「每天 2 次 × 几十秒 × 明显快但不满速」这三个特征，正好由 `guide_times=2` / `guide_speed=6` /
`speed_percent=60` 三个数字解释。** ✅

### 1.2 "能不能提"由服务端说了算

客户端会把这些字段上报给服务端（`0x1271076`，日志点 `0xf6a1e`）：

```
eApiCode=%1%|eTaskCode=%2%|eErrorCode=%3%|n64FileSize=%4%|n64DownloadedSize=%5%|
n64P2PDownloadedSize=%6%|nHttpSpeed=%7%|nP2PSpeed=%8%|strFileName=%9%|
rollback_switch=%10%|can_speedup=%11%|p2puser_percent=%12%|speedup_percent=%13%|
basic_speed=%14%|disk_slow=%15%|pcs_code=%16%|pcs_msg=%17%|request_id=%18%
```

注意 `can_speedup`、`p2puser_percent`、`speedup_percent`、`basic_speed`、`disk_slow`
**这几个是"上报"而不是"读取"** —— 说明判定权在服务端（`p2p_switch_param` 里回的
`spup_percent=860` / `spup_peer=100000` 就是同一套参数）。

每个任务还单独带一个试用标记（`0x127d3a0`）：

```
push task 1|id=%1%|path=%2%|if_try_vip=%3%
```

### 1.3 试用额度是独立的一路令牌

`0x1276df0` 这条日志把"令牌"分了五路：

```
|no token|total_token=%1%:%2%|task_token=%3%:%4%|cdn_token=%5%:%6%|
peer_token=%7%:%8%|svip_control_token=%9%:%10%|addr=%11%:%12%|task_type=%13%|bd_token=%14%|ptype=%15%
```

`svip_control_token` 与 `task_token` / `cdn_token` / `peer_token` **并列**但不共用：
**没有 `svip_control_token` 就没有试用提速**，这正是本次样本的状态（见 §4）。

---

## 2. 提速到底改了什么：`set_try_speedup_flag` @`0xe2fb0`

这是全篇最关键的函数。签名大致是 `void set_try_speedup_flag(bool on)`（`__thiscall`，
`mov al,[ebp+8]` 取参数），源码行号 207（另一个实例 `0xe42b6` 行 227 是它的"恢复版"）。

```c
void Task::set_try_speedup_flag(bool on) {
    if (this->try_on /*+0x1c0*/ != 0) return;      // 已在试用中 → 幂等返回
    if (!on) { ... 走恢复分支（见 §2.2） ... }

    this->try_on = 1;

    // ① 先备份四个限速档（每个档 = 一个 SpeedLimitor + 一个 TokenBucket）
    this->pre[0] = this->cur[0 /*+0x30*/];                      // 0x3011-0x3017
    bucket(this+0x38).set_rate( get_capacity(bucket(this+0x00)) ); // 0x301a-0x3024
    this->pre[1] = this->cur[1 /*+0x110*/];                     // 0x3032-0x303e
    bucket(this+0x118).set_rate( get_capacity(bucket(this+0xe0)) );
    this->pre[2] = this->cur[2 /*+0xa0*/];
    bucket(this+0xa8).set_rate( get_capacity(bucket(this+0x70)) );
    this->pre[3] = this->cur[3 /*+0x180*/];
    bucket(this+0x188).set_rate( get_capacity(bucket(this+0x150)) );

    // ② ★ 四个桶全部钉到 0x1F400000
    bucket(this+0x00 ).set_rate(0x1F400000);   // 0x309d-0x30a4
    bucket(this+0x38 ).set_rate(0x1F400000);   // 0x30af-0x30b6
    bucket(this+0xe0 ).set_rate(0x1F400000);   // 0x30bb-0x30c3
    bucket(this+0x150).set_rate(0x1F400000);   // 0x30c8-0x30d0

    // ③ 日志
    log(0x1122dfb4, "try speedup start|total_sl=%1%|user_sl=%2%|cur_server_sl=%3%|"
                    "pre_server_sl=%4%|pre_flag=%5%|set_flag=%6%|");
}
```

对应的汇编（`re/out` 风格，节选，全部实测）：

```asm
100e2ff8  mov  cl,[esi+0x1c0]      ; try_on
100e2ffe  test cl,cl
100e3000  jne  0x100e39dd          ; 已在试用 → 直接跳到收尾
100e3006  test al,al
100e3008  je   0x100e39dd          ; on==false → 恢复分支
100e3011  mov  eax,[esi+0x30]
100e3017  mov  [esi+0x68],eax      ; 备份 rate
100e301c  call 0x100db010          ; get_capacity() → [this+8]
100e3023  push eax
100e3024  call 0x100db150          ; set_rate(...)
...                                ; ×4 组（+0x38 / +0x118 / +0xa8 / +0x188）
100e309f  push 0x1f400000
100e30a4  call 0x100db150          ; ★ 钉死
100e30b1  push 0x1f400000
100e30b6  call 0x100db150
100e30be  push 0x1f400000
100e30c3  call 0x100db150
100e30cb  push 0x1f400000
100e30d0  call 0x100db150
100e30f2  push 0x1122dfb4          ; "try speedup start|cdn_sl=…"
```

### 2.1 `0x1F400000` 就是"无限"

`0x1F400000 = 524 288 000` B/s ≈ **500 MB/s**。这个常数在库里到处出现：

- 令牌桶构造函数 `0x100db020`：`[+8]=0x1f400000`、`[+0x20]=0x1f400000` → **默认就是"不限"**
- `calculate_target_speed` 的"关闭抖动"分支返回 `0x1F400000`
- 本函数把它当作"解除限速"的哨兵值写进 rate

**所以"试用提速"在实现上等于"把限速器整个旁路掉"**，而不是"给一个更大的数字"。✅

### 2.2 结束：按快照还原，不是重算

`on == false` 的分支（`0xe39dd`–`0xe3ab1`）是一串 `movups` 快照回填：

```asm
100e39f0  movups xmm0,[esi+0x40] ; movups [esi+8],xmm0     ; 还原 max_speed(64位)+ratio
100e39f8  movups xmm0,[esi+0x50] ; movups [esi+0x18],xmm0
100e3a00  mov    eax,[esi+0x60]  ; mov    [esi+0x28],eax
100e3a06  mov    eax,[esi+0x68]  ; mov    [esi+0x30],eax   ← 备份的 rate 写回
100e3a0c  ... +0xb0/+0xc0/+0xd0/+0xd8 → +0x78/+0x88/+0x98/+0xa0
100e3a3d  movsd  xmm0,[esi+0x130]; movsd [esi+0xf8],xmm0
100e3a77  mov    eax,[esi+0x148]; mov   [esi+0x110],eax
100e3a83  ... +0x190/+0x1a0/+0x1b0/+0x1b8 → +0x158/+0x168/+0x178/+0x180
100e3adb  push 0x1122e00f        ; "try speedup end|cdn_sl=…"
```

**这就是"为什么时间一到速度是台阶式掉回去"的答案**：不是重新计算一个更低的目标，
而是把试用开始时拍下的快照**整块写回**。所以你看到的是"前一秒 6 MB/s，下一秒 100 KB/s"。✅

### 2.3 还有第二套（CDN 侧）

两个字符串说明"提速"要同时动两条线：

```
try speedup start|cdn_sl=%1%|total_sl=%2%|cdn_src=%3%|total_src=%4%|flag=%5%|old_flag=%6%|
try speedup end  |cdn_sl=%1%|total_sl=%2%|cdn_src=%3%|total_src=%4%|flag=%5%|old_flag=%6%|
```

`cdn_sl` 与 `total_sl` 各有自己的 `src`（来源）和 `flag`，
对应 02 篇的三层结构：**总速率**（`SpeedLimitor`）与**CDN 配额**（`cdn_speed_limit_dispatch` @`0x2ed84e`）分别放开。

### 2.4 顺带还有"SVIP 加成"

`adjust_max_cdn_peer_per_task_for_svip` @`0x2ec27e`（行 1341）：
真 SVIP 不只放开 rate，还会**调高每任务的 CDN peer 上限**（配置 `max_cdn_peer_count_per_taskfor_svip`）。
所以"试用"和"真 SVIP"体感仍有差别——试用只借走了限速，没借走更多连接。🟡

---

## 3. 为什么只给几十秒，时间由谁定

| 线索 | 内容 | 结论 |
|---|---|---|
| `SVIP_STRIAL_TOKEN` @`0x1261dfd`、`SVIP_STRIAL_TIME` @`0x1263152` | 两个字符串存在，但**在本 DLL 里没有代码引用**（`xrefs = []`） | 试用时长是"外部传入的字段名"，不是本地常量 🟡 |
| `bandwidth_speedup_download_tip` | "SVIP限免福利！移动宽带**每日2次**下载1000M带宽体验，**每次1分钟**，间隔4小时。(仅广西…)" | 运营商合作款的时长就是 **1 分钟**，与"几十秒"直接吻合 ✅ |
| `vip_experience_guide_times = 2` | 每日次数 | ✅ |
| `set_try_speedup_flag` | **没有本地定时器**，只有一个 `+0x1c0` 的置位标志 | 倒计时不在这个函数里 🟡 |

**推断链**：`TryVipToken`（`set_param` key=1）里带下发的额度/时长 → 服务端在额度用尽时把
flag/`TryVipToken` 打回 0（下一次 `set_param`）→ 客户端 `set_try_speedup_flag(false)` 按快照还原。

> 🟡 未验证项：客户端是否存在一次本地回退定时器（可能在 `YunLogic.dll` 的 VMProtect 段里，
> 或由 `TRY_SPEEDUP_FLAG=%1%` 这条日志的轮询逻辑驱动）。
> 想一次定论：hook `0xe2fb0` 的入口，打时间戳 + 入参，看 0→1→0 的间隔是否恒等于 60 s。

---

## 4. 为什么这一次（本仓库样本）没有提速

解密日志里明明白白：

```
{Kernel} set_parameter:138  TryVipToken=            ← 空
{Task}   operator():3786    set try vip speed up|cur flag=0|set flag=0|membership=1
```

- `TryVipToken` **为空** → 没有试用额度
- `set flag=0` → 从未置位 → `0xe2fb0` 的"钉桶"分支一次都没执行
- 同时服务端给的 `spup_peer = 100000`（要 10 万个 peer 才触发普通 P2P 提速）= **事实上禁用**

于是这个账号能看到的只有**营销提示**，点下去也只是"下次一定"。✅

---

## 5. 一张图串起来

```
       服务端 CMS  ──spup_percent=860 / spup_peer=100000──▶ 普通 P2P 提速（实际被禁用）
           │
           ├─ TryVipToken / can_speedup ──▶ 试用额度（有 = 才可能真提速）
           │
   客户端  ▼
   [速度 < 50KiB/s] ──┬── enable_p2pspeedupguide_percent(10%) ──▶ 弹提示（营销）
                      └── 用户点了 + 有 token
                                │
                                ▼
                   set_try_speedup_flag(true)         @0xe2fb0
                     ① 备份 4 个桶的 rate 到 +0x68/0x148/0xd8/0x1b8
                     ② 4 个桶 set_rate(0x1F400000 = 500 MB/s)
                     ③ log "try speedup start|cdn_sl…|total_sl…"
                                │
                     几十秒（服务端额度用尽 / 1 分钟体验）
                                ▼
                   set_try_speedup_flag(false)
                     ① 快照整块写回 → 台阶式掉回原速
                     ② log "try speedup end|…"
```

---

## 6. 和 06 篇的关系（很重要）

06 篇说"变速开太大 → 后段反而更慢"，原因之一是**门限 ∝ rate**。
试用为什么不会这样？因为试用**同时**把 `max_speed` 也顶到 500 MB/s（`+0x40/+0x44` 的 64 位快照一起换），
`close cdn` 的 1~2 MiB/s 阈值也远远满足 —— 也就是说**它是一整套"进入 VIP 状态"的完整切换**，
而你用的变速工具通常只改了 rate 这一个字段。
这也解释了为什么"试用几十秒"的体感比"变速开很大"好得多。✅

---

## 7. 诚实的缺口

| # | 缺口 | 影响 | 怎么补 |
|---|---|---|---|
| 1 | 试用倒计时的实现位置未定位 | 无法说"正好 60 秒"是不是客户端控的 | hook `0xe2fb0` 打时间戳 |
| 2 | `SVIP_STRIAL_TOKEN/TIME` 无代码 xref | 不知道它被哪个模块消费 | 在 `YunLogic.dll`/`KernelCom.dll` 里找同名字符串 |
| 3 | `0x1F400000` 是否等于"真无限" | 桶容量也是 500 MB/s，理论上仍有限 | 用 `sample_max_speed` 上报值反推真实峰值 |
| 4 | `vip_experience_*` 四个 key 无代码 xref | 这几个数字的"消费方"未定位（可能在 VMProtect 段） | 需要脱壳 |
| 5 | `svip_control_token` 的签发/校验流程 | 不知道 token 是否绑定单任务 | 抓 `pan.baidu.com` 的试接口 |
