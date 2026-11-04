# 百度网盘 PC 8.1.6.101 下载/限速机制逆向报告

> 对象：`MANIFEST.md` 记录的百度网盘 Windows 客户端 8.1.6.101 运行时快照（11 个 PE / 127 MB）。
> 结论全部可复现：脚本在 `re/tools/`，中间产物在 `re/out/`。

## 先看这三段（结论）

**1. 它是靠什么限速的？**
`kernel.dll`（P2P SDK 3.0.20.237）里有一个 `SpeedLimitor` + `AccumulateTokenBucket`（令牌桶），
`calculate_target_speed()` @RVA `0x2ddb90` 把「服务端下发的 `max_speed`」乘以「`restrict_ratio` + 随机抖动%」
算出本 tick 的目标速率，再由 `0x2dd780` 这个 thunk **直接 `push` 给 `TokenBucket::set_rate()`**。
真正"卡"住带宽的动作是 `TokenBucket::consume()` @`0xdb170`：桶里没令牌就不发 `request`，
BT/HTTP 的请求驱动模型于是自然少收数据。**限速完全在客户端执行，服务端只给数字。**

**2. 具体限到多少？**（本次样本实测/取证值）

| 场景 | 值 |
|---|---|
| 非会员基准（`basic_speed` = `download_total_speed_default`） | **122 880 B/s = 120 KiB/s** |
| 普通会员 | 409 600 B/s = 400 KiB/s |
| 高级会员 | 0 = 不限（改由 `restrict_ratio` 与桶 rate 压） |
| 触发提速（`spup_percent=860`） | 1 056 768 B/s ≈ 1.01 MiB/s |
| P2P 上传（`p2pu_percent=40`） | 49 152 B/s = 48 KiB/s |
| 判"慢速" | < 51 200 B/s 持续 15 s |
| "不限"哨兵 | `0x1F400000` = 524 288 000 B/s |

**3. 下载速度的逻辑是什么？**
`下载速度 ≈ min(并发链路数 × 每链路有效速率, 令牌桶配额)`。
前半段由「文件大小阈值决定走不走 P2P」+「网络等级 1/2/3 → 连接数 4/2/1」决定；
后半段由「服务端参数 → `calculate_target_speed` → 桶 rate」决定；
中间还有一个 `close cdn`（@`0x1aea38`）负反馈：**速度不达阈值就主动砍掉最快的 CDN 链路**。

## 文档

| 文件 | 内容 |
|---|---|
| [01-总览.md](01-总览.md) | 结论、样本信息、分析路线、**反推符号表**方法、证据分级 |
| [02-限速机制.md](02-限速机制.md) | 三层限速结构、服务端三条下发通道（含真实 JSON）、客户端默认值、`calculate_target_speed` 伪代码、令牌桶、B/s 速查表 |
| [03-crypto-and-config.md](03-crypto-and-config.md) | 配置/日志的编码与加密（**日志 = XOR 0x8A**，含复现代码） |
| [04-下载速度全链路.md](04-下载速度全链路.md) | 建任务 → 取链 → 造 peer → 连 peer → 分片 → 速度闸门 → 上报；`close cdn` 数值表 |
| [06-变速与收尾减速.md](06-变速与收尾减速.md) | **为什么开变速前段有效、后段反而更慢；为什么关掉变速会回血**（阈值 ∝ rate 的自我判定 + close cdn + 磁盘/请求超额） |
| [07-SVIP试用与提速.md](07-SVIP试用与提速.md) | **"试用 SVIP 几十秒"的完整实现**：提示触发条件（阈值+10% 灰度+每日 2 次）、`set_try_speedup_flag` 把 4 个令牌桶钉到 500 MB/s、结束时按快照台阶式还原 |
| [05-完整逆向报告.md](05-完整逆向报告.md) | 文件清单、`.rsrc` 自解压（内嵌 btsdk/cronet/speedtest）、模块图、导入导出、结构体、协议栈、反调试、方法论、Frida 点位、**已知缺口** |

## 工具

```bash
pip install pefile capstone
python3 re/tools/dump_all.py          # 元数据 + 日志解密
python3 re/tools/logsites.py bin/kernel.dll   # 反推符号表（1531 个函数名）
python3 re/tools/funcmap.py bin/kernel.dll    # → re/out/funcmap_kernel.dll.csv
python3 re/tools/extract_rsrc.py bin/kernel.dll  # 抽出内嵌的 3 个 PE
```

| 产物 | 内容 |
|---|---|
| `re/out/funcmap_kernel.dll.csv` | **1531 个函数的符号表**（RVA / VA / 名字 / 源码行号） |
| `re/out/YunLogic_config_template.txt` | 913 条明文默认配置（限速"出厂值"） |
| `re/out/set_param_table.txt` | `set_param` 的 147 项类型表 |
| `re/out/logmap_limiter.txt` | 限速代码区的日志点 → 文案映射 |
| `re/frida/hooks.js` | 10 个动态验证点 + 反反调试 |

## 免责声明

本文只做**静态取证与机制说明**，不含脱壳/破解/绕过工具；`re/frida/hooks.js` 里的
`PATCH_CONSUME` 仅用于验证"令牌桶就是限速点"这一结论，默认关闭。请勿用于违反服务条款的用途。
