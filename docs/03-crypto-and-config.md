# 03 · 配置与日志的加密方式（附 Python 复现）

本仓库里的 `config/` 与 `logs/` 都不是明文。逐个验证后的结论：

| 文件 | 编码/加密 | 复现方式 | 解密后内容 |
|---|---|---|---|
| `config/AppSettingApp.dat` | UTF-16LE 文本包裹的 **Base64**，解开后是密文（疑似 AES/RC4 + 机器相关密钥） | `b64decode(f.read().decode('utf-16le'))` → 18920 字节熵 ≈ 7.99 | 应用设置（下载/限速偏好所在），密钥未在包内暴露 → 需动态抓 `set_parameter` |
| `config/users/<uk>/PersonalSetting.xml` | 同上，Base64 后 6774 字节密文 | 同上 | 账号级设置（初始化时会 `?AVConfigFile` 读） |
| `config/VersionInfo` / `VersionInfo2` | 192 字节裸密文，熵 6.9；与 `PersonalSetting` 密文同一密钥（同尺寸结构） | 无 | 版本号 |
| `config/kernel_kernelb.cfg` | 3397 字节裸密文，熵 7.94 | 无 | 内核运行时配置（限速开关/CMS 域名） |
| `config/kernel_download.s3dbe` | 3072 字节密文（SQLite 页大小对齐，说明是加密后的 sqlite 页） | 无 | 任务表 `t_download_task` / `t_p2p_task` |
| `config/kernel_pop` | 456 字节密文 | 无 | POP 节点列表 |
| `config/crossdomain.dat` | 7520 字节密文，熵 7.98 | 无 | 跨域策略 |
| `config/users/*/BaiduYunGuanjia.db` | **明文 SQLite3**（`SQLite format 3`） | `sqlite3` | 账号/本地数据 |
| `config/resource.db` | **未加密的 OLE2/CFBF 容器**（`D0CF11E0A1B11AE1`） | `olefile` | 资源索引 |
| `resources/resources.pri` | **明文 MRT/PRI v2**（`mrm_pri2`），内含 `AIAssets\*.png` 等 WinUI 资源名 | 直接解析 | 只有图标资源，**不含**限速文案 |
| `config/install.log` | **明文 UTF-16LE** | `decode('utf-16le')` | NSIS 安装日志（4628 行） |
| `logs/BaiduKernel_*.log` | **单字节 XOR 0x8A** | `bytes(b ^ 0x8a for b in data)` | 完整内核运行日志 |

> ⚠️ 注意 `MANIFEST.md` 的两处判断需要修正：
> 1. `resources.pri` 里**没有**限速/提速文案，只有 AI 图标（`AI\\AIAssets\\*.png` 等）。限速文案在 `YunLogic.dll` 的内嵌配置里（见 02 篇）。
> 2. `logs/*.log` 不是"压缩/未知加密"，而是 **XOR 0x8A** 的纯文本日志，解出来可直接读。

## 1. 日志解密（一键复现）

> `python3 re/tools/dump_all.py` 会把两份日志解密到 `re/out/*.log.decoded`。

```python
# 最小复现（正式版在 re/tools/dump_all.py）
KEY = 0x8A
for f in ("logs/BaiduKernel_20261028040309_641_1.log",
          "logs/BaiduKernel_20261119200054_937_1.log"):
    raw = open(f, "rb").read()
    open(f + ".decoded", "wb").write(bytes(b ^ KEY for b in raw))
```

解出的行格式：

```
|<ISO8601 时间> <级别> [<线程id>] {<模块>} <函数>:<行号> <正文>
```

模块名即内核子系统：`Kernel` `Task` `netio` `serverProxy` `uTP` `upload` `filesystem`
`network_detector` `cronet` `Update` …（完整清单见 `re/out/log_modules.txt`）。

### 日志里挖到的、与限速直接相关的两条关键记录

```
|2026-11-19T20:14:18.162791 1 [27668] {serverProxy} handle_p2p_switch_param_recv:411
  |task_handle=0|data={"cfg":{"p2p_switch_param":{
      "basic_speed":122880,        # 基准速度 120 KiB/s
      "p2pu_percent":40,           # P2P 上传占基准速度比例 40%  -> 48 KiB/s
      "spup_peer":100000,          # 触发"提速"的 peer 数阈值
      "spup_percent":860,          # 提速后目标 = basic_speed * 860% = 10.1 MiB/s
      "ss_strategy":0,
      "ss_strategy_version":2}},"error_code":0,...}

|2026-11-19T20:14:18.162791 1 [18180] {Task} operator():214 get p2p switch
  |spup_peer=100000|spup_percent=860|basic_speed=122880

|2026-11-19T20:16:56.392926 1 [23904] {Kernel} set_parameter:138 TryVipToken=
|2026-11-19T20:16:56.393925 1 [18180] {Task} operator():3786 set try vip speed up
  |cur flag=0|set flag=0|membership=1          # membership=1 → 普通用户
|2026-11-19T20:16:56.393925 1 [18180] {Kernel} operator():3811 token =
|2026-11-19T20:16:56.393925 1 [23904] {Kernel} set_parameter:264
  |UserSpeedLimit={"p2s_s":"0","total_s":"0","tm":"1793240482","rnd":"111b881b24af47e7ae548f071fc39132"}
```

这三个 JSON/键值就是"限速参数的三条下发通道"：**CMS 开关（p2p_switch_param）**、
**试用会员令牌（TryVipToken）**、**用户级限速（UserSpeedLimit）**。
`total_s=0 / p2s_s=0` 的含义是"用户没有自设全局限速、也没有自设单任务限速"，
真正生效的限制全部来自服务端 + 本地策略（见 02 篇）。
