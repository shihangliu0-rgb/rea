# re/frida —— 动态验证工具包

文件说明：

| 文件 | 作用 |
|---|---|
| `hooks.js` | 全部 hook 点（14 个），纯 JS，Frida 脚本 |
| `run.py` | **不用 `frida` 命令也能跑**，纯 Python API 启动/附加 |
| `selftest.js` | 30 秒体检：位数/模块/能不能 hook/kernel.dll 是否加载 |
| `dump_ps.py` | 不用 `frida-ps` 也能列进程，找 PID |
| `verify_rva.py` | **离线**校验 hooks.js 里的 RVA 与字节签名是否对得上你的 kernel.dll |
| `census.py` | **多进程普查**：列出每个百度进程里有哪些关键模块，直接告诉你该 attach 哪个 pid |
| `rescan.py` | **离线重定位**：在新版本 kernel.dll 上重新找 13 个点位，并读 FileVersion/SizeOfImage 做版本指纹 |
| `locate.py` | **活体重定位**：在运行进程里 Memory.scan，输出可粘贴的 `PROFILES` 条目 |
| `tests/smoke.py` | **提交前自检**：node --check + 用假 Frida API 真跑 locate 的 agent + 假 frida import 测 Python + verify_rva 正负例 |
| `README.md` | 本文件 |

---

## 0. 先搞清楚一件事：`pip install frida` 不给命令行

| 包 | 提供什么 |
|---|---|
| `frida` | Python 绑定（`import frida`）+ 每个平台的 `frida-core` 原生库 |
| `frida-tools` | **命令行**：`frida`、`frida-ps`、`frida-trace` … |

所以：

```bat
pip install frida frida-tools
```

装完 `frida-tools`，`frida --version` 才有东西。**但这不是必须的** —— 本目录的 `run.py` 只用
`frida` 这个 Python 包，不需要命令行。

> ⚠️ 用哪个 Python 装，就用哪个 Python 跑。`py -3 -m pip install frida` → `py -3 run.py spawn`。

---

## 0.5 Frida 17 的破坏性变更（`TypeError: ... is not a function` 的根源）

Frida 17 删掉了一批静态 `Module` API。旧脚本一跑就报 `not a function`：

| 旧写法（≤16） | Frida 17 的写法 |
|---|---|
| `Module.findExportByName(null, 'open')` | `Module.findGlobalExportByName('open')` |
| `Module.getExportByName(null, 'open')` | `Module.getGlobalExportByName('open')` |
| `Module.findExportByName('kernel32.dll', 'x')` | `Process.getModuleByName('kernel32.dll').findExportByName('x')` |
| `Module.getExportByName('kernel32.dll', 'x')` | `Process.getModuleByName('kernel32.dll').getExportByName('x')` |
| `Module.findBaseAddress('x.dll')` / `getBaseAddress` | `Process.getModuleByName('x.dll').base` |

另外几条也会咬人：

- `Module.getSymbolByName(null, x)` → `Module.getGlobalExportByName(x)`
- 静态枚举（`Module.enumerateExports` 等）已删除，要用 `Process.getModuleByName(...).enumerateExports()`
- `frida -f` 的 `--no-pause` 已移除；`--runtime=v8` 不必再写（默认就是 V8）
- 静态属性 `Module.load/ensureInitialized` 也没有了

**本仓库的 `hooks.js` 已经全部改完**：所有符号查找都走 `findExport()` 兼容函数，
16/17 都能跑，也不再使用箭头函数。

---

## 1. 最快的用法（推荐）

**以管理员身份**打开命令提示符（Frida 注入需要管理员权限；否则会被 UAC/杀软拦）：

```bat
cd /d <本仓库路径>\re\frida

REM ① 先体检（版本/位数/进程）
python run.py check

REM ①.5 先离线确认"地址还对不对"（不需要 Frida、不需要开客户端）
python verify_rva.py

REM ①.6 注入死活不通时，用 selftest 判断是环境问题还是脚本问题
python run.py attach --name BaiduNetdisk.exe --script selftest.js

REM ② 关掉已经开着的百度网盘，然后让脚本自己拉起客户端
python run.py spawn

REM ③ 客户端已经开着，直接挂上去
python run.py attach
```

`spawn` 和 `attach` 的区别：

| 模式 | 能抓到什么 | 代价 |
|---|---|---|
| `spawn` | **启动期**的一切（`set_param` 首次下发、`kernel.dll` 加载、试用 flag 初始值） | 会重新启动客户端 |
| `attach` | 挂上之后的行为（下载中、试用触发、限速变化） | 抓不到启动期 |

想验证"试用 SVIP 到底是不是 60 秒"，用 `attach` 就够（点提示的那一刻才开始有关键事件）。

想抓 `set_param` 的完整下发，用 `spawn`。

---

## 2. `run.py` 的参数

```bat
python run.py check
python run.py spawn  [--exe "D:\BaiduNetdisk\BaiduNetdisk.exe"] [--out log.txt]
python run.py attach [--name BaiduNetdisk.exe | --pid 12345]   [--out log.txt]
```

- `--exe`  客户端路径（默认找 `C:\Program Files\Baidu\BaiduNetdisk\`）
- `--name` 进程名（默认 `BaiduNetdisk.exe`）
- `--pid`  直接给 PID
- `--out`  同时把输出写文件（UTF-8）

按 `Ctrl-C` 结束；`spawn` 模式下会 detach，**不会**杀掉客户端。

---

## 3. 如果是用官方命令行

装了 `frida-tools` 之后也可以直接：

```bat
frida -f "C:\Program Files\Baidu\BaiduNetdisk\BaiduNetdisk.exe" -l hooks.js --runtime=v8
```

或附加：

```bat
frida -n BaiduNetdisk.exe -l hooks.js
frida -p 12345 -l hooks.js
```

> **必须带 `--runtime=v8`**。`hooks.js` 用了箭头函数，默认的 QuickJS 运行时在部分版本上会报
> `SyntaxError: unexpected token '=>'`。

---

## 4. 应该看到什么

注入成功后会先打：

```
[+] 已屏蔽 IsDebuggerPresent
[+] 已屏蔽 CheckRemoteDebuggerPresent
[+] hook set_param @ 0x.... (RVA 0x1225f0)
[+] hook update_max_speed ...
...
[+] 开始输出（Ctrl-C 结束）
```

然后随事件打（节选）：

```
[set_param] type=37 value={"p2s_s":"0","total_s":"0","tm":"...","rnd":"..."}
[max_speed] 122880 -> 122880 B/s
[ratio] old=100% new=85%
[threshold] download_threshold_speed=122880 B/s (= rate × 1.3，rate 越大门槛越高)
[gate] left_block=37 rate=8388608 ratio=85
[trial] on=1 state_before=0
          bucket+0x0: rate=524288000 cap=524288000
[trial] 持续时间 ≈ 61.2 s
[trial] on=0 state_before=1
```

排查用的对照表：

| 你的问题 | 看哪一行 |
|---|---|
| 服务端下发了什么参数 | `[set_param] type=…` |
| 限速值到底多少 | `[max_speed]` / `[target]` |
| 试用到底提速了没 | `[trial] on=1` + `bucket+0x…: rate=524288000` |
| 试用是不是 60 秒 | `[trial] 持续时间 ≈ N s` |
| 后段为什么变慢 | `[gate] left_block` 逼近 0 而 `[threshold]` 仍是几 MB/s |
| 谁在改下限 | `[ratio] new=…` |

---

## 4.2 改完脚本先跑自检（30 秒）

```bat
python re\frida\tests\smoke.py
```

它做四件事，其中第 2 件是**必须的**：

1. `node --check` 所有 js
2. 把 `locate.py` 生成的 agent JS 抽出来，用**假 Frida API 在 Node 里真跑一遍**
   —— 之前 `ReferenceError: 'kernel' is not defined` 就是漏了这一步
3. 用假 `frida` 模块 import `locate.py` / `census.py`，确认 Python 侧不炸
4. 跑 `verify_rva.py` 正例（`bin/kernel.dll` 全 OK）+ 负例（`kernel_o.dll` 全 BAD）

全部通过才算可以提交。

---

## 4.3 版本不匹配：13 条全报"字节不匹配"

```
[!] 跳过 set_param：RVA 0x1225f0 处字节不匹配 期望=55 89 e5 … 实际=50 e8 ca 3c fb ff …
========== 安装完成：成功 0 个，跳过 13 个 ==========
```

**不是脚本写错，是 `kernel.dll` 版本不同**。`hooks.js` 的 RVA 定在
3.0.20.237（`SizeOfImage = 0x2a3a000` = 42.23MB）上；你机器上是 43.1MB 的那一版，
`.text` 长度不同 → 每个函数 RVA 都变了。

先看第一行版本指纹输出，它会直接告诉你是不是这个问题：

```
[+] 版本核对通过：SizeOfImage = 0x2a3a000 (42.23MB)
```

或者：

```
!!!!!! 版本不匹配 !!!!!!
  实际 SizeOfImage = 0x2b10000  (43.10MB)
  → 13 个 RVA 全部错位 …
```

三条路（详见 `docs/09-内核版本不匹配与重定位.md`）：

| 路线 | 命令 | 说明 |
|---|---|---|
| A 离线重定位 | `python rescan.py --dll "<安装目录>\kernel.dll"` | 静态扫，不碰进程 |
| B 活体扫描 | `python locate.py --pid 27568` | 直接输出可粘贴的 `PROFILES` 条目 |
| C 换回旧版 | 装 8.1.6.101 | docs 01–07 全部基于这一版，最省成本 |

---

## 4.4 先跑 census.py：找出 kernel.dll 到底在哪个进程

百度网盘是多进程的，attach 错进程就会永远"等 kernel.dll"。这个脚本把每个百度进程
挨个扫一遍，列成一张表：

```bat
python census.py
```

```
pid     name                       kernel.dll   kernel_btsdk  YunDls  YunLogic  netbase  模块数
27668   BaiduNetdisk.exe           0x5a3c0000   -             有      有        有       118
4120    YunUtilityService.exe      -            -             -       -         -        22

★ 下载内核在：pid=27668  BaiduNetdisk.exe
   挂上去： python run.py attach --pid 27668
```

表里谁有 `kernel.dll`，就 attach 谁。全都没有再看 §4.5。
详细的事实梳理见 `docs/08-复核-kernel加载事实.md`。

---

## 4.5 一直等待 kernel.dll —— 怎么办（最常见）

`kernel.dll` **不是启动就加载的**。它是客户端"要用到 P2P 下载内核"时才按需
`LoadLibrary` 的（解密日志显示，先有 `serverProxy`/`Kernel` 初始化，之后才有 `netio`/`uTP`/`Task`）。

现在的 `hooks.js` 会自动诊断，你会看到：

```
[*] 3 秒了，kernel.dll 还没出现。先看一眼当前状态：
---------- 诊断 ----------
已加载模块数：118
  [已加载] BaiduNetdisk.exe     base=... size=...
  [已加载] YunLogic.dll         base=... size=4.1MB
  [已加载] YunDls.dll           base=... size=2.4MB
  [  --  ] kernel.dll
  ...
[i] YunDls.dll 已在 → 下载内核随时可能按需 LoadLibrary("kernel.dll")。
    现在去客户端里点一个下载（任意文件），kernel.dll 会立刻加载。
--------------------------
```

对照结论：

| 诊断输出 | 含义 | 怎么做 |
|---|---|---|
| 连 `YunDls.dll` 都没有 | 客户端还停在登录/首屏，下载子系统没起来 | 登录进主界面 |
| 有 `YunDls.dll`、没 `kernel.dll` | 正常。P2P 内核还没被用到 | **点一个下载**（文件要够大，≥5 MiB 才会走 P2P） |
| `kernel.dll` 出现了但没打印 `[+] hook ...` | 观察者漏事件 | 等 2 秒，脚本有轮询兜底 |
| `frida-ps` 里有**另一个** Baidu 进程 | 客户端是多进程，下载在别的 pid | `python run.py attach --pid <那个pid>` |
| 用 `spawn` 起的进程一直不初始化 | VMProtect 对新进程敏感 | 改成先手动开客户端，再 `attach` |

**推荐流程**（最省事，成功率最高）：

```bat
REM 1. 先手动打开百度网盘，登录进主界面
REM 2. 挂上去
python run.py attach

REM 3. 看到 "[i] 已注册模块观察者" 之后，在客户端里点一个下载
REM 4. kernel.dll 一加载就会自动打出 "[+] hook ..." 共 12 行
```

`spawn` 模式只在你要抓"启动瞬间的 set_param"时才需要；验试用/限速用 `attach` 就够。

另外：如果你的 `frida` CLI 输出里夹着一堆
`message: {'type': 'send', 'payload': {...}}`，那是脚本开了 `SEND_DUP`（为 `run.py` 落文件用）。
把 `hooks.js` 顶部 `SEND_DUP` 改成 `false` 就干净了。

---

## 5. 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| `'frida' 不是内部或外部命令` | 只装了 `frida`，没装 `frida-tools`；或者直接用 `python run.py` |
| `ImportError: No module named frida` | pip 装到了另一个 Python。用 `python -c "import sys;print(sys.executable)"` 对齐 |
| `Failed to spawn: unable to access process` / `access denied` | 没用管理员运行；或被杀软拦（加白名单） |
| `Failed to attach: process not found` | 进程名不对。用 `python run.py check` 列出来 |
| 注入成功但**一行 hook 都没打** | `kernel.dll` 还没加载。`attach` 模式下要么先开始一个下载，要么用 `spawn` |
| `[!] 等不到 kernel.dll` | 同上：客户端起来了但 P2P 内核没被用到（比如还没开始下载） |
| 客户端启动就退出 / 报 0xc0000005 | 说明被检测或注入时机不对。改用 `attach`（等界面出来再挂），并确认 `hooks.js` 里 `PATCH_CONSUME=false` |
| `TypeError: Module.findExportByName is not a function` | Frida 17 删了这个 API。用本仓库最新 `hooks.js`（已改成兼容写法）；自己写的脚本按 §0.5 改 |
| `[JS-ERROR] SyntaxError: unexpected token '=>'` | 换成最新 `hooks.js`（已全改 function 写法）；或命令行加 `--runtime=v8` |
| `[!] 跳过 xxx：RVA 0x… 处字节不匹配` | 你的 kernel.dll 不是 8.1.6.101 那份。跑 `python verify_rva.py --dll <你的kernel.dll>` 确认，并按 docs/05 §3 重新定位 |
| `android`/`java` 之类无关报错 | 与本脚本无关，忽略 |
| 中文乱码 | Windows 控制台默认 GBK。先执行 `chcp 65001`，或用 `--out` 写文件再用编辑器看 |
| 打印量大到卡住 | 只在下 `[trial]` 相关行：`python run.py attach --out a.txt`，之后再 `findstr /C:"[trial]"` |

---

## 6. 安全说明

- `hooks.js` 默认**只读取，不修改**任何行为。
- 唯一的写操作是 `PATCH_CONSUME = true` 时把令牌桶 rate 改大 —— **默认关闭**，仅用于验证"桶就是限速点"。
- 反反调试只把 `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` 的返回值改成 0，
  不改其它检测（TLS 回调、`OutputDebugString` 等原样保留）。
