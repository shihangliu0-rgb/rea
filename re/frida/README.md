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

## 4.25 已内置两个内核版本的 RVA 表（不用手改配置）

`hooks.js` 内置两张表，**按 `SizeOfImage` 自动选择**：

| 表 | SizeOfImage | 说明 |
|---|---|---|
| `3.0.20.237` | 0x2a3a000 (42.23MB) | 旧样本 |
| `3.0.20.242` | 0x2b25000 (43.14MB) | **内核热更新版（客户端同为 8.1.6.101）** |

```js
var PROFILE = 'auto';   // 默认自动
```

启动会打印选中的表；遇到全新版本会提示去跑 `rescan.py`。
详见 `docs/10-242版本重定位.md`。

---

## 4.27 12 个 hook 全部挂上，却一条日志都没有

**先敲 `stats()`**（脚本已内置，直接在 frida REPL 里输入）：

```
[Local::PID::28804]-> stats()
---------- hook 命中统计（累计 0 次）----------
  全部为 0 —— 这些函数一次都没被调用。
  → 最可能：客户端当前没有活跃的下载任务。
    在客户端里点一个下载（文件 ≥5 MiB 才会走 P2P 内核路径），
    或者暂停/继续一次已有任务，然后再敲 stats()。
------------------------------------------------------
```

两种情况，含义完全不同：

| `stats()` 结果 | 含义 | 处理 |
|---|---|---|
| 全部 0 | 函数**根本没被调用** | 开始一个真实下载；确认 attach 的是 `baidunetdiskhost.exe` |
| 有计数但没日志 | 被脚本内部的**过滤条件**挡住了 | 见下面的 bug |

### 曾经的真实 bug：`isTokenBucket()` 硬编码 237 的地址

```js
function isTokenBucket(obj, kernelBase) {
    var g = vtableSlot(obj, 1);
    return g.equals(kernelBase.add(0xdb150));   // ← 0xdb150 是 237 的 set_rate
}
```

242 的 `set_rate` 是 **0xdd320**，所以这个判断在 242 上**永远返回 false**：

- `bucket.set_rate` 的 `onEnter` 第一句就是 `if (!isTokenBucket(...)) return;` → 静默返回
- `bucket.consume` 的 `onLeave` 同理 → 静默返回
- `PATCH_RATE` 的写入也不会执行（整段在 `isTokenBucket` 判断里面）

表现就是：**12 个 hook 全部 `[+] hook …` 成功，`安装完成：成功 12 个`，然后一条日志都没有，也不报错。**

现在改成从当前生效的 RVA 表取：

```js
var sr = RVA['bucket.set_rate'];
if (sr === undefined) return false;
return g.equals(kernelBase.add(sr));
```

回归测试断言：源码里不得出现 `add(0xdb150)` / `add(0xdb170)` 这类硬编码。

---

## 4.28 `[!] 跳过 bucket.consume(PATCH)：字节不匹配 实际=e9 bf 44 5e 8d`

**这不是版本问题，是脚本 bug（已修）。**

`e9 xx xx xx xx` 是 `jmp rel32` —— Frida 的 inline hook 跳板。
旧版 `hooks.js` 在 `PATCH_RATE=true` 时对 `bucket.consume` **attach 了两次**：
第一次把函数头改写成 `e9 ...`，第二次再做字节签名校验，读到的自然是跳板而不是
原来的 `53 57 56 89 ce`，于是报"不匹配"并跳过。

现在 PATCH 逻辑合并进同一个 `onEnter`，**不再二次 attach**：

```js
hook(RVA['bucket.consume'], 'bucket.consume', '53 57 56 89 ce',
    function () {
        if (PATCH_RATE) { /* 在这里写 rate */ }
        ...
    }, ...);
```

正确输出：

```
========== 安装完成：成功 12 个，跳过 0 个 ==========
[!] PATCH_RATE 已生效：consume 时把 rate/cap 写成 0x1F400000 (524288000 B/s)
```

回归测试：`tests/smoke.py` 会用 `PATCH_RATE=true` 的副本再跑一遍端到端，
要求同样 `12 成功 / 0 跳过`，并断言**没有地址被 attach 两次**。

---

## 4.29 已经挂满 12 个 hook，屏幕上却还留着"[i] 已注册模块观察者，等 kernel.dll 加载"

**误导性提示，已修。**

旧版启动顺序是"先注册观察者并打印，再处理 onAdded"。如果 `kernel.dll`
**本来就在进程里**（attach 一个已经在下载的 `baidunetdiskhost.exe` 就是这种情况），
观察者回调会立刻触发、12 个 hook 全部挂好，但那句"等 kernel.dll 加载"
已经先打印出去了，永远不会被撤销 —— 看起来就像"明明在 28804 里却还在等"。

现在先判断再打印：

```js
var present = getModule(KERNEL);
if (present) {
    log('[i] kernel.dll 已在进程内 @ ' + present.base + '，直接安装');
    install();          // 不注册观察者，也不打印"等"
} else {
    /* 注册观察者并提示"还没加载，等它出现" */
}
```

正确输出（attach 已加载的进程）：

```
[+] kernel.dll 加载了 @ 0x78100000
[i] 使用 RVA 表: 3.0.20.242（…）
[+] hook set_param …
========== 安装完成：成功 12 个，跳过 0 个 ==========
```

**不会再出现"等 kernel.dll"字样。** 回归测试里有专门断言：
kernel.dll 已加载时，日志中不得出现 `等 kernel.dll 加载` / `已注册模块观察者，等 kernel`。

---

## 4.30 12 个 hook 都挂上了，但只有 2 个有命中（新）

真机 `stats()` 实测（3.0.20.242）：

```
  bucket.set_rate : 208
  bucket.consume : 2665
  从未被调用：set_param, update_max_speed, set_restrict_ratio, calculate_target_speed,
  cdn_speed_limit_dispatch, close_cdn(decided), set_try_speedup_flag, block_gate(pre),
  download_threshold, set_download_restrict_ratio
```

**这不是脚本坏了，是那 10 个点位不在活的调用链上。**
"字节签名在文件里唯一匹配" ≠ "运行时会执行"。用
`python3 re/tools/audit_points.py bin/kernel.dll` 可以把判定依据摊开来看
（函数入口 vs 函数内部 / E8 调用者 / 取地址引用 / set_rate 入参分布）。

注意一个坑：**探针落在别人函数中间时，"E8 调用数 = 0" 是废话**，
它只是说明没人调用那条指令，不能拿来判死。只有"函数入口 + 0 调用 + 0 取地址"才是可疑死代码。

下一步用 `probe2.js` 拿运行时调用栈：

```
frida -p <pid> -l probe2.js
（点下载，等 10~30 秒）
report()          # 总览 + 一行可粘贴摘要
why(16384)        # 谁把速率设成 16384 的完整调用链
buckets()         # 每个令牌桶的 rate/cap
chains()          # 原始样本（带线程号、时序）
boost()           # 强制提速（默认关，唯一写内存的入口，不会重新 attach）
```

### 找到决策者了

真机 `report()` 的调用者排行第一名 `0x19fcf1` = `0x19fcec` 的 `E8` 调用点，
所在函数 **`kernel.dll+0x19fab0`**：

```
0x19fae2  cmp [edx+0xb4], 0        ← +0xb4 限流开关
0x19fce6  push [edx+0xb0]          ← +0xb0 限速值（字节/秒）
0x19fcec  call TokenBucket::set_rate
```

它**没有 E8 调用者 → 是虚函数**。这就是之前静态 xref 追不到上游的原因：
只扫 `E8` 会漏掉 `call [reg+off]`。

`probe2.js` 现在已经挂上这一族三个虚函数（`0x19fab0` / `0x19fd30` / `0x19fd70`），
`report()` 里多了一节"3.5 限速器"，直接给出每个限速器的 `+0xb0` / `+0xb4`。
`boost()` 现在会写 `+0xb0`（仍然不重新 attach）。

详见 `docs/11-242点位复核与调用栈追踪.md` 与 `docs/12-限速决策器定位.md`。

> `boost()` 里那两处写入（`+0x20` = rate、`+8` = cap）是从 `set_rate` 的反汇编确定的：
> `mov [ecx+0x20],eax` / `mov [ecx+8],max(eax,0x4000)`。效果**尚未上真机验证**。

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
| B 活体扫描 | `python locate.py --pid 27568` | 直接输出可粘贴的 `PROFILES` 条目（分页 64KB 扫，不怕大模块） |
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
