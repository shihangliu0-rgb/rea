# 08 · 复核：`kernel.dll` 到底在哪里、由谁加载

> 起因：用户按 `hooks.js` 跑，一直"等 kernel.dll"；任务管理器里也翻不到。
> 于是**不再猜**，把仓库里所有相关证据重新过一遍。
> 这一节记录：哪些结论成立、哪些是我之前**没有证据就下了判断**、缺什么证据。

---

## 1. 已证实的事实（可复现）

### 1.1 `BaiduNetdisk.exe` 是**唯一**提到 `kernel.dll` 的模块 ✅

对 `bin/` 下 10 个 PE 做 ASCII + UTF-16LE 双编码搜索 `kernel.dll`：

| 文件 | ascii | utf-16le |
|---|---|---|
| `BaiduNetdisk.exe` | 0 | **1** |
| `YunDls.dll` | 0 | 0 |
| `YunLogic.dll` | 0 | 0 |
| `KernelCom.dll` | 0 | 0 |
| `channelpcsdk.dll` | 0 | 0 |
| 其余 5 个 | 0 | 0 |

而且它出现在一串 **"受信任/需验签模块白名单"** 里（`0x2df57c`，UTF-16LE）：

```
… 'AutoUpdate\\AutoUpdateUtil.dll' 'AutoUpdate\\Autoupdate.exe'
   'kernel.dll'  '签名无效 %s'  'enable_clear_no_sign_module'  'kernel_o.dll'
   'module\\BrowserEngine' …
```

**结论**：`kernel.dll` 是被 `BaiduNetdisk.exe` **运行时按需加载**的，
并且加载时要做签名校验；`enable_clear_no_sign_module` 是"签名无效就清掉别加载"的开关。✅

### 1.2 没有任何 PE 静态依赖 `kernel.dll` ✅

`re/out/imports_map.json` + 重新解析的导入表（含 DELAY_IMPORT）：

| 模块 | 导入数 | 是否 import/延迟导入 kernel.dll |
|---|---:|---|
| `BaiduNetdisk.exe` | 41 个 DLL | **否** |
| `YunDls.dll` | 29 个 DLL | **否**（无 delay import 表） |
| `YunLogic.dll` | — | 否 |
| `KernelCom.dll` | 8 个 DLL | 否 |

而且 `BaiduNetdisk.exe` 里 `LoadLibraryExW` / `LoadLibraryW` / `LoadLibraryA` / `GetProcAddress`
各只出现 **1~2 次**（导入表里的名字），**没有找到任何拼接路径或完整路径字符串**。

**所以"是谁、在什么时机调 LoadLibrary"这一层，我没有直接证据。** ⚪

### 1.3 `kernel.png` 不存在，但 `kernel` 这个名字确实在跑

解密日志表头是 `{Kernel}`、`{serverProxy}`、`{uTP}`、`{netio}`、`{Task}`、`{upload}` ——
这些都是 **`kernel.dll` 内部自己注册的模组名**，文件名叫 `BaiduKernel_*.log`。
日志线程 id：`27668`（主）、`24656`（uTP 定时器）等 —— **同一进程内的多线程**，
而不是多个进程。

日志首行（`20:00:54`）就是 `{Kernel} on_recv … type=p2p_log`，说明内核在这个会话开始时**已经在跑**。

### 1.4 内核确实有"要不要开 P2P"的开关 ✅

```
{serverProxy} enable_p2p:132 upload_flag=0|enbale_qingluan_netdisk_p2p=0|has_user_uploading_task=0|
```

（`enbale_…` 是源码里的拼写错误，原样引用。）
**`enbale_qingluan_netdisk_p2p=0`** —— 这个会话里 P2P 通道是**关闭**的。

---

## 2. 我之前说错/说过头的地方（自我更正）

| 我之前说 | 问题 | 更正 |
|---|---|---|
| "`kernel.dll` 只在真正开始 P2P 下载时才加载" | **没有证据**。日志首行内核就已启动；而且 HTTP/CDN 下载也走同一个内核 | 只能说"按需加载"，**不能**断言必须点下载才加载 ⚪ |
| "看 `YunDls.dll` 有没有加载就知道初始化到哪一步" | `YunDls.dll` 是 exe 静态导入的（41 个导入之一），**一启动就在** | 它不能作为进度指标，但可以作为"模块观察者是否工作"的对照物 |
| "肯定是多进程，下载在别的 pid" | 日志里全是同进程多线程；`BaiduNetdiskHost.exe` / `bddownloader` 之类的字符串在 exe 里**搜不到** | **不确定**。可能存在多进程，但我没有证据 ⚪ |

唯一的旁证：`BaiduNetdisk.exe` 里有 `%s\YunUtilityService.exe` / `YunUtilityServiceV2.exe`
（"启动唤起服务进程失败：0X%X"），说明**确实有至少一个辅助进程**，但它跟下载内核有没有关系，不清楚。

---

## 3. 那么"一直等 kernel.dll"到底可能是什么

按"能被测量"的顺序列，每条都给出**怎么验证**：

| # | 可能原因 | 怎么验证 | 现状 |
|---|---|---|---|
| 1 | **attach 的进程不对**（下载内核在另一个 pid） | `python re/frida/census.py` —— 把所有百度进程挨个扫一遍，列出谁有 `kernel.dll` | 未测 ⚪ |
| 2 | **模块名不是 `kernel.dll`**（同一功能的另一条支线） | `census.py` 的 WATCH 列表里含 `kernel_btsdk.dll` / `kernel_o.dll`；也可以 `--all` 扫全部进程 | 未测 ⚪ |
| 3 | 你装的**不是 8.1.6.101**，文件名不同 | `python re/frida/verify_rva.py --dll "你的\kernel.dll"`（先确认文件存在） | 未测 ⚪ |
| 4 | Frida **在 32 位进程里看不到模块列表** | `selftest.js` 的 `modules = N` 一行；如果 N 很小或报错，就是这个 | 未测 ⚪ |
| 5 | 客户端把下载内核加载进**子进程/受保护进程** | `census.py` 里出现 `! attach 失败` | 未测 ⚪ |
| 6 | 模块确实在，但 `Process.findModuleByName` 大小写/后缀没匹配上 | `census.py` 会打印真实模块名，对一眼就知道 | 未测 ⚪ |

> 注意：`hooks.js` 里 `getModule()` 用的是 `Process.findModuleByName('kernel.dll')`，
> 这是**大小写不敏感**的（Frida 内部按 basename 比对），所以 6 的概率低 —— 但也只有实测能排除。

---

## 4. 现在该做的唯一一件事

在**客户端已经开着、并且正在下载**的状态下，另开一个管理员 cmd：

```bat
cd /d <仓库>\re\frida
python census.py
```

它会输出一张表（示例）：

```
frida 17.25.2  |  扫描 3 个进程

pid     name                       kernel.dll   kernel_btsdk  YunDls  YunLogic  netbase  模块数
27668   BaiduNetdisk.exe           0x5a3c0000   -             有      有        有       118
4120    YunUtilityService.exe      -            -             -       -         -        22

★ 下载内核在：pid=27668  BaiduNetdisk.exe
      kernel.dll    0x5a3c0000 (42.1MB)
   挂上去： python run.py attach --pid 27668
```

三种结果对应三条路：

- **表里某一行的 `kernel.dll` 有地址** → 之前 attach 错进程了。用表里给出的 `--pid` 重跑。
- **有 `kernel_btsdk.dll` 但没有 `kernel.dll`** → 你这一版走的是另一条内核支线，
  `hooks.js` 的 RVA 不适用，需要按 `docs/05 §3` 重新定位。
- **全都没有** → 把这张表的截图给我；这时才需要怀疑"内核根本没被加载"，
  我会改用 `LoadLibraryExW` 断点 + `GetProcAddress` 反查的方式定位它。

---

## 5. 交付物

| 文件 | 作用 |
|---|---|
| `re/frida/census.py` | 多进程模块普查，直接给出该 attach 哪个 pid |
| `re/frida/verify_rva.py` | 离线核对 RVA/签名，确认版本 |
| `re/frida/hooks.js` | 诊断里的提示已按本文更正（不再断言"必须点下载"） |
