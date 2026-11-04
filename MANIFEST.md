# BN_RE 取证包清单（百度网盘客户端逆向工程）

> 来源：`D:\Wang_Pan\BaiduNetdisk`（安装目录，v8.1.6.101）与 `%APPDATA%\BaiduYunKernel`（运行时配置/日志）  
> 方式：**复制**（原目录未做任何修改）  
> 规模：33 个文件，127.0 MB

## 目录结构

```
bn_re/
├─ bin/          # 可执行体：内核、业务层、网络栈、测速、边缘 Agent
├─ config/       # 客户端配置 + 账号数据 + 内核运行时配置（多数加密）
├─ resources/    # resources.pri 资源索引
├─ logs/         # 内核日志样本（加密/压缩）
└─ MANIFEST.md   # 本文件
```

## 文件清单

| 文件 | 大小 | SHA-256（前 16） | 用途 |
|---|---:|---|---|
| `bin\BaiduNetdisk.exe` | 7.91 MB | `E48932EFEFF25773` | 主程序（UI/浏览器壳）：任务列表、设置项、提速提示文案与状态机 |
| `bin\Bull140U.dll` | 3.18 MB | `3DAA8281CF443083` | BULL UI 框架核心：YunDls/YunLogic 的导入依赖，解析其 COM 接口所需 |
| `bin\KernelCom.dll` | 2.19 MB | `EC379E37E9C76A8F` | 边缘计算 Agent（bifrost-edge-computing-agent）：另一条下载/加速通道 |
| `bin\YunDls.dll` | 2.20 MB | `5ADFEC70A821A7F2` | 下载业务层：任务模型、设置持久化、与内核的 COM/接口调用边界 |
| `bin\YunLogic.dll` | 4.12 MB | `7D9399AF1E3B3407` | 逻辑层：内嵌客户端配置模板（speedup/vip_experience/p2pspeedup 阈值） |
| `bin\channelpcsdk.dll` | 399.0 KB | `5718F62DCE7CA033` | PCS 通道 SDK：取链/通道相关逻辑 |
| `bin\kernel.dll` | 42.12 MB | `E8C6EB9BDBE9BCC1` | 核心下载内核（p2p-sdk-pc v3.0.20.237）：限速器/调度/令牌/取链解析，本次主战场 |
| `bin\kernel_btsdk.dll` | 4.23 MB | `8CF4988EB5A4A5BC` | BT 下载 SDK（btsdk）：BT 任务的限速与调度路径 |
| `bin\kernel_o.dll` | 41.89 MB | `7AE2E25F867B7B3A` | 旧版内核备份：与 kernel.dll 做二进制 diff，定位策略新增与阈值变更 |
| `bin\netbase.dll` | 11.89 MB | `6AA2482741CFCFF9` | Cronet 145 网络栈（Chromium）：WebUI 与页面侧请求，含 CMS/更新等 |
| `bin\speedtest.dll` | 5.63 MB | `6B55DE07A34E6855` | 独立测速 SDK（46 个导出）：为 max_speed 提供输入 |
| `config\AppConfig.ini` | 0.0 KB | `B1DDC8B46A6CA466` | 启动配置（明文） |
| `config\AppProperty.xml` | 0.0 KB | `843A030382CE1229` | 应用属性（明文） |
| `config\AppSettingApp.dat` | 50.0 KB | `85C21BCB5B74EDBE` | 应用设置（加密）：下载/限速偏好所在 |
| `config\VersionInfo` | 0.2 KB | `43545CA2971E9AD7` | 版本信息（加密） |
| `config\VersionInfo2` | 0.2 KB | `BA00CA363B6FC7E8` | 版本信息副本（加密） |
| `config\crossdomain.dat` | 7.3 KB | `C9661AE33C1B0A37` | 跨域策略数据 |
| `config\install.log` | 861.3 KB | `CCDE0A28FCB1FD2C` | 安装日志：组件清单、版本号、升级历史（明文） |
| `config\kernel_download.s3dbe` | 3.0 KB | `54438BBF1508BA82` | 下载状态库（加密） |
| `config\kernel_kernelb.cfg` | 3.3 KB | `55C30415CF39EC4D` | 内核运行时配置（加密）：限速/CMS 相关开关 |
| `config\kernel_pop` | 0.4 KB | `66444C32304BF2F4` | POP 节点配置（加密） |
| `config\resource.db` | 154.0 KB | `E2BE981EE8B46757` | 资源索引库 |
| `config\users\3392342571c1267308ff27d7ee5e212d\BaiduYunGuanjia.db` | 56.0 KB | `A50ADDE8DA69B072` | 账号/本地数据（加密） |
| `config\users\3392342571c1267308ff27d7ee5e212d\PersonalSetting.xml` | 17.9 KB | `258370BD94C343D8` | 账号/本地数据（加密） |
| `config\users\3392342571c1267308ff27d7ee5e212d\PersonalSetting.xml.bak` | 17.9 KB | `258370BD94C343D8` | 账号/本地数据（加密） |
| `config\users\3392342571c1267308ff27d7ee5e212d\localdata.dat` | 0.2 KB | `F3DD6F8132AD7F82` | 账号/本地数据（加密） |
| `config\users\BaiduNetdiskData.dat` | 3.2 KB | `94F3670BCBFA44B9` | 账号级数据（加密） |
| `config\users\ProxySetting.ini` | 0.1 KB | `A181B2AA21FA1D1D` | 代理设置（明文） |
| `config\users\localdata.dat` | 4.0 KB | `B708742C0DFA2989` | 本地数据（加密） |
| `config\users\temp2.data` | 3.6 KB | `E4F97322F952D9D1` | 临时数据（加密） |
| `logs\BaiduKernel_20261028040309_641_1.log` | 2.1 KB | `340285101F7B365C` | （见说明） |
| `logs\BaiduKernel_20261119200054_937_1.log` | 49.3 KB | `24A2341EE8F7AACD` | （见说明） |
| `resources\resources.pri` | 4.9 KB | `D44E31DCE3EB2A37` | WinUI 资源索引：界面文案（限速/提速提示） |

## 没有复制的东西（以及为什么）

| 对象 | 大小 | 不复制的原因 |
|---|---:|---|
| `libcef.dll` / `icudtl.dat` / `pepflashplayer.dll` | ~130 MB | Chromium 浏览器引擎，与下载/限速无关 |
| `module\ImageViewer`（含 rawengine 相机配置） | ~900 MB | 看图模块资源，无关 |
| `module\SpeechSDK` / `VastPlayer` | — | 语音/播放器模块，无关 |
| `browserres\*.pak` | 5.7 MB | CEF 本地化资源包，不含业务逻辑 |
| `sysres\*.msix` / `AIAssets` / `Assets` | 6.3 MB | 安装包与图标 |
| `sysres\YunShell*.dll` | 4.5 MB | 资源管理器扩展，无关 |
| `%APPDATA%\BaiduYunKernel\Config\indexb.s3dbs` | 5.6 MB | 文件索引库，无关 |
| 其余 `BaiduKernel_*.log`（约 9 个 × 8 MB） | ~75 MB | 已保留 2 个样本，内容加密，多份无增量信息 |
| `%APPDATA%\BaiduNetdisk\Network\Cookies` 等 | — | 含账号凭据，**不复制**（隐私） |

## 缺失但关键的材料（决定逆向能做到多深）

| 材料 | 状态 | 影响 |
|---|---|---|
| PDB 符号 | **未随安装包提供**（仅内嵌 PDB 路径） | 函数名/结构体需靠 RTTI + 手工恢复；这是本次最大的成本项 |
| 源码 | 无 | 只能反编译，变量名/注释丢失 |
| 明文日志 | 日志已加密/压缩 | 动态验证需先解密，或改用 Frida 打点 |
| 网络抓包 | 未提供 | 需自行用 mitmproxy/Fiddler 抓自己的流量（仅分析本人账号） |

## 完整性自检

```text
bin\kernel.dll: MATCH (E8C6EB9BDBE9BCC1)
bin\BaiduNetdisk.exe: MATCH (E48932EFEFF25773)
bin\netbase.dll: MATCH (6AA2482741CFCFF9)
```