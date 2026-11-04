#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
re/frida/census.py —— 找出"哪个进程里才有 kernel.dll"

为什么需要它：
  百度网盘是多进程结构。下载内核 kernel.dll 只加载在**某一个**进程里，
  你如果 attach 错了进程，就会一直"等 kernel.dll"。
  这个脚本把本机所有百度相关进程挨个 attach，列出关键模块，做成一张表。

用法（Windows，管理员）：
  python census.py
  python census.py --all          # 连非百度进程也扫（慢，一般不需要）

输出示例：
  pid     name                      kernel.dll   kernel_btsdk   YunDls  YunLogic  netbase  模块数
  27668   BaiduNetdisk.exe          0x5a3c0000   -              有      有        有       118
  4120    YunUtilityService.exe     -            -              -       -         -        22
"""
import argparse
import sys
import time

try:
    import frida
except ImportError:
    sys.exit("没装 frida：pip install frida")

# 想看的模块（不含路径，大小写不敏感）
WATCH = ["kernel.dll", "kernel_btsdk.dll", "kernel_o.dll",
         "YunDls.dll", "YunLogic.dll", "netbase.dll", "KernelCom.dll",
         "channelpcsdk.dll", "speedtest.dll", "Bull140U.dll"]

AGENT = r"""
(function () {
  var watch = %s;
  var out = { modules: {}, count: 0, names: [] };
  try {
    var mods = Process.enumerateModules();
    out.count = mods.length;
    for (var i = 0; i < mods.length; i++) {
      var n = (mods[i].name || '').toLowerCase();
      out.names.push(mods[i].name);
      for (var j = 0; j < watch.length; j++) {
        if (n === watch[j].toLowerCase()) {
          out.modules[mods[i].name] = mods[i].base.toString() +
            ' (' + (mods[i].size / 1048576).toFixed(1) + 'MB)';
        }
      }
    }
  } catch (e) {
    out.error = '' + e;
  }
  send(out);
})();
"""


def scan(frida, dev, proc, timeout=6.0):
    """attach 到进程并取模块清单；失败返回 {'error': ...}"""
    try:
        session = dev.attach(proc.pid)
    except Exception as e:
        return {"error": "attach 失败: %s" % e}

    result = {}
    try:
        script = session.create_script(AGENT % (WATCH,))
        box = []

        def on_msg(message, data):
            if message.get("type") == "send":
                box.append(message.get("payload"))
            elif message.get("type") == "error":
                box.append({"error": str(message.get("description"))})

        script.on("message", on_msg)
        script.load()
        deadline = time.time() + timeout
        while time.time() < deadline and not box:
            time.sleep(0.05)
        result = box[0] if box else {"error": "超时（进程可能挂起或受保护）"}
    except Exception as e:
        result = {"error": "脚本失败: %s" % e}
    finally:
        try:
            session.detach()
        except Exception:
            pass
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="连非百度进程也扫")

    ap.add_argument("--timeout", type=float, default=6.0)
    args = ap.parse_args()

    frida_version = getattr(frida, "__version__", "?")
    dev = frida.get_local_device()
    procs = list(dev.enumerate_processes())

    if not args.all:
        kw = ("baidu", "netdisk", "yun", "bd")
        procs = [p for p in procs if any(k in p.name.lower() for k in kw)]
    # 过滤系统噪音
    procs = [p for p in procs if p.name and not p.name.lower().startswith("svchost")]

    if not procs:
        print("没找到候选进程。先确认百度网盘在运行。")
        return 1

    print("frida %s  |  扫描 %d 个进程（每个最多 %.0f 秒）\n" % (frida_version, len(procs), args.timeout))
    header = "%-7s %-26s %-13s %-13s %-7s %-9s %-9s %s" % (
        "pid", "name", "kernel.dll", "kernel_btsdk", "YunDls", "YunLogic", "netbase", "模块数")
    print(header)
    print("-" * len(header))

    found = []
    for p in procs:
        r = scan(frida, dev, p, args.timeout)
        if "error" in r:
            print("%-7d %-26s  ! %s" % (p.pid, p.name[:26], r["error"][:60]))
            continue
        mods = r.get("modules", {})

        def cell(name):
            for k, v in mods.items():
                if k.lower() == name.lower():
                    return v.split(" ")[0] or "有"
            return "-"

        print("%-7d %-26s %-13s %-13s %-7s %-9s %-9s %d" % (
            p.pid, p.name[:26],
            cell("kernel.dll"), cell("kernel_btsdk.dll"),
            "有" if cell("YunDls.dll") != "-" else "-",
            "有" if cell("YunLogic.dll") != "-" else "-",
            "有" if cell("netbase.dll") != "-" else "-",
            r.get("count", 0)))

        if cell("kernel.dll") != "-":
            found.append((p, mods))

    print()
    if found:
        print("=" * 78)
        for p, mods in found:
            print("★ 下载内核在：pid=%d  %s" % (p.pid, p.name))
            for k in sorted(mods):
                print("     %-22s %s" % (k, mods[k]))
            print("   挂上去： python run.py attach --pid %d" % p.pid)
        print("=" * 78)
    else:
        print("=" * 78)
        print("所有进程里都没有 kernel.dll。可能原因（按概率排序）：")
        print("  1) 还没开始真正的下载（HTTP 直连/CDN 也会用内核，但要先有下载任务）")
        print("  2) 客户端是 8.x 的另一条支线，下载内核叫别的名字")
        print("     → 用 --match kernel 看有没有 kernel_btsdk.dll 之类")
        print("  3) 服务端把 P2P 关了（日志里有 enbale_qingluan_netdisk_p2p=0）")
        print("  4) 进程被保护，attach 不上（上面的 ! 行）")
        print("=" * 78)

    return 0 if found else 2


if __name__ == "__main__":
    sys.exit(main())
