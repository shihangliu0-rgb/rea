#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
re/frida/active_pids.py —— 谁在真正下载？（多进程同时采样网络吞吐）

为什么需要它：
  throughput.js 在 PID 28804 上采到 92 秒的数据：
      ws2 收·请求      5.9 KiB 总计，pending 0 次
      ws2 收·完成      0 B
      IOCP 完成      194.7 KiB，18187 次调用（每次平均 11 B = 心跳）
  也就是说 **28804 这个进程一个字节都没主动要过**。
  如果当时下载真的在跑 120 KiB/s，那 92 秒应该收 11 MB —— 它只收了 195 KB。
  → 下载流量在**别的进程**里。

这个脚本同时 attach 所有百度相关进程，每个进程都挂 ws2_32!WSARecv +
kernel32!GetQueuedCompletionStatus，按窗口统计，最后给出排行：
**谁收的字节最多，谁就是在下载。**

用法（Windows，管理员）：
    python active_pids.py                  # 扫百度相关进程，采样 15 秒
    python active_pids.py --seconds 30
    python active_pids.py --all            # 连非百度进程也扫
    python active_pids.py --pid 28804 1234 # 只测指定 pid

判读：
    排行第一的 pid 就是下载进程 → 把 probe2.js / throughput.js 挂到它上面
    所有 pid 吞吐都接近 0 → 下载根本没在跑（或者在别的用户会话）

注意：这是**只读观测**，不修改目标进程任何内存。
"""
import argparse
import sys
import time

try:
    import frida
except ImportError:
    sys.exit("没装 frida：pip install frida")

# 每个进程跑的 agent：只挂导出符号，猜 0 个地址
AGENT = r"""
(function () {
  var C = { recvReq: 0, recvDone: 0, recvPend: 0, iocpDone: 0, iocpCalls: 0 };
  var hooked = [];

  function findExport(modName, sym) {
    try {
      var m = Process.findModuleByName ? Process.findModuleByName(modName)
                                       : Process.getModuleByName(modName);
      if (m) {
        if (m.findExportByName) {
          var a = m.findExportByName(sym);
          if (a) return a;
        }
      }
    } catch (e) { }
    try {
      if (typeof Module !== 'undefined' && Module.findGlobalExportByName) {
        return Module.findGlobalExportByName(sym);
      }
    } catch (e) { }
    return null;
  }

  function sumWsabuf(arr, cnt) {
    var t = 0;
    try {
      var n = cnt > 16 ? 16 : cnt;
      for (var i = 0; i < n; i++) t += arr.add(i * 8).readU32();
    } catch (e) { }
    return t;
  }

  var aRecv = findExport('ws2_32.dll', 'WSARecv');
  if (aRecv) {
    Interceptor.attach(aRecv, {
      onEnter: function (args) {
        this.req = 0;
        try { this.req = sumWsabuf(args[1], args[2].toUInt32()); } catch (e) { }
        C.recvReq += this.req;
      },
      onLeave: function (retval) {
        var r = 0;
        try { r = retval.toInt32(); } catch (e) { }
        if (r === 997) { C.recvPend++; return; }
        if (r === 0) { C.recvDone += this.req; }
      }
    });
    hooked.push('WSARecv');
  }

  var aFrom = findExport('ws2_32.dll', 'WSARecvFrom');
  if (aFrom) {
    try {
      Interceptor.attach(aFrom, {
        onEnter: function (args) {
          try { C.recvReq += sumWsabuf(args[1], args[2].toUInt32()); } catch (e) { }
        }
      });
      hooked.push('WSARecvFrom');
    } catch (e) { }
  }

  var aIocp = findExport('kernel32.dll', 'GetQueuedCompletionStatus');
  if (aIocp) {
    Interceptor.attach(aIocp, {
      onEnter: function (args) { this.nPtr = args[1]; },
      onLeave: function (retval) {
        C.iocpCalls++;
        var ok = 0;
        try { ok = retval.toInt32(); } catch (e) { }
        if (ok) {
          try { C.iocpDone += this.nPtr.readU32(); } catch (e) { }
        }
      }
    });
    hooked.push('IOCP');
  }

  var kern = null, netb = null;
  try {
    var ms = Process.enumerateModules();
    for (var i = 0; i < ms.length; i++) {
      var nm = (ms[i].name || '').toLowerCase();
      if (nm === 'kernel.dll') kern = ms[i].base.toString();
      if (nm === 'netbase.dll') netb = ms[i].base.toString();
    }
  } catch (e) { }

  send({ t: 'init', hooked: hooked, kernel: kern, netbase: netb });

  // Python 侧定时来取快照
  rpc.exports = {
    snap: function () {
      return { recvReq: C.recvReq, recvDone: C.recvDone, recvPend: C.recvPend,
               iocpDone: C.iocpDone, iocpCalls: C.iocpCalls };
    }
  };
})();
"""


def guess_candidates(procs, all_procs):
    if all_procs:
        return [p for p in procs if p.name and not p.name.lower().startswith("svchost")]
    kw = ("baidu", "netdisk", "yun", "bd", "p2p", "dls")
    out = []
    for p in procs:
        n = (p.name or "").lower()
        if not n or n.startswith("svchost"):
            continue
        if any(k in n for k in kw):
            out.append(p)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=15.0, help="采样多少秒（默认 15）")
    ap.add_argument("--window", type=float, default=2000.0, help="每个窗口多少毫秒")
    ap.add_argument("--all", action="store_true", help="连非百度进程也扫")
    ap.add_argument("--pid", type=int, nargs="*", help="只测这些 pid")
    args = ap.parse_args()

    dev = frida.get_local_device()
    all_procs = list(dev.enumerate_processes())

    if args.pid:
        want = set(args.pid)
        targets = [p for p in all_procs if p.pid in want]
        missing = want - {p.pid for p in targets}
        if missing:
            print("找不到这些 pid：%s" % sorted(missing))
    else:
        targets = guess_candidates(all_procs, args.all)

    if not targets:
        print("没有候选进程。先用 python census.py 看看有哪些百度进程。")
        return 1

    print("frida %s | 对 %d 个进程同时采样 %.0f 秒（窗口 %.0f ms）"
          % (getattr(frida, "__version__", "?"), len(targets), args.seconds, args.window))
    print()

    sessions = []      # [(proc, session, script, info)]
    fails = []
    for p in targets:
        try:
            sess = dev.attach(p.pid)
        except Exception as e:
            fails.append((p, "attach 失败: %s" % e))
            continue
        info = {"hooked": [], "kernel": None, "netbase": None}
        try:
            scr = sess.create_script(AGENT)

            def on_msg(message, data, _info=info):
                if message.get("type") == "send":
                    pl = message.get("payload") or {}
                    if pl.get("t") == "init":
                        _info.update(pl)
                elif message.get("type") == "error":
                    _info["error"] = message.get("description")

            scr.on("message", on_msg)
            scr.load()
            sessions.append([p, sess, scr, info])
        except Exception as e:
            fails.append((p, "脚本加载失败: %s" % e))
            try:
                sess.detach()
            except Exception:
                pass

    if not sessions:
        print("一个都没挂上：")
        for p, why in fails:
            print("  pid=%-7d %-26s %s" % (p.pid, p.name, why))
        return 1

    for p, sess, scr, info in sessions:
        note = ""
        if info.get("error"):
            note = "  [错误: %s]" % str(info["error"])[:40]
        print("  挂上 pid=%-7d %-26s hook=%-22s kernel=%s%s"
              % (p.pid, (p.name or "")[:26], ",".join(info.get("hooked") or ["无"]),
                 info.get("kernel") or "-", note))
    for p, why in fails:
        print("  跳过 pid=%-7d %-26s %s" % (p.pid, (p.name or "")[:26], why))
    print()

    # 取基线
    base = {}
    for p, sess, scr, info in sessions:
        try:
            base[p.pid] = scr.exports_sync.snap()
        except Exception as e:
            base[p.pid] = None
            info["error"] = str(e)

    t0 = time.time()
    last_report = 0.0
    win = args.window / 1000.0
    n_win = max(1, int(round(args.seconds / win)))
    print("  开始采样……")
    print("  %-8s %-24s %12s %12s %10s" %
          ("t(s)", "pid/name", "收(请求)", "IOCP", "IOCP次数"))
    print("  " + "-" * 70)

    for w in range(n_win):
        time.sleep(win)
        elapsed = time.time() - t0
        rows = []
        for p, sess, scr, info in sessions:
            b = base.get(p.pid)
            if b is None:
                continue
            try:
                cur = scr.exports_sync.snap()
            except Exception:
                continue
            d_recv = cur["recvReq"] - b["recvReq"]
            d_iocp = cur["iocpDone"] - b["iocpDone"]
            d_calls = cur["iocpCalls"] - b["iocpCalls"]
            base[p.pid] = cur
            rows.append((d_recv, d_iocp, d_calls, p))
        rows.sort(key=lambda x: -(x[0] + x[1]))
        for d_recv, d_iocp, d_calls, p in rows[:6]:
            if d_recv == 0 and d_iocp == 0 and d_calls == 0:
                continue
            print("  %-8.1f %-24s %11.1fK %11.1fK %10d" %
                  (elapsed, ("%d %s" % (p.pid, (p.name or "")[:16]))[:24],
                   d_recv / 1024.0, d_iocp / 1024.0, d_calls))
        last_report = elapsed

    # 收尾：累计排行
    print()
    print("=" * 78)
    print("累计排行（整段采样）")
    print("=" * 78)
    total = []
    for p, sess, scr, info in sessions:
        try:
            cur = scr.exports_sync.snap()
        except Exception:
            continue
        total.append((cur["recvReq"], cur["recvDone"], cur["iocpDone"],
                      cur["iocpCalls"], cur["recvPend"], p, info))
    total.sort(key=lambda x: -(x[0] + x[2]))
    print("%-8s %-24s %12s %12s %10s %8s" %
          ("pid", "name", "收(请求)", "收(完成)", "IOCP", "次数"))
    print("-" * 78)
    for recvReq, recvDone, iocp, calls, pend, p, info in total:
        print("%-8d %-24s %11.1fK %11.1fK %11.1fK %8d" %
              (p.pid, (p.name or "")[:24], recvReq / 1024.0, recvDone / 1024.0,
               iocp / 1024.0, calls))
    print()

    if total:
        top = total[0]
        top_bytes = top[0] + top[2]
        print("★ 下载最可能在：pid=%d  %s  （收请求+收完成 %d B，IOCP %d B）"
              % (top[5].pid, top[5].name, top[0] + top[1], top[2]))
        if top_bytes < 100 * 1024:
            print("  但有吞吐的进程太小（< 100 KiB）—— 说明这段时间**根本没有下载在跑**。")
            print("  请确认：① 下载任务真的在走 ② 采样期间确实在传输 ③ 不是别的用户会话")
        else:
            print("  → 把探针挂到它上面：")
            print("      frida -p %d -l throughput.js" % top[5].pid)
            print("      frida -p %d -l probe2.js" % top[5].pid)

    # 清理
    for p, sess, scr, info in sessions:
        try:
            sess.detach()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
