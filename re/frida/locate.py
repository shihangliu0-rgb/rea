#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
re/frida/locate.py —— 在**运行中的进程**里重新定位 hooks.js 需要的点位（不用拷 43MB 文件）

适用场景：
  census.py 找到 kernel.dll 在某个 pid 里，但 hooks.js 报"字节不匹配"
  → 说明内核版本不同，RVA 全错位。本脚本直接在活体进程里做 Memory.scan，
    把命中位置换算成 RVA 打印出来，可以立刻拿去替换 hooks.js。

用法：
  python locate.py                       # 自动找唯一有 kernel.dll 的进程
  python locate.py --pid 27568
  python locate.py --module kernel.dll --limit 8

原理：
  用 hooks.js 里那 13 条**函数体特征字节**（不是函数头），在模块的内存镜像里扫。
  命中 0 个 → 这条特征在新版本里也变了，需要用别的锚点（MEM_SCAN 更长模式）。
  命中多个 → 会按"离旧 RVA 最近"排序，并标出候选数，人工确认。

注意：本脚本只**报告**地址，不做 hook，不会影响客户端运行。
"""
import argparse
import sys
import time

try:
    import frida
except ImportError:
    sys.exit("没装 frida：pip install frida")

# (名字, 旧RVA, 特征字节, 说明) —— 与 hooks.js / rescan.py 保持一致
POINTS = [
    ("set_param", 0x1225F0, "55 89 e5 53 57 56 83 ec 2c", "配置下发入口"),
    ("update_max_speed", 0x2DD200, "55 89 e5 53 57 56 83 e4 f8", "更新 max_speed"),
    ("set_restrict_ratio", 0x2DCDE0, "55 89 e5 53 57 56 81 ec", "限速比例"),
    ("calculate_target_speed", 0x2DDB90, "55 89 e5 53 57 56 83 e4 f8", "目标速度"),
    ("bucket.set_rate", 0xDB150, "8b 44 24 04 85 c0", "set_rate"),
    ("bucket.consume", 0xDB170, "53 57 56 89 ce", "consume"),
    ("cdn_speed_limit_dispatch", 0x2ED84E, "8b 0b e8", "CDN 限速调度"),
    ("close_cdn(decided)", 0x1AEB6D, "8b 7d d0 0f af ce", "close cdn 判定"),
    ("set_try_speedup_flag", 0xE2FB0, "55 89 e5 53 57 56 81 ec", "试用提速开关"),
    ("block_gate(pre)", 0x1AFD38, "29 d8 89 86 f0 00 00 00", "块门限"),
    ("download_threshold", 0x1AFFB3, "f2 0f 59 0d", "门限浮点"),
    ("set_download_restrict_ratio", 0x27FEE0, "55 89 e5 53 57 56 81 ec", "下载限速比例"),
]

AGENT = r"""
(function () {
  var cfg = %s;          // [{name, rva, pat, desc}]
  var modName = %s;      // 'kernel.dll'
  var limit = %d;

  var mod = null;
  try { mod = Process.findModuleByName(modName); } catch (e) {}
  if (!mod) {
    send({ type: 'no_module', want: modName,
           have: Process.enumerateModules().map(function (m) { return m.name; }) });
    return;
  }

  var info = { type: 'head', name: mod.name, path: mod.path,
               base: mod.base.toString(), size: mod.size,
               baseAddr: mod.base };
  send(info);

  var start = mod.base;
  var end = mod.base.add(mod.size);
  var out = [];

  for (var i = 0; i < cfg.length; i++) {
    var p = cfg[i];
    var bytes = [];
    var toks = p.pat.split(' ');
    for (var k = 0; k < toks.length; k++) bytes.push(parseInt(toks[k], 16));

    var hits = [];
    var cur = start;
    while (hits.length < limit) {
      var m = Memory.scanSync(cur, end.sub(cur).toInt32(), p.pat)[0];
      if (!m) break;
      hits.push(m.address);
      cur = m.address.add(1);
      if (cur.compare(end) >= 0) break;
    }
    var rvas = [];
    for (var j = 0; j < hits.length; j++) {
      rvas.push(hits[j].sub(mod.base).toInt32());
    }
    out.push({ name: p.name, old: p.rva, hits: rvas, desc: p.desc });
    send({ type: 'point', name: p.name, old: p.rva, hits: rvas });
  }
  send({ type: 'done' });
})();
"""


def pick_pid(dev, module):
    """找唯一含该模块的进程"""
    found = []
    for p in dev.enumerate_processes():
        if not any(k in p.name.lower() for k in ("baidu", "yun", "bd")):
            continue
        try:
            s = dev.attach(p.pid)
            sc = s.create_script(
                "try { send(Process.findModuleByName(%r) ? 1 : 0); } catch(e) { send(-1); }"
                % module)
            box = []
            sc.on("message", lambda m, d: box.append(m.get("payload")))
            sc.load()
            for _ in range(60):
                if box:
                    break
                time.sleep(0.05)
            s.detach()
            if box and box[0] == 1:
                found.append(p)
        except Exception:
            continue
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--module", default="kernel.dll")
    ap.add_argument("--limit", type=int, default=8, help="每个点位最多列几个候选")
    args = ap.parse_args()

    dev = frida.get_local_device()
    pid = args.pid
    if pid is None:
        cands = pick_pid(dev, args.module)
        if not cands:
            sys.exit("没有任何进程加载了 %s（先跑 census.py 看看）" % args.module)
        if len(cands) > 1:
            print("多个进程都有 %s，请用 --pid 指定：" % args.module)
            for p in cands:
                print("   %d  %s" % (p.pid, p.name))
            return 1
        pid = cands[0].pid
        print("选中 pid=%d (%s)" % (pid, cands[0].name))

    session = dev.attach(pid)
    cfg = [{"name": n, "rva": r, "pat": p, "desc": d} for n, r, p, d in POINTS]
    header_box = []
    results = {}
    state = {"done": False, "head": None}

    def on_msg(message, data):
        if message.get("type") != "send":
            if message.get("type") == "error":
                print("[!] 脚本错误:", message.get("description"))
            return
        p = message.get("payload") or {}
        t = p.get("type")
        if t == "head":
            header_box.append(p)
            state["head"] = p
            print("模块：%s" % p["name"])
            print("  路径 = %s" % p.get("path", "?"))
            print("  base = %s   size = 0x%x (%.2fMB)" % (p["base"], p["size"], p["size"] / 1048576))
            print("  参照：hooks.js 目标版本 3.0.20.237，SizeOfImage=0x2a3a000 (42.23MB)")
            if abs(p["size"] - 0x2A3A000) > 0x60000:
                print("  ⚠ 版本不同 → 下面扫出来的 RVA 才是你这台机器上真正可用的\n")
            else:
                print("  ✓ 版本一致 → 扫出来的 RVA 应与 hooks.js 完全相同（用来验证脚本本身）\n")
        elif t == "no_module":
            print("进程里没有 %s。有的模块：" % p["want"])
            print("  " + ", ".join(p["have"][:60]))
        elif t == "done":
            state["done"] = True
        elif t == "point":
            hits = p["hits"]
            results[p["name"]] = {"old": p["old"], "hits": hits}
            print("%-28s 旧=0x%-8x 命中=%d" % (p["name"], p["old"], len(hits)))
            if not hits:
                print("%-28s   ✗ 这条特征在新版本里也没了" % "")
                return
            hits_sorted = sorted(hits, key=lambda r: abs(r - p["old"]))
            for r in hits_sorted[:args.limit]:
                mark = "  ← 最接近旧 RVA" if r == hits_sorted[0] else ""
                print("%-28s   0x%-8x%s" % ("", r, mark))

    script = session.create_script(AGENT % (cfg, args.module, args.limit))
    script.on("message", on_msg)
    script.load()

    # 等 done（on_msg 里已经逐条打印）
    waited = 0.0
    while not state["done"] and waited < 90:
        time.sleep(0.1)
        waited += 0.1
    try:
        session.detach()
    except Exception:
        pass

    if not results:
        print("\n[!] 一条也没扫到 —— 这个进程里的 kernel.dll 可能被加壳/加密，或模块名不对。")
        return 2

    # ── 生成可直接粘贴的 PROFILES 条目 ─────────────────────────────
    head = state["head"] or {}
    size = head.get("size", 0)
    ver = "unknown"
    path = head.get("path", "")
    if path:
        import os as _os
        ver = _os.path.basename((path or "").strip()) or "unknown"

    print()
    print("=" * 78)
    print("把下面这段粘进 hooks.js 的 PROFILES，并把 PROFILE 改成这个 key：")
    print("=" * 78)
    key = "size_0x%x" % size
    print("    '%s': {" % key)
    print("        note: '自动生成，SizeOfImage=0x%x (%.2fMB)'," % (size, size / 1048576.0))
    for name, old, pat, desc in POINTS:
        r = results.get(name)
        if not r or not r["hits"]:
            print("        // '%s': ???  —— 未命中，需手工（%s）" % (name, desc))
            continue
        best = sorted(r["hits"], key=lambda x: abs(x - old))[0]
        warn = "" if len(r["hits"]) == 1 else "   // %d 个候选，请人工确认" % len(r["hits"])
        print("        '%s': 0x%x,%s" % (name, best, warn))
    print("    }")
    print("=" * 78)
    print("粘完后再跑： python verify_rva.py --dll \"<那个 kernel.dll>\" --profile %s" % key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
