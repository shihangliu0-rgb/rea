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
import json
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
  var cfg = __CFG__;        // [{name, rva, pat, desc}]
  var modName = __MODULE__; // 'kernel.dll'
  var limit = __LIMIT__;

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
  var modSize = mod.size;
  var PAGE = 0x10000;              // 64KB 一页：Frida 的 range 上限很小，不能一次扫 43MB

  for (var i = 0; i < cfg.length; i++) {
    var p = cfg[i];
    var hits = [];
    var refuse = 0;                // 被拒绝的页数
    var scannedBytes = 0;
    var nextBeat = 8 * 1024 * 1024;

    for (var off = 0; off < modSize && hits.length < limit; off += PAGE) {
      var len = Math.min(PAGE, modSize - off);
      var base0 = start.add(off);
      var found;
      try {
        found = Memory.scanSync(base0, len, p.pat);
      } catch (e) {
        refuse++;
        scannedBytes += len;
        continue;
      }
      if (found && found.length) {
        for (var q = 0; q < found.length && hits.length < limit; q++) {
          var rva = found[q].address.sub(mod.base).toInt32();
          var before = '';
          try {
            var back = found[q].address.sub(8);
            if (back.compare(mod.base) >= 0) {
              before = hexdump(back, { length: 8, header: false, ansi: false });
              before = before.split('\n')[0].replace(/^[0-9a-f]+\s+/, '').trim();
            }
          } catch (e2) { before = '?'; }
          hits.push({ rva: rva, before: before });
        }
      }
      scannedBytes += len;
      if (scannedBytes >= nextBeat) {
        send({ type: 'progress', name: p.name, rva: scannedBytes, size: modSize });
        nextBeat += 8 * 1024 * 1024;
      }
    }

    send({ type: 'point', name: p.name, old: p.rva, hits: hits,
           desc: p.desc, refuse: refuse,
           pages: Math.ceil(modSize / PAGE) });
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
    ap.add_argument("--show", type=int, default=8, help="每个点位最多显示几个候选")
    ap.add_argument("--limit", type=int, default=400,
                    help="每个点位最多收集多少命中（短签名会命中很多处，默认 400）")
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
                print("[!] 脚本错误:", message.get("description"), flush=True)
                state["done"] = True      # 出错就别再等了
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
        elif t == "progress":
            print("  … 正在扫 0x%x / 0x%x" % (p["rva"], p["size"]), flush=True)
        elif t == "point":
            hits = p["hits"]
            results[p["name"]] = {"old": p["old"], "hits": hits}
            print("%-28s 旧=0x%-8x 命中=%d%s"
                  % (p["name"], p["old"], len(hits),
                     "  (扫描被拒绝)" if p.get("stuck") else ""), flush=True)
            if not hits:
                print("%-28s   ✗ 这条特征在新版本里也没了" % "")
            hits_sorted = sorted(hits, key=lambda h: abs(h["rva"] - p["old"]))
            for i, h in enumerate(hits_sorted[:args.show]):
                mark = "  ← 最接近旧 RVA" if i == 0 else ""
                print("%-28s   0x%-8x  前8字节: %s%s"
                      % ("", h["rva"], (h.get("before") or "?")[:32], mark))

    body = (AGENT.replace('__CFG__', json.dumps(cfg, ensure_ascii=False))
                 .replace('__MODULE__', json.dumps(args.module))
                 .replace('__LIMIT__', str(int(args.limit))))
    # 自检：生成出来的 JS 必须是合法 JS（上一次就是这里没检查 → ReferenceError）
    try:
        import subprocess
        subprocess.run(['node', '--check', '-'], input=body.encode('utf-8'),
                       check=True, capture_output=True)
    except FileNotFoundError:
        pass          # 没装 node 就跳过，不影响运行
    except subprocess.CalledProcessError as e:
        sys.exit("生成的 JS 语法错误（这不该发生，请把下面内容反馈）：\n%s\n%s"
                 % (e.stderr.decode('utf-8', 'replace')[:800], body[:800]))

    script = session.create_script(body)
    script.on("message", on_msg)
    try:
        script.load()
    except Exception as e:
        sys.exit("[!] 注入失败：%s" % e)
    print("[i] 脚本已注入，开始扫描（每个点位都要扫一遍 43MB，约 10-60 秒）", flush=True)

    # 等 done（on_msg 里已经逐条打印）
    waited = 0.0
    try:
        while not state["done"] and waited < 90:
            time.sleep(0.1)
            waited += 0.1
            if abs(waited - round(waited)) < 1e-9 and int(waited) % 10 == 0 and int(waited) > 0:
                print("  …已等 %ds / 90s（模块越大约慢，正常）" % int(waited), flush=True)
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
        state["done"] = True
    try:
        session.detach()
    except Exception:
        pass

    if not results:
        print("\n[!] 一条也没扫到 —— 这个进程里的 kernel.dll 可能被加壳/加密，或模块名不对。")
        return 2

    total_refuse = sum(r.get("refuse", 0) for r in results.values())
    if total_refuse and all((not r["hits"]) for r in results.values()):
        print()
        print("!" * 78)
        print("扫描基本全被拒绝（%d 次）—— 这不是「特征没了」，是**脚本读不了这块内存**。" % total_refuse)
        print("常见原因：")
        print("  1) 这个 kernel.dll 被保护（VMProtect/Themida/页属性 PGUARD）")
        print("  2) 客户端是 32 位但宿主进程有反注入（attach 成功但 Memory.scan 被拦）")
        print("  3) 权限不足 —— 用管理员身份运行 cmd 再试")
        print("下一步：换**离线**路线，不碰进程：")
        print('  python rescan.py --dll "D:\\Wang_Pan\\BaiduNetdisk\\kernel.dll"')
        print("!" * 78)
        return 3

    # ── 生成可直接粘贴的 PROFILES 条目 ─────────────────────────────
    head = state["head"] or {}
    size = head.get("size", 0)
    path = head.get("path", "")
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
            why = "内存读不了" if (r and r.get("refuse")) else "未命中"
            print("        // '%s': ???  —— %s，需手工（%s）" % (name, why, desc))
            continue
        best = sorted(r["hits"], key=lambda h: abs(h["rva"] - old))[0]["rva"]
        warn = "" if len(r["hits"]) == 1 else "   // %d 个候选，请人工确认" % len(r["hits"])
        print("        '%s': 0x%x,%s" % (name, best, warn))
    print("    }")
    print("=" * 78)
    print("粘完后再跑： python verify_rva.py --dll \"<那个 kernel.dll>\" --profile %s" % key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
