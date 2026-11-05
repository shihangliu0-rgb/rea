#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
re/frida/tests/smoke.py —— 提交前必须跑的自检（不依赖真机、不依赖 frida 真进程）

它会：
  1. node --check 所有 js（语法）
  2. 把 locate.py 生成的 agent JS 抽出来，用 Node + 假 Frida API **真跑一遍**
     （这一步就是为了拦住 "ReferenceError: 'kernel' is not defined" 这类问题）
  3. 用一个假的 frida 模块 import locate.py / census.py，确认 Python 侧不炸
  4. 校验 hooks.js 的 PROFILES 表能被 verify_rva.py 解析，且对 bin/kernel.dll 全 OK

用法：
  python re/frida/tests/smoke.py
退出码 0 = 全部通过。
"""
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FRIDA_DIR = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(FRIDA_DIR))

fails = []


def shutil_which(x):
    from shutil import which
    return which(x)


def step(name):
    print("\n== %s" % name)


def ok(msg):
    print("   OK  %s" % msg)


def bad(msg):
    print("   FAIL %s" % msg)
    fails.append(msg)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


# ── 1. JS 语法 ────────────────────────────────────────────────────────────
step("1. node --check 所有 js")
for js in ["hooks.js", "selftest.js"]:
    p = os.path.join(FRIDA_DIR, js)
    if not os.path.exists(p):
        bad("%s 不存在" % js)
        continue
    if not shutil_which("node"):
        print("   SKIP 没装 node")
        break
    r = run(["node", "--check", p])
    (ok if r.returncode == 0 else bad)("%s %s" % (js, r.stderr.strip()[:200]))



# ── 2. locate.py 生成的 agent 真跑（假 Frida API） ─────────────────────────
step("2. locate.py agent 用假 Frida API 实跑")
locate_src = open(os.path.join(FRIDA_DIR, "locate.py"), encoding="utf-8").read()
m = re.search(r'AGENT = r"""(.*?)"""', locate_src, re.S)
if not m:
    bad("locate.py 里找不到 AGENT 模板")
else:
    agent = m.group(1)
    if "__CFG__" not in agent or "__MODULE__" not in agent:
        bad("AGENT 模板里缺少 __CFG__/__MODULE__ 占位符")
    # 复刻 locate.py 的拼装方式（必须与源码一致）
    pts = re.findall(r'\("([^"]+)",\s*(0x[0-9A-Fa-f]+),\s*"([^"]+)"', locate_src)
    cfg = [{"name": n, "rva": int(r, 16), "pat": p} for n, r, p in pts]
    body = (agent.replace("__CFG__", json.dumps(cfg))
                 .replace("__MODULE__", json.dumps("kernel.dll"))
                 .replace("__LIMIT__", "400"))

    # 关键断言：模块名必须是带引号的字符串字面量
    if 'var modName = "kernel.dll";' not in body:
        bad('注入后的 JS 里 modName 不是字符串字面量（这就是 ReferenceError 的原因）')
    else:
        ok("模块名以字符串字面量注入")

    if not shutil_which("node"):
        print("   SKIP 没装 node")
    else:
        with tempfile.TemporaryDirectory() as td:
            ap = os.path.join(td, "agent.js")
            open(ap, "w", encoding="utf-8").write(body)
            r = run(["node", "--check", ap])
            (ok if r.returncode == 0 else bad)(
                "生成的 agent 语法合法%s" % ("" if r.returncode == 0 else "：" + r.stderr[:300]))
            harness = os.path.join(HERE, "harness_locate.js")
            r = run(["node", harness, ap])
            tail = "\n".join(r.stdout.strip().splitlines()[-12:])
            (ok if r.returncode == 0 else bad)("假 Frida 实跑：\n%s" % tail)


# ── 2.5 hooks.js 端到端：假 Frida 下真正执行，检查选表 + 12 个 hook ──────
step("2.5 hooks.js 端到端（假 Frida 实跑）")
if not shutil_which("node"):
    print("   SKIP 没装 node")
else:
    hooks_js = os.path.join(FRIDA_DIR, "hooks.js")
    harness = os.path.join(HERE, "harness_hooks.js")
    for size, label in ((0x2B25000, "3.0.20.242（应 12/12 全挂）"),
                        (0x2A3A000, "3.0.20.237（喂 242 字节，应 0/12 全跳过）")):
        r = run(["node", harness, hooks_js, hex(size)])
        tail = "\n".join(r.stdout.strip().splitlines()[:7])
        (ok if r.returncode == 0 else bad)("%s\n%s" % (label, tail))


# ── 3. Python 侧：用假 frida 模块 import ──────────────────────────────────
step("3. Python 脚本可 import（假 frida）")
class FakeMod:
    """最简 frida 桩"""
    __version__ = "17.25.2"

    class _Ptr:
        def __init__(self, v=0):
            self.v = v

    class _Proc:
        def __init__(self, pid, name):
            self.pid = pid
            self.name = name

    class _Script:
        def __init__(self, body=""):
            self.body = body

        def on(self, *a, **k):
            pass

        def load(self):
            pass

    class _Session:
        def create_script(self, body=""):
            return FakeMod._Script(body)

        def detach(self):
            pass

    def get_local_device(self):
        s = FakeMod._Session()

        class Dev:
            def enumerate_processes(self):
                return [FakeMod._Proc(1, "BaiduNetdisk.exe")]

            def attach(self, pid):
                return s

        return Dev()


fake = type(sys)("frida")
for k, v in list(vars(FakeMod).items()):
    if not k.startswith("__"):
        setattr(fake, k, v)
fake.__version__ = FakeMod.__version__
fake._FakeMod = FakeMod
sys.modules["frida"] = fake

for name in ["locate", "census"]:
    p = os.path.join(FRIDA_DIR, name + ".py")
    try:
        src = open(p, encoding="utf-8").read()
        compile(src, p, "exec")
        ok("%s.py 编译通过" % name)
    except Exception as e:
        bad("%s.py 编译失败：%s" % (name, e))

# locate.pick_pid 必须能跑通（假设备里没有 kernel.dll → 返回空，不炸）
sys.path.insert(0, FRIDA_DIR)
try:
    import importlib
    loc = importlib.import_module("locate")
    dev = fake._FakeMod().get_local_device()
    got = loc.pick_pid(dev, "kernel.dll")
    ok("locate.pick_pid 可执行，返回 %r" % (got,))
except Exception as e:
    bad("locate.pick_pid 抛异常：%r" % (e,))


# ── 4. hooks.js 的 PROFILES 能解析，且对样本全 OK ─────────────────────────
step("4. hooks.js PROFILES + verify_rva")
dll = os.path.join(REPO, "bin", "kernel.dll")
verifier = os.path.join(FRIDA_DIR, "verify_rva.py")
if not os.path.exists(dll):
    print("   SKIP 没有 bin/kernel.dll")
else:
    r = run([sys.executable, verifier])
    out = r.stdout + r.stderr
    mm = re.search(r"合计：OK=(\d+)  BAD=(\d+)  MISS=(\d+)", out)
    if not mm:
        bad("verify_rva.py 没有输出合计行：\n%s" % out[-500:])
    else:
        o, b, mi = map(int, mm.groups())
        (ok if (b == 0 and mi == 0 and o >= 12) else bad)(
            "样本 kernel.dll：OK=%d BAD=%d MISS=%d" % (o, b, mi))

    # 242 表：找得到就校验
    for cand, prof in ((os.path.join(REPO, "bin", "kernel.dll"), "3.0.20.242"),):
        if os.path.exists(cand):
            r = run([sys.executable, verifier, "--dll", cand, "--profile", prof,
                     "--js", os.path.join(FRIDA_DIR, "hooks.js")])
            out = r.stdout + r.stderr
            mm = re.search(r"合计：OK=(\d+)  BAD=(\d+)  MISS=(\d+)", out)
            if mm and "%s（" % prof not in out and "RVA 表   : " + prof in out:
                o, b, mi = map(int, mm.groups())
                (ok if (b == 0 and mi == 0 and o >= 12) else bad)(
                    "%s 表：OK=%d BAD=%d MISS=%d" % (prof, o, b, mi))

    # 负例：kernel_o.dll 必须全 BAD
    dll_o = os.path.join(REPO, "bin", "kernel_o.dll")
    if os.path.exists(dll_o):
        r = run([sys.executable, verifier, "--dll", dll_o])
        out = r.stdout
        mm = re.search(r"合计：OK=(\d+)  BAD=(\d+)  MISS=(\d+)", out)
        if mm:
            o, b, mi = map(int, mm.groups())
            (ok if b >= 12 else bad)("负例 kernel_o.dll：OK=%d BAD=%d（应全 BAD）" % (o, b))


# ── 汇总 ─────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
if fails:
    print("失败 %d 项：" % len(fails))
    for f in fails:
        print("  - %s" % f.splitlines()[0])
    sys.exit(1)
print("全部通过 ✅")
