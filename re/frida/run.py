#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
re/frida/run.py —— 不用 `frida` 命令也能跑 hooks.js（纯 Python API）

为什么需要它：`pip install frida` 只装 **Python 绑定**，**不含** 命令行工具。
`frida` / `frida-ps` / `frida-trace` 这些命令在另一个包里：`frida-tools`。

用法（在 Windows 上，用**管理员**命令提示符）：

  # 1) 让脚本自己启动客户端（推荐，能抓到启动期的调用）
  python run.py spawn

  # 2) 客户端已经在跑，直接挂上去
  python run.py attach
  python run.py attach --name BaiduNetdisk.exe
  python run.py attach --pid 12345

  # 3) 只检查环境（Frida 版本 / 目标位数 / 模块是否加载）
  python run.py check

  # 4) 打印所有输出到文件（默认同时也打印到屏幕）
  python run.py spawn --out trial_log.txt

按 Ctrl-C 结束；spawn 模式下 Ctrl-C 会顺带把客户端 detach（不杀进程）。
"""

import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "hooks.js")

# 默认路径；用 --exe 覆盖
DEFAULT_EXE = r"C:\Program Files\Baidu\BaiduNetdisk\BaiduNetdisk.exe"
FALLBACK_EXES = [
    r"C:\Program Files (x86)\Baidu\BaiduNetdisk\BaiduNetdisk.exe",
    r"D:\Program Files\Baidu\BaiduNetdisk\BaiduNetdisk.exe",
]


def die(msg):
    print("[x] " + msg)
    sys.exit(1)


def load_frida():
    try:
        import frida
    except ImportError:
        die(
            "没装 frida 的 Python 包。请先执行：\n"
            "    pip install frida frida-tools\n"
            "（frida = Python 绑定；frida-tools = 命令行工具，装了才有 `frida` 命令）"
        )
        return None
    return frida


def on_message(message, data):
    """Frida 的 console.log 走 send 通道；异常走 error"""
    if message.get("type") == "error":
        print("[JS-ERROR] " + str(message.get("description") or message))
        stack = message.get("stack") or ""
        for line in stack.splitlines()[:6]:
            print("           " + line)
        return
    if message.get("type") == "send":
        payload = message.get("payload")
        # hooks.js 若开了 SEND_DUP，这里去重：console.log 已经打过了
        if isinstance(payload, dict) and payload.get("tag") == "log":
            return
        print(payload)
        return
    print("[msg] " + str(message))


def cmd_check(frida, args):
    print("frida python 版本 :", frida.__version__)
    print("CPU 架构          :", os.environ.get("PROCESSOR_ARCHITECTURE", "?"))
    print("hooks.js          :", "OK" if os.path.exists(SCRIPT) else "缺失！" + SCRIPT)
    for extra in ("run.py", "selftest.js", "dump_ps.py"):
        p = os.path.join(HERE, extra)
        print("%-18s" % (extra + " :"), "OK" if os.path.exists(p) else "缺失")
    try:
        dev = frida.get_local_device()
        print("本地设备          :", dev)
    except Exception as e:
        die("拿不到本地设备（多半是权限/杀软）：%s" % e)
    procs = [p for p in dev.enumerate_processes() if "baidu" in p.name.lower()
             or "netdisk" in p.name.lower()]
    if procs:
        print("已在运行的百度进程：")
        for p in procs:
            print("   pid=%-6d %s" % (p.pid, p.name))
        # 顺手看看第一个进程里有没有 kernel.dll
        try:
            session = frida.attach(procs[0].pid)
            src = ("var m=Process.findModuleByName?Process.findModuleByName('kernel.dll'):null;"
                   "send(m?m.base.toString():'kernel.dll 未加载');")
            sc = session.create_script(src)
            got = []
            sc.on("message", lambda m, d: got.append(m.get("payload")))
            sc.load()
            import time as _t
            for _ in range(20):
                if got:
                    break
                _t.sleep(0.05)
            print("   kernel.dll : %s" % (got[0] if got else "查询超时"))
            session.detach()
        except Exception as e:
            print("   (无法查询 kernel.dll：%s)" % e)
    else:
        print("当前没有百度网盘进程在跑（spawn 模式没关系）")


def find_exe(args):
    if args.exe:
        if not os.path.exists(args.exe):
            die("找不到可执行文件：" + args.exe)
        return args.exe
    for p in [DEFAULT_EXE] + FALLBACK_EXES:
        if os.path.exists(p):
            return p
    die("没找到 BaiduNetdisk.exe，请用 --exe 指定，例如：\n"
        r'    python run.py spawn --exe "D:\BaiduNetdisk\BaiduNetdisk.exe"')


def run(frida, pid_or_name, source, args, resume_pid=None):
    session = frida.attach(pid_or_name)

    # Frida 17 起默认就是 V8（也能跑 QJS 写法）；旧版本显式指定 v8 更稳。
    # 这里做降级：v8 不可用就退回默认运行时。
    try:
        script = session.create_script(source, runtime="v8")
    except Exception as e:
        print("[i] v8 运行时不可用，改用默认运行时：%s" % e)
        script = session.create_script(source)

    script.on("message", on_message)

    def on_detached(reason, *rest):
        print("[!] 目标已断开：" + str(reason))

    session.on("detached", on_detached)
    script.load()
    print("[+] 脚本已注入")

    if resume_pid is not None:
        # Frida 17 的 device.spawn() 默认不再自动恢复主线程（--no-pause 已移除），
        # 仍然需要显式 resume；这里做容错，已经跑起来就跳过。
        try:
            frida.resume(resume_pid)
            print("[+] 已 resume，客户端开始运行")
        except Exception as e:
            print("[i] resume 跳过（可能已自动恢复）：%s" % e)

    print("[+] 开始输出（Ctrl-C 结束）")

    try:
        while True:
            time.sleep(0.3)
    except KeyboardInterrupt:
        print("\n[*] 收工")
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["spawn", "attach", "check"])
    ap.add_argument("--exe", default=None, help="BaiduNetdisk.exe 的完整路径")
    ap.add_argument("--name", default="BaiduNetdisk.exe", help="attach 模式下的进程名")
    ap.add_argument("--pid", type=int, default=None, help="attach 模式下的 PID")
    ap.add_argument("--out", default=None, help="同时把输出写进这个文件")
    ap.add_argument("--script", default=None,
                    help="换成别的 Frida 脚本（默认 hooks.js，可用 selftest.js 体检）")
    args = ap.parse_args()

    frida = load_frida()

    if args.out:
        class Tee:
            def __init__(self, f):
                self.f = f

            def write(self, s):
                sys.__stdout__.write(s)
                self.f.write(s)
                self.f.flush()

            def flush(self):
                self.f.flush()

        sys.stdout = Tee(open(args.out, "w", encoding="utf-8"))

    script_path = args.script or SCRIPT
    if not os.path.isabs(script_path):
        script_path = os.path.join(HERE, script_path)
    if not os.path.exists(script_path):
        die("找不到脚本：" + script_path)
    source = open(script_path, "r", encoding="utf-8").read()
    print("[*] 脚本：", script_path)

    if args.mode == "check":
        cmd_check(frida, args)
        return

    if args.mode == "spawn":
        exe = find_exe(args)
        print("[*] 启动：", exe)
        # 关键：spawn 会先挂起，注入脚本后再 resume，才能抓到启动期的调用
        pid = frida.spawn(exe)
        print("[*] 已挂起，pid =", pid)
        run(frida, pid, source, args, resume_pid=pid)
    else:
        target = args.pid if args.pid else args.name
        print("[*] attach 到：", target)
        run(frida, target, source, args)


if __name__ == "__main__":
    main()
