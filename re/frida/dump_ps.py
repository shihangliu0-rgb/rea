#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""re/frida/dump_ps.py —— 不用 frida-ps，直接列进程（找 PID / 进程名）"""
import sys

try:
    import frida
except ImportError:
    sys.exit("没装 frida：pip install frida")

dev = frida.get_local_device()
kw = sys.argv[1].lower() if len(sys.argv) > 1 else ""
print("%-8s %s" % ("PID", "NAME"))
for p in dev.enumerate_processes():
    if not kw or kw in p.name.lower():
        print("%-8d %s" % (p.pid, p.name))
