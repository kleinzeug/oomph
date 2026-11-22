#!/usr/bin/env python3
"""Child allocates and touches MB megabytes; parent reads its RssAnon + VmSwap before and after.
footprint.py MB SETTLE_S"""
import os, subprocess, sys, time
mb = int(sys.argv[1]) if len(sys.argv) > 1 else 200
settle = float(sys.argv[2]) if len(sys.argv) > 2 else 2
def fields(pid):
    d = {}
    for line in open("/proc/%d/status" % pid):
        k, _, v = line.partition(":")
        if k in ("RssAnon", "VmSwap", "VmRSS", "RssShmem", "RssFile"):
            d[k] = int(v.split()[0]) // 1024
    return d
code = ("import sys,time\nprint('pre',flush=True)\nsys.stdin.readline()\n"
        "b=bytearray(%d<<20)\nfor i in range(0,len(b),4096): b[i]=1\nprint('post',flush=True)\ntime.sleep(600)\n" % mb)
p = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
assert p.stdout.readline().strip() == "pre"; time.sleep(0.5)
a = fields(p.pid); print("before:", a, flush=True)
p.stdin.write("go\n"); p.stdin.flush()
assert p.stdout.readline().strip() == "post"
last = None
for i in range(int(settle * 2) + 1):
    time.sleep(0.5); b = fields(p.pid)
    if b == last and i > 2: break
    last = b
print("after:", b)
fa, fb = a["RssAnon"] + a["VmSwap"], b["RssAnon"] + b["VmSwap"]
print("RssAnon+VmSwap: %d MB -> %d MB, delta %+d MB (VmSwap after %d MB, VmRSS after %d MB)"
      % (fa, fb, fb - fa, b["VmSwap"], b["VmRSS"]))
print("DELTA_MB=%d SWAP_MB=%d" % (fb - fa, b["VmSwap"]))
p.kill()
