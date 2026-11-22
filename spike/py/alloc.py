#!/usr/bin/env python3
"""alloc.py hold MB [secs] | grow CHUNK_MB DELAY_S [MAX_MB] | thrash MB SECS
options via env: IGNORE_TERM=1, OOM_ADJ=n"""
import os, signal, sys, time
if os.environ.get("OOM_ADJ"):
    try:
        open("/proc/self/oom_score_adj", "w").write(os.environ["OOM_ADJ"])
    except OSError as e:
        print("oom_score_adj:", e, flush=True)
if os.environ.get("IGNORE_TERM"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
PAGE = 4096
def block(mb):
    b = bytearray(mb << 20)
    for i in range(0, len(b), PAGE):
        b[i] = 1
    return b
mode = sys.argv[1]
if mode == "hold":
    keep = block(int(sys.argv[2])); print("held %s MB pid %d" % (sys.argv[2], os.getpid()), flush=True)
    time.sleep(float(sys.argv[3]) if len(sys.argv) > 3 else 3600)
elif mode == "grow":
    chunk, delay = int(sys.argv[2]), float(sys.argv[3]); mx = int(sys.argv[4]) if len(sys.argv) > 4 else 1 << 30
    keep = []; n = 0
    while n < mx:
        keep.append(block(chunk)); n += chunk
        if n % (chunk * 10) == 0:
            print("grown %d MB" % n, flush=True)
        time.sleep(delay)
    print("reached max %d MB" % n, flush=True); time.sleep(3600)
elif mode == "thrash":
    mb, secs = int(sys.argv[2]), float(sys.argv[3])
    b = block(mb); end = time.time() + secs; rounds = 0
    while time.time() < end:
        for i in range(0, len(b), PAGE):
            b[i] = (b[i] + 1) & 0xff
        rounds += 1
    print("thrash rounds", rounds, flush=True)
