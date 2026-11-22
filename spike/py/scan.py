#!/usr/bin/env python3
"""Time one full /proc scan the way section 5.7 describes: stat, status; cgroup and cmdline once per (pid,start)."""
import os, sys, time
def scan(cache):
    n = 0
    for e in os.listdir("/proc"):
        if not e.isdigit(): continue
        try:
            with open("/proc/%s/stat" % e, "rb") as f: st = f.read()
            r = st.rfind(b")"); parts = st[r + 2:].split()
            flags = int(parts[6]); start = parts[19]
            if flags & 0x00200000:  # PF_KTHREAD
                n += 1; continue
            with open("/proc/%s/status" % e, "rb") as f: s = f.read()
            key = (e, start)
            if key not in cache:
                with open("/proc/%s/cgroup" % e, "rb") as f: cg = f.read()
                with open("/proc/%s/cmdline" % e, "rb") as f: cl = f.read()
                cache[key] = (cg, cl)
            n += 1
        except (OSError, IndexError):
            pass
    return n
cold = []; warm = []
for i in range(5):
    t = time.perf_counter(); n = scan({}); cold.append((time.perf_counter() - t) * 1000)
cache = {}; scan(cache)
for i in range(5):
    t = time.perf_counter(); scan(cache); warm.append((time.perf_counter() - t) * 1000)
cold.sort(); warm.sort()
print("processes=%d cold(cgroup+cmdline read) median=%.1f ms min=%.1f max=%.1f ; warm(cached) median=%.1f ms"
      % (n, cold[2], cold[0], cold[4], warm[2]))
print("MEDIAN_COLD_MS=%.1f MEDIAN_WARM_MS=%.1f N=%d" % (cold[2], warm[2], n))
