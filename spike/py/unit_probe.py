#!/usr/bin/env python3
"""Stands in for oomphd.py under the draft unit (row 15): writes samples, asks loginctl, keeps a journalctl child."""
import json, os, select, subprocess, sys, threading, time
LOG = "/var/log/oomph"
def w(name, text, mode="w"):
    with open(os.path.join(LOG, name), mode) as f: f.write(text)
st = {k: v.strip() for k, _, v in (l.partition(":") for l in open("/proc/self/status"))
      if k in ("Uid", "Gid", "Groups", "CapEff", "CapBnd", "CapPrm", "CapAmb", "NoNewPrivs", "Seccomp")}
w("probe-status.json", json.dumps(st) + "\n")
def run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return "$ %s\nexit %d\n%s%s" % (" ".join(cmd), p.returncode, p.stdout[-3000:], p.stderr[-1500:])
    except Exception as e:
        return "$ %s\nEXC %r\n" % (" ".join(cmd), e)
txt = run(["loginctl", "list-sessions", "--no-legend"])
try:
    ids = [l.split()[0] for l in subprocess.run(["loginctl", "list-sessions", "--no-legend"], capture_output=True,
           text=True, timeout=10).stdout.splitlines() if l.strip()]
except Exception:
    ids = []
txt += run(["loginctl", "show-session"] + ids[:5] + ["-p", "Type", "-p", "Class", "-p", "TTY", "-p", "IdleHint",
            "-p", "IdleSinceHint"]) if ids else "(no sessions)\n"
w("probe-loginctl.txt", txt)
# PSI trigger from inside the unit
try:
    fd = os.open("/proc/pressure/memory", os.O_RDWR | os.O_NONBLOCK)
    os.write(fd, b"some 200000 2000000\0"); psi = "REGISTERED"
except OSError as e:
    psi = "FAILED errno=%d %s" % (e.errno, e.strerror)
w("probe-psi.txt", psi + "\n")
jl = {"lines": 0, "first": None}
try:
    child = subprocess.Popen(["journalctl", "-f", "-o", "json", "-n", "50", "_TRANSPORT=kernel"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    def rd():
        for line in child.stdout:
            jl["lines"] += 1
            if jl["first"] is None: jl["first"] = line[:200].decode(errors="replace")
    threading.Thread(target=rd, daemon=True).start()
except Exception as e:
    child = None; jl["error"] = repr(e)
n = 0
while True:
    ma = [l for l in open("/proc/meminfo") if l.startswith("MemAvailable")][0].split()[1]
    n += 1
    w("samples.jsonl", json.dumps({"t": time.time(), "n": n, "avail_kb": int(ma)}) + "\n", "a")
    w("probe-journal.json", json.dumps({"child_pid": child.pid if child else None,
       "child_alive": child is not None and child.poll() is None,
       "child_rc": child.poll() if child else None, **jl}) + "\n")
    time.sleep(2)
