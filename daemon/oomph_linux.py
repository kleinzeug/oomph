"""oomph's backend for Linux: what measures a Linux machine, behind the backend contract of
oomph_darwin.py (roadmap 03 §4.3). Text files under /proc and /sys, and two programs of the system
(journalctl for kills, nvidia-smi for NVIDIA cards), each in a child process: no ctypes, no GPU
library, no privilege. Every path goes through OOMPH_SYSROOT (default empty), so that a recorded
tree stands in for a machine in the tests (tools/linuxfixture.py), on a Mac too. Nothing happens
at import.

1.9.4 was Linux for agents (step L1): checks, reservations, `oomph run`, the MCP server, the hook
and `oomph top` measure live. 1.13.0 adds the logger (step L2): oomphd.py runs as the systemd
service oomphd, without capabilities or network, and this backend gives it kills from the journal,
CPU, disks, I/O and NVIDIA cards. What the design settled from the fact spike (03 Appendix C.3)
and applies here:

  memory     /proc/meminfo; MemAvailable is "available" (03 §5.2). Compressed is zswap plus the RAM
             of zram devices that are swap; swap is what lies on disk.
  pressure   from stall time (PSI) and headroom (03 §5.3): headroom alone stops at warning, critical
             needs stall time. RHEL 9 boots without PSI (CONFIG_PSI_DEFAULT_DISABLED): a first-class
             mode where the level stops at warning and `oomph doctor` explains psi=1.
  processes  /proc/<pid>/stat and status, world-readable. The footprint is RssAnon + VmSwap; the
             name comes from comm and the command line, never from `exe` (Claude Code's native
             binary is named by its version; both installs show as "claude", C.3 row 22).
  groups     by cgroup: a container, a systemd unit, an app scope, else the program (03 §5.8).
  scope      inside a cgroup with a memory limit (a container, a systemd-run scope) the limit is the
             machine: figures, stall time and the margin are the cgroup's, and the level is the worse
             of the cgroup's and the host's (03 §5.14).
  kills      the journal, one victim counted once however often a group kill names it, the cursor
             always one this watcher read (C.3 rows 9, 13); without a readable journal, the kernel's
             counter (KillWatcher).

The thresholds live in P; `level`, `margin` and `oversize_limit` are pure functions of numbers,
so oomph.py judges a Linux sample with them on any system.
"""
import errno
import functools
import hashlib
import math
import os
import re
import socket
import time

OS = "linux"
KB = 1024
MB = 1024 * KB
GB = 1024 * MB
ROOT = os.environ.get("OOMPH_SYSROOT", "")
CAP = 1 << 20              # bytes read of any one file
try:
    CLK_TCK = os.sysconf("SC_CLK_TCK") or 100
except (AttributeError, ValueError, OSError):
    CLK_TCK = 100
CG_ROOT = "/sys/fs/cgroup"
PF_KTHREAD = 0x00200000

P = {"some_warn": 10, "some_crit": 40, "full_warn": 5, "full_crit": 15,      # % of the last 10 s
     "upper_pct": 15, "upper_cap_gb": 8, "lower_pct": 10, "lower_cap_gb": 4,  # headroom bounds
     "swap_half": 0.5, "swap_gone": 0.10, "swap_none": 0.10,                  # swap under 10 % of RAM is none
     "margin_min_gb": 0.2}
WALK = {"levels": 6, "cgroups": 256, "ms": 50, "min_some": 1.0, "bound": 0.95}  # stall attribution (03 §5.3)


def _p(path):
    return ROOT + path


def read(path, cap=CAP):
    """A file below the root as text (None when it cannot be read): /proc and /sys files are small
    and change between reads, so one read of at most `cap` bytes."""
    try:
        with open(_p(path), "rb") as f:
            return f.read(cap).decode("utf-8", "replace")
    except (OSError, ValueError):
        return None


def _int(s, default=None):
    try:
        return int(s)
    except (TypeError, ValueError):
        return default


def _gb(b, nd=2):
    return round((b or 0) / GB, nd)


# ------------------------------------------------------------------ memory
def meminfo():
    """/proc/meminfo in bytes ("kB" lines; the HugePages counts stay counts)."""
    out = {}
    for line in (read("/proc/meminfo") or "").splitlines():
        k, _, v = line.partition(":")
        f = v.split()
        if f and f[0].isdigit():
            out[k.strip()] = int(f[0]) * (KB if len(f) > 1 and f[1] == "kB" else 1)
    return out


def swaps():
    """The swap devices of /proc/swaps: [(name, type, size bytes, used bytes)]."""
    out = []
    for line in (read("/proc/swaps") or "").splitlines()[1:]:
        f = line.split()
        if len(f) >= 4 and f[2].isdigit() and f[3].isdigit():
            out.append((f[0].replace("\\040", " "), f[1], int(f[2]) * KB, int(f[3]) * KB))
    return out


def zram_swap(devs=None):
    """What the zram devices that are swap hold: orig (pages stored, uncompressed), ram (what that
    costs in RAM), disksize, used (by the kernel's count). A zram device that is not swap (a file
    system on it) is not here: it is RAM a driver holds, in the remainder (03 §5.2)."""
    z = {"orig": 0, "ram": 0, "disksize": 0, "used": 0, "n": 0}
    for name, _typ, size, used in devs if devs is not None else swaps():
        m = re.fullmatch(r"/dev/(zram\d+)", name)
        if not m:
            continue
        mm = (read("/sys/block/%s/mm_stat" % m.group(1)) or "").split()
        z["n"] += 1
        z["orig"] += _int(mm[0], 0) if mm else 0
        z["ram"] += _int(mm[2], 0) if len(mm) > 2 else 0
        z["disksize"] += _int((read("/sys/block/%s/disksize" % m.group(1)) or "").strip(), size) or size
        z["used"] += used
    return z


def psi_file(path):
    """A pressure file ("some avg10=… avg60=… avg300=… total=…", "full …") as
    {"some": {"avg10", "avg60", "total"}, "full": {…}}, or None where there is none: PSI off
    (RHEL 9 by default: no /proc/pressure at all) or a kernel without it."""
    text = read(path, 4096)
    if not text:
        return None
    out = {}
    for line in text.splitlines():
        f = line.split()
        if f and f[0] in ("some", "full"):
            kv = dict(x.split("=", 1) for x in f[1:] if "=" in x)
            try:
                out[f[0]] = {"avg10": float(kv.get("avg10", 0)), "avg60": float(kv.get("avg60", 0)),
                             "total": int(kv.get("total", 0))}
            except ValueError:
                return None
    return out if "some" in out else None


def _avg(x, kind, key="avg10"):
    return (x or {}).get(kind, {}).get(key, 0.0) if x else None


def bounds(ram_gb):
    """(upper, lower) headroom bounds in GB: min(15 %, 8 GB) and min(10 %, 4 GB) of RAM."""
    return (min(P["upper_pct"] / 100.0 * ram_gb, P["upper_cap_gb"]),
            min(P["lower_pct"] / 100.0 * ram_gb, P["lower_cap_gb"]))


def level(some, full, avail_gb, ram_gb, swap_left):
    """1 normal, 2 warning, 4 critical (the values of macOS's own level), from the stall time of
    the last 10 s (`some`, `full` in %; None without PSI) and the headroom (03 §5.3). Headroom
    alone stops at warning; critical needs measured stall time."""
    upper, lower = bounds(ram_gb)
    low, vlow = avail_gb < upper, avail_gb < lower
    pain_warn = some is not None and (some >= P["some_warn"] or (full or 0) >= P["full_warn"])
    pain_crit = some is not None and (some >= P["some_crit"] or (full or 0) >= P["full_crit"])
    if pain_crit or (pain_warn and vlow and swap_left < P["swap_gone"]):
        return 4
    if pain_warn or vlow or (low and swap_left < P["swap_half"]):
        return 2
    return 1


def margin(ram_gb):
    """The ledger's margin: the upper headroom bound, with or without swap, so that a grant used as
    declared cannot change the level by itself (03 §5.3, invariant 2)."""
    return math.ceil(max(P["margin_min_gb"], bounds(ram_gb)[0]) * 100) / 100  # up: never below the bound


def oversize_limit(avail_gb, swap_free_gb, ram_gb):
    """The largest request granted when nothing else is: what RAM and swap can hold, less the
    lower bound below which stalls turn critical (03 §5.3)."""
    return math.floor(max(0.0, avail_gb + swap_free_gb - bounds(ram_gb)[1]) * 100) / 100  # down: never past it


def swap_room(kswap_free, zram_free, zram_ratio):
    """What more swap can take in, in RAM's terms: free disk swap whole, free zram only by what
    compressing saves (its pages stay in RAM, at 1/ratio of their size). The ratio is what the
    devices achieve now, held to 1..3; 2 before they hold enough to tell (03 §5.2)."""
    r = min(3.0, max(1.0, zram_ratio or 2.0))
    zf = min(max(0, zram_free), max(0, kswap_free))
    return max(0, kswap_free - zf) + zf * (1 - 1 / r)


def _zram_ratio(z):
    return z["orig"] / z["ram"] if z["ram"] >= (64 << 20) else None


def swap_left(total, free, ram):
    """The share of swap still free; a swap smaller than 10 % of RAM counts as none."""
    return free / total if total > 0 and total >= P["swap_none"] * ram else 0.0


# ------------------------------------------------------------------ cgroups
def cgroup_of(pid="self"):
    """The process's cgroup: ("v2", path) from its "0::" line, ("v1", path) of the memory
    controller, or (None, None)."""
    text = read("/proc/%s/cgroup" % pid, 64 << 10) or ""
    v1 = None
    for line in text.splitlines():
        f = line.split(":", 2)
        if len(f) != 3:
            continue
        if f[0] == "0" and f[1] == "":
            return "v2", f[2].strip() or "/"
        if "memory" in f[1].split(","):
            v1 = f[2].strip() or "/"
    return ("v1", v1) if v1 else (None, None)


def _cg_num(d, name):
    """A cgroup file holding one number or "max" (None for max or unreadable)."""
    v = (read("%s/%s" % (d, name), 256) or "").strip()
    return None if v in ("", "max") else _int(v)


def _cg_stat(d, name="memory.stat"):
    out = {}
    for line in (read("%s/%s" % (d, name), 64 << 10) or "").splitlines():
        f = line.split()
        if len(f) == 2 and f[1].isdigit():
            out[f[0]] = int(f[1])
    return out


def cgroup_version():
    if os.path.isfile(_p(CG_ROOT + "/cgroup.controllers")):
        return "v2"
    return "v1" if os.path.isdir(_p(CG_ROOT + "/memory")) else "none"


def _cg_dir(path):
    """The directory of a v2 cgroup path as this process sees it. Inside a container with its own
    cgroup namespace the path is "/" and the mount is the container's cgroup; a path that does not
    exist below the mount (a host path seen from a container) falls back to the mount."""
    d = CG_ROOT + ("" if path in ("", "/") else path)
    return d if os.path.isdir(_p(d)) else CG_ROOT


def limit_of(ram_bytes):
    """The memory limit this process lives under, smaller than RAM, or None (03 §5.14): the
    smallest of memory.max and memory.high on the way from its cgroup up to the mount (v2), or
    memory.limit_in_bytes (v1). {"dir", "id", "limit", "by", "v"}."""
    v, path = cgroup_of()
    best = None
    if v == "v2":
        d = _cg_dir(path)
        for _hop in range(64):
            for name, by in (("memory.max", "max"), ("memory.high", "high")):
                n = _cg_num(d, name)
                if n is not None and (best is None or n < best["limit"]):
                    best = {"dir": d, "limit": n, "by": by}
            if len(d) <= len(CG_ROOT):
                break
            d = os.path.dirname(d)
    elif v == "v1":
        base = CG_ROOT + "/memory"
        d = base + ("" if path in ("", "/") else path)
        d = d if os.path.isdir(_p(d)) else base
        n = _cg_num(d, "memory.limit_in_bytes")
        if n is not None:
            best = {"dir": d, "limit": n, "by": "max"}
    if best is None or not ram_bytes or best["limit"] >= ram_bytes:
        return None
    best["v"] = v
    best["id"] = best["dir"][len(CG_ROOT):] or "/"
    return best


def limit_bound(budget_ms=WALK["ms"]):
    """The maximal cgroups that sit at their own limit and stall there: from the root, descending
    only into children that stall themselves (some ≥ 1 %), not below a limit-bound one; at most
    6 levels, 256 cgroups or 50 ms. [(path, some, full)], or None when the walk could not finish
    (then the stall time cannot be attributed, 03 §5.3). Also None inside a cgroup namespace: the
    mount is then the container's own subtree (it has a memory.max, the real root has none), and a
    neighbour at its limit is out of sight while /proc/pressure/memory still counts it."""
    if os.path.exists(_p(CG_ROOT + "/memory.max")):
        return None
    t0, seen, found = time.monotonic(), 0, []
    stack = [(CG_ROOT, 0)]
    while stack:
        d, depth = stack.pop()
        try:
            kids = sorted(e.name for e in os.scandir(_p(d)) if e.is_dir(follow_symlinks=False))
        except OSError:
            continue
        for k in kids:
            seen += 1
            if seen > WALK["cgroups"] or (time.monotonic() - t0) * 1000 > budget_ms:
                return None
            c = d + "/" + k
            pr = psi_file(c + "/memory.pressure")
            some = _avg(pr, "some")
            if not some or some < WALK["min_some"]:
                continue
            lim = [n for n in (_cg_num(c, "memory.max"), _cg_num(c, "memory.high")) if n is not None]
            cur = _cg_num(c, "memory.current")
            if lim and cur is not None and cur >= WALK["bound"] * min(lim):
                found.append((c[len(CG_ROOT):], some, _avg(pr, "full")))
            elif depth + 1 < WALK["levels"]:
                stack.append((c, depth + 1))
    return found


def machine_stall(raw, avail_gb, upper_gb, cgv):
    """(some, full, limit) of the MACHINE: the stall time that cgroups lost at their own limit is
    taken out while the machine itself has room (03 §5.3, invariant 3). `limit` says what was
    taken out, and from whom."""
    if raw is None:
        return None, None, None
    some, full = _avg(raw, "some"), _avg(raw, "full")
    if not (some >= P["some_warn"] or full >= P["full_warn"]) or avail_gb < upper_gb:
        return some, full, None
    L = limit_bound() if cgv == "v2" else None
    if L is None:  # cannot attribute: with room, pain warns but never reads critical
        return min(some, P["some_crit"] - 1), min(full, P["full_crit"] - 1), None
    if not L:
        return some, full, None
    s2 = max(0.0, some - sum(x[1] for x in L))
    f2 = max(0.0, full - sum(x[2] or 0 for x in L))
    return s2, f2, {"some": round(some - s2, 2), "full": round(full - f2, 2),
                    "cgroups": [group_of_cgroup(x[0]) or x[0] for x in L[:3]]}


# ------------------------------------------------------------------ the sample
def _host(m, z, devs):
    """The canonical fields of the whole machine from meminfo (03 §5.2), and the raw figures."""
    total = m.get("MemTotal", 0)
    hugetlb = m.get("HugePages_Total", 0) * m.get("Hugepagesize", 0)
    avail = min(total, m.get("MemAvailable", m.get("MemFree", 0)))
    app = m.get("AnonPages", 0) + m.get("Shmem", 0)
    comp = m.get("Zswap", 0) + z["ram"]
    wired = max(0, total - avail - app - comp)
    free = min(m.get("MemFree", 0), avail)
    kswap_total, kswap_free = m.get("SwapTotal", 0), m.get("SwapFree", 0)
    kswap_used = kswap_total - kswap_free
    disk_swap = [d for d in devs if not re.fullmatch(r"/dev/zram\d+", d[0])]
    return {
        "ram_gb": _gb(total, 1), "free_pct": round(100.0 * avail / total) if total else None,
        "app_gb": _gb(app), "wired_gb": _gb(wired), "compressed_gb": _gb(comp),
        "compressor_logical_gb": _gb(m.get("Zswapped", 0) + z["orig"]),
        "cached_gb": _gb(avail - free), "free_gb": _gb(free),
        "swap_total_gb": _gb(max(0, kswap_total - z["disksize"])),
        "swap_used_gb": _gb(max(0, kswap_used - z["used"] - m.get("Zswapped", 0))),
        "swapfiles": len(disk_swap),
    }, {
        "avail_gb": _gb(avail), "anon_gb": _gb(m.get("AnonPages", 0)), "shmem_gb": _gb(m.get("Shmem", 0)),
        "slab_unreclaim_gb": _gb(m.get("SUnreclaim", 0)), "hugetlb_gb": _gb(hugetlb), "dirty_gb": _gb(m.get("Dirty", 0)),
        "kswap_total_gb": _gb(kswap_total), "kswap_free_gb": _gb(kswap_free), "zram_disk_gb": _gb(z["disksize"]),
        "swap_room_gb": _gb(swap_room(kswap_free, z["disksize"] - z["used"], _zram_ratio(z))),
        "commit_pct": round(100.0 * m["Committed_AS"] / m["CommitLimit"]) if m.get("CommitLimit") and "Committed_AS" in m
        else None,
        "overcommit": _int((read("/proc/sys/vm/overcommit_memory", 64) or "").strip()),
    }


def _vmstat():
    out = {}
    for line in (read("/proc/vmstat") or "").splitlines():
        f = line.split()
        if len(f) == 2 and f[0] in ("pswpin", "pswpout", "oom_kill"):
            out[f[0]] = _int(f[1], 0)
    return out


def _disk_free_gb(path="/"):
    try:
        st = os.statvfs(_p(path) or "/")
        return round(st.f_bavail * st.f_frsize / GB, 1)
    except OSError:
        return None


def _psi_block(mem, some, full):
    """The sample's `psi` (%): the machine's memory stall time (what the level used), the 60 s
    averages, and CPU and I/O, which are free to record."""
    cpu, io = psi_file("/proc/pressure/cpu"), psi_file("/proc/pressure/io")
    out = {"mem_some": round(some, 2), "mem_full": round(full or 0, 2),
           "mem_some60": round(_avg(mem, "some", "avg60"), 2), "mem_full60": round(_avg(mem, "full", "avg60") or 0, 2)}
    if cpu:
        out["cpu_some"] = round(_avg(cpu, "some"), 2)
    if io:
        out["io_some"], out["io_full"] = round(_avg(io, "some"), 2), round(_avg(io, "full") or 0, 2)
    return out


def system_memory():
    """The canonical memory fields of a sample (and disk_free_gb), plus `psi`, `linux` (the
    kernel's own figures and the margin in force) and, inside a limited cgroup, `scope`: then the
    figures are the cgroup's and `pressure` the worse of its level and the host's."""
    m, devs = meminfo(), swaps()
    z = zram_swap(devs)
    host, lx = _host(m, z, devs)
    ram = host["ram_gb"] - lx["hugetlb_gb"]           # the bounds are of RAM outside the hugepage pool
    upper, lower = bounds(ram)
    left = swap_left(m.get("SwapTotal", 0), m.get("SwapFree", 0), m.get("MemTotal", 0))
    cgv = cgroup_version()
    mem = psi_file("/proc/pressure/memory")
    some, full, lim = machine_stall(mem, lx["avail_gb"], upper, cgv)
    host_level = level(some, full, lx["avail_gb"], ram, left)
    vm = _vmstat()
    s = dict(host, pressure=host_level, disk_free_gb=_disk_free_gb("/"),
             swapins=vm.get("pswpin", 0), swapouts=vm.get("pswpout", 0))
    if mem is not None:
        s["psi"] = _psi_block(mem, some, full)
        if lim:
            s["psi"]["limit"] = lim
    lx["margin_gb"] = margin(ram)
    lx["oversize_gb"] = oversize_limit(lx["avail_gb"], lx["swap_room_gb"], ram)
    lx["floor_gb"] = round(lower, 2)  # the lower bound the oversize limit leaves free
    s["linux"] = lx
    c = limit_of(m.get("MemTotal", 0))
    if c:
        _cgroup_scope(s, c, m, host_level)
    return s


def _cgroup_scope(s, c, m, host_level):
    """Replace the machine's figures by the cgroup's (03 §5.14): the limit is the RAM, available is
    what the limit leaves after the cgroup's unreclaimable use (never more than the host's), its
    own stall time undiscounted, its own swap. The host's figures stay in `scope`."""
    d, lim = c["dir"], c["limit"]
    host_avail = s["linux"]["avail_gb"]
    if c["v"] == "v2":
        st = _cg_stat(d)
        cur = _cg_num(d, "memory.current") or 0
        reclaim = st.get("inactive_file", 0) + st.get("active_file", 0) + st.get("slab_reclaimable", 0)
        app, comp = st.get("anon", 0) + st.get("shmem", 0), _cg_num(d, "memory.zswap.current") or 0
        sw_cur = _cg_num(d, "memory.swap.current") or 0
        sw_max = _cg_num(d, "memory.swap.max")
        pr = psi_file(d + "/memory.pressure")
    else:
        st = _cg_stat(d)
        cur = _cg_num(d, "memory.usage_in_bytes") or 0
        reclaim = st.get("total_inactive_file", 0) + st.get("total_active_file", 0)
        app, comp = st.get("total_rss", 0) + st.get("total_shmem", 0), 0
        sw_cur, sw_max, pr = 0, 0, None
    host_swap_free = m.get("SwapFree", 0)
    sw_total = min(sw_max, m.get("SwapTotal", 0)) if sw_max is not None else m.get("SwapTotal", 0)
    avail = max(0, min(lim - (cur - reclaim), host_avail * GB))
    free = max(0, min(lim - cur, avail))
    wired = max(0, lim - avail - app - comp)
    ram = lim / GB
    left = swap_left(sw_total, max(0, min(sw_total - sw_cur, host_swap_free)), lim)
    some, full = (_avg(pr, "some"), _avg(pr, "full")) if pr else (None, None)
    lv = level(some, full, avail / GB, ram, left)
    s["scope"] = {"kind": "cgroup", "id": c["id"][:200], "limit_gb": _gb(lim), "by": c["by"],
                  "host_ram_gb": s["ram_gb"], "host_avail_gb": host_avail, "host_pressure": host_level,
                  "host_margin_gb": s["linux"]["margin_gb"]}
    s.update(ram_gb=_gb(lim), free_pct=round(100.0 * avail / lim) if lim else None, app_gb=_gb(app),
             wired_gb=_gb(wired), compressed_gb=_gb(comp), compressor_logical_gb=_gb(comp), cached_gb=_gb(avail - free),
             free_gb=_gb(free), swap_total_gb=_gb(sw_total), swap_used_gb=_gb(sw_cur),
             pressure=max(lv, host_level))
    if pr:
        s["psi"] = dict(s.get("psi") or {}, mem_some=round(some, 2), mem_full=round(full or 0, 2),
                        mem_some60=round(_avg(pr, "some", "avg60"), 2), mem_full60=round(_avg(pr, "full", "avg60") or 0, 2))
        s["psi"].pop("limit", None)
    room = min(max(0, sw_total - sw_cur) / GB, s["linux"]["swap_room_gb"])  # its own allowance, within the host's
    s["linux"].update(avail_gb=_gb(avail), margin_gb=margin(ram), swap_room_gb=round(room, 2),
                      oversize_gb=oversize_limit(avail / GB, room, ram), floor_gb=round(bounds(ram)[1], 2))


def scope():
    """{"kind": "host"} or the cgroup this process is limited by (03 §5.14)."""
    c = limit_of(meminfo().get("MemTotal", 0))
    return {"kind": "host"} if not c else {"kind": "cgroup", "id": c["id"], "limit_gb": _gb(c["limit"]), "by": c["by"]}


def away_state():
    """No presence without the logger (it comes with it, from loginctl): nothing is known, and
    nothing is drawn as away."""
    return {"idle_s": None, "display_on": None, "locked": False, "user": None, "uid": None, "sleep_preventers": []}


# ------------------------------------------------------------------ processes
_static = {}   # (pid, start) -> (name, path, cgroup, agent, conmon args): read once per process
_AGENT_ARG = re.compile(r"(^|/)(claude|claude-code/cli\.js)$")


def _stat(pid):
    """(comm, ppid, flags, starttime, (utime, stime, cutime, cstime)) from /proc/<pid>/stat, times in
    clock ticks: the name is what lies between the first "(" and the LAST ")" (names hold spaces and
    parentheses)."""
    t = read("/proc/%d/stat" % pid, 4096)
    if not t:
        return None
    a, b = t.find("("), t.rfind(")")
    if a < 0 or b < a:
        return None
    f = t[b + 2:].split()
    if len(f) < 20:
        return None
    return t[a + 1:b], _int(f[1], 0), _int(f[6], 0), _int(f[19], 0), tuple(_int(x, 0) for x in f[11:15])


def _io(pid):
    """(read_bytes, write_bytes) of /proc/<pid>/io: what reached storage. None where it cannot be read."""
    out = {}
    for line in (read("/proc/%d/io" % pid, 4096) or "").splitlines():
        k, _, v = line.partition(":")
        if k in ("read_bytes", "write_bytes"):
            out[k] = _int(v.strip())
    r, w = out.get("read_bytes"), out.get("write_bytes")
    return (r, w) if isinstance(r, int) and isinstance(w, int) else None


def _status(pid):
    out = {}
    for line in (read("/proc/%d/status" % pid, 16 << 10) or "").splitlines():
        k, _, v = line.partition(":")
        if k in ("Uid", "VmRSS", "RssAnon", "VmSwap", "NSpid"):
            out[k] = v.split()
    return out


def _cmdline(pid):
    raw = read("/proc/%d/cmdline" % pid, 64 << 10) or ""
    return [x for x in raw.split("\0")][:-1] if raw.endswith("\0") else raw.split("\0") if raw else []


def _printable(s):
    """A name as any user may have chosen it (argv, comm, a unit name), with every character a
    terminal could take for a command shown as '?'."""
    return s if s.isprintable() else "".join(c if c.isprintable() else "?" for c in s)


def _static_of(pid, start, comm):
    """What does not change while a process lives, read once: its name by the rule of 03 §5.7 (the
    basename of argv[0] where its first 15 characters are comm, so that a name the kernel cut is
    whole again; else comm), argv[0] as the path when it is absolute, its cgroup, whether it is a
    Claude Code session started through node or bun, and conmon's container id and name."""
    key = (pid, start)
    if key in _static:
        return _static[key]
    argv, comm = _cmdline(pid), _printable(comm)
    a0 = _printable(argv[0]) if argv else ""
    base = os.path.basename(a0.split(" ")[0]) if a0 else ""
    name = base if base and base[:15] == comm[:15] and len(base) >= len(comm) else comm
    agent = comm in ("node", "bun") and any(_AGENT_ARG.search(x) for x in argv[1:3])
    con = None
    if comm == "conmon":
        o = {}
        for i, x in enumerate(argv[:-1]):
            if x in ("-c", "--cid", "-n", "--name"):
                o[x.lstrip("-")[0]] = _printable(argv[i + 1])
        con = (o.get("c"), o.get("n"))
    v, cg = cgroup_of(pid)
    r = _static[key] = (name[:64], a0[:1024] if a0.startswith("/") else "", cg if v == "v2" else None, agent, con)
    return r


def list_pids():
    try:
        return [int(e) for e in os.listdir(_p("/proc")) if e.isdigit()]
    except OSError:
        return []


def _ancestors(pids):
    """The pids, and all their ancestors, by their stat files."""
    out, todo = set(), list(pids)
    while todo:
        x = todo.pop()
        if x in out or x <= 0:
            continue
        out.add(x)
        st = _stat(x)
        if st:
            todo.append(st[1])
    return out


def collect_procs(only=None):
    """{pid: {pid ppid uid name start fp rss path cg nspid cpu_s child_s t0}} of every process this
    caller may see (kernel threads own no memory and are left out). `start` is the start time in clock
    ticks since boot: compared for equality only; `t0` is that time as a date. `cpu_s` and `child_s`
    are CPU seconds of the process and of the children it reaped, from the world-readable stat file;
    `rd` and `wr`, bytes read from and written to storage, only where /proc/<pid>/io may be read (the
    caller's own processes; root's: all) and only in a full scan (03 §11.2). With `only` (pids), those
    processes and their ancestors, without a full scan (03 §4.4): what finding one's own session needs."""
    procs = {}
    pids = _ancestors(only) if only is not None else list_pids()
    live = set()
    bt, me = boot_time(), os.geteuid()
    for pid in pids:
        st = _stat(pid)
        if not st:
            continue
        comm, ppid, flags, start, ticks = st
        if flags & PF_KTHREAD:
            continue
        s = _status(pid)
        try:
            uid = int(s["Uid"][0])
        except (KeyError, IndexError, ValueError):
            continue
        kb = lambda k: _int((s.get(k) or [0])[0], 0) * KB
        name, path, cg, agent, con = _static_of(pid, start, comm)
        live.add((pid, start))
        p = procs[pid] = {"pid": pid, "ppid": ppid, "uid": uid, "name": name, "start": start,
                          "fp": kb("RssAnon") + kb("VmSwap"), "rss": kb("VmRSS"), "path": path,
                          "cpu_s": (ticks[0] + ticks[1]) / CLK_TCK, "child_s": (ticks[2] + ticks[3]) / CLK_TCK}
        if bt is not None:
            p["t0"] = bt + start / CLK_TCK  # when it started (epoch): the Meter's "new since the last reading"
        if only is None and (me == 0 or uid == me):  # /proc/<pid>/io: one's own processes, or as root
            io = _io(pid)
            if io:
                p["rd"], p["wr"] = io
        if cg:
            p["cg"] = cg
        ns = s.get("NSpid")
        if ns and len(ns) > 1:
            p["nspid"] = _int(ns[-1])
        if agent:
            p["agent"] = True
        if con:
            p["conmon"] = con
    if only is None:
        for k in [k for k in _static if k not in live]:
            del _static[k]
        _name_containers(procs)
    return procs


def proc_cwd(pid):
    """A process's working directory: the caller's own processes only (another user's needs ptrace
    rights, which oomph never asks for)."""
    try:
        return os.readlink(_p("/proc/%d/cwd" % pid))
    except OSError:
        return None


def is_agent(p):
    """A Claude Code session's root: `claude` (the native build sets that title, and the npm
    package now ships it too, C.3 row 22), or an old npm build run by node or bun."""
    return p["name"] == "claude" or bool(p.get("agent"))


# ------------------------------------------------------------------ groups (03 §5.8)
_X2D = re.compile(r"\\x([0-9a-fA-F]{2})")
_CONTAINER = re.compile(r"(?:^|/)(?:docker-|cri-containerd-|crio-)?([0-9a-f]{64})(?:\.scope)?(?:/|$)|(?:^|/)docker/([0-9a-f]{12,64})(?:/|$)")
_PODMAN = re.compile(r"(?:^|/)libpod-([0-9a-f]{64})\.scope(?:/|$)")
_POD = re.compile(r"kubepods.*?pod([0-9a-f_-]{36})")
_main_of = {}  # container id -> its main program (refreshed with every full scan)


def _unescape(s):
    """systemd's \\xNN escapes undone where they stand for a printable character."""
    return _X2D.sub(lambda m: _printable(chr(int(m.group(1), 16))), s)


def _cid(kind, cid, main):
    """docker:3f9c1a7e (nginx): the id `docker ps` shows, and the program that runs in it."""
    return "%s:%s (%s)" % (kind, cid[:8], main) if main else "%s:%s" % (kind, cid[:8])


def group_of_cgroup(cg, main=None):
    """The group name a cgroup path stands for, or None (then the program names the group)."""
    if not cg or cg == "/":
        return None
    m = _PODMAN.search(cg)
    if m:
        cid = m.group(1)
        name = _podman_names.get(cid)
        return "podman:%s" % name if name else _cid("podman", cid, main or _main_of.get(cid))
    m = _POD.search(cg)
    if m:
        uid = m.group(1).replace("_", "-")
        return _cid("pod", uid.replace("-", ""), main or _main_of.get(uid))
    m = _CONTAINER.search(cg)
    if m:
        cid = m.group(1) or m.group(2)
        return _cid("docker", cid, main or _main_of.get(cid))
    parts = [_unescape(_printable(p)) for p in cg.split("/") if p]
    for i in range(len(parts) - 1, -1, -1):
        p = parts[i]
        m = re.match(r"lxc\.payload\.(.+)$", p)
        if m or (i > 0 and parts[i - 1] == "lxc"):
            return "lxc:%s" % (m.group(1) if m else p)
        m = re.match(r"machine-qemu-\d+-(.+)\.scope$", p)
        if m:
            return "vm:%s" % m.group(1)
        m = re.match(r"machine-(.+)\.scope$", p)
        if m:
            return "machine:%s" % m.group(1)
        m = re.match(r"snap\.([^.]+)\.", p)
        if m:
            return m.group(1)
        if p.startswith("app-") and p.endswith((".scope", ".service")):
            return _app_name(p)
    if len(parts) >= 2 and parts[0] == "system.slice" and parts[1].endswith(".service"):
        return parts[1][:-len(".service")]
    return None


def _app_name(p):
    """An app's scope or service, as systemd names them: app[-<launcher>]-<app id>[-<random>|@<n>].scope
    (app-gnome-firefox-4711.scope, app-flatpak-org.gimp.GIMP-12.scope, app-firefox@ab12.service)."""
    s = re.sub(r"(@[^.]*)?\.(scope|service)$", "", p[4:])
    s = re.sub(r"-[0-9a-f]{1,32}$", "", s) if "-" in s else s
    first, _, rest = s.partition("-")
    return rest if rest and re.fullmatch(r"[a-z]{1,12}", first) else s


_podman_names = {}


def _name_containers(procs):
    """Names for containers without privilege (03 §5.8): a container's main program is its init,
    the process whose innermost pid is 1; Podman's name is on conmon's command line."""
    _main_of.clear()
    _podman_names.clear()
    for p in procs.values():
        if p.get("conmon") and p["conmon"][0] and p["conmon"][1]:
            _podman_names[p["conmon"][0]] = re.sub(r"[^A-Za-z0-9_.-]", "_", p["conmon"][1])[:64]
        cg = p.get("cg")
        if not cg or p.get("nspid") != 1:
            continue
        m = _PODMAN.search(cg) or _POD.search(cg) or _CONTAINER.search(cg)
        if m:
            cid = next(g for g in m.groups() if g)
            _main_of[cid.replace("_", "-") if "kubepods" in cg else cid] = p["name"]


def group_of(p):
    """The group a process counts under: its container, unit or app (03 §5.8), else its program."""
    return group_of_cgroup(p.get("cg")) or p["name"]


def group_key(path, name):
    """The contract's form, for callers that have no process: the program."""
    return name


def ownership(sysm, procs):
    """What the processes' footprints add up to. No unowned figure on Linux (03 §5.12)."""
    return {"procs_gb": round(sum(p["fp"] for p in procs.values()) / GB, 1)}


# ------------------------------------------------------------------ time, the machine
def uptime_s():
    """Seconds awake since boot: CLOCK_MONOTONIC stops while the machine sleeps."""
    return time.clock_gettime(time.CLOCK_MONOTONIC)


@functools.lru_cache(maxsize=4)
def _btime(root):
    for line in (read("/proc/stat") or "").splitlines():
        if line.startswith("btime "):
            return _int(line.split()[1])
    return None


def boot_time():
    """When this machine booted (epoch seconds, the btime line of /proc/stat), read once."""
    return _btime(ROOT)


def boot_id():
    """Changes at every boot (/proc/sys/kernel/random/boot_id)."""
    v = (read("/proc/sys/kernel/random/boot_id", 128) or "").strip()
    return v if re.fullmatch(r"[0-9a-f-]{8,64}", v) else None


def machine_id():
    """(id, from): feature 1's formula over the first platform id of the chain /etc/machine-id,
    /var/lib/dbus/machine-id (03 §6.4). The chain's last link, a random id kept in the state
    folder, waits for the release that creates it; until then an image without either has none."""
    for f, src in (("/etc/machine-id", "machine-id"), ("/var/lib/dbus/machine-id", "dbus")):
        v = (read(f, 64) or "").strip()
        if re.fullmatch(r"[0-9a-f]{32}", v):
            return "m-" + hashlib.sha256(("oomph-machine-v1:" + v).encode()).hexdigest()[:16], src
    return None, "none"


def os_release():
    out = {}
    for f in ("/etc/os-release", "/usr/lib/os-release"):
        for line in (read(f, 16 << 10) or "").splitlines():
            k, _, v = line.partition("=")
            if k and v:
                out[k.strip()] = v.strip().strip('"').strip("'")
        if out:
            break
    return out


def virt():
    """none, a hypervisor's name, docker, podman, lxc, wsl (no subprocess: files only)."""
    if os.path.exists(_p("/.dockerenv")):
        return "docker"
    if os.path.exists(_p("/run/.containerenv")):
        return "podman"
    c = (read("/run/systemd/container", 64) or "").strip()  # systemd's own finding, world-readable
    if re.fullmatch(r"[a-z][a-z0-9-]{0,31}", c):
        return c
    if os.path.exists(_p("/proc/sys/fs/binfmt_misc/WSLInterop")) or "microsoft" in (read("/proc/sys/kernel/osrelease", 256) or "").lower():
        return "wsl"
    dmi = " ".join((read("/sys/class/dmi/id/%s" % f, 256) or "").strip() for f in ("sys_vendor", "product_name")).lower()
    for k, v in (("kvm", "kvm"), ("qemu", "qemu"), ("vmware", "vmware"), ("virtualbox", "virtualbox"),
                 ("microsoft", "hyperv"), ("amazon ec2", "kvm"), ("google", "kvm"), ("xen", "xen"),
                 ("parallels", "parallels"), ("apple", "apple")):
        if k in dmi:
            return v
    if "hypervisor" in (read("/proc/cpuinfo", 8192) or ""):
        return "vm"
    return "none"


def hidepid():
    """The hidepid option of /proc's mount ("0" when everything is visible)."""
    for line in (read("/proc/self/mountinfo", 256 << 10) or "").splitlines():
        f = line.split(" - ")
        if len(f) == 2 and f[1].startswith("proc "):
            m = re.search(r"hidepid=(\w+)", line)
            return m.group(1) if m else "0"
    return "0"


@functools.lru_cache(maxsize=1)
def _machine_static():
    rel = os_release()
    u = os.uname()
    mid, src = machine_id()
    vt = virt()
    gui = bool(os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY"))
    try:
        bat = any(e.startswith("BAT") for e in os.listdir(_p("/sys/class/power_supply")))
    except OSError:
        bat = False
    name = socket.gethostname().split(".")[0] or None
    kind = "container" if vt in ("docker", "podman", "lxc") else "laptop" if bat else "desktop" if gui else "server"
    return {"id": mid, "id_from": src, "name": name[:64] if name else None, "os": OS, "arch": u.machine,
            "os_version": (rel.get("PRETTY_NAME") or rel.get("NAME") or "Linux")[:64], "kernel": u.release,
            "kind": kind, "cpus": os.cpu_count(), "virt": vt}


def _zswap():
    """Is zswap on: True, False, or "unseen" where the kernel has no zswap fields (Debian 12's cloud
    kernel, C.3 row 2)."""
    if "Zswap" not in meminfo():
        return "unseen"
    return (read("/sys/module/zswap/parameters/enabled", 16) or "").strip() in ("Y", "1")


def machine(all_procs=None):
    """The `machine` block (03 §6.4) with `measures`: what this machine can measure, here and now."""
    m = dict(_machine_static())
    z = zram_swap()
    sc = scope()
    if sc["kind"] != "host":
        m["kind"] = "container"
    hp = hidepid()
    m["measures"] = {"memory": True, "psi": os.path.exists(_p("/proc/pressure/memory")), "kills": "count",
                     "cgroup": cgroup_version(), "zram": z["n"] > 0, "zswap": _zswap(),
                     "presence": "none", "footprint": "anon+swap", "names": "argv", "containers": "main-program",
                     "unowned": False, "scope": sc["kind"], "cpu": "proc-stat", "io": "diskstats", "disks": "mountinfo",
                     "gpu": "nvidia-smi" if gpu_available() else "none",
                     "net": "ss" if ss_path() and _netdir() == "/proc/net" else "proc-net-dev",
                     "all_procs": (os.geteuid() == 0 or hp == "0") if all_procs is None else bool(all_procs)}
    return m


# ------------------------------------------------------------------ internet traffic (NET, 1.15; NET-concept §12.2)
# The backend contract's network part (oomph_darwin.py lists it). No packet is sent. The logger runs as the
# service oomphd in a network namespace of its own (PrivateNetwork=yes, no netlink): its /proc/net shows only lo,
# so the host's figures are read where pid 1 sees them (/proc/1/net, world-readable), and ss and ip, which need
# netlink, are not there for it: its samples are totals only ("src": "if"). A user's CLI, and a logger run as root,
# have ss: as root every socket's process, as a user one's own (12.2, epyc-1).
NET_FLOWS = "ss"
SS_ARGS = ["-tinpeHO"]            # TCP, internal info, processes, extended (uid, cookie), no header, one line each
SS_CAP, SS_TIMEOUT = 4 << 20, 3.0
_IFN = re.compile(r"[A-Za-z0-9_.:@-]{1,15}\Z")


def _ifname_ok(x):
    """A device name the kernel could have given (dev_valid_name: no '/', not '.' or '..'): safe in a /sys path."""
    return bool(isinstance(x, str) and _IFN.match(x) and x not in (".", ".."))

_TUN_TYPES = ("65534", "512")     # ARPHRD_NONE (tun, WireGuard), ARPHRD_PPP
_TUN_NAME = re.compile(r"(tun|wg|ppp|tap|vpn)")


def _netdir():
    """/proc/net, or /proc/1/net where this process's network namespace has nothing but lo (the service's
    PrivateNetwork): the host's devices, routes and neighbours."""
    for d in ("/proc/net", "/proc/1/net"):
        dev = read(d + "/dev", 64 << 10) or ""
        if any(ln.split(":", 1)[0].strip() not in ("", "lo") for ln in dev.splitlines()[2:] if ":" in ln):
            return d
    return "/proc/net"


def _hex4(h):
    """/proc/net/route's little-endian hex address as a dotted quad."""
    try:
        return ".".join(str(b) for b in bytes.fromhex(h.zfill(8))[::-1])
    except ValueError:
        return None


def _routes(d):
    """/proc/net/route's IPv4 routes: [(dev, dest, gateway, mask, metric, flags)]."""
    out = []
    for ln in (read(d + "/route", 256 << 10) or "").splitlines()[1:4096]:
        t = ln.split()
        if len(t) >= 8 and _ifname_ok(t[0]):
            flags = int(t[3], 16) if re.fullmatch(r"[0-9A-Fa-f]{1,8}", t[3]) else 0
            out.append((t[0], _hex4(t[1]), _hex4(t[2]), _hex4(t[7]), _int(t[6], 0), flags))
    return out


def _is_tunnel(dev):
    if not _ifname_ok(dev):
        return False
    t = (read("/sys/class/net/%s/type" % dev, 64) or "").strip()
    return t in _TUN_TYPES if t else bool(_TUN_NAME.match(dev))


def _ip():
    """iproute2's ip, where it is (never for a recorded machine, OOMPH_SYSROOT)."""
    for p in ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"):
        if not ROOT and os.access(p, os.X_OK):
            return p
    return None


def _v4_addrs(dev, ip):
    """A device's own IPv4 addresses: `ip -o -4 addr show dev X` (as nobody), else its primary one (SIOCGIFADDR);
    none for a recorded machine."""
    if ROOT or not _ifname_ok(dev):
        return []
    if ip:
        out = (run_capped([ip, "-o", "-4", "addr", "show", "dev", dev], 64 << 10, 2.0) or b"").decode("utf-8", "replace")
        return re.findall(r"\binet (\d{1,3}(?:\.\d{1,3}){3})/\d{1,2}\b", out)[:64]
    import fcntl
    import struct
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as so:
            r = fcntl.ioctl(so.fileno(), 0x8915, struct.pack("256s", dev.encode()[:15]))   # SIOCGIFADDR
        return [socket.inet_ntoa(r[20:24])]
    except OSError:
        return []


def _v6_dev(d, ip):
    """The device of the IPv6 route to the internet: `ip -o -6 route get` (no packet), else the lowest-metric
    default of `d`/ipv6_route (RTF_GATEWAY or RTF_ADDRCONF, not lo), or None."""
    if ip:
        out = (run_capped([ip, "-o", "-6", "route", "get", "2606:4700:4700::1111"], 16 << 10, 2.0) or b"").decode(
            "utf-8", "replace")
        m = re.search(r"\bdev (\S+)", out)
        return m.group(1) if m and _ifname_ok(m.group(1)) else None
    best = None
    for ln in (read(d + "/ipv6_route", 256 << 10) or "").splitlines()[:4096]:
        t = ln.split()
        if len(t) == 10 and t[0] == "0" * 32 and t[1] == "00" and t[9] != "lo" and _ifname_ok(t[9]) and \
                re.fullmatch(r"[0-9a-f]{8}", t[5]) and re.fullmatch(r"[0-9a-f]{8}", t[8]) and \
                int(t[8], 16) & 0x40002 and not int(t[8], 16) & 0x200 and (best is None or int(t[5], 16) < best[0]):
            best = (int(t[5], 16), t[9])   # 0x200: RTF_REJECT (the unreachable default some systems keep)
    return best[1] if best else None


def net_route():
    """The egress (12.2): `ip -o route get 1.1.1.1` (honours policy routing, which wg-quick uses; no packet), else the
    lowest-metric default of /proc/net/route. A tun/WireGuard/ppp device is a VPN; the physical device is then the
    main table's lowest-metric default on another device. With its IPv4 subnet (the on-link route, not a host route,
    that holds the gateway: a link-local 169.254/16 one can come first) and IPv6 prefixes (if_inet6), and the addresses of it and of
    the tunnel (`addrs`, `tun_addrs`: ss names no device, a socket's local address does)."""
    d = _netdir()
    routes = _routes(d)
    defaults = sorted((m, dev, gw) for dev, dest, gw, mask, m, fl in routes if dest == "0.0.0.0" and mask == "0.0.0.0"
                      and fl & 1)
    dev = gw = None
    ip = _ip() if d == "/proc/net" else None
    if ip:
        out = (run_capped([ip, "-o", "route", "get", "1.1.1.1"], 16 << 10, 2.0) or b"").decode("utf-8", "replace")
        m = re.search(r"\bdev (\S+)", out)
        dev = m.group(1) if m and _ifname_ok(m.group(1)) else None
        m = re.search(r"\bvia (\d{1,3}(?:\.\d{1,3}){3})\b", out)
        gw = m.group(1) if m else None
    if dev is None and defaults:
        _, dev, gw = defaults[0]
    if dev is None:   # IPv6 only (or NAT64 without CLAT): online all the same, no IPv4 gateway (the identity: router_mac6)
        dev = _v6_dev(d, ip)
    if dev is None:
        return None
    tun = None
    if _is_tunnel(dev):
        phys = [(m, x, g) for m, x, g in defaults if not _is_tunnel(x)]
        if phys:
            tun, (_, dev, gw) = dev, phys[0]
        # else the tunnel is the line itself (PPPoE dialled on this machine, a box reached only through it): no VPN
    gw = gw if gw and gw != "0.0.0.0" else None
    import ipaddress
    nets = ["%s/%d" % (dest, bin(int.from_bytes(bytes(int(x) for x in mask.split(".")), "big")).count("1"))
            for x_dev, dest, g, mask, m, fl in routes if x_dev == dev and g == "0.0.0.0" and mask not in (None, "0.0.0.0")
            and dest]
    lans = ["%s/%d" % (dest, bin(int.from_bytes(bytes(int(x) for x in mask.split(".")), "big")).count("1"))
            for x_dev, dest, g, mask, m, fl in routes if x_dev == dev and g == "0.0.0.0" and mask not in (None, "0.0.0.0")
            and dest and not fl & 4]   # not a host route (DHCP adds one to the gateway: 192.168.178.1/32)
    subnet = lans[0] if lans else nets[0] if nets else None
    if gw:
        try:
            held = [ipaddress.ip_network(n, strict=False) for n in lans]
            held = [n for n in held if ipaddress.ip_address(gw) in n]
            subnet = str(max(held, key=lambda n: n.prefixlen)) if held else subnet
        except ValueError:
            pass
    v6, a6 = [], {dev: [], tun: []}
    for ln in (read(d + "/if_inet6", 64 << 10) or "").splitlines()[:1024]:
        t = ln.split()
        if len(t) == 6 and t[5] in a6 and re.fullmatch(r"[0-9a-f]{32}", t[0]) and re.fullmatch(r"[0-9a-f]{2}", t[2]):
            try:
                a = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(t[0]))
            except (ValueError, OSError):
                continue
            a6[t[5]].append(a)
            if t[5] == dev and t[3] == "00":  # global scope
                v6.append("%s/%d" % (a, int(t[2], 16)))
    out = {"if": dev, "tun": tun, "gw": gw, "subnet": subnet, "onlink": nets + v6,
           "addrs": _v4_addrs(dev, ip) + a6[dev][:64]}
    if tun:
        out["tun_addrs"] = _v4_addrs(tun, ip) + a6[tun][:64]
    return out


def net_bytes(ifname):
    """(bytes in, bytes out) of a device from /proc/net/dev, or None."""
    for ln in (read(_netdir() + "/dev", 64 << 10) or "").splitlines()[2:1024]:
        name, sep, rest = ln.partition(":")
        if sep and name.strip() == ifname:
            t = rest.split()
            if len(t) >= 9 and t[0].isdigit() and t[8].isdigit() and len(t[0]) <= 20 and len(t[8]) <= 20:
                return int(t[0]), int(t[8])
    return None


def ss_path():
    for p in ("/usr/bin/ss", "/usr/sbin/ss", "/bin/ss", "/sbin/ss"):
        if os.access(p, os.X_OK):
            return p
    return None


def net_flows(tun=None):
    """(`ss -tinpeHO`'s output or None, why: "timeout", "cap", "missing", "exit N"); `tun` is the macOS backend's concern. As root it keeps root (only root sees
    every socket's process); a test may hand over a recorded one with OOMPH_SS_FIXTURE, never to a process whose real
    user is root."""
    fx = os.environ.get("OOMPH_SS_FIXTURE")
    if fx and os.getuid() != 0:
        try:
            with open(fx, "rb") as f:
                data = f.read(SS_CAP + 1)
            return (data, None) if len(data) <= SS_CAP else (None, "cap")
        except OSError:
            return None, "missing"
    ss = ss_path()
    if ss is None or ROOT or _netdir() != "/proc/net":   # none, or in a namespace of its own: its sockets are not the host's
        return None, "missing"
    why = []
    out = run_capped([ss] + SS_ARGS, SS_CAP, SS_TIMEOUT, as_root=True, why=why)
    return (out, None) if out is not None else (None, why[0] if why else "missing")


@functools.lru_cache(maxsize=1)
def host_secret():
    """/etc/machine-id (or D-Bus's copy), or None: the salt of a network's public id (oomph_traffic.public_id). It
    never leaves the machine; machine.id is a hash of it."""
    for f in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        v = (read(f, 64) or "").strip()
        if re.fullmatch(r"[0-9a-f]{32}", v):
            return v
    return None


def router_mac(gw, ifname):
    """The gateway's MAC from /proc/net/arp (complete entries only: ATF_COM, a permanent one too), or None."""
    for ln in (read(_netdir() + "/arp", 256 << 10) or "").splitlines()[1:4096]:
        t = ln.split()
        if len(t) >= 6 and t[0] == gw and t[5] == ifname and re.fullmatch(r"0x[0-9a-fA-F]{1,4}", t[2]) and \
                int(t[2], 16) & 0x2:
            return t[3]
    return None


def _v6(x):
    """An IPv6 address without its %scope, normalised, or None."""
    import ipaddress
    try:
        return ipaddress.IPv6Address(str(x or "").partition("%")[0])
    except ValueError:
        return None


def router_mac6(ifname):
    """The IPv6 default router's MAC on that interface (`ip -6 route show default dev X` names it, `ip -6 neigh show
    dev X` holds its MAC), or None (no ip, or no netlink). Not any router: a Thread border router or a mesh
    repeater sends router advertisements on the LAN too."""
    ip = _ip() if _netdir() == "/proc/net" else None
    if not ip or not _ifname_ok(ifname):
        return None
    routes = (run_capped([ip, "-6", "route", "show", "default", "dev", ifname], 64 << 10, 2.0) or b"").decode(
        "utf-8", "replace")
    best = None   # the lowest metric's (the kernel's choice; ip lists it first anyway)
    for ln in routes.splitlines()[:256]:
        m = re.search(r"\bvia (\S+)", ln)
        gw = _v6(m.group(1)) if m else None
        met = re.search(r"\bmetric (\d{1,10})\b", ln)
        met = int(met.group(1)) if met else 0
        if gw is not None and (best is None or met < best[0]):
            best = (met, gw)
    if best is None:
        return None
    out = (run_capped([ip, "-6", "neigh", "show", "dev", ifname], 256 << 10, 2.0) or b"").decode(
        "utf-8", "replace")
    for ln in out.splitlines()[:4096]:
        t = ln.split()
        m = re.search(r"\blladdr (\S+)", ln)
        if t and m and _v6(t[0]) == best[1]:
            return m.group(1)
    return None


# ------------------------------------------------------------------ CPU, disks, I/O (03 §11.2)
# What the logger's Meter and Volumes turn into the sample's cpu, io and disks blocks, the same
# readings the Mac's backend gives (oomph_darwin.py lists the contract). World-readable files only.
@functools.lru_cache(maxsize=1)
def cpu_topology():
    """{"n", "p", "e", "e_ids"}: the logical cores /proc/stat counts (no performance and efficiency
    clusters on Linux in this version). Read once."""
    return {"n": len(cpu_ticks() or ()) or os.cpu_count() or 1, "p": None, "e": None, "e_ids": None}


def cpu_ticks():
    """Per core [user, system, idle, nice] ticks since boot, as the Mac's backend gives them: system
    holds irq and softirq, idle holds iowait and steal (time this machine did not have). None where
    /proc/stat cannot be read."""
    rows = []
    for line in (read("/proc/stat") or "").splitlines():
        if line.startswith("cpu") and line[3:4].isdigit():
            f = [_int(x, 0) for x in line.split()[1:9]] + [0] * 8
            user, nice, system, idle, iowait, irq, softirq, steal = f[:8]
            rows.append([user, system + irq + softirq, idle + iowait + steal, nice])
    return rows or None


_VIRTUAL_DISK = re.compile(r"(loop|ram|zram|dm-|md|nbd|sr|fd)\d")


def _phys_disks():
    """The names of /sys/block that are disks of their own: not a loop, RAM, zram, device-mapper, md
    or optical device (their bytes are a real disk's bytes once more, or no disk's)."""
    try:
        names = os.listdir(_p("/sys/block"))
    except OSError:
        return set()
    out = set()
    for n in names:
        try:
            virt = "/devices/virtual/" in os.path.realpath(_p("/sys/block/" + n))
        except OSError:
            virt = True
        if not virt and not _VIRTUAL_DISK.match(n):
            out.add(n)
    return out


def disk_bytes():
    """(read, written) bytes of every physical disk since boot, from /proc/diskstats (sectors of 512
    bytes, whatever the disk's own size): the sample's `io` block counts all processes, other users'
    included, which /proc/<pid>/io cannot. None where it cannot be read."""
    text = read("/proc/diskstats")
    if text is None:
        return None
    disks, r, w = _phys_disks(), 0, 0
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 10 and f[2] in disks:
            r, w = r + _int(f[5], 0) * 512, w + _int(f[9], 0) * 512
    return r, w


LOCAL_FS = frozenset(("ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs", "bcachefs", "jfs", "reiserfs", "nilfs2",
                      "vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "hfsplus"))
NETWORK_FS = frozenset(("nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "9p", "afs", "lustre", "davfs",
                        "virtiofs", "sshfs"))
SYSTEM_MOUNTS = ("/boot", "/efi", "/snap", "/var/lib/snapd", "/var/lib/docker", "/var/lib/containers", "/run", "/proc",
                 "/sys", "/dev")
MNT_RDONLY = 0x1
_OCTAL = re.compile(r"\\([0-7]{3})")


def _unoctal(s):
    """A path as mountinfo writes it: space, tab, newline and backslash as \\040, \\011, \\012, \\134."""
    return _OCTAL.sub(lambda m: chr(int(m.group(1), 8)), s)


STATVFS_FUSE_S = 2.0        # a FUSE disk's (ntfs-3g, exfat-fuse: fuseblk) statvfs waits on its daemon at most this long
STATVFS_BACKOFF_S = 60.0    # ... and after it did not answer in time, the mount is not asked again for this long
_statvfs_stuck = {}         # mount point -> (the thread asked last, not before when it is asked again)


def statvfs_bounded(path, fs):
    """os.statvfs, which for a FUSE file system goes to a daemon in user space: one that hangs would hang the
    logger with it (1.14.1). So for those it runs in a thread for at most STATVFS_FUSE_S; a mount that did not
    answer in time is not asked again while that thread still waits, nor for STATVFS_BACKOFF_S after (a slow one
    that answers in 3 s would otherwise cost every sample the full wait). Raises OSError (ETIMEDOUT)."""
    if not fs.startswith("fuse"):
        return os.statvfs(path)
    import threading
    t = _statvfs_stuck.get(path)
    if t is not None:
        if t[0].is_alive() or time.monotonic() < t[1]:
            raise OSError(errno.ETIMEDOUT, "statvfs still waiting or slow", path)
        del _statvfs_stuck[path]
    box = {}

    def ask():
        try:
            box["v"] = os.statvfs(path)
        except OSError as e:
            box["e"] = e
    t = threading.Thread(target=ask, name="statvfs", daemon=True)
    t.start()
    t.join(STATVFS_FUSE_S)
    if t.is_alive():
        _statvfs_stuck[path] = (t, time.monotonic() + STATVFS_BACKOFF_S)
        raise OSError(errno.ETIMEDOUT, "statvfs did not answer", path)
    if "e" in box:
        raise box["e"]
    return box["v"]


def mounts():
    """Every mount of /proc/self/mountinfo, the last one per mount point (what a path there reaches),
    as the Mac's records: mount, from, fs, flags (MNT_RDONLY when the file system itself is read-only:
    a sandbox's read-only view of a writable disk is not), dev (st_dev of files on it), majmin, and
    total_gb, free_gb (what df shows). statvfs is asked only for / and local disk file systems: a
    network mount whose server is gone would block it (a FUSE disk is waited for at most STATVFS_FUSE_S).
    None when the table cannot be read or has no /."""
    text = read("/proc/self/mountinfo")
    if not text:
        return None
    by = {}
    for line in text.splitlines():
        a, sep, b = line.partition(" - ")
        f, g = a.split(), b.split()
        if not sep or len(f) < 5 or len(g) < 2:
            continue
        mm = f[2].split(":")
        if len(mm) != 2 or not (mm[0].isdigit() and mm[1].isdigit()):
            continue
        mnt, src = _printable(_unoctal(f[4])), _printable(_unoctal(g[1]))
        by[mnt] = {"mount": mnt, "from": src, "fs": g[0][:32],
                   "flags": MNT_RDONLY if "ro" in (g[2].split(",") if len(g) > 2 else ()) else 0,
                   "dev": os.makedev(int(mm[0]), int(mm[1])) & 0xFFFFFFFF, "majmin": "%d:%d" % (int(mm[0]), int(mm[1]))}
    out = []
    for r in by.values():
        if r["mount"] == "/" or (r["fs"] in LOCAL_FS and (r["from"].startswith("/dev/") or r["fs"] in ("zfs", "btrfs"))):
            try:
                v = statvfs_bounded(_p(r["mount"]) if ROOT else r["mount"], r["fs"])
            except OSError:
                continue
            size, free = v.f_blocks * v.f_frsize, v.f_bavail * v.f_frsize
            if size > 1 << 60 or free > size:
                if r["mount"] == "/":
                    return None
                continue
            r.update(total_gb=round(size / GB, 1), free_gb=round(free / GB, 1))
        out.append(r)
    return out if any(r["mount"] == "/" and "total_gb" in r for r in out) else None


def mount_key(rec):
    return "%s|%s|%s" % (rec.get("from"), rec.get("mount"), rec.get("dev"))


def _rawread(path, cap=4096):
    try:
        with open(path, "rb") as f:
            return f.read(cap).decode("utf-8", "replace")
    except OSError:
        return None


def _udev(majmin):
    """The file system's UUID and label as udev recorded them (/run/udev/data/b<maj>:<min>,
    world-readable; /dev/disk/by-uuid is not there inside the logger's sandbox)."""
    out = {}
    for line in (read("/run/udev/data/b" + majmin, 64 << 10) or "").splitlines():
        k, _, v = line.partition("=")
        if k in ("E:ID_FS_UUID", "E:ID_FS_LABEL"):
            out[k[2:]] = v.strip()
    return out


def _block_facts(majmin):
    """What sysfs says about a block device: removable (the disk's own flag), on USB. None for no device."""
    try:
        real = os.path.realpath(_p("/sys/dev/block/" + majmin))
    except OSError:
        return None
    if not os.path.isdir(real):
        return None
    disk = os.path.dirname(real) if os.path.exists(os.path.join(real, "partition")) else real
    return {"removable": (_rawread(os.path.join(disk, "removable")) or "").strip() == "1", "usb": "/usb" in real}


def volume_facts(dev):
    """The Mac's slow question (diskutil) has no counterpart: disk_pools reads sysfs and udev itself."""
    return None


def linux_floors(total):
    """(low, critical) GB of the system's pool on Linux: 5 % and 1 % of it, within 2..20 and 1..5 GB.
    Swap does not grow there (its size is fixed), so a small server's disk is not red at 19 GB (03 §11.2)."""
    t = total if isinstance(total, (int, float)) and total > 0 else 0.0
    return round(max(2.0, min(20.0, 0.05 * t)), 1), round(max(1.0, min(5.0, 0.01 * t)), 1)


def _pool(rec):
    """The device a mount's free space belongs to ("maj:min"): mountinfo's own, or for a file system
    with an anonymous device (btrfs, zfs: major 0) the device it is mounted from."""
    if not rec["majmin"].startswith("0:"):
        return rec["majmin"]
    base = os.path.basename(rec["from"]) if rec["from"].startswith("/dev/") else ""
    mm = (read("/sys/class/block/%s/dev" % base, 64) or "").strip() if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", base) else ""
    return mm if re.fullmatch(r"\d+:\d+", mm) else rec["majmin"]


def _classify(r, pool, data_pool):
    fs, mnt = r.get("fs") or "", r["mount"]
    if mnt == "/" or (pool == data_pool and not r["flags"] & MNT_RDONLY):
        return "watched", "the system's pool", "internal"
    if any(mnt == p or mnt.startswith(p + "/") for p in SYSTEM_MOUNTS):
        return "ignored", "part of the system", None
    if fs in NETWORK_FS or (fs.startswith("fuse.") and fs != "fuseblk"):
        return "ignored", "network file system", None
    if fs not in LOCAL_FS or "total_gb" not in r:
        return "ignored", "not a disk", None
    if r["flags"] & MNT_RDONLY:
        return "ignored", "read-only", None
    if r["from"].startswith("/dev/loop"):
        return "ignored", "disk image", None
    f = _block_facts(pool)
    if f and f["removable"]:
        return "ignored", "removable media", None
    if f and f["usb"]:
        return "listed", "external disk", "external"
    return "listed", "second internal disk", "internal"


def disk_pools(recs, facts=None):
    """(pools, rows) for `mounts()` records, as on the Mac (oomph_darwin.disk_pools): rows are every
    mount with its class; pools the system's pool (`data`: the file system of /, watched, with the floors
    of linux_floors) and every listed disk by its file system's UUID (`vol:<UUID>`), else `mnt:` and a
    hash of the mount point and `weak`. No mount waits for an answer here (no class `pending`)."""
    root = next((r for r in recs if r["mount"] == "/"), None)
    data_pool = _pool(root) if root else None
    rows, listed = [], {}
    for r in sorted(recs, key=lambda r: r["mount"]):
        pool = _pool(r)
        cls, why, kind = _classify(r, pool, data_pool)
        u = _udev(pool) if cls == "listed" else {}
        rows.append(dict(r, pool=pool, cls=cls, why=why,
                         name=_printable(u.get("ID_FS_LABEL") or "")[:64] or os.path.basename(r["mount"]) or r["mount"]))
        if cls == "listed" and pool not in listed:
            uuid = u.get("ID_FS_UUID")
            uuid = uuid if isinstance(uuid, str) and re.fullmatch(r"[0-9A-Za-z-]{1,64}", uuid) else None
            p = {"id": "vol:" + uuid if uuid else _mount_id(r["mount"]), "name": rows[-1]["name"][:64],
                 "mount": r["mount"], "dev": pool, "fs": r["fs"], "total_gb": r["total_gb"], "free_gb": r["free_gb"],
                 "roles": [], "kind": kind, "watch": False}
            if not uuid:
                p["weak"] = True
            listed[pool] = p
    pools = []
    if root and "total_gb" in root:
        low, crit = linux_floors(root["total_gb"])
        free = root["free_gb"]
        roles = ["home"] if not any(r["mount"] == "/home" for r in recs) else []
        pools.append({"id": "data", "name": "System", "mount": "/", "dev": data_pool, "fs": root["fs"],
                      "total_gb": root["total_gb"], "free_gb": free, "roles": roles + ["tmp"], "watch": True,
                      "low_gb": low, "crit_gb": crit, "level": "critical" if free < crit else "low" if free < low else "ok"})
    return pools + list(listed.values()), rows


def _mount_id(mount):
    return "mnt:" + hashlib.sha256(mount.encode("utf-8", "surrogateescape")).hexdigest()[:16]


# ------------------------------------------------------------------ NVIDIA cards (roadmap §11: utilisation and memory per card and per process)
# Read with nvidia-smi, a program of its own: no GPU library is ever loaded into an oomph process,
# and when the caller is root the program runs as nobody (the device files are 0666; nothing else is
# needed). The logger itself is never root on Linux. A machine without nvidia-smi has no `gpu` block.
NVIDIA_SMI = "/usr/bin/nvidia-smi"
NV_QUERY = ["--query-gpu=index,uuid,name,utilization.gpu,memory.total,memory.used,memory.free,display_active,"
            "mig.mode.current", "--format=csv,noheader,nounits"]   # 1.14: free memory and the modes, for the pools
NV_QUERY_OLD = ["--query-gpu=index,uuid,name,utilization.gpu,memory.total,memory.used", "--format=csv,noheader,nounits"]
NV_PMON = ["pmon", "-c", "1", "-s", "um"]
NV_APPS = ["--query-compute-apps=gpu_uuid,pid,used_memory", "--format=csv,noheader,nounits"]
NV_RETRY_S = 600         # nvidia-smi missing or failing: asked again after this long
NV_TIMEOUT_S = 4.0       # one run of nvidia-smi
NV_HUNG_RETRY_S = 60     # nvidia-smi that did not answer the long question in time (a busy driver): asked again sooner
NV_PROCS = 16            # processes kept per card
_nv = {"off_until": 0.0, "old_until": 0.0}  # old_until: a driver that did not know a field of NV_QUERY


def _nobody():
    """subprocess arguments that make a child of root nobody, with no other groups (03 §12.3: nothing runs
    as root that does not have to); none for anyone else. Resolved here, in the parent: a lookup in the
    forked child of a threaded process can deadlock on a lock another thread held."""
    if os.geteuid() != 0:
        return {}
    import pwd
    try:
        pw = pwd.getpwnam("nobody")
        uid, gid = pw.pw_uid, pw.pw_gid
    except KeyError:
        uid = gid = 65534
    return {"user": uid, "group": gid, "extra_groups": []}


def run_capped(cmd, cap, timeout, tail=False, rc=None, as_root=False, why=None):
    """stdout of `cmd` (bytes), at most `cap` of them within `timeout` seconds, else None; as nobody
    when this process is root (unless `as_root`: ss names the processes of other users only to root). With `tail`,
    more than `cap` (or the deadline) keeps the last whole lines within `cap` instead. `rc`, a list, gets the
    child's exit status when it ended by itself within both (a timeout or too much output adds nothing); `why`, a
    list, gets "missing", "timeout", "cap" or "exit N" (the child's status, not 0) when the answer is None for one of
    those. The child is always reaped."""
    import collections
    import select
    import subprocess
    why = why if why is not None else []
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/",
                             env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
                             **({} if as_root else _nobody()))
    except OSError:
        why.append("missing")
        return None
    out, n, cut, deadline = collections.deque(), 0, False, time.monotonic() + timeout
    fd = p.stdout.fileno()

    def kept():
        b = b"".join(out)
        return b[b.find(b"\n") + 1:] if cut else b   # a line cut at its front is dropped whole
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([fd], [], [], left)[0]:
                why.append("timeout")
                return kept() if tail else None
            b = os.read(fd, 1 << 16)
            if not b:
                break
            n += len(b)
            out.append(b)
            while n > cap:
                if not tail:
                    why.append("cap")
                    return None
                cut, drop = True, out.popleft()
                n -= len(drop)
                if n < cap:                           # keep what of it still fits
                    out.appendleft(drop[n - cap:])
                    n = cap
        p.wait(max(0.01, deadline - time.monotonic()))
        if rc is not None:
            rc.append(p.returncode)
        if p.returncode == 0 or (tail and out):
            return kept()
        why.append("exit %d" % p.returncode)
        return None
    except (OSError, subprocess.TimeoutExpired):
        return kept() if tail and out else None
    finally:
        if p.returncode is None:
            p.kill()
            try:
                p.wait(2)
            except subprocess.TimeoutExpired:
                pass
        p.stdout.close()


def _num_or_none(x):
    try:
        v = float(x)
    except (TypeError, ValueError):
        return None
    return v if math.isfinite(v) and 0 <= v < 1e9 else None


_NV_UUID = re.compile(r"GPU-[0-9a-fA-F-]{8,60}")


def parse_nvidia_gpus(text, tail=6):
    """The cards of `nvidia-smi --query-gpu=<NV_QUERY's fields> --format=csv,noheader,nounits`: [{index, uuid,
    name, util (%), total_mb, used_mb, and from NV_QUERY's longer form free_mb, display (a desktop on it), mig
    (MIG mode on)}], a figure None where the driver says "[N/A]" or "[Not Supported]". `tail`: the fields
    after the name (6 for NV_QUERY, 3 for NV_QUERY_OLD); a name may hold commas. The name is the driver's,
    cut and cleaned."""
    out = []
    for line in (text or "").splitlines():
        f = [x.strip() for x in line.split(",")]
        if len(f) < 3 + tail or not f[0].isdigit():
            continue
        num = f[-tail:]
        c = {"index": int(f[0]), "uuid": f[1] if _NV_UUID.fullmatch(f[1]) else None,
             "name": _printable(",".join(f[2:-tail]).strip())[:64] or "NVIDIA GPU", "util": _num_or_none(num[0]),
             "total_mb": _num_or_none(num[1]), "used_mb": _num_or_none(num[2])}
        if tail >= 6:
            c.update(free_mb=_num_or_none(num[3]), display=num[4].lower() == "enabled", mig=num[5].lower() == "enabled")
        out.append(c)
    return out[:16]


def parse_nvidia_pmon(text):
    """{card index: {pid: {"sm": %, "mb": MB}}} from `nvidia-smi pmon -c 1 -s um`, by the column names
    of its header line (they differ between drivers); "-" is a figure nobody measured. A process that
    uses a card for compute and graphics has two rows: they add up. None when there is no header."""
    cols, out = None, {}
    for line in (text or "").splitlines():
        if line.startswith("#"):
            h = line[1:].split()
            if "gpu" in h and "pid" in h and cols is None:
                cols = h
            continue
        f = line.split()
        if not cols or len(f) < cols.index("pid") + 1:
            continue
        row = dict(zip(cols, f))
        gi, pid = _int(row.get("gpu")), _int(row.get("pid"))
        if gi is None or pid is None or pid <= 0:
            continue
        e = out.setdefault(gi, {}).setdefault(pid, {})
        for k, col in (("sm", "sm"), ("mb", "fb")):
            v = _num_or_none(row.get(col))
            if v is not None:
                e[k] = e.get(k, 0.0) + v
    return out if cols else None


def parse_nvidia_apps(text):
    """{card uuid: {pid: MB}} from `nvidia-smi --query-compute-apps=gpu_uuid,pid,used_memory
    --format=csv,noheader,nounits`: the fallback for memory per process where pmon gives none."""
    out = {}
    for line in (text or "").splitlines():
        f = [x.strip() for x in line.split(",")]
        if len(f) >= 3 and _NV_UUID.fullmatch(f[0]) and f[1].isdigit():
            mb = _num_or_none(f[2])
            if mb is not None:
                d = out.setdefault(f[0], {})
                d[int(f[1])] = d.get(int(f[1]), 0.0) + mb
    return out


def _nvsmi(args, rc=None):
    raw = run_capped([_p(NVIDIA_SMI)] + args, 256 << 10, NV_TIMEOUT_S, rc=rc)
    return raw.decode("utf-8", "replace") if raw is not None else None


def gpu_cards(fresh=False):
    """The NVIDIA cards with what each process uses of them: [{index, uuid, name, util, total_mb,
    used_mb, free_mb, display, mig, procs {pid: {"sm", "mb"}}}], two short runs of nvidia-smi (30 and 100 ms on the Epyc's two
    RTX 4090). None where there is no nvidia-smi or it lists no card (asked again after NV_RETRY_S). `fresh` (admission,
    02 §6.5.1): asks now whatever failed before, the long form first, so that one passing failure in a long-lived
    process (the MCP server) does not refuse GPU requests for NV_RETRY_S. The short form only for a driver that
    refused the long one (it ended by itself: exit 2, "is not a valid field", or no line it could read): a timeout
    or another failure says nothing about the fields, and the cards then stay unread rather than lose free memory."""
    now = time.monotonic()
    if fresh:
        _nv["off_until"] = _nv["old_until"] = 0.0
    if now < _nv["off_until"]:
        return None
    if not os.access(_p(NVIDIA_SMI), os.X_OK):
        _nv["off_until"] = now + NV_RETRY_S
        return None
    rc, cards = [0], None
    if now >= _nv["old_until"]:
        rc = []
        cards = parse_nvidia_gpus(_nvsmi(NV_QUERY, rc))
    if not cards and rc and rc[0] in (0, 2):  # a driver older than a field of the long form refuses it: the short one
        cards = parse_nvidia_gpus(_nvsmi(NV_QUERY_OLD), 3)
        if cards:
            _nv["old_until"] = now + NV_RETRY_S
    if not cards:
        _nv["off_until"] = now + (NV_RETRY_S if rc else NV_HUNG_RETRY_S)
        return None
    per = parse_nvidia_pmon(_nvsmi(NV_PMON))
    if per is None:  # a driver without pmon: memory per process from the compute apps, no utilisation
        apps = parse_nvidia_apps(_nvsmi(NV_APPS))
        per = {c["index"]: {pid: {"mb": mb} for pid, mb in apps.get(c["uuid"], {}).items()} for c in cards}
    for c in cards:
        c["procs"] = dict(sorted((per.get(c["index"]) or {}).items(), key=lambda kv: -kv[1].get("mb", 0))[:NV_PROCS])
    return cards


def card_sample(c, procs):
    """A card of gpu_cards() as the sample's `gpu` block has it (the logger's and a live read's alike): id
    "gpu<index>" (nvidia-smi's index: PCI bus order, only a label), uuid (the card's identity), name, busy time,
    memory used, free and on the card (GB), the driver's own part (`mem_reserved_gb` = total − used − free),
    `display` and `mig` where on, and the processes on it biggest first (`procs`: pid, name from `procs`,
    never from the driver, MB, SM share). The roadmap's 02 §6.5.1 pools are made from these."""
    g = {"id": "gpu%d" % c["index"], "index": c["index"], "name": c["name"], "unified": False, "src": "nvidia-smi"}
    if c.get("util") is not None:
        g["util"] = g["now"] = round(c["util"], 1)
    if c.get("used_mb") is not None:
        g["mem_gb"] = round(c["used_mb"] / 1024.0, 2)
    if c.get("total_mb"):
        g["mem_limit_gb"] = round(c["total_mb"] / 1024.0, 1)
        g["mem_total_gb"] = round(c["total_mb"] / 1024.0, 2)
    if c.get("free_mb") is not None:
        g["mem_free_gb"] = round(c["free_mb"] / 1024.0, 2)
        if c.get("total_mb") and c.get("used_mb") is not None:
            g["mem_reserved_gb"] = round(max(0.0, c["total_mb"] - c["used_mb"] - c["free_mb"]) / 1024.0, 2)
    for k in ("display", "mig"):
        if c.get(k):
            g[k] = True
    if c.get("uuid"):
        g["uuid"] = c["uuid"]
    rows = []
    for pid, x in (c.get("procs") or {}).items():
        p = procs.get(pid) if procs else None
        e = {"pid": pid, "name": p["name"] if p else None}
        if x.get("mb") is not None:
            e["mb"] = round(x["mb"])
        if x.get("sm") is not None:
            e["util"] = round(x["sm"], 1)
        rows.append({k: v for k, v in e.items() if v is not None})
    if rows:
        g["procs"] = rows
    return g


def gpu_available():
    """Is there an nvidia-smi to ask (for `measures`): no run, just the file."""
    return os.access(_p(NVIDIA_SMI), os.X_OK)


# ------------------------------------------------------------------ kills (03 §5.5, Appendix B, C.3 rows 8 to 13, 32, 33)
# The kernel's OOM lines, systemd-oomd's and earlyoom's, from one `journalctl -f -o json` child: the
# logger is in group systemd-journal and holds no capability. Patterns from the kernel's format
# strings, checked against the lines the fact spike captured on 4.18 to 7.0. Names in them are
# chosen by whoever named the process: cut and cleaned before they are stored.
JOURNALCTL = "/usr/bin/journalctl"
JOURNAL_MATCH = ["_TRANSPORT=kernel", "+", "_SYSTEMD_UNIT=systemd-oomd.service", "+", "_SYSTEMD_UNIT=earlyoom.service"]
INVOKED = re.compile(r"^(?P<who>.+) invoked oom-killer: gfp_mask=(?P<gfp>0x[0-9a-f]+)\(.*?\), "
                     r"(?:nodemask=\S+, )?order=(?P<order>-?\d+), oom_score_adj=(?P<adj>-?\d+)")
SUMMARY = re.compile(r"^oom-kill:constraint=(?P<constraint>CONSTRAINT_\w+),nodemask=[^,]*(?:,[^,=]+=[^,]*)*?"
                     r",(?:oom_memcg=(?P<memcg>.+?)|global_oom),task_memcg=(?P<task_cg>.+?)"
                     r",task=(?P<name>.+),pid=(?P<pid>\d+),uid=(?P<uid>\d+)$")
KILLED = re.compile(r"^(?:(?P<what>Memory cgroup out of memory|Out of memory(?: \(oom_kill_allocating_task\))?): )?"
                    r"Killed process (?P<pid>\d+) \((?P<name>.+)\),? total-vm:(?P<vm>\d+)kB, anon-rss:(?P<anon>\d+)kB, "
                    r"file-rss:(?P<file>\d+)kB(?:, shmem-rss:(?P<shmem>\d+)kB)?(?:, UID:(?P<uid>\d+))?")
KILL_OLD = re.compile(r"^(?P<what>Memory cgroup out of memory|Out of memory(?: \(oom_kill_allocating_task\))?): "
                      r"Kill process (?P<pid>\d+) \((?P<name>.+)\) score \d+ or sacrifice child")
OOMD_P = re.compile(r"^Killed (?P<cg>\S+) due to memory pressure for (?P<mon>\S+) being (?P<pct>[\d.]+)% > (?P<lim>[\d.]+)%")
OOMD_S = re.compile(r"^Killed (?P<cg>\S+) due to memory used \((?P<used>\d+)\) / total \((?P<total>\d+)\) and swap used ")
EARLY = re.compile(r'^sending (?P<sig>SIGTERM|SIGKILL) to process (?P<pid>\d+) uid (?P<uid>\d+) "(?P<name>.*?)": ')
REAPED = re.compile(r"^oom_reaper: reaped process \d+|^Tasks in \S+ are going to be killed due to memory\.oom\.group set")
OTHER_MEM = re.compile(r"page allocation failure|blocked for more than \d+ seconds")
_CURSOR = re.compile(r"[A-Za-z0-9=;_-]{1,512}")
LINE_MAX = 64 << 10      # a journal entry longer than this is not one of ours: skipped
MACHINE_WIDE = ("kernel", "systemd-oomd", "earlyoom")


def journal_message(e):
    """The MESSAGE of a journal entry as text: `journalctl -o json` writes a string, or a list of byte
    values where the text is not UTF-8; None for anything else."""
    m = e.get("MESSAGE") if isinstance(e, dict) else None
    if isinstance(m, str):
        return m
    if isinstance(m, list) and len(m) <= LINE_MAX and all(isinstance(x, int) and 0 <= x < 256 for x in m):
        return bytes(m).decode("utf-8", "replace")
    return None


def _clean(name, n=64):
    return _printable(str(name).strip())[:n]


def headline(fmt, name, *rest, width=44):
    """An incident headline of at most `width` characters (03 §3.12): the name is what gives way."""
    whole = fmt % ((name,) + rest)
    if len(whole) <= width:
        return whole
    room = max(1, len(name) - (len(whole) - width) - 1)
    return fmt % ((name[:room] + "…",) + rest)


def kill_headline(v):
    """The headline of a machine-wide kill, at most 44 characters (03 §6.3): "OOM killer killed node (pid
    48211, 2.1 GB)", "systemd-oomd killed firefox (3.4 GB)"; the pid goes first, then the name is cut."""
    size = _gb_text(v["mb"]) if v.get("mb") else None
    who = "OOM killer" if v["by"] == "kernel" else v["by"]
    tails = ([" (pid %d, %s)" % (v["pid"], size)] if size and v.get("pid") and v["by"] == "kernel" else []) + \
        [" (%s)" % size if size else " (pid %d)" % v["pid"] if v.get("pid") else ""]
    for tail in tails:
        if len("%s killed %s%s" % (who, v["name"], tail)) <= 44:
            return "%s killed %s%s" % (who, v["name"], tail)
    return headline("%s killed %%s%s" % (who, tails[-1].replace("%", "%%")), v["name"])


def _gb_text(mb):
    return "%.1f GB" % (mb / 1024.0) if mb >= 102.4 else "%d MB" % round(mb)


class KillWatcher:
    """The kill watcher of the Linux logger (03 §5.5). One thread follows the journal; the sampler
    calls flush() once per sample and gets what was killed since the last one.

    Rules, from the fact spike (03 Appendix C.3):
      one victim, one count   a group kill reports its chosen victim twice (row 9), earlyoom may send
                              SIGTERM and then SIGKILL: a (killer, pid) seen in the last 30 s is the
                              same victim, updated, not counted again.
      the class               from the prefix of the kill line ("Memory cgroup out of memory" or "Out of
                              memory") on every kernel: summaries are rate-limited, kill lines are not.
      OOM events              a summary line, or a run of kill lines of one class and cgroup within a
                              second that no summary preceded; a cgroup with 5 in 10 minutes is a storm.
      the cursor              only that of an entry this watcher read with its own filter, so the next
                              start resumes exactly after it (row 13: systemd 249 drops the first match
                              after a foreign cursor). The first start ever reads this boot from its
                              beginning, without counting what happened before the logger started: told
                              by the entry's monotonic time of this boot (a wall clock stepped back after
                              the start, as NTP does at boot, would hide every kill until it caught up),
                              and only until the first entry from after the start.
      lost records            the kernel's own counter (/proc/vmstat oom_kill) against the kill lines read,
                              before de-duplication (it counts a group's repeated victim too); a difference
                              that stays LOST_S (30 s: journald lags under memory pressure, and a sample may be
                              5 s apart) is recorded as `unknown`, and only that much of it.
      hidepid                 where /proc hides other accounts' processes from the logger, it does not name them
                              either (03 §5.6): another account's victim is "?", with no pid, account or
                              cgroup, and so is a storm in another account's slice; sizes and counts stay.
    Without a journal it can read (no systemd, not in group systemd-journal) it counts: the counter's
    delta, classified by the level (`count` mode). State (cursor, counter, boot) is kept in state.json
    in the logger's state folder, written at most once per sample."""
    VICTIM_S = 30.0
    LOST_S = 30.0
    EVENT_S = 1.0
    STORM_N, STORM_S = 5, 600
    VICTIMS_MAX = 15
    HISTORY_S = 60.0
    RETRY_S = 5.0
    COUNT_RETRY_S = 600.0

    def __init__(self, state_dir=None, trigger=None, storm=None, event=None, journalctl=None, now=time.time,
                 mono=time.monotonic):
        import threading
        self.state_path = os.path.join(state_dir, "state.json") if state_dir else None
        self.trigger = trigger or (lambda kind, msg: None)
        self.storm = storm or (lambda name, ooms, cg: None)
        self.event = event or (lambda kind, **kw: None)
        self.journalctl = journalctl or _p(JOURNALCTL)
        self.now, self.mono = now, mono       # mono: CLOCK_MONOTONIC, the journal's __MONOTONIC_TIMESTAMP
        self.lock = threading.Lock()
        self.started, self.last_t = now(), None
        self.started_m, self.last_m = mono(), None
        self.procs = {}
        st = self._load()
        self.boot = boot_id()
        cnt = _vmstat().get("oom_kill")
        self.cursor = st.get("cursor") if st.get("cursor") and _CURSOR.fullmatch(str(st.get("cursor"))) else None
        self.fresh = self.cursor is None
        if st.get("boot") == self.boot and isinstance(st.get("oom_kill"), int) and cnt is not None and st["oom_kill"] <= cnt:
            self.base = st["oom_kill"]            # a restart: what happened meanwhile is counted, once
        elif st.get("boot") and st.get("boot") != self.boot and self.cursor:
            self.base = 0                         # a new boot: its kills are in the journal after the cursor
        else:
            self.base = cnt                       # the first start: nothing before it is counted
        self.acc, self.pending = 0, None          # kernel kill lines read since `base`; (a difference, since when)
        self.victims, self.seen, self.storms = [], {}, {}
        self.ooms, self.ev, self.summ, self.old = 0, None, None, {}
        self.mode = "journal" if self._can_journal() else "count"
        self.proc, self.stopping, self.saved, self.thread = None, False, None, None
        self.hide = os.geteuid() != 0 and hidepid() != "0"

    def _hidden(self, v):
        """A victim as this machine lets the logger see it: under hidepid another account's is only a size."""
        if not self.hide or (v.get("uid") is not None and v.get("uid") == os.getuid()):
            return v
        return dict({k: x for k, x in v.items() if k in ("mb", "rss_mb", "constraint", "sig")}, name="?")

    def _own_slice(self, cg):
        """Is cgroup `cg` none of another account's (user-<uid>.slice)?"""
        m = re.search(r"/user-(\d+)\.slice(?:/|$)", cg or "")
        return not m or int(m.group(1)) == os.getuid()

    def _load(self):
        if not self.state_path:
            return {}
        try:
            with open(self.state_path, "rb") as f:
                d = __import__("json").loads(f.read(64 << 10).decode("utf-8"))
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _can_journal(self):
        return os.access(self.journalctl, os.X_OK) and os.path.isdir(_p("/run/systemd/system"))

    # -- the thread
    def start(self):
        import threading
        if self.mode == "journal":
            self.thread = threading.Thread(target=self.loop, name="kills", daemon=True)
            self.thread.start()
        return self

    def stop(self):
        self.stopping = True
        p = self.proc
        if p is not None and p.poll() is None:
            try:
                p.terminate()
            except OSError:
                pass

    def command(self):
        """The journalctl command line: after the stored cursor, else this boot from its start."""
        with self.lock:
            c = self.cursor
        return [self.journalctl, "-f", "-q", "--no-pager", "-o", "json"] + \
            (["--after-cursor=" + c] if c else ["-b", "--no-tail"]) + JOURNAL_MATCH

    def loop(self):
        import subprocess
        fails = 0
        while not self.stopping:
            t0, n = time.monotonic(), 0
            try:
                p = self.proc = subprocess.Popen(self.command(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                 stderr=subprocess.DEVNULL, cwd="/",
                                                 env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SYSTEMD_COLORS": "0"})
            except OSError as e:
                self.mode = "count"
                self.event("daemon_error", where="kills", error="journalctl: %s" % e)
                time.sleep(self.COUNT_RETRY_S)
                continue
            for line in _lines(p.stdout, LINE_MAX):
                n += 1
                try:
                    self.feed(line)
                except Exception as e:  # one entry that breaks the parser costs that entry
                    self.event("daemon_error", where="kills", error=repr(e)[:300])
            rc = p.wait()
            p.stdout.close()
            if self.stopping:
                break
            if n == 0 and rc != 0 and time.monotonic() - t0 < 10:
                with self.lock:
                    stale = self.cursor is not None
                    if stale and fails == 0:  # a cursor the journal no longer has (vacuumed), or journald was away:
                        # this boot from its start, nothing up to the last line handled counted again (what the
                        # journal lost meanwhile the kernel's counter still finds)
                        self.cursor, self.fresh = None, True
                        self.started = self.last_t + self.HISTORY_S + 1e-3 if self.last_t else self.now()
                        self.started_m = self.last_m + self.HISTORY_S + 1e-3 if self.last_m else \
                            None if self.last_t else self.mono()    # (None: told by the wall clock, as last_t)
                fails += 1
                if fails >= 3:
                    self.mode = "count"
                    self.event("daemon_error", where="kills", error="journalctl exits with %s: kills are counted, "
                               "not named (is the logger in group systemd-journal?)" % rc)
                    time.sleep(self.COUNT_RETRY_S)
                    fails = 0
                    continue
            else:
                fails = 0
                if n:
                    self.mode = "journal"
            time.sleep(self.RETRY_S)

    def feed(self, line):
        """One line of `journalctl -o json`."""
        e = __import__("json").loads(line)
        if not isinstance(e, dict):
            return
        msg = journal_message(e)
        try:
            t = int(e.get("__REALTIME_TIMESTAMP")) / 1e6
        except (TypeError, ValueError):
            t = self.now()
        m = None                          # its monotonic time, when it is of this boot
        if self.boot and e.get("_BOOT_ID") == self.boot.replace("-", ""):
            try:
                m = int(e.get("__MONOTONIC_TIMESTAMP")) / 1e6
            except (TypeError, ValueError):
                m = None
        cur = e.get("__CURSOR")
        before = False
        if self.fresh:                    # the first start (or a lost cursor): this boot's past is not counted
            x, ref = (m, self.started_m) if m is not None and self.started_m is not None else (t, self.started)
            before = x < ref - self.HISTORY_S
            if x >= ref:
                self.fresh = False        # the past is read: from here on every entry counts
        if msg is not None and not before:
            unit = e.get("_SYSTEMD_UNIT") if isinstance(e.get("_SYSTEMD_UNIT"), str) else ""
            self.handle(msg, unit, t)
        if isinstance(cur, str) and _CURSOR.fullmatch(cur):
            with self.lock:
                self.cursor, self.last_t, self.last_m = cur, t, m

    # -- the lines
    def handle(self, msg, unit, t):
        """One journal line: a victim, a summary, or nothing of ours."""
        msg = msg.strip()
        if unit == "systemd-oomd.service":
            m = OOMD_P.match(msg) or OOMD_S.match(msg)
            if m:
                cg = _clean(m.group("cg"), 200)
                name = group_of_cgroup(cg) or os.path.basename(cg) or cg
                mb = sum(p["fp"] for p in self.procs.values() if p.get("cg") == cg or (p.get("cg") or "").startswith(cg + "/")) / MB
                self._victim(t, "systemd-oomd", cg, {"name": _clean(name), "cg": cg, "mb": round(mb)})
            return
        if unit == "earlyoom.service":
            m = EARLY.match(msg)
            if m:
                pid = int(m.group("pid"))
                p = self.procs.get(pid) or {}
                rss = re.search(r"VmRSS (\d+) MiB", msg)
                self._victim(t, "earlyoom", pid, {"name": _clean(m.group("name")), "pid": pid, "uid": int(m.group("uid")),
                                                  "mb": int(rss.group(1)) if rss else round(p.get("fp", 0) / MB),
                                                  "sig": m.group("sig"), "cg": p.get("cg")})
            return
        m = SUMMARY.match(msg)
        if m:
            cls = "cgroup" if m.group("constraint") == "CONSTRAINT_MEMCG" else "kernel"
            cg = _clean(m.group("memcg") if cls == "cgroup" and m.group("memcg") else m.group("task_cg"), 200)
            with self.lock:
                self.summ = (t, cls, cg, m.group("constraint"))
            self._oom_event(t, cls, cg, summary=True)
            return
        m = KILL_OLD.match(msg)
        if m:
            with self.lock:   # waits a second for its "Killed process" line; one that never comes is dropped
                self.old = {k: v for k, v in self.old.items() if 0 <= t - v[0] <= self.EVENT_S}
                self.old[int(m.group("pid"))] = (t, m.group("what"))
            return
        m = KILLED.match(msg)
        if not m:
            return
        pid = int(m.group("pid"))
        with self.lock:
            self.acc += 1                         # a kernel kill line, before de-duplication (the counter's unit)
            what = m.group("what")
            old = self.old.pop(pid, None)
            summ = self.summ if self.summ and 0 <= t - self.summ[0] <= self.EVENT_S else None
        if what is None and old and t - old[0] <= self.EVENT_S:
            what = old[1]
        if what is not None:
            cls = "cgroup" if what.startswith("Memory cgroup") else "kernel"
        else:
            cls = summ[1] if summ else "kernel"
        p = self.procs.get(pid) or {}
        cg = summ[2] if summ and summ[1] == cls else p.get("cg") or ""
        if not summ or summ[1] != cls:
            self._oom_event(t, cls, cg)
        else:
            with self.lock:
                if self.ev:
                    self.ev[2] = t
        anon, shmem, filerss = int(m.group("anon")), int(m.group("shmem") or 0), int(m.group("file"))
        self._victim(t, "cgroup" if cls == "cgroup" else "kernel", pid, {
            "name": _clean(m.group("name")), "pid": pid, "uid": int(m.group("uid")) if m.group("uid") else p.get("uid"),
            "mb": round((anon + shmem) / 1024.0), "rss_mb": round((anon + shmem + filerss) / 1024.0),
            "constraint": "memcg" if cls == "cgroup" else "none", "cg": cg or None})

    def _oom_event(self, t, cls, cg, summary=False):
        """Count an invocation of the killer: a summary is one; kill lines of one class and cgroup within a
        second of each other, with no summary, are one."""
        with self.lock:
            ev = self.ev
            if not summary and ev and ev[0] == cls and ev[1] == cg and 0 <= t - ev[2] <= self.EVENT_S:
                ev[2] = t
                return
            self.ev = [cls, cg, t]
            self.ooms += 1
            if cls != "cgroup" or not cg:
                return
            times = [x for x in self.storms.get(cg, ()) if t - x <= self.STORM_S] + [t]
            self.storms[cg] = times[-64:]
            for k in [k for k, v in self.storms.items() if t - v[-1] > self.STORM_S]:
                del self.storms[k]
            n = len(times)
        if n >= self.STORM_N:
            if self.hide and not self._own_slice(cg):
                self.storm("?", n, "?")
            else:
                self.storm(group_of_cgroup(cg) or cg.rsplit("/", 1)[-1] or cg, n, cg)

    def _victim(self, t, by, key, v):
        v = self._hidden(v)
        with self.lock:
            k = (by, key)
            old = self.seen.get(k)
            if old and 0 <= t - old[0] <= self.VICTIM_S:
                old[0] = t
                if v.get("sig"):
                    old[1]["sig"] = v["sig"]
                return
            if len(self.seen) > 4096:
                self.seen = {a: b for a, b in self.seen.items() if t - b[0] <= self.VICTIM_S}
            v = {a: b for a, b in v.items() if b is not None}
            v.update(by=by, t=round(t, 1))
            self.seen[k] = [t, v]
            self.victims.append(v)
            del self.victims[:-256]
        if by in MACHINE_WIDE:
            self.trigger("oom" if by == "kernel" else "oomd", kill_headline(v))

    # -- once per sample
    def flush(self, level=1, procs=None):
        """What was killed since the last flush: {"kills": machine-wide victims, "cgroup": victims at a
        cgroup's limit, "ooms", "by": {killer: n}, "top": {name: n}, "victims": [...] (biggest first, at
        most 15)}. `level`: the machine's level in this or the last sample (unexplained kills count as
        machine-wide at warning or above); `procs`: this sample's processes, for the next lines."""
        if procs is not None:
            self.procs = procs
        cnt = _vmstat().get("oom_kill")
        with self.lock:
            victims, self.victims = self.victims, []
            ooms, self.ooms = self.ooms, 0
            unknown = 0
            if cnt is not None:
                if self.base is None or cnt < self.base:
                    self.base, self.acc, self.pending = cnt, 0, None
                gap, now = cnt - self.base - self.acc, self.now()
                if self.mode == "count":  # (less what lines were read before the journal stopped answering)
                    unknown, self.base, self.acc, self.pending = max(0, gap), cnt, 0, None
                elif gap > 0 and self.pending and now - self.pending[1] >= self.LOST_S:
                    unknown = min(gap, self.pending[0])  # what stayed missing that long; the rest waits its turn
                    self.base += unknown
                    self.pending = (gap - unknown, now) if gap > unknown else None
                elif gap > 0:
                    self.pending = (min(gap, self.pending[0]), self.pending[1]) if self.pending else (gap, now)
                else:
                    self.base, self.acc, self.pending = cnt, 0, None
            state = {"boot": self.boot, "cursor": self.cursor,
                     "oom_kill": (self.base + self.acc) if self.base is not None else None}
        by, top = {}, {}
        for v in victims:
            by[v["by"]] = by.get(v["by"], 0) + 1
            top[v["name"]] = top.get(v["name"], 0) + 1
        machine = sum(n for k, n in by.items() if k in MACHINE_WIDE)
        cgroup = by.get("cgroup", 0)
        if unknown:
            by["unknown"] = unknown
            if (level or 0) >= 2:
                machine += unknown
            else:
                cgroup += unknown
        self._save(state)
        victims.sort(key=lambda v: -(v.get("mb") or 0))
        return {"kills": machine, "cgroup": cgroup, "ooms": max(ooms, 1 if unknown else 0) if (victims or unknown) else 0,
                "by": by, "top": dict(sorted(top.items(), key=lambda kv: -kv[1])[:15]), "victims": victims[:self.VICTIMS_MAX]}

    def _save(self, state):
        if not self.state_path or state == self.saved:
            return
        try:
            tmp = "%s.%d.tmp" % (self.state_path, os.getpid())
            with open(tmp, "w") as f:
                f.write(__import__("json").dumps(state))
            os.replace(tmp, self.state_path)
            self.saved = state
        except OSError as e:
            self.event("daemon_error", where="kills", error="state: %s" % e)

    def status(self):
        return self.mode


def _lines(f, cap):
    """The lines of a binary pipe, each at most `cap` bytes (a longer one is skipped whole)."""
    skip = False
    while True:
        b = f.readline(cap + 1)
        if not b:
            return
        if len(b) > cap and not b.endswith(b"\n"):
            skip = True
            continue
        if skip:
            skip = not b.endswith(b"\n")
            continue
        yield b


# ------------------------------------------------------------------ the pressure watch (03 §5.3)
class PressureWatch:
    """Asks the logger for an early sample when memory turns tight between two samples: every 2 s it
    reads the machine's memory stall time (where PSI is on) and what is available, and wakes the
    sampler once the stall time or the headroom crosses warning while it samples slowly. A 2 s read
    works on every kernel (C.3 row 5: the unprivileged trigger exists on some 6.1 kernels and not on
    others, and RHEL 9 has no PSI at all); waking is all it does."""
    EVERY_S, QUIET_S = 2.0, 30.0

    def __init__(self, wake, hot):
        self.wake, self.hot, self.stopping, self.last = wake, hot, False, -1e18

    def start(self):
        import threading
        threading.Thread(target=self.loop, name="pressure", daemon=True).start()
        return self

    def tight(self):
        pr = psi_file("/proc/pressure/memory")
        some, full = _avg(pr, "some"), _avg(pr, "full")
        if some is not None and (some >= P["some_warn"] or (full or 0) >= P["full_warn"]):
            return True
        m = meminfo()
        total = m.get("MemTotal", 0)
        return bool(total) and m.get("MemAvailable", total) / GB < bounds(total / GB)[1]

    def loop(self):
        while not self.stopping:
            time.sleep(self.EVERY_S)
            try:
                if not self.hot() and time.monotonic() - self.last >= self.QUIET_S and self.tight():
                    self.last = time.monotonic()
                    self.wake()
            except Exception:  # a reading that fails costs this early sample only
                pass


# ------------------------------------------------------------------ telling somebody (03 §5.13)
def journal(level, text):
    """One line in the journal at a syslog priority (2 critical, 4 warning, 5 notice): systemd reads
    the <N> prefix of what the logger writes to stderr."""
    import sys
    sys.stderr.write("<%d>oomph: %s\n" % (level, _printable(text.replace("\n", " "))[:500]))
    sys.stderr.flush()


def notify(title, msg, console):
    """A notification on Linux is a journal line at *critical* (`journalctl -p crit` sees it); scripts in
    /etc/oomph/alert.d hear of it through the logger's alert records."""
    journal(4 if title.startswith("Disk") else 2, "%s: %s" % (title, msg))  # a full disk is a warning (03 §5.13)
    return True


def _journal_since(since, cap=8 << 20, timeout=20):
    """The entries of our filter since `since` (epoch), as dicts; [] where the journal cannot be read. Only the
    fields read here (systemd 236 and later), and the last `cap` bytes of them: a storm of OOM reports keeps
    its latest, not nothing."""
    import json
    exe = _p(JOURNALCTL)
    if not os.access(exe, os.X_OK):
        return []
    raw = run_capped([exe, "-q", "--no-pager", "-o", "json", "--output-fields=MESSAGE,_SYSTEMD_UNIT,__REALTIME_TIMESTAMP",
                      "--since=@%d" % int(since)] + JOURNAL_MATCH, cap, timeout, tail=True)
    out = []
    for line in (raw or b"").splitlines():
        if len(line) > LINE_MAX:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict):
            out.append(e)
    return out


# The lines of an OOM report syslog.txt keeps besides its header, its summary and its kill line: the memory
# summary (Mem-Info, per node and zone, swap, pages; a cgroup's usage and its memory.stat). Not the table of
# every task (pid, uid, size and name of each process: what hidepid hides from other accounts), no stack,
# no registers, nothing else the kernel printed meanwhile.
OOM_MEM = re.compile(r"^(?:Mem-Info:|Node \d+ |lowmem_reserve\[\]:|\d+ (?:total pagecache pages|pages in swap cache|"
                     r"pages RAM|pages HighMem/MovableOnly|pages reserved|pages cma reserved|pages hwpoisoned)$|"
                     r"Free swap +=|Total swap +=|Swap cache stats:|(?:memory|swap|memory\+swap|kmem): usage \d+kB|"
                     r"Memory cgroup stats for |(?:[a-z_]+:\d+(?:kB)?\s*)+$|[a-z_]+ \d+$)")


def oom_excerpt(entries, cap=256 << 10, per_report=400):
    """syslog.txt for an incident (03 §5.6): the OOM evidence and nothing else of the kernel log. Each
    OOM report's "invoked oom-killer" line, its memory summary (OOM_MEM, at most `per_report` lines) and
    its kill lines, a kill line whose header was rate-limited away, the lines of systemd-oomd and earlyoom,
    and kernel lines about memory from a short list. Every local account reads it: no task table. At most
    `cap` bytes."""
    out, size, inside, n, killed = [], 0, False, 0, False
    for e in entries:
        msg = journal_message(e)
        if msg is None:
            continue
        msg = _printable(msg.strip())[:500]
        unit = e.get("_SYSTEMD_UNIT") if isinstance(e.get("_SYSTEMD_UNIT"), str) else ""
        try:
            t = int(e.get("__REALTIME_TIMESTAMP")) / 1e6
        except (TypeError, ValueError):
            t = 0
        who = unit[:-len(".service")] if unit.endswith(".service") else "kernel"
        keep = False
        if unit in ("systemd-oomd.service", "earlyoom.service"):
            keep = True
        elif INVOKED.match(msg):
            inside, n, killed, keep = True, 0, False, True
        elif KILLED.match(msg) or KILL_OLD.match(msg) or REAPED.match(msg):
            keep, killed = True, True
        elif inside and not killed:
            keep = n < per_report and (bool(OOM_MEM.match(msg)) or bool(SUMMARY.match(msg)))
        elif OTHER_MEM.search(msg):
            keep = True
        if inside and killed and not (KILLED.match(msg) or KILL_OLD.match(msg) or REAPED.match(msg) or INVOKED.match(msg)):
            inside = False
            keep = bool(OTHER_MEM.search(msg)) or unit in ("systemd-oomd.service", "earlyoom.service")
        if not keep:
            continue
        n += 1
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)) if t else "?"
        row = "%s %s: %s\n" % (stamp, who, msg)
        if size + len(row) > cap:
            out.append("(cut at %d KB)\n" % (cap >> 10))
            break
        out.append(row)
        size += len(row)
    return "".join(out)


def dump_syslog(d, predicate):
    """The OOM evidence of the last 15 minutes into d/syslog.txt (oom_excerpt), nothing else of the
    kernel log: the logs are readable by every local user, and kernel.dmesg_restrict exists for a reason."""
    text = oom_excerpt(_journal_since(time.time() - 15 * 60)) or \
        "(no OOM lines in the journal in the 15 minutes before this incident)\n"
    # where /proc hides other accounts' processes (hidepid), so does this file, which names them: the logger's
    # own group only (0640), as the kernel's lines are root's (dmesg_restrict) and the journal's group's (03 §5.6)
    hide = os.geteuid() != 0 and hidepid() != "0"
    try:
        fd = os.open(os.path.join(d, "syslog.txt"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o640 if hide else 0o644)
    except FileExistsError:  # (an incident's folder written again: its first excerpt stays)
        return
    if hide:
        os.fchmod(fd, 0o640)  # (whatever the umask)
    with os.fdopen(fd, "w") as f:
        f.write(text)


ALERTS = True    # the logger writes alert records for /etc/oomph/alert.d (03 §5.13)
WORDS = {"machine": "machine", "system": "Linux", "killer": "the OOM killer", "available": "available"}
