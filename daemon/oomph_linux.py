"""oomph's backend for Linux: what measures a Linux machine, behind the backend contract of
oomph_darwin.py (roadmap 03 §4.3). Text files under /proc and /sys only: no ctypes, no
subprocess, no privilege. Every path goes through OOMPH_SYSROOT (default empty), so that a
recorded tree stands in for a machine in the tests (tools/linuxfixture.py), on a Mac too.
Nothing happens at import.

1.9.4 is Linux for agents (step L1): checks, reservations, `oomph run`, the MCP server, the hook
and `oomph top` measure live; there is no logger yet, so no kills by name, no presence, no
notifications. What the design settled from the fact spike (03 Appendix C.3) and applies here:

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

The thresholds live in P; `level`, `margin` and `oversize_limit` are pure functions of numbers,
so oomph.py judges a Linux sample with them on any system.
"""
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
    """(comm, ppid, flags, starttime) from /proc/<pid>/stat: the name is what lies between the
    first "(" and the LAST ")" (names hold spaces and parentheses)."""
    t = read("/proc/%d/stat" % pid, 4096)
    if not t:
        return None
    a, b = t.find("("), t.rfind(")")
    if a < 0 or b < a:
        return None
    f = t[b + 2:].split()
    if len(f) < 20:
        return None
    return t[a + 1:b], _int(f[1], 0), _int(f[6], 0), _int(f[19], 0)


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
    """{pid: {pid ppid uid name start fp rss path cg nspid}} of every process this caller may see
    (kernel threads own no memory and are left out). `start` is the start time in clock ticks since
    boot: compared for equality only. With `only` (pids), those processes and their ancestors,
    without a full scan (03 §4.4): what finding one's own session needs."""
    procs = {}
    pids = _ancestors(only) if only is not None else list_pids()
    live = set()
    for pid in pids:
        st = _stat(pid)
        if not st:
            continue
        comm, ppid, flags, start = st
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
                          "fp": kb("RssAnon") + kb("VmSwap"), "rss": kb("VmRSS"), "path": path}
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
                     "unowned": False, "scope": sc["kind"],
                     "all_procs": (os.geteuid() == 0 or hp == "0") if all_procs is None else bool(all_procs)}
    return m


# ------------------------------------------------------------------ telling somebody
def notify(title, msg, console):
    """No notifications without the Linux logger (it comes with its alert hooks)."""
    return False


def dump_syslog(d, predicate):
    """The kernel's OOM lines come with the Linux logger; until then there is nothing to copy."""
    with open(os.path.join(d, "syslog.txt"), "w") as f:
        f.write("(no system log excerpt: the journal is not read on Linux yet)\n")


WORDS = {"machine": "machine", "system": "Linux", "killer": "the OOM killer", "available": "available"}
