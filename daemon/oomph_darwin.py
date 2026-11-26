"""oomph's backend for macOS: everything that measures a Mac, behind the backend contract.

oomph.py and oomphd.py are portable: they import on any system and measure only through
oomph.plat(), which imports this module on a Mac (oomph_linux, from 1.9.4, on Linux). The
contract, the same names in every backend (roadmap 03 §4.3; the self-test checks the shape):

  OS                       "macos": the value of a sample's `os` and of machine.os
  machine()                the `machine` block of current.json: id, name, os, arch, os_version,
                           kernel, kind, cpus, virt, measures (what this machine can measure)
  system_memory()          the canonical memory fields of a sample (and disk_free_gb)
  away_state()             idle time, display, lock, sleep preventers, the console user
  collect_procs()          {pid: {pid ppid uid name start fp rss path}}
  proc_cwd(pid)            a process's working directory, or None
  group_key(path, name)    the group a process counts under (its outermost .app here)
  is_agent(p)              is this process the root of a Claude Code session
  ownership(sysm, procs)   {procs_gb, unowned_gb}
  uptime_s()               seconds awake since boot (stops while asleep)
  notify(title, msg, console)   one notification on the console user's screen
  dump_syslog(d, predicate)     the last 15 minutes of the system log into d/syslog.txt

Optional, from 1.9.1 (a backend without them records memory only; oomphd.Meter and oomphd.Volumes
turn them into the sample's cpu, gpu, io and disks blocks, roadmap 02 §4):
  collect_procs()          ... with cpu_s child_s rd wr where the caller may read them
  list_pids()              every pid, zombies included
  cpu_ticks()              per core [user, system, idle, nice] ticks
  cpu_topology()           {n, p, e, e_ids}
  thermal_level()          0 nominal … 4 sleeping
  gpu_registry()           [{name, now, mem, alloc, clients {id: (pid, ns)}, usage}]
  gpu_mem_limit_gb(ram)    (GB, estimated)
  gpu_dvfs_mhz()           the GPU's frequency per performance state, from the device tree
  ioreport_helper()        the command of the IOReport helper (1.9.3), which the caller starts as nobody
  boot_id()                (boot session UUID, macOS version and build): what the helper's crash count is kept per
  mounts()                 [{mount, from, fs, flags, dev, total_gb, free_gb}]
  mount_key(rec)           volume_facts(dev)           disk_pools(recs, facts)

Optional, from 1.15 (internet traffic, NET-concept §12; oomph_traffic turns them into the sample's net block):
  NET_FLOWS                "nettop": what net_flows hands over
  net_route()              the egress: {if (physical), tun, gw, subnet, onlink [cidr]}, or None offline
  net_bytes(ifname)        (bytes in, bytes out) of an interface, 64-bit
  net_flows(tun=None)      (nettop's output or None, why: None, "timeout", "cap", "missing"); with a tunnel, its rows too
  router_mac(gw, ifname)   the IPv4 gateway's MAC from the ARP cache;  router_mac6(ifname) the IPv6 router's
  host_secret()            the hardware UUID, never sent: the salt of a network's public id

The ctypes libraries load when this module is imported, so only code that measures imports it:
the hook and `oomph serve` never do. Nothing here opens anything in the shared ledger folder, and
nothing here loads IOReport: only oomph_ioreport.py does, in a process of its own that never runs as root.
"""
import ctypes
import functools
import glob
import hashlib
import os
import plistlib
import re
import select
import socket
import struct
import subprocess
import time

OS = "macos"
RESERVES_CPU = True  # cores can be reserved here (1.12.0): a backend opts in on purpose, with its margins
RESERVES_DISK = True  # and disk space on a volume (1.12.1), by the pool ids of disk_pools
MB = 1024 * 1024
GB = 1024 * MB

# ---------------------------------------------------------------- native bits
_libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
_proc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)


class _RUsage(ctypes.Structure):  # rusage_info_v4 up to the bytes written (+ padding past its 296 bytes)
    _fields_ = [("uuid", ctypes.c_uint8 * 16), ("user", ctypes.c_uint64),
                ("system", ctypes.c_uint64), ("pkg_idle", ctypes.c_uint64),
                ("intr", ctypes.c_uint64), ("pageins", ctypes.c_uint64),
                ("wired", ctypes.c_uint64), ("resident", ctypes.c_uint64),
                ("footprint", ctypes.c_uint64), ("start_abs", ctypes.c_uint64), ("exit_abs", ctypes.c_uint64),
                ("child_user", ctypes.c_uint64), ("child_system", ctypes.c_uint64),
                ("child_pkg_idle", ctypes.c_uint64), ("child_intr", ctypes.c_uint64),
                ("child_pageins", ctypes.c_uint64), ("child_elapsed", ctypes.c_uint64),
                ("bytes_read", ctypes.c_uint64), ("bytes_written", ctypes.c_uint64),
                ("pad", ctypes.c_uint64 * 56)]


class _Timebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


def _timebase():
    """Seconds per unit of rusage's CPU times: Mach time units on Apple Silicon (125/3 ns each on an M3),
    nanoseconds on Intel. Unconverted, a busy loop on Apple Silicon reads as 0.02 cores (02 A.6)."""
    tb = _Timebase()
    if _libc.mach_timebase_info(ctypes.byref(tb)) != 0 or not tb.denom:
        return 1e-9
    return tb.numer / tb.denom * 1e-9


_TICK_S = _timebase()


_BSDINFO_SIZE = 136
_VNODEPATH_SIZE = 2352
_bsd_buf = ctypes.create_string_buffer(_BSDINFO_SIZE)
_vp_buf = ctypes.create_string_buffer(_VNODEPATH_SIZE)
_path_buf = ctypes.create_string_buffer(4096)


def sysctl_raw(name, size=64):
    buf = ctypes.create_string_buffer(size)
    sz = ctypes.c_size_t(size)
    if _libc.sysctlbyname(name.encode(), buf, ctypes.byref(sz), None, ctypes.c_size_t(0)) != 0:
        return None
    return buf.raw[:sz.value]


def sysctl_int(name):
    raw = sysctl_raw(name)
    return int.from_bytes(raw, "little") if raw else None


def sysctl_str(name):
    raw = sysctl_raw(name, 256)
    return raw.split(b"\0")[0].decode("utf-8", "replace") if raw else None


def list_pids():
    n = _proc.proc_listallpids(None, 0)
    arr = (ctypes.c_int * (n + 256))()
    n = _proc.proc_listallpids(arr, ctypes.sizeof(arr))
    return [p for p in arr[:max(n, 0)] if p > 0]


def _rusage(pid):
    r = _RUsage()
    return r if _proc.proc_pid_rusage(pid, 4, ctypes.byref(r)) == 0 else None


def proc_rusage(pid):
    r = _rusage(pid)
    return (r.footprint, r.resident) if r else None


def proc_bsdinfo(pid):
    if _proc.proc_pidinfo(pid, 3, ctypes.c_uint64(0), _bsd_buf, _BSDINFO_SIZE) != _BSDINFO_SIZE:
        return None
    raw = _bsd_buf.raw
    ppid, uid = struct.unpack_from("<II", raw, 16)
    comm = raw[48:64].split(b"\0")[0].decode("utf-8", "replace")
    name = raw[64:96].split(b"\0")[0].decode("utf-8", "replace")
    start = struct.unpack_from("<Q", raw, 120)[0]
    return ppid, uid, name or comm, start


def proc_path(pid):
    n = _proc.proc_pidpath(pid, _path_buf, 4096)
    return _path_buf.value.decode("utf-8", "replace") if n > 0 else ""


def proc_cwd(pid):
    if _proc.proc_pidinfo(pid, 9, ctypes.c_uint64(0), _vp_buf, _VNODEPATH_SIZE) <= 0:
        return None
    return _vp_buf.raw[152:152 + 1024].split(b"\0")[0].decode("utf-8", "replace") or None


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


# ------------------------------------------------------------- system sample
def system_memory():
    out = run(["/usr/bin/vm_stat"])
    m = re.search(r"page size of (\d+)", out)
    ps = int(m.group(1)) if m else 16384
    v = {}
    for line in out.splitlines():
        k, _, val = line.partition(":")
        val = val.strip().rstrip(".")
        if val.isdigit():
            v[k.strip().strip('"').lower()] = int(val)
    internal = sysctl_int("vm.page_pageable_internal_count") or v.get("anonymous pages", 0)
    purgeable = v.get("pages purgeable", 0)
    sw = sysctl_raw("vm.swapusage")
    sw_total = sw_used = 0
    if sw and len(sw) >= 24:
        sw_total, _avail, sw_used = struct.unpack_from("<QQQ", sw, 0)
    swapfiles = glob.glob("/System/Volumes/VM/swapfile*")
    st = os.statvfs("/System/Volumes/Data")
    return {
        "pressure": sysctl_int("kern.memorystatus_vm_pressure_level") or 0,
        "free_pct": sysctl_int("kern.memorystatus_level"),
        "ram_gb": round((sysctl_int("hw.memsize") or 0) / GB, 1),
        "app_gb": round(max(internal - purgeable, 0) * ps / GB, 2),
        "wired_gb": round(v.get("pages wired down", 0) * ps / GB, 2),
        "compressed_gb": round(v.get("pages occupied by compressor", 0) * ps / GB, 2),
        "compressor_logical_gb": round(v.get("pages stored in compressor", 0) * ps / GB, 2),
        "cached_gb": round((v.get("file-backed pages", 0) + purgeable) * ps / GB, 2),
        "free_gb": round((v.get("pages free", 0) + v.get("pages speculative", 0)) * ps / GB, 2),
        "swap_total_gb": round(sw_total / GB, 2),
        "swap_used_gb": round(sw_used / GB, 2),
        "swapfiles": len(swapfiles),
        "disk_free_gb": round(st.f_bavail * st.f_frsize / GB, 1),
        "swapins": v.get("swapins", 0),
        "swapouts": v.get("swapouts", 0),
    }


_PREVENT_RE = re.compile(r"pid \d+\(([^)]*)\):.*?(PreventUserIdleSystemSleep|PreventSystemSleep|PreventUserIdleDisplaySleep|NoDisplaySleepAssertion|NoIdleSleepAssertion)\s+named: \"([^\"]*)\"")


def away_state():
    out = run(["/usr/sbin/ioreg", "-c", "IOHIDSystem", "-r", "-k", "HIDIdleTime", "-d", "1"])
    m = re.search(r'"HIDIdleTime" = (\d+)', out)
    idle = int(m.group(1)) // 1_000_000_000 if m else None
    asr = run(["/usr/bin/pmset", "-g", "assertions"])
    display_on = "Prevent sleep while display is on" in asr
    preventers = sorted({mm.group(1) for mm in _PREVENT_RE.finditer(asr) if mm.group(1) != "powerd"})
    locked, user, uid = False, None, None
    try:
        raw = subprocess.run(["/usr/sbin/ioreg", "-n", "Root", "-d1", "-a"], stdin=subprocess.DEVNULL, capture_output=True,
                             timeout=10).stdout
        for u in plistlib.loads(raw).get("IOConsoleUsers", []):
            if u.get("kCGSSessionOnConsoleKey"):
                user, uid = u.get("kCGSSessionUserNameKey"), u.get("kCGSSessionUserIDKey")
                locked = bool(u.get("CGSSessionScreenIsLocked", False))
    except Exception:
        pass
    return {"idle_s": idle, "display_on": display_on, "locked": locked,
            "user": user, "uid": uid, "sleep_preventers": preventers}


# ---------------------------------------------------------------- processes
_path_cache = {}


def group_key(path, name):
    i = path.find(".app/")
    if i > 0:
        return os.path.basename(path[:i])
    return name


def is_agent(p):
    """A Claude Code session's root process is called `claude`."""
    return p["name"] == "claude"


def collect_procs():
    """Every process this caller may see. Where rusage answers (as root: every one; else one's own)
    also the counters the logger turns into rates: `cpu_s` and `child_s`, CPU seconds of the process
    and of the children it has reaped, and `rd` / `wr`, bytes read from and written to disk."""
    procs = {}
    for pid in list_pids():
        ru = _rusage(pid)
        bi = proc_bsdinfo(pid)
        if not bi:
            continue
        ppid, uid, name, start = bi
        key = (pid, start)
        path = _path_cache.get(key)
        if path is None:
            path = _path_cache[key] = proc_path(pid)
        p = procs[pid] = {"pid": pid, "ppid": ppid, "uid": uid, "name": name, "start": start,
                          "fp": ru.footprint if ru else 0, "rss": ru.resident if ru else 0, "path": path}
        if ru:
            p["cpu_s"] = (ru.user + ru.system) * _TICK_S
            p["child_s"] = (ru.child_user + ru.child_system) * _TICK_S
            p["rd"], p["wr"] = ru.bytes_read, ru.bytes_written
    live = {(p["pid"], p["start"]) for p in procs.values()}
    for k in [k for k in _path_cache if k not in live]:
        del _path_cache[k]
    return procs


def ownership(sysm, procs):
    """What all processes' footprints add up to, and how much memory none of them owns.
    A footprint counts its compressed and swapped pages at their uncompressed size, so
    app memory + the compressor's logical size should roughly equal the sum; a large
    remainder is memory held outside every process (last seen: a WebKit GPU-process leak
    that survived its processes and froze the Mac)."""
    procs_gb = sum(p["fp"] for p in procs.values()) / GB
    return {"procs_gb": round(procs_gb, 1),
            "unowned_gb": round(max(0.0, sysm["app_gb"] + sysm["compressor_logical_gb"] - procs_gb), 1)}


def uptime_s():
    """Seconds the Mac has been awake since boot (stops while asleep, unlike time.time())."""
    return time.clock_gettime(time.CLOCK_UPTIME_RAW)


# ------------------------------------------------------------------ more resources (roadmap 02 §4)
# Each returns plain data, or None where the reading is not available; the logger turns readings into
# rates (oomphd.Meter) and never fails a sample over one of them. Nothing here needs root.
def _nobody():
    """subprocess arguments that make a child of root nobody, with no other groups (nothing runs as root that does
    not have to, as on Linux); none for anyone else. Resolved here, in the parent: a lookup in the forked child of a
    threaded process can deadlock on a lock another thread held."""
    if os.geteuid() != 0:
        return {}
    import pwd
    try:
        pw = pwd.getpwnam("nobody")
        uid, gid = pw.pw_uid, pw.pw_gid
    except KeyError:
        uid = gid = 4294967294   # macOS's nobody, -2
    return {"user": uid, "group": gid, "extra_groups": []}


def run_capped(cmd, cap, timeout, why=None, as_nobody=False, strict=False):
    """stdout of `cmd`, at most `cap` bytes within `timeout` seconds, else None: what the system hands
    the root logger is read with a cap and a deadline (02 §10.5), and the child is always reaped. `why`, a
    list, gets "missing", "timeout", "cap" or (`strict`) "exit N" when the answer is None. `as_nobody`: as nobody when
    this process is root (route and scutil need no privilege; arp and ndp do: current macOS hides the neighbour caches'
    entries from anyone else, and its own addresses' MACs read 2:0:0:0:0:0). `strict`: a child that did not exit 0 answers
    None (nettop's partial output would read as a complete sample)."""
    why = why if why is not None else []
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             cwd="/", env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
                             **(_nobody() if as_nobody else {}))
    except OSError:
        why.append("missing")
        return None
    out, n, deadline = [], 0, time.monotonic() + timeout
    fd = p.stdout.fileno()
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([fd], [], [], left)[0]:
                why.append("timeout")
                return None
            b = os.read(fd, 1 << 16)
            if not b:
                break
            n += len(b)
            if n > cap:
                why.append("cap")
                return None
            out.append(b)
        p.wait(max(0.01, deadline - time.monotonic()))
        if strict and p.returncode != 0:
            why.append("exit %d" % p.returncode)
            return None
        return b"".join(out)
    except subprocess.TimeoutExpired:
        why.append("timeout")
        return None
    except OSError:
        why.append("missing")
        return None
    finally:
        if p.returncode is None:
            p.kill()
            try:
                p.wait(2)    # a child stuck in the kernel ignores even SIGKILL: the sampler goes on
            except subprocess.TimeoutExpired:
                pass
        p.stdout.close()


_host = None
_task_self = ctypes.c_uint32.in_dll(_libc, "mach_task_self_")
_libc.mach_host_self.restype = ctypes.c_uint32
_libc.host_processor_info.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32),
                                      ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)]
_libc.vm_deallocate.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t]


def cpu_ticks():
    """Per core [user, system, idle, nice] ticks since boot (32-bit counters: subtract modulo 2**32).
    host_processor_info hands out a fresh array on every call; it is given back right away, or the
    logger would grow by a page or more per sample (02 §4.1)."""
    global _host
    if _host is None:
        _host = _libc.mach_host_self()  # one send right, kept: asking each time would pile up references
    n, arr, cnt = ctypes.c_uint32(), ctypes.c_void_p(), ctypes.c_uint32()
    if _libc.host_processor_info(_host, 2, ctypes.byref(n), ctypes.byref(arr), ctypes.byref(cnt)) != 0 or not arr.value:
        return None
    try:
        ints = (ctypes.c_uint32 * cnt.value).from_address(arr.value)
        return [list(ints[4 * i:4 * i + 4]) for i in range(min(n.value, cnt.value // 4))]
    finally:
        _libc.vm_deallocate(_task_self.value, arr.value, cnt.value * 4)


@functools.lru_cache(maxsize=1)
def cpu_topology():
    """{"n", "p", "e", "e_ids"}: the core count, the performance and efficiency cores (None on an Intel
    Mac, where every core is a P core) and which logical cores are E, from the device tree's cpu nodes
    (`logical-cpu-id`, `cluster-type`). Read once."""
    n = os.cpu_count() or 1
    p, e = sysctl_int("hw.perflevel0.logicalcpu"), sysctl_int("hw.perflevel1.logicalcpu")
    if not e or (sysctl_int("hw.nperflevels") or 0) < 2:
        return {"n": n, "p": None, "e": None, "e_ids": None}
    ids = set()
    raw = run_capped(["/usr/sbin/ioreg", "-a", "-l", "-p", "IODeviceTree", "-n", "cpus", "-r", "-d", "2"], 1 << 20, 5)
    try:
        for node in (plistlib.loads(raw)[0].get("IORegistryEntryChildren") or []) if raw else []:
            cid, kind = node.get("logical-cpu-id"), node.get("cluster-type")
            if isinstance(cid, bytes):
                cid = int.from_bytes(cid[:4], "little")
            if isinstance(kind, bytes) and kind[:1] == b"E" and isinstance(cid, int):
                ids.add(cid)
    except Exception:
        ids = set()
    return {"n": n, "p": p, "e": e, "e_ids": sorted(ids) if len(ids) == e else None}


_therm = None
_libc.notify_register_check.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
_libc.notify_get_state.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint64)]


def thermal_level():
    """The thermal pressure level: 0 nominal, 1 moderate, 2 heavy, 3 trapping, 4 sleeping."""
    global _therm
    if _therm is None:
        tok = ctypes.c_int()
        if _libc.notify_register_check(b"com.apple.system.thermalpressurelevel", ctypes.byref(tok)) != 0:
            _therm = -1
            return None
        _therm = tok.value
    st = ctypes.c_uint64()
    if _therm < 0 or _libc.notify_get_state(_therm, ctypes.byref(st)) != 0:
        return None
    return int(st.value) if st.value <= 16 else None


_CREATOR = re.compile(r"pid (\d+)")


def parse_gpu_registry(raw):
    """The accelerators of `ioreg -a -r -w 0 -c IOAccelerator -l` (a property list): per device its
    model, the driver's instantaneous "Device Utilization %", the memory it has in use and allocated,
    and per user client (by registry id) the pid that opened it and the GPU time it has accumulated
    (ns); `usage`: whether any client reports that time at all. From a client's creator string only the pid is taken (`pid 413, WindowServer`): a process
    picks its own name, and names come from the logger's process table (02 §10.5)."""
    out = []
    for dev in plistlib.loads(raw) if raw else []:
        if not isinstance(dev, dict):
            continue
        ps = dev.get("PerformanceStatistics")
        ps = ps if isinstance(ps, dict) else {}
        clients, usage = {}, False
        for c in dev.get("IORegistryEntryChildren") or []:
            m = _CREATOR.match(c.get("IOUserClientCreator") or "") if isinstance(c, dict) else None
            if not m:
                continue
            ns = 0
            for u in c.get("AppUsage") or []:
                v = u.get("accumulatedGPUTime") if isinstance(u, dict) else None
                if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 1 << 63:
                    ns, usage = ns + v, True
            rid = c.get("IORegistryEntryID")
            clients[rid if isinstance(rid, int) else len(clients)] = (int(m.group(1)), ns)

        def num(k):
            v = ps.get(k)
            return v if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0 else None
        model = dev.get("model")
        if isinstance(model, bytes):
            model = model.split(b"\0")[0].decode("utf-8", "replace")
        out.append({"name": model[:64] if isinstance(model, str) and model else dev.get("IOClass") or "GPU",
                    "now": num("Device Utilization %"), "mem": num("In use system memory"),
                    "alloc": num("Alloc system memory"), "clients": clients, "usage": usage})
    return out


def gpu_registry():
    """parse_gpu_registry of the live registry, read with a cap of 8 MB and a deadline of 2 s
    (every client a process opens adds an entry: 160 KB with 60 clients here). None if that failed,
    [] on a Mac without an accelerator in the registry (a VM may have none)."""
    raw = run_capped(["/usr/sbin/ioreg", "-a", "-r", "-w", "0", "-c", "IOAccelerator", "-l"], 8 << 20, 2)
    if raw is None:
        return None
    try:
        return parse_gpu_registry(raw) if raw.strip() else []
    except Exception:
        return None


def parse_dvfs(raw):
    """The GPU's frequencies in MHz from the device tree's `pmgr` node as a property list: its
    `voltage-states9` is (frequency in Hz, voltage) pairs of little-endian 32-bit numbers, entry i
    the frequency of performance state Pi (entry 0: 0 MHz, the state OFF). Not monotonic on an
    M3 Max (02 A.4). None when the node or the key is missing or malformed."""
    nodes = plistlib.loads(raw) if raw else []
    for n in nodes if isinstance(nodes, list) else []:
        v = n.get("voltage-states9") if isinstance(n, dict) else None
        if isinstance(v, bytes) and 8 <= len(v) <= 8 * 64 and len(v) % 8 == 0:
            return [int.from_bytes(v[i:i + 4], "little") / 1e6 for i in range(0, len(v), 8)]
    return None


@functools.lru_cache(maxsize=1)
def gpu_dvfs_mhz():
    """parse_dvfs of this Mac's device tree (read once, with a cap of 1 MB and a deadline of 5 s:
    80 KB on an M3 Max). The table the IOReport helper's residencies are weighed with."""
    raw = run_capped(["/usr/sbin/ioreg", "-a", "-p", "IODeviceTree", "-n", "pmgr", "-r", "-d", "1", "-w", "0"], 1 << 20, 5)
    try:
        return parse_dvfs(raw)
    except Exception:
        return None


IOREPORT_HELPER = os.path.join(os.path.dirname(os.path.realpath(__file__)), "oomph_ioreport.py")


def ioreport_helper():
    """The command that starts the IOReport helper (oomph_ioreport.py, next to this file), or None
    where it is missing. The caller starts it as nobody when it is root: the private library is
    never loaded into a process that runs as root (02 §10.6)."""
    return ["/usr/bin/python3", "-I", "-B", IOREPORT_HELPER] if os.path.isfile(IOREPORT_HELPER) else None


def boot_id():
    """This boot and this system, as the crash counter of the IOReport helper keys them: (the boot
    session's UUID, the macOS version and build). A new boot or an update starts the count afresh.
    Not the boot time: macOS moves kern.boottime whenever the clock is set (after a wake, an NTP
    step), which would start the count afresh within one boot. The boot time only where the UUID
    is missing, and the time of this reading where both are: then each start of the logger counts
    afresh, which is no worse than a counter that never does."""
    boot = sysctl_str("kern.bootsessionuuid")
    if not boot:
        raw = sysctl_raw("kern.boottime", 16)
        boot = int.from_bytes(raw[:8], "little") if raw and len(raw) >= 8 else time.time()
    return boot, "%s %s" % (sysctl_str("kern.osproductversion") or "?", sysctl_str("kern.osversion") or "?")


def gpu_mem_limit_gb(ram_gb):
    """How much memory the GPU may address: `iogpu.wired_limit_mb` when someone set it, else an
    estimate of Metal's working-set limit (0.75 of RAM from 36 GB up, 0.66 below; the logger never
    loads Metal). Returns (GB, estimated)."""
    mb = sysctl_int("iogpu.wired_limit_mb")
    if mb:
        return round(mb / 1024, 1), False
    return round(ram_gb * (0.75 if ram_gb >= 36 else 0.66), 1), True


class _StatFS(ctypes.Structure):  # struct statfs, the 64-bit-inode layout: 2168 bytes
    _fields_ = [("bsize", ctypes.c_uint32), ("iosize", ctypes.c_int32), ("blocks", ctypes.c_uint64),
                ("bfree", ctypes.c_uint64), ("bavail", ctypes.c_uint64), ("files", ctypes.c_uint64),
                ("ffree", ctypes.c_uint64), ("fsid", ctypes.c_int32 * 2), ("owner", ctypes.c_uint32),
                ("type", ctypes.c_uint32), ("flags", ctypes.c_uint32), ("fssubtype", ctypes.c_uint32), ("fstypename", ctypes.c_char * 16),
                ("mntonname", ctypes.c_char * 1024), ("mntfromname", ctypes.c_char * 1024),
                ("flags_ext", ctypes.c_uint32), ("reserved", ctypes.c_uint32 * 7)]


try:  # x86_64: the plain symbol is the old 32-bit-inode layout; arm64 has only the new one
    _getfsstat = _libc["getfsstat$INODE64"]
except AttributeError:
    _getfsstat = _libc.getfsstat
_getfsstat.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]


def mounts():
    """Every mount, from the kernel's cache (getfsstat MNT_NOWAIT: never blocks on a dead network
    mount, never touches a volume; up to a few seconds old). Records: mount, from, fs, flags, dev
    (the st_dev of files on it), total_gb, free_gb (what df shows). None when the binding does not
    trust its own answer (see mount_records)."""
    if ctypes.sizeof(_StatFS) != 2168:
        return None
    n = _getfsstat(None, 0, 2)
    if n <= 0:
        return None
    buf = (_StatFS * (n + 8))()
    n = _getfsstat(buf, ctypes.sizeof(buf), 2)
    return mount_records({"mount": f.mntonname.decode("utf-8", "replace"), "from": f.mntfromname.decode("utf-8", "replace"),
                          "fs": f.fstypename.decode("utf-8", "replace"), "flags": f.flags, "dev": f.fsid[0] & 0xFFFFFFFF,
                          "size": f.blocks * f.bsize, "free": f.bavail * f.bsize} for f in buf[:max(n, 0)])


def mount_records(raw):
    """The records of mounts() from what statfs said (sizes in bytes). A record with an absurd size
    (free above size, or above 1 EiB) is left out: whoever mounts a FUSE or network file system
    chooses what its statfs answers. The whole answer is refused (None) only when the layout itself
    is not to be trusted: `/` missing, or `/` or /System/Volumes/Data absurd."""
    out = []
    for r in raw:
        size, free = r["size"], r["free"]
        if size > 1 << 60 or free > size:
            if r["mount"] in ("/", "/System/Volumes/Data"):
                return None
            continue
        out.append({"mount": r["mount"], "from": r["from"], "fs": r["fs"], "flags": r["flags"], "dev": r["dev"],
                    "total_gb": round(size / GB, 1), "free_gb": round(free / GB, 1)})
    return out if any(m["mount"] == "/" for m in out) else None


_DISK_DEV = re.compile(r"/dev/(disk\d+(?:s\d+)*)")
FACT_KEYS = ("BusProtocol", "Internal", "RemovableMedia", "RemovableMediaOrExternalDevice", "Ejectable", "SolidState",
             "VolumeName", "VolumeUUID", "DiskUUID", "APFSContainerReference", "GlobalPermissionsEnabled")


def _diskutil(ident):
    raw = run_capped(["/usr/sbin/diskutil", "info", "-plist", ident], 1 << 20, 5)
    try:
        d = plistlib.loads(raw) if raw else None
    except Exception:
        return None
    return d if isinstance(d, dict) else None


def volume_facts(dev):
    """What diskutil says about a device (`/dev/disk7s1`), FACT_KEYS only, plus `pool_uuid`: the
    APFS container's DiskUUID (one more call per container), else the volume's UUID. 120 to 600 ms a
    call, so the logger asks once per newly seen mount, off the sampling path. Called only for names
    of the form /dev/diskN[sN…]: whoever mounts chooses that string (02 §4.4). None if diskutil
    failed, for the volume or for its container."""
    m = _DISK_DEV.fullmatch(dev or "")
    if not m:
        return None
    d = _diskutil(m.group(1))
    if d is None:
        return None
    f = {k: d[k] for k in FACT_KEYS if isinstance(d.get(k), (str, bool))}
    uuid = None
    cont = f.get("APFSContainerReference")
    if isinstance(cont, str) and re.fullmatch(r"disk\d+", cont):
        c = _diskutil(cont)
        if c is None:  # failed as a whole, not the volume's UUID instead: a pool's id never changes while mounted
            return None
        uuid = c.get("DiskUUID")
    f["pool_uuid"] = uuid if isinstance(uuid, str) else f.get("VolumeUUID") or f.get("DiskUUID")
    return f


MNT_RDONLY, MNT_REMOVABLE, MNT_LOCAL, MNT_DONTBROWSE, MNT_IGNORE_OWNERSHIP = 0x1, 0x200, 0x1000, 0x100000, 0x200000
NETWORK_FS = frozenset(("smbfs", "nfs", "afpfs", "webdav", "ftp", "cifs", "cd9660"))
SYSTEM_FS = frozenset(("devfs", "autofs", "nullfs", "lifs", "fdesc"))
ROLE_PATHS = (("home", "/Users"), ("tmp", "/private/tmp"), ("tmp", "/private/var/tmp"), ("swap", "/System/Volumes/VM"))
DATA_FLOORS = (20, 5)  # GB: the system's pool runs low below 20 and critical below 5, because swap grows there


def mount_key(rec):
    """What volume_facts' answer for a mount is remembered by: a device mounted again, or another
    device under the same name, is a new mount."""
    return "%s|%s|%s" % (rec.get("from"), rec.get("mount"), rec.get("dev"))


def _pool_dev(rec):
    """The pool a mount's free space belongs to: on APFS the container (disk3 for disk3s5, whose
    volumes share free space), else the device itself; None for a mount that is not a disk."""
    m = _DISK_DEV.fullmatch(rec.get("from") or "")
    if not m:
        return None
    return re.match(r"disk\d+", m.group(1)).group(0) if rec.get("fs") == "apfs" else m.group(1)


def mount_id(mount):
    """The pool id of a volume without a UUID: `mnt:` and 16 hex digits of its mount point's SHA-256,
    printable and short whatever the mount point holds (spaces, any script, any length)."""
    return "mnt:" + hashlib.sha256(mount.encode("utf-8", "surrogateescape")).hexdigest()[:16]


def _backup(rec, facts):
    """A Time Machine volume. The property that marks one is unverified (02 §4.4): its mount point
    and its name are what is known to give it away."""
    mnt, name = rec.get("mount") or "", facts.get("VolumeName") or ""
    return "/.timemachine" in mnt or "com.apple.TimeMachine" in mnt or name.startswith("Backups of ")


def classify_volume(rec, facts):
    """(class, reason, kind) of a mount outside the system's pool, from its mount flags and, for a
    disk, what diskutil said (`facts`; None while it has not answered). `listed`: local, writable,
    browsable and on fixed media (kind `external` or `internal`): the logger samples it, nothing
    raises a flag for it. `ignored`: not sampled, with the reason `oomph volumes --all` gives.
    `pending`: diskutil has to answer first. MNT_REMOVABLE does not decide: the kernel sets it on an
    external SSD too (02 A.30)."""
    fl, fs = rec.get("flags") or 0, rec.get("fs") or ""
    if fs in SYSTEM_FS:
        return "ignored", "part of the system", None
    if fs in NETWORK_FS or not fl & MNT_LOCAL:
        return "ignored", "network file system", None
    if fl & MNT_RDONLY:
        return "ignored", "read-only", None
    if not _DISK_DEV.fullmatch(rec.get("from") or ""):
        return "ignored", "not a disk device", None
    if fl & MNT_DONTBROWSE:
        return "ignored", "hidden", None
    if facts is None:
        return "pending", "not looked at yet", None
    if not facts:
        return "ignored", "diskutil did not answer", None
    if facts.get("BusProtocol") == "Disk Image":
        return "ignored", "disk image", None
    if _backup(rec, facts):
        return "ignored", "backup volume", None
    if facts.get("RemovableMedia") is True:
        return "ignored", "removable media", None
    if facts.get("Internal") is False:
        return "listed", "external disk", "external"
    if facts.get("Internal") is True:
        return "listed", "second internal disk", "internal"
    return "ignored", "unknown kind of device", None


def disk_pools(recs, facts):
    """(pools, rows) for `mounts()` records. `facts`: volume_facts' answers by mount_key (an empty
    dict for one that failed; absent: not asked yet). Rows: every mount with its class and reason.
    Pools: the system's pool (`data`: the container of /System/Volumes/Data, which holds home, the
    temporary folders and swap), watched, with its floors and level; then every listed pool, by the
    APFS container's or the volume's UUID (`vol:<UUID>`), or `mnt:` and a hash of the mount point and
    `weak` without one (an id is printable and at most 80 characters: the ledger keeps it). The free
    space is what df shows (purgeable space is not counted)."""
    by_dev = {r["dev"]: r for r in recs}
    data_rec = next((r for r in recs if r["mount"] == "/System/Volumes/Data"), None) or \
        next((r for r in recs if r["mount"] == "/"), None)
    data_pool = _pool_dev(data_rec) if data_rec else None
    roles = {}
    for role, path in ROLE_PATHS:
        try:
            r = by_dev.get(os.stat(path).st_dev & 0xFFFFFFFF)
        except OSError:
            continue
        if r and _pool_dev(r):
            roles.setdefault(_pool_dev(r), set()).add(role)
    rows, pools, listed = [], [], {}
    for r in sorted(recs, key=lambda r: r["mount"]):
        pool = _pool_dev(r)
        f = facts.get(mount_key(r))
        if pool and pool == data_pool and not r["flags"] & MNT_RDONLY:
            cls, why, kind = "watched", "the system's pool", "internal"
        else:
            cls, why, kind = classify_volume(r, f)
        rows.append(dict(r, pool=pool, cls=cls, why=why, name=(f or {}).get("VolumeName") or os.path.basename(r["mount"])
                         or r["mount"]))
        if cls == "listed" and pool not in listed:
            uuid = (f or {}).get("pool_uuid")
            uuid = uuid if isinstance(uuid, str) and re.fullmatch(r"[0-9A-Za-z-]{1,64}", uuid) else None
            p = {"id": "vol:" + uuid if uuid else mount_id(r["mount"]), "name": rows[-1]["name"][:64],
                 "mount": r["mount"], "dev": pool, "fs": r["fs"], "total_gb": r["total_gb"], "free_gb": r["free_gb"],
                 "roles": sorted(roles.get(pool, ())), "kind": kind, "watch": False}
            if not uuid:
                p["weak"] = True
            listed[pool] = p
    if data_rec and data_pool:
        free, (low, crit) = data_rec["free_gb"], DATA_FLOORS
        pools.append({"id": "data", "name": "Data", "mount": data_rec["mount"], "dev": data_pool, "fs": data_rec["fs"],
                      "total_gb": data_rec["total_gb"], "free_gb": free, "roles": sorted(roles.get(data_pool, ())),
                      "watch": True, "low_gb": low, "crit_gb": crit,
                      "level": "critical" if free < crit else "low" if free < low else "ok"})
    return pools + list(listed.values()), rows


# ------------------------------------------------------------------ internet traffic (NET, 1.15; NET-concept §12.1)
# No packet is sent: the routing table, the ARP and neighbour caches, the interface's counters and nettop's list of
# live connections are read. What the programs print is untrusted input: fixed argument lists, a deadline, a cap;
# oomph_traffic parses it with limits on rows, lines and numbers.
NET_FLOWS = "nettop"
NETTOP = ["/usr/bin/nice", "-n", "10", "/usr/bin/nettop", "-L", "1", "-x", "-n", "-t", "external",
          "-J", "interface,state,bytes_in,bytes_out"]   # -n: no reverse DNS, so the logger causes no traffic
# `-t external` leaves out utun (seen on macOS 27: its rows are listed only without -t): under a VPN every interface
# is listed, and the parser keeps the physical interface's and the tunnel's rows by name (loopback's are dropped).
# Loopback's rows cost time too (nettop is quadratic in its rows): `-t undefined` lists the utuns, but nettop 27
# takes it with no other type, so leaving loopback out would take two runs; a backoff says so in daemon.net instead
NETTOP_ALL = [x for i, x in enumerate(NETTOP) if x != "-t" and (i == 0 or NETTOP[i - 1] != "-t")]
NETTOP_CAP, NETTOP_TIMEOUT = 4 << 20, 3.0   # nettop's cost grows with the square of the flows it shows (mac-5)
_TUNNEL = re.compile(r"(utun|ipsec|ppp)\d{1,4}\Z")
_IFNAME = re.compile(r"[a-z][a-z0-9]{0,14}\Z")
_V4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}\Z")


def _kv(out):
    """`route get`'s `   key: value` lines as a dict."""
    d = {}
    for line in (out or b"").decode("utf-8", "replace").splitlines()[:64]:
        k, sep, v = line.strip().partition(": ")
        if sep and k and len(v) <= 64:
            d.setdefault(k, v.strip())
    return d


def _route(*args):
    return _kv(run_capped(["/sbin/route", "-n", "get"] + list(args), 64 << 10, 2.0, as_nobody=True))


def _physical():
    """The first Ethernet-like interface (en*) in scutil --nwi's IPv4 list: what a VPN runs over."""
    out = (run_capped(["/usr/sbin/scutil", "--nwi"], 64 << 10, 2.0, as_nobody=True) or b"").decode("utf-8", "replace")
    v4 = out.split("IPv4 network interface information", 1)[-1].split("IPv6 network interface information", 1)[0]
    for line in v4.splitlines():
        m = re.match(r"\s+(en\d{1,4}) :", line)
        if m:
            return m.group(1)
    return None


def net_route():
    """The egress (12.1): `route -n get 1.1.1.1` (a table lookup, no packet) names the interface and the gateway;
    a utun, ipsec or ppp interface is a VPN, and then the physical interface is the first en* of scutil --nwi's IPv4
    list (route -n get default would miss a VPN with split routes; system utuns exist without one, mac-7). With
    the interface's addresses (getifaddrs): its IPv4 subnet and every prefix on it, for LAN or internet. Without an
    IPv4 route, the IPv6 route's interface (gw None)."""
    d, v6 = _route("1.1.1.1"), []
    if not d.get("interface"):   # IPv6 only (or NAT64 without CLAT): online all the same; no IPv4 gateway, the
        d, v6 = _route("-inet6", "2606:4700:4700::1111"), ["-inet6"]   # identity from the IPv6 router (router_mac6)
    ifn = d.get("interface")
    if not ifn or not _IFNAME.match(ifn):
        return None
    tun = None
    if _TUNNEL.match(ifn):
        tun, ifn = ifn, _physical()
        if not ifn:
            return None
        d = _route(*v6 + ["-ifscope", ifn, "default"])
    gw = d.get("gateway")
    gw = gw if gw and _V4.match(gw) else None
    addrs = if_addrs().get(ifn, [])
    v4 = [a for a in addrs if ":" not in a]
    return {"if": ifn, "tun": tun, "gw": gw, "subnet": _net_of(v4[0]) if v4 else None,
            "onlink": [_net_of(a) for a in addrs if not a.startswith("fe80:")]}


def _net_of(cidr):
    """`192.168.178.42/24` → `192.168.178.0/24`."""
    import ipaddress
    try:
        return str(ipaddress.ip_interface(cidr).network)
    except ValueError:
        return None


class _Sockaddr(ctypes.Structure):
    _fields_ = [("sa_len", ctypes.c_uint8), ("sa_family", ctypes.c_uint8), ("sa_data", ctypes.c_uint8 * 14)]


class _Ifaddrs(ctypes.Structure):
    pass


_Ifaddrs._fields_ = [("ifa_next", ctypes.POINTER(_Ifaddrs)), ("ifa_name", ctypes.c_char_p), ("ifa_flags", ctypes.c_uint),
                     ("ifa_addr", ctypes.POINTER(_Sockaddr)), ("ifa_netmask", ctypes.POINTER(_Sockaddr)),
                     ("ifa_dstaddr", ctypes.POINTER(_Sockaddr)), ("ifa_data", ctypes.c_void_p)]
_libc.getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(_Ifaddrs))]
_libc.freeifaddrs.argtypes = [ctypes.POINTER(_Ifaddrs)]


def _sa_bytes(p, n):
    """The first `n` bytes of a sockaddr, as far as its own length says (a netmask's may be shorter), zero-padded."""
    if not p or p.contents.sa_len < 2:
        return None
    return ctypes.string_at(p, min(p.contents.sa_len, n)).ljust(n, b"\0")


def if_addrs():
    """{interface: ["addr/prefixlen", …]} of every IPv4 and IPv6 address (getifaddrs; read anew each time: a
    delegated IPv6 prefix changes, mac-8)."""
    head = ctypes.POINTER(_Ifaddrs)()
    if _libc.getifaddrs(ctypes.byref(head)) != 0:
        return {}
    out = {}
    try:
        p, n = head, 0
        while p and n < 1024:
            n += 1
            a = p.contents
            fam = a.ifa_addr.contents.sa_family if a.ifa_addr else None
            if fam in (socket.AF_INET, socket.AF_INET6) and a.ifa_name:
                v6 = fam == socket.AF_INET6
                raw, mask = _sa_bytes(a.ifa_addr, 24 if v6 else 8), _sa_bytes(a.ifa_netmask, 24 if v6 else 8)
                if raw is None:
                    p = a.ifa_next
                    continue
                addr = raw[8:24] if v6 else raw[4:8]
                bits = sum(bin(b).count("1") for b in (mask[8:24] if v6 else mask[4:8])) if mask else (128 if v6 else 32)
                name = a.ifa_name.decode("utf-8", "replace")[:16]
                out.setdefault(name, []).append("%s/%d" % (socket.inet_ntop(fam, addr), bits))
            p = a.ifa_next
    finally:
        _libc.freeifaddrs(head)
    return out


CTL_NET, PF_ROUTE, NET_RT_IFLIST2, RTM_IFINFO2 = 4, 17, 6, 0x12


def net_bytes(ifname):
    """(bytes in, bytes out) of an interface, 64-bit (sysctl NET_RT_IFLIST2: if_msghdr2 + if_data64; getifaddrs'
    counters are 32-bit and wrap every 34 s at 1 Gbit/s), or None."""
    mib = (ctypes.c_int * 6)(CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0)
    sz = ctypes.c_size_t(0)
    if _libc.sysctl(mib, 6, None, ctypes.byref(sz), None, ctypes.c_size_t(0)) != 0 or not 0 < sz.value <= 16 << 20:
        return None
    buf = ctypes.create_string_buffer(sz.value + 8192)
    sz.value = len(buf)
    if _libc.sysctl(mib, 6, buf, ctypes.byref(sz), None, ctypes.c_size_t(0)) != 0:
        return None
    try:
        index = socket.if_nametoindex(ifname)
    except OSError:
        return None
    raw, off = buf.raw[:sz.value], 0
    while off + 4 <= len(raw):
        msglen, _, typ = struct.unpack_from("<HBB", raw, off)
        if msglen < 4:
            break
        if typ == RTM_IFINFO2 and off + 32 + 80 <= len(raw) and struct.unpack_from("<H", raw, off + 12)[0] == index:
            return struct.unpack_from("<QQ", raw, off + 32 + 64)   # if_data64's ifi_ibytes, ifi_obytes
        off += msglen
    return None


def net_flows(tun=None):
    """(nettop's CSV or None, why it is missing: "timeout", "cap", "missing", "exit N"); with `tun` (a VPN's interface) of every
    interface, since -t external leaves the tunnel out. A test may hand over a recorded one with
    OOMPH_NETTOP_FIXTURE, never to a process whose real user is root."""
    fx = os.environ.get("OOMPH_NETTOP_FIXTURE")
    if fx and os.getuid() != 0:
        try:
            with open(fx, "rb") as f:
                data = f.read(NETTOP_CAP + 1)
            return (data, None) if len(data) <= NETTOP_CAP else (None, "cap")
        except OSError:
            return None, "missing"
    why = []
    out = run_capped(NETTOP_ALL if tun else NETTOP, NETTOP_CAP, NETTOP_TIMEOUT, why, strict=True)
    return (out, None) if out is not None else (None, why[0] if why else "missing")


def router_mac(gw, ifname):
    """The MAC the ARP cache holds for the gateway on that interface (`arp -n`; no packet is sent), or None. As the
    logger's root: macOS 26/27 shows anyone else no entry ("no entry" while route lists the gateway's LLINFO route),
    and every network would then be the gw: of its gateway and subnet. arp reads a kernel table and opens nothing in a
    shared folder (fixed argv, LC_ALL=C, cwd /, capped)."""
    if not (gw and _V4.match(gw) and ifname and _IFNAME.match(ifname)):
        return None
    out = (run_capped(["/usr/sbin/arp", "-n", gw], 64 << 10, 2.0) or b"").decode("utf-8", "replace")
    for line in out.splitlines()[:32]:
        m = re.match(r"\S+ \(([\d.]+)\) at (\S+) on (\S+)", line)
        if m and m.group(1) == gw and m.group(3) == ifname:
            return m.group(2)
    return None


def _v6(x):
    """An IPv6 address without its %scope, normalised, or None."""
    import ipaddress
    try:
        return ipaddress.IPv6Address(str(x or "").partition("%")[0])
    except ValueError:
        return None


def router_mac6(ifname):
    """The MAC of the IPv6 default router on that interface (`route -n get -inet6 -ifscope X default` names it, the
    neighbour cache, `ndp -an`, holds its MAC), or None. Not any router: a HomePod or Apple TV (a Thread border
    router) and a mesh repeater send router advertisements on the LAN too. ndp as the logger's root, as arp."""
    if not (ifname and _IFNAME.match(ifname)):
        return None
    gw = _v6(_route("-inet6", "-ifscope", ifname, "default").get("gateway"))
    if gw is None:
        return None
    out = (run_capped(["/usr/sbin/ndp", "-an"], 1 << 20, 2.0) or b"").decode("utf-8", "replace")
    for line in out.splitlines()[1:4096]:
        t = line.split()
        if len(t) >= 3 and t[2] == ifname and ":" in t[1] and _v6(t[0]) == gw:
            return t[1]
    return None


@functools.lru_cache(maxsize=1)
def host_secret():
    """This Mac's hardware UUID (gethostuuid, IOPlatformUUID's value) as hex, or None: the salt of a network's public
    id (oomph_traffic.public_id). It never leaves the machine; machine.id is a hash of it, not it."""
    buf, wait = ctypes.create_string_buffer(16), (ctypes.c_long * 2)(5, 0)
    try:
        if _libc.gethostuuid(buf, wait) == 0 and buf.raw.strip(b"\0"):
            return buf.raw.hex()
    except (AttributeError, OSError):
        pass
    return None


# ------------------------------------------------------------------ the machine
@functools.lru_cache(maxsize=1)
def _machine_static():
    """What does not change while the logger runs. Read once: three short commands."""
    out = run(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
    m = re.search(r'"IOPlatformUUID" = "([0-9A-Fa-f-]+)"', out)
    mid = "m-" + hashlib.sha256(("oomph-machine-v1:" + m.group(1)).encode()).hexdigest()[:16] if m else None
    name = run(["/usr/sbin/scutil", "--get", "ComputerName"], timeout=5).strip() or \
        socket.gethostname().split(".")[0] or None
    battery = "InternalBattery" in run(["/usr/bin/pmset", "-g", "batt"], timeout=5)
    u = os.uname()
    ver = sysctl_str("kern.osproductversion")
    return {"id": mid, "name": name[:64] if name else None, "os": OS, "arch": u.machine,
            "os_version": "macOS %s" % ver if ver else "macOS", "kernel": u.release,
            "kind": "laptop" if battery else "desktop", "cpus": os.cpu_count(),
            "virt": "vm" if sysctl_int("kern.hv_vmm_present") else "none"}


def machine(all_procs=None):
    """The `machine` block (roadmap 03 §6.4) for the `daemon` block of current.json, with
    `measures`: what this machine can measure. `all_procs`: does the caller see every process
    (the logger as root does; a user sees footprints of their own only); default: am I root."""
    m = dict(_machine_static())
    m["measures"] = {"memory": True, "pressure": "kernel", "kills": "log", "presence": "desktop",
                     "footprint": "phys_footprint", "unowned": True, "scope": "host",
                     "cpu": "ticks", "gpu": "registry", "disks": "getfsstat", "io": "rusage", "thermal": "notify",
                     "net": "nettop",
                     "all_procs": os.geteuid() == 0 if all_procs is None else bool(all_procs)}
    return m


# ------------------------------------------------------------------ telling somebody
def notify(title, msg, console):
    """A notification with a sound on the screen of the console user (`console`: their uid and
    name, from away_state). As root it runs osascript in that user's session; with nobody logged
    in it shows nothing. Raises on failure; returns True when it ran."""
    script = 'display notification "%s" with title "%s" sound name "Basso"' % (
        msg.replace('"', "'"), title.replace('"', "'"))
    if os.geteuid() == 0:
        uid, user = console.get("uid"), console.get("user")
        if uid is None or not user:
            return False
        cmd = ["/bin/launchctl", "asuser", str(uid), "/usr/bin/sudo", "-u", user, "/usr/bin/osascript", "-e", script]
    else:
        cmd = ["/usr/bin/osascript", "-e", script]
    subprocess.run(cmd, capture_output=True, timeout=15)
    return True


def dump_syslog(d, predicate):
    """What the system log said about memory in the last 15 minutes, into d/syslog.txt."""
    out = run(["/usr/bin/log", "show", "--last", "15m", "--style", "compact", "--predicate", predicate], timeout=300)
    with open(os.path.join(d, "syslog.txt"), "w") as f:
        f.write(out)
