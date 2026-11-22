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

The ctypes libraries load when this module is imported, so only code that measures imports it:
the hook and `oomph serve` never do. Nothing here opens anything in the shared ledger folder.
"""
import ctypes
import functools
import glob
import hashlib
import os
import plistlib
import re
import socket
import struct
import subprocess
import time

OS = "macos"
MB = 1024 * 1024
GB = 1024 * MB

# ---------------------------------------------------------------- native bits
_libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
_proc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)


class _RUsage(ctypes.Structure):  # rusage_info_v4 prefix (+ padding)
    _fields_ = [("uuid", ctypes.c_uint8 * 16), ("user", ctypes.c_uint64),
                ("system", ctypes.c_uint64), ("pkg_idle", ctypes.c_uint64),
                ("intr", ctypes.c_uint64), ("pageins", ctypes.c_uint64),
                ("wired", ctypes.c_uint64), ("resident", ctypes.c_uint64),
                ("footprint", ctypes.c_uint64), ("pad", ctypes.c_uint64 * 64)]


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


def proc_rusage(pid):
    r = _RUsage()
    if _proc.proc_pid_rusage(pid, 4, ctypes.byref(r)) != 0:
        return None
    return r.footprint, r.resident


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
    procs = {}
    for pid in list_pids():
        ru = proc_rusage(pid)
        bi = proc_bsdinfo(pid)
        if not bi:
            continue
        ppid, uid, name, start = bi
        key = (pid, start)
        path = _path_cache.get(key)
        if path is None:
            path = _path_cache[key] = proc_path(pid)
        procs[pid] = {"pid": pid, "ppid": ppid, "uid": uid, "name": name, "start": start,
                      "fp": ru[0] if ru else 0, "rss": ru[1] if ru else 0, "path": path}
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
