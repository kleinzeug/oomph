"""A stand-in for a Mac's backend, for the self-test where there is no Mac (CI's Linux jobs).

It keeps the backend contract of daemon/oomph_darwin.py with made-up memory numbers (a calm
16 GB machine) and the real process table from `ps`, so that the portable half of oomph (the
logger's bookkeeping, incidents, reports, the ledger, the CLI) runs in CI on Linux:
tools/selftest.py installs it as oomph._plat when it is not on a Mac, or with
OOMPH_SELFTEST_PORTABLE=1 to try the Linux run on a Mac. It stands in for a Mac's numbers
(OS "macos"), so the self-test's checks keep their meaning; it is never installed or shipped.
"""
import os
import subprocess
import time

OS = "macos"
MB = 1024 * 1024
GB = 1024 * MB


def machine(all_procs=None):
    return {"id": "m-0000000000000000", "name": "fixture", "os": OS, "arch": os.uname().machine,
            "os_version": "fixture", "kernel": os.uname().release, "kind": "server", "cpus": os.cpu_count(),
            "virt": "none", "measures": {"memory": True, "scope": "host", "all_procs": bool(all_procs)}}


def system_memory():
    return {"pressure": 1, "free_pct": 60, "ram_gb": 16.0, "app_gb": 6.0, "wired_gb": 2.0, "compressed_gb": 0.5,
            "compressor_logical_gb": 1.0, "cached_gb": 3.0, "free_gb": 4.5, "swap_total_gb": 0.0, "swap_used_gb": 0.0,
            "swapfiles": 0, "disk_free_gb": 60.0, "swapins": 0, "swapouts": 0}


def away_state():
    return {"idle_s": None, "display_on": False, "locked": False, "user": None, "uid": None, "sleep_preventers": []}


def collect_procs():
    """Every process `ps` lists: pid, parent, owner, start time, resident size (as the footprint)."""
    out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,uid=,rss=,lstart=,comm="], capture_output=True, text=True,
                         env=dict(os.environ, LC_ALL="C"), timeout=30).stdout
    procs = {}
    for line in out.splitlines():
        f = line.split(None, 9)
        if len(f) < 10 or not f[0].isdigit():
            continue
        try:
            start = int(time.mktime(time.strptime(" ".join(f[4:9]), "%a %b %d %H:%M:%S %Y")))
        except ValueError:
            start = 0
        comm = f[9].strip()
        rss = int(f[3]) * 1024
        procs[int(f[0])] = {"pid": int(f[0]), "ppid": int(f[1]), "uid": int(f[2]), "name": os.path.basename(comm)[:32],
                            "start": start, "fp": rss, "rss": rss, "path": comm if comm.startswith("/") else ""}
    return procs


def proc_cwd(pid):
    try:
        return os.readlink("/proc/%d/cwd" % pid)
    except OSError:
        return os.getcwd() if pid == os.getpid() else None


def group_key(path, name):
    i = path.find(".app/")
    return os.path.basename(path[:i]) if i > 0 else name


def is_agent(p):
    return p["name"] == "claude"


def ownership(sysm, procs):
    procs_gb = sum(p["fp"] for p in procs.values()) / GB
    return {"procs_gb": round(procs_gb, 1),
            "unowned_gb": round(max(0.0, sysm["app_gb"] + sysm["compressor_logical_gb"] - procs_gb), 1)}


def uptime_s():
    return time.monotonic()


def notify(title, msg, console):
    return True


def dump_syslog(d, predicate):
    with open(os.path.join(d, "syslog.txt"), "w") as f:
        f.write("")
