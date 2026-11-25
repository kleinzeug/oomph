#!/usr/bin/python3 -I
"""oomphd — continuous memory papertrail. See ../DESIGN.md.

Runs as a root LaunchDaemon. For unprivileged testing set OOMPH_DIR to a
writable directory (only your own processes will report a footprint then).

The logger itself is portable and imports on any system: it measures only through
oomph.plat(), the backend for this system (oomph_darwin on a Mac), loaded at the first sample.
"""
import datetime
import glob
import gzip
import json
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

# The real directory, not /usr/local/libexec/oomph: that is a link that the next install
# swaps, and this process keeps importing from the version it started from.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import oomph  # noqa: E402  (shared paths + HTML/summary rendering)

VERSION = oomph.VERSION
LOG_DIR = oomph.LOG_DIR
# The logger's own state (the journal cursor and the kill counter on Linux, 03 §8.1): /var/lib/oomph/daemon
# beside the system's log folder, else (a test, a logger run by hand) the log folder itself.
STATE_DIR = os.environ.get("OOMPH_DAEMON_DIR") or (
    oomph.PATHS_HERE.get("daemon_state") if LOG_DIR == oomph.PATHS_HERE["log"] and oomph.PATHS_HERE.get("daemon_state")
    else LOG_DIR)

# Names that measured here until 1.8.7 and now live in the backend. oomph.py 1.6.2 to 1.8.7 calls
# them on this module, and an MCP server of those versions started from a real
# /usr/local/libexec/oomph imports this file at its first tool call, after an install has swapped
# that path for a link to this version. Forwarded on use (PEP 562), so importing this module
# still loads no native code.
_MOVED = frozenset(("system_memory", "away_state", "collect_procs", "proc_cwd", "ownership", "uptime_s",
                    "group_key", "list_pids", "proc_rusage", "proc_bsdinfo", "proc_path", "sysctl_raw",
                    "sysctl_int"))


def __getattr__(name):
    if name in _MOVED:
        return getattr(oomph.plat(), name)
    raise AttributeError("module %r has no attribute %r" % (__name__, name))

INTERVAL = 30
HOT_INTERVAL = 5
TOP_N = 25
GROUPS_N = 15
GONE_MIN_MB = 300
RETAIN_DAYS = 14
INCIDENT_RETAIN_DAYS = 90
NOTIFY_COOLDOWN = 15 * 60
DISK_LOW_GB = 20
DISK_COOLDOWN = 6 * 3600
INCIDENT_CLOSE_AFTER = 180
INCIDENT_MAX_S = 2 * 3600  # a longer incident is closed and, while triggers last, continued in a new one
INCIDENT_LOOKBACK = 15 * 60
KERNEL_LINES_PER_MIN = 60
JETSAM_POLL = 60          # s between `log show` queries for launchd's jetsam exits
JETSAM_POLL_HOT = 10      # ... while memory is under pressure
STALL_TRIGGER_S = 60      # the daemon not running this long while the Mac is awake = starved
UNOWNED_SUSTAIN_S = 60    # unowned memory must stay above the limit this long to count
FLAP_WINDOW = 60          # pressure changes closer than this are batched into one event
FLAP_REPORT_EVERY = 15 * 60
QUIET_RETAIN_DAYS = 14    # quiet incidents (containers at their own limit, 03 §5.6) are kept like samples
ALERT_KEEP_S = 86400      # alert records for /etc/oomph/alert.d are pruned after a day ...
ALERT_BEAT_S = 600        # ... and while one is younger than this, every sample rewrites alerts/.beat (03 App. A)
# events of the other resources (roadmap 02 §5.3)
CPU_SAT = 0.9             # busy on this share of the cores ...
CPU_SAT_S = 600           # ... for this long is saturated
CPU_SAT_CLEAR = 0.75      # and below this share it is over (a margin, so that it does not flap)
CPU_SAT_COOLDOWN = 3600
CPU_SAT_GAP = 3 * INTERVAL  # a longer gap between two samples (a sleep) starts the clock again
DISK_FILL_GB = 2.0        # a watched disk whose free space fell this much ...
DISK_FILL_S = 120         # ... within this long ...
DISK_FILL_ETA_MIN = 30    # ... and that reaches its critical floor within this, at that rate, is filling
DISK_FILL_NOTIFY_MIN = 10 # a notification when that is this close
DISK_FILL_COOLDOWN = 1800
VOLUME_SETTLE_S = 120     # the disks the first minutes after a start find are what was there, not news
VOLUME_QUIET_S = 300      # a disk's changes within this long of its last event are told once, after it (a flapping mount)

MB = 1024 * 1024
GB = 1024 * MB


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


# ---------------------------------------------------------------- processes
def summarize_procs(procs):
    """The top processes, the biggest groups and the agent sessions of a process table, as a
    sample carries them. The backend says what a group and a session root are."""
    return _summarize(procs)[:3]


def _rates(e, x, keys=("cpu", "gpu", "w")):
    """A process's, group's or session's rates (cores, % of the GPU, MB/s written), each only when
    it is not zero."""
    for k in keys:
        v = round(x.get(k) or 0.0, 2)
        if v > 0:
            e[k] = v
    return e


def _summarize(procs, use=None):
    """summarize_procs, and with `use` (the Meter's rates per pid) the same lists with their rates,
    plus session_of (pid -> the agent session it runs in)."""
    P = oomph.plat()
    is_claude = P.is_agent
    group_of = getattr(P, "group_of", None) or (lambda p: P.group_key(p["path"], p["name"]))  # Linux: by cgroup
    use = use or {}
    groups = {}
    for p in procs.values():
        g = groups.setdefault(group_of(p), [0, 0, 0.0, 0.0])
        g[0] += p["fp"]
        g[1] += 1
        u = use.get(p["pid"])
        if u:
            g[2] += u.get("cpu") or 0.0
            g[3] += u.get("gpu") or 0.0
    grp = [_rates({"name": k, "mb": round(v[0] / MB), "n": v[1]}, {"cpu": v[2], "gpu": v[3]})
           for k, v in sorted(groups.items(), key=lambda kv: kv[1][0], reverse=True)[:GROUPS_N]]

    children = {}
    for p in procs.values():
        children.setdefault(p["ppid"], []).append(p["pid"])

    sessions, session_of = [], {}
    for p in procs.values():
        if not is_claude(p):
            continue
        anc, q, nested = p["ppid"], 0, False
        while anc in procs and q < 64:
            if is_claude(procs[anc]):
                nested = True
                break
            anc, q = procs[anc]["ppid"], q + 1
        if nested:
            continue
        stack, members = [p["pid"]], []
        while stack:
            cur = stack.pop()
            members.append(cur)
            stack.extend(children.get(cur, []))
        for m in members:
            session_of[m] = p["pid"]
        desc = [procs[m] for m in members if m != p["pid"] and m in procs]
        big = max(desc, key=lambda d: d["fp"]) if desc else None
        tot = {k: sum((use.get(m) or {}).get(k) or 0.0 for m in members) for k in ("cpu", "gpu", "w")} if use else {}
        sessions.append(_rates({
            "pid": p["pid"], "cwd": P.proc_cwd(p["pid"]),
            "mb": round(sum(procs[m]["fp"] for m in members if m in procs) / MB),
            "own_mb": round(p["fp"] / MB), "n": len(members),
            "biggest": {"name": big["name"], "pid": big["pid"], "mb": round(big["fp"] / MB)} if big else None,
        }, tot))
    sessions.sort(key=lambda s: s["mb"], reverse=True)

    # g: app group, pn: parent's name, s: Claude session it runs under (for the report's tree)
    by_fp = sorted(procs.values(), key=lambda p: p["fp"], reverse=True)
    top = []
    for p in by_fp[:TOP_N]:
        e = {"pid": p["pid"], "ppid": p["ppid"], "name": p["name"], "uid": p["uid"],
             "mb": round(p["fp"] / MB), "rss_mb": round(p["rss"] / MB), "g": group_of(p)}
        if p["ppid"] in procs:
            e["pn"] = procs[p["ppid"]]["name"]
        if p["pid"] in session_of:
            e["s"] = session_of[p["pid"]]
        top.append(_rates(e, use.get(p["pid"]) or {}))
    return top, grp, sessions, session_of


# ---------------------------------------------------------------- CPU, GPU, I/O and disks (roadmap 02 §4, §5.1)
TOP_RATES = {"top_cpu": ("cpu", 8), "top_gpu": ("gpu", 5), "top_io": ("w", 5)}
CPU_NAMES_N = 5           # rows of the sample's cpu_names (the cores by process name)


class Meter:
    """Rates between two readings: busy cores (system-wide, by cluster and per process), the GPU
    from the IO registry (with `full`, a FullSpeed, also at full speed: then `util` is the share of
    the GPU's capacity, `active` its busy time and `src` "ioreport", and a process's GPU is its share
    of the busy time × util), bytes read and written. The first reading, and the first after a gap,
    has no rates: those blocks then carry only what one reading tells (core count, load, thermal
    level; the GPU's instantaneous figure and memory).

    A process's CPU is its own time plus what its reaped children added to its child time, less
    what was already counted for those children while a sample could see them: a child that ends
    leaves a debt with its parent, paid out of the parent's next growth in child time, for as long
    as the child's pid is still listed (a zombie) and one reading after that (02 §4.1, A.14, A.25).
    No process reads above the core count, and the per-process figures never add up to more than
    the machine was busy plus half a core. The backend's readings are optional; one that fails
    costs its block, and is noted in `errors` for the logger to report."""

    def __init__(self, P, full=None):
        self.P = P
        self.full = full     # the full-speed rung (FullSpeed), when it is switched on
        self.prev = None     # {t, up, ticks, procs {(pid, start): (cpu_s, child_s, ppid, rd, wr)}, gpu [{id: (pid, ns)}]}
        self.debts = {}      # parent pid -> [[seconds still owed, the child's pid, readings since its pid left]]
        self.errors = []     # (where, error) since the caller last looked
        self.scaled = 0.0    # cores the last clamp took off the per-process sum
        self.gpu_apart = {}  # device index -> uptime since when the clients rung and `now` disagree
        self.gpu_off = set() # devices whose clients rung was given up for this run (rung 3 instead)

    def _get(self, name, *a):
        fn = getattr(self.P, name, None)
        if fn is None:
            return None
        try:
            return fn(*a)
        except Exception as e:
            self.errors.append((name, repr(e)[:300]))
            return None

    def read(self, procs, ram_gb=None, gap=False, up=None):
        """(blocks for the sample, {pid: {"cpu", "gpu", "w"}}) for this process table; `up`: the uptime
        taken right after the table was, so that the per-process deltas and the interval match."""
        t, up = time.time(), self.P.uptime_s() if up is None else up
        prev = None if gap else self.prev
        dt = up - prev["up"] if prev else 0.0
        if dt <= 0.05:
            prev = None
        out, use = {}, {}
        topo = self._get("cpu_topology") or {}
        ticks = self._get("cpu_ticks")
        n = len(ticks) if ticks else topo.get("n") or os.cpu_count() or 1
        if hasattr(self.P, "cpu_ticks"):
            cpu = out["cpu"] = {"n": n}
            if topo.get("e"):
                cpu["p"], cpu["e"] = topo["p"], topo["e"]
            try:
                cpu["load"] = [round(x, 2) for x in os.getloadavg()]
            except OSError:
                pass
            th = self._get("thermal_level")
            if th is not None:
                cpu["therm"] = th
            if prev and ticks and prev["ticks"] and len(prev["ticks"]) == len(ticks):
                cpu.update(self._busy(prev["ticks"], ticks, topo.get("e_ids")))

        disk = self._get("disk_bytes") if hasattr(self.P, "disk_bytes") else None
        cur = {(p["pid"], p["start"]): (p["cpu_s"], p["child_s"], p["ppid"], p.get("rd", 0), p.get("wr", 0),
                                        p.get("t0", p["start"]))  # Linux: start is ticks since boot, t0 the date
               for p in procs.values() if "cpu_s" in p}
        if prev:
            for k, v in prev["procs"].items():  # gone since the last reading: what was counted becomes a debt
                if k not in cur and (k[0] not in procs or procs[k[0]]["start"] != k[1]):
                    self.debts.setdefault(v[2], []).append([v[0] + v[1], k[0], 0])
            r_sum = w_sum = 0.0
            for k, (c, ch, _pp, rd, wr, t0) in cur.items():
                last = prev["procs"].get(k)
                if last is None:
                    if t0 < prev["t"] - 1:
                        continue  # seen for the first time, but older: no basis to say what it did
                    last = (0.0, 0.0, 0, 0, 0, t0)
                own, reaped = max(0.0, c - last[0]), max(0.0, ch - last[1])
                for d in self.debts.get(k[0], ()):
                    pay = min(reaped, d[0])
                    reaped, d[0] = reaped - pay, d[0] - pay
                if k[0] == 1:
                    reaped = 0.0  # launchd reaps every orphan
                x = use.setdefault(k[0], {})
                x["cpu"] = min((own + reaped) / dt, float(n))
                rb, wb = max(0, rd - last[3]) / dt / MB, max(0, wr - last[4]) / dt / MB
                r_sum, w_sum = r_sum + rb, w_sum + wb
                x["w"] = wb
            out["io"] = {"r_mb_s": round(r_sum, 2), "w_mb_s": round(w_sum, 2)}
            if disk and prev.get("disk"):  # Linux: every disk's bytes (other users' processes' io cannot be read)
                out["io"] = {"r_mb_s": round(max(0, disk[0] - prev["disk"][0]) / dt / MB, 2),
                             "w_mb_s": round(max(0, disk[1] - prev["disk"][1]) / dt / MB, 2)}
            busy = out.get("cpu", {}).get("busy")
            total = sum(x["cpu"] for x in use.values())
            self.scaled = 0.0
            if busy is not None and total > busy + 0.5:
                f = (busy + 0.5) / total
                self.scaled = total - busy - 0.5
                for x in use.values():
                    x["cpu"] *= f
        self._prune(procs)

        if not prev:
            self.gpu_apart = {}
        if hasattr(self.P, "gpu_cards"):  # Linux: NVIDIA cards through nvidia-smi
            self._cards(out, use, procs)
            self.prev = {"t": t, "up": up, "ticks": ticks, "procs": cur, "gpu": [], "disk": disk}
            return out, use
        devs = self._get("gpu_registry")
        fig = None
        if self.full is not None:
            try:
                fig = self.full.figure(dt if prev else None)
            except Exception as e:  # costs the full-speed figure, never the block
                self.errors.append(("ioreport", repr(e)[:300]))
        gstate = [{cid: c for cid, c in d["clients"].items()} for d in devs] if devs else []
        if devs:
            lim = self._get("gpu_mem_limit_gb", ram_gb) if ram_gb else None
            out["gpu"] = []
            for i, d in enumerate(devs):
                g = {"id": "gpu%d" % i, "name": d["name"], "unified": os.uname().machine == "arm64"}
                if d["now"] is not None:
                    g["now"] = d["now"]
                if d["mem"] is not None:
                    g["mem_gb"] = round(d["mem"] / GB, 2)
                if d["alloc"] is not None:
                    g["mem_alloc_gb"] = round(d["alloc"] / GB, 2)
                if lim and i == 0:
                    g["mem_limit_gb"] = lim[0]
                    if lim[1]:
                        g["mem_limit_est"] = True
                pg = prev["gpu"][i] if prev and i < len(prev["gpu"]) else None
                full = fig if i == 0 and g["unified"] else None  # IOReport's channel is the built-in GPU's
                if pg is not None and d.get("usage", True) and i not in self.gpu_off:
                    per = {}
                    for cid, (pid, ns) in d["clients"].items():
                        old = pg.get(cid)
                        delta = ns - old[1] if old and old[0] == pid else ns
                        if delta > 0:
                            per[pid] = per.get(pid, 0) + delta
                    busy = min(100.0, sum(per.values()) / (dt * 1e9) * 100)
                    g.update(util=round(busy, 1), active=round(busy, 1), src="clients")
                    self._gpu_check(i, busy, g.get("now"), up)
                    tot = sum(per.values())
                    for pid, ns in per.items():  # at full speed: its share of the busy time × util (02 §5.1)
                        x = use.setdefault(pid, {})
                        x["gpu"] = min(100.0, x.get("gpu", 0.0) + (ns / tot * full[0] if full else ns / (dt * 1e9) * 100))
                elif g.get("now") is not None:
                    g.update(util=float(g["now"]), src="ioreg")
                if full:
                    g.update(util=round(full[0], 1), active=round(full[1], 1), src="ioreport")
                out["gpu"].append(g)
        elif devs == []:
            out["gpu"] = []
        self.prev = {"t": t, "up": up, "ticks": ticks, "procs": cur, "gpu": gstate, "disk": disk}
        return out, use

    def _cards(self, out, use, procs):
        """The `gpu` block of a machine with NVIDIA cards (roadmap §11): per card its busy time (the share of
        the last sample period the driver saw a kernel run: the GPU's `util` here as the Mac's busy time is),
        the memory in use, free and on the card, and the processes on it biggest first (`procs`, names from
        this table, never from the driver: oomph_linux.card_sample); per process its SM share on all cards
        (`gpu`). Only a list nvidia-smi answered is written: a block is every card (1.14's GPU pools)."""
        cards = self._get("gpu_cards")
        if cards is None:
            return
        out["gpu"] = []
        for c in cards:
            out["gpu"].append(self.P.card_sample(c, procs))
            for pid, x in (c.get("procs") or {}).items():
                if x.get("sm") is not None:
                    u = use.setdefault(pid, {})
                    u["gpu"] = min(100.0, u.get("gpu", 0.0) + x["sm"])

    GPU_APART, GPU_APART_S = 25.0, 300.0

    def _gpu_check(self, i, busy, now, up):
        """The safety net of the clients rung (02 §12): its busy time is compared with the driver's
        own figure every sample; more than GPU_APART points apart for GPU_APART_S and the device
        reads rung 3 (ioreg) for the rest of the run, which is reported once."""
        if now is None or abs(busy - now) <= self.GPU_APART:
            self.gpu_apart.pop(i, None)
            return
        since = self.gpu_apart.setdefault(i, up)
        if up - since >= self.GPU_APART_S:
            self.gpu_off.add(i)
            self.errors.append(("gpu", "gpu%d: the clients' GPU time and the driver's figure disagree by more than "
                                       "%.0f points for %.0f s; reading the driver's figure from now on"
                                % (i, self.GPU_APART, up - since)))

    @staticmethod
    def _busy(a, b, e_ids):
        user = sys_ = pb = eb = 0.0
        e = set(e_ids or ())
        for i, (x, y) in enumerate(zip(a, b)):
            d = [(q - p) % (1 << 32) for p, q in zip(x, y)]
            tot = sum(d)
            if tot <= 0:
                continue
            u, s = (d[0] + d[3]) / tot, d[1] / tot
            user, sys_ = user + u, sys_ + s
            if i in e:
                eb += u + s
            else:
                pb += u + s
        r = {"busy": round(user + sys_, 2), "user": round(user, 2), "sys": round(sys_, 2)}
        if e_ids:
            r["p_busy"], r["e_busy"] = round(pb, 2), round(eb, 2)
        return r

    def _prune(self, procs):
        """A debt lives while its child's pid is listed and one reading after; it goes when paid or
        when its parent is gone (then nobody would be credited with the child's time)."""
        if not self.debts:
            return
        raw = self._get("list_pids")
        raw = set(raw) if raw else set(procs)
        for ppid in list(self.debts):
            keep = []
            for d in self.debts[ppid] if ppid in procs else ():
                d[2] = 0 if d[1] in raw else d[2] + 1
                if d[0] > 1e-6 and d[2] <= 1:
                    keep.append(d)
            if keep:
                self.debts[ppid] = keep
            else:
                del self.debts[ppid]


# ---------------------------------------------------------------- the GPU at full speed (roadmap 02 §4.2, §10.6)
IOREPORT_TOL = 0.02     # the residencies add up to the helper's interval within this share
IOREPORT_BAD_OFF = 60   # unusable readings in a row that switch the figure off until the next boot
IOREPORT_MAX = 1 << 62  # bound of an interval or a residency (Mach units): a bigger number is a bad reading


def dvfs_usable(table):
    """A DVFS table the residencies can be weighed with: a list of at most 64 frequencies, at least
    two of them above zero."""
    return isinstance(table, list) and len(table) <= 64 and \
        all(isinstance(f, (int, float)) and not isinstance(f, bool) and 0 <= f < 1e5 for f in table) and \
        sum(1 for f in table if f > 0) >= 2


def full_speed(states, table, dt):
    """One helper reading as (util, active): util the share of the GPU's capacity used at full
    speed, Σ residency(Pi) × table[i] ÷ (Σ residencies × the table's maximum, which is not its last
    entry: the table is not monotonic), active the share of the time it was busy at any speed, both
    in percent. Or (None, why) when the reading does not fit this Mac: the states are not OFF, P1 …
    Pn in that order; the table has fewer than two non-zero entries; a state with residency has no
    entry in the table or a zero one (P14 and P15 have none on an M3 Max); a residency is negative
    or beyond IOREPORT_MAX; or the residencies do not add up to the interval `dt` (Mach time units) within IOREPORT_TOL."""
    if not dvfs_usable(table):
        return None, "no usable DVFS table"
    if not isinstance(states, list) or not 2 <= len(states) <= 64 or not all(
            isinstance(s, list) and len(s) == 2 and isinstance(s[0], str) and type(s[1]) is int for s in states):
        return None, "malformed states"
    if [s[0] for s in states] != ["OFF"] + ["P%d" % i for i in range(1, len(states))]:
        return None, "states are not OFF, P1 … P%d: %s" % (len(states) - 1, ", ".join(s[0][:8] for s in states[:4]))
    if any(s[1] < 0 for s in states):
        return None, "a negative residency"
    if any(s[1] >= IOREPORT_MAX for s in states):
        return None, "a residency beyond 2^62"
    for i, (name, r) in enumerate(states[1:], 1):
        if r and (i >= len(table) or table[i] <= 0):
            return None, "%s has residency but no frequency in the table" % name
    if type(dt) is not int or not 0 < dt < IOREPORT_MAX:
        return None, "an interval out of range"
    tot = sum(s[1] for s in states)
    if tot <= 0 or abs(tot - dt) > IOREPORT_TOL * dt:
        return None, "the residencies (%s) do not add up to the interval (%s)" % (tot, dt)
    fmax = max(table)
    util = sum(r * table[i] for i, (_n, r) in enumerate(states) if 0 < i < len(table)) / (tot * fmax) * 100
    return min(100.0, util), (tot - states[0][1]) / tot * 100


class FullSpeed:
    """Rung 1 of the GPU reading (02 §4.2): the IOReport helper (oomph_ioreport.py), the only source
    of how fast the GPU ran. The private library it loads is never loaded here: the helper is a
    process of its own, as nobody when the logger is root, asked for one line per sample: a newline
    in, at most ANSWER_CAP bytes of JSON out within DEADLINE seconds.

    A crash, a hang or garbage costs that sample's full-speed figure (the GPU then reads busy time,
    labelled so) and counts in `ioreport.json` in the log folder, so a crash loop cannot hide behind
    restarts of the logger. The helper is started again right away, at most MAX_CRASHES times per
    boot; the next crash switches the figure off until the Mac restarts or macOS changes. So do
    IOREPORT_BAD_OFF readings in a row that do not fit this Mac's table (full_speed). A Mac without
    the channel (Intel, most VMs) or without a usable table has the figure off for the run. `errors`:
    what went wrong, which the logger reports (daemon_error, where "ioreport"), each one once;
    `notes`: why the figure is off on a Mac that cannot have it, a designed state that the logger
    only writes to daemon.err (current.json's daemon.ioreport says it too)."""
    ANSWER_CAP = 64 << 10
    DEADLINE = 1.0
    MAX_CRASHES = 3

    def __init__(self, cmd, table, state_path, ident):
        self.cmd, self.table, self.path, self.ident = cmd, table, state_path, ident
        self.proc, self.buf = None, b""
        self.bad, self.why = 0, None   # unusable readings in a row, and the last reason
        self.errors, self.notes = [], []
        self.closed = False  # by the logger's stop: nothing more is asked or counted
        st = self._load()
        if st.get("boot") != ident[0] or st.get("macos") != ident[1]:
            st = {"boot": ident[0], "macos": ident[1], "crashes": 0, "off": False}
        self.state = st
        self.off = st["off"] or None   # why the figure is off: crashes, shape (persisted), unavailable, table
        if not self.off and not dvfs_usable(table):
            self.off = "table"
            self.notes.append("no usable GPU frequency table in the device tree: the GPU reads busy time")

    def _load(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            return {}
        try:
            st = os.fstat(fd)
            data = os.read(fd, 4096) if stat.S_ISREG(st.st_mode) and st.st_size <= 4096 else b""
        except OSError:
            data = b""
        finally:
            os.close(fd)
        d = oomph.loads_untrusted(data) or {}
        if not isinstance(d, dict) or type(d.get("crashes")) is not int or d.get("off") not in (False, "crashes", "shape"):
            return {}
        return d

    def _save(self):
        try:
            write_atomic(self.path, json.dumps(self.state, allow_nan=False))
        except OSError as e:
            self.errors.append("ioreport.json not written: %s" % e)

    def status(self):
        """For current.json: "on", or why the figure is off."""
        return self.off or "on"

    def _start(self):
        self.buf = b""
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     cwd="/", env={"PATH": "/usr/bin:/bin"}, close_fds=True,
                                     **oomph._drop_to("nobody", "nobody"))

    def close(self, final=False):
        """Ends the helper; `final` (the logger stops) also ends the asking: a reading the stop
        interrupts is not counted as a crash."""
        self.closed = self.closed or final
        p, self.proc = self.proc, None
        if p is None:
            return
        try:
            if p.poll() is None:
                p.kill()
            p.wait(2)
        except Exception:
            pass
        for f in (p.stdin, p.stdout):
            try:
                f.close()
            except Exception:
                pass

    def _crash(self, what):
        if self.closed:
            return
        self.close()
        self.state["crashes"] += 1
        n = self.state["crashes"]
        if n > self.MAX_CRASHES:
            self.off = self.state["off"] = "crashes"
        self._save()
        self.errors.append("the IOReport helper %s (crash %d since the Mac started); %s" % (
            what, n, "the GPU reads busy time until the next restart of the Mac or macOS update" if self.off
            else "started again"))
        if not self.off:
            try:  # now, so that the next sample has its reading: a crash costs one sample's figure
                self._start()
            except (OSError, subprocess.SubprocessError):
                self.proc = None  # tried again, and counted, at the next sample

    def _line(self):
        """One answer, or raises RuntimeError with what went wrong."""
        p = self.proc
        try:
            p.stdin.write(b"\n")
            p.stdin.flush()
        except (OSError, ValueError):
            raise RuntimeError("ended (exit status %s)" % p.poll())
        fd, deadline = p.stdout.fileno(), time.monotonic() + self.DEADLINE
        while b"\n" not in self.buf:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([fd], [], [], left)[0]:
                raise RuntimeError("did not answer within %g s" % self.DEADLINE)
            b = os.read(fd, 1 << 16)
            if not b:
                raise RuntimeError("ended (exit status %s)" % p.poll())
            self.buf += b
            if len(self.buf) > self.ANSWER_CAP:
                raise RuntimeError("said more than %d KB" % (self.ANSWER_CAP >> 10))
        line, _, self.buf = self.buf.partition(b"\n")
        if self.buf:
            raise RuntimeError("said more than one line")
        return line

    def figure(self, dt_s):
        """(util, active) for a sample whose interval was `dt_s` seconds, or None. Asked every sample
        while the figure is on, also when the sample has no interval (dt_s None: the first one, or
        after a gap), so that the helper's next reading starts where the sample's interval does. A
        reading whose own interval is far from the sample's is dropped without counting against
        the helper."""
        if self.off or self.closed:
            return None
        try:
            if self.proc is None:
                self._start()
                return None  # its first reading would be measured from its start
            d = oomph.loads_untrusted(self._line())
            if not isinstance(d, dict):
                raise RuntimeError("answered something that is not JSON")
        except (RuntimeError, OSError, subprocess.SubprocessError) as e:
            self._crash(str(e) if isinstance(e, RuntimeError) else "could not be started: %s" % e)
            return None
        if d.get("error") == "no channel":
            self.close()
            self.off = "unavailable"
            self.notes.append("this Mac reports no GPU performance states: the GPU reads busy time")
            return None
        dt, hz = d.get("dt"), d.get("hz")
        ok = type(dt) is int and 0 < dt < IOREPORT_MAX and isinstance(hz, (int, float)) and not isinstance(hz, bool) and 1e3 < hz < 1e12
        if dt_s is None or (ok and abs(dt / hz - dt_s) > max(0.5, 0.1 * dt_s)):
            return None
        r = full_speed(d.get("states"), self.table, dt) if ok else (None, str(d.get("error") or "no interval")[:100])
        if r[0] is None:
            self.bad, self.why = self.bad + 1, r[1]
            if self.bad >= IOREPORT_BAD_OFF:
                self.off = self.state["off"] = "shape"
                self._save()
                self.close()
                self.errors.append("%d GPU readings in a row did not fit this Mac (%s): the GPU reads busy time until "
                                   "the next restart of the Mac or macOS update" % (self.bad, self.why))
            return None
        self.bad = 0
        return r


def full_speed_rung(P, log_dir=None):
    """The full-speed rung when it is switched on (oomph.ioreport_wanted) and this backend has it,
    else None."""
    if not oomph.ioreport_wanted() or not all(hasattr(P, f) for f in ("ioreport_helper", "gpu_dvfs_mhz", "boot_id")):
        return None
    cmd = P.ioreport_helper()
    return FullSpeed(cmd, P.gpu_dvfs_mhz(), os.path.join(log_dir or LOG_DIR, "ioreport.json"), P.boot_id()) \
        if cmd else None


def _by_name(rows, field, n=5):
    """{name: amount} of the first n of a top_cpu / top_io list, a name's processes added up."""
    out = {}
    for x in (rows if isinstance(rows, list) else [])[:8]:
        if isinstance(x, dict) and isinstance(x.get(field), (int, float)):
            k = str(x.get("name") or "?")[:64]
            out[k] = round(out.get(k, 0) + x[field], 2)
    return dict(sorted(out.items(), key=lambda kv: -kv[1])[:n])


def cpu_names(procs, use, n=CPU_NAMES_N):
    """The sample's `cpu_names`: the busiest names over the whole process table, each name's cores
    added up, with how many processes carry it (fourteen `yes` at 0.9 are one row of 12.6, which the
    eight rows of top_cpu cannot say)."""
    out = {}
    for pid, u in use.items():
        c = u.get("cpu") or 0.0
        if c > 0 and pid in procs:
            a = out.setdefault(str(procs[pid]["name"] or "?")[:64], [0.0, 0])
            a[0] += c
            a[1] += 1
    rows = sorted(((v[0], k, v[1]) for k, v in out.items()), reverse=True)[:n]
    return [{"name": k, "cpu": round(c, 2), "n": m} for c, k, m in rows if round(c, 2) > 0]


def rate_lists(procs, use, session_of, group_key, n=None):
    """top_cpu (8), top_gpu (5), top_io (5): the biggest consumers of each, in cores, percent of the
    GPU and MB/s written (`n` of each instead, for `oomph ps`)."""
    out = {}
    for key, (field, cap) in TOP_RATES.items():
        cap = n or cap
        rows = sorted(((x.get(field) or 0.0, pid) for pid, x in use.items() if pid in procs), reverse=True)
        lst = []
        for v, pid in rows[:cap]:
            if round(v, 2) <= 0:
                break
            p = procs[pid]
            e = {"pid": pid, "name": p["name"], "g": group_key(p["path"], p["name"]), field: round(v, 2)}
            if pid in session_of:
                e["s"] = session_of[pid]
            lst.append(e)
        if lst:
            out[key] = lst
    return out


class Volumes:
    """The sample's `disks` block: the system's pool and every listed pool (02 §4.4). getfsstat
    runs with every sample (0.1 ms, from the kernel's cache); what diskutil says about a device takes
    up to half a second, so it is asked once per newly seen mount, on a thread of its own, and until
    it has answered the volume is not listed. `wait`: ask in the caller's thread instead (the CLI).
    A failed answer is asked again after RETRY_S. `unsure` after a read: a disk is mounted that
    diskutil has not answered for (yet, or it failed), so the pools listed may not be every pool and
    one missing from them is not gone (the sample's `disks_partial`)."""
    RETRY_S = 600

    def __init__(self, P, wait=False):
        self.P, self.wait, self.unsure = P, wait, False
        self.facts = {}      # mount_key -> facts ({} when diskutil failed)
        self.failed = {}     # mount_key -> when it failed
        self.todo = []       # (mount_key, device) to ask about
        self.cond = threading.Condition()
        self.thread = None

    def read(self):
        """(pools, rows), or (None, None) where this backend cannot list mounts."""
        P = self.P
        if not hasattr(P, "mounts"):
            return None, None
        recs = P.mounts()
        if recs is None:
            return None, None
        live = {P.mount_key(r): r for r in recs}
        with self.cond:
            for k in [k for k in self.facts if k not in live]:
                del self.facts[k]
                self.failed.pop(k, None)
            self.todo = [x for x in self.todo if x[0] in live]   # gone before diskutil was asked: not asked
            for k, t in list(self.failed.items()):
                if time.time() - t > self.RETRY_S:
                    del self.failed[k]
                    self.facts.pop(k, None)
            facts = dict(self.facts)
        pools, rows = P.disk_pools(recs, facts)
        ask = [(P.mount_key(r), r["from"]) for r in rows if r["cls"] == "pending"]
        if ask and self.wait:
            for k, dev in ask:
                self._answer(k, dev)
            with self.cond:
                facts = dict(self.facts)
            pools, rows = P.disk_pools(recs, facts)
            ask = []
        with self.cond:
            self.unsure = bool(ask) or any(k in self.failed for k in live)
        if ask:
            with self.cond:
                queued = {k for k, _ in self.todo}
                self.todo += [x for x in ask if x[0] not in queued]
                self.cond.notify()
            if self.thread is None:
                self.thread = threading.Thread(target=self._loop, name="volumes", daemon=True)
                self.thread.start()
        return pools, rows

    def _answer(self, k, dev):
        try:
            f = self.P.volume_facts(dev)
        except Exception:
            f = None
        with self.cond:
            self.facts[k] = f or {}
            if not f:
                self.failed[k] = time.time()

    def _loop(self):
        while True:
            with self.cond:
                while not self.todo:
                    self.cond.wait()
                k, dev = self.todo.pop(0)
                if k in self.facts:
                    continue
            self._answer(k, dev)


def measure(window=0.25, procs=None):
    """A live reading of the rates, for the CLI when no logger runs: two readings `window` seconds
    apart ("window_s" in the result). Returns (blocks, use, procs)."""
    P = oomph.plat()
    m = Meter(P)
    m.read(procs or P.collect_procs())
    time.sleep(window)
    procs = P.collect_procs()
    out, use = m.read(procs, ram_gb=P.system_memory().get("ram_gb"))
    out["window_s"] = window
    return out, use, procs


def log_time(j, default):
    try:
        return datetime.datetime.strptime(j["timestamp"], "%Y-%m-%d %H:%M:%S.%f%z").timestamp()
    except Exception:
        return default


# ------------------------------------------------------------------ helpers
def now_iso(t=None):
    return datetime.datetime.fromtimestamp(t or time.time()).astimezone().isoformat(timespec="seconds")


def append_json(path, obj):
    with open(path, "a") as f:
        f.write(json.dumps(obj, separators=(",", ":")) + "\n")


def write_atomic(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def ledger_signature():
    """What lstat — which opens nothing — says about the shared ledger.json: it changes whenever a
    writer renames a new one in."""
    try:
        if not stat.S_ISDIR(os.lstat(oomph.LEDGER_DIR).st_mode):
            return ("not a directory",)
        st = os.lstat(os.path.join(oomph.LEDGER_DIR, "ledger.json"))
        return (st.st_ino, st.st_size, st.st_mtime_ns)
    except OSError as e:
        return (e.errno,)


def cpu_pool_block(cpu, leases, prev_others=None):
    """current.json's `pools.cpu` (02 §5.2): what admission needs that only the logger knows well. `cap` logical
    cores, `margin`, `reserved` (Σ granted cores, from the last ledger snapshot), and with a reading `busy` and
    `others`: the load that holds no reservation, busy less what each grant is charged (its measured use, at
    most what it got), smoothed as new = ½ old + ½ measured (about a minute). None without a core count."""
    n = cpu.get("n") if isinstance(cpu, dict) else None
    if not (isinstance(n, int) and n > 0):
        return None
    clamp = lambda x: min(max(float(x), 0.0), float(n)) if isinstance(x, (int, float)) else 0.0  # noqa: E731
    got = [(clamp(l["cpu"]), clamp(l.get("cpu_used"))) for l in leases or () if l.get("state") == "granted"
           and isinstance(l.get("cpu"), (int, float))]  # from the ledger, which anyone writes: within the machine
    out = {"cap": n, "margin": oomph.cpu_margin(n), "reserved": round(sum(g for g, _ in got), 1)}
    busy = cpu.get("busy")
    if isinstance(busy, (int, float)):
        measured = max(0.0, busy - sum(min(u, g) for g, u in got))
        others = measured if prev_others is None else 0.5 * prev_others + 0.5 * measured
        out.update(busy=round(busy, 2), others=round(others, 2))
    return out


class LedgerWorker:
    """The daemon's ledger work (oomph.ledger_tick: retire dead and expired reservations, take
    the snapshot of live ones) on a thread of its own, so the sampler never waits on the shared
    directory or on a child that does: sample() drops its newest sample and process list into a
    one-slot mailbox (the latest wins) and goes on; this thread runs the child with them and
    keeps the snapshot it answers with. Errors become a daemon_error event (where "ledger", at
    most one per ERROR_EVERY), never an exception in the sampler. While nothing is reserved the
    child is skipped as long as ledger.json's lstat is unchanged, at most for FORCE_EVERY."""
    FORCE_EVERY = 300
    ERROR_EVERY = 900

    def __init__(self, event, tick=None):
        self.event = event
        self.tick = tick or oomph.ledger_tick
        self.cond = threading.Condition()
        self.slot = None
        self.leases, self.at = [], 0.0  # the last snapshot, and when it arrived
        self.sig, self.last_run, self.runs = None, 0.0, 0  # runs: children run so far, answered or not
        self.last_err, self.suppressed = 0.0, 0

    def start(self):
        threading.Thread(target=self.loop, name="ledger", daemon=True).start()
        return self

    def offer(self, s, procs, rates=None, writes=None, gpus=None):
        """The newest sample and process table, and the cores each process kept busy ({pid: cores}, when the
        Meter had an interval), the MB/s it wrote to disk ({pid: MB/s}) and its share of the GPU ({pid: %}): the
        child charges every grant's cores, disk writes and a Mac's GPU share from them (02 §6.3)."""
        with self.cond:
            self.slot = (s, procs, rates, writes, gpus)
            self.cond.notify()

    def latest(self, max_age):
        """The last snapshot, unless it is older than `max_age` seconds."""
        with self.cond:
            return list(self.leases) if time.time() - self.at <= max_age else []

    def loop(self):
        while True:
            with self.cond:
                while self.slot is None:
                    self.cond.wait()
                (s, procs, rates, writes, gpus), self.slot = self.slot, None
            try:
                self.run_once(s, procs, rates, writes, gpus)
            except Exception as e:
                self.sig = None
                self.error(str(e) if isinstance(e, oomph.LedgerError) else repr(e))
                with self.cond:
                    self.runs += 1

    def run_once(self, s, procs, rates=None, writes=None, gpus=None):
        sig, now = ledger_signature(), time.time()
        if not self.leases and sig == self.sig and now - self.last_run < self.FORCE_EVERY:
            with self.cond:
                self.at = now  # still nothing reserved
            return
        self.sig, self.last_run = sig, now
        leases, err = self.tick(s, procs, rates=rates, **dict({"writes": writes} if writes else {},
                                                              **({"gpus": gpus} if gpus else {}))) \
            if rates is not None else self.tick(s, procs)
        if err:  # e.g. busy: the snapshot still counts
            self.sig = None
            self.error(err)
        with self.cond:
            self.leases, self.at = leases, time.time()
            self.runs += 1

    def error(self, msg):
        now = time.time()
        if now - self.last_err < self.ERROR_EVERY:
            self.suppressed += 1
            return
        extra = {"suppressed": self.suppressed} if self.suppressed else {}
        self.last_err, self.suppressed = now, 0
        self.event("daemon_error", where="ledger", error=str(msg)[:300], **extra)


def ledger_kept_to_group():
    """Linux: the machine's ledger kept to a group (doctor's way: no access for others). Its purposes and
    projects then stay out of the samples, which every local account can read."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        return not os.stat(oomph.LEDGER_DIR).st_mode & 0o007
    except OSError:
        return False


class Daemon:
    def __init__(self):
        os.umask(0o022)
        os.makedirs(os.path.join(LOG_DIR, "incidents"), exist_ok=True)
        if getattr(oomph.plat(), "ALERTS", False):  # made by the logger, not by the installer: root touches nothing in
            os.makedirs(os.path.join(LOG_DIR, "alerts"), exist_ok=True)  # a folder of the logger's (oomph-alert.path watches it)
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.pending_triggers = []
        self.kernel_budget = [time.time(), 0]
        self.jet = {"kills": 0, "names": {}, "reasons": {}}
        self.kill_times = []
        self.storm = False
        self.report_trig = False
        self.prev_big = {}
        self.prev_t = None
        self.prev_pressure = None
        self.prev_up = None
        self.seen_exits = {}
        self.flap = None
        self.last_pr_event = 0
        self.unowned_since = None
        self.unowned_flagged = False
        self.swap_hist = []
        self.incident = None
        self.rolled = None  # (id, t, top rank, escalated, it if the hooks heard of it) of an incident just closed at INCIDENT_MAX_S
        self.last_notify = 0
        self.last_disk_notify = 0
        self.last_maint = 0
        self.started = time.time()
        self.console = {"uid": None, "user": None}
        self.stopping = False
        self.stream_proc = None
        self.ledger = LedgerWorker(self.event)  # started by run()
        self.machine = None  # the `machine` block of current.json, made at the first sample
        self.meter = self.volumes = None  # rates and disks, made at the first sample
        self.full = None  # the GPU's full-speed figure (FullSpeed), when it is switched on
        self.full_off = None  # why it is missing although switched on: "missing" (no helper), "failed"
        self.soft_at = {}  # where -> when a failed reading was last reported
        self.clamp_told = False
        self.prev_therm = self.therm_batch = None
        self.last_therm_event = 0
        self.sat_since, self.sat_on, self.last_sat = None, False, -1e18
        self.sat_last, self.sat_n = 0.0, 0  # the last sample with a busy figure, while the cores are busy
        self.disk_low_at = {}      # pool id -> when its disk_low was last told
        self.free_hist = {}        # pool id -> [(t, free GB)] of the last minutes
        self.filling = {}          # pool id -> when its disk_filling was last told (while it fills)
        self.fill_at, self.fill_told = {}, {}
        self.prev_pools = None     # pool id -> (watched, mount, name), for the volume events
        self.cpu_others = None     # the smoothed load on the cores that holds no reservation (pools.cpu.others)
        self.vol_at, self.vol_held = {}, {}   # pool id -> its last volume event; -> [state told, changes held]
        self.kills = None          # Linux: the kill watcher (oomph_linux.KillWatcher), started by run()
        self.storms = []           # cgroups whose OOMs repeat (name, ooms, cgroup), from the watcher's thread
        self.quiet = None          # the open quiet incident (03 §5.6): containers at their own limit
        self.alert_t = 0.0         # when the newest alert record was written

    # -- events
    def event(self, kind, **kw):
        ev = {"t": round(time.time(), 1), "iso": now_iso(), "kind": kind}
        ev.update(kw)
        with self.lock:
            append_json(os.path.join(LOG_DIR, "events.jsonl"), ev)
        return ev

    def trigger(self, kind, msg):
        """An incident trigger from another thread (the kill watcher): the next evaluation takes it, now."""
        with self.lock:
            self.pending_triggers.append({"kind": kind, "msg": msg[:300], "t": time.time()})
        self.wake.set()

    def cgroup_storm(self, name, ooms, cg):
        """A cgroup that hit its own limit `ooms` times in ten minutes (from the kill watcher's thread)."""
        with self.lock:
            self.storms.append((oomph.notify_text(name, 64), ooms, cg[:200], time.time()))
            del self.storms[:-64]

    # -- log stream (jetsam kills are logged by launchd and ReportSystemMemory,
    #    not by the kernel; a low-swap storm is ~1000 lines/min -> aggregate)
    JETSAM_EXIT_RE = re.compile(r"\[(?:system|gui/\d+|user/\d+|pid/\d+)/([^\s\]]+) \[(\d+)\]:\] exited .*OS_REASON_JETSAM")
    REPORT_RE = re.compile(r"Process (.+?) \[(\d+)\] killed by jetsam reason (\S+)")
    TRIGGER_REASONS = {"low-swap", "vm-pageshortage", "vm-thrashing", "vm-compressor-thrashing",
                       "vm-compressor-space-shortage", "fc-thrashing", "zone-map-exhaustion"}
    STORM_KILLS_PER_MIN = 10

    def stream_loop(self):
        while not self.stopping:
            try:
                p = self.stream_proc = subprocess.Popen(["/usr/bin/log", "stream", "--style", "ndjson", "--level", "info",
                                      "--predicate", oomph.LOG_PREDICATE],
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                for line in p.stdout:
                    if line.startswith("{"):
                        try:
                            self.handle_log(json.loads(line))
                        except ValueError:
                            pass
            except Exception as e:  # pragma: no cover
                self.event("daemon_error", where="stream", error=str(e))
            time.sleep(5)

    def poll_loop(self):
        since = time.time()
        while not self.stopping:
            time.sleep(JETSAM_POLL_HOT if self.hot else JETSAM_POLL)
            try:
                since = self.poll_jetsam(since)
            except Exception as e:  # pragma: no cover
                self.event("daemon_error", where="jetsam_poll", error=repr(e))

    def poll_jetsam(self, since):
        """Count launchd's jetsam exits since `since` with `log show`; returns the next cursor.
        Windows overlap by a few seconds; handle_log drops lines it has already counted."""
        now = time.time()
        start = datetime.datetime.fromtimestamp(since - 3).strftime("%Y-%m-%d %H:%M:%S")
        out = run(["/usr/bin/log", "show", "--style", "ndjson", "--start", start,
                   "--predicate", oomph.JETSAM_EXIT_PREDICATE], timeout=120)
        if '"finished"' not in out:
            return since  # timed out or failed: retry the same window next time
        for line in out.splitlines():
            if line.startswith("{") and "eventMessage" in line:
                try:
                    self.handle_log(json.loads(line))
                except ValueError:
                    pass
        return now

    def handle_log(self, j):
        msg = (j.get("eventMessage") or "").strip()
        proc = os.path.basename(j.get("processImagePath") or "")
        now = time.time()
        m = self.JETSAM_EXIT_RE.search(msg)
        r = None if m else self.REPORT_RE.search(msg)
        with self.lock:
            jet = self.jet
            if m:
                key = (j.get("machTimestamp") or j.get("timestamp"), msg)
                if key in self.seen_exits:
                    return
                if len(self.seen_exits) > 20000:
                    self.seen_exits = {k: v for k, v in self.seen_exits.items() if now - v < 600}
                self.seen_exits[key] = now
                ts = log_time(j, now)
                jet["kills"] += 1
                jet["names"][m.group(1)] = jet["names"].get(m.group(1), 0) + 1
                self.kill_times = sorted([x for x in self.kill_times if ts - x <= 60] + [ts])
                recent = [x for x in self.kill_times if ts - x <= 60]
                if len(recent) >= self.STORM_KILLS_PER_MIN and not self.storm:
                    self.storm = True
                    self.pending_triggers.append({"kind": "jetsam_storm", "t": now,
                        "msg": "macOS is killing processes for memory (%d jetsam kills in 60 s)" % len(recent)})
                    self.wake.set()
                return
            if r:
                reason = r.group(3)
                jet["reasons"][reason] = jet["reasons"].get(reason, 0) + 1
                if reason in self.TRIGGER_REASONS and not self.report_trig:
                    self.report_trig = True
                    self.pending_triggers.append({"kind": "jetsam_report", "t": now,
                        "msg": "Processes killed by jetsam, reason %s" % reason})
                    self.wake.set()
                return
        # anything else matched by the predicate (dialog text, kernel low-swap) is rare -> log verbatim
        if now - self.kernel_budget[0] > 60:
            self.kernel_budget = [now, 0]
        self.kernel_budget[1] += 1
        if self.kernel_budget[1] > KERNEL_LINES_PER_MIN:
            return
        low = msg.lower()
        trig = "application memory" in low or "low swap" in low
        self.event("log", process=proc, pid=j.get("processID"), msg=msg[:500], trigger=trig)
        if trig:
            with self.lock:
                self.pending_triggers.append({"kind": "dialog" if "application memory" in low else "lowmem",
                                              "msg": msg[:300], "t": now})
            self.wake.set()

    def flush_jetsam(self):
        """Called once per sample: turn the aggregated counters into one event."""
        with self.lock:
            jet = self.jet
            self.jet = {"kills": 0, "names": {}, "reasons": {}}
            if not self.kill_times or time.time() - max(self.kill_times) > 120:
                self.storm = False
            self.report_trig = False
        if jet["kills"] or jet["reasons"]:
            names = sorted(jet["names"].items(), key=lambda kv: -kv[1])[:15]
            self.event("jetsam", kills=jet["kills"], reasons=jet["reasons"], top=dict(names))
        return jet["kills"]

    def soft_error(self, where, err):
        """A reading that failed costs its block of the sample; it is reported at most hourly."""
        if time.time() - self.soft_at.get(where, 0) >= 3600:
            self.soft_at[where] = time.time()
            self.event("daemon_error", where=where, error=str(err)[:300])

    def resources(self, P, procs, ram_gb, gap, up=None):
        """The sample's cpu, gpu, io and disks blocks and the rates per pid; a failure costs its block."""
        if self.meter is None:
            try:
                self.full = full_speed_rung(P)
                if self.full is None and oomph.ioreport_wanted() and hasattr(P, "ioreport_helper"):
                    self.full_off = "missing"  # switched on, but the helper is not installed next to the logger
                    self.event("daemon_error", where="ioreport", error="switched on, but the IOReport helper "
                               "(oomph_ioreport.py) is missing: the GPU reads busy time")
            except Exception as e:  # the GPU then reads busy time
                self.full_off = "failed"
                self.event("daemon_error", where="ioreport", error=repr(e)[:300])
            self.meter, self.volumes = Meter(P, self.full), Volumes(P)
        try:
            blocks, use = self.meter.read(procs, ram_gb, gap=gap, up=up)
        except Exception as e:
            blocks, use = {}, {}
            self.meter.prev = None
            self.soft_error("meter", repr(e))
        errs, self.meter.errors = self.meter.errors, []
        if self.full is not None:  # a handful per boot at most: each is reported
            for e in self.full.errors:
                self.event("daemon_error", where="ioreport", error=str(e)[:300])
            for e in self.full.notes:  # a Mac that cannot have the figure: designed, so no alarm
                sys.stderr.write("%s oomphd: %s\n" % (now_iso(), e))
                sys.stderr.flush()
            del self.full.errors[:], self.full.notes[:]
        for where, e in errs:
            self.soft_error(where, e)
        if self.meter.scaled > 1 and not self.clamp_told:  # once per start, to daemon.err: a diagnostic, no alarm
            self.clamp_told = True
            sys.stderr.write("%s oomphd: per-process CPU scaled down by %.1f cores to what the machine was busy\n"
                             % (now_iso(), self.meter.scaled))
            sys.stderr.flush()
        try:
            pools = self.volumes.read()[0]
            if pools is not None:
                blocks["disks"] = pools
                if self.volumes.unsure:  # a disk diskutil has not answered for: a pool missing here is not gone
                    blocks["disks_partial"] = True
        except Exception as e:
            self.soft_error("disks", repr(e))
        return blocks, use

    # -- notifications
    def notify(self, title, msg, **kw):
        title, msg = oomph.notify_text(title, 80), oomph.notify_text(msg, 300)
        try:
            if oomph.plat().notify(title, msg, self.console):
                self.event("notified", title=title, msg=msg, **kw)
        except Exception as e:
            self.event("daemon_error", where="notify", error=str(e))

    # -- incidents
    def open_incident(self, t, reasons):
        """Open an incident headlined by its most severe reason. Right after an incident was
        closed for its length, the new one continues it: no notification, and the kill it
        announced stays announced. Only a kill (dialog, low swap) the continued incident had
        not reached is announced, once, as it would have been there."""
        reasons = oomph.sort_reasons(reasons)
        iid = datetime.datetime.fromtimestamp(t).strftime("%Y%m%d-%H%M%S")
        while self.quiet_id(iid):  # Linux: a quiet incident opened in this second keeps its folder
            iid = datetime.datetime.fromtimestamp(datetime.datetime.strptime(iid, "%Y%m%d-%H%M%S").timestamp() + 1).strftime(
                "%Y%m%d-%H%M%S")
        d = os.path.join(LOG_DIR, "incidents", iid)
        os.makedirs(d, exist_ok=True)
        rolled, self.rolled = self.rolled, None
        cont = rolled if rolled and t - rolled[1] <= INCIDENT_CLOSE_AFTER else None
        self.incident = {"id": iid, "start": t, "start_iso": now_iso(t), "last_trigger": t,
                         "reasons": reasons, "opened_by": reasons[0]["kind"], "open": True}
        rank, escalate = oomph.reason_rank(reasons[0]), False
        if cont:
            self.incident["continues"] = cont[0]
            escalate = rank >= oomph.ESCALATE_RANK and rank > cont[2] and not cont[3]
            if cont[3] or escalate:
                self.incident["escalated"] = t if escalate else cont[3]
        write_atomic(os.path.join(d, "incident.json"), json.dumps(self.incident, indent=1))
        self.event("incident_open", id=iid, reasons=reasons, **({"continues": cont[0]} if cont else {}))
        threading.Thread(target=self.dump_syslog, args=(d,), daemon=True).start()
        if escalate:
            self.last_notify = time.time()
            self.notify("Memory incident", "%s — papertrail: oomph incident %s" % (reasons[0]["desc"], iid), event="kill")
            self.alert("kill", self.incident, reasons[0]["desc"])
        elif not cont and time.time() - self.last_notify > NOTIFY_COOLDOWN:
            self.last_notify = time.time()
            self.notify("Memory incident", "%s — papertrail: oomph incident %s" % (reasons[0]["desc"], iid))
            self.alert("open", self.incident, reasons[0]["desc"])
        elif not cont:  # within the cool-down: no notification, no hook, but the journal line at critical, always
            self.journal(2, "Memory incident: %s — papertrail: oomph incident %s"
                         % (oomph.notify_text(reasons[0]["desc"], 300), iid))
        if cont and len(cont) > 4 and cont[4]:
            self.incident["alerted"] = True  # the hooks heard of the incident it continues: they hear of its close

    def join_incident(self, t, reasons):
        """Add the reasons the open incident doesn't have yet, keeping the most severe first.
        One that takes over the headline and is a kill, the dialog or low swap is announced
        once more, past the cool-down: the notification of an incident opened by pressure
        would otherwise be the only one, and name the lesser cause."""
        inc = self.incident
        inc["last_trigger"] = t
        known = {r["kind"] for r in inc["reasons"]}
        top = max([oomph.reason_rank(r) for r in inc["reasons"]] + [0])
        changed = False
        for r in reasons:
            if r["kind"] in known or len(inc["reasons"]) >= 20:
                continue
            known.add(r["kind"])
            inc["reasons"] = oomph.sort_reasons(inc["reasons"] + [r])
            changed = True
            rank = oomph.reason_rank(r)
            if rank > top and rank >= oomph.ESCALATE_RANK and not inc.get("escalated"):
                inc["escalated"] = t
                self.last_notify = time.time()
                self.notify("Memory incident", "%s — papertrail: oomph incident %s" % (r["desc"], inc["id"]),
                            event="kill")
                self.alert("kill", inc, r["desc"])
            elif r["kind"] in ("dialog", "lowmem", "jetsam_storm", "jetsam_report", "unowned", "stall") and \
                    time.time() - self.last_notify > NOTIFY_COOLDOWN:
                self.last_notify = time.time()
                self.notify("Memory incident", r["desc"])
            top = max(top, rank)
        if changed:  # readers see the new headline while it is still open
            try:
                write_atomic(os.path.join(LOG_DIR, "incidents", inc["id"], "incident.json"), json.dumps(inc, indent=1))
            except OSError as e:
                self.event("daemon_error", where="join_incident", error=str(e))

    def dump_syslog(self, d):
        oomph.plat().dump_syslog(d, oomph.LOG_PREDICATE)

    def close_incident(self, t, rolled=False):
        """Close, summarise and write the report. Both read the samples one at a time: the
        report spans the day before, and the logger must not hold that in memory."""
        inc = self.incident
        self.incident = None
        inc["end"] = t
        inc["end_iso"] = now_iso(t)
        inc["open"] = False
        if rolled:
            inc["rolled"] = True
        d = os.path.join(LOG_DIR, "incidents", inc["id"])
        try:
            samples = oomph.iter_samples(inc["start"] - INCIDENT_LOOKBACK, t)
            events = oomph.load_events(inc["start"] - INCIDENT_LOOKBACK, t)
            inc["summary"] = oomph.summarize(samples, events)
            write_atomic(os.path.join(d, "incident.json"), json.dumps(inc, indent=1))
            html = oomph.incident_html(inc)
            write_atomic(os.path.join(d, "report.html"), html)
        except Exception as e:
            write_atomic(os.path.join(d, "incident.json"), json.dumps(inc, indent=1))
            self.event("daemon_error", where="close_incident", error=repr(e))
        self.event("incident_close", id=inc["id"], duration_s=round(t - inc["start"]), **({"rolled": True} if rolled else {}))
        if not rolled and inc.get("alerted"):
            self.close_alert(t, inc)

    def close_alert(self, t, inc):
        """The close record and journal line of an incident the hooks heard of (or of the one it continued)."""
        self.alert("close", inc, (inc.get("reasons") or [{}])[0].get("desc", ""))
        self.journal(5, "memory incident %s closed after %d min" % (inc["id"], round((t - inc["start"]) / 60)))

    # -- alert records and journal lines (Linux, 03 §5.13)
    def journal(self, level, text):
        P = oomph.plat()
        if hasattr(P, "journal"):
            P.journal(level, text)

    def alert(self, ev, inc, desc):
        """An alert record alerts/<incident>.<event>.json (open, kill, close) for the scripts in
        /etc/oomph/alert.d, which oomph-alert.service runs; the logger itself runs nothing. Only where the
        backend says so (Linux), never for a quiet incident or a roll-over (03 §5.13)."""
        if not getattr(oomph.plat(), "ALERTS", False) or inc.get("quiet"):
            return
        try:
            d = os.path.join(LOG_DIR, "alerts")
            os.makedirs(d, exist_ok=True)
            host = oomph.notify_text(((self.machine or {}).get("name") or os.uname()[1]), 64)
            rec = {"v": 1, "event": ev, "incident": inc["id"], "t": round(time.time(), 3), "iso": now_iso(), "host": host,
                   "level": "notice" if ev == "close" else "critical", "title": "Memory incident on %s" % host,
                   "message": oomph.notify_text(desc, 300),
                   "report": os.path.join(LOG_DIR, "incidents", inc["id"], "report.html" if ev == "close" else "")}
            if inc.get("continues"):  # a roll-over's next part: its close ends what the first part opened
                rec["continues"] = inc["continues"]
            write_atomic(os.path.join(d, "%s.%s.json" % (inc["id"], ev)), json.dumps(rec))
            inc["alerted"] = True
            self.alert_t = time.time()
            self.beat()
        except OSError as e:
            self.event("daemon_error", where="alert", error=str(e)[:300])

    def beat(self):
        """alerts/.beat rewritten while an alert record is young: each rewrite starts oomph-alert.path again, so
        a record written while the runner was finishing is not left until the next one (03 Appendix A)."""
        if self.alert_t and time.time() - self.alert_t < ALERT_BEAT_S:
            try:
                write_atomic(os.path.join(LOG_DIR, "alerts", ".beat"), "%.1f\n" % time.time())
            except OSError:
                pass

    # -- quiet incidents (Linux, 03 §5.6): containers at their own limit
    def quiet_storms(self, t):
        """Cgroups that hit their own limit five times in ten minutes share one quiet incident per machine and
        day: no notification, no alert, a journal line at notice. While it is open each further cgroup joins
        it; after it closed, the day's later storms are folded into it (`repeats`) and it is written again at
        its next close."""
        with self.lock:
            storms, self.storms = self.storms, []
        q = self.quiet
        if storms:
            if q is None:
                day = datetime.date.fromtimestamp(t).strftime("%Y%m%d")
                q = self.quiet_of_day(day)
                if q is None:
                    iid = datetime.datetime.fromtimestamp(t).strftime("%Y%m%d-%H%M%S")
                    while os.path.exists(os.path.join(LOG_DIR, "incidents", iid)) or \
                            (self.incident and self.incident["id"] == iid):
                        t += 1
                        iid = datetime.datetime.fromtimestamp(t).strftime("%Y%m%d-%H%M%S")
                    q = {"id": iid, "start": t, "start_iso": now_iso(t), "quiet": True, "open": True, "cgroups": [],
                         "opened_by": "cgroup_oom_storm", "reasons": []}
                    self.event("incident_open", id=iid, quiet=True, reasons=[{"kind": "cgroup_oom_storm", "t": t}])
                else:
                    q.update(open=True, repeats=q.get("repeats", 0) + 1)
                    q.pop("end", None)
                    q.pop("end_iso", None)
                self.quiet = q
            for name, ooms, cg, at in storms:
                row = next((c for c in q["cgroups"] if c["name"] == name), None)
                if row is None:
                    row = {"name": name, "ooms": 0, "first": round(at, 1)}
                    q["cgroups"].append(row)
                row.update(ooms=max(row["ooms"], ooms), last=round(at, 1))
            q["cgroups"].sort(key=lambda c: -c["ooms"])
            q["more"] = max(0, len(q["cgroups"]) - 20)
            del q["cgroups"][20:]
            q["last_trigger"] = t
            top = q["cgroups"][0]
            desc = oomph.notify_text("%s: %d OOMs at its limit" % (top["name"], top["ooms"]), 44) \
                if len(q["cgroups"]) == 1 else "%d containers hit their limit repeatedly" % (len(q["cgroups"]) + q["more"])
            new = not q["reasons"]
            q["reasons"] = [{"kind": "cgroup_oom_storm", "t": q["start"], "desc": desc}]
            try:
                d = os.path.join(LOG_DIR, "incidents", q["id"])
                os.makedirs(d, exist_ok=True)
                write_atomic(os.path.join(d, "incident.json"), json.dumps(q, indent=1))
            except OSError as e:
                self.event("daemon_error", where="quiet_incident", error=str(e)[:300])
            if new:
                self.journal(5, "containers at their own memory limit: %s (quiet incident %s)" % (desc, q["id"]))
        elif q is not None and t - q.get("last_trigger", t) > INCIDENT_CLOSE_AFTER:
            self.quiet = None
            q.update(open=False, end=t, end_iso=now_iso(t))
            d = os.path.join(LOG_DIR, "incidents", q["id"])
            try:
                q["summary"] = oomph.summarize(oomph.iter_samples(q["start"] - INCIDENT_LOOKBACK, t),
                                               oomph.load_events(q["start"] - INCIDENT_LOOKBACK, t))
                write_atomic(os.path.join(d, "incident.json"), json.dumps(q, indent=1))
                write_atomic(os.path.join(d, "report.html"), oomph.incident_html(q))
            except Exception as e:
                write_atomic(os.path.join(d, "incident.json"), json.dumps(q, indent=1))
                self.event("daemon_error", where="close_incident", error=repr(e)[:300])
            self.event("incident_close", id=q["id"], quiet=True, duration_s=round(t - q["start"]))

    def quiet_id(self, iid):
        """Is `iid` the folder of a quiet incident (open, or written today)?"""
        if self.quiet and self.quiet["id"] == iid:
            return True
        try:
            with open(os.path.join(LOG_DIR, "incidents", iid, "incident.json")) as f:
                return json.load(f).get("quiet") is True
        except (OSError, ValueError, AttributeError):
            return False

    def quiet_of_day(self, day):
        """Today's quiet incident, closed, to fold a later storm into; None if there is none."""
        for f in sorted(glob.glob(os.path.join(LOG_DIR, "incidents", day + "-*", "incident.json")), reverse=True):
            try:
                with open(f) as h:
                    inc = json.load(h)
            except (OSError, ValueError):
                continue
            if isinstance(inc, dict) and inc.get("quiet") and isinstance(inc.get("cgroups"), list):
                return inc
        return None

    # -- maintenance
    def maintenance(self):
        today = datetime.date.today()
        for f in glob.glob(os.path.join(LOG_DIR, "samples-*.jsonl*")):
            m = re.search(r"samples-(\d{4}-\d{2}-\d{2})\.jsonl(\.gz)?$", f)
            if not m:
                continue
            day = datetime.date.fromisoformat(m.group(1))
            if (today - day).days > RETAIN_DAYS:
                os.remove(f)
            elif day < today and not m.group(2):
                with open(f, "rb") as src, gzip.open(f + ".gz", "wb") as dst:
                    shutil.copyfileobj(src, dst)
                os.chmod(f + ".gz", 0o644)
                os.remove(f)
        ev = os.path.join(LOG_DIR, "events.jsonl")
        if os.path.exists(ev) and os.path.getsize(ev) > 20 * MB:
            os.replace(ev, ev + ".1")
        cutoff = time.time() - INCIDENT_RETAIN_DAYS * 86400
        quiet = time.time() - QUIET_RETAIN_DAYS * 86400
        for d in glob.glob(os.path.join(LOG_DIR, "incidents", "*")):
            m = os.path.getmtime(d)
            if m < cutoff:
                shutil.rmtree(d, ignore_errors=True)
            elif m < quiet and (not self.quiet or self.quiet["id"] != os.path.basename(d)):
                try:
                    with open(os.path.join(d, "incident.json")) as f:
                        if json.load(f).get("quiet"):
                            shutil.rmtree(d, ignore_errors=True)
                except (OSError, ValueError, AttributeError):
                    pass
        for f in glob.glob(os.path.join(LOG_DIR, "alerts", "*.json")):
            try:
                if os.path.getmtime(f) < time.time() - ALERT_KEEP_S:
                    os.remove(f)
            except OSError:
                pass

    # -- main loop
    def sample(self):
        P = oomph.plat()
        t = time.time()
        sysm = P.system_memory()
        away = P.away_state()
        if away.get("uid") is not None:
            self.console = {"uid": away["uid"], "user": away["user"]}
        procs = P.collect_procs()
        up = P.uptime_s()  # here, not later: the Meter's interval must be the process table's
        killed = None
        if self.kills is not None:  # Linux: from the journal (or the kernel's counter), one event per sample
            killed = self.kills.flush(max(self.prev_pressure or 1, sysm.get("pressure") or 1), procs)
            jetsam_kills = killed["kills"]
            if killed["victims"] or killed["by"]:
                self.event("oom_kill", kills=killed["kills"], cgroup=killed["cgroup"], ooms=killed["ooms"],
                           by=killed["by"], top=killed["top"], victims=killed["victims"])  # (machine-wide, at a limit)
        else:
            jetsam_kills = self.flush_jetsam()

        big = {(p["pid"], p["start"]): (p["name"], round(p["fp"] / MB)) for p in procs.values()
               if p["fp"] >= GONE_MIN_MB * MB}
        gone = [{"pid": k[0], "name": v[0], "mb": v[1]} for k, v in self.prev_big.items() if k not in big
                and k[0] not in procs]
        # a pid that is still present with the same start time is not gone
        self.prev_big = big

        gap = stall = None
        if self.prev_t and t - self.prev_t > 3 * (HOT_INTERVAL if self.hot else INTERVAL) + 5:
            gap = round(t - self.prev_t)
            asleep = max(0.0, (t - self.prev_t) - (up - self.prev_up)) if self.prev_up is not None else gap
            if asleep >= gap / 2:
                self.event("sleep_gap", seconds=gap, asleep_s=round(asleep))
            else:
                # awake, yet the daemon didn't get to run: the system is starved
                stall = gap
                self.event("stall", seconds=gap, pressure=sysm["pressure"], swap_used_gb=sysm["swap_used_gb"])
                if gap >= STALL_TRIGGER_S:
                    with self.lock:
                        self.pending_triggers.append({"kind": "stall", "t": t,
                            "msg": "oomph couldn't run for %d s while the %s was awake — the system is starved for memory"
                            % (gap, "Mac" if P.OS == "macos" else "machine")})
        self.prev_t, self.prev_up = t, up
        blocks, use = self.resources(P, procs, sysm.get("ram_gb"), bool(gap), up)
        top, groups, sessions, session_of = _summarize(procs, use)

        s = {"t": round(t, 1), "iso": now_iso(t), "hot": self.hot, "os": P.OS}
        if gap:
            s["gap"] = gap
        if stall:
            s["stall"] = stall
        s.update(sysm)
        s.update(P.ownership(sysm, procs))
        s["jetsam_kills"] = jetsam_kills
        if killed is not None:
            s["cgroup_kills"] = killed["cgroup"]
            big = [{"name": v["name"], "mb": v.get("mb"), "by": v["by"]} for v in killed["victims"] if v["by"] != "cgroup"]
            if big:
                s["killed"] = big[:3]
        s.update(blocks)  # cpu, gpu, disks, io (02 §5.1): each where it could be read
        s["away"] = {k: away[k] for k in ("idle_s", "display_on", "locked", "sleep_preventers")}
        s["top"] = top
        s["groups"] = groups
        s["claude"] = sessions
        s.update(rate_lists(procs, use, session_of, P.group_key))
        names = cpu_names(procs, use)
        if names:
            s["cpu_names"] = names
        # Retire reservations of sessions that died or expired, close to when it happened, and
        # copy the live ones into the sample. The shared ledger directory is world-writable, so
        # the daemon never opens anything in it: its thread hands the work to an unprivileged
        # child and the sample carries the last snapshot that child answered with (none if it
        # is older than two intervals).
        leases = self.ledger.latest(2 * (HOT_INTERVAL if self.hot else INTERVAL))
        pools = None
        cp = cpu_pool_block(s.get("cpu"), leases, self.cpu_others)
        if cp is not None:  # what only the logger knows well, for admission (02 §5.2): current.json only
            self.cpu_others = cp.get("others", self.cpu_others)
            pools = {"t": s["t"], "cpu": cp}
        rates = {pid: u["cpu"] for pid, u in use.items() if "cpu" in u} if use else None
        writes = {pid: u["w"] for pid, u in use.items() if u.get("w")} if use else None
        gpus = {pid: u["gpu"] for pid, u in use.items() if u.get("gpu")} if use else None
        self.ledger.offer(dict({k: v for k, v in s.items() if k not in ("top", "groups", "claude", "cpu_names")
                                and k not in TOP_RATES}, **({"pools": pools} if pools else {})),
                          procs, rates or None, writes or None, gpus or None)
        if leases:  # memory sessions have reserved through oomph's ledger (purposes left out where it is a group's)
            s["leases"] = [dict(x, purpose="?", project=None) for x in leases] if ledger_kept_to_group() else leases
        if gone:
            s["gone"] = gone
        if self.incident:
            s["incident"] = self.incident["id"]

        day = datetime.date.fromtimestamp(t).isoformat()
        with self.lock:
            append_json(os.path.join(LOG_DIR, "samples-%s.jsonl" % day), s)
        cur = dict(s)
        if pools:
            cur["pools"] = pools
        if self.machine is None:
            try:
                self.machine = P.machine()
            except Exception as e:  # who this machine is matters less than the sample
                self.machine = {"os": P.OS}
                self.event("daemon_error", where="machine", error=repr(e)[:300])
        if self.kills is not None and isinstance(self.machine.get("measures"), dict):
            self.machine["measures"]["kills"] = self.kills.mode  # journal, or count where it cannot be read
        cur["daemon"] = {"pid": os.getpid(), "version": VERSION, "started": self.started,
                         "interval": HOT_INTERVAL if self.hot else INTERVAL,
                         "incident": self.incident["id"] if self.incident else None,
                         "root": os.geteuid() == 0, "machine": self.machine}
        if P.OS != "macos":
            cur["daemon"].update(user=oomph._whoami(), all_procs=bool((self.machine.get("measures") or {}).get("all_procs")))
            if self.quiet:
                cur["daemon"]["quiet"] = self.quiet["id"]
        self.beat()
        if self.full is not None or self.full_off:
            cur["daemon"]["ioreport"] = self.full.status() if self.full is not None else self.full_off
        write_atomic(os.path.join(LOG_DIR, "current.json"), json.dumps(cur))
        return s

    hot = False

    def evaluate(self, s):
        t = s["t"]
        pr = s["pressure"]
        if self.prev_pressure is not None and pr != self.prev_pressure:
            if self.flap is None and t - self.last_pr_event > FLAP_WINDOW:
                self.event("pressure_change", old=self.prev_pressure, new=pr,
                           swap_used_gb=s["swap_used_gb"], disk_free_gb=s["disk_free_gb"],
                           idle_s=s["away"]["idle_s"])
                self.last_pr_event = t
            else:  # flapping: count it, report once it settles (or every 15 min)
                f = self.flap = self.flap or {"since": t, "flips": 0, "levels": {self.prev_pressure}}
                f["flips"] += 1
                f["levels"].add(pr)
                f["last"] = t
        self.prev_pressure = pr
        if self.flap and (t - self.flap["last"] > FLAP_WINDOW or t - self.flap["since"] >= FLAP_REPORT_EVERY):
            f, self.flap = self.flap, None
            self.event("pressure_flapping", since=now_iso(f["since"]), flips=f["flips"],
                       levels=[oomph.PRESSURE.get(x, x) for x in sorted(f["levels"])],
                       now=oomph.PRESSURE.get(pr, pr), swap_used_gb=s["swap_used_gb"])
            self.last_pr_event = t

        self.swap_hist = [(tt, v) for tt, v in self.swap_hist if t - tt <= 60] + [(t, s["swap_used_gb"])]
        swap_jump = s["swap_used_gb"] - min(v for _, v in self.swap_hist) > 0.5

        with self.lock:
            trig = self.pending_triggers
            self.pending_triggers = []
        reasons = [{"kind": x["kind"], "desc": x["msg"][:120], "t": x["t"]} for x in trig]
        u, lim = s.get("unowned_gb"), oomph.unowned_limit_gb(s["ram_gb"])
        if u is not None and u >= lim:
            self.unowned_since = self.unowned_since or t
            if t - self.unowned_since >= UNOWNED_SUSTAIN_S:
                if not self.unowned_flagged:
                    self.unowned_flagged = True
                    gpu = [g.get("mem_alloc_gb") for g in s.get("gpu") or () if isinstance(g, dict)]
                    gpu = [x for x in gpu if isinstance(x, (int, float))]
                    self.event("unowned_memory", gb=u, procs_gb=s.get("procs_gb"),
                               compressor_logical_gb=s["compressor_logical_gb"],
                               **({"gpu_alloc_gb": round(sum(gpu), 2)} if gpu else {}))
                reasons.append({"kind": "unowned", "t": t, "desc": "%.0f GB of memory belongs to no process — likely a GPU "
                                "or driver leak; save your work and restart before the Mac freezes" % u})
        else:
            self.unowned_since = None
            if self.unowned_flagged and (u is None or u < 0.75 * lim):
                self.unowned_flagged = False
                self.event("unowned_memory_cleared", gb=u)
        if pr >= 4 and s.get("os") == "linux":
            psi = s.get("psi") if isinstance(s.get("psi"), dict) else {}
            reasons.append({"kind": "pressure", "t": t, "desc": "pressure CRITICAL (stalled %d%%, fully %d%%)" % (
                round(psi.get("mem_some") or 0), round(psi.get("mem_full") or 0)) if psi else
                "pressure CRITICAL (%.1f GB available)" % ((s.get("linux") or {}).get("avail_gb") or 0)})
        elif pr >= 4:
            reasons.append({"kind": "pressure", "desc": "Memory pressure CRITICAL (swap %.1f GB, disk %.0f GB free)"
                            % (s["swap_used_gb"], s["disk_free_gb"]), "t": t})
        if self.kills is not None:
            try:
                self.quiet_storms(t)
            except Exception as e:  # a quiet incident lost costs no sample
                self.soft_error("quiet_incident", repr(e))
        inc = self.incident
        if inc and t - inc.get("start", t) >= INCIDENT_MAX_S:
            if t - inc.get("last_trigger", t) <= INCIDENT_CLOSE_AFTER:  # still going: continued below
                top = max([oomph.reason_rank(r) for r in inc.get("reasons", [])] + [0])
                # a kill it opened with was announced then: the continuation doesn't announce it again
                done = inc.get("escalated") or (inc.get("start") if top >= oomph.ESCALATE_RANK else None)
                self.rolled = (inc["id"], t, top, done, inc if inc.get("alerted") else None)
                self.close_incident(t, rolled=True)
            else:  # left open across a sleep or a restart: it ended, a trigger now opens a new one
                self.close_incident(t)
        r = self.rolled
        if r and t - r[1] > INCIDENT_CLOSE_AFTER:  # rolled over, then nothing went on: it ended
            self.rolled = None
            if r[4]:
                self.close_alert(t, r[4])
        if reasons:
            if self.incident:
                self.join_incident(t, reasons)
            else:
                self.open_incident(t, reasons)
        elif self.incident and t - self.incident["last_trigger"] > INCIDENT_CLOSE_AFTER:
            self.close_incident(t)

        # swap grows on the startup disk of a Mac: there a full disk is a memory problem (roadmap 03 §5.4)
        mac = s.get("os", "macos") == "macos"
        pools = [p for p in s.get("disks") or () if isinstance(p, dict) and isinstance(p.get("id"), str)] \
            if isinstance(s.get("disks"), list) else None
        if not any(p["id"] == "data" and p.get("watch") for p in pools or ()) and mac and \
                s["disk_free_gb"] < DISK_LOW_GB and time.time() - self.last_disk_notify > DISK_COOLDOWN:
            self.last_disk_notify = time.time()     # a logger without the disks block: the startup disk as before
            self.disk_low_at["data"] = t            # (one cooldown for both ways, whichever told it)
            self.event("disk_low", disk_free_gb=s["disk_free_gb"])
            self.notify("Disk space low", "Only %.0f GB free — swap can't grow, risk of memory kills."
                        % s["disk_free_gb"])
        try:
            self.resource_events(s, t, pools, mac)
        except Exception as e:  # an event lost costs no sample
            self.soft_error("resource_events", repr(e))

        self.hot = bool(pr >= 2 or swap_jump or s.get("jetsam_kills") or (mac and s["disk_free_gb"] < 5) or self.incident
                        or self.filling)

    def resource_events(self, s, t, pools, mac):
        """The events of the other resources (roadmap 02 §5.3): the thermal level changed (batched like
        pressure flips), the cores saturated for ten minutes and when that is over, a watched disk low
        (per disk) or filling fast, a disk that came or went. Times are the sample's."""
        cpu = s.get("cpu") if isinstance(s.get("cpu"), dict) else {}
        busy, n = cpu.get("busy"), cpu.get("n")
        th = cpu.get("therm")
        if isinstance(th, int) and not isinstance(th, bool):
            if self.prev_therm is not None and th != self.prev_therm:
                if self.therm_batch is None and t - self.last_therm_event > FLAP_WINDOW:
                    self.event("thermal", old=self.prev_therm, new=th, busy=busy)
                    self.last_therm_event = t
                else:
                    b = self.therm_batch = self.therm_batch or {"old": self.prev_therm, "flips": 0, "since": t}
                    b["flips"], b["last"] = b["flips"] + 1, t
            self.prev_therm = th
            b = self.therm_batch
            if b and (t - b["last"] > FLAP_WINDOW or t - b["since"] >= FLAP_REPORT_EVERY):
                self.therm_batch = None
                self.event("thermal", old=b["old"], new=th, busy=busy, flips=b["flips"])
                self.last_therm_event = t
        ok = isinstance(busy, (int, float)) and not isinstance(busy, bool) and isinstance(n, int) and n > 0
        if self.sat_since is not None and (not ok or t - self.sat_last > CPU_SAT_GAP):
            if self.sat_on:     # a sleep or a logger gap (no rates after one) ends the episode where it was last seen
                self.event("cpu_saturated_cleared", n=self.sat_n, minutes=round((self.sat_last - self.sat_since) / 60),
                           gap=round(t - self.sat_last))
            self.sat_since, self.sat_on = None, False
        if ok:
            if busy >= CPU_SAT * n:
                self.sat_since = self.sat_since or t
                if not self.sat_on and t - self.sat_since >= CPU_SAT_S and t - self.last_sat >= CPU_SAT_COOLDOWN:
                    self.sat_on, self.last_sat = True, t
                    names = [x for x in s.get("cpu_names") or () if isinstance(x, dict)][:5]
                    self.event("cpu_saturated", busy=busy, n=n, minutes=round((t - self.sat_since) / 60),
                               **({"top": {x["name"]: x["cpu"] for x in names}, "top_n": {x["name"]: x["n"] for x in names}}
                                  if names else {"top": _by_name(s.get("top_cpu"), "cpu")}))
            elif busy < CPU_SAT_CLEAR * n or not self.sat_on:   # once saturated, over only below the lower mark
                if self.sat_on:
                    self.event("cpu_saturated_cleared", busy=busy, n=n, minutes=round((t - self.sat_since) / 60))
                self.sat_since, self.sat_on = None, False
            self.sat_last, self.sat_n = t, n
        if pools is None:
            return
        for p in pools:
            if not p.get("watch") or not isinstance(p.get("free_gb"), (int, float)):
                continue
            pid, free = p["id"], p["free_gb"]
            what = dict(pool=pid, mount=p.get("mount"), name=p.get("name"), free_gb=free)
            crit = p["crit_gb"] if isinstance(p.get("crit_gb"), (int, float)) else 5
            if p.get("level") in ("low", "critical") and t - self.disk_low_at.get(pid, -1e18) > DISK_COOLDOWN:
                self.disk_low_at[pid] = t
                if pid == "data" and not mac:           # Linux: no swap on it, so no memory wording (03 §5.4)
                    self.event("disk_low", disk_free_gb=free, level=p["level"], **what)
                    self.notify("Disk space low", "Only %.0f GB free on %s." % (
                        free, oomph.notify_text(p.get("mount") or "/", 40)))
                elif pid == "data":
                    self.last_disk_notify = time.time()
                    self.event("disk_low", disk_free_gb=s.get("disk_free_gb", free), level=p["level"], **what)
                    self.notify("Disk space low", "Only %.0f GB free — swap can't grow, risk of memory kills." % free)
                else:
                    self.event("disk_low", level=p["level"], **what)
                    self.notify("Disk space low", "Only %.0f GB free on %s." % (free, oomph.notify_text(p.get("name"), 40)))
            hist = [x for x in self.free_hist.get(pid, ()) if t - 600 <= x[0] < t] + [(t, free)]
            self.free_hist[pid] = hist
            back = [x for x in hist if t - x[0] >= DISK_FILL_S]
            filling = None
            if back and t - back[-1][0] <= 2.5 * DISK_FILL_S:
                t0, f0 = back[-1]
                rate = (f0 - free) / ((t - t0) / 60.0)
                if f0 - free >= DISK_FILL_GB and rate > 0:
                    eta = max(0.0, (free - crit) / rate)
                    if eta <= DISK_FILL_ETA_MIN:
                        filling = (round(rate, 2), round(eta, 1))
            if filling is None:
                self.filling.pop(pid, None)
                continue
            self.filling[pid] = t
            if t - self.fill_at.get(pid, -1e18) > DISK_FILL_COOLDOWN:
                self.fill_at[pid] = t
                self.event("disk_filling", rate_gb_min=filling[0], eta_min=filling[1], top=_by_name(s.get("top_io"), "w"),
                           **what)
            if filling[1] < DISK_FILL_NOTIFY_MIN and t - self.fill_told.get(pid, -1e18) > DISK_FILL_COOLDOWN:
                self.fill_told[pid] = t
                self.notify("Disk filling up", "%s: %.0f GB free, full in about %d min at %.1f GB a minute." % (
                    oomph.notify_text(p.get("name") or pid, 40), free, max(1, round(filling[1])), filling[0]),
                    event="disk_filling")
        cur = {p["id"]: (bool(p.get("watch")), p.get("mount"), p.get("name")) for p in pools}
        for d in (self.filling, self.free_hist):        # a disk that went is neither filling nor remembered
            for pid in [k for k in d if k not in cur or not cur[k][0]]:
                del d[pid]
        prev, self.prev_pools = self.prev_pools, cur
        if prev is None or t - self.started < VOLUME_SETTLE_S:
            return
        def what(a, b):
            return None if a is None and b is None else "mounted" if a is None else "unmounted" if b is None else \
                ("watched" if b[0] else "unwatched") if a[0] != b[0] else None

        for pid in [k for k, w in self.vol_at.items() if t - w > VOLUME_QUIET_S and k not in self.vol_held]:
            del self.vol_at[pid]                        # (only the recent ones are kept)
        for pid in sorted(set(cur) | set(prev) | set(self.vol_held)):
            a, b, held = prev.get(pid), cur.get(pid), self.vol_held.get(pid)
            if what(a, b):
                if held is None and t - self.vol_at.get(pid, -1e18) > VOLUME_QUIET_S:
                    x = b or a
                    self.event("volume", pool=pid, mount=x[1], name=x[2], what=what(a, b))
                    self.vol_at[pid] = t
                    continue
                held = self.vol_held.setdefault(pid, [a, 0, None])
                held[1], held[2] = held[1] + 1, b or a
            if held and t - self.vol_at.get(pid, -1e18) > VOLUME_QUIET_S:
                del self.vol_held[pid]                  # the quiet time is over: how it is now against what was told
                if what(held[0], b):
                    x = b or held[2]
                    self.event("volume", pool=pid, mount=x[1], name=x[2], what=what(held[0], b), changes=held[1])
                    self.vol_at[pid] = t

    def run(self):
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        self.event("daemon_start", version=VERSION, pid=os.getpid(), root=os.geteuid() == 0,
                   **({"os": oomph.plat().OS, "user": oomph._whoami()} if oomph.plat().OS != "macos" else {}))
        # resume a still-open incident after restart
        for f in sorted(glob.glob(os.path.join(LOG_DIR, "incidents", "*", "incident.json")))[-3:]:
            try:
                inc = json.load(open(f))
                if inc.get("open") and inc.get("quiet"):
                    self.quiet = inc
                elif inc.get("open"):
                    self.incident = inc
            except Exception:
                pass
        P = oomph.plat()
        if P.OS == "macos":  # kills are read from the unified log
            threading.Thread(target=self.stream_loop, daemon=True).start()
            threading.Thread(target=self.poll_loop, daemon=True).start()
        if hasattr(P, "KillWatcher"):  # Linux: from the journal, or the kernel's counter (03 §5.5)
            try:
                os.makedirs(STATE_DIR, exist_ok=True)
            except OSError:
                pass
            self.kills = P.KillWatcher(STATE_DIR, trigger=self.trigger, storm=self.cgroup_storm, event=self.event).start()
        if hasattr(P, "PressureWatch"):
            P.PressureWatch(self.wake.set, lambda: self.hot).start()
        self.ledger.start()
        while not self.stopping:
            t0 = time.time()
            try:
                if t0 - self.last_maint > 3600:
                    self.last_maint = t0
                    self.maintenance()
                s = self.sample()
                self.evaluate(s)
            except Exception as e:
                self.event("daemon_error", where="loop", error=repr(e))
            delay = (HOT_INTERVAL if self.hot else INTERVAL) - (time.time() - t0)
            self.wake.wait(max(delay, 1))
            self.wake.clear()

    def stop(self, *_):
        self.stopping = True
        if self.kills is not None:
            self.kills.stop()
        if self.full is not None:  # a reading this signal interrupts is not a crash of the helper
            self.full.close(final=True)
        if self.stream_proc:
            try:
                self.stream_proc.terminate()
            except Exception:
                pass
        self.event("daemon_stop")
        sys.exit(0)


if __name__ == "__main__":
    Daemon().run()
