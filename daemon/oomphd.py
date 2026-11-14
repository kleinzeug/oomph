#!/usr/bin/python3 -I
"""oomphd — continuous memory papertrail for macOS. See ../DESIGN.md.

Runs as a root LaunchDaemon. For unprivileged testing set OOMPH_DIR to a
writable directory (only your own processes will report a footprint then).
"""
import ctypes
import datetime
import glob
import gzip
import json
import os
import plistlib
import re
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oomph  # noqa: E402  (shared paths + HTML/summary rendering)

VERSION = oomph.VERSION
LOG_DIR = oomph.LOG_DIR

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
INCIDENT_LOOKBACK = 15 * 60
KERNEL_LINES_PER_MIN = 60

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
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
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
        raw = subprocess.run(["/usr/sbin/ioreg", "-n", "Root", "-d1", "-a"], capture_output=True, timeout=10).stdout
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


def summarize_procs(procs):
    by_fp = sorted(procs.values(), key=lambda p: p["fp"], reverse=True)
    top = [{"pid": p["pid"], "ppid": p["ppid"], "name": p["name"], "uid": p["uid"],
            "mb": round(p["fp"] / MB), "rss_mb": round(p["rss"] / MB)} for p in by_fp[:TOP_N]]
    groups = {}
    for p in procs.values():
        g = groups.setdefault(group_key(p["path"], p["name"]), [0, 0])
        g[0] += p["fp"]
        g[1] += 1
    grp = [{"name": k, "mb": round(v[0] / MB), "n": v[1]}
           for k, v in sorted(groups.items(), key=lambda kv: kv[1][0], reverse=True)[:GROUPS_N]]

    children = {}
    for p in procs.values():
        children.setdefault(p["ppid"], []).append(p["pid"])

    def is_claude(p):
        return p["name"] == "claude"

    sessions = []
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
        desc = [procs[m] for m in members if m != p["pid"] and m in procs]
        big = max(desc, key=lambda d: d["fp"]) if desc else None
        sessions.append({
            "pid": p["pid"], "cwd": proc_cwd(p["pid"]),
            "mb": round(sum(procs[m]["fp"] for m in members if m in procs) / MB),
            "own_mb": round(p["fp"] / MB), "n": len(members),
            "biggest": {"name": big["name"], "pid": big["pid"], "mb": round(big["fp"] / MB)} if big else None,
        })
    sessions.sort(key=lambda s: s["mb"], reverse=True)
    return top, grp, sessions


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


class Daemon:
    def __init__(self):
        os.umask(0o022)
        os.makedirs(os.path.join(LOG_DIR, "incidents"), exist_ok=True)
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
        self.swap_hist = []
        self.incident = None
        self.last_notify = 0
        self.last_disk_notify = 0
        self.last_maint = 0
        self.started = time.time()
        self.console = {"uid": None, "user": None}
        self.stopping = False
        self.stream_proc = None

    # -- events
    def event(self, kind, **kw):
        ev = {"t": round(time.time(), 1), "iso": now_iso(), "kind": kind}
        ev.update(kw)
        with self.lock:
            append_json(os.path.join(LOG_DIR, "events.jsonl"), ev)
        return ev

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

    def handle_log(self, j):
        msg = (j.get("eventMessage") or "").strip()
        proc = os.path.basename(j.get("processImagePath") or "")
        now = time.time()
        m = self.JETSAM_EXIT_RE.search(msg)
        r = None if m else self.REPORT_RE.search(msg)
        with self.lock:
            jet = self.jet
            if m:
                jet["kills"] += 1
                jet["names"][m.group(1)] = jet["names"].get(m.group(1), 0) + 1
                self.kill_times = [x for x in self.kill_times if now - x <= 60] + [now]
                if len(self.kill_times) >= self.STORM_KILLS_PER_MIN and not self.storm:
                    self.storm = True
                    self.pending_triggers.append({"kind": "jetsam_storm", "t": now,
                        "msg": "macOS is killing processes for memory (%d jetsam kills in 60 s)" % len(self.kill_times)})
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
            if not self.kill_times or time.time() - self.kill_times[-1] > 120:
                self.storm = False
            self.report_trig = False
        if jet["kills"] or jet["reasons"]:
            names = sorted(jet["names"].items(), key=lambda kv: -kv[1])[:15]
            self.event("jetsam", kills=jet["kills"], reasons=jet["reasons"], top=dict(names))
        return jet["kills"]

    # -- notifications
    def notify(self, title, msg):
        script = 'display notification "%s" with title "%s" sound name "Basso"' % (
            msg.replace('"', "'"), title.replace('"', "'"))
        try:
            if os.geteuid() == 0:
                uid = self.console.get("uid")
                user = self.console.get("user")
                if uid is None or not user:
                    return
                cmd = ["/bin/launchctl", "asuser", str(uid), "/usr/bin/sudo", "-u", user,
                       "/usr/bin/osascript", "-e", script]
            else:
                cmd = ["/usr/bin/osascript", "-e", script]
            subprocess.run(cmd, capture_output=True, timeout=15)
            self.event("notified", title=title, msg=msg)
        except Exception as e:
            self.event("daemon_error", where="notify", error=str(e))

    # -- incidents
    def open_incident(self, t, reasons):
        iid = datetime.datetime.fromtimestamp(t).strftime("%Y%m%d-%H%M%S")
        d = os.path.join(LOG_DIR, "incidents", iid)
        os.makedirs(d, exist_ok=True)
        self.incident = {"id": iid, "start": t, "start_iso": now_iso(t), "last_trigger": t,
                         "reasons": reasons, "open": True}
        write_atomic(os.path.join(d, "incident.json"), json.dumps(self.incident, indent=1))
        self.event("incident_open", id=iid, reasons=reasons)
        threading.Thread(target=self.dump_syslog, args=(d,), daemon=True).start()
        if time.time() - self.last_notify > NOTIFY_COOLDOWN:
            self.last_notify = time.time()
            self.notify("Memory incident", "%s — papertrail: oomph incident %s" % (reasons[0]["desc"], iid))

    def dump_syslog(self, d):
        out = run(["/usr/bin/log", "show", "--last", "15m", "--style", "compact",
                   "--predicate", oomph.LOG_PREDICATE], timeout=300)
        with open(os.path.join(d, "syslog.txt"), "w") as f:
            f.write(out)

    def close_incident(self, t):
        inc = self.incident
        self.incident = None
        inc["end"] = t
        inc["end_iso"] = now_iso(t)
        inc["open"] = False
        d = os.path.join(LOG_DIR, "incidents", inc["id"])
        try:
            samples = oomph.load_samples(inc["start"] - INCIDENT_LOOKBACK, t)
            events = oomph.load_events(inc["start"] - INCIDENT_LOOKBACK, t)
            inc["summary"] = oomph.summarize(samples, events)
            write_atomic(os.path.join(d, "incident.json"), json.dumps(inc, indent=1))
            html = oomph.render_html(samples, events, "Memory incident " + inc["id"], inc)
            write_atomic(os.path.join(d, "report.html"), html)
        except Exception as e:
            write_atomic(os.path.join(d, "incident.json"), json.dumps(inc, indent=1))
            self.event("daemon_error", where="close_incident", error=repr(e))
        self.event("incident_close", id=inc["id"], duration_s=round(t - inc["start"]))

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
        for d in glob.glob(os.path.join(LOG_DIR, "incidents", "*")):
            if os.path.getmtime(d) < cutoff:
                shutil.rmtree(d, ignore_errors=True)

    # -- main loop
    def sample(self):
        t = time.time()
        sysm = system_memory()
        away = away_state()
        if away.get("uid") is not None:
            self.console = {"uid": away["uid"], "user": away["user"]}
        procs = collect_procs()
        jetsam_kills = self.flush_jetsam()
        top, groups, sessions = summarize_procs(procs)

        big = {(p["pid"], p["start"]): (p["name"], round(p["fp"] / MB)) for p in procs.values()
               if p["fp"] >= GONE_MIN_MB * MB}
        gone = [{"pid": k[0], "name": v[0], "mb": v[1]} for k, v in self.prev_big.items() if k not in big
                and k[0] not in procs]
        # a pid that is still present with the same start time is not gone
        self.prev_big = big

        gap = None
        if self.prev_t and t - self.prev_t > 3 * (HOT_INTERVAL if self.hot else INTERVAL) + 5:
            gap = round(t - self.prev_t)
            self.event("sleep_gap", seconds=gap)
        self.prev_t = t

        s = {"t": round(t, 1), "iso": now_iso(t), "hot": self.hot}
        if gap:
            s["gap"] = gap
        s.update(sysm)
        s["jetsam_kills"] = jetsam_kills
        s["away"] = {k: away[k] for k in ("idle_s", "display_on", "locked", "sleep_preventers")}
        s["top"] = top
        s["groups"] = groups
        s["claude"] = sessions
        if gone:
            s["gone"] = gone
        if self.incident:
            s["incident"] = self.incident["id"]

        day = datetime.date.fromtimestamp(t).isoformat()
        with self.lock:
            append_json(os.path.join(LOG_DIR, "samples-%s.jsonl" % day), s)
        cur = dict(s)
        cur["daemon"] = {"pid": os.getpid(), "version": VERSION, "started": self.started,
                         "interval": HOT_INTERVAL if self.hot else INTERVAL,
                         "incident": self.incident["id"] if self.incident else None,
                         "root": os.geteuid() == 0}
        write_atomic(os.path.join(LOG_DIR, "current.json"), json.dumps(cur))
        return s

    hot = False

    def evaluate(self, s):
        t = s["t"]
        pr = s["pressure"]
        if self.prev_pressure is not None and pr != self.prev_pressure:
            self.event("pressure_change", old=self.prev_pressure, new=pr,
                       swap_used_gb=s["swap_used_gb"], disk_free_gb=s["disk_free_gb"],
                       idle_s=s["away"]["idle_s"])
        self.prev_pressure = pr

        self.swap_hist = [(tt, v) for tt, v in self.swap_hist if t - tt <= 60] + [(t, s["swap_used_gb"])]
        swap_jump = s["swap_used_gb"] - min(v for _, v in self.swap_hist) > 0.5

        with self.lock:
            trig = self.pending_triggers
            self.pending_triggers = []
        reasons = [{"kind": x["kind"], "desc": x["msg"][:120], "t": x["t"]} for x in trig]
        if pr >= 4:
            reasons.append({"kind": "pressure", "desc": "Memory pressure CRITICAL (swap %.1f GB, disk %.0f GB free)"
                            % (s["swap_used_gb"], s["disk_free_gb"]), "t": t})
        if reasons:
            if self.incident:
                self.incident["last_trigger"] = t
                known = {r["kind"] for r in self.incident["reasons"]}
                for r in reasons:
                    if r["kind"] not in known and len(self.incident["reasons"]) < 20:
                        self.incident["reasons"].append(r)
                        if r["kind"] in ("dialog", "lowmem", "jetsam_storm", "jetsam_report") and time.time() - self.last_notify > NOTIFY_COOLDOWN:
                            self.last_notify = time.time()
                            self.notify("Memory incident", r["desc"])
            else:
                self.open_incident(t, reasons)
        elif self.incident and t - self.incident["last_trigger"] > INCIDENT_CLOSE_AFTER:
            self.close_incident(t)

        if s["disk_free_gb"] < DISK_LOW_GB and time.time() - self.last_disk_notify > DISK_COOLDOWN:
            self.last_disk_notify = time.time()
            self.event("disk_low", disk_free_gb=s["disk_free_gb"])
            self.notify("Disk space low", "Only %.0f GB free — swap can't grow, risk of memory kills."
                        % s["disk_free_gb"])

        self.hot = bool(pr >= 2 or swap_jump or s.get("jetsam_kills") or s["disk_free_gb"] < 5 or self.incident)

    def run(self):
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        self.event("daemon_start", version=VERSION, pid=os.getpid(), root=os.geteuid() == 0)
        # resume a still-open incident after restart
        for f in sorted(glob.glob(os.path.join(LOG_DIR, "incidents", "*", "incident.json")))[-3:]:
            try:
                inc = json.load(open(f))
                if inc.get("open"):
                    self.incident = inc
            except Exception:
                pass
        threading.Thread(target=self.stream_loop, daemon=True).start()
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
        if self.stream_proc:
            try:
                self.stream_proc.terminate()
            except Exception:
                pass
        self.event("daemon_stop")
        sys.exit(0)


if __name__ == "__main__":
    Daemon().run()
