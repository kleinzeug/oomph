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
    P = oomph.plat()
    group_key, is_claude = P.group_key, P.is_agent
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
        sessions.append({
            "pid": p["pid"], "cwd": P.proc_cwd(p["pid"]),
            "mb": round(sum(procs[m]["fp"] for m in members if m in procs) / MB),
            "own_mb": round(p["fp"] / MB), "n": len(members),
            "biggest": {"name": big["name"], "pid": big["pid"], "mb": round(big["fp"] / MB)} if big else None,
        })
    sessions.sort(key=lambda s: s["mb"], reverse=True)

    # g: app group, pn: parent's name, s: Claude session it runs under (for the report's tree)
    by_fp = sorted(procs.values(), key=lambda p: p["fp"], reverse=True)
    top = []
    for p in by_fp[:TOP_N]:
        e = {"pid": p["pid"], "ppid": p["ppid"], "name": p["name"], "uid": p["uid"],
             "mb": round(p["fp"] / MB), "rss_mb": round(p["rss"] / MB), "g": group_key(p["path"], p["name"])}
        if p["ppid"] in procs:
            e["pn"] = procs[p["ppid"]]["name"]
        if p["pid"] in session_of:
            e["s"] = session_of[p["pid"]]
        top.append(e)
    return top, grp, sessions


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

    def offer(self, s, procs):
        with self.cond:
            self.slot = (s, procs)
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
                (s, procs), self.slot = self.slot, None
            try:
                self.run_once(s, procs)
            except Exception as e:
                self.sig = None
                self.error(str(e) if isinstance(e, oomph.LedgerError) else repr(e))
                with self.cond:
                    self.runs += 1

    def run_once(self, s, procs):
        sig, now = ledger_signature(), time.time()
        if not self.leases and sig == self.sig and now - self.last_run < self.FORCE_EVERY:
            with self.cond:
                self.at = now  # still nothing reserved
            return
        self.sig, self.last_run = sig, now
        leases, err = self.tick(s, procs)
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
        self.prev_up = None
        self.seen_exits = {}
        self.flap = None
        self.last_pr_event = 0
        self.unowned_since = None
        self.unowned_flagged = False
        self.swap_hist = []
        self.incident = None
        self.rolled = None  # (id, t, top rank, escalated) of an incident just closed at INCIDENT_MAX_S
        self.last_notify = 0
        self.last_disk_notify = 0
        self.last_maint = 0
        self.started = time.time()
        self.console = {"uid": None, "user": None}
        self.stopping = False
        self.stream_proc = None
        self.ledger = LedgerWorker(self.event)  # started by run()
        self.machine = None  # the `machine` block of current.json, made at the first sample

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

    # -- notifications
    def notify(self, title, msg, **kw):
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
        elif not cont and time.time() - self.last_notify > NOTIFY_COOLDOWN:
            self.last_notify = time.time()
            self.notify("Memory incident", "%s — papertrail: oomph incident %s" % (reasons[0]["desc"], iid))

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
        P = oomph.plat()
        t = time.time()
        sysm = P.system_memory()
        away = P.away_state()
        if away.get("uid") is not None:
            self.console = {"uid": away["uid"], "user": away["user"]}
        procs = P.collect_procs()
        jetsam_kills = self.flush_jetsam()
        top, groups, sessions = summarize_procs(procs)

        big = {(p["pid"], p["start"]): (p["name"], round(p["fp"] / MB)) for p in procs.values()
               if p["fp"] >= GONE_MIN_MB * MB}
        gone = [{"pid": k[0], "name": v[0], "mb": v[1]} for k, v in self.prev_big.items() if k not in big
                and k[0] not in procs]
        # a pid that is still present with the same start time is not gone
        self.prev_big = big

        up = P.uptime_s()
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
                            "msg": "oomph couldn't run for %d s while the Mac was awake — the system is starved for memory" % gap})
        self.prev_t, self.prev_up = t, up

        s = {"t": round(t, 1), "iso": now_iso(t), "hot": self.hot, "os": P.OS}
        if gap:
            s["gap"] = gap
        if stall:
            s["stall"] = stall
        s.update(sysm)
        s.update(P.ownership(sysm, procs))
        s["jetsam_kills"] = jetsam_kills
        s["away"] = {k: away[k] for k in ("idle_s", "display_on", "locked", "sleep_preventers")}
        s["top"] = top
        s["groups"] = groups
        s["claude"] = sessions
        # Retire reservations of sessions that died or expired, close to when it happened, and
        # copy the live ones into the sample. The shared ledger directory is world-writable, so
        # the daemon never opens anything in it: its thread hands the work to an unprivileged
        # child and the sample carries the last snapshot that child answered with (none if it
        # is older than two intervals).
        self.ledger.offer({k: v for k, v in s.items() if k not in ("top", "groups", "claude")}, procs)
        leases = self.ledger.latest(2 * (HOT_INTERVAL if self.hot else INTERVAL))
        if leases:
            s["leases"] = leases  # memory sessions have reserved through oomph's ledger
        if gone:
            s["gone"] = gone
        if self.incident:
            s["incident"] = self.incident["id"]

        day = datetime.date.fromtimestamp(t).isoformat()
        with self.lock:
            append_json(os.path.join(LOG_DIR, "samples-%s.jsonl" % day), s)
        cur = dict(s)
        if self.machine is None:
            try:
                self.machine = P.machine()
            except Exception as e:  # who this machine is matters less than the sample
                self.machine = {"os": P.OS}
                self.event("daemon_error", where="machine", error=repr(e)[:300])
        cur["daemon"] = {"pid": os.getpid(), "version": VERSION, "started": self.started,
                         "interval": HOT_INTERVAL if self.hot else INTERVAL,
                         "incident": self.incident["id"] if self.incident else None,
                         "root": os.geteuid() == 0, "machine": self.machine}
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
                    self.event("unowned_memory", gb=u, procs_gb=s.get("procs_gb"),
                               compressor_logical_gb=s["compressor_logical_gb"])
                reasons.append({"kind": "unowned", "t": t, "desc": "%.0f GB of memory belongs to no process — likely a GPU "
                                "or driver leak; save your work and restart before the Mac freezes" % u})
        else:
            self.unowned_since = None
            if self.unowned_flagged and (u is None or u < 0.75 * lim):
                self.unowned_flagged = False
                self.event("unowned_memory_cleared", gb=u)
        if pr >= 4:
            reasons.append({"kind": "pressure", "desc": "Memory pressure CRITICAL (swap %.1f GB, disk %.0f GB free)"
                            % (s["swap_used_gb"], s["disk_free_gb"]), "t": t})
        inc = self.incident
        if inc and t - inc.get("start", t) >= INCIDENT_MAX_S:
            if t - inc.get("last_trigger", t) <= INCIDENT_CLOSE_AFTER:  # still going: continued below
                top = max([oomph.reason_rank(r) for r in inc.get("reasons", [])] + [0])
                # a kill it opened with was announced then: the continuation doesn't announce it again
                done = inc.get("escalated") or (inc.get("start") if top >= oomph.ESCALATE_RANK else None)
                self.rolled = (inc["id"], t, top, done)
                self.close_incident(t, rolled=True)
            else:  # left open across a sleep or a restart: it ended, a trigger now opens a new one
                self.close_incident(t)
        if reasons:
            if self.incident:
                self.join_incident(t, reasons)
            else:
                self.open_incident(t, reasons)
        elif self.incident and t - self.incident["last_trigger"] > INCIDENT_CLOSE_AFTER:
            self.close_incident(t)

        # swap grows on the startup disk of a Mac: there a full disk is a memory problem (roadmap 03 §5.4)
        mac = s.get("os", "macos") == "macos"
        if mac and s["disk_free_gb"] < DISK_LOW_GB and time.time() - self.last_disk_notify > DISK_COOLDOWN:
            self.last_disk_notify = time.time()
            self.event("disk_low", disk_free_gb=s["disk_free_gb"])
            self.notify("Disk space low", "Only %.0f GB free — swap can't grow, risk of memory kills."
                        % s["disk_free_gb"])

        self.hot = bool(pr >= 2 or swap_jump or s.get("jetsam_kills") or (mac and s["disk_free_gb"] < 5) or self.incident)

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
        if oomph.plat().OS == "macos":  # kills are read from the unified log
            threading.Thread(target=self.stream_loop, daemon=True).start()
            threading.Thread(target=self.poll_loop, daemon=True).start()
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
        if self.stream_proc:
            try:
                self.stream_proc.terminate()
            except Exception:
                pass
        self.event("daemon_stop")
        sys.exit(0)


if __name__ == "__main__":
    Daemon().run()
