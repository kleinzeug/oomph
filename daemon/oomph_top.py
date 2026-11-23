"""`oomph top`: the dashboard in a terminal (roadmap 04-tui, step T1). Full screen and keyboard
driven: spans, the two lists and their cards, the panels a s e, help, themes, glyph sets, the size
ladder; `--once` prints one frame and exits; `--ssh host` runs it on another machine and stays
to restore this terminal when the link ends.

This half reads (the logger's files; the ledger through oomph.py's bounded readers, as nobody or
the sudo user when run as root) and talks to the terminal: raw mode, the input decoder, the
writer, signals, a worker thread for everything that can take long. Everything it draws comes
from the pure oomph_view.render. It reads only, and writes one settings file (top.json) in the
user's own state folder, never as root.
"""
import array
import base64
import collections
import errno
import fcntl
import gzip
import json
import math
import os
import platform
import queue
import re
import select
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
import zlib

import oomph
import oomph_view as view

view.BRAND = oomph.BRAND

DAY_CAP = 128 << 20         # bytes of one day's samples, inflated (a day at a 5 s interval is about 60 MB)
CURRENT_CAP = 256 << 10
INCIDENT_CAP = 256 << 10
EVENTS_CAP = 1 << 20        # the newest MB of events.jsonl is plenty for one frame
CHART_EVENTS = 5000         # the inspector keeps the newest this many (the budget: about 1 MB)
INCIDENTS_SHOWN = 30
INCIDENT_ID = re.compile(r"\d{8}-\d{6}$")
CHOICES = {"--color": ("auto", "truecolor", "256", "16", "never"), "--theme": ("auto", "dark", "light"),
           "--glyphs": ("auto", "unicode", "cells", "ascii")}
LIVE_S, LIVE_KEEP = 30, 720  # no logger: measure every 30 s as the logger would (about 60 ms each), keep 6 h
ROOT_LEDGER_S = 30          # under sudo the reservations lag by up to this (04 §4.10)
CELLS_TERMINALS = ()        # TERM_PROGRAM values that seam at their default profile (04 §8): none so far
USAGE = ("usage: oomph top [--span inf|24h|6h|1h] [--color auto|truecolor|256|16|never] [--theme auto|dark|light]\n"
         "                 [--glyphs auto|unicode|cells|ascii] [--bell | --no-bell] [--mouse | --no-mouse] [--no-probe]\n"
         "                 [--machine NAME] [--no-connect] [--ssh [USER@]HOST [--ssh-port N]]\n"
         "                 [--once [--size COLSxROWS] [--format text|ansi|golden] [--now UNIXTIME]]")


# ------------------------------------------------------------------ reading
def _read(path, cap, tail=False):
    """A regular file of the log directory (root's, readable by all), at most `cap` bytes; None for
    anything else. With `tail` a bigger file gives its newest whole lines within `cap`."""
    d = oomph.read_bounded(path, cap, tail=tail)
    if d is None:
        return None
    try:
        return d.decode("utf-8", "replace")
    except Exception:
        return None


def _tail_lines(path, cap):
    """The newest whole lines of a log file within `cap` bytes, as _read reads it, one at a time:
    neither the whole as text nor a list of its lines is ever held (a MB of events made 3 MB more of
    peak resident that way, past the dashboard's 40 MB)."""
    d = oomph.read_bounded(path, cap, tail=True) or b""
    i = 0
    while i < len(d):
        j = d.find(b"\n", i)
        j = len(d) if j < 0 else j
        yield d[i:j].decode("utf-8", "replace")
        i = j + 1


def _no_constant(c):
    raise ValueError("%s is not a finite number" % c)


def _loads(line):
    """A line of the log (root's, written by the daemon): json.loads without NaN and Infinity."""
    return json.loads(line, parse_constant=_no_constant)


def _num(x, default=0.0):
    """A finite number, else `default` (1e999 parses as infinity; an int too big for a float is none)."""
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return default
    try:
        return x if math.isfinite(x) else default
    except OverflowError:
        return default


def _day_files(log_dir):
    """{day: path} of the samples files; the plain file wins while both exist (the logger writes
    the .gz beside it, then removes the plain one)."""
    out = {}
    try:
        names = os.listdir(log_dir)
    except OSError:
        return out
    for n in sorted(names):
        if n.startswith("samples-") and (n.endswith(".jsonl") or n.endswith(".jsonl.gz")):
            day = n[len("samples-"):len("samples-") + 10]
            if n.endswith(".jsonl") or day not in out:
                out[day] = os.path.join(log_dir, n)
    return out


def _lines(path):
    """The lines of a day's file: of a plain file (today's) bigger than DAY_CAP its newest DAY_CAP
    bytes, of a .gz at most DAY_CAP bytes inflated."""
    try:
        if path.endswith(".gz"):
            n = 0
            with gzip.open(path, "rb") as f:
                for line in f:
                    n += len(line)
                    if n > DAY_CAP:
                        return
                    yield line
            return
        with open(path, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            if size > DAY_CAP:
                f.seek(size - DAY_CAP)
                f.readline()                    # a piece of a line
            for line in f:
                yield line
    except (OSError, EOFError, ValueError, zlib.error):
        return


def _point(s):
    """The seven keys the chart needs, from one sample."""
    t = _num(s.get("t"), None)
    if t is None:
        return None
    return dict(t=float(t), wired=_num(s.get("wired_gb")), app=_num(s.get("app_gb")), comp=_num(s.get("compressed_gb")),
                swap=_num(s.get("swap_used_gb")), away=oomph.is_away(s) if isinstance(s.get("away"), dict) else False,
                kills=int(_num(s.get("jetsam_kills"), 0)))


def load_points(log_dir, now, since):
    """Samples from `since` to now, as chart points, oldest first; and whether older ones exist."""
    files = _day_files(log_dir)
    first_day = time.strftime("%Y-%m-%d", time.localtime(since - 86400))   # the day before: the gap into the window
    pts, older = [], False
    for day, path in sorted(files.items()):
        if day < first_day:
            older = True
            continue
        for line in _lines(path):
            try:
                s = _loads(line)
            except ValueError:
                continue
            p = _point(s) if isinstance(s, dict) else None
            if p and p["t"] <= now + 60:
                pts.append(p)
    pts.sort(key=lambda p: p["t"])
    return pts, older


def _current(log_dir):
    c = oomph.loads_untrusted(_read(os.path.join(log_dir, "current.json"), CURRENT_CAP))
    return c if isinstance(c, dict) and oomph._t(c.get("t")) else None


def _list(x):
    return x if isinstance(x, list) else []


def readings(s):
    """What the frame shows of a sample."""
    p = s.get("pressure")
    pressure = {1: "Normal", 2: "Warning", 4: "Critical"}.get(p, "Normal") if isinstance(p, int) else "Normal"
    groups = [(str(x.get("name") or "?"), _num(x.get("mb")) / 1024.0, int(_num(x.get("n"), 1)))
              for x in _list(s.get("groups")) if isinstance(x, dict)]
    claude = []
    for x in _list(s.get("claude")):
        if isinstance(x, dict):
            big = x.get("biggest") if isinstance(x.get("biggest"), dict) else {}
            home = os.path.expanduser("~")
            cwd = str(x.get("cwd") or "?")
            cwd = "~" + cwd[len(home):] if home != "/" and cwd.startswith(home + "/") else cwd
            claude.append((x.get("pid"), cwd, _num(x.get("mb")) / 1024.0, int(_num(x.get("n"), 1)),
                           "%s %.1fG" % (big.get("name"), _num(big.get("mb")) / 1024.0) if big.get("name") else ""))
    top = [(int(_num(x.get("pid"), 0)), str(x.get("name") or "?"), _num(x.get("mb")) / 1024.0, str(x.get("g") or ""),
            int(_num(x.get("s"), 0)) if x.get("s") is not None else None)
           for x in _list(s.get("top"))[:25] if isinstance(x, dict)]
    a = s.get("away") if isinstance(s.get("away"), dict) else {}
    ram, app, wired, comp = (_num(s.get(k)) for k in ("ram_gb", "app_gb", "wired_gb", "compressed_gb"))
    return dict(app=app, comp=comp, wired=wired, swap=_num(s.get("swap_used_gb")), swap_total=_num(s.get("swap_total_gb")),
                ram=ram, disk=_num(s.get("disk_free_gb")),
                idle=None if _num(a.get("idle_s"), None) is None else int(a["idle_s"]),  # None: not known (Linux)
                display_on=a.get("display_on") if isinstance(a.get("display_on"), bool) else None,
                pressure=pressure, free=max(0.0, ram - app - wired - comp),
                unowned=s.get("unowned_gb") if isinstance(s.get("unowned_gb"), (int, float)) else None,
                procs=int(_num(s.get("procs"), 0)) or None, groups=groups, claude=claude, top=top)


def _card_summary(summ):
    """What an incident's card shows of its summary: a few typed, capped fields, not the whole thing."""
    def pairs(rows, name, val, n):
        out = []
        for x in _list(rows)[:n]:
            if isinstance(x, dict) and val(x) is not None:
                out.append((str(x.get(name) or "?")[:40], val(x)))
        return out
    mk = summ.get("most_killed") if isinstance(summ.get("most_killed"), dict) else {}
    return {"peak_pressure": str(summ["peak_pressure"])[:20] if isinstance(summ.get("peak_pressure"), str) else None,
            "peak_at": str(summ["peak_at"])[:32] if isinstance(summ.get("peak_at"), str) else None,
            "max_swap_used_gb": _num(summ.get("max_swap_used_gb"), None),
            "max_swap_total_gb": _num(summ.get("max_swap_total_gb"), None),
            "most_killed": [(str(k)[:40], int(_num(v, 0))) for k, v in list(mk.items())[:4]],
            "risers": pairs(summ.get("group_risers"), "name",
                            lambda x: _num(x.get("rise_mb"), None) and _num(x.get("rise_mb")) / 1024.0, 3),
            "on_top": pairs(summ.get("groups_at_peak"), "name", lambda x: _num(x.get("mb")) / 1024.0, 4),
            "sessions": pairs(summ.get("claude_at_peak"), "cwd", lambda x: _num(x.get("mb")) / 1024.0, 2),
            "away_fraction": _num(summ.get("away_fraction"), None),
            "cpu": _num(summ.get("max_cpu_busy"), None), "cpu_n": _num(summ.get("cpu_n"), None),
            "gpu_util": _num(summ.get("max_gpu_util"), None), "gpu_busy": _num(summ.get("max_gpu_busy"), None),
            "data_free": _num((summ.get("min_free_gb") if isinstance(summ.get("min_free_gb"), dict) else {}).get("data"),
                              None)}


def incident_of(inc, iid, d=None):
    """An incident.json's object as the list, its card and the inspector show it (None: not one)."""
    if not (isinstance(inc, dict) and isinstance(inc.get("start"), (int, float)) and not isinstance(inc["start"], bool)
            and math.isfinite(inc["start"])):
        return None
    reasons = [str(r.get("desc") or "")[:200] for r in inc.get("reasons") or [] if isinstance(r, dict)] \
        if isinstance(inc.get("reasons"), list) else []
    summ = inc.get("summary") if isinstance(inc.get("summary"), dict) else {}
    rid = str(inc.get("id") or iid)
    report = os.path.join(d, iid, "report.html") if d else None
    return dict(id=rid if INCIDENT_ID.match(rid) else iid, start=float(inc["start"]),
                end=_num(inc.get("end"), None) if isinstance(inc.get("end"), (int, float)) else None,
                open=inc.get("open") is True, kills=int(_num(summ.get("jetsam_kills"), 0)),
                desc=reasons[0] if reasons else "", reasons=[r for r in reasons if r][:3], nreasons=len(reasons),
                summary=_card_summary(summ), dir=os.path.join(d, iid) if d else None,
                report=report if report and os.path.isfile(report) else None)


def _incident(d, iid, cache=None):
    """One incident as the list and its card show it (None: not an incident). `cache` keeps the
    parsed ones by file identity, so a dashboard that runs all day reads each once."""
    path = os.path.join(d, iid, "incident.json")
    key = None
    if cache is not None:
        try:
            st = os.stat(path)
            key = (st.st_ino, st.st_size, st.st_mtime)
        except OSError:
            return None
        hit = cache.get(iid)
        if hit and hit[0] == key:
            return hit[1]
    out = incident_of(oomph.loads_untrusted(_read(path, INCIDENT_CAP)), iid, d)
    if cache is not None:
        cache[iid] = (key, out)
    return out


def load_incidents(log_dir, now, cache=None):
    """The newest incidents (an open one first) and how many started in the last 90 days."""
    d = os.path.join(log_dir, "incidents")
    try:
        ids = sorted((n for n in os.listdir(d) if not n.startswith(".")), reverse=True)
    except OSError:
        return [], 0
    out, n90 = [], 0
    for iid in ids[:INCIDENTS_SHOWN]:
        inc = _incident(d, iid, cache)
        if inc is None:
            continue
        out.append(inc)
        if inc["start"] >= now - 90 * 86400:
            n90 += 1
    if cache is not None:
        for k in [k for k in cache if k not in ids[:INCIDENTS_SHOWN]]:
            del cache[k]
    try:                        # the rest are counted by name: the logger names them by local start time
        cut = time.strftime("%Y%m%d-%H%M%S", time.localtime(now - 90 * 86400))
    except (OverflowError, ValueError, OSError):
        cut = None
    n90 += sum(1 for iid in ids[INCIDENTS_SHOWN:] if cut and INCIDENT_ID.match(iid) and iid >= cut)
    out.sort(key=lambda i: (not i["open"], -i["start"]))
    return out, n90


PRESSURE_WORD = {1: "normal", 2: "warning", 4: "critical"}
ALARMING = ("jetsam", "stall", "unowned_memory", "disk_low", "disk_filling", "pressure_flapping", "daemon_error")
VOLUME_WORD = {"mounted": "mounted", "unmounted": "unmounted", "watched": "watched", "unwatched": "no longer watched"}


def _vol_name(e):
    for k in ("name", "mount", "pool"):
        if isinstance(e.get(k), str) and e[k]:
            return e[k]
    return "?"


def _word(words, v, default):
    return words.get(v, default) if isinstance(v, (str, int, float)) else default   # (a list is no key)


def event_text(e):
    """ChartEvent's words for a line of events.jsonl (None: not shown)."""
    k = e.get("kind")

    def num(key):
        return _num(e.get(key))
    if k == "pressure_change":
        return "pressure %s → %s" % (_word(PRESSURE_WORD, e.get("old"), e.get("old")), _word(PRESSURE_WORD, e.get("new"), e.get("new")))
    if k == "pressure_flapping":
        return "pressure flapping, %d flips" % num("flips")
    if k == "jetsam":
        return "%d killed by jetsam" % num("kills") if num("kills") > 0 else "jetsam report"
    if k == "sleep_gap":
        return "asleep " + view.duration(num("seconds"))
    if k == "stall":
        return "system stalled " + view.duration(num("seconds"))
    if k == "unowned_memory":
        return "%.0f GB unowned memory (leak?)" % num("gb")
    if k == "unowned_memory_cleared":
        return "unowned memory cleared"
    if k == "disk_low":
        if isinstance(e.get("name"), str) and _num(e.get("free_gb"), None) is not None:
            return "disk low: %s %.1f GB free" % (e["name"], num("free_gb"))
        return "disk low: %.1f GB free" % num("disk_free_gb")
    if k == "disk_filling":
        return "disk filling: %s, full in %.0f min at %.1f GB/min" % (_vol_name(e), num("eta_min"), num("rate_gb_min"))
    if k == "volume":
        return "disk %s: %s" % (_word(VOLUME_WORD, e.get("what"), "changed"), _vol_name(e))
    if k == "thermal":
        return "thermal %s → %s" % tuple(oomph.THERMAL.get(int(_num(e.get(x), -1)), "?") for x in ("old", "new"))
    if k == "cpu_saturated":
        return "cores saturated: %.1f of %.0f busy for %.0f min" % (num("busy"), num("n"), num("minutes"))
    if k == "cpu_saturated_cleared":
        return "cores no longer saturated, after %.0f min" % num("minutes")
    if k == "daemon_start":
        return "logger started" + (" (v%s)" % e["version"] if isinstance(e.get("version"), str) else "")
    if k == "daemon_stop":
        return "logger stopped"
    if k == "daemon_error":
        return "logger error (%s)" % e.get("where", "?")
    if k == "notified":
        return "notified: %s" % e.get("title", "")
    if k == "log":
        return "system log: " + str(e.get("msg") or "")[:60]
    if k in ("incident_open", "incident_close") or not isinstance(k, str):
        return None
    return k.replace("_", " ")


def chart_event(e, memo=None):
    """One line of events.jsonl as the app's ChartEvent has it (None: not shown): a view.ChartEv of t,
    kind, text, alarming, and what the hover card adds up (kills, top, seconds). `memo` shares the
    strings that repeat (kinds and words) between the events of one load."""
    if not isinstance(e, dict) or _num(e.get("t"), None) is None:
        return None
    try:
        text = event_text(e)
    except (TypeError, ValueError, OverflowError):  # (one odd line costs only itself)
        return None
    if not text:
        return None
    kind = e["kind"][:64]
    if memo is not None:
        kind, text = memo.setdefault(kind, kind), memo.setdefault(text, text)
    top = e.get("top") if kind == "jetsam" and isinstance(e.get("top"), dict) else {}   # (only jetsam's is added up)
    top = {str(k)[:64]: v for k, v in list(top.items())[:32] if isinstance(v, int) and not isinstance(v, bool)}
    return view.ChartEv(float(e["t"]), kind, text, kind in ALARMING, int(_num(e.get("kills"))), top or None,
                        _num(e.get("seconds")) or 0)


def load_events(log_dir, n=40, chart=False):
    """The newest events in words, newest first. With `chart` also the newest CHART_EVENTS read, oldest
    first, as the inspector aggregates them (view.ChartEv, the app's ChartEvent)."""
    every, memo = collections.deque(maxlen=CHART_EVENTS), {}
    for name in ("events.jsonl.1", "events.jsonl"):
        for line in _tail_lines(os.path.join(log_dir, name), EVENTS_CAP):
            try:
                c = chart_event(_loads(line), memo)
            except ValueError:
                continue
            if c:
                every.append(c)     # (the files are in time order, near enough: sorted below)
    out = [(c.t, c.text, c.alarming) for c in sorted(every, key=lambda e: -e.t)[:n]]
    every = sorted(every, key=lambda e: e.t)
    return (out, every) if chart else out


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def load_reservations(now, with_state=False):
    """The reservations of the last 14 days and the live ones, merged as the app merges them. Read
    through oomph.ledger_view: bounded, never as root (a root caller reads in a child). With
    `with_state` also what the ledger last said about free memory and its margin."""
    try:
        v = oomph.ledger_view(since=now - view.KEEP_DAYS * 86400)   # the frame's clock, not the wall's
    except oomph.LedgerError as e:
        return ([], "can't read the ledger: %s" % e) + (({},) if with_state else ())
    res = view.merge_reservations(v.get("records") or [], v.get("ledger") or {}, now, _alive,
                                  own_ns=oomph._own_ns())
    if not with_state:
        return res, None
    st = (v.get("ledger") or {}).get("state")
    st = {k: _num(st.get(k), None) for k in ("free_gb", "margin_gb")} if isinstance(st, dict) else {}
    return res, None, st


def host_name():
    n = socket.gethostname().split(".")[0]
    return n or "this Mac"


def os_name():
    v = platform.mac_ver()[0]
    return "macOS %s" % v if v else platform.system()


def load_model(span="24h", now=None, log_dir=None, live=True):
    """Everything one frame shows of this machine. `now` fixed: a reproducible frame (tests)."""
    log_dir = log_dir or oomph.LOG_DIR
    fixed = now is not None
    now = float(now if fixed else time.time())
    s = _current(log_dir)
    logger, logger_t, interval = "ok", None, 30
    if s is None:
        logger = "off"
        if live and not fixed:
            try:
                s = oomph.live_sample(with_procs=False)
            except Exception:
                s = None
    else:
        d = s.get("daemon") if isinstance(s.get("daemon"), dict) else {}
        interval = _num(d.get("interval"), 30) or 30
        if now - s["t"] > 3 * interval + 15:
            logger, logger_t = "silent", s["t"]
    sp = view.SPANS.get(span)
    pts, older = load_points(log_dir, now, now - (sp or 400 * 86400))
    gaps = view.find_gaps(pts, now)
    first = pts[0]["t"] if pts else None
    if older and pts:           # history began before what was read: never "before history" in view
        first = min(first, now - (sp or 0) - 86400)
    cur = readings(s) if s else None
    res, note, lstate = load_reservations(now, with_state=True)
    incidents, n90 = load_incidents(log_dir, now)
    events, cevents = load_events(log_dir, chart=True)
    model = dict(now=now, brand=oomph.BRAND, host=host_name(), os=os_name(), ram=cur["ram"] if cur else None,
                 pts=view.multires(pts, now), first=first, gaps=gaps, res=res, blocks=view.stack_reservations(res, now),
                 incidents=incidents, incidents_90d=n90, cur=cur, events=events, cevents=cevents,
                 logger=logger, logger_t=logger_t, interval=interval, ledger_state=lstate)
    if note:
        model.update(status=note, status_role="warntx")
    return model


# ------------------------------------------------------------------ the full-screen program's data
class Day:
    """One day of samples as the chart needs them: seven typed arrays (14 days are about 2 MB this
    way, against 20 MB as a dict per sample). A plain file (today's) is read on from where the last
    read stopped; a .gz once."""
    __slots__ = ("sig", "path", "ino", "off", "t", "w", "a", "c", "s", "away", "kills", "ordered", "tmax")

    def __init__(self, path, ino):
        self.path, self.ino, self.off, self.sig = path, ino, 0, None
        self.ordered, self.tmax = True, float("-inf")      # so that series() need not look at every sample
        self.t, self.w, self.a, self.c, self.s = (array.array("d") for _ in range(5))
        self.away, self.kills = bytearray(), array.array("l")

    def add(self, line):
        try:
            s = _loads(line)
        except ValueError:
            return
        if not isinstance(s, dict):
            return
        p = _point(s)
        if p is None:
            return
        if p["t"] < self.tmax:
            self.ordered = False
        self.tmax = max(self.tmax, p["t"])
        self.t.append(p["t"])
        self.w.append(p["wired"])
        self.a.append(p["app"])
        self.c.append(p["comp"])
        self.s.append(p["swap"])
        self.away.append(1 if p["away"] else 0)
        self.kills.append(max(-(1 << 31), min(p["kills"], (1 << 31) - 1)))


def _read_day(path, old):
    """A day's file into a Day: on from `old`'s offset when it is the same plain file grown, else
    whole. A .gz that ends early is not kept (the logger may be writing it: tried again later)."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    sig = (path, st.st_ino, st.st_size, st.st_mtime)
    if old is not None and old.sig == sig:
        return old
    if path.endswith(".gz"):
        d = Day(path, st.st_ino)
        n = 0
        try:
            with gzip.open(path, "rb") as f:
                for line in f:
                    n += len(line)
                    if n > DAY_CAP:
                        break
                    d.add(line)
        except (OSError, EOFError, ValueError, zlib.error):
            return None
        d.sig = sig
        return d
    d = old if old is not None and old.path == path and old.ino == st.st_ino and st.st_size >= old.off else None
    if d is None:
        d = Day(path, st.st_ino)
    try:
        with open(path, "rb") as f:
            if d.off == 0 and st.st_size > DAY_CAP:
                f.seek(st.st_size - DAY_CAP)
                d.off = st.st_size - DAY_CAP + len(f.readline())
            f.seek(d.off)
            for line in f:
                if not line.endswith(b"\n"):
                    break                       # a line still being written: read it whole next time
                d.off += len(line)
                d.add(line)
    except OSError:
        return old
    d.sig = sig
    return d


class History:
    """Every day of samples on file, kept current by refresh() (only what changed is read)."""

    def __init__(self, log_dir):
        self.log_dir, self.days = log_dir, {}

    def refresh(self, newest=None):
        """Re-read what changed; with `newest` only that many of the newest days (the first frame
        needs today and yesterday, the rest follows). True when anything changed."""
        files = _day_files(self.log_dir)
        changed = False
        for day in [d for d in self.days if d not in files]:
            del self.days[day]
            changed = True
        for k, day in enumerate(sorted(files, reverse=True)):
            if newest is not None and k >= newest:
                break
            old = self.days.get(day)
            old_sig = old.sig if old is not None else None
            d = _read_day(files[day], old)
            if d is None:
                if old is not None:
                    del self.days[day]
                    changed = True
                continue
            if d is not old or d.sig != old_sig:
                changed = True
            self.days[day] = d
        return changed

    def series(self, now, since):
        """The samples from the day before `since` to now + 60 s, as seven arrays in time order, and
        whether older days exist (the same window load_points reads)."""
        first_day = time.strftime("%Y-%m-%d", time.localtime(since - 86400))
        cols = [array.array("d") for _ in range(5)] + [bytearray(), array.array("l")]
        older, ordered, future, prev = False, True, False, float("-inf")
        for day in sorted(self.days):
            if day < first_day:
                older = True
                continue
            d = self.days[day]
            if len(d.t):
                ordered = ordered and d.ordered and d.t[0] >= prev
                prev, future = d.tmax, future or d.tmax > now + 60
            for dst, src in zip(cols, (d.t, d.w, d.a, d.c, d.s, d.away, d.kills)):
                dst.extend(src)
        T = cols[0]
        if ordered and not future:          # the usual case: each day in order, the days in order
            return cols, older
        keep = [i for i in range(len(T)) if T[i] <= now + 60] if future else None
        if keep is not None:
            cols = [type(c)(c[i] for i in keep) if not isinstance(c, bytearray) else bytearray(c[i] for i in keep)
                    for c in cols]
            T = cols[0]
        if any(T[i] < T[i - 1] for i in range(1, len(T))):
            order = sorted(range(len(T)), key=T.__getitem__)
            cols = [type(c)(c[i] for i in order) if not isinstance(c, bytearray) else bytearray(c[i] for i in order)
                    for c in cols]
        return cols, older


def multires_cols(cols, now):
    """view.multires over the typed arrays, point for point the same (the self-test compares them),
    without a dict per sample: only the thinned points become dicts."""
    T, W, A, C, S, AW, K = cols
    out, j, gap = [], len(T) - 1, view.GAP_S
    while j >= 0:
        tj = T[j]
        lo = tj - max(30.0, (now - tj) / 720)
        i = j
        while i > 0 and T[i - 1] > lo and T[i] - T[i - 1] <= gap:
            i -= 1
        best, bv = i, A[i] + C[i] + S[i]
        for k in range(i + 1, j + 1):
            v = A[k] + C[k] + S[k]
            if v > bv:
                best, bv = k, v
        p = dict(t=T[best], wired=W[best], app=A[best], comp=C[best], swap=S[best], away=bool(AW[best]), kills=K[best])
        if j > i:
            p["away"] = any(AW[i:j + 1])
            p["kills"] = sum(K[i:j + 1])
        out.append(p)
        j = i - 1
    out.reverse()
    return out


def gaps_cols(T):
    """view.find_gaps between the samples (the stretch from the last one to now is added per frame)."""
    return [(T[k - 1], T[k]) for k in range(1, len(T)) if T[k] - T[k - 1] > view.GAP_S]


def install_hint():
    """How to start the logger, in words for the machine this runs on (04 §3.15): the real path of
    the install script that came with this CLI, or the app's button."""
    here = os.path.dirname(os.path.realpath(oomph.__file__))
    if "/Contents/Resources" in here:
        return "Logging is off: click Activate in the app"
    if sys.platform.startswith("linux"):  # no logger on Linux yet (1.9.4): the readings of this run only.
        return "Logging is off: live readings only"  # short: at 80 columns a longer status would give way to the keys
    for cand in (os.path.join(here, "install.sh"), os.path.join(os.path.dirname(here), "install.sh")):
        if os.path.isfile(cand):
            home = os.path.expanduser("~")
            shown = "~" + cand[len(home):] if home != "/" and cand.startswith(home + "/") else cand
            return "Logging is off: sudo %s" % (shown if re.fullmatch(r"[A-Za-z0-9_./~+-]+", shown) else
                                               "'%s'" % shown.replace("'", "'\\''"))
    return "Logging is off"


class Feed:
    """One machine's data as the frames need it: this machine's log and ledger, or another machine's
    mirror (roadmap 01 §5.6, in the logs' own layout). It looks at a few files' identities and reads
    only what changed. A mirror is never measured here and its reservations are never ended by
    looking at pids: they are another machine's (04 §4.7)."""

    def __init__(self, log_dir, ledger_dir=None, root=False):
        self.log_dir, self.ledger_dir, self.root = log_dir, ledger_dir, root
        self.remote = ledger_dir is not None
        self.history = History(log_dir)
        self.incident_cache = {}
        self.sigs = {}
        self.cur = None
        self.pts = self.gaps = None
        self.first, self.points_at, self.points_span = None, 0.0, None
        self.res, self.res_note, self.lstate, self.res_at = [], None, {}, -1e9
        self.blocks = []
        self.incidents, self.n90, self.inc_at = [], 0, -1e9
        self.events, self.cevents = [], []
        self.live, self.live_pts, self.live_at = None, [], -1e9
        self.loaded_all = False

    def _sig(self, path):
        try:
            st = os.stat(path, follow_symlinks=False)
            return (st.st_ino, st.st_size, st.st_mtime_ns)
        except OSError:
            return None

    def _changed(self, key, path):
        sig = self._sig(path)
        if self.sigs.get(key, 0) != sig:
            self.sigs[key] = sig
            return True
        return False

    def step(self, now, span):
        """Read what changed; True when the model did."""
        changed = False
        if self._changed("current", os.path.join(self.log_dir, "current.json")):
            self.cur = _current(self.log_dir)
            changed = True
        hist = False
        if not self.loaded_all:
            hist = self.history.refresh(newest=2) if self.pts is None else self.history.refresh()
            self.loaded_all = self.pts is not None
        elif changed or now - self.points_at > 60:
            hist = self.history.refresh()
        if hist or span != self.points_span or now - self.points_at > 300 or self.pts is None:
            sp = view.SPANS.get(span)
            cols, older = self.history.series(now, now - (sp or 400 * 86400))
            self.pts, self.gaps = multires_cols(cols, now), gaps_cols(cols[0])
            self.pts_v = getattr(self, "pts_v", 0) + 1
            T = cols[0]
            self.first = T[0] if len(T) else None
            if older and len(T):
                self.first = min(self.first, now - (sp or 0) - 86400)
            self.last_t = T[-1] if len(T) else None
            self.points_at, self.points_span, changed = now, span, True
        if self.cur is None and not self.remote and now - self.live_at >= LIVE_S:   # no logger: measure here
            self.live_at = now
            try:
                s = oomph.live_sample(with_procs=False)
            except Exception:
                s = None
            if isinstance(s, dict):
                s.setdefault("t", now)
                p = _point(s)
                self.live = s                                   # the newest whole sample: the readings
                self.live_pts = (self.live_pts + [p])[-LIVE_KEEP:] if p else self.live_pts
                changed = True
        if self.remote:
            due = (self._changed("ledger", os.path.join(self.ledger_dir, "ledger.json")) |
                   self._changed("history", os.path.join(self.ledger_dir, "reservations.jsonl"))) or now - self.res_at >= 60
        elif self.root:     # each read starts an unprivileged child (about 0.1 s of CPU): every 30 s
            due = now - self.res_at >= ROOT_LEDGER_S
        else:
            led = oomph.LEDGER_DIR
            due = (self._changed("ledger", os.path.join(led, "ledger.json")) |
                   self._changed("history", os.path.join(led, "reservations.jsonl"))) or now - self.res_at >= 10
        if due:
            if self.remote:
                self.res, self.res_note, self.lstate = mirror_reservations(self.ledger_dir, now)
            else:
                self.res, self.res_note, self.lstate = load_reservations(now, with_state=True)
            self.blocks = view.stack_reservations(self.res, now)
            self.res_at, changed = now, True
        incident_now = ((self.cur or {}).get("daemon") or {}).get("incident") if isinstance(
            (self.cur or {}).get("daemon"), dict) else None
        if now - self.inc_at >= 10 or self.sigs.get("incident_now") != incident_now:
            self.sigs["incident_now"] = incident_now
            self.incidents, self.n90 = load_incidents(self.log_dir, now, self.incident_cache)
            self.inc_at, changed = now, True
        if self._changed("events", os.path.join(self.log_dir, "events.jsonl")):
            self.events, self.cevents = load_events(self.log_dir, chart=True)
            changed = True
        return changed

    def model(self, now):
        """The model for render(), as load_model builds it for --once."""
        s, logger, logger_t, interval = self.cur, "ok", None, 30
        pts, gaps, first, pv = self.pts or [], list(self.gaps or []), self.first, getattr(self, "pts_v", None)
        if s is None and not self.remote:
            logger = "off"
            s = self.live
            if self.live_pts and not pts:
                live = self.live_pts
                pts = view.multires(live, now)
                gaps = view.find_gaps(live, now)
                first, pv = (live[0]["t"] if live else None), None
        elif s is not None:
            d = s.get("daemon") if isinstance(s.get("daemon"), dict) else {}
            interval = _num(d.get("interval"), 30) or 30
            if now - s["t"] > 3 * interval + 15:
                logger, logger_t = "silent", s["t"]
        cur = readings(s) if s else None
        m = dict(now=now, brand=oomph.BRAND, host=host_name(), os=os_name(), ram=cur["ram"] if cur else None, pts=pts,
                 first=first, gaps=gaps, last_t=getattr(self, "last_t", None), res=self.res,
                 blocks=self.blocks, incidents=self.incidents, incidents_90d=self.n90, cur=cur,
                 events=self.events, cevents=self.cevents, logger=logger, logger_t=logger_t, interval=interval,
                 ledger_state=self.lstate, log_dir=self.log_dir,
                 off_text=install_hint() if logger == "off" else None, pts_v=pv)
        if self.res_note:
            m.update(status=self.res_note, status_role="warntx")
        return m


def mirror_reservations(ledger_dir, now):
    """Another machine's reservations from its mirror (read as the user, never as root): the
    ledger and the history log's records of the last 14 days, merged without asking whether a
    holder lives (its pids are another machine's; its logger retires them, 01 §4.4)."""
    try:
        fd = os.open(ledger_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return [], None, {}
    try:
        L = oomph._valid_ledger(oomph.loads_untrusted(oomph.read_bounded("ledger.json", oomph.LIMITS["ledger"], fd,
                                                                          shared=True)))
        recs = oomph._view_records(oomph.read_history(dfd=fd), now - view.KEEP_DAYS * 86400)
    except (oomph.LedgerError, OSError, ValueError):
        return [], None, {}
    finally:
        os.close(fd)
    return view.merge_reservations(recs, L or {}, now, None), None, {}


# ------------------------------------------------------------------ machines (04 §3.7, §4.7)
FILE_CAPS = {"status.json": 64 << 10, "sync.json": 1 << 20, "machine.json": 64 << 10, "current.json": CURRENT_CAP}
BOOK_CAP = 4 << 20
SYNC_BACKOFF = (1, 2, 4, 8, 15, 30, 60)
FEED_KEEP_S = 60.0          # another machine's feed (its history) is kept this long after its tab was left
UNDO_S = 6.0
HIDE_S = 30.0               # a forget machines.json never shows (an event lost, the sync child gone): its tab back


def sync_module():
    """oomph_sync, when it is installed beside this program (1.10): machine tabs exist only then."""
    try:
        import oomph_sync
        return oomph_sync
    except Exception:
        return None


def _json_in(d, name, cap, own=False):
    """A JSON file of a directory of this user's, read without following a link in the last step and
    bounded; None for anything else (with `own`, also when the directory is someone else's)."""
    try:
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if own and os.fstat(fd).st_uid != os.geteuid():
            return None
        return oomph.loads_untrusted(oomph.read_bounded(name, cap, fd))
    except (OSError, ValueError):
        return None
    finally:
        os.close(fd)


def read_book(base, S):
    """machines.json as the dashboard reads it: only read, never written or created (04 §4.7: every
    change goes to the sync child). The entries oomph_sync trusts, each once."""
    v = _json_in(base, "machines.json", BOOK_CAP, own=True)
    out, seen = [], set()
    for e in (v.get("machines") if isinstance(v, dict) and isinstance(v.get("machines"), list) else []):
        ok = S.valid_entry(e)
        if ok and ok["mid"] not in seen:
            seen.add(ok["mid"])
            ok["forgetting"] = isinstance(e, dict) and e.get("state") == "forgetting"
            out.append(ok)
    return out


def _pressure(s):
    p = s.get("pressure")
    return {1: "Normal", 2: "Warning", 4: "Critical"}.get(p, "Normal") if isinstance(p, int) else "Normal"


def cur_summary(c, now):
    """What a tab shows of a machine's current.json: pressure, when, its interval, whether its logger
    went silent, an open incident, free memory."""
    if not isinstance(c, dict) or not oomph._t(c.get("t")):
        return None
    d = c.get("daemon") if isinstance(c.get("daemon"), dict) else {}
    interval = _num(d.get("interval"), 30) or 30
    inc = d.get("incident")
    return dict(pressure=_pressure(c), t=float(c["t"]), interval=interval, silent=now - c["t"] > 3 * interval + 15,
                incident=inc if isinstance(inc, str) and inc else None)


class Machines:
    """The tabs' facts, for the worker: machines.json (its pinned entries are tabs, after this machine,
    at most twelve; the rest are Recents) and each tab's status.json, sync.json, machine.json and
    current.json, each read again only when its identity changed."""

    def __init__(self, base, S):
        self.base, self.S = base, S
        self.entries, self.sigs, self.files = [], {}, {}
        self.opened = {}            # mid → (when this run opened it, whether its link was live then)
        self.hidden = {}            # mid → when forgotten here: no tab while machines.json still lists it (and no longer)
        self.hidden_lock = threading.Lock()     # the loop hides and unhides, the worker reads and expires
        self.alive = {}

    def _sig(self, path):
        try:
            st = os.stat(path, follow_symlinks=False)
            return (st.st_ino, st.st_size, st.st_mtime_ns)
        except OSError:
            return None

    def hide(self, mid, at=None):
        """A forget sent from here: no tab for it until machines.json says so or HIDE_S passed without it."""
        with self.hidden_lock:
            self.hidden[mid] = time.monotonic() if at is None else at

    def unhide(self, mid):
        """The forget failed: its tab again (it is still in machines.json)."""
        with self.hidden_lock:
            self.hidden.pop(mid, None)

    def is_hidden(self, mid):
        with self.hidden_lock:
            return mid in self.hidden

    def tabs(self):
        """The pinned entries in their order, without the ones being forgotten."""
        with self.hidden_lock:
            hidden = set(self.hidden)
        pinned = [e for e in self.entries if e["pinned"] and not e.get("forgetting") and e["mid"] not in hidden]
        return sorted(pinned, key=lambda e: (_num(e.get("order"), 0), _num(e.get("added"), 0)))[:view.MAX_TABS]

    def refresh(self, wall):
        changed = False
        sig = self._sig(os.path.join(self.base, "machines.json"))
        if sig != self.sigs.get("book", 0):
            self.sigs["book"] = sig
            self.entries = read_book(self.base, self.S) if sig else []
            ids = {e["mid"] for e in self.entries}
            with self.hidden_lock:
                for k in [k for k in self.hidden if k not in ids]:
                    del self.hidden[k]      # gone: added again, it is a tab again
            changed = True
        with self.hidden_lock:
            late = [e["mid"] for e in self.entries if not e.get("forgetting") and
                    time.monotonic() - self.hidden.get(e["mid"], math.inf) > HIDE_S]
            for mid in late:            # the forget never showed in machines.json: it was not done
                self.hidden.pop(mid, None)
                changed = True
        mids = {e["mid"] for e in self.tabs()}
        for k in [k for k in self.files if k[0] not in mids]:
            del self.files[k]
            self.sigs.pop(k, None)
        for mid in mids:
            d = os.path.join(self.base, mid)
            for name, sub in (("status.json", ""), ("sync.json", ""), ("machine.json", ""), ("current.json", "log")):
                path = os.path.join(d, sub, name)
                sig = self._sig(path)
                if sig != self.sigs.get((mid, name), 0):
                    self.sigs[(mid, name)] = sig
                    self.files[(mid, name)] = _json_in(os.path.dirname(path), name, FILE_CAPS[name]) if sig else None
                    changed = True
            st = self.files.get((mid, "status.json"))
            pid = st.get("pid") if isinstance(st, dict) else None
            alive = isinstance(pid, int) and not isinstance(pid, bool) and 0 < pid < 1 << 31 and _alive(pid)
            if self.alive.get(mid) != alive:
                self.alive[mid] = alive
                changed = True
            if mid not in self.opened:
                self.opened[mid] = (wall, self.was_live(mid, wall))
        return changed

    def was_live(self, mid, wall):
        """01 §3.6: what status.json says the link was when this opening began."""
        st = self.files.get((mid, "status.json"))
        if not isinstance(st, dict):
            return False
        if st.get("state") == "idle":
            return st.get("was") == "live"
        upd = _num(st.get("updated"), None)
        return st.get("state") in ("live", "catching_up") and upd is not None and wall - upd < view.LIVE_FRESH_S

    def reopen(self, wall):
        """A new opening of every tab (the sync child started again: at start, after a resume)."""
        self.opened = {e["mid"]: (wall, self.was_live(e["mid"], wall)) for e in self.tabs()}

    def tab(self, e, wall):
        S, mid = self.S, e["mid"]
        f = lambda n: self.files.get((mid, n)) if isinstance(self.files.get((mid, n)), dict) else {}
        st, sy, mj = f("status.json"), f("sync.json"), f("machine.json")
        off = _num(sy.get("offset_s"), 0.0)
        off = off if abs(off) < 366 * 86400 else 0.0
        have = [s_ for s_ in (sy.get("have") or []) if S._span(s_)] if isinstance(sy.get("have"), list) else []
        gone = [s_ for s_ in (sy.get("gone") or []) if S._span(s_)] if isinstance(sy.get("gone"), list) else []
        system = mj.get("os_version") if isinstance(mj.get("os_version"), str) else e.get("os_version")
        if not system and (mj.get("os") or e.get("os")) == "linux":
            system = "Linux"
        version = mj.get("version") if isinstance(mj.get("version"), str) else e.get("version")
        return dict(mid=mid, local=False, label=S.label(e), addr=S.show_target(e), transport=e["transport"],
                    status=st, pid_alive=self.alive.get(mid, False), cur=cur_summary(f("current.json"), wall + off),
                    sync=dict(offset_s=off, synced=sy.get("synced") if isinstance(sy.get("synced"), dict) else {},
                              have=[tuple(x) for x in have], gone=[tuple(x) for x in gone],
                              oldest=_num(sy.get("oldest") if sy.get("oldest") is not None else mj.get("oldest"), None)),
                    known=have[-1][1] if have else None, opened=self.opened.get(mid),
                    version=net_clean(version, 24), system=net_clean(system, 24), os=e.get("os"))


def net_clean(x, n):
    return view.fit(x, n) if isinstance(x, str) and x else None


class SyncChild:
    """This dashboard's one child for remote machines: `oomph remote sync --json` (04 §4.7, 01 §4.3).
    It is the engine or a follower, by 01's engine.lock; the dashboard does not need to know which.
    Commands go down its stdin, one JSON object a line; its events come back on stdout and only
    wake the worker (what is drawn comes from the files). Its own session: a ctrl-z here never
    reaches it, so a suspend closes its stdin first (quit), and a resume starts a new one."""

    def __init__(self, argv, wake=None):
        self.argv, self.p, self.attempt, self.next_at = argv, None, 0, 0.0
        self.started = None
        self.wake = wake or (lambda failed: None)
        self.failed = collections.deque(maxlen=8)

    def running(self):
        return self.p is not None and self.p.poll() is None

    def start(self, nowm):
        try:
            self.p = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        except OSError:
            self.p = None
            self.attempt += 1
            self.next_at = nowm + SYNC_BACKOFF[min(self.attempt, len(SYNC_BACKOFF) - 1)]
            return False
        threading.Thread(target=self._read, args=(self.p.stdout,), daemon=True).start()
        self.started = nowm
        return True

    def _read(self, f):
        """The child's events, on a thread of their own and never on the terminal's: that loop waits
        on a terminal that stopped reading, and a child that is the engine must not be left on a full
        pipe while it holds engine.lock (every viewer would see its machines go stale). Every event
        wakes the worker; a `failed` one is kept for a note (the last 8). At most 1 MB is kept
        between lines. The thread owns the pipe: it closes it at the end of the child's output."""
        buf = b""
        try:
            fd = f.fileno()
            while True:
                b = os.read(fd, 65536)
                if not b:
                    break
                buf += b
                if len(buf) > 1 << 20:
                    buf = b""
                failed = False
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    ev = oomph.loads_untrusted(line) if len(line) < 64 << 10 else None
                    if isinstance(ev, dict) and ev.get("ev") == "failed":
                        self.failed.append(ev)
                        failed = True
                self.wake(failed)
        except (OSError, ValueError):
            pass
        finally:
            try:
                f.close()
            except (OSError, ValueError):
                pass

    def send(self, obj):
        if not self.running():
            return False
        try:
            self.p.stdin.write((json.dumps(obj) + "\n").encode())
            self.p.stdin.flush()
            return True
        except (OSError, ValueError):
            return False

    def events(self):
        """The `failed` events the reader kept since the last call."""
        out = []
        while self.failed:
            try:
                out.append(self.failed.popleft())
            except IndexError:
                break
        return out

    def reap(self, nowm):
        """True when the child ended (then it is started again after a backoff: 1, 2, 4 … 60 s)."""
        if self.p is None or self.p.poll() is None:
            return False
        lasted = self.started is not None and nowm - self.started >= 30
        self.close()
        self.attempt = 0 if lasted else self.attempt + 1
        self.next_at = nowm + SYNC_BACKOFF[min(max(self.attempt - 1, 0), len(SYNC_BACKOFF) - 1)]
        return True

    def quit(self):
        """01's quit: the end of its input. It closes its connections, writes their status as idle and
        exits by itself; nothing waits for that here."""
        if self.p is not None:
            try:
                self.p.stdin.close()
            except (OSError, ValueError):
                pass
        self.close(wait=False)

    def close(self, wait=True):
        """Its input closed (its output is the reader's, which ends with it)."""
        p, self.p = self.p, None
        if p is None:
            return
        try:
            p.stdin.close()
        except (OSError, ValueError):
            pass
        if wait:
            try:
                p.wait(0.2)
            except subprocess.TimeoutExpired:
                pass


class AddRun:
    """One `oomph remote add TARGET --json --no-mirror --ask`, as the app runs it: it reaches the
    machine and pairs with the code (on stdin, never in an argument other users could read) bound to
    the key the code step showed (--fp). The identity question comes as a line and is answered on
    stdin. Its own session, no terminal."""

    def __init__(self, argv, code=None):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  start_new_session=True, close_fds=True)
        os.set_blocking(self.p.stdout.fileno(), False)
        self.buf, self.result, self.ask, self.eof = b"", None, None, False
        if code is not None:
            self.answer(code)

    def fileno(self):
        return self.p.stdout.fileno() if not self.eof else None

    def answer(self, line):
        try:
            self.p.stdin.write((line + "\n").encode())
            self.p.stdin.flush()
        except (OSError, ValueError):
            pass

    def pump(self):
        """Read what came; True when something changed (an ask, the answer, the end)."""
        got = False
        try:
            while True:
                b = self.p.stdout.read(65536)
                if b is None:
                    break
                if not b:
                    self.eof = got = True
                    break
                self.buf += b
                if len(self.buf) > 1 << 20:
                    self.buf = b""
        except (OSError, ValueError, TypeError):
            self.eof = got = True
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            o = oomph.loads_untrusted(line) if len(line) < 64 << 10 else None
            if isinstance(o, dict) and o.get("ev") == "ask":
                self.ask, got = o, True
            elif isinstance(o, dict):
                self.result, got = o, True
        return got

    def done(self):
        return self.eof and self.p.poll() is not None

    def cancel(self):
        try:
            self.p.kill()
        except OSError:
            pass
        for s in (self.p.stdin, self.p.stdout):
            try:
                s.close()
            except (OSError, ValueError):
                pass
        try:
            self.p.wait(1)
        except subprocess.TimeoutExpired:
            pass


def local_tab(model=None, cur=None):
    """This machine's tab: from its model while it is the one shown, else from the worker's summary of
    its current.json."""
    if model is not None and model.get("cur"):
        cur = dict(pressure=model["cur"]["pressure"], t=model["now"], interval=model.get("interval") or 30,
                   silent=model.get("logger") != "ok", incident=any(i["open"] for i in model["incidents"]) or None)
    return dict(mid="local", local=True, label=host_name(), addr="this machine", transport=None, cur=cur,
                version=oomph.VERSION, system=os_name(), known=None)


def with_tabs(model, wall=None):
    """A model of this machine as the dashboard draws it when no other machine is a tab: its own tab
    and the + (what tests compare the program's frame with)."""
    return dict(model, tabs=[local_tab(model)], sel=0, tab_mid="local", wall=model["now"] if wall is None else wall,
                engine="on", book=[])


class Source(threading.Thread):
    """The worker: every read and parse, the thinning, the reservation merge, the live measurement
    when no logger runs. It never touches the terminal; it hands finished models to the loop
    (`post`). Once a second it steps the selected machine's Feed and, with machines, reads the tabs'
    facts; another tab's feed keeps what it read for a minute after that tab was left, then goes
    with its history (04 §4.6)."""

    def __init__(self, log_dir, post, clock=time.time, root=False, machines=None):
        threading.Thread.__init__(self, daemon=True)
        self.log_dir, self.post, self.clock, self.root = log_dir, post, clock, root
        self.span = "24h"
        self.wake, self.stop = threading.Event(), threading.Event()
        self.feeds = {"local": Feed(log_dir, root=root)}
        self.machines = machines
        self.mid = "local"
        self.engine = "on"
        self.local_sig, self.local_cur = 0, None
        self.posted = None
        self.error = None
        self.left = {}              # mid → when its tab was left (its feed is dropped FEED_KEEP_S later)

    def set_span(self, span):
        self.span = span
        self.wake.set()

    def select(self, mid):
        self.mid = mid
        self.wake.set()

    def run(self):
        while not self.stop.is_set():
            try:
                self.step()
                self.error = None
            except Exception:
                self.error = traceback.format_exc()
            self.wake.wait(1.0)
            self.wake.clear()

    def step(self):
        wall = self.clock()
        tabs_changed = False
        M = self.machines
        if M is not None:
            tabs_changed = M.refresh(wall)
            p = os.path.join(self.log_dir, "current.json")
            try:
                st = os.stat(p)
                sig = (st.st_ino, st.st_size, st.st_mtime_ns)
            except OSError:
                sig = None
            if sig != self.local_sig or (self.local_cur and not self.local_cur["silent"] and
                                         wall - self.local_cur["t"] > 3 * self.local_cur["interval"] + 15):
                self.local_sig, self.local_cur = sig, cur_summary(_current(self.log_dir), wall)
                tabs_changed = True
        tabs = M.tabs() if M is not None else []
        entry = next((e for e in tabs if e["mid"] == self.mid), None)
        mid = entry["mid"] if entry is not None else "local"
        if M is not None:           # another tab's history goes a minute after it was left (04 §4.6)
            nowm = time.monotonic()
            live = {e["mid"] for e in tabs}
            for m_ in [m_ for m_ in self.feeds if m_ != "local" and m_ != mid]:
                if m_ not in live or nowm - self.left.setdefault(m_, nowm) > FEED_KEEP_S:
                    del self.feeds[m_]
                    self.left.pop(m_, None)
            self.left.pop(mid, None)
        feed = self.feeds.get(mid)
        if feed is None:
            d = os.path.join(M.base, mid)
            feed = self.feeds[mid] = Feed(os.path.join(d, "log"), os.path.join(d, "ledger"))
        now = wall + (M.tab(entry, wall)["sync"]["offset_s"] if entry is not None else 0.0)
        changed = feed.step(now, self.span)
        if changed or tabs_changed or self.posted != mid:
            self.posted = mid
            self.post(self.model(now, wall, mid))

    def model(self, now, wall=None, mid="local"):
        """The selected machine's model, with the tabs when there are machines."""
        m = self.feeds[mid].model(now)
        M = self.machines
        if M is None:
            return m
        wall = now if wall is None else wall
        local = local_tab(m if mid == "local" else None, self.local_cur)
        tabs = [local] + [M.tab(e, wall) for e in M.tabs()]
        sel = next((i for i, t in enumerate(tabs) if t["mid"] == mid), 0)
        m.update(tabs=tabs, sel=sel, tab_mid=mid, wall=wall, engine=self.engine,
                 book=[dict(e) for e in M.entries if not e.get("forgetting") and not M.is_hidden(e["mid"])])
        if mid != "local":
            t = tabs[sel]
            m.update(remote=True, host=t["label"], os=t.get("system") or "", off_text=None,
                     incidents=[dict(i, report=None) for i in m["incidents"]])
            if m.get("logger") == "off":
                m["logger"] = "ok"
        return m


def at(model, now):
    """The model as of `now` (a frame drawn between two of the worker's models): the clock, and the
    stretch without samples from the last one to now. For another machine its clock (01 §4.6), what
    claims to be now greyed when the link is not live, and the stretches not received (01 §3.5)."""
    m = dict(model, now=now)
    m.pop("views", None)
    t = None
    if "tabs" in model:
        m["wall"] = now
        if model.get("remote"):
            t = model["tabs"][model.get("sel", 0)]
            m["now"] = now = now + t["sync"]["offset_s"]
    last = model.get("last_t")
    if last is not None and now - last > view.GAP_S:
        m["gaps"] = list(model["gaps"]) + [(last, now)]
    if t is not None:
        v = view.link_view(t, m["wall"], model.get("engine", "on"))
        sy = t["sync"]
        m["stale"], m["known"] = v["stale"], t.get("known")
        m["gaps"], m["missing"] = view.mirror_gaps(m["gaps"], sy["have"], sy["gone"], sy["oldest"], now, v["stale"])
        if m["missing"]:
            m["first"] = min(m["first"], m["missing"][0][0]) if m.get("first") is not None else m["missing"][0][0]
    return m


# ------------------------------------------------------------------ the terminal
def detect_color(opt, tty, env):
    if opt in ("truecolor", "256", "16"):
        return opt
    if opt == "never" or not tty or "NO_COLOR" in env or env.get("TERM", "") in ("dumb", "vt100", "vt220", ""):
        return "none"
    if env.get("COLORTERM", "").lower() in ("truecolor", "24bit") or env.get("TERM", "").endswith("-direct"):
        return "truecolor"
    if "256" in env.get("TERM", ""):
        return "256"
    return "16"


def detect_theme(opt, env):
    if opt in ("dark", "light"):
        return opt
    bg = env.get("COLORFGBG", "").split(";")[-1]
    return "light" if bg in ("7", "15") else "dark"


def detect_glyphs(opt, env):
    if opt in ("unicode", "cells", "ascii"):
        return opt
    loc = env.get("LC_ALL") or env.get("LC_CTYPE") or env.get("LANG") or ""
    if loc and "UTF-8" not in loc.upper().replace("UTF8", "UTF-8"):
        return "ascii"
    if env.get("TERM_PROGRAM") in CELLS_TERMINALS:
        return "cells"
    return "unicode"


# ------------------------------------------------------------------ input: bytes → keys
ESC = "\x1b"
CSI_KEYS = {"A": "up", "B": "down", "C": "right", "D": "left", "H": "home", "F": "end", "Z": "shift-tab"}
TILDE = {"1": "home", "7": "home", "4": "end", "8": "end", "5": "pgup", "6": "pgdn", "3": "delete", "2": "insert",
         "11": "f1", "12": "f2", "13": "f3", "14": "f4", "15": "f5"}
SS3_KEYS = {"A": "up", "B": "down", "C": "right", "D": "left", "H": "home", "F": "end",
            "P": "f1", "Q": "f2", "R": "f3", "S": "f4"}
MODS = {"2": "shift-", "3": "alt-", "5": "ctrl-", "6": "ctrl-shift-"}
PASTE_WAIT = 2.0            # seconds without a byte that end a paste whose ESC [201~ never came
CTRL = {"\r": "enter", "\n": "enter", "\t": "tab", "\x7f": "backspace", "\x08": "backspace"}


class Decoder:
    """Bytes from the terminal → events, one at a time through `emit`: ("key", name), ("text", ch),
    ("paste", text), ("paste-too-long",), ("mouse", b, x, y, down), ("reply", kind, data). 04 §4.3.

    Mode-aware: in command mode a printable character is a key, in text mode (a field has the focus;
    `in_text()` is asked at every character) it is text. Works on bytes; UTF-8 is decoded only
    outside sequences and inside a paste. Sequences are consumed whole whatever their length: a CSI
    longer than any known one, an OSC or DCS string, a paste over 64 KB are swallowed to their end,
    never replayed as keys; a paste whose end does not come within PASTE_WAIT of its last byte is
    dropped (`paste-too-long`), so a torn one cannot swallow q and ctrl-c. A lone ESC is the Escape key once nothing follows it for `esc_wait`; the
    tail of a sequence that a slow link tore apart is recognised in command mode only, within a
    second after that ESC was reported. Time is an argument: tests never sleep."""

    def __init__(self, emit, in_text=lambda: False, esc_wait=0.05, tail_window=1.0, mouse=lambda: False):
        import codecs
        self.emit, self.in_text, self.mouse = emit, in_text, mouse
        self.esc_wait, self.tail_window = esc_wait, tail_window
        self.reads = 0
        self.utf8 = codecs.getincrementaldecoder("utf-8")("replace")
        self.state, self.seq, self.esc_at, self.tail_until = "ground", "", None, -1.0
        self.paste, self.overflow, self.prev_esc, self.skip = None, False, False, 0

    def tick(self, now):
        if self.state == "esc" and now - self.esc_at >= self.esc_wait:
            self.state = "ground"
            self.tail_until = now + self.tail_window
            self.emit(("key", "esc"))
        if self.state in ("csi", "ss3", "osc", "dcs", "x10") and now - self.esc_at >= 1.0:
            self.state, self.seq, self.overflow = "ground", "", False
        if self.state == "paste" and now - self.esc_at >= PASTE_WAIT:     # its end never came: dropped whole
            self.state, self.paste, self.overflow = "ground", None, False
            self.utf8.reset()
            self.emit(("paste-too-long",))

    def next_timeout(self):
        """When tick() has something to do (None: nothing pending)."""
        if self.state == "esc":
            return self.esc_at + self.esc_wait
        if self.state in ("csi", "ss3", "osc", "dcs", "x10"):
            return self.esc_at + 1.0
        if self.state == "paste":
            return self.esc_at + PASTE_WAIT
        return None

    def feed(self, data, now):
        self.tick(now)
        self.reads += 1
        for b in data:
            self._byte(b, now)

    def _byte(self, b, now):
        st = self.state
        if st == "x10":
            self.esc_at = now
            self.skip -= 1
            if self.skip <= 0:
                self.state = "ground"
            return
        if st in ("ground", "paste") and b >= 0x80:
            for ch in self.utf8.decode(bytes((b,))):
                self._char(ch, now)
            return
        if st not in ("ground", "paste"):
            self.utf8.reset()
        self._char(chr(b), now)

    def _char(self, ch, now):
        st = self.state
        if st in ("csi", "ss3", "osc", "dcs", "paste"):
            self.esc_at = now
        if st == "paste":
            self.paste += ch
            if self.paste.endswith(ESC + "[201~"):
                text = self.paste[:-6]
                if not self.overflow:
                    self.emit(("paste", "".join(c for c in text if c >= " " and c != "\x7f" and not "\x80" <= c <= "\x9f")))
                else:
                    self.emit(("paste-too-long",))
                self.state, self.paste, self.overflow = "ground", None, False
            elif len(self.paste) > 65536:
                self.paste, self.overflow = self.paste[-8:], True
            return
        if st == "ground":
            if ch == ESC:
                self.state, self.esc_at = "esc", now
            elif ch == "\x9b":
                self.state, self.seq, self.esc_at = "csi", "", now
            elif not self.in_text() and now < self.tail_until and ch in "[O]":
                self.state, self.seq, self.esc_at = {"[": "csi", "O": "ss3", "]": "osc"}[ch], "", now
                self.tail_until = -1.0
            elif ch in CTRL:
                self.emit(("key", CTRL[ch]))
            elif ch < " ":
                self.emit(("key", "ctrl-" + chr(ord(ch) + 96)))
            elif "\x80" <= ch <= "\x9f":
                pass
            else:
                self.emit(("text", ch) if self.in_text() else ("key", ch))
            return
        if st == "esc":
            self.seq = ""
            if ch == "[":
                self.state = "csi"
            elif ch == "O":
                self.state = "ss3"
            elif ch == "]":
                self.state = "osc"
            elif ch == "P":
                self.state = "dcs"
            elif ch == ESC:
                self.emit(("key", "esc"))
                self.esc_at = now
            else:
                self.state = "ground"
                if ch >= " ":
                    self.emit(("key", "alt-" + ch))
            return
        if st == "ss3":
            self.state = "ground"
            if ch in SS3_KEYS:
                self.emit(("key", SS3_KEYS[ch]))
            return
        if st == "csi":
            if "\x20" <= ch <= "\x3f":
                if len(self.seq) < 64:
                    self.seq += ch
                else:
                    self.overflow = True
            elif "\x40" <= ch <= "\x7e":
                self.state, over, self.overflow = "ground", self.overflow, False
                if not over:
                    self._csi(self.seq, ch)
            else:
                self.state, self.overflow = "ground", False
                self._byte(ord(ch), now)
            return
        if st in ("osc", "dcs"):
            if ch == "\x07" or (ch == "\\" and self.prev_esc):
                if not self.overflow:
                    self.emit(("reply", st, self.seq.rstrip(ESC)))
                self.state, self.overflow, self.prev_esc = "ground", False, False
                return
            self.prev_esc = ch == ESC
            if len(self.seq) < 256:
                self.seq += ch
            else:
                self.overflow = True

    def _csi(self, params, final):
        if final == "~":
            p = params.split(";")
            if p[0] == "200":
                self.state, self.paste = "paste", ""      # (esc_at: this sequence's last byte, just now)
            elif p[0] in TILDE:
                self.emit(("key", MODS.get(p[1], "") + TILDE[p[0]] if len(p) > 1 else TILDE[p[0]]))
            return
        if final == "M" and params == "":
            if self.mouse():
                self.state, self.skip = "x10", 3
            return
        if params.startswith("<") and final in "Mm":
            try:
                b, x, y = (int(v) for v in params[1:].split(";"))
            except ValueError:
                return
            self.emit(("mouse", b, x, y, final == "M"))
            return
        if params.startswith("?") and final == "c":
            self.emit(("reply", "da", params[1:]))
            return
        if final == "R" and ";" in params and not params.startswith("1;"):
            self.emit(("reply", "cpr", params))     # asked from row 2: "CSI 1;4R" is also a modified F3
            return
        if final in CSI_KEYS and not params.startswith("?"):
            p = params.split(";")
            mod = MODS.get(p[1], "") if len(p) > 1 else ""
            name = CSI_KEYS[final]
            self.emit(("key", name if not mod else (mod + name if name != "shift-tab" else name)))


# ------------------------------------------------------------------ the terminal
ENTER = "\x1b[?1049h\x1b[?25l\x1b[?7l\x1b[?2004h"
LEAVE = "\x1b[?2026l\x1b[?2004l\x1b[?1000l\x1b[?1006l\x1b[0m\x1b[?7h\x1b[?25h\x1b[?1049l"
SSH_LEAVE = LEAVE.replace("\x1b[?1049l", "\x1b[?1047l")     # back to the main screen, the cursor left alone
PROBE_GLYPH = "\x1b[2;1H∞─█\x1b[6n"          # "∞─█" from row 2, then where the cursor is
PROBE_REST = "\x1b]11;?\x1b\\\x1b[48;2;1;2;3m\x1bP$qm\x1b\\\x1b[0m\x1b[c"


class Leave(Exception):
    """SIGTERM or SIGHUP: unwinds even a write that is blocked on a stalled terminal."""


class Gone(Exception):
    """The terminal went away (end of input, EIO): leave without writing."""


class Term:
    """Raw mode, the alternate screen, and leaving them again on every way out, without waiting on a
    terminal that has stopped reading (04 §4.3)."""

    def __init__(self, fd_in, fd_out):
        import termios
        self.termios = termios
        self.fd_in, self.fd_out = fd_in, fd_out
        self.saved = termios.tcgetattr(fd_in)
        self.entered = False
        self.shown = None

    def enter(self, extra=""):
        import tty
        tty.setraw(self.fd_in, self.termios.TCSANOW)
        self.entered = True
        self.shown = None
        self.write(ENTER + extra)

    def restore(self):
        """Back to how the terminal was: pending output discarded, modes restored at once (never
        waiting for output to drain), the leave sequences written for at most 200 ms."""
        if not self.entered:
            return
        self.entered = False
        tc = self.termios
        try:
            tc.tcflush(self.fd_out, tc.TCOFLUSH)
        except (OSError, tc.error):
            pass
        try:
            tc.tcsetattr(self.fd_in, tc.TCSANOW, self.saved)
        except (OSError, tc.error):
            pass
        data, deadline = LEAVE.encode(), time.monotonic() + 0.2
        try:
            fl = fcntl.fcntl(self.fd_out, fcntl.F_GETFL)
            fcntl.fcntl(self.fd_out, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        except OSError:
            return
        try:
            while data and time.monotonic() < deadline:
                try:
                    data = data[os.write(self.fd_out, data):]
                except BlockingIOError:
                    time.sleep(0.01)
                except OSError:
                    break
        finally:
            try:
                fcntl.fcntl(self.fd_out, fcntl.F_SETFL, fl)
            except OSError:
                pass

    def size(self):
        try:
            w, h = os.get_terminal_size(self.fd_out)
        except OSError:
            return 80, 24
        return (w or 80), (h or 24)

    def write(self, text):
        data = text.encode("utf-8", "replace")
        while data:
            try:
                data = data[os.write(self.fd_out, data):]
            except OSError as e:
                if e.errno in (errno.EIO, errno.EPIPE, errno.ENXIO, errno.EBADF):
                    self.entered = False            # nothing more can reach it
                    raise Gone()
                if e.errno == errno.EAGAIN:
                    select.select([], [self.fd_out], [], 1.0)
                    continue
                raise

    def present(self, frame, caps, extra=""):
        """Show `frame`: the difference to what is on screen (everything after forget())."""
        out = view.diff_ansi(self.shown, frame, caps)
        if out or extra:
            self.write(extra + out)
        self.shown = frame

    def forget(self):
        self.shown = None


# ------------------------------------------------------------------ settings and who we are
def state_dir(euid=None):
    """The per-user state folder, from the password database (never $HOME: `sudo -u other` keeps
    HOME on macOS). OOMPH_STATE_DIR wins, as everywhere in oomph."""
    if os.environ.get("OOMPH_STATE_DIR"):
        return os.environ["OOMPH_STATE_DIR"]
    import pwd
    try:
        home = pwd.getpwuid(os.geteuid() if euid is None else euid).pw_dir
    except KeyError:
        return None
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support", oomph.CMD)
    x = os.environ.get("XDG_STATE_HOME") or ""
    return os.path.join(x if os.path.isabs(x) else os.path.join(home, ".local", "state"), oomph.CMD)


def readonly_reason(sdir, euid=None, home=None):
    """Why this run is a pure viewer, or None (04 §4.10): run as root, or the settings folder (or,
    while it does not exist, its nearest existing ancestor up to the home folder: a fresh Linux
    account has no ~/.local/state, and save_settings creates it) belongs to someone else."""
    euid = os.geteuid() if euid is None else euid
    if euid == 0:
        return "Running as root: read-only, settings not saved"
    if not sdir:
        return "Read-only: no settings folder for this user"
    if home is None:
        import pwd
        try:
            home = pwd.getpwuid(euid).pw_dir
        except KeyError:
            home = None
    d = os.path.abspath(sdir)
    while True:
        try:
            st = os.stat(d)
        except FileNotFoundError:
            up = os.path.dirname(d)
            if up == d or (home and d == os.path.abspath(home)):
                return "Read-only: no settings folder for this user"
            d = up
            continue
        except OSError:
            return "Read-only: can't look at the settings folder"
        return None if st.st_uid == euid else "Read-only: the settings folder is not this user's"


def config_path(sdir):
    return os.environ.get("OOMPH_TOP_CONFIG") or (os.path.join(sdir, "top.json") if sdir else None)


def load_settings(path):
    """top.json: where the last run left off and what was chosen; damaged or missing → defaults."""
    if not path:
        return {}
    d = oomph.read_bounded(path, 64 << 10)
    v = oomph.loads_untrusted(d) if d else None
    return v if isinstance(v, dict) else {}


def save_settings(path, settings):
    """Into the user's own state folder (created 700 if missing) by a new file and a rename; 600."""
    import tempfile
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".top-", suffix=".json")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(settings, f, sort_keys=True)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_crash(sdir, text):
    """The last crash's traceback beside top.json (never in a shared temp folder, never as root)."""
    if not sdir:
        return
    p = os.path.join(sdir, "top-crash.log")
    try:
        os.makedirs(sdir, mode=0o700, exist_ok=True)
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
    except OSError:
        pass


# ------------------------------------------------------------------ the loop
NAV = ("up", "down", "pgup", "pgdn", "home", "end")
KEY_ALIASES = {"j": "down", "k": "up", "f1": "?", " ": "space"}   # the decoder gives a printable key as itself
SPAN_WORDS = {"inf": "14 days", "24h": "24 h", "6h": "6 h", "1h": "1 h"}
MACHINE_DIALOGS = ("connect", "pair", "ssh", "ask", "name", "rename", "forget", "attention", "list")
TEXT_DIALOGS = ("connect", "pair", "name", "rename", "list")
REPORT_LAST = {"inf": "14d", "24h": "24h", "6h": "6h", "1h": "1h"}


def _clip_tool():
    """A clipboard tool where the user sits (an argument vector), or None: then OSC 52."""
    import shutil
    if sys.platform == "darwin":
        return ["/usr/bin/pbcopy"] if os.path.exists("/usr/bin/pbcopy") else None
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
        return [shutil.which("wl-copy")]
    if os.environ.get("DISPLAY"):
        for tool, a in (("xclip", ["-selection", "clipboard"]), ("xsel", ["-ib"])):
            if shutil.which(tool):
                return [shutil.which(tool)] + a
    return None


def detected_text(c, auto, size):
    """The help's last line: what is in use (04 §5.2: where to find the option for a glyph set)."""
    dot = "·" if c.glyphs != "ascii" else "-"
    return "detected: %s %s %s glyphs %s %s%s %s %dx%d" % (
        {"truecolor": "24-bit colour", "256": "256 colours", "16": "16 colours", "none": "no colour"}[c.color],
        dot, c.glyphs, dot, c.theme, " (auto)" if auto.get("theme") else "", dot, size[0], size[1])


class App:
    """The full-screen dashboard (04 §4.9): one thread that answers keys and draws, and the worker
    (Source) that reads. A key redraws at once; data at most twice a second; the clock and the ages
    once a second while something on screen counts seconds, else every 10 s. No change writes
    nothing."""

    def __init__(self, term, caps, auto, span, log_dir, readonly=None, bell=False, fixed_now=None, probe=True,
                 note=None, mouse=False, machines=None, no_connect=False, start_mid="local"):
        self.term, self.caps, self.auto = term, caps, auto
        self.mouse = mouse
        self.ui = {"span": span}
        if readonly:
            self.ui["readonly"] = readonly
        self.readonly, self.bell, self.fixed_now = readonly, bell, fixed_now
        self.model, self.models = None, queue.Queue(maxsize=1)
        self.wake_r, self.wake_w = os.pipe()
        for fd in (self.wake_r, self.wake_w):
            fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        self.me = [sys.executable or "/usr/bin/python3", "-I", "-B", os.path.realpath(oomph.__file__)]
        self.src = Source(log_dir, self.post, clock=self.now, root=os.geteuid() == 0, machines=machines)
        self.src.span = span
        self.M = machines                    # None: no machine tabs (oomph_sync missing, root, read-only)
        self.S = machines.S if machines is not None else None
        self.src.engine = "off" if no_connect else "on"
        self.sync = SyncChild(self.remote_argv() + ["sync", "--json"], self.sync_woke) \
            if machines is not None and not no_connect else None
        self.add, self.add_from, self.undo, self.pending_select, self.watching = None, None, None, None, None
        self.queued = []                     # commands for the sync child while it is not running
        self.mid = start_mid if machines is not None else "local"
        self.src.mid = self.mid
        ssh = bool(os.environ.get("SSH_CONNECTION"))
        self.decoder = Decoder(self.on_event, esc_wait=0.15 if ssh else 0.05, mouse=lambda: self.mouse,
                               in_text=self.in_text)
        self.probe_until = (time.monotonic() + (0.5 if ssh else 0.15)) if probe else 0.0
        self.probe = probe
        self.full = self.dirty = True
        self.quit = False
        self.flags = set()
        self.resize_at = 0.0
        self.next_tick = 0.0
        self.note_until = 0.0
        self.pending = ""
        self.children = []
        self.open_ids, self.pressure, self.bell_at, self.first_model = set(), None, -1e9, True
        self.data_at = 0.0
        self.size = (80, 24)
        self.starting, self.pending_leave = False, None
        if note:
            self.note(note, "warntx", 10.0)

    # ---- time and the worker
    def now(self):
        return self.fixed_now if self.fixed_now is not None else time.time()

    def sync_woke(self, failed):
        """From the sync child's reader: the worker reads the files again; a failure wakes the loop
        too, for its note."""
        self.src.wake.set()
        if failed:
            try:
                os.write(self.wake_w, b"f")
            except OSError:
                pass

    def post(self, model):
        """From the worker: a finished model. Only the newest is kept: while the loop is held up (a
        terminal that stopped reading) models must not pile up."""
        try:
            self.models.get_nowait()
        except queue.Empty:
            pass
        try:
            self.models.put_nowait(model)
        except queue.Full:                  # (only the worker puts: cannot happen)
            pass
        try:
            os.write(self.wake_w, b"m")
        except OSError:
            pass

    def note(self, text, role="dim", secs=4.0):
        self.ui["note"] = (text, role)
        self.note_until = time.monotonic() + secs
        self.dirty = True

    # ---- signals
    def _flag(self, name):
        def h(signum, frame):
            self.flags.add(name)
        return h

    def install_signals(self):
        signal.signal(signal.SIGWINCH, self._flag("winch"))
        signal.signal(signal.SIGCONT, self._flag("cont"))
        signal.signal(signal.SIGTSTP, self._flag("tstp"))
        signal.signal(signal.SIGTERM, self._leave)
        signal.signal(signal.SIGHUP, self._leave)
        signal.set_wakeup_fd(self.wake_w)

    def _leave(self, signum, frame):
        """SIGTERM, SIGHUP: raise (even a blocked write unwinds), except while the worker thread is being
        started, which must not be torn in half: then right after."""
        signal.signal(signum, signal.SIG_DFL)       # a second one kills outright
        if self.starting:
            self.pending_leave = signum
            return
        raise Leave(signum)

    @staticmethod
    def _late(signum, frame):
        """SIGTERM, SIGHUP while leaving: no Leave, so the terminal's restore runs to its end (a blocked
        write is resumed), but a second one kills outright, as in _leave. A handler, not SIG_IGN: an
        ignored signal would stay ignored in any child started meanwhile, a handler resets at exec."""
        signal.signal(signum, signal.SIG_DFL)

    # ---- running
    def run(self):
        tb = None
        rc = 0
        try:
            self.install_signals()
            self.size = self.term.size()
            try:
                self.src.step()                      # the first frame needs today, the ledger, nothing else
            except (Leave, Gone):
                raise
            except Exception:
                if not self.readonly:                # the worker tries again; the frame says "reading…"
                    write_crash(state_dir(), traceback.format_exc())
            probe = ""
            if self.probe:
                probe = (PROBE_GLYPH if self.auto.get("glyphs") and self.caps.glyphs != "ascii" else "") + PROBE_REST
            self.term.enter(probe + self.mouse_modes())
            self.take_models()
            self.paint()
            self.starting = True
            self.src.start()
            self.starting = False
            if self.pending_leave:
                raise Leave(self.pending_leave)
            self.loop()
        except (Leave, Gone, KeyboardInterrupt):
            rc = 0
        except Exception:
            tb, rc = traceback.format_exc(), 1
        finally:
            for s in (signal.SIGTERM, signal.SIGHUP):         # leaving anyway: a first one doesn't interrupt the restore
                signal.signal(s, self._late)
            self.src.stop.set()
            self.src.wake.set()
            if self.sync is not None:            # quitting settles an undo, as closing the popup does
                self.sync.quit()
            if self.add is not None:
                self.add.cancel()
            try:
                self.term.restore()
            finally:
                try:
                    signal.set_wakeup_fd(-1)
                except (ValueError, OSError):
                    pass
                self.leave_children()
                for s in (signal.SIGTERM, signal.SIGHUP):     # no Leave outside this method
                    signal.signal(s, signal.SIG_DFL)
        if tb:
            sys.stderr.write(tb)
            if not self.readonly:
                write_crash(state_dir(), tb)
        return rc

    def loop(self):
        fd = self.term.fd_in
        while not self.quit:
            nowm = time.monotonic()
            due = [self.next_tick, self.resize_at if "resize" in self.flags else None,
                   self.note_until if self.ui.get("note") else None, self.decoder.next_timeout(),
                   nowm + (0.1 if any(c[3] for c in self.children) else 0.5) if self.children else None,
                   self.data_at + 0.5 if not self.models.empty() else None]
            wait = max(0.0, min([d for d in due if d is not None]) - nowm)
            kids = [self.add.fileno()] if self.add is not None and self.add.fileno() is not None else []
            if self.sync is not None and not self.sync.running() and self.wants_sync():
                wait = min(wait, max(0.0, self.sync.next_at - nowm))
            try:
                r, _, _ = select.select([fd, self.wake_r] + kids, [], [],
                                        min(wait, 1.0 if self.add is not None or self.sync is not None and self.wants_sync()
                                            else 10.0))
            except InterruptedError:
                r = []
            nowm = time.monotonic()
            if self.wake_r in r:
                try:
                    while os.read(self.wake_r, 512):
                        pass
                except OSError:
                    pass
            if fd in r:
                try:
                    data = os.read(fd, 65536)
                except OSError as e:
                    if e.errno in (errno.EAGAIN, errno.EINTR):
                        data = None
                    else:
                        raise Gone()
                if data == b"":
                    raise Gone()                     # the terminal is gone: leave, writing nothing
                if data:
                    self.decoder.feed(data, nowm)
            self.decoder.tick(nowm)
            self.handle_flags(nowm)
            if self.M is not None:
                self.machines_tick(nowm)
            if not self.models.empty() and nowm >= self.data_at + 0.5:
                self.take_models()
                self.data_at = nowm
            self.reap(nowm)
            if self.ui.get("note") and nowm >= self.note_until:
                del self.ui["note"]
                self.dirty = True
            if nowm >= self.next_tick:
                self.dirty = True
            if self.dirty and not ("resize" in self.flags and nowm < self.resize_at) and not self.quit:
                if "resize" in self.flags:
                    self.flags.discard("resize")
                    self.size, self.full = self.term.size(), True
                self.paint()

    def handle_flags(self, nowm):
        f = self.flags
        if "winch" in f:
            f.discard("winch")
            f.add("resize")
            self.resize_at, self.dirty = nowm + 0.03, True
        if "tstp" in f:
            f.discard("tstp")
            self.suspend()
        if "cont" in f:
            f.discard("cont")
            if self.sync is not None and self.sync.running() is False and self.M is not None:
                self.M.reopen(self.now())
            self.term.enter(self.mouse_modes())      # a shell may have changed the modes while we were stopped
            self.size, self.full, self.dirty = self.term.size(), True, True

    def suspend(self):
        """ctrl-z: the terminal restored, then stopped the way a shell expects; `fg` repaints. Where no
        shell does job control the kernel discards the stop: the session's leader (what sshd starts for
        `ssh -t host oomph top` and for --ssh) is told so up front, without leaving the screen; any other
        stop that did not happen (no SIGCONT came) is told so after."""
        if os.getpgrp() == os.getsid(0):
            self.no_stop()
            return
        if self.sync is not None:       # suspended is not watching (04 §4.7): the lock is free for the app at once
            self.sync.quit()
            self.sync.next_at = 0.0
            self.watching = None
        self.term.restore()
        signal.signal(signal.SIGTSTP, signal.SIG_DFL)
        self.flags.discard("cont")
        os.kill(os.getpid(), signal.SIGTSTP)
        time.sleep(0.01)                            # (the SIGCONT handler of a stop that happened runs here)
        signal.signal(signal.SIGTSTP, self._flag("tstp"))
        stopped = "cont" in self.flags
        self.flags.discard("cont")
        if self.M is not None:
            self.M.reopen(self.now())
        self.term.enter(self.mouse_modes())
        self.size, self.full, self.dirty = self.term.size(), True, True
        if not stopped:
            self.no_stop()

    def no_stop(self):
        self.note("can't suspend; ssh's own: enter ~ ctrl-z" if os.environ.get("SSH_CONNECTION") else
                  "can't suspend here: no job control", "dim", 6.0)

    def take_models(self):
        m = None
        while True:
            try:
                m = self.models.get_nowait()
            except queue.Empty:
                break
        if m is None:
            return
        self.attention(m)
        self.model, self.dirty = m, True
        self.clamp()

    def clamp(self):
        """Selections stay inside lists that may have shrunk."""
        if not self.model:
            return
        seq = view.res_seq(at(self.model, self.now()))[0]
        for key, n in (("res_sel", len(seq)), ("inc_sel", len(self.model["incidents"]))):
            if key in self.ui:
                self.ui[key] = max(0, min(self.ui[key], n - 1))
        if self.ui.get("panel"):
            n = len(view.panel_items(self.model, self.ui["panel"]))
            self.ui["panel_sel"] = max(0, min(self.ui.get("panel_sel", 0), n - 1))

    def attention(self, m):
        """--bell: one BEL when an incident opens or pressure turns critical; at most once in 15 min."""
        open_ids = {i["id"] for i in m["incidents"] if i["open"]}
        pressure = (m.get("cur") or {}).get("pressure")
        if self.bell and not self.first_model and time.monotonic() - self.bell_at >= 900 and (
                open_ids - self.open_ids or (pressure == "Critical" and self.pressure != "Critical")):
            self.pending += "\x07"
            self.bell_at = time.monotonic()
        self.open_ids, self.pressure, self.first_model = open_ids, pressure, False

    def seconds_on_screen(self, m):
        """Does anything on screen count seconds ("waiting 40 s", an incident open for 20 s, a grant
        with 45 s left)? Then the frame is drawn every second; otherwise every 10 s (minutes and the
        clock are at most that late)."""
        now = m["now"]
        if self.undo is not None or any(not t.get("local") for t in m.get("tabs") or ()):
            return True                 # marks, countdowns and the opening's steps change by the second
        for r in m["res"]:
            if r.get("ended") is None:
                if r.get("granted") is None and now - r["requested"] < 90:
                    return True
                if r.get("expires") is not None and r["expires"] - now < 60:
                    return True
        return any(i["open"] and now - i["start"] < 90 for i in m["incidents"])

    def detected(self):
        return detected_text(self.caps, self.auto, self.size)

    def paint(self):
        W, H = self.size
        now = self.now()
        self.ui["detected"] = self.detected()
        if self.model is None:
            fr = view.Frame(W, H, self.caps.glyphs == "ascii")
            fr.put(1, 0, "%s top: reading…" % oomph.CMD, "dim")
        else:
            m = at(self.model, now)
            try:
                fr = view.render(m, W, H, self.caps, self.ui)
            except (Leave, Gone):
                raise
            except Exception:
                tb = traceback.format_exc()
                if not self.readonly:
                    write_crash(state_dir(), tb)
                fr = view.Frame(W, H, self.caps.glyphs == "ascii")
                fr.put(1, 0, "%s top" % oomph.CMD, "fg", None, view.BOLD)
                fr.put(1, 2, "can't draw this frame (%s); the details are in top-crash.log" % tb.strip().splitlines()[-1][:80],
                       "warntx")
                fr.put(1, H - 1, "q quit  esc back", "dim")
            if fr.yhold:
                self.ui["yhold"] = (self.ui["span"], fr.yhold)
            self.next_tick = time.monotonic() + (1.0 if self.seconds_on_screen(m) else 10.0)
        if self.full:
            self.term.forget()
            self.full = False
        extra, self.pending = self.pending, ""
        self.term.present(fr, self.caps, extra)
        self.dirty = False

    # ---- input
    def mouse_modes(self):
        """What turns mouse reporting on: buttons and the wheel in SGR coordinates, no motion (04 §3.10)."""
        return "\x1b[?1000h\x1b[?1006h" if self.mouse else ""

    def toggle_mouse(self):
        """ctrl-o (04 §3.10, the owner's key): mouse on or off. Off by default, since reporting takes the
        terminal's own text selection away (it then needs shift or option)."""
        self.mouse = not self.mouse
        self.pending += "\x1b[?1000h\x1b[?1006h" if self.mouse else "\x1b[?1000l\x1b[?1006l"
        self.note("mouse on · shift-drag selects text" if self.mouse else "mouse off", "dim", 6.0 if self.mouse else 3.0)

    def on_event(self, ev):
        kind = ev[0]
        if kind == "reply":
            self.on_reply(ev[1], ev[2])
            return
        if kind in ("text", "paste") and self.in_text():
            self.dirty = True
            try:
                self.type_text(ev[1])
            except (Leave, Gone):
                raise
            except Exception:
                if not self.readonly:
                    write_crash(state_dir(), traceback.format_exc())
                self.note("that key failed; the details are in top-crash.log", "warntx")
            return
        if kind in ("paste", "paste-too-long"):
            self.note("pasted text ignored")
            return
        if kind == "mouse":
            if self.mouse and ev[4]:
                self.dirty = True
                try:
                    self.click(ev[1], ev[2] - 1, ev[3] - 1)
                except (Leave, Gone):
                    raise
                except Exception:
                    if not self.readonly:
                        write_crash(state_dir(), traceback.format_exc())
                    self.note("that click failed; the details are in top-crash.log", "warntx")
            return
        if kind != "key":
            return
        self.dirty = True
        try:
            self.key(ev[1])
        except (Leave, Gone):
            raise
        except Exception:
            if not self.readonly:
                write_crash(state_dir(), traceback.format_exc())
            self.note("that key failed; the details are in top-crash.log", "warntx")

    def on_reply(self, kind, data):
        if time.monotonic() > self.probe_until:
            return
        c, changed = self.caps, False
        if kind == "cpr" and self.auto.get("glyphs"):
            parts = data.split(";")
            if len(parts) == 2 and parts[0] == "2" and parts[1] != "4" and c.glyphs != "ascii":
                c.glyphs, changed = "ascii", True        # ambiguous characters are wide, or no UTF-8
        elif kind == "osc" and data.startswith("11;") and self.auto.get("theme"):
            mm = re.search(r"rgb:([0-9a-fA-F]{1,4})/([0-9a-fA-F]{1,4})/([0-9a-fA-F]{1,4})", data)
            if mm:
                r, g, b = (int(x, 16) / float(16 ** len(x) - 1) for x in mm.groups())
                theme = "light" if 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.5 else "dark"
                if theme != c.theme:
                    c.theme, changed = theme, True
        elif kind == "dcs" and self.auto.get("color") and c.color == "256":
            if re.search(r"(^|[;:])2[;:]+1[;:]2[;:]3m", data):
                c.color, changed = "truecolor", True
        elif kind == "da":
            self.probe_until = 0.0
        if changed:
            self.full = self.dirty = True

    def model_now(self):
        return at(self.model, self.now()) if self.model else None

    def keep_note(self):
        """A note the view left in `ui` ("nothing to select there") stays its few seconds."""
        n = self.ui.get("note")
        if n and time.monotonic() >= self.note_until:
            self.note(*n)

    def click(self, button, x, y):
        """A mouse button pressed at the 0-based cell (x, y)."""
        m, ui = self.model_now(), self.ui
        if m is None or self.size[0] < 40 or self.size[1] < 10:
            return
        if ui.get("overlay"):                        # a click closes a dialog, as esc does
            if not button & 64:
                ui.pop("overlay")
            return
        if y == 0 and m.get("tabs") and not button & 64:      # row 0: a tab, a counter, the +
            fr = view.Frame(self.size[0], 1, self.caps.glyphs == "ascii")
            view.machine_tabs(fr, m, self.caps, view.GLYPHS[self.caps.glyphs])
            for x0, x1, kind, which in fr.tab_hits:
                if x0 <= x < x1:
                    tabs = m["tabs"]
                    if kind == "tab":
                        self.select_mid(tabs[which]["mid"])
                    elif kind == "plus":
                        self.key_machines("+", m)
                    else:                            # a counter: the nearest machine it hides
                        shown = [h[3] for h in fr.tab_hits if h[2] == "tab"]
                        i = min(shown) - 1 if which == "l" else max(shown) + 1
                        self.select_mid(tabs[max(0, min(i, len(tabs) - 1))]["mid"])
            return
        P = view.layout(m, *self.size)
        act = view.mouse(ui, m, P, view.GLYPHS[self.caps.glyphs], button, x, y)
        self.keep_note()
        if act and act[0] == "span":
            self.set_span(act[1])
        elif act and act[0] == "card":
            self.open_card(m)

    def key(self, k):
        ui, m = self.ui, self.model_now()
        k = KEY_ALIASES.get(k, k)
        if k == "ctrl-c":
            self.quit = True
            return
        if k == "ctrl-l":
            self.full = True
            return
        if k == "ctrl-z":
            self.suspend()
            return
        if k == "ctrl-o":
            self.toggle_mouse()
            return
        if m is None:
            if k == "q":
                self.quit = True
            return
        W, H = self.size
        P = view.layout(m, W, H)
        ov = ui.get("overlay")
        if ov and ov.get("kind") in MACHINE_DIALOGS:
            self.key_machine_dialog(k, ov, m)
            return
        if ov:
            self.key_overlay(k, ov, m, P)
            return
        if self.M is not None and not ui.get("inspect") and self.key_machines(k, m):
            return
        if ui.get("inspect") and W >= 40 and H >= 10:
            if k in ("t", "T"):                      # the span changes; the cursor keeps its time
                i = (view.SPAN_ORDER.index(ui["span"]) + (1 if k == "t" else -1)) % len(view.SPAN_ORDER)
                self.set_span(view.SPAN_ORDER[i])
                return
            if k in ("q", "?") or not view.inspect_key(ui, k, m, P):
                if k in ("a", "s", "e"):             # a panel takes the readout's place
                    ui.pop("inspect", None)
                elif k not in ("q", "?"):
                    return
            else:
                self.keep_note()
                return
        if k == "i" and W >= 40 and H >= 10:
            if ui.get("panel"):
                view.press(ui, "esc", m, P)
            view.inspect_at(ui, m, P, P["plot_w"] - 1)
            return
        if k == "q":
            self.quit = True
        elif k == "?":
            ui["overlay"] = {"kind": "help", "page": 1, "off": 0}
        elif k in ("left", "right", "t", "T"):
            i = view.SPAN_ORDER.index(ui["span"])
            if k in ("left", "right"):
                i = max(0, min(len(view.SPAN_ORDER) - 1, i + (-1 if k == "left" else 1)))
            else:
                i = (i + (1 if k == "t" else -1)) % len(view.SPAN_ORDER)
            self.set_span(view.SPAN_ORDER[i])
        elif k in ("a", "s", "e"):
            if ui.get("panel") == k:
                view.press(ui, "esc", m, P)
            else:
                for x in ("panel_sel", "panel_off"):
                    ui.pop(x, None)
                if ui.get("focus") in ("res", "inc", "panel"):
                    ui.pop("focus")
                ui["panel"] = k
        elif k == "enter":
            self.open_card(m)
        elif k in ("o", "y") and m.get("tab_mid", "local") != self.mid:
            pass                        # the frame is still the last tab's: its incidents are not this one's
        elif k == "o":
            kind, item = view.selected(m, ui)
            self.report(item if kind == "inc" else None)
        elif k == "y":
            kind, item = view.selected(m, ui)
            if kind == "inc":
                self.copy(item)
        elif k in NAV + ("esc", "space"):
            view.press(ui, k, m, P)

    def set_span(self, span):
        if span != self.ui["span"]:
            self.ui["span"] = span
            self.src.set_span(span)

    def open_card(self, m):
        kind, item = view.selected(m, self.ui)
        if kind == "res":
            self.ui["overlay"] = {"kind": "res", "key": item["key"]}
        elif kind == "inc":
            self.ui["overlay"] = {"kind": "inc", "id": item["id"]}
        elif kind in ("a", "s"):
            self.ui["overlay"] = {"kind": kind, "id": item[0]}

    def key_overlay(self, k, ov, m, P):
        ui = self.ui
        boxed_help = self.size[0] >= 76 and self.size[1] >= 24
        if k in ("esc", "q"):
            ui.pop("overlay")
        elif k == "?":
            if ov["kind"] == "help" and boxed_help:
                ov["page"] = ov.get("page", 1) % view.help_count(m) + 1
            elif ov["kind"] == "help":
                ui.pop("overlay")
            else:
                ui["overlay"] = {"kind": "help", "page": 1, "off": 0}
        elif ov["kind"] == "help":
            if not boxed_help and k in NAV:
                n, rows = view.help_rows(self.size[0], self.size[1], view.GLYPHS[self.caps.glyphs], m)
                off = ov.get("off", 0)
                off = {"down": off + 1, "up": off - 1, "pgdn": off + rows - 1, "pgup": off - rows + 1, "home": 0,
                       "end": n}.get(k, off)
                ov["off"] = max(0, min(off, max(n - rows, 0)))
            elif boxed_help and k in ("left", "right", "tab"):
                n = view.help_count(m)
                ov["page"] = (ov.get("page", 1) - 1 + (-1 if k == "left" else 1)) % n + 1
        elif k in NAV:
            same = {"res": "res", "inc": "inc", "a": "panel", "s": "panel"}.get(ov["kind"])
            if ui.get("focus") == same:              # the card follows the selection of its list
                view.press(ui, k, m, P)
                kind, item = view.selected(m, ui)
                if kind == "res":
                    ov["key"] = item["key"]
                elif kind == "inc":
                    ov["id"] = item["id"]
                elif kind in ("a", "s"):
                    ov["id"] = item[0]
        elif ov["kind"] == "inc" and k in ("o", "y") and m.get("tab_mid", "local") == self.mid:
            inc = next((i for i in m["incidents"] if i["id"] == ov.get("id")), None)
            if inc:
                (self.report if k == "o" else self.copy)(inc)

    # ---- machines (04 §3.7, §3.8, §4.7)
    def remote_argv(self):
        """How `oomph remote …` is run: this program's own CLI (OOMPH_TOP_REMOTE, a JSON argument
        vector, puts a stand-in there for the tests)."""
        v = os.environ.get("OOMPH_TOP_REMOTE")
        if v:
            try:
                a = json.loads(v)
                if isinstance(a, list) and a and all(isinstance(x, str) for x in a):
                    return a
            except ValueError:
                pass
        return self.me + ["remote"]

    def in_text(self):
        """A text field has the keyboard: letters are letters (q too), until esc."""
        ov = self.ui.get("overlay")
        return bool(ov and ov.get("kind") in TEXT_DIALOGS and not ov.get("busy"))

    def tabs(self):
        return (self.model or {}).get("tabs") or []

    def wants_sync(self):
        """The child runs while another machine is a tab, or a command waits for it."""
        return bool(self.queued) or len(self.tabs()) > 1 or (self.M is not None and bool(self.M.tabs()))

    def command(self, c):
        """A command for the sync child (01 §5.8's pipe commands); queued while it is not running."""
        if self.sync is None:
            return False
        if not self.sync.send(c):
            self.queued.append(c)
        return True

    def machines_tick(self, nowm):
        """The sync child: its events wake the worker; it is started while wanted (again after a
        backoff when it ended) and told which machines to keep live, the selected one first."""
        sc = self.sync
        if self.pending_select and any(t["mid"] == self.pending_select for t in self.tabs()):
            self.select_mid(self.pending_select)
            self.pending_select = None
        elif self.model is not None and self.model.get("tabs") and self.mid != "local" and \
                not any(t["mid"] == self.mid for t in self.tabs()):
            self.select_mid("local")            # its tab went (disconnected or forgotten in the app)
        if self.add is not None:
            if self.add.pump() or self.add.done():
                self.add_progress()
        if sc is None:
            return
        for ev in sc.events():
            self.note("%s failed: %s" % (ev.get("cmd") or "that", view.fit(str(ev.get("detail") or ev.get("reason")), 60)),
                      "warntx", 8.0)
            if ev.get("cmd") == "forget" and self.M is not None:
                self.M.unhide(ev.get("id"))                 # still in machines.json: its tab again
                self.src.wake.set()
        if sc.p is not None and sc.reap(nowm):
            self.watching = None
        if not sc.running() and self.wants_sync() and nowm >= sc.next_at:
            if sc.start(nowm):
                self.watching = None
                if self.M is not None and sc.attempt:
                    self.M.reopen(self.now())
        if sc.running():
            mids = [t["mid"] for t in self.tabs() if not t.get("local")]
            want = (tuple(mids), self.mid if self.mid != "local" else None)
            if want != self.watching:
                if sc.send({"cmd": "watch", "ids": mids, "focus": want[1]}):
                    self.watching = want
            q, self.queued = self.queued, []
            for c in q:
                self.command(c)
        if self.undo and nowm >= self.undo[2]:
            self.undo = None

    def select_mid(self, mid):
        """Show another tab: its lists start unselected; the span is shared by all (04 §3.7)."""
        if mid == self.mid:
            return
        self.mid = mid
        self.src.select(mid)
        for k in ("focus", "res_sel", "inc_sel", "res_off", "inc_off", "panel", "panel_sel", "panel_off", "inspect",
                  "yhold"):
            self.ui.pop(k, None)
        self.dirty = True

    def sel_tab(self):
        tabs = self.tabs()
        i = next((i for i, t in enumerate(tabs) if t["mid"] == self.mid), 0)
        return i, (tabs[i] if tabs else None)

    def key_machines(self, k, m):
        """The keys of the tabs; True when one was used."""
        tabs = m.get("tabs") or []
        if not tabs:
            return False
        i, t = self.sel_tab()
        v = view.tab_views(m)[min(i, len(tabs) - 1)]
        remote = t is not None and not t.get("local")
        on = self.sync is not None
        if k in "123456789" and len(k) == 1:
            if int(k) <= len(tabs):
                self.select_mid(tabs[int(k) - 1]["mid"])
            return True
        if k == "0":
            self.ui["overlay"] = {"kind": "list", "filter": "", "sel": i}
            return True
        if k in ("tab", "n", "shift-tab", "p"):
            if len(tabs) > 1:
                self.select_mid(tabs[(i + (1 if k in ("tab", "n") else -1)) % len(tabs)]["mid"])
            return True
        if k == "+":
            if not on:
                self.note("--no-connect: nothing is added", "dim", 6.0)
            elif len(tabs) - 1 >= view.MAX_TABS:
                self.note("Twelve machines are connected. Disconnect one to add another.", "warntx", 8.0)
            else:
                self.ui["overlay"] = {"kind": "connect", "text": "", "sel": None}
            return True
        if not remote or k not in ("x", "X", "r", "R", "u", "enter"):
            if k == "u" and self.undo:
                return self.undo_unpin()
            return False
        if k == "u":
            return self.undo_unpin()
        if not on:
            self.note("not syncing (--no-connect)", "dim", 4.0)
            return k != "enter"
        if k == "x":
            self.command({"cmd": "unpin", "id": t["mid"]})
            self.undo = (t["mid"], t["label"], time.monotonic() + UNDO_S)
            self.note("%s disconnected %s u undo" % (view.fit(t["label"], 24), view.MIDDOT), "dim", UNDO_S)
            self.select_mid(tabs[i - 1]["mid"] if i > 0 else "local")
        elif k == "X":
            self.ui["overlay"] = {"kind": "forget", "mid": t["mid"], "label": t["label"], "connected": v["live"],
                                  "ssh": t.get("transport") == "ssh"}
        elif k == "r":
            if v["retry"]:
                self.command({"cmd": "retry", "id": t["mid"]})
                self.note("trying %s now" % view.fit(t["label"], 24), "dim")
            elif v["attention"]:
                self.note("r can't help: enter says why", "dim")
        elif k == "R":
            self.ui["overlay"] = {"kind": "rename", "mid": t["mid"], "name": t["label"], "text": t["label"], "fresh": True}
        elif k == "enter":
            if not v["attention"] or view.selected(m, self.ui)[0] is not None:
                return False
            self.ui["overlay"] = {"kind": "attention", "mid": t["mid"]}
        return True

    def undo_unpin(self):
        u = self.undo
        if not u or time.monotonic() >= u[2]:
            return False
        self.command({"cmd": "pin", "id": u[0]})
        self.pending_select, self.undo = u[0], None
        self.note("%s is a tab again" % view.fit(u[1], 24), "dim")
        return True

    def entry(self, mid):
        return next((e for e in (self.model or {}).get("book") or [] if e["mid"] == mid), None)

    def type_text(self, text):
        """Typed or pasted into the dialog's field."""
        ov = self.ui["overlay"]
        kind = ov["kind"]
        if kind == "pair":
            c = ov.get("code", "")
            for ch in text.upper().translate(str.maketrans("OIL", "011")):
                if ch in self.S.net.CODE_ALPHABET and len(c) < 12:
                    c += ch
            ov["code"], ov["error"] = c, None
            return
        key = "filter" if kind == "list" else "text"
        old = "" if ov.get("fresh") else ov.get(key, "")
        ov[key] = (old + "".join(ch for ch in text if ch >= " " and ch != "\x7f"))[:300]
        ov["fresh"], ov["error"] = False, None
        if kind == "connect":
            ov["sel"] = None
        if kind == "list":
            ov["sel"] = 0

    def key_machine_dialog(self, k, ov, m):
        """The keys of the machines' dialogs (04 §3.8). Every one leaves with esc; q quits nothing
        here (in a field it is a letter, elsewhere it closes like esc)."""
        kind = ov["kind"]
        ui = self.ui
        if ov.get("busy"):
            if k == "esc":
                if self.add is not None:
                    self.add.cancel()
                    self.add = None
                ov.pop("busy", None)
            return
        if k in ("backspace", "ctrl-u") and kind in TEXT_DIALOGS:
            if kind == "pair":
                ov["code"] = "" if k == "ctrl-u" else ov.get("code", "")[:-1]
            else:
                key = "filter" if kind == "list" else "text"
                ov[key] = "" if k == "ctrl-u" or ov.get("fresh") else ov.get(key, "")[:-1]
                ov["fresh"] = False
                if kind == "connect":
                    ov["sel"] = None
            ov["error"] = None
            return
        if kind == "connect":
            rows, start = view.connect_rows(ov.get("text", ""), m.get("book") or [])
            sel = ov.get("sel") if ov.get("sel") is not None else start
            if sel is not None and not 0 <= sel < len(rows):     # the Recents shrank meanwhile (the app forgot one)
                sel = ov["sel"] = None if not rows else len(rows) - 1
            if k == "esc":
                ui.pop("overlay")
            elif k in ("up", "down") and rows:
                ov["sel"] = max(0, min(len(rows) - 1, (sel if sel is not None else -1) + (1 if k == "down" else -1)))
            elif k == "tab" and sel is not None and rows[sel][0] == "known":
                ov["text"], ov["sel"], ov["fresh"] = rows[sel][2], None, False
            elif k == "ctrl-d" and sel is not None and rows[sel][0] == "known":
                e = rows[sel][1]
                ui["overlay"] = {"kind": "forget", "mid": e["mid"], "label": view.label_of(e), "connected": False,
                                 "ssh": e.get("transport") == "ssh", "back": dict(ov)}
            elif k == "enter" and sel is not None:
                row = rows[sel]
                if row[0] == "known":
                    self.use_known(row[1])
                else:
                    self.connect_typed(row[1], ov)
            return
        if kind == "pair":
            if k == "esc":
                ui["overlay"] = {"kind": "connect", "text": ov.get("target", ""), "sel": None}
            elif k == "ctrl-y":
                self.clip("sudo %s share pair" % oomph.CMD)
            elif k == "enter":
                if len(ov.get("code", "")) != 12:
                    ov["error"] = "A code has twelve characters, as `sudo oomph share pair` shows them there."
                else:
                    c = ov["code"]
                    self.run_add(ov["target"], "-".join((c[:4], c[4:8], c[8:])), ov.get("fp"))
            return
        if kind == "ssh":
            if k in ("esc", "q"):
                ui["overlay"] = {"kind": "connect", "text": ov.get("target", ""), "sel": None}
            elif k == "enter":
                self.run_add(ov["target"], None)
            return
        if kind == "ask":
            if k in ("up", "down"):
                ov["sel"] = 1 - ov.get("sel", 0) if k in ("up", "down") else ov.get("sel", 0)
            elif k == "enter" and self.add is not None:
                back = ov.get("back") or {"kind": "connect", "text": ""}
                self.add.answer("new" if ov.get("sel", 0) == 0 else "replace:" + ov["mid"])
                ui["overlay"] = dict(back, busy="Adding %s…" % view.fit(ov.get("label") or "it", 24), error=None)
                self.add.ask = None
            elif k in ("esc", "q"):
                if self.add is not None:
                    self.add.answer("")
                    back = ov.get("back") or {"kind": "connect", "text": ""}
                    ui["overlay"] = dict(back, busy="Giving the pairing back…", error=None)
                    self.add.ask = None
                else:
                    ui.pop("overlay")
            return
        if kind in ("name", "rename"):
            if k == "esc":
                ui.pop("overlay")
            elif k == "enter":
                label = ov.get("text", "").strip()
                if kind == "rename" or (label and label != ov.get("text0")):
                    self.command({"cmd": "rename", "id": ov["mid"], "label": label})
                ui.pop("overlay")
            return
        if kind == "forget":
            if k in ("esc", "q", "n"):
                if ov.get("back"):
                    ui["overlay"] = ov["back"]
                else:
                    ui.pop("overlay")
            elif k == "y":
                if not self.command({"cmd": "forget", "id": ov["mid"]}):
                    self.note("not syncing (--no-connect): nothing is forgotten", "dim", 6.0)
                    ui.pop("overlay")
                    return
                if self.M is not None:
                    self.M.hide(ov["mid"])
                    self.src.wake.set()
                if self.mid == ov["mid"]:
                    i, _ = self.sel_tab()
                    tabs = self.tabs()
                    self.select_mid(tabs[i - 1]["mid"] if i > 0 else "local")
                self.note("forgetting %s" % view.fit(ov.get("label") or "it", 24), "dim")
                ui.pop("overlay")
            return
        if kind == "attention":
            _, t = self.sel_tab()
            if k in ("esc", "q") or t is None or t["mid"] != ov.get("mid"):
                ui.pop("overlay")
                return
            keys = [x[0] for x in view.attention_keys(view.tab_views(m)[self.sel_tab()[0]]["cause"],
                                                      t.get("transport") == "ssh")]
            if k == "p" and "p" in keys:
                e = self.entry(t["mid"])
                target = self.S.show_target(e) if e else t.get("addr")
                ui["overlay"] = {"kind": "pair", "target": target, "code": "", "fp": None, "fp_short": ""}
                self.run_add(target, None)
            elif k == "r" and "r" in keys:
                self.command({"cmd": "retry", "id": t["mid"]})
                self.note("trying %s now" % view.fit(t["label"], 24), "dim")
                ui.pop("overlay")
            elif k == "X":
                ui["overlay"] = {"kind": "forget", "mid": t["mid"], "label": t["label"], "connected": False,
                                 "ssh": t.get("transport") == "ssh"}
            return
        if kind == "list":
            rows = view.list_rows_machines(m, ov.get("filter", ""))
            if k == "esc":
                ui.pop("overlay")
            elif k in NAV and rows:
                n = len(rows)
                ov["sel"] = max(0, min(n - 1, ov.get("sel", 0) + {"up": -1, "down": 1, "pgup": -10, "pgdn": 10,
                                                                   "home": -n, "end": n}[k]))
            elif k == "enter" and rows:
                self.select_mid(rows[max(0, min(ov.get("sel", 0), len(rows) - 1))][1]["mid"])
                ui.pop("overlay")

    def use_known(self, e):
        """A remembered machine always becomes a tab, reachable or not (01 §3.7); a tab is just shown."""
        self.ui.pop("overlay", None)
        if e.get("pinned"):
            self.select_mid(e["mid"])
            return
        if len(self.tabs()) - 1 >= view.MAX_TABS:
            self.note("Twelve machines are connected. Disconnect one to add another.", "warntx", 8.0)
            return
        self.command({"cmd": "pin", "id": e["mid"]})
        self.pending_select = e["mid"]

    def connect_typed(self, text, ov):
        """enter on "as typed": a link fills the code step (nothing is sent until enter there); an ssh
        address asks for consent first; anything else is tried, and a new machine asks for its code."""
        S = self.S
        try:
            if text.startswith("oomph://"):
                target, code = S.parse_link(text)
                self.ui["overlay"] = {"kind": "pair", "target": target, "code": code, "fp": None, "fp_short": ""}
                return
            t = S.parse_target(text)
        except ValueError:
            ov["error"] = view.connect_message("bad_address", text)
            return
        if t["transport"] == "ssh" or text.startswith("ssh://"):
            self.ui["overlay"] = {"kind": "ssh", "target": text}
        else:
            self.run_add(text, None)

    def run_add(self, target, code, fp=None):
        """`oomph remote add`, the dialog showing that it works (esc lets it go)."""
        ov = self.ui.get("overlay") or {"kind": "connect", "text": target}
        argv = self.remote_argv() + ["add", target, "--json", "--no-mirror", "--ask"]
        if code is not None:
            argv += ["--code", "-"] + (["--fp", fp] if fp else [])
        if self.add is not None:
            self.add.cancel()
        try:
            self.add = AddRun(argv, code)
        except OSError:
            ov["error"] = "can't start the %s command" % oomph.CMD
            return
        self.add_from = dict(ov, busy=None, error=None)
        ov["busy"] = "Connecting to %s…" % view.fit(target.rpartition("@")[2], 40)
        ov["error"] = None
        self.ui["overlay"] = ov

    def add_progress(self):
        """What `remote add` said: the identity question, then its answer (01 §3.7's errors stay in
        the dialog; a new machine asks for the tab's name)."""
        a = self.add
        if a.ask is not None and (self.ui.get("overlay") or {}).get("kind") != "ask":
            k = a.ask.get("known") if isinstance(a.ask.get("known"), dict) else {}
            if isinstance(k.get("mid"), str) and self.S.MID.fullmatch(k["mid"]):
                self.ui["overlay"] = {"kind": "ask", "mid": k["mid"], "label": view.fit(str(k.get("label") or k["mid"]), 32),
                                      "sel": 0, "back": dict(self.add_from)}
            else:
                a.answer("")
                a.ask = None
            self.dirty = True
            return
        if not a.done():
            return
        self.add = None
        o = a.result or {}
        back = dict(self.add_from or {"kind": "connect", "text": ""})
        self.dirty = True
        if o.get("ok") is True and isinstance(o.get("machine"), dict) and self.S.MID.fullmatch(str(o["machine"].get("mid"))):
            mm = o["machine"]
            self.pending_select = mm["mid"]
            if o.get("new") is True:
                name = mm.get("name") if isinstance(mm.get("name"), str) else back.get("target") or "?"
                short = view.fit(name.split(".")[0] if not self.S._is_ip(name) else name, 32)
                about = (" %s " % view.MIDDOT).join(x for x in (
                    mm.get("os_version") if isinstance(mm.get("os_version"), str) else None,
                    "%.0f GB" % mm["ram_gb"] if _num(mm.get("ram_gb"), None) else None,
                    "%s %s" % (oomph.CMD, mm["version"]) if isinstance(mm.get("version"), str) else None) if x)
                self.ui["overlay"] = {"kind": "name", "mid": mm["mid"], "name": view.fit(name, 32), "text": short,
                                      "text0": short, "fresh": True, "about": view.fit(about, 60)}
            else:
                self.ui.pop("overlay", None)
            return
        code, detail = str(o.get("error") or ""), str(o.get("detail") or "")
        target = back.get("target") or back.get("text") or ""
        if code in ("needs_code", "revoked"):
            self.ui["overlay"] = {"kind": "pair", "target": target, "code": back.get("code", "") if back.get("kind") == "pair" else "",
                                  "fp": o.get("fp") if isinstance(o.get("fp"), str) else None,
                                  "fp_short": view.fit(str(o.get("fp_short") or ""), 24),
                                  "revoked": code == "revoked" or o.get("revoked") is True}
            return
        if code == "identity_changed" and back.get("kind") == "pair" and isinstance(o.get("fp"), str):
            back.update(fp=o["fp"], fp_short=view.fit(str(o.get("fp_short") or ""), 24))
        back["error"] = view.connect_message(code, target, view.fit(detail, 200), o.get("side")) if (code or detail) \
            else "%s remote add ended without an answer" % oomph.CMD
        self.ui["overlay"] = back

    def clip(self, text):
        tool = _clip_tool() if not self.readonly and not os.environ.get("SSH_CONNECTION") else None
        if not (tool and self.spawn(tool, "copy", text)):
            self.osc52(text)

    # ---- o and y: the report, the clipboard
    def local_desktop(self):
        return not self.readonly and not os.environ.get("SSH_CONNECTION") and (
            sys.platform == "darwin" or bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")))

    def spawn(self, argv, kind="open", data=None):
        """A child that never sees the terminal: its own session, /dev/null or a pipe for its streams.
        Only a clipboard tool (`copy`) has a deadline (3 s, then OSC 52 instead); a report writer
        (`report`: 14 days take seconds and hundreds of MB) and an opener run to their end, even
        after the dashboard has left (leave_children)."""
        try:
            p = subprocess.Popen(argv, stdin=subprocess.PIPE if kind == "copy" else subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                                 close_fds=True)
        except OSError:
            return False
        if kind == "copy":              # (`data`: the text; for a report, what to call it in a note)
            try:
                p.stdin.write(data.encode("utf-8"))
                p.stdin.close()
            except OSError:
                pass
        self.children.append((p, kind, data, time.monotonic() + 3.0 if kind == "copy" else None))
        return True

    def reap(self, nowm):
        keep = []
        for p, kind, data, deadline in self.children:
            rc = p.poll()
            if rc is None and (deadline is None or nowm < deadline):
                keep.append((p, kind, data, deadline))
                continue
            if rc is None:
                try:
                    p.kill()
                    p.wait(1)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if kind == "copy":
                if rc == 0:
                    self.note("copied")
                else:
                    self.osc52(data)
            elif rc:
                self.note("report failed (%s: exit %d)" % (data, rc) if data else "couldn't open the report (exit %d)" % rc,
                          "warntx", 8.0)
        self.children = keep

    def leave_children(self):
        """On the way out: a clipboard tool is stopped; a report writer and an opener are left to
        finish (their own session, no terminal); the init process reaps them."""
        for p, kind, _, _ in self.children:
            if kind == "copy":
                try:
                    p.kill()
                except OSError:
                    pass
        self.children = []

    def osc52(self, text):
        self.pending += "\x1b]52;c;%s\x07" % base64.b64encode(text.encode("utf-8")).decode("ascii")
        self.note("sent to the terminal's clipboard, if it allows it")

    def copy(self, inc):
        """y: the path of the incident's report (of its folder while it is open)."""
        text = inc.get("report") or inc.get("dir")
        if not text:
            return
        tool = _clip_tool() if not self.readonly and not os.environ.get("SSH_CONNECTION") else None
        if not (tool and self.spawn(tool, "copy", text)):
            self.osc52(text)

    def report(self, inc):
        """o: the incident's report, or with nothing selected the report for the span on screen; where
        no browser can open (over SSH, as root) the dashboard says where it is instead."""
        me = self.me
        if getattr(self, "mid", "local") != "local":        # another machine's reports are written there
            self.note("a report of %s: %s incident%s --html there" % (
                view.fit(self.model.get("host") or "?", 16), oomph.CMD, " " + inc["id"] if inc else ""), "dim", 8.0)
            return
        local = self.local_desktop()
        if local and any(k == "report" for _, k, _, _ in self.children):
            self.note("a report is still being written…")
            return
        opener = "/usr/bin/open" if sys.platform == "darwin" else "xdg-open"
        if inc:
            if inc.get("report") and local:
                self.spawn([opener, inc["report"]])
                self.note("opening the report of %s" % inc["id"])
            elif local and sys.platform == "darwin":
                if self.spawn(me + ["incident", inc["id"], "--html"], "report", "%s incident" % oomph.CMD):
                    self.note("writing the report of %s…" % inc["id"])
            elif inc.get("report"):
                self.note("the report: %s (y copies the path)" % inc["report"], "dim", 8.0)
            else:
                self.note("no report yet: %s incident %s --html writes one" % (oomph.CMD, inc["id"]), "dim", 8.0)
            return
        last = REPORT_LAST[self.ui["span"]]
        if local and sys.platform == "darwin":
            if self.spawn(me + ["html", "--last", last, "--open"], "report", "%s html" % oomph.CMD):
                self.note("writing the report of the last %s…" % SPAN_WORDS[self.ui["span"]])
        else:
            self.note("for a report: %s html --last %s -o report.html" % (oomph.CMD, last), "dim", 8.0)


# ------------------------------------------------------------------ --ssh: run it there, and stay
SSH_TARGET = re.compile(r"[A-Za-z0-9._:\[\]@%-]{1,255}")
NOT_INSTALLED = {121: "Darwin", 122: "Linux", 123: None}
TOO_OLD = 124               # the far side's oomph is older than the first full-screen one
NEEDS = (1, 9)


def ssh_command(target, port, remote_args):
    """The argument vector of `oomph top --ssh` (04 §5.2, with fixed options that keep the user's
    multiplexing, agent, forwardings and a RemoteCommand of ~/.ssh/config out of it and notice a
    dead link within about 15 s). The far side looks for oomph on its PATH, then where install.sh
    puts it, and otherwise exits with a code that says which system it is; an oomph whose `top`
    has no --ssh in its help is older than the full-screen one: exit TOO_OLD (no output: this
    terminal belongs to ssh until it exits). The remote words are this program's own
    enumerations: nothing to quote inside the single quotes."""
    a, c = " ".join(remote_args), oomph.CMD
    remote = ("exec /bin/sh -c 'if command -v %s >/dev/null 2>&1; then o=%s; "
              "elif [ -x /usr/local/bin/%s ]; then o=/usr/local/bin/%s; "
              "elif [ -x \"$HOME/.local/bin/%s\" ]; then o=\"$HOME/.local/bin/%s\"; "
              "else case $(uname -s) in Darwin) exit 121;; Linux) exit 122;; esac; exit 123; fi; "
              "case $(\"$o\" top --help 2>/dev/null) in *--ssh*) exec \"$o\" top %s;; esac; exit %d'"
              % (c, c, c, c, c, c, a, TOO_OLD))
    return (["ssh", "-t", "-o", "RequestTTY=force", "-o", "RemoteCommand=none", "-o", "ClearAllForwardings=yes",
             "-o", "ForwardAgent=no", "-o", "ControlMaster=no", "-o", "ControlPath=none",
             "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2"] + (["-p", str(port)] if port else []) +
            ["--", target, remote])


def ssh_target_ok(target):
    if not SSH_TARGET.fullmatch(target or ""):
        return False
    user, _, host = target.rpartition("@")
    return bool(host) and not host.startswith("-") and not user.startswith("-")


def not_installed_text(target, rc):
    host = target.rpartition("@")[2]
    if rc == TOO_OLD:
        return ("%s on %s is older than %d.%d.0, the first with this dashboard.\n"
                "Update it there: Upgrade in the app, or git pull and ./build-app.sh in its clone."
                % (oomph.CMD, host, NEEDS[0], NEEDS[1]))
    system = NOT_INSTALLED[rc]
    head = "%s is not installed on %s." % (oomph.CMD, host)
    repo = "https://github.com/kleinzeug/oomph.git"
    if system == "Darwin":
        return head + ("\nInstall it there: git clone %s && cd %s && ./build-app.sh, then Activate in the app "
                       "(or sudo ./install.sh)." % (repo, oomph.CMD))
    if system == "Linux":
        return head + ("\nInstall it there: git clone %s && %s/linux/install.sh (no root; it puts %s in "
                       "~/.local/bin)." % (repo, oomph.CMD, oomph.CMD))
    return head + "\n%s does not run on that system yet." % oomph.BRAND


def run_ssh(target, port, remote_args, fd=0, out=None):
    """Runs `ssh -t` with this terminal and stays (04's review, major): it watches the link (ssh's
    keep-alive ends a dead one within about 15 s), puts this terminal back when ssh exits (a far side
    that died cannot), follows ssh into the background and out again, and passes SIGTERM and SIGHUP
    on. The far side leaves when its terminal hangs up (it unwinds even a blocked write)."""
    import termios
    out = out or sys.stdout
    try:
        saved = termios.tcgetattr(fd)
    except termios.error:
        saved = None
    got = []

    def on_signal(signum, frame):
        got.append(signum)
        try:
            p.send_signal(signum)
        except OSError:
            pass
    try:
        p = subprocess.Popen(ssh_command(target, port, remote_args))
    except OSError as e:
        sys.stderr.write("%s top --ssh: can't run ssh: %s\n" % (oomph.CMD, e.strerror or e))
        return 2
    old = {s: signal.signal(s, h) for s, h in ((signal.SIGINT, signal.SIG_IGN), (signal.SIGQUIT, signal.SIG_IGN),
                                                (signal.SIGTERM, on_signal), (signal.SIGHUP, on_signal))}
    rc = 255
    try:
        while True:
            try:
                pid, status = os.waitpid(p.pid, os.WUNTRACED)
            except InterruptedError:
                continue
            except ChildProcessError:
                break
            if os.WIFSTOPPED(status):           # ssh's ~^Z: go into the background with it
                os.kill(os.getpid(), signal.SIGSTOP)
                p.send_signal(signal.SIGCONT)
                continue
            rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
            break
    finally:
        for s, h in old.items():
            signal.signal(s, h)
        if saved is not None:
            try:
                termios.tcsetattr(fd, termios.TCSANOW, saved)
            except termios.error:
                pass
    if (rc not in (0, 1, 2, TOO_OLD) and rc not in NOT_INSTALLED) or got:
        # the far side could not put the screen back (the link died under it): we do. ?1047l leaves the
        # alternate screen without restoring a cursor that, after a connection that never came up, nobody saved
        try:
            os.write(fd if os.isatty(fd) else 1, SSH_LEAVE.encode())
        except OSError:
            pass
    if rc in NOT_INSTALLED or rc == TOO_OLD:
        sys.stderr.write(not_installed_text(target, rc) + "\n")
        return 127
    if rc == 255 and not got:
        sys.stderr.write("%s top --ssh: the connection to %s ended (ssh exit 255)\n" % (oomph.CMD, target))
    return rc


def probe_quick(fd, wait=0.15):
    """Before handing the terminal to ssh: the background colour and 24-bit colour, asked and
    answered within `wait` (nothing is drawn: no glyph probe here). {theme?, color?}."""
    import termios
    import tty
    found = {}
    try:
        saved = termios.tcgetattr(fd)
    except termios.error:
        return found

    def emit(ev):
        if ev[0] != "reply":
            return
        kind, data = ev[1], ev[2]
        if kind == "osc" and data.startswith("11;"):
            mm = re.search(r"rgb:([0-9a-fA-F]{1,4})/([0-9a-fA-F]{1,4})/([0-9a-fA-F]{1,4})", data)
            if mm:
                r, g, b = (int(x, 16) / float(16 ** len(x) - 1) for x in mm.groups())
                found["theme"] = "light" if 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.5 else "dark"
        elif kind == "dcs" and re.search(r"(^|[;:])2[;:]+1[;:]2[;:]3m", data):
            found["color"] = "truecolor"
        elif kind == "da":
            found["done"] = True
    dec = Decoder(emit)
    try:
        tty.setraw(fd, termios.TCSANOW)
        os.write(fd, PROBE_REST.encode())
        t0, heard = time.monotonic(), False
        while "done" not in found:
            # the answers within `wait`; a terminal that has begun to answer gets up to 0.5 s more for
            # the DA reply, which comes last: a late answer must not reach ssh's terminal while it echoes
            left = t0 + wait + (0.5 if heard else 0.0) - time.monotonic()
            if left <= 0:
                break
            r, _, _ = select.select([fd], [], [], left)
            if fd in r:
                data = os.read(fd, 4096)
                if not data:
                    break
                heard = True
                dec.feed(data, time.monotonic())
    except OSError:
        pass
    finally:
        try:
            termios.tcflush(fd, termios.TCIFLUSH)       # whatever arrived late, or half
        except termios.error:
            pass
        termios.tcsetattr(fd, termios.TCSANOW, saved)
    found.pop("done", None)
    return found


def cmd_top(args, out=None, env=None):
    """oomph top …: the full-screen dashboard; --once: one frame of it on stdout; --ssh: on another
    machine."""
    out = out or sys.stdout
    env = os.environ if env is None else env
    opts, ignored = {}, []
    takes = ("--span", "--size", "--color", "--theme", "--glyphs", "--format", "--now", "--ssh", "--ssh-port", "--machine")
    i = 0
    while i < len(args):
        a = args[i]
        name, eq, val = a.partition("=")
        if name in takes:
            if not eq:
                if i + 1 >= len(args):
                    print(USAGE, file=sys.stderr)
                    return 2
                val, i = args[i + 1], i + 1
            opts[name] = val
        elif a in ("--once", "--no-probe", "--no-connect", "--bell", "--no-bell", "--from-ssh", "--mouse", "--no-mouse"):
            opts[a] = True
        elif a == "--ascii":
            opts["--glyphs"] = "ascii"
        elif a in ("-h", "--help"):
            print(USAGE, file=out)
            return 0
        else:
            ignored.append(a)       # options of a newer oomph top are ignored, and named (04 §5.2)
        i += 1
    once = "--once" in opts
    if once and "--ssh" in opts:
        sys.stderr.write("oomph top: --once draws this machine; on another: ssh HOST oomph top --once\n")
        return 2
    sdir = None if once else state_dir()
    readonly = None if once else readonly_reason(sdir)
    cfg = config_path(sdir) if not once else None
    settings = load_settings(cfg) if cfg else {}
    span = opts.get("--span") or (settings.get("span") if settings.get("span") in view.SPANS else None) or "24h"
    if span in ("∞", "all"):
        span = "inf"
    if span not in view.SPANS:
        print("oomph top: --span takes inf, 24h, 6h or 1h", file=sys.stderr)
        return 2
    for o, allowed in CHOICES.items():
        if opts.get(o, "auto") not in allowed:
            print("oomph top: %s takes %s" % (o, ", ".join(allowed)), file=sys.stderr)
            return 2
    tty = out.isatty() if hasattr(out, "isatty") else False
    if "--size" in opts:
        try:
            w, h = (int(x) for x in opts["--size"].lower().split("x"))
            assert 1 <= w <= 1000 and 1 <= h <= 1000
        except (ValueError, AssertionError):
            print("oomph top: --size takes COLSxROWS, e.g. 80x24", file=sys.stderr)
            return 2
    else:
        w, h = 80, 24
        if tty:
            try:
                w, h = (a or b for a, b in zip(os.get_terminal_size(out.fileno()), (w, h)))  # a pty may say 0 x 0
            except (OSError, ValueError):
                pass
    now = None
    if "--now" in opts:
        try:
            now = float(opts["--now"])
            if not 0 <= now <= 1e11:                    # also NaN: time.localtime refuses these
                raise ValueError
        except ValueError:
            print("oomph top: --now takes a unix time", file=sys.stderr)
            return 2

    def chosen(o, key):         # the option (`auto` too), else what top.json remembers, else detection
        v = opts.get(o)
        if v is None and not once and settings.get(key) in CHOICES[o]:
            v = settings[key]
        return v or "auto"
    color, theme, glyphs = chosen("--color", "color"), chosen("--theme", "theme"), chosen("--glyphs", "glyphs")
    if once:
        caps = view.Caps(detect_color(color, tty, env), detect_glyphs(glyphs, env), detect_theme(theme, env))
        fmt = opts.get("--format") or ("ansi" if caps.color != "none" else "text")
        if fmt not in ("text", "ansi", "golden"):
            print("oomph top: --format takes text, ansi or golden", file=sys.stderr)
            return 2
        if "--machine" in opts:
            model = once_machine(opts["--machine"], span, now)
            if isinstance(model, str):
                sys.stderr.write("oomph top: %s\n" % model)
                return 2
        else:
            model = load_model(span, now)
        if ignored:
            model.update(status="ignored: %s" % " ".join(ignored)[:60], status_role="warntx")
        fr = view.render(model, w, h, caps, {"span": span})
        if fmt == "golden":
            text = fr.golden("oomph top golden frame v2 · %dx%d · glyphs=%s theme=%s color=%s"
                             % (w, h, caps.glyphs, caps.theme, caps.color))
        elif fmt == "ansi":
            text = fr.ansi(caps)
        else:
            text = fr.text()
        out.write(text)
        out.flush()
        return 0
    term_name = env.get("TERM", "")
    if term_name in ("", "dumb") or not (sys.stdin.isatty() and tty):
        sys.stderr.write("oomph top: %s; `oomph top --once` prints one frame, `oomph status` the readings\n"
                         % ("this terminal cannot draw a dashboard (TERM=%s)" % (term_name or "unset")
                            if term_name in ("", "dumb") else "the dashboard needs a terminal"))
        return 2
    bell = settings.get("bell") is True
    if "--bell" in opts or "--no-bell" in opts:
        bell = "--bell" in opts
    mouse = settings.get("mouse") is True and "--from-ssh" not in opts    # (over --ssh: the near side's choice)
    if "--mouse" in opts or "--no-mouse" in opts:
        mouse = "--mouse" in opts

    def remember(**more):
        """top.json (04 §5.1): where this run left off, --bell, and a --color, --theme or --glyphs given
        by hand (`auto` forgets it), --mouse or --no-mouse (and ctrl-o's last word, in `more`). Choices that --ssh passed from the other side (the bell too) are
        not hand-given: the far side keeps its own."""
        if not cfg or readonly:
            return
        want = dict(settings, v=1, **more)
        if "--from-ssh" not in opts:
            want["bell"] = bell
            if ("--mouse" in opts or "--no-mouse" in opts) and "mouse" not in more:
                want["mouse"] = mouse
            for o in ("--color", "--theme", "--glyphs"):
                if o in opts:
                    if opts[o] == "auto":
                        want.pop(o[2:], None)
                    else:
                        want[o[2:]] = opts[o]
        if want != settings:
            try:
                save_settings(cfg, want)
            except OSError:
                pass
    if "--ssh" in opts:
        target = opts["--ssh"]
        if os.geteuid() == 0:
            sys.stderr.write("oomph top --ssh: run it without sudo\n")
            return 2
        port = opts.get("--ssh-port")
        if not ssh_target_ok(target) or (port is not None and not re.fullmatch(r"[0-9]{1,5}", port)):
            sys.stderr.write("oomph top --ssh: give a host, user@host or an address (and --ssh-port N)\n")
            return 2
        found = {} if "--no-probe" in opts else probe_quick(sys.stdin.fileno(),
                                                             0.5 if env.get("SSH_CONNECTION") else 0.15)
        remote = ["--span", span,
                  "--color", detect_color(color if color != "auto" else found.get("color", "auto"), True, env),
                  "--theme", detect_theme(theme if theme != "auto" else found.get("theme", "auto"), env),
                  "--glyphs", detect_glyphs(glyphs, env), "--no-probe", "--from-ssh", "--bell" if bell else "--no-bell"]
        if mouse:                                    # (a far side older than 1.9.5 names it as ignored)
            remote.append("--mouse")
        remember()
        return run_ssh(target, port, [x if x != "none" else "never" for x in remote], sys.stdin.fileno())
    probe = "--no-probe" not in opts and term_name not in ("linux", "vt100", "vt220", "ansi")
    caps = view.Caps(detect_color(color, True, env), detect_glyphs(glyphs, env), detect_theme(theme, env))
    auto = {"color": color == "auto", "theme": theme == "auto", "glyphs": glyphs == "auto"}
    machines, start, kept, note = None, "local", False, "ignored: %s" % " ".join(ignored)[:60] if ignored else None
    why = no_tabs_reason(readonly)
    S = sync_module() if why is None else None
    if S is not None:
        machines = Machines(S.machines_dir(), S)
        machines.refresh(now if now is not None else time.time())
        start, kept = start_tab(machines, settings.get("machine"), opts.get("--machine"))
        if start is None:
            start, note = "local", "no machine named %s: oomph remote list" % view.fit(opts["--machine"], 32)
    elif "--machine" in opts:
        note = "--machine: no other machines in this run (%s)" % (why or "oomph remote is not installed")
    app = App(Term(sys.stdin.fileno(), out.fileno()), caps, auto, span, oomph.LOG_DIR, readonly, bell, now, probe,
              note=note, mouse=mouse, machines=machines, start_mid=start,
              no_connect="--no-connect" in opts or "--from-ssh" in opts)   # over --ssh: that account's mirrors, no dialling
    rc = app.run()
    more = {} if "--from-ssh" in opts else {"mouse": app.mouse}
    if machines is not None and "--machine" not in opts and not (kept and app.mid == "local"):
        more["machine"] = app.mid               # (a start on this machine for what it had to say keeps the tab)
    remember(span=app.ui["span"], **more)
    return rc


def no_tabs_reason(readonly):
    """Why this run has no machine tabs, or None: they need the state folder writable and not root
    (04 §4.10), and on Linux they come with T3 (roadmap §3.1, 1.13.2: the engine's files there)."""
    if readonly:
        return "read-only"
    if os.geteuid() == 0:
        return "running as root"
    if sys.platform != "darwin" and not os.environ.get("OOMPH_TOP_TABS"):
        return "not on Linux yet"
    return None


def start_tab(M, remembered, asked):
    """Which tab a run starts on (01 §3.3 rule 4, 04 §3.7), and whether the remembered one was passed
    over: the one named by --machine (None when no machine has that name); else the tab of the last
    run, unless this machine has something to say (D9, as the app's localHasSay): its pressure is
    critical, an incident is open, or its logger is installed but not reporting. Warning is not
    enough. That does not change the remembered tab."""
    tabs = M.tabs()
    if asked is not None:
        if asked in ("local", "this", host_name()):
            return "local", False
        e = next((e for keys in (("mid", "id"), ("label",), ("name",), ("host",)) for e in tabs
                  if any(e.get(k) == asked for k in keys)), None)
        return (e["mid"] if e else None), False
    if not (isinstance(remembered, str) and any(e["mid"] == remembered for e in tabs)):
        return "local", False
    c = _current(oomph.LOG_DIR)
    if c is not None:
        cs = cur_summary(c, time.time())
        if cs["pressure"] == "Critical" or cs["incident"] or cs["silent"]:
            return "local", True
    return remembered, False


def once_machine(asked, span, now=None):
    """--once --machine NAME: that tab's frame, read as the dashboard's worker reads it (its mirror,
    never measured here); this machine's own frame for its own name. A string says why not."""
    why = no_tabs_reason(None)
    S = sync_module() if why is None else None
    if S is None:
        return "--machine: no other machines here (%s)" % (why or "oomph remote is not installed")
    wall = float(now) if now is not None else time.time()
    M = Machines(S.machines_dir(), S)
    M.refresh(wall - 30)
    mid, _ = start_tab(M, None, asked)
    if mid is None:
        return "no machine named %s: oomph remote list" % view.fit(asked, 32)
    if mid == "local":
        return load_model(span, now)
    got = []
    src = Source(oomph.LOG_DIR, got.append, clock=lambda: wall, machines=M)
    src.span, src.mid = span, mid
    src.step()
    return at(got[-1], wall)
