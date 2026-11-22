"""`oomph top`: the dashboard in a terminal (roadmap 04-tui). This release has its first form,
`oomph top --once`, which prints one frame of this Mac's dashboard and exits; until the full-screen
program exists, `oomph top` without --once does the same.

This half reads (the logger's files, the ledger through oomph.py's bounded readers) and talks to
the terminal; everything it draws comes from the pure oomph_view.render. It writes nothing.
"""
import gzip
import json
import math
import os
import platform
import re
import socket
import sys
import time
import zlib

import oomph
import oomph_view as view

DAY_CAP = 128 << 20         # bytes of one day's samples, inflated (a day at a 5 s interval is about 60 MB)
CURRENT_CAP = 256 << 10
INCIDENT_CAP = 256 << 10
EVENTS_CAP = 1 << 20        # the newest MB of events.jsonl is plenty for one frame
INCIDENTS_SHOWN = 30
INCIDENT_ID = re.compile(r"\d{8}-\d{6}$")
CELLS_TERMINALS = ()        # TERM_PROGRAM values that seam at their default profile (04 §8): none so far
USAGE = ("usage: oomph top [--once] [--span inf|24h|6h|1h] [--size COLSxROWS] [--color auto|truecolor|256|16|never]\n"
         "                 [--theme auto|dark|light] [--glyphs auto|unicode|cells|ascii] [--format text|ansi|golden]\n"
         "                 [--now UNIXTIME]")


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
    a = s.get("away") if isinstance(s.get("away"), dict) else {}
    ram, app, wired, comp = (_num(s.get(k)) for k in ("ram_gb", "app_gb", "wired_gb", "compressed_gb"))
    return dict(app=app, comp=comp, wired=wired, swap=_num(s.get("swap_used_gb")), swap_total=_num(s.get("swap_total_gb")),
                ram=ram, disk=_num(s.get("disk_free_gb")), idle=int(_num(a.get("idle_s"), 0)),
                display_on=a.get("display_on") if isinstance(a.get("display_on"), bool) else None,
                pressure=pressure, free=max(0.0, ram - app - wired - comp),
                unowned=s.get("unowned_gb") if isinstance(s.get("unowned_gb"), (int, float)) else None,
                procs=None, groups=groups, claude=claude)


def load_incidents(log_dir, now):
    """The newest incidents (an open one first) and how many started in the last 90 days."""
    d = os.path.join(log_dir, "incidents")
    try:
        ids = sorted((n for n in os.listdir(d) if not n.startswith(".")), reverse=True)
    except OSError:
        return [], 0
    out, n90 = [], 0
    for iid in ids[:INCIDENTS_SHOWN]:
        inc = oomph.loads_untrusted(_read(os.path.join(d, iid, "incident.json"), INCIDENT_CAP))
        if not isinstance(inc, dict) or not isinstance(inc.get("start"), (int, float)):
            continue
        reasons = [r for r in inc.get("reasons") or [] if isinstance(r, dict)]
        summ = inc.get("summary") if isinstance(inc.get("summary"), dict) else {}
        out.append(dict(id=str(inc.get("id") or iid), start=float(inc["start"]), end=inc.get("end") if
                        isinstance(inc.get("end"), (int, float)) else None, open=inc.get("open") is True,
                        kills=int(_num(summ.get("jetsam_kills"), 0)),
                        desc=str(reasons[0].get("desc") or "") if reasons else ""))
        if inc["start"] >= now - 90 * 86400:
            n90 += 1
    try:                        # the rest are counted by name: the logger names them by local start time
        cut = time.strftime("%Y%m%d-%H%M%S", time.localtime(now - 90 * 86400))
    except (OverflowError, ValueError, OSError):
        cut = None
    n90 += sum(1 for iid in ids[INCIDENTS_SHOWN:] if cut and INCIDENT_ID.match(iid) and iid >= cut)
    out.sort(key=lambda i: (not i["open"], -i["start"]))
    return out, n90


PRESSURE_WORD = {1: "normal", 2: "warning", 4: "critical"}
ALARMING = ("jetsam", "stall", "unowned_memory", "disk_low", "pressure_flapping", "daemon_error")


def event_text(e):
    """ChartEvent's words for a line of events.jsonl (None: not shown)."""
    k = e.get("kind")

    def num(key):
        return _num(e.get(key))
    if k == "pressure_change":
        return "pressure %s → %s" % (PRESSURE_WORD.get(e.get("old"), e.get("old")), PRESSURE_WORD.get(e.get("new"), e.get("new")))
    if k == "pressure_flapping":
        return "pressure flapping, %d flips" % num("flips")
    if k == "jetsam":
        return "%d killed by jetsam" % num("kills") if num("kills") > 0 else "jetsam report"
    if k == "sleep_gap":
        return "asleep " + view.ago(num("seconds"))
    if k == "stall":
        return "system stalled " + view.ago(num("seconds"))
    if k == "unowned_memory":
        return "%.0f GB unowned memory (leak?)" % num("gb")
    if k == "unowned_memory_cleared":
        return "unowned memory cleared"
    if k == "disk_low":
        return "disk low: %.1f GB free" % num("disk_free_gb")
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


def load_events(log_dir, n=40):
    """The newest events in words, newest first."""
    out = []
    for name in ("events.jsonl.1", "events.jsonl"):
        for line in (_read(os.path.join(log_dir, name), EVENTS_CAP, tail=True) or "").splitlines():
            try:
                e = _loads(line)
            except ValueError:
                continue
            if isinstance(e, dict) and _num(e.get("t"), None) is not None:
                text = event_text(e)
                if text:
                    out.append((float(e["t"]), text, e.get("kind") in ALARMING))
    out.sort(key=lambda e: -e[0])
    return out[:n]


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def load_reservations(now):
    """The reservations of the last 14 days and the live ones, merged as the app merges them. Read
    through oomph.ledger_view: bounded, never as root (a root caller reads in a child)."""
    try:
        v = oomph.ledger_view(since=now - view.KEEP_DAYS * 86400)   # the frame's clock, not the wall's
    except oomph.LedgerError as e:
        return [], "can't read the ledger: %s" % e
    return view.merge_reservations(v.get("records") or [], v.get("ledger") or {}, now, _alive), None


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
    res, note = load_reservations(now)
    incidents, n90 = load_incidents(log_dir, now)
    model = dict(now=now, brand=oomph.BRAND, host=host_name(), os=os_name(), ram=cur["ram"] if cur else None,
                 pts=view.multires(pts, now), first=first, gaps=gaps, res=res, blocks=view.stack_reservations(res, now),
                 incidents=incidents, incidents_90d=n90, cur=cur, events=load_events(log_dir),
                 logger=logger, logger_t=logger_t, interval=interval)
    if note:
        model.update(status=note, status_role="warntx")
    return model


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


def cmd_top(args, out=None, env=None):
    """oomph top [--once] …: one frame of this Mac's dashboard on stdout."""
    out = out or sys.stdout
    env = os.environ if env is None else env
    opts, ignored = {}, []
    takes = ("--span", "--size", "--color", "--theme", "--glyphs", "--format", "--now")
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
        elif a in ("--once", "--no-probe", "--no-connect"):
            opts[a] = True
        elif a == "--ascii":
            opts["--glyphs"] = "ascii"
        elif a in ("-h", "--help"):
            print(USAGE, file=out)
            return 0
        else:
            ignored.append(a)       # options of a newer oomph top are ignored, and named (04 §5.2)
        i += 1
    span = opts.get("--span", "24h")
    if span in ("∞", "all"):
        span = "inf"
    if span not in view.SPANS:
        print("oomph top: --span takes inf, 24h, 6h or 1h", file=sys.stderr)
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
    caps = view.Caps(detect_color(opts.get("--color", "auto"), tty, env), detect_glyphs(opts.get("--glyphs", "auto"), env),
                     detect_theme(opts.get("--theme", "auto"), env))
    fmt = opts.get("--format") or ("ansi" if caps.color != "none" else "text")
    if fmt not in ("text", "ansi", "golden"):
        print("oomph top: --format takes text, ansi or golden", file=sys.stderr)
        return 2
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
