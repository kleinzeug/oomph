#!/usr/bin/python3 -I
"""Golden frames of `oomph top` (roadmap 04-tui §10.2): deterministic fixture directories, read
through the same loader `oomph top --once` uses, drawn at a fixed clock in Europe/Berlin and
compared with tools/golden/top/*.golden (the characters, then one plane per style: a text change
and a colour change are separate, readable diffs).

    tools/topfixture.py               check every golden frame (the self-test runs this)
    tools/topfixture.py --update      rewrite them (review the diff before committing)
    tools/topfixture.py --dir DIR     only write the fixture directories into DIR (by hand:
                                      OOMPH_DIR=DIR/default/log OOMPH_LEDGER_DIR=DIR/default/ledger
                                      oomph top --once --now 1795191997)

All data is invented. The list of frames is closed: a new one retires an old one.
"""
import gzip
import json
import math
import os
import random
import shutil
import sys
import tempfile
import time

os.environ["TZ"] = "Europe/Berlin"
time.tzset()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(ROOT, "tools", "golden", "top")
sys.path.insert(0, os.path.join(ROOT, "daemon"))


def T(day, hh, mm=0, ss=0):
    """A local time in November 2026."""
    return time.mktime((2026, 11, day, hh, mm, ss, 0, 0, -1))


NOW = T(20, 13, 27)
HOST, OS = "studio", "macOS 27.2"


def _within(t, spans):
    return any(a <= t < b for a, b in spans)


def synth(seed=1120, until=NOW, start=None, crisis=False):
    """A week of samples every 30 s: working hours, nights asleep, a leak on Monday, a build that
    swaps and gets processes killed on Thursday, pressure critical for a moment on Friday."""
    rng = random.Random(seed)
    asleep, away = [], []
    for d in range(13, 21):
        j = rng.uniform(-12, 12) * 60
        asleep.append((T(d, 0, 50) + j, T(d, 6, 45) + j))
        away.append((T(d, 0, 0) - 40 * 60, T(d, 8, 10) + j))
    asleep += [(T(14, 11, 30), T(14, 16, 0)), (T(14, 18, 5), T(15, 20, 15)), (T(18, 12, 28), T(18, 13, 14)),
               (T(19, 19, 30), T(19, 21, 10))]
    away += [(T(14, 11, 0), T(14, 16, 5)), (T(14, 17, 50), T(15, 20, 20)), (T(17, 12, 15), T(17, 13, 5)),
             (T(20, 12, 5), T(20, 12, 40))]
    pts, t = [], start or T(13, 8, 20)
    app, comp, burst_until, burst, slept = 8.0, 6.5, 0, 0.0, False
    while t <= until:
        if _within(t, asleep):
            t += 30
            slept = True
            continue
        if slept:
            app, slept = max(6.0, app * 0.94), False
        lt = time.localtime(t)
        hr = lt.tm_hour + lt.tm_min / 60.0
        work = (1.0 if 8.5 <= hr < 19 else 0.45 if 19 <= hr < 23.3 else 0.08) * (1.0 if lt.tm_wday < 5 else 0.5)
        if t > burst_until and work > 0.5 and rng.random() < 0.006:
            burst_until, burst = t + rng.uniform(4, 16) * 60, rng.uniform(2.5, 6.0)
        extra = burst if t <= burst_until else 0.0
        swap, kills, cplus = 0.0, 0, 0.0
        if T(16, 15, 30) <= t < T(16, 17, 5):
            cplus = 5.5 * min(1.0, (t - T(16, 15, 30)) / 4500.0)
        if T(19, 14, 0) <= t < T(19, 14, 27):
            extra += 7.0 * (t - T(19, 14, 0)) / 1620.0
        if T(19, 14, 8) <= t < T(19, 15, 30):
            up = min(1.0, (t - T(19, 14, 8)) / 960.0)
            down = 1.0 - max(0.0, (t - T(19, 14, 40)) / 3000.0)
            swap, cplus = 7.4 * up * max(0.0, down), 2.2 * up * max(0.0, down)
        if T(19, 14, 22) <= t < T(19, 14, 27):
            kills = 2 if rng.random() < 0.75 else 1
        if T(20, 10, 10) <= t < T(20, 10, 34):
            extra += 4.5 * min(1.0, (t - T(20, 10, 10)) / 1140.0)
        if T(20, 10, 18) <= t < T(20, 11, 10):
            up = min(1.0, (t - T(20, 10, 18)) / 780.0)
            swap = 2.6 * up * max(0.0, 1.0 - max(0.0, (t - T(20, 10, 40)) / 1800.0))
        if crisis and t >= NOW - 21 * 60:
            up = min(1.0, (t - (NOW - 21 * 60)) / 900.0)
            extra += 6.5 * up
            swap = 6.8 * max(0.0, (t - (NOW - 13 * 60)) / 780.0) if t >= NOW - 13 * 60 else 0.0
            cplus = 2.5 * up
        target = 8.2 + 6.3 * work + extra
        app += (target - app) * (0.09 if crisis and t >= NOW - 21 * 60 else 0.035) + rng.gauss(0, 0.11)
        app = min(max(app, 5.0), 22.0)
        comp += (7.2 + 0.5 * (app - 8.2) + cplus - comp) * 0.02 + rng.gauss(0, 0.04)
        comp = min(max(comp, 3.0), 15.0)
        wired = 6.8 + 0.5 * math.sin(t / 21000.0) + rng.gauss(0, 0.04)
        idle = 900 if _within(t, away) else 0
        pts.append({"t": t, "app_gb": round(app, 2), "wired_gb": round(wired, 2), "compressed_gb": round(comp, 2),
                    "swap_used_gb": round(swap, 2), "jetsam_kills": kills,
                    "away": {"idle_s": idle, "display_on": idle == 0, "locked": False}})
        t += 30
    return pts


PURPOSES = [("gradle assembleDebug", 6.0, "atlas", 6), ("pnpm check", 2.0, "webshop", 9), ("pytest -n 8", 4.0, "ml-eval", 5),
            ("docker build api", 8.0, "atlas", 2), ("xcodebuild test", 10.0, "atlas-ios", 1),
            ("cargo build --release", 5.0, "indexer", 2), ("playwright e2e", 3.0, "webshop", 3)]
LIVE = [("gradle assembleDebug", 6.0, "atlas", 730, 4.1, 1800, False), ("pytest -n 8", 4.0, "ml-eval", 240, 1.3, 1800, False),
        ("pnpm check", 2.0, "webshop", 70, 0.3, 1800, False), ("docker build api", 8.0, "atlas", 40, 0.0, 1800, True)]
LIVE_CRISIS = [("xcodebuild test", 10.0, "atlas-ios", 1310, 7.9, 3600, False),
               ("gradle assembleDebug", 6.0, "atlas", 730, 4.1, 1800, False),
               ("pytest -n 8", 4.0, "ml-eval", 240, 1.3, 1800, False), ("playwright e2e", 3.0, "webshop", 150, 1.1, 1800, False),
               ("pnpm check", 2.0, "webshop", 70, 0.3, 1800, False), ("docker build api", 8.0, "atlas", 95, 0.0, 1800, True),
               ("cargo build --release", 5.0, "indexer", 40, 0.0, 1800, True)]
HOSTILE = [("\x1b]52;c;aGk=\x07clipboard \x1b[2J", 3.0, "\x1b[31mred", 300, 1.0, 1800, False),
           ("right\u202eto left \u2066x\u2069", 2.0, "שלום עולם", 200, 0.5, 1800, False),
           ("emoji \U0001F680\u26A0\uFE0F build", 1.0, "e\u0301\u0301\u0301tude", 100, 0.2, 1800, False),
           ("構築テスト 構築テスト 構築テスト", 4.0, "ｗｉｄｅ", 60, 0.0, 1800, True)]


def reservations(live, seed=82, now=NOW):
    """Finished reservations of the working days, as reservations.jsonl holds them, and the live
    ones as ledger.json leases (held by pid 1, which is always alive)."""
    rng = random.Random(seed)
    recs, leases, seq = [], [], 100
    bag = [p for p in PURPOSES for _ in range(p[3])]
    t = T(16, 9, 10)
    while t < now - 25 * 60:
        t += rng.expovariate(1.0 / (26 * 60))
        lt = time.localtime(t)
        if not (9 <= lt.tm_hour < 19) or lt.tm_wday >= 5 or t >= now - 25 * 60:
            continue
        fan = 1 + (rng.random() < 0.35) * rng.randint(1, 3)
        base = rng.choice(bag)
        for n in range(fan):
            purpose, gb, project, _ = base if n == 0 or rng.random() < 0.6 else rng.choice(bag)
            seq += 1
            req = round(t + n * rng.uniform(3, 40), 1)
            wait = 0.0 if rng.random() < 0.72 else round(rng.uniform(25, 260), 1)
            dur = round(rng.uniform(1.5, 13) * 60 * (2.0 if gb >= 8 else 1.0), 1)
            rec = {"event": "end", "t": req + wait + dur, "key": "r%d@%d" % (seq, int(req)), "id": "r%d" % seq,
                   "purpose": purpose, "project": "/srv/proj/" + project, "holder": "session", "gb": gb,
                   "requested": req, "granted": req + wait, "ended": req + wait + dur,
                   "outcome": rng.choice(["released"] * 8 + ["expired", "holder_gone"]),
                   "peak_gb": round(gb * rng.uniform(0.45, 1.05), 1)}
            if rng.random() < 0.12:
                rec["gb"] = round(gb * 0.6, 1)
                rec["segments"] = [{"t": req, "gb": gb}, {"t": round(req + wait + dur * 0.4, 1), "gb": rec["gb"]}]
            recs.append(rec)
    for purpose, gb, project, ago_s, used, ttl, queued in live:
        seq += 1
        req = now - ago_s
        lease = {"id": "r%d" % seq, "key": "r%d@%d" % (seq, int(req)), "state": "queued" if queued else "granted",
                 "gb": gb, "purpose": purpose, "project": "/srv/proj/" + project,
                 "holder": {"pid": 1, "start": None, "kind": "session"}, "requested": req, "seen": now - 1,
                 "used_gb": used, "peak_gb": used}
        if not queued:
            lease.update(granted=req, ttl=ttl, expires=req + ttl)
        leases.append(lease)
    return recs, {"seq": seq, "leases": leases, "history": [], "state": {}}


INCIDENTS = [("20261120-102907", T(20, 10, 29, 7), T(20, 10, 36), 0, "memory pressure critical"),
             ("20261119-142210", T(19, 14, 22, 10), T(19, 14, 50), 14, "14 processes killed for memory in 60 s"),
             ("20261116-164502", T(16, 16, 45, 2), T(16, 17, 6), 0, "17 GB held outside any process (leak?)")]
GROUPS = [("Google Chrome", 5.1, 23), ("Xcode", 4.2, 6), ("Code", 3.4, 14), ("OrbStack", 3.1, 4), ("Slack", 1.2, 5),
          ("Safari", 1.1, 9), ("Figma", 0.9, 4), ("iTerm2", 0.6, 3), ("Spotify", 0.5, 4), ("Mail", 0.4, 2),
          ("Notes", 0.3, 1), ("Finder", 0.2, 1)]
EVENTS = [(T(20, 12, 40), "sleep_gap", {"seconds": 2100}), (T(20, 10, 29), "pressure_change", {"old": 2, "new": 4}),
          (T(20, 10, 21), "pressure_change", {"old": 1, "new": 2}), (T(20, 8, 12), "sleep_gap", {"seconds": 20400}),
          (T(19, 14, 22), "jetsam", {"kills": 14}), (T(19, 14, 20), "pressure_change", {"old": 2, "new": 4}),
          (T(19, 9, 2), "daemon_start", {"version": "1.8.7"}), (T(18, 13, 14), "sleep_gap", {"seconds": 2760}),
          (T(16, 16, 45), "unowned_memory", {"gb": 17}), (T(20, 10, 36), "incident_close", {})]


def write_fixture(d, scenario):
    """One machine's log and ledger directories for a scenario: default, critical, silent (the
    logger stopped at 13:02), fresh (a first run: 14 minutes of history, nothing on record), hostile
    (text that must not reach the terminal as it is)."""
    log, led = os.path.join(d, "log"), os.path.join(d, "ledger")
    os.makedirs(log)
    os.makedirs(led)
    crisis = scenario == "critical"
    until = T(20, 13, 2) if scenario == "silent" else NOW
    pts = synth(until=until, start=NOW - 14 * 60 if scenario == "fresh" else None, crisis=crisis)
    by_day = {}
    for p in pts:
        by_day.setdefault(time.strftime("%Y-%m-%d", time.localtime(p["t"])), []).append(p)
    today = time.strftime("%Y-%m-%d", time.localtime(NOW))
    for day, ps in sorted(by_day.items()):
        text = "".join(json.dumps(p, separators=(",", ":")) + "\n" for p in ps).encode()
        if day == today:
            with open(os.path.join(log, "samples-%s.jsonl" % day), "wb") as f:
                f.write(text)
        else:
            with gzip.GzipFile(os.path.join(log, "samples-%s.jsonl.gz" % day), "wb", mtime=0) as f:
                f.write(text)
    last = pts[-1]
    ram = 36.0
    cur = dict(last, ram_gb=ram, pressure=4 if crisis else 1, swap_total_gb=9.0 if crisis else 0.0,
               disk_free_gb=63.0, unowned_gb=3.6,
               groups=[{"name": n, "mb": int(gb * 1024), "n": k} for n, gb, k in GROUPS],
               claude=[{"pid": 640, "cwd": "/srv/proj/atlas", "mb": 3174, "n": 14, "biggest": {"name": "java", "mb": 2253}},
                       {"pid": 2210, "cwd": "/srv/proj/ml-eval", "mb": 2662, "n": 9, "biggest": {"name": "python", "mb": 1946}},
                       {"pid": 3120, "cwd": "/srv/proj/webshop", "mb": 1434, "n": 11, "biggest": {"name": "node", "mb": 819}}],
               daemon={"pid": 99, "version": "1.8.7", "interval": 30, "incident": None, "root": True})
    if scenario == "hostile":
        cur["groups"][0]["name"] = "\x1b[2J\x1b[Hevil\x07 app"
        cur["groups"][1]["name"] = "\u202eppA dooG"
    with open(os.path.join(log, "current.json"), "w") as f:
        json.dump(cur, f)
    events = list(EVENTS)
    if crisis:
        events += [(T(20, 13, 24), "pressure_change", {"old": 2, "new": 4}), (T(20, 13, 23), "jetsam", {"kills": 3})]
    with open(os.path.join(log, "events.jsonl"), "w") as f:
        for t, kind, extra in sorted(events):
            f.write(json.dumps(dict(extra, t=t, kind=kind)) + "\n")
    incs = [] if scenario == "fresh" else list(INCIDENTS)
    if crisis:
        incs.insert(0, ("20261120-132412", T(20, 13, 24, 12), None, 3, "memory pressure critical"))
    if scenario == "hostile":
        incs[0] = (incs[0][0], incs[0][1], incs[0][2], 0, "\x1b]0;title\x07 killed \u202eevil\u202c ⚠️ 進程")
    for iid, start, end, kills, desc in incs:
        os.makedirs(os.path.join(log, "incidents", iid))
        with open(os.path.join(log, "incidents", iid, "incident.json"), "w") as f:
            json.dump({"id": iid, "start": start, "end": end, "open": end is None,
                       "reasons": [{"kind": "pressure", "desc": desc, "t": start}],
                       "summary": {"jetsam_kills": kills}}, f)
    if scenario != "fresh":
        recs, ledger = reservations(LIVE_CRISIS if crisis else HOSTILE if scenario == "hostile" else LIVE)
        with open(os.path.join(led, "reservations.jsonl"), "w") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")
        with open(os.path.join(led, "ledger.json"), "w") as f:
            json.dump(ledger, f)
    return log, led


# (name, scenario, width, height, span, colour, glyphs, theme, format)
FRAMES = [
    ("80x24-default", "default", 80, 24, "24h", "256", "unicode", "dark", "golden"),
    ("80x24-inf", "default", 80, 24, "inf", "256", "unicode", "dark", "golden"),
    ("80x24-1h", "default", 80, 24, "1h", "256", "unicode", "dark", "golden"),
    ("160x48-wide", "default", 160, 48, "24h", "256", "unicode", "dark", "golden"),
    ("160x24-wide", "default", 160, 24, "6h", "256", "unicode", "dark", "golden"),
    ("60x16-small", "default", 60, 16, "24h", "256", "unicode", "dark", "golden"),
    ("40x10-minimum", "default", 40, 10, "24h", "256", "unicode", "dark", "golden"),
    ("36x8-too-small", "default", 36, 8, "24h", "256", "unicode", "dark", "golden"),
    ("80x24-cells", "default", 80, 24, "24h", "256", "cells", "dark", "golden"),
    ("80x24-ascii", "default", 80, 24, "24h", "256", "ascii", "dark", "golden"),
    ("80x24-16", "default", 80, 24, "24h", "16", "unicode", "dark", "golden"),
    ("80x24-mono", "default", 80, 24, "24h", "none", "unicode", "dark", "golden"),
    ("80x24-critical", "critical", 80, 24, "1h", "256", "unicode", "dark", "golden"),
    ("80x24-logger-silent", "silent", 80, 24, "1h", "256", "unicode", "dark", "golden"),
    ("80x24-first-run", "fresh", 80, 24, "1h", "256", "unicode", "dark", "golden"),
    ("80x24-hostile", "hostile", 80, 24, "24h", "256", "unicode", "dark", "golden"),
    ("80x24-256-dark", "default", 80, 24, "24h", "256", "unicode", "dark", "ans"),
    ("80x24-truecolor-light", "critical", 80, 24, "1h", "truecolor", "cells", "light", "ans"),
]


def frames(base):
    """{name: (text, frame)} for every golden frame, from fixtures written under `base`."""
    import oomph
    import oomph_top
    import oomph_view as view
    dirs, out = {}, {}
    for name, scen, w, h, span, color, glyphs, theme, fmt in FRAMES:
        if scen not in dirs:
            dirs[scen] = write_fixture(os.path.join(base, scen), scen)
        log, led = dirs[scen]
        oomph.LEDGER_DIR = led
        model = oomph_top.load_model(span, NOW, log_dir=log, live=False)
        model.update(host=HOST if scen != "hostile" else "st\x1b[2Judio\u202e", os=OS)
        caps = view.Caps(color, glyphs, theme)
        fr = view.render(model, w, h, caps, {"span": span})
        if fmt == "golden":
            text = fr.golden("oomph top golden frame v2 · %dx%d · scenario=%s · span=%s glyphs=%s color=%s"
                             % (w, h, scen, span, glyphs, color))
        else:
            text = fr.ansi(caps)
        out[name + "." + ("golden" if fmt == "golden" else "ans")] = (text, fr)
    return out


def main(argv):
    if "--dir" in argv:
        base = argv[argv.index("--dir") + 1]
        for scen in ("default", "critical", "silent", "fresh", "hostile"):
            write_fixture(os.path.join(base, scen), scen)
        print("topfixture: fixtures in %s (now = %d)" % (base, NOW))
        return 0
    base = tempfile.mkdtemp(prefix="oomph-topfixture-")
    real = time.time
    try:
        got = frames(base)
        time.time = lambda: real() + 40 * 86400     # the frames are the fixture's: the wall clock must not show
        later = frames(os.path.join(base, "later"))
    finally:
        time.time = real
        shutil.rmtree(base, ignore_errors=True)
    import oomph_view as view
    bad = 0
    drift = sorted(n for n in got if later.get(n, (None,))[0] != got[n][0])
    if drift:
        bad += 1
        print("FAIL  top golden: drawn 40 days later by the wall clock, %s differ%s (only `now` may decide what a "
              "frame shows)" % (", ".join(drift), "s" if len(drift) == 1 else ""))
    for name, (text, fr) in got.items():
        path = os.path.join(GOLDEN, name)
        problems = []
        rows = text.split("\n")
        widths = {sum(2 if c[0] and view._in(ord(c[0][0]), view.WIDE2) else (0 if c[0] == "" else 1) for c in r) for r in fr.c}
        if widths != {fr.w}:
            problems.append("rows are %s cells wide, not %d" % (sorted(widths), fr.w))
        if any(unicodedata_c(ch) for r in fr.c for c in r for ch in c[0]):
            problems.append("a control or format character in the frame")
        if view.lint_pairing(fr):
            problems.append("colour rule: %s" % view.lint_pairing(fr)[:3])
        if "--update" in argv:
            os.makedirs(GOLDEN, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        else:
            try:
                with open(path, encoding="utf-8") as f:
                    want = f.read()
            except OSError:
                want = None
            if want != text:
                problems.append("differs from %s" % os.path.relpath(path, ROOT) if want is not None else "no golden file")
                if want is not None:
                    w_rows = want.split("\n")
                    for i, (a, b) in enumerate(zip(w_rows, rows)):
                        if a != b:
                            problems.append("first difference, line %d:\n      want %r\n      got  %r" % (i + 1, a, b))
                            break
        bad += bool(problems)
        print("%s top golden %s%s" % ("FAIL " if problems else "ok   ", name, "".join("\n      " + p for p in problems)))
    known = {n for n in os.listdir(GOLDEN)} if os.path.isdir(GOLDEN) else set()
    for extra in sorted(known - set(got)):
        bad += 1
        print("FAIL  top golden %s: no frame makes it any more (remove it)" % extra)
    print("topfixture: %d golden frames %s" % (len(got), "updated" if "--update" in argv else
                                                 "match" if not bad else "— %d problem(s)" % bad))
    return 1 if bad else 0


def unicodedata_c(ch):
    import unicodedata
    return unicodedata.category(ch)[0] == "C"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
