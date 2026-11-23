#!/usr/bin/python3 -I
"""Golden frames of `oomph top` (roadmap 04-tui §10.2): deterministic fixture directories, read
through the same loader `oomph top --once` uses, drawn at a fixed clock in Europe/Berlin and
compared with tools/golden/top/*.golden (the characters, then one plane per style: a text change
and a colour change are separate, readable diffs).

    tools/topfixture.py               check every golden frame (the self-test runs this)
    tools/topfixture.py --update      rewrite them (review the diff before committing)
    tools/topfixture.py --dir DIR     only write the fixture directories into DIR (by hand:
                                      OOMPH_DIR=DIR/default/log OOMPH_LEDGER_DIR=DIR/default/ledger
                                      oomph top --once --now 1795177620)

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
    return recs, {"seq": seq, "leases": leases, "history": [],
                  "state": {"t": now - 1, "level": "ok", "free_gb": 3.3, "margin_gb": 1.8}}


INCIDENTS = [("20261120-102907", T(20, 10, 29, 7), T(20, 10, 36), 0, "memory pressure critical"),
             ("20261119-142210", T(19, 14, 22, 10), T(19, 14, 50), 14, "14 processes killed for memory in 60 s"),
             ("20261116-164502", T(16, 16, 45, 2), T(16, 17, 6), 0, "17 GB held outside any process (leak?)")]
GROUPS = [("Google Chrome", 5.1, 23), ("Xcode", 4.2, 6), ("Code", 3.4, 14), ("OrbStack", 3.1, 4), ("Slack", 1.2, 5),
          ("Safari", 1.1, 9), ("Figma", 0.9, 4), ("iTerm2", 0.6, 3), ("Spotify", 0.5, 4), ("Mail", 0.4, 2),
          ("Notes", 0.3, 1), ("Finder", 0.2, 1)]
PROCS = [(4410, "Google Chrome Helper (Renderer)", 1650, "Google Chrome", None), (4402, "Google Chrome", 980, "Google Chrome", None),
         (2301, "Xcode", 3100, "Xcode", None), (4471, "Google Chrome Helper (GPU)", 760, "Google Chrome", None),
         (651, "java", 2253, "Code", 640), (2215, "python", 1946, "Code", 2210), (3127, "node", 819, "Code", 3120),
         (1201, "OrbStack Helper", 2900, "OrbStack", None)]
INCIDENT_SUMMARY = {"peak_pressure": "critical", "peak_at": "2026-11-19T14:24:40", "max_swap_used_gb": 7.4,
                    "max_swap_total_gb": 9.0, "jetsam_kills": 14,
                    "most_killed": {"WebContent": 6, "mdworker_shared": 3, "Slack Helper": 2},
                    "group_risers": [{"name": "java", "rise_mb": 6963}, {"name": "Google Chrome", "rise_mb": 1229}],
                    "groups_at_peak": [{"name": "java", "mb": 9114}, {"name": "Google Chrome", "mb": 5222},
                                       {"name": "Xcode", "mb": 4300}],
                    "claude_at_peak": [{"cwd": "/srv/proj/atlas", "mb": 9626}], "away_fraction": 0.0}
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
               daemon={"pid": 99, "version": "1.8.7", "interval": 30, "incident": None, "root": True},
               procs=742, top=[{"pid": pid, "ppid": 1, "name": n, "uid": 501, "mb": mb, "g": g, "s": ses}
                               for pid, n, mb, g, ses in PROCS])
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
                       "summary": dict(INCIDENT_SUMMARY, jetsam_kills=kills) if kills == 14 else
                       {"jetsam_kills": kills}}, f)
    if scenario != "fresh":
        recs, ledger = reservations(LIVE_CRISIS if crisis else HOSTILE if scenario == "hostile" else LIVE)
        with open(os.path.join(led, "reservations.jsonl"), "w") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")
        with open(os.path.join(led, "ledger.json"), "w") as f:
            json.dump(ledger, f)
    return log, led


# ------------------------------------------------------------------ machines (T2: 04 §3.7, from 01's formats)
# (mirror name, label, transport, state, error, live pid, synced all, have) — times relative to NOW
MACHINES = [
    ("m-7f3a9c1e5b2d4a68", "mac-mini", "tcp", "live", None, True, True, None),
    ("m-1b2c3d4e5f607182", "build-box", "tcp", "offline", "timeout", False, True, "holes"),
    ("m-90a1b2c3d4e5f607", "gpu-box", "tcp", "needs_attention", "identity_changed", False, True, None),
    ("m-2c3d4e5f60718293", "render-01", "ssh", "catching_up", None, True, False, "recent"),
]
RECENT = ("m-5a6b7c8d9e0f1a2b", "air", "air.local")


def write_machines(base, more=0, pid=None):
    """An OOMPH_MACHINES_DIR as `oomph remote add` and the engine leave it, in 01's formats (machines.json,
    and per mirror log/, ledger/, status.json, sync.json, machine.json), every time relative to NOW: a
    live machine, one not connected for 40 minutes with an older stretch not received, one whose key
    changed, one just paired over ssh (catching up), a recent one that is not a tab, and `more` pinned
    machines that have never answered (the twelve-tab frames). `pid`: the process a live status names."""
    pid = os.getpid() if pid is None else pid
    mdir = os.path.join(base, "machines")
    os.makedirs(mdir, mode=0o700)
    src_log, src_led = write_fixture(os.path.join(base, "machines-src"), "default")
    entries = []
    for i, (mid, name, tr, state, err, live, synced, have) in enumerate(MACHINES):
        d = os.path.join(mdir, mid)
        shutil.copytree(src_log, os.path.join(d, "log"))
        shutil.copytree(src_led, os.path.join(d, "ledger"))
        down = NOW - 40 * 60 if state == "offline" else NOW
        spans = [[NOW - 14 * 86400, NOW]]
        if have == "holes":
            spans = [[NOW - 14 * 86400, NOW - 7 * 3600], [NOW - 5 * 3600, down]]
        elif have == "recent":
            spans = [[NOW - 6 * 3600, NOW]]
        if state == "needs_attention":
            spans = [[NOW - 14 * 86400, NOW - 22 * 3600]]
        st = {"v": 1, "state": state, "was": None, "since": NOW - 3600, "last_contact": down if state != "needs_attention"
              else NOW - 22 * 3600, "error": err, "detail": None, "attempt": 3 if state == "offline" else 0,
              "next_try": NOW + 40 if state == "offline" else None, "connect_ms": 120, "transport": tr,
              "peer": None, "pid": pid if live else None, "fast": None, "updated": NOW}
        sy = {"v": 1, "have": spans, "gone": [], "bad": [], "oldest": NOW - 14 * 86400, "samples_at": None,
              "synced": {"ledger": synced, "reservations": synced, "incidents": synced},
              "dropped": {"samples": 0, "records": 0}, "offset_s": 0}
        mj = {"id": mid, "name": name, "os": "macos", "os_version": "macOS 27.1", "version": "1.10.0",
              "oldest": NOW - 14 * 86400, "caps": []}
        for n, v in (("status.json", st), ("sync.json", sy), ("machine.json", mj)):
            with open(os.path.join(d, n), "w") as f:
                json.dump(v, f)
        entries.append({"mid": mid, "id": mid, "name": name, "label": None, "transport": tr,
                        "host": name if tr == "ssh" else name + ".local", "port": None if tr == "ssh" else 6674,
                        "user": "sam" if tr == "ssh" else None, "addrs": ["192.168.1.%d" % (40 + i)],
                        "fp": None if tr == "ssh" else "sha256:" + "%064x" % (i + 1), "client": None, "os": "macos",
                        "os_version": "macOS 27.1", "ram_gb": 64, "version": "1.10.0", "caps": [],
                        "added": NOW - 86400 * (9 - i), "last_connected": NOW - 3600, "pinned": True, "order": i + 1})
    for k in range(more):
        entries.append({"mid": "m-%016x" % (0xc0ffee00 + k), "id": None, "name": "ci-%02d" % (k + 1), "label": None,
                        "transport": "tcp", "host": "ci-%02d.local" % (k + 1), "port": 6674, "pinned": True,
                        "order": 10 + k, "added": NOW - 3600})
    entries.append({"mid": RECENT[0], "id": RECENT[0], "name": RECENT[1], "label": None, "transport": "tcp",
                    "host": RECENT[2], "port": 6674, "addrs": ["192.168.1.47"], "os": "macos", "os_version": "macOS 26.4",
                    "ram_gb": 16, "last_connected": NOW - 2 * 86400, "pinned": False, "order": 30})
    with open(os.path.join(mdir, "machines.json"), "w") as f:
        json.dump({"v": 1, "machines": entries}, f, indent=1)
    return mdir


def machine_model(mdir, mid, span, now=NOW):
    """The model `oomph top` draws with `mid` selected, read from `mdir` as the program reads it (its
    worker's Machines and Feed), at `now`; this machine's tab named as the frames name it."""
    import oomph
    import oomph_sync
    import oomph_top
    M = oomph_top.Machines(mdir, oomph_sync)
    M.refresh(now - 30)                     # opened half a minute ago: no grace on any tab
    src = oomph_top.Source(oomph.LOG_DIR, lambda m: None, clock=lambda: now, machines=M)
    src.span, src.mid = span, mid
    src.step()
    m = src.model(now, now, mid)
    t0 = m["tabs"][0]
    t0.update(label=HOST, version="1.10.0", system=OS)
    if mid == "local":
        m.update(host=HOST, os=OS)
    return oomph_top.at(m, now)


# (name, mirror selected ("local": this machine), width, height, span, glyphs, the dialog open, pinned machines more):
# 04 §8's four for T2. The tab bar with this machine selected, the attention card, Connect, the list and twelve
# tabs in ASCII are row expectations in tools/toptest.py (test_machine_rows), drawn by machine_frame
MACHINE_FRAMES = [
    ("80x24-not-connected", "m-1b2c3d4e5f607182", 80, 24, "24h", "unicode", None, 0),
    ("80x24-catching-up", "m-2c3d4e5f60718293", 80, 24, "24h", "unicode", None, 0),
    ("60x16-pair", "local", 60, 16, "24h", "unicode", {"kind": "pair", "target": "studio.local", "code": "K7QF2M9XD4",
                                                       "fp_short": "3288 6121 2BBE 5CC8"}, 0),
    ("40x10-tabs-12", "m-00000000c0ffee03", 40, 10, "24h", "unicode", None, 8),
]


def machine_frame(base, dirs, mid, w, h, span, glyphs, ov, more):
    """One frame of the machine fixture (written under `base` once, kept in `dirs`) with `mid` selected."""
    import oomph
    import oomph_view as view
    key = "machines-%d" % more
    if key not in dirs:
        dirs[key] = write_machines(os.path.join(base, key), more)
    if "default" not in dirs:
        dirs["default"] = write_fixture(os.path.join(base, "default"), "default")
    log, led = dirs["default"]
    oomph.LEDGER_DIR, oomph.LOG_DIR = led, log
    model = machine_model(dirs[key], mid, span)
    ui = {"span": span}
    if ov:
        ui["overlay"] = dict(ov)
    return view.render(model, w, h, view.Caps("256", glyphs, "dark"), ui)


def format_problems(mdir):
    """The machine fixture read by oomph remote's own readers (04 §8 wants 01's fixtures; this one is
    written here so the frames keep a fixed clock): every machines.json entry is one oomph_sync.Book
    keeps as written, every sync.json is taken whole by oomph_sync.Sync, and every status.json has
    exactly write_status's fields. A drift of 01's formats fails here, not silently in a frame."""
    import oomph_sync as S
    out = []
    with open(os.path.join(mdir, "machines.json")) as f:
        raw = json.load(f)["machines"]
    book = S.Book(mdir)
    kept = {e["mid"]: e for e in book.machines}
    for e in raw:
        k = kept.get(e["mid"])
        if k is None:
            out.append("machines.json: %s is dropped by oomph_sync.valid_entry" % e["mid"])
        elif any(k.get(n) != e.get(n) for n in ("name", "transport", "host", "port", "user", "fp", "pinned", "addrs")):
            out.append("machines.json: %s is changed by oomph_sync.valid_entry" % e["mid"])
    tmp = tempfile.mkdtemp(prefix="oomph-status-")
    try:
        fields = set(S.write_status(S.Mirror(tmp)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for e in raw:
        d = os.path.join(mdir, e["mid"])
        if not os.path.isdir(d):
            continue
        m = S.Mirror(d)
        st, sy = m.json("", "status.json"), m.json("", "sync.json")
        if set(st or {}) != fields:
            out.append("%s/status.json: fields %s, write_status writes %s" % (e["mid"], sorted(st or {}), sorted(fields)))
        sync = S.Sync(None, m, {"now": NOW, "oldest": (sy or {}).get("oldest")})
        lost = [k for k, v in (sy or {}).items() if sync.state.get(k) != v]
        if lost or [list(x) for x in sync.have.spans] != [list(x) for x in sy["have"]]:
            out.append("%s/sync.json: oomph_sync.Sync does not take %s" % (e["mid"], lost or "have as written"))
    return out


# (name, scenario, width, height, span, colour, glyphs, theme, format[, keys pressed first])
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
    # T1: the selection, a panel, the help, the cards (the keys are pressed through oomph_view.press, as the
    # program presses them)
    ("80x24-selected", "default", 80, 24, "24h", "256", "unicode", "dark", "golden",
     "down down down down down space down"),
    ("80x24-apps", "default", 80, 24, "24h", "256", "unicode", "dark", "golden", "a down"),
    ("60x16-apps", "default", 60, 16, "24h", "256", "unicode", "dark", "golden", "a"),
    ("80x24-help", "default", 80, 24, "24h", "256", "unicode", "dark", "golden", "?"),
    ("80x24-reservation-card", "default", 80, 24, "24h", "256", "unicode", "dark", "golden", "down enter"),
    ("80x24-incident-card", "default", 80, 24, "24h", "256", "unicode", "dark", "golden", "up down enter"),
    # T1b: inspect, the readout docked in the place of the lists, and floating where a pane has no list area
    ("80x24-inspect", "default", 80, 24, "6h", "256", "unicode", "dark", "golden",
     "i shift-left shift-left shift-left left left left left left left"),
    ("60x16-inspect", "default", 60, 16, "24h", "256", "unicode", "dark", "golden", "i shift-left shift-left shift-left"),
]


def press_keys(model, w, h, span, keys):
    """The ui state after `keys`, as the program's key map reaches it for these keys."""
    import oomph_top
    import oomph_view as view
    ui = {"span": span}
    if keys:
        ui["detected"] = oomph_top.detected_text(view.Caps("256", "unicode", "dark"), {"theme": True}, (w, h))
    for k in (keys or "").split():
        P = view.layout(model, w, h)
        if k == "i":
            view.inspect_at(ui, model, P, P["plot_w"] - 1)
        elif ui.get("inspect"):
            view.inspect_key(ui, k, model, P)
        elif k == "?":
            ui["overlay"] = {"kind": "help", "page": 1, "off": 0}
        elif k in ("a", "s", "e"):
            ui["panel"] = k
        elif k == "enter":
            kind, item = view.selected(model, ui)
            ui["overlay"] = {"kind": kind, "key": item["key"]} if kind == "res" else \
                {"kind": kind, "id": item["id"] if kind == "inc" else item[0]}
        else:
            view.press(ui, k, model, P)
    return ui


def frames(base):
    """{name: (text, frame)} for every golden frame, from fixtures written under `base`."""
    import oomph
    import oomph_top
    import oomph_view as view
    dirs, out = {}, {}
    for name, scen, w, h, span, color, glyphs, theme, fmt, *keys in FRAMES:
        if scen not in dirs:
            dirs[scen] = write_fixture(os.path.join(base, scen), scen)
        log, led = dirs[scen]
        oomph.LEDGER_DIR = led
        model = oomph_top.load_model(span, NOW, log_dir=log, live=False)
        model.update(host=HOST if scen != "hostile" else "st\x1b[2Judio\u202e", os=OS)
        caps = view.Caps(color, glyphs, theme)
        fr = view.render(model, w, h, caps, press_keys(model, w, h, span, keys[0] if keys else None))
        if fmt == "golden":
            text = fr.golden("oomph top golden frame v2 · %dx%d · scenario=%s · span=%s glyphs=%s color=%s%s"
                             % (w, h, scen, span, glyphs, color, " · keys=%s" % keys[0] if keys else ""))
        else:
            text = fr.ansi(caps)
        out[name + "." + ("golden" if fmt == "golden" else "ans")] = (text, fr)
    import oomph_sync  # noqa: F401  (the machine frames need oomph remote's formats)
    for name, mid, w, h, span, glyphs, ov, more in MACHINE_FRAMES:
        fr = machine_frame(base, dirs, mid, w, h, span, glyphs, ov, more)
        out[name + ".golden"] = (fr.golden("oomph top golden frame v2 · %dx%d · machines · selected=%s span=%s glyphs=%s%s"
                                           % (w, h, mid, span, glyphs, " · dialog=%s" % ov["kind"] if ov else "")), fr)
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
    if os.geteuid() != 0:                   # (oomph remote refuses root; its readers too)
        fx = tempfile.mkdtemp(prefix="oomph-topfixture-")
        try:
            fmt = format_problems(write_machines(fx))
        finally:
            shutil.rmtree(fx, ignore_errors=True)
        bad += bool(fmt)
        print("%s top machine fixture in 01's formats%s" % ("FAIL " if fmt else "ok   ", "".join("\n      " + p for p in fmt)))
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
