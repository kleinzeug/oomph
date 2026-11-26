#!/usr/bin/python3 -I
"""Holds the chart maths of `oomph top` (daemon/oomph_view.py) to the app's (app/oomph.swift).

tools/vectors/chart.json holds inputs and the expected answers of the functions both programs
share: the mapper and its inversion (the app's TimeAxis, which every chart row is drawn on),
thinning, gap finding, band merging, lane stacking, the strip's top, the colour index, the
reservation merge and the hover card over a column (which `oomph top`'s inspect readout shows);
from 1.11.0 the four resources (02 §3.7, §3.8): the selection's gestures, the capsule's words, what
each tile says, and an agent's palette slot; from 1.12.3 a band per reserved resource (B3, 02 §3.4.5,
§3.4.6, §3.7.7): which bands a selection draws, their lanes and scales, and the list's words (the rows
of what holds a shown resource in their order, with their amounts and status, the caption, the line
for the rest).
The expected answers are the app's: `oomph --chart-vectors FILE` runs its own functions over the
inputs and prints what they return. A change on either side that is not made on the other fails here.

    tools/chartvectors.py                    the Python against the file (the self-test runs this)
    tools/chartvectors.py --app BINARY       the app against the file (CI runs this after the build)
    tools/chartvectors.py --app BINARY --write
                                             new inputs (cases below) answered by the app, written to
                                             the file; then run without --app to see the Python agree
Exit 0 when every group agrees, 1 when one differs, 2 when it could not run.
"""
import json
import os
import subprocess
import sys
import time

# The hover card's words have local times in them: both programs run in one fixed zone (the app reads TZ
# from the environment it is started with, which is this one).
os.environ["TZ"] = "Europe/Berlin"
time.tzset()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILE = os.path.join(ROOT, "tools", "vectors", "chart.json")
sys.path.insert(0, os.path.join(ROOT, "daemon"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import oomph  # noqa: E402
import oomph_top  # noqa: E402
import oomph_view as V  # noqa: E402

GROUPS = ("mapper", "invert", "color_index", "strip_top", "multires", "gaps", "calm_bands", "stack", "merge", "order",
          "hover", "selection", "capsule", "tiles", "agent", "rows", "band_stack", "band_top", "net_scale", "net_row")


def cases():
    """The inputs, in the shapes the files have: a lease as ledger.json holds it, a record as
    reservations.jsonl does, so the app's own initialisers read them."""
    now, first = 1795180000.0, 1795180000.0 - 7.2 * 86400
    ages = [0, 60, 300, 3600, 21600, 86400, 259200, 622080]
    v = {g: [] for g in GROUPS}
    for span in (86400.0, 21600.0, 3600.0, None):
        v["mapper"].append({"now": now, "first": first, "span": span, "t": [now - a for a in ages]})
    v["mapper"].append({"now": now, "first": now - 600, "span": None, "t": [now, now - 200, now - 400, now - 600]})
    for span in (3600.0, None):     # a sample after the frame's clock (skew, or --now in the past) sits at now
        v["mapper"].append({"now": now, "first": first, "span": span, "t": [now + 1, now + 90, now + 7200]})
    us = [0.0, 0.001, 0.1, 0.25, 0.5, 0.75, 0.9, 0.999, 1.0]
    for span in (86400.0, 21600.0, 3600.0, None):   # x back to time, as an age: what the hover card is about
        v["invert"].append({"now": now, "first": first, "span": span, "u": us})
    v["invert"].append({"now": now, "first": now - 600, "span": None, "u": us})   # short: clamped to first - 1
    # where the axis starts (TimeAxis.start): another machine's oldest sample newer than its first point loaded,
    # older than it, a machine that reported none, and a machine with no points
    for oldest, fp in ((first + 7200, first), (first - 86400, first), (None, first), (now - 3 * 86400, None),
                       (None, None)):
        for span in (86400.0, None):
            v["invert"].append({"now": now, "first": fp, "oldest": oldest, "span": span, "u": us})
    for purpose in ("gradle assembleDebug", "pnpm check", "pytest -n 8", "docker build api", "xcodebuild test",
                    "cargo build --release", "playwright e2e", "training eval (overnight)", "größer – 構築", "",
                    "emoji \U0001F680 and é"):
        v["color_index"].append({"purpose": purpose})
    for tallest in (0, 0.5, 2, 2.01, 5.5, 12, 13, 40, 256, 300):
        v["strip_top"].append({"tallest": tallest})
    pts = [dict(t=now - a, wired=7.0 + 0.1 * i, app=10.0 + (i % 4), comp=6.0 - 0.2 * (i % 3), swap=0.5 * (i == 5),
                away=(i == 2), kills=int(i == 9) + int(i == 10))
           for i, a in enumerate((90000, 89970, 89940, 89910, 50000, 49970, 49940, 400, 370, 60, 30, 0))]
    v["multires"].append({"now": now, "points": pts})
    dense = [dict(t=now - 3 * 86400 + 30 * i + 400 * (i > 60), wired=6.0, app=8.0 + (i * 7919 % 13) / 4.0,
                  comp=5.0 + (i % 5) / 3.0, swap=(i % 17) / 10.0, away=(i % 23 == 0), kills=int(i % 31 == 0))
             for i in range(120)]
    v["multires"].append({"now": now, "points": dense})
    holes = [dict(t=now - 5 * 86400 + 30 * i + 400 * (i > 13) + 550 * (i > 37), wired=6.0, app=8.0 + (i % 7) / 2.0,
                  comp=5.0, swap=0.0, away=False, kills=0) for i in range(60)]   # buckets of 600 s, holes of 400 and 550
    v["multires"].append({"now": now, "points": holes})
    v["gaps"].append({"now": now + 400, "points": pts})
    v["gaps"].append({"now": now, "points": []})
    v["gaps"].append({"now": now, "points": [dict(t=now - 301, wired=0, app=0, comp=0, swap=0, away=False, kills=0)]})
    for away, gaps, tol in (([(10, 20), (40, 45)], [(20, 26), (30, 31), (60, 70)], 0.0),
                            ([(10, 20), (40, 45)], [(21.5, 26), (27, 39), (60, 70)], 2.0),
                            ([], [(5, 6), (6.5, 9)], 1.0),
                            ([(3, 4), (0, 2)], [], 0.0)):
        v["calm_bands"].append({"away": [list(a) for a in away], "gaps": [list(g) for g in gaps], "tolerance": tol})

    def lease(id_, req, gb, granted=None, ended=None, segs=None, **more):
        o = {"id": id_, "key": "%s@%d" % (id_, int(req)), "gb": gb, "purpose": "p " + id_, "requested": req,
             "granted": granted}
        if ended is not None:
            o["ended"] = ended
        if segs:
            o["segments"] = [{"t": t, "gb": g} for t, g in segs]
        o.update(more)
        return o
    v["stack"].append({"now": now, "reservations": [
        lease("a", now - 900, 4.0, now - 900, now - 300, [(now - 900, 6.0), (now - 600, 4.0)]),
        lease("b", now - 800, 2.0, now - 700), lease("c", now - 300, 8.0)]})
    v["stack"].append({"now": now, "reservations": [
        lease("d", now - 5000, 3.0, now - 5000, now - 4000), lease("e", now - 4500, 1.0, now - 4400, now - 3000),
        lease("f", now - 4000, 2.0, now - 4000, now - 3500), lease("g", now - 3800, 5.0, now - 3600, now - 3590),
        lease("h", now - 10, 1.5)]})
    # merge: the three record shapes, an "end" that a later "edit" must not undo, a ledger reset under an
    # edited reservation ("unknown"), a grant past its expiry, a queue place that lapsed, a holder that is
    # gone, a 1.6.2 ledger entry without key and segments, and something that is not a reservation at all
    holder = {"pid": 4242, "start": 1, "kind": "session"}
    gone = {"pid": 4343, "start": 1, "kind": "process"}
    records = [dict(lease("r1", now - 5000, 6.0, now - 5000, segs=[(now - 5000, 8.0), (now - 4000, 6.0)]), event="edit",
                    t=now - 4000, holder="session"),
               dict(lease("r1", now - 5000, 6.0, now - 5000, now - 3000, [(now - 5000, 8.0), (now - 4000, 6.0)]),
                    event="end", t=now - 3000, outcome="released", holder="session", peak_gb=5.1),
               dict(lease("r1", now - 5000, 6.0, now - 5000), event="edit", t=now - 2900, holder="session"),
               dict(lease("r2", now - 2000, 3.0, now - 2000, segs=[(now - 2000, 4.0), (now - 1500, 3.0)]), event="edit",
                    t=now - 1500, holder="run"),
               dict(lease("r9", now - 1000, 2.0, now - 1000, segs=[(now - 1000, 1.0), (now - 900, 2.0)]), event="edit",
                    t=now - 900, holder="session"),
               dict(lease("r3", now - 20 * 86400, 1.0, now - 20 * 86400, now - 19 * 86400), event="end",
                    outcome="released"),
               {"id": "r4", "purpose": "no size"}]
    ledger = {"seq": 12,
              "leases": [dict(lease("r9", now - 1000, 2.0, now - 1000, segs=[(now - 1000, 1.0), (now - 900, 2.0)]),
                              holder=holder, state="granted", seen=now - 10, expires=now + 800, used_gb=1.2),
                         dict(lease("r10", now - 4000, 5.0, now - 4000), holder=holder, state="granted", seen=now - 2500,
                              expires=now - 2200),
                         dict(lease("r11", now - 600, 7.0), holder=holder, state="queued", seen=now - 400),
                         dict(lease("r12", now - 300, 1.0, now - 290), holder=gone, state="granted", seen=now - 20,
                              expires=now + 1000)],
              "history": [{"id": "r0", "purpose": "p r0", "gb": 1.0, "holder": "session", "requested": now - 9000,
                           "granted": now - 9000, "ended": now - 8000, "outcome": "released", "peak_gb": 0.4}]}
    v["merge"].append({"now": now, "records": records, "ledger": ledger, "gone": [4343]})
    v["merge"].append({"now": now, "records": records, "ledger": {"seq": 0, "leases": [], "history": []}, "gone": []})
    queue = [dict(lease("q%d" % i, now - 900, 2.0), holder=holder, state="queued", seen=now - ago)
             for i, ago in enumerate((100, 179, 200, 290))]                       # around QUEUE_STALE_S
    v["merge"].append({"now": now, "records": [], "ledger": {"seq": 4, "leases": queue, "history": []}, "gone": []})
    # ledger version 2 (1.9.2): a newer writer's "grant" record, then an edit, then the end a 1.8 process
    # writes without the newer fields (the records merge: the edit's segments stay); a "grant" alone whose
    # lease is gone ("unknown", like an edit); the outcomes "refused" and "volume_gone"; a lease without
    # memory (gb 0); holders in another pid namespace, whose pid is not looked up (null is no namespace)
    agent = {"key": "3f9a0c21", "slot": 0}
    v2 = [dict(lease("v1", now - 3000, 2.0, now - 2990), event="grant", t=now - 2990, holder="session", v=2,
               agent=agent, res={"ram": 2.0, "cpu": 6, "disk": 20.0, "disk_pool": "data"}),
          dict(lease("v1", now - 3000, 3.0, now - 2990, segs=[(now - 2990, 2.0), (now - 2500, 3.0)]), event="edit",
               t=now - 2500, holder="session", v=2, agent=agent, res={"ram": 3.0, "cpu": 6}),
          dict(lease("v1", now - 3000, 3.0, now - 2990, now - 2000), event="end", outcome="holder_gone",
               holder="session", peak_gb=2.5),
          dict(lease("v2", now - 1800, 0.0, now - 1790), event="grant", t=now - 1790, holder="run", v=2,
               res={"cpu": 4}),
          dict(lease("v3", now - 1700, 4.0, None, now - 1650), event="end", outcome="refused", note="8 cores on 6", holder="session"),
          dict(lease("v4", now - 1600, 0.0, now - 1590, now - 1200), event="end", outcome="volume_gone",
               holder="process", res={"disk": 30.0, "disk_pool": "vol:0A1B2C3D-0000"}, peak={"disk": 12.0})]
    elsewhere = dict(gone, ns=4026531836)
    v2_ledger = {"seq": 9, "v": 2, "boot": "6f1c", "sessions": {"4242@1": {"cwd": "/w", "uid": 501, "seen": now}},
                 "leases": [dict(lease("v5", now - 500, 0.0, now - 490), holder=dict(holder, uid=501), state="granted",
                                 seen=now - 5, v=2, res={"cpu": {"ask": 8, "min": 4, "got": 6}}, res_granted=now - 490,
                                 agent=agent, user="x", scope="host"),
                            dict(lease("v6", now - 400, 1.0, now - 390), holder=elsewhere, state="granted",
                                 seen=now - 5),
                            dict(lease("v7", now - 300, 1.0, now - 290), holder=dict(gone, ns=None), state="granted",
                                 seen=now - 5, expires=now + 900),
                            dict(lease("v8", now - 200, 0.0), holder=holder, state="queued", seen=now - 5, v=2,
                                 waiting_on=["cpu"], hold=["cpu"], res={"cpu": {"ask": 8, "min": 4}})],
                 "history": []}
    v["merge"].append({"now": now, "records": v2, "ledger": v2_ledger, "gone": [4343]})
    # the list's order (C13): waiting by request time, then grants by expiry, one without a ttl last; ties by key
    v["order"].append({"now": now, "reservations": [
        lease("o1", now - 900, 2.0, now - 900, expires=now + 600), lease("o2", now - 300, 4.0),
        lease("o3", now - 800, 1.0, now - 700), lease("o4", now - 600, 3.0), lease("o5", now - 100, 1.0, now - 90,
                                                                                    expires=now + 60),
        lease("o6", now - 5000, 2.0, now - 5000, now - 4000), lease("o7", now - 50, 1.0, now - 40, expires=now + 600),
        lease("o8", now - 600, 2.0)]})
    v["order"].append({"now": now, "reservations": []})
    # the queue is the ledger's order: r21 grew while queued and went to the back, behind r22 and r23
    v["order"].append({"now": now, "ledger": {"seq": 23, "history": [], "leases": [
        dict(lease("r20", now - 900, 2.0, now - 900), holder=holder, state="granted", seen=now - 5, expires=now + 900),
        dict(lease("r22", now - 400, 1.0), holder=holder, state="queued", seen=now - 5),
        dict(lease("r23", now - 300, 2.0), holder=holder, state="queued", seen=now - 5),
        dict(lease("r21", now - 600, 6.0, segs=[(now - 600, 3.0), (now - 120, 6.0)]), holder=holder, state="queued",
             seen=now - 5)]}})
    # the hover card (T1b: `oomph top`'s inspect readout): two days of thinned points with holes, away stretches,
    # a sleep; incidents, events of every kind the card groups (and the new resources' kinds), reservations that
    # waited, were edited and ended; columns at the right edge, inside a gap, over an incident, before history
    hp, t = [], now - 2 * 86400
    while t <= now:
        k = len(hp)
        if not (now - 30 * 3600 < t < now - 26 * 3600 or now - 7000 < t < now - 6000):      # two holes
            hp.append(dict(t=t, wired=6.0 + (k % 3) * 0.1, app=9.0 + (k * 7 % 11) / 2.0, comp=5.0 + (k % 5) / 4.0,
                           swap=(k % 13) / 10.0 if k % 40 > 30 else 0.0, away=(k % 97) < 9, kills=int(k % 211 == 0)))
        t += 60 if now - t < 3 * 3600 else 900
    hp = V.multires(hp, now)
    hgaps = [list(g) for g in V.find_gaps(hp, now)]
    ev = [dict(t=now - 5000, kind="jetsam", kills=3, top={"mds": 2, "Safari": 1}),
          dict(t=now - 4990, kind="jetsam", kills=4, top={"mds": 2, "Xcode": 2}),
          dict(t=now - 4980, kind="pressure_change", old=1, new=2), dict(t=now - 4970, kind="pressure_change", old=2, new=4),
          dict(t=now - 4960, kind="stall", seconds=75), dict(t=now - 4950, kind="stall", seconds=3700),
          dict(t=now - 4940, kind="unowned_memory", gb=17), dict(t=now - 4930, kind="daemon_start", version="1.9.5"),
          dict(t=now - 4920, kind="disk_low", disk_free_gb=12.4, pool="data", name="Data", free_gb=12.4, level="low"),
          dict(t=now - 4910, kind="disk_filling", pool="data", name="Data", free_gb=30.0, rate_gb_min=2.5, eta_min=10.0),
          dict(t=now - 4900, kind="volume", pool="vol:X", mount="/Volumes/Scratch", name="Scratch", what="unwatched"),
          dict(t=now - 4890, kind="thermal", old=0, new=2, busy=12.5),
          dict(t=now - 4880, kind="cpu_saturated", busy=13.2, n=14, minutes=10, top={"cargo": 9.1}),
          dict(t=now - 4870, kind="cpu_saturated_cleared", busy=3.0, n=14, minutes=24),
          dict(t=now - 4860, kind="disk_low", disk_free_gb=19.0), dict(t=now - 4850, kind="incident_open", id="x"),
          dict(t=now - 4840, kind="sleep_gap", seconds=2100), dict(t=now - 4830, kind="sleep_gap", seconds=20400),
          dict(t=now - 4820, kind="some_future_kind", x=1), dict(t=now - 600, kind="pressure_flapping", flips=6),
          dict(t=now - 30, kind="disk_filling", mount="/Volumes/Fast", rate_gb_min=12.25, eta_min=1.5)]
    incs = [{"id": "20261122-120000", "start": now - 5100, "end": now - 4000, "open": False,
             "reasons": [{"kind": "jetsam_storm", "desc": "macOS is killing processes for memory (12 jetsam kills in 60 s)"}]},
            {"id": "20261122-133000", "start": now - 700, "open": True, "reasons": [{"kind": "pressure", "desc": "pressure"}]},
            {"id": "20261121-090000", "start": now - 100000, "end": now - 99000, "open": False, "reasons": []}]
    hres = [lease("h1", now - 5200, 4.0, now - 5100, now - 4500, [(now - 5200, 6.0), (now - 4800, 4.0)]),
            lease("h2", now - 5150, 2.0), lease("h3", now - 5050, 8.0, now - 5000, now - 4950),
            lease("h4", now - 5040, 1.5, now - 5040), lease("h5", now - 5030, 3.0, now - 5030, now - 3000),
            lease("h6", now - 400, 2.5, now - 300)]
    us = [1.0, 0.999, 0.5, 0.0, 0.25, 0.75, 0.97, 0.9]
    for span in (86400.0, None):                       # (6 h: the fixture's case below)
        f, _ = V.mapper(now, hp[0]["t"], span)
        at = sorted(set(us + [round(f(x), 6) for x in (now - 5000, now - 4900, now - 28 * 3600, now - 6500, now - 650)]))
        v["hover"].append({"now": now, "first": hp[0]["t"], "span": span, "du": 1.0 / 73, "u": [x for x in at if 0 <= x <= 1],
                           "points": hp, "gaps": hgaps, "events": ev, "incidents": incs, "reservations": hres})
    v["hover"].append({"now": now, "first": now - 600, "span": 3600.0, "du": 1.0 / 40, "u": [0.0, 0.5, 0.95, 1.0],
                       "points": [], "gaps": [], "events": [], "incidents": [], "reservations": []})
    v["hover"] += fixture_hover()
    resource_cases(v)
    return v


def resource_cases(v):
    """The four resources (1.11.0): every gesture on every tile from a few selections, with and without
    a GPU; the capsule and the tiles over samples that touch each rule; agents valid and not."""
    full = list(V.RESOURCES)
    for sel, focus in ((["memory"], "memory"), (["memory", "cpu"], "memory"), (["memory", "gpu", "disk"], "memory"),
                       (["memory", "cpu", "disk"], "disk"), (full, "gpu"), (["cpu"], "cpu"), (["gpu"], "gpu"),
                       ([], "memory"), (["disk", "gpu"], "cpu")):
        for avail in (full, ["memory", "cpu", "disk"]):
            for gesture in ("click", "cmd", "shift"):
                for res in V.RESOURCES:
                    v["selection"].append({"sel": sel, "focus": focus, "gesture": gesture, "res": res, "avail": avail})
    base = {"t": 1795180000.0, "ram_gb": 36.0, "app_gb": 14.6, "wired_gb": 7.2, "compressed_gb": 1.9, "pressure": 1,
            "swap_used_gb": 0.0, "swap_total_gb": 0.0, "disk_free_gb": 63.0, "jetsam_kills": 0,
            "cpu": {"n": 14, "p": 10, "e": 4, "busy": 9.13, "user": 7.6, "sys": 1.53, "therm": 0},
            "gpu": [{"id": "gpu0", "name": "Apple M3 Max", "unified": True, "util": 64.4, "active": 87.0,
                     "src": "ioreport", "mem_gb": 5.31, "mem_alloc_gb": 9.0, "mem_limit_gb": 27.0}],
            "disks": [{"id": "data", "name": "Data", "free_gb": 63.2, "total_gb": 995.0, "roles": ["home", "swap", "tmp"],
                       "watch": True, "low_gb": 20, "crit_gb": 5, "level": "ok"}],
            "groups": [{"name": "com.apple.WebKit.WebContent", "mb": 4100, "n": 9}, {"name": "Xcode", "mb": 3000}],
            "top_cpu": [{"pid": 1, "name": "rustc", "g": "cargo", "cpu": 2.5}, {"pid": 2, "name": "rustc", "g": "cargo",
                                                                               "cpu": 2.0},
                        {"pid": 3, "name": "java", "g": "Code", "cpu": 3.9}],
            "top_gpu": [{"pid": 4, "name": "python", "g": "python", "gpu": 51.0}],
            "top_io": [{"pid": 5, "name": "cp", "g": "Finder", "w": 120.0}]}
    two = [dict(base["disks"][0]), {"id": "vol:AB", "name": "Footage Archive SSD", "free_gb": 912.4, "total_gb": 1863.0,
                                    "roles": [], "watch": True, "low_gb": 50, "crit_gb": 10, "level": "low"}]
    variants = [{}, {"pressure": 2}, {"pressure": 4}, {"jetsam_kills": 3}, {"app_gb": 25.4},
                {"unowned_gb": 22.0}, {"disk_free_gb": 14.0}, {"disk_free_gb": 3.5}, {"disk_free_gb": 3.5, "pressure": 4},
                {"disk_free_gb": 14.0, "pressure": 2}, {"disk_free_gb": 3.5, "pressure": 2},
                {"disk_free_gb": 15.0, "swap_used_gb": 5.7, "swap_total_gb": 6.0},
                {"os": "linux", "pressure": 2, "disk_free_gb": 2.0},
                {"cpu": dict(base["cpu"], busy=13.2, therm=2)}, {"cpu": dict(base["cpu"], busy=12.9)},
                {"gpu": [dict(base["gpu"][0], util=93.0)]}, {"gpu": [dict(base["gpu"][0], util=93.0, src="clients")]},
                {"gpu": [{"id": "gpu0", "util": 41.0, "src": "ioreg"}]}, {"gpu": []}, {"cpu": None, "gpu": None},
                {"disks": two}, {"disks": [two[0], dict(two[1], level="critical")]},
                {"disks": [dict(two[1], roles=["tmp"]), two[0]], "disk_free_gb": 912.4}, {"disks": None},
                {"groups": [], "top_cpu": [], "top_gpu": None, "top_io": "x"},
                # another machine's sample is untrusted: absurd core counts must not crash the app (Int(1e20) traps)
                {"cpu": dict(base["cpu"], n=1e20, busy=1.0)}, {"cpu": dict(base["cpu"], n=1e300, busy=1e300)},
                {"cpu": dict(base["cpu"], n=7.5)},
                # Linux strict overcommit at 95 % of its limit is tight (oomph._verdict_parts), not past 1e15
                {"os": "linux", "pressure": 1, "linux": {"overcommit": 2, "commit_pct": 96}},
                {"os": "linux", "pressure": 1, "linux": {"overcommit": 2, "commit_pct": 94.9}},
                {"os": "linux", "pressure": 1, "linux": {"overcommit": 1, "commit_pct": 99}},
                {"os": "linux", "pressure": 1, "linux": {"overcommit": 2, "commit_pct": 1e20}},
                {"os": "linux", "pressure": 1, "linux": {"overcommit": True, "commit_pct": 99}},
                {"os": "linux", "pressure": 1, "linux": {"overcommit": 2, "commit_pct": "99"}},
                {"pressure": 1, "linux": {"overcommit": 2, "commit_pct": 99}}]
    # a metered network under 10 % of its cap (NET D-N13, 1.15): amber "Network 1.8 GB left", after memory and disk;
    # current.json's pools are what the verdict reads, and another logger's figures may be anything
    q = {"network": "rmac:00:00:5e:00:53:01", "cap": 20, "margin": 2, "used": 18.2, "from": 1795129200.0,
         "to": 1797807600.0, "period": "month", "label": "phone"}
    for qv, more in (({}, {}), ({"used": 18.0}, {}), ({"used": 18.0001}, {}), ({"used": 18.25}, {}), ({"used": 25.0}, {}),
                     ({"used": 19.95}, {}), ({"used": 12.4}, {}), ({}, {"pressure": 2}), ({}, {"pressure": 4}),
                     ({}, {"disk_free_gb": 14.0}), ({}, {"disk_free_gb": 3.5}), ({"cap": True}, {}), ({"cap": "20"}, {}),
                     ({"used": -1}, {}), ({"cap": 0.05, "used": 0.049}, {}), ({"cap": 1e300}, {}), ({"used": None}, {}),
                     ({"cap": 100000, "used": 99999.5}, {}), ({"cap": 100001, "used": 100000.5}, {}),
                     ({"label": 5}, {}), ({"to": "14 Dec"}, {}), ({"label": ["phone"], "to": True}, {})):
        v_q = dict(q, **qv)
        variants.append(dict({"pools": {"t": 1795180000.0, "net.quota": {k: x for k, x in v_q.items() if x is not None}}},
                             **more))
    variants += [{"pools": "x"}, {"pools": {"net.quota": [1, 2]}}, {"pools": {"net.quota": {"cap": 20}}},
                 {"pools": {"t": 1795180000.0, "net.down": {"cap": 250, "margin": 62.5}}}]
    for i, var in enumerate(variants):
        smp = dict(base, **var)
        smp = {k: x for k, x in smp.items() if x is not None}
        v["capsule"].append({"sample": smp})
        waiting = [{}, {"memory": 1}, {"memory": 2, "cpu": 1}][i % 3]
        v["tiles"].append({"sample": smp, "waiting": waiting})
    net_cases(v, base)
    band_cases(v)
    for a in ({"key": "3f9a0c21", "slot": 0}, {"key": "3f9a0c21", "slot": 5}, {"key": "3f9a0c21"},
              {"key": "3f9a0c21", "slot": 6}, {"key": "3f9a0c21", "slot": -1}, {"key": "3F9A0C21", "slot": 1},
              {"key": "3f9a0c2", "slot": 1}, {"key": 12345678, "slot": 1}, {"key": "3f9a0c21", "slot": True},
              {"key": "3f9a0c21", "slot": 2.0}, None, "3f9a0c21", {}):
        v["agent"].append({"agent": a})


def net_cases(v, base):
    """The network (NET N4, 1.15): its tile over samples that touch each rule (no figure, a figure, busy, metered, under
    10 % left, offline, the stale hint each way, the system's "metered?", hostile figures and names); the chart's scale;
    its row thinned, each bucket's mean and peak."""
    nb = {"if": "en0", "vpn": False, "network": "rmac:00:00:5e:00:53:01", "src": "flows", "flows": 87,
          "down_mbps": 212.4, "up_mbps": 8.14, "lan_mbps": 0.1}
    names = [{"name": "Google Chrome", "down": 3.1, "up": 0.2, "n": 9}, {"name": "curl", "down": 205.0, "up": 0.3, "n": 1}]
    down = {"network": "rmac:00:00:5e:00:53:01", "cap": 250.0, "margin": 62.5, "reserved": 150.0, "busy": 212.4, "others": 8}
    up = {"network": "rmac:00:00:5e:00:53:01", "cap": 40.0, "margin": 12.0, "reserved": 0.0, "busy": 8.1, "others": 1}
    quota = {"network": "rmac:00:00:5e:00:53:01", "cap": 20.0, "margin": 2.0, "used": 12.4, "from": 1795129200.0,
             "to": 1797807600.0, "period": "month"}
    pools = {"t": 1795180000.0, "net.down": down, "net.up": up}
    flows3 = [[300.0, 7.0, True], [310.0, 8.0, True], [320.0, 9.0, True]]
    keyed = [[300.0, 7.0, True, 5], [310.0, 8.0, True, 5], [320.0, 9.0, True, 5]]   # one network's mark (net_key)
    for more, recent, hint, waiting in (
            ({"net": nb, "net_names": names}, None, False, {}),
            ({"net": nb, "net_names": names, "pools": pools}, None, False, {"net": 1}),
            ({"net": nb, "pools": dict(pools, **{"net.down": dict(down, level="busy")})}, None, False, {}),
            ({"net": nb, "pools": dict(pools, **{"net.down": dict(down, level="busy")})}, None, False, {"net": 2}),
            ({"net": nb, "pools": dict(pools, **{"net.quota": quota})}, None, False, {}),
            ({"net": nb, "pools": dict(pools, **{"net.quota": quota})}, None, False, {"net": 1}),
            ({"net": nb, "pools": {"t": 1, "net.quota": dict(quota, used=18.2)}}, None, False, {}),
            ({"net": nb, "pools": {"t": 1, "net.quota": dict(quota, used=25.0)}}, None, True, {}),
            ({"net": {"if": None}}, None, False, {}), ({"net": {"src": "if"}}, None, False, {}),
            ({"net": dict(nb, **{"if": 5})}, None, False, {}), ({"net": dict(nb, **{"if": ""})}, None, False, {}),
            ({"net": dict(nb, down_mbps=None, up_mbps=None)}, None, False, {}),
            ({"net": dict(nb, down_mbps=1e300, up_mbps="x")}, None, False, {}),
            ({"net": dict(nb, down_mbps=0.04, up_mbps=9.96)}, None, False, {}),
            ({"net": dict(nb, down_mbps=900.0)}, None, False, {}),
            ({"net": nb, "pools": pools}, flows3, False, {}),
            ({"net": nb, "pools": pools}, [[230.0, 7.0, True], [290.0, 8.0, False], [300.0, 9.0, True]], False, {}),
            ({"net": nb, "pools": pools}, flows3[1:], False, {}),
            ({"net": nb, "pools": pools}, [[10.0, 45.0, True], [12.0, 47.0, True], [9.0, 46.0, True]], False, {}),
            ({"net": nb, "pools": pools}, [[None, 45.0, True], ["x", 47.0, True], [9.0, 46.0, True]], False, {}),
            ({"net": nb}, None, True, {}), ({"net": nb, "pools": pools}, None, True, {}),
            ({"net": nb, "pools": pools}, flows3, True, {}),
            ({"net": nb, "pools": pools}, keyed, False, {}),
            ({"net": nb, "pools": pools}, [[300.0, 7.0, True, 9]] + keyed[1:], False, {}),     # moved here: no hint
            ({"net": nb, "pools": pools}, keyed[:2] + [[320.0, 9.0, True, 255]], False, {}),   # a bucket over a move
            ({"net": nb, "pools": {"t": 1, "net.down": dict(down, cap=0.2), "net.up": dict(up, cap=True)}}, None, False, {}),
            ({"net": nb, "pools": {"t": 1, "net.down": dict(down, cap=1e6, margin=-1), "net.up": "x"}}, None, False, {}),
            ({"net": nb, "pools": {"t": 1, "net.down": dict(down, margin=900, reserved=1e9)}}, None, False, {}),
            ({"net": nb, "net_names": [{"name": 5, "down": 9}, {"name": "", "down": 9}, {"name": "x", "down": -1, "up": 1e300},
                                       {"name": "y", "down": 0.2}, "junk"]}, None, False, {}),
            ({"net": nb, "net_names": [{"name": "a", "down": 1.0}, {"name": "b", "up": 1.0}]}, None, False, {}),
            ({"net": nb, "net_names": "x"}, None, False, {}), ({"net": "x"}, None, False, {}), ({"net": [1]}, None, False, {})):
        smp = dict(base, **more)
        case = {"sample": smp, "waiting": waiting}
        if recent is not None:
            case["recent"] = recent
        if hint:
            case["hint"] = True
        v["tiles"].append(case)
    for top in (0, 0.4, 1, 1.01, 2, 2.5, 9.99, 10, 194, 200, 250, 501, 999.9, 1000, 1000.1, 100000, -3):
        v["net_scale"].append({"top": top})
    now = 1795180000.0
    pts = []
    for i in range(150):                    # 10 s apart over 20 min, then every 20 s a day back, whole Mbit/s
        t = now - 1200 + 10 * i if i < 120 else now - 86400 + 20 * (i - 120)
        pts.append({"t": t, "wired": 6.0, "app": 9.0 + (i * 7 % 5), "comp": 5.0, "swap": 0.0, "away": False, "kills": 0,
                    "cpu": None, "nd": float((i * 37) % 260) if i % 41 else None, "nu": float((i * 13) % 45),
                    "nf": i % 17 != 0, "nk": 1 + (i // 40) % 3})
    pts.sort(key=lambda p: p["t"])
    for cap in ([250.0, 40.0], [0, 0]):
        v["net_row"].append({"now": now, "points": pts, "cap": cap})


def band_cases(v):
    """B3's inputs: the resources fixture's ledger and records (tools/topfixture.py: cores over and idle, disk space on
    Data and over on Scratch, a request waiting for cores), seen through several selections; and hand-made leases
    with odd and hostile fields."""
    import topfixture
    now = topfixture.NOW
    recs, ledger = topfixture.reservations(topfixture.LIVE_RES, agents=True)
    recs = recs[-12:]                       # Friday's: some of them held cores or disk space too
    sels = [(["memory"], "memory", "data"), (["memory", "cpu"], "memory", "data"), (["cpu"], "cpu", "data"),
            (["memory", "cpu", "gpu", "disk"], "disk", "data"), (["disk"], "disk", "vol:4F632FD2"),
            (["gpu"], "gpu", None), (["cpu", "disk"], "cpu", None), (["memory", "cpu", "gpu", "disk"], "gpu", "data")]
    for shown, focus, pool in sels:
        v["rows"].append({"now": now, "records": recs, "ledger": ledger, "shown": shown, "focus": focus, "pool": pool,
                          "day": 42})
    t0 = now - 4000

    def lease(i, req, gb, **more):
        return dict({"id": i, "key": "%s@%d" % (i, int(req)), "state": "granted" if more.get("granted") else "queued",
                     "gb": gb, "purpose": "p " + i, "requested": req, "seen": now - 2,
                     "holder": {"pid": 1, "start": 1, "kind": "session"}}, **more)
    odd = {"seq": 30, "v": 2, "history": [], "leases": [
        lease("x1", t0, 2.5, granted=t0, expires=now + 600, used_gb=1.04, v=2,
              res={"ram": {"ask": 2.5, "got": 2.5}, "cpu": {"ask": 1, "got": 1, "used": 1.05, "flag": "idle", "low_t": now - 61},
                   "disk": {"ask": 0.5, "got": 0.5, "pool": "data", "w": 0.96, "flag": "over", "over_t": now - 5}},
              segments=[{"t": t0, "gb": 2.5, "res": {"ram": 2.5, "cpu": 1, "disk": 0.5}},
                        {"t": t0 + 1200, "gb": 2.5, "res": {"ram": 2.5, "cpu": 2.25, "disk": 0.5}}]),
        lease("x2", t0 + 100, 0.01, granted=t0 + 100, v=2,
              res={"cpu": {"ask": 12, "min": 6, "got": 6.5, "used": "lots", "flag": "on fire"},
                   "disk": {"ask": True, "got": -3, "pool": 7}}),
        lease("x3", t0 + 200, 3.0, v=2, waiting_on=["critical"], res={"ram": {"ask": 3.0}}),
        lease("x4", t0 + 300, 0.01, v=2, waiting_on=["cpu", "disk:vol:AB", "gpu0"],
              res={"cpu": {"ask": 4, "min": 4}, "disk": {"ask": 1500, "pool": "vol:AB", "name": "Footage Archive SSD"}}),
        lease("x5", t0 + 400, 1.0, granted=t0 + 400, expires=now + 30, v=2,
              res={"ram": {"ask": 1.0, "got": 1.0}, "cpu": {"ask": 1e9, "got": 3, "used": 0.04, "flag": "over",
                                                           "over_t": "x"}}),
        lease("x6", t0 + 500, 4.0, waiting_on="ram")]}
    odd_recs = [{"event": "end", "key": "y1@%d" % int(t0 - 3000), "id": "y1", "purpose": "p y1", "gb": 0.01,
                 "requested": t0 - 3000, "granted": t0 - 3000, "ended": t0 - 100, "outcome": "released", "v": 2,
                 "res": {"cpu": 8, "disk": 300.0, "disk_pool": "vol:AB"}}]
    for shown, focus, pool in ((["memory", "cpu", "disk"], "cpu", "data"), (["disk"], "disk", "vol:AB"),
                               (["memory"], "memory", None)):
        v["rows"].append({"now": now, "records": odd_recs, "ledger": odd, "shown": shown, "focus": focus, "pool": pool,
                          "day": 7})
    for kind, pool in (("memory", None), ("cpu", None), ("disk", "data"), ("disk", "vol:4F632FD2"), ("disk", None)):
        v["band_stack"].append({"now": now, "records": recs, "ledger": ledger, "kind": kind, "pool": pool})
    for kind, pool in (("cpu", None), ("disk", "vol:AB"), ("memory", None)):
        v["band_stack"].append({"now": now, "records": odd_recs, "ledger": odd, "kind": kind, "pool": pool})
    for kind in ("memory", "cpu", "disk"):
        for tallest in (0, 3, 12, 255, 300, 1500, 70000):
            v["band_top"].append({"tallest": tallest, "kind": kind})
    # the network (NET N4, 1.15): the fixture's grant and a request waiting for the line, through several selections;
    # hand-made parts (unmanaged, upload only, a record, over, hostile); the band's scale against what the line shares
    nrecs, nledger = topfixture.reservations(topfixture.LIVE_RES + topfixture.LIVE_NET, agents=True)
    nrecs = nrecs[-6:]
    for shown, focus, pool in ((["net"], "net", None), (["memory", "net"], "memory", "data"),
                               (["memory", "cpu", "gpu", "disk", "net"], "net", "data"), (["cpu"], "cpu", None)):
        v["rows"].append({"now": now, "records": nrecs, "ledger": nledger, "shown": shown, "focus": focus, "pool": pool,
                          "day": 9})
    odd_net = {"seq": 40, "v": 2, "history": [], "leases": [
        lease("n1", t0, 0.01, granted=t0, v=2, res={"net": {"gb": 40, "unmanaged": True, "moved": 3.5, "network": "gw:x"}}),
        lease("n2", t0 + 50, 0.01, granted=t0 + 50, expires=now + 900, v=2,
              res={"net_up": {"ask": 20, "got": 20, "used": 26, "gb": 5, "moved": 6.1, "flag": "over", "over_t": now - 30}}),
        lease("n3", t0 + 100, 2.0, granted=t0 + 100, v=2,
              res={"ram": {"ask": 2, "got": 2}, "net": {"ask": 200, "min": 100, "got": 150.5, "used": 3, "gb": 12.25,
                                                        "moved": 0.04, "eta": now + 7200, "flag": "idle", "low_t": now - 700},
                   "net_up": {"ask": 10, "got": 10}},
              segments=[{"t": t0 + 100, "gb": 2, "res": {"ram": 2, "net": 200}},
                        {"t": t0 + 900, "gb": 2, "res": {"ram": 2, "net": 150.5}}]),
        lease("n4", t0 + 150, 0.01, v=2, waiting_on=["net.quota"], res={"net": {"ask": 50, "min": 50, "gb": 8}}),
        lease("n5", t0 + 200, 0.01, granted=t0 + 200, v=2,
              res={"net": {"ask": "fast", "got": -5, "gb": 1e9, "moved": True, "eta": "soon", "unmanaged": 1}}),
        lease("n6", t0 + 250, 0.01, v=2, res={"net": {"ask": 80}}),
        # granted unmanaged with the rate it asked kept (the network changed to one without a figure): no rate held
        lease("n7", t0 + 300, 0.01, granted=t0 + 300, v=2,
              res={"net": {"ask": 200, "min": 100, "gb": 40, "unmanaged": True, "moved": 1.5}}),
        lease("n8", t0 + 350, 0.01, v=2, res={"net_up": {"ask": 20, "min": 10}})]}   # waiting, upload only
    odd_net_recs = [{"event": "end", "key": "z1@%d" % int(t0 - 2000), "id": "z1", "purpose": "p z1", "gb": 0.01,
                     "requested": t0 - 2000, "granted": t0 - 2000, "ended": t0 - 50, "outcome": "released", "v": 2,
                     "res": {"net": 150, "net_gb": 40, "net_up": 20, "net_up_gb": 0.41, "net_network": "rmac:x"}}]
    for shown, focus, pool in ((["net"], "net", None), (["memory", "net"], "memory", None), (["memory"], "memory", None)):
        v["rows"].append({"now": now, "records": odd_net_recs, "ledger": odd_net, "shown": shown, "focus": focus,
                          "pool": pool, "day": 3})
    # another machine's leases as its mirror carries them (no `res`, no `waiting_on`, no `v`): a queued one of gb 0.01
    # reads "waiting" (N4-4), a granted one keeps its 0.0G memory row as in 1.14.2, one with memory waits for memory
    mirror = {"seq": 50, "v": 2, "history": [], "leases": [
        {k: x for k, x in lease("m1", t0, 0.01, granted=t0, expires=now + 600).items() if k != "holder"},
        {k: x for k, x in lease("m2", t0 + 50, 0.01).items() if k != "holder"},
        {k: x for k, x in lease("m3", t0 + 100, 4.0).items() if k != "holder"}]}
    for shown, focus in ((["memory", "net"], "memory"), (["net"], "net"), (["cpu"], "cpu")):
        v["rows"].append({"now": now, "records": [], "ledger": mirror, "shown": shown, "focus": focus, "pool": None,
                          "day": 0})
    v["band_stack"].append({"now": now, "records": nrecs, "ledger": nledger, "kind": "net", "pool": None})
    v["band_stack"].append({"now": now, "records": odd_net_recs, "ledger": odd_net, "kind": "net", "pool": None})
    for line in (None, 187.5, 28.0, 0.5):
        for tallest in (0, 0.5, 94, 150, 187.5, 244, 70000):
            v["band_top"].append({"tallest": tallest, "kind": "net", "line": line})


def band_answers(v, out):
    """What oomph_view answers for B3's inputs (band_cases)."""
    for c in v["rows"]:
        all_ = V.merge_reservations(c["records"], c["ledger"], c["now"])
        waiting, granted, _ = V.ordered_res(all_, flags_first=True)
        rows, rest = V.rv_split(waiting + granted, c["shown"])
        out["rows"].append({"bands": V.bands(all_, c["shown"], c["focus"], c["pool"]),
                            "rows": [[r["key"], V.amounts_text(r, c["pool"]), V.status_text(r, c["shown"], c["focus"], c["now"])]
                                     for r in rows],
                            "rest": [r["key"] for r in rest], "caption": V.caption_text(rows, c["shown"], c["day"]),
                            "other": V.other_text(rest), "other_short": V.other_text(rest, short=True)})
    for c in v["band_stack"]:
        rs = [r for r in V.merge_reservations(c["records"], c["ledger"], c["now"]) if V.holds(r, c["kind"], c["pool"], band=True)]
        out["band_stack"].append([{"key": b["res"]["key"], "lane": b["lane"], "steps": [list(st) for st in b["steps"]]}
                                  for b in V.stack_reservations(rs, c["now"], c["kind"])])
    out["band_top"] = [V.band_top(c["tallest"], c["kind"], c.get("line")) for c in v["band_top"]]


def tile_answer(t):
    """What the vectors keep of a tile: its words, its flag slot as drawn, its level, queue and top; its short reading,
    the network's note and the flag as a narrow tile draws it (NET 12.15)."""
    return [t["reading"], V.flag_text(t), t["level"], t["queue"], t["top"], t["meter"], t.get("short"), t.get("note"),
            V.flag_text(t, short=True)]


def fixture_hover():
    """The hover card over every column of the 80 x 24 frame at 6 h (the golden frame 80x24-inspect), on the
    fixture of the golden frames (tools/topfixture.py), with the points, gaps, events, incidents and
    reservations `oomph top` loads from it: its inspect readout and the app's card on the same data."""
    import shutil
    import tempfile
    import oomph
    import topfixture
    base = tempfile.mkdtemp(prefix="oomph-vectors-")
    out = []
    try:
        log, led = topfixture.write_fixture(os.path.join(base, "fx"), "default")
        oomph.LEDGER_DIR = led
        with open(os.path.join(log, "events.jsonl")) as f:
            events = [json.loads(x) for x in f if x.strip()]
        incidents = []
        for iid in sorted(os.listdir(os.path.join(log, "incidents"))):
            with open(os.path.join(log, "incidents", iid, "incident.json")) as f:
                incidents.append(json.load(f))
        for span, every in (("6h", 1),):
            m = oomph_top.load_model(span, topfixture.NOW, log_dir=log, live=False)
            W, lo = 73, m["now"] - V.SPANS[span] - 120          # the plot of an 80-column frame; what it can show
            res = [{"id": r["id"], "key": r["key"], "purpose": r["purpose"], "project": r["project"],
                    "requested": r["requested"], "granted": r["granted"], "ended": r["ended"], "outcome": r["outcome"],
                    "gb": r["segments"][-1][1], "segments": [{"t": t, "gb": gb} for t, gb in r["segments"]]}
                   for r in m["res"] if r["ended"] is None or r["ended"] >= lo]
            out.append({"now": m["now"], "first": m["first"], "span": V.SPANS[span], "du": 1.0 / W,
                        "u": [(c + 0.5) / W for c in range(0, W, every)],
                        "points": [p for p in m["pts"] if p["t"] >= lo], "gaps": [list(g) for g in m["gaps"] if g[1] >= lo],
                        "events": events, "incidents": incidents, "reservations": res})
    finally:
        shutil.rmtree(base, ignore_errors=True)
    return out


def axis_start(oldest, first_point, now):
    """TimeAxis.start: the oldest of another machine's reported oldest sample and the first point loaded;
    the first point alone for this Mac (no oldest), now without either. `oomph top` gets the same start for
    a mirror from the not-received stretches, which begin at that oldest sample (oomph_view.mirror_gaps)."""
    if oldest is None:
        return now if first_point is None else first_point
    return oldest if first_point is None else min(oldest, first_point)


def python_answers(v):
    """What oomph_view answers for the inputs of v, in the shape `oomph --chart-vectors` prints."""
    out = {g: [] for g in GROUPS}
    for c in v["mapper"]:
        f, _ = V.mapper(c["now"], c["first"], c["span"])
        out["mapper"].append([f(t) for t in c["t"]])
    for c in v["invert"]:
        first = axis_start(c.get("oldest"), c["first"], c["now"])
        f, _ = V.mapper(c["now"], first, c["span"])
        out["invert"].append([c["now"] - V.time_at(u, f, first, c["now"]) for u in c["u"]])
    out["color_index"] = [V.res_color_index(c["purpose"]) for c in v["color_index"]]
    out["strip_top"] = [V.strip_top(c["tallest"]) for c in v["strip_top"]]
    for c in v["multires"]:
        out["multires"].append([[p["t"], p["wired"], p["app"], p["comp"], p["swap"], p["away"], p["kills"]]
                                for p in V.multires(c["points"], c["now"])])
    for c in v["gaps"]:
        out["gaps"].append([list(g) for g in V.find_gaps(c["points"], c["now"])])
    for c in v["calm_bands"]:
        grey, hatched = V.calm_bands([tuple(a) for a in c["away"]], [tuple(g) for g in c["gaps"]], c["tolerance"])
        out["calm_bands"].append({"grey": [list(s) for s in grey], "hatched": [list(s) for s in hatched]})
    for c in v["stack"]:
        rs = [V._norm(o) for o in c["reservations"]]
        out["stack"].append([{"key": b["res"]["key"], "lane": b["lane"], "steps": [list(st) for st in b["steps"]]}
                             for b in V.stack_reservations(rs, c["now"])])
    for c in v["order"]:
        rs = (V.merge_reservations([], c["ledger"], c["now"]) if "ledger" in c else
              [V._norm(o) for o in c["reservations"]])
        waiting, granted, _ = V.ordered_res(rs)
        out["order"].append([r["key"] for r in waiting + granted])
    for c in v["merge"]:
        gone = set(c.get("gone") or ())
        rs = V.merge_reservations(c["records"], c["ledger"], c["now"], lambda pid: pid not in gone)
        out["merge"].append([{"key": r["key"], "ended": r["ended"], "outcome": r["outcome"],
                              "gb": r["segments"][-1][1], "segments": len(r["segments"])} for r in rs])
    for c in v["hover"]:
        f, _ = V.mapper(c["now"], c["first"], c["span"])
        evs = sorted((x for x in (oomph_top.chart_event(e) for e in c["events"]) if x), key=lambda e: e.t)
        incs = [oomph_top.incident_of(i, i["id"]) for i in c["incidents"]]
        blocks = V.stack_reservations([V._norm(o) for o in c["reservations"]], c["now"])
        answers = []
        for u in c["u"]:
            i = V.hover_info(c["points"], [tuple(g) for g in c["gaps"]], incs, evs, blocks, c["now"], c["first"], f, u,
                             c["du"])
            answers.append({"when": i["when"], "ago": i["ago"], "samples": i["samples"], "peak": i["peak"],
                            "away": i["away"], "readings": [list(r) for r in i["readings"]], "no_data": i["no_data"],
                            "incidents": i["incidents"], "events": [list(e) for e in i["events"]],
                            "more_events": i["more_events"], "reserved": [r[0] for r in i["reserved"]],
                            "more_reserved": i["more_reserved"]})
        out["hover"].append(answers)
    for c in v["selection"]:
        out["selection"].append(list(V.selection_apply(c["sel"], c["focus"], c["gesture"], c["res"], c["avail"])))
    for c in v["capsule"]:
        out["capsule"].append(oomph.capsule(c["sample"]))
    for c in v["tiles"]:
        recent = [tuple(r) for r in c["recent"]] if "recent" in c else None
        t = V.tiles(c["sample"], oomph.capsule(c["sample"]), c["waiting"], recent, c.get("hint", False))
        out["tiles"].append([tile_answer(t[r]) for r in V.RESOURCES])
    out["net_scale"] = [V.net_scale(c["top"]) for c in v["net_scale"]]
    for c in v["net_row"]:
        row = V.multires(c["points"], c["now"])

        def r3(x):
            return None if x is None else round(x, 3)
        most = max([max(p.get("ndp", p["nd"]) or 0.0, p.get("nup", p["nu"]) or 0.0) for p in row] + [0.0])
        out["net_row"].append({"scale": V.net_scale(max(c["cap"] + [most])),
                               "points": [[p["t"], r3(p["nd"]), r3(p["nu"]), r3(p.get("ndp", p["nd"])),
                                           r3(p.get("nup", p["nu"])), p["nf"], p.get("nk", 0)] for p in row]})
    out["agent"] = [V.agent_index(c["agent"]) for c in v["agent"]]
    band_answers(v, out)
    return out


def expected(v):
    return {g: [c["out"] for c in v[g]] for g in GROUPS}


def same(a, b, tol):
    if isinstance(a, bool) or isinstance(b, bool) or a is None or b is None or isinstance(a, str):
        return a == b
    if isinstance(a, (int, float)):
        return isinstance(b, (int, float)) and abs(a - b) <= tol
    if isinstance(a, list):
        return isinstance(b, list) and len(a) == len(b) and all(same(x, y, tol) for x, y in zip(a, b))
    return isinstance(b, dict) and a.keys() == b.keys() and all(same(a[k], b[k], tol) for k in a)


def compare(want, got, tol, who):
    """One line per group; the number of groups that differ."""
    bad = 0
    for g in GROUPS:
        ok = same(want[g], got.get(g), tol)
        bad += not ok
        print("  %-12s %s (%d case%s)" % (g, "agree" if ok else "DIFFER", len(want[g]), "" if len(want[g]) == 1 else "s"))
        if not ok:
            print("     expected: %s" % json.dumps(want[g])[:400])
            print("     %-9s %s" % (who + ":", json.dumps(got.get(g))[:400]))
    return bad


def run_app(app, path):
    p = subprocess.run([app, "--chart-vectors", path], capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        raise RuntimeError("%s --chart-vectors exited %d: %s" % (app, p.returncode, p.stderr.strip()[-300:]))
    return json.loads(p.stdout)


def _round(x):
    """The app's answers as stored: floats to 9 decimals (the tolerance is 1e-6)."""
    if isinstance(x, float):
        return round(x, 9)
    if isinstance(x, list):
        return [_round(y) for y in x]
    if isinstance(x, dict):
        return {k: _round(y) for k, y in x.items()}
    return x


def dumps(x, ind=""):
    """JSON with one line per container that fits in 110 characters: reviewable diffs, small file."""
    flat = json.dumps(x, ensure_ascii=False)
    if len(ind) + len(flat) <= 110 or not isinstance(x, (list, dict)) or not x:
        return flat
    inner = ind + " "
    if isinstance(x, list):
        return "[\n%s\n%s]" % (",\n".join(inner + dumps(y, inner) for y in x), ind)
    return "{\n%s\n%s}" % (",\n".join("%s%s: %s" % (inner, json.dumps(k, ensure_ascii=False), dumps(y, inner))
                                     for k, y in x.items()), ind)


def write(app):
    import tempfile
    v = dict(v=1, tolerance=1e-6, about="Inputs and the app's answers (oomph --chart-vectors); written by "
             "tools/chartvectors.py --write, checked against both programs.")
    v.update(cases())
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(v, f)
    try:
        got = run_app(app, f.name)
    finally:
        os.unlink(f.name)
    for g in GROUPS:
        if len(got.get(g) or []) != len(v[g]):
            raise RuntimeError("the app answered %d cases of %s, not %d" % (len(got.get(g) or []), g, len(v[g])))
        for c, out in zip(v[g], got[g]):
            c["out"] = _round(out)
    with open(FILE, "w", encoding="utf-8") as f:
        f.write(dumps(v) + "\n")
    print("chartvectors: wrote %s (%s)" % (os.path.relpath(FILE, ROOT), ", ".join("%d %s" % (len(v[g]), g) for g in GROUPS)))


def main(argv):
    app = argv[argv.index("--app") + 1] if "--app" in argv and argv.index("--app") + 1 < len(argv) else None
    try:
        if "--write" in argv:
            if not app:
                print(__doc__)
                return 2
            write(app)
            return 0
        with open(FILE, encoding="utf-8") as f:
            v = json.load(f)
        if app:
            who, got = "app", run_app(app, FILE)
        else:
            who, got = "python", python_answers(v)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as e:
        print("chartvectors: %s" % e)
        return 2
    bad = compare(expected(v), got, v["tolerance"], who)
    print("chartvectors: %s and tools/vectors/chart.json %s" % (
        "the app" if app else "oomph_view.py", "agree in all %d groups" % len(GROUPS) if not bad else "DIFFER in %d group(s)" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
