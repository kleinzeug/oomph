#!/usr/bin/python3 -I
"""Holds the chart maths of `oomph top` (daemon/oomph_view.py) to the app's (app/oomph.swift).

tools/vectors/chart.json holds inputs and the expected answers of the functions both programs
share: the mapper, thinning, gap finding, band merging, lane stacking, the strip's top, the
colour index and the reservation merge. The expected answers are the app's: `oomph
--chart-vectors FILE` runs its own functions over the inputs and prints what they return. A
change on either side that is not made on the other fails here.

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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILE = os.path.join(ROOT, "tools", "vectors", "chart.json")
sys.path.insert(0, os.path.join(ROOT, "daemon"))

import oomph_view as V  # noqa: E402

GROUPS = ("mapper", "color_index", "strip_top", "multires", "gaps", "calm_bands", "stack", "merge", "order")


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
    return v


def python_answers(v):
    """What oomph_view answers for the inputs of v, in the shape `oomph --chart-vectors` prints."""
    out = {g: [] for g in GROUPS}
    for c in v["mapper"]:
        f, _ = V.mapper(c["now"], c["first"], c["span"])
        out["mapper"].append([f(t) for t in c["t"]])
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
