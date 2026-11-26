#!/usr/bin/python3 -I
"""Tests of how 1.15 shows the internet line (roadmap NET-concept §7, §12.15, §12.16, D-N17; step N4), on the Python side
(tools/vectors/chart.json holds the app to the same words and numbers): the fifth tile only where the logger reports a
network, its reading, meter, flag and line 4 in every state (no figure, a figure, busy, metered, under 10 % left,
offline, the stale hint each way, the system's "metered?"), a lease's network parts (granted, queued, unmanaged, a
record of the history log) as a row's amounts, its status and its band, the scales, the mirror's current sample carrying
the line's pools without the network's key or label, and `oomph top`'s frames of the network fixture in every glyph set
and colour depth (w and W, the mirrored plot, the band, the `a` panel of names, the help). Unprivileged and portable (no
traffic: everything is made up); folders of its own. tools/selftest.py runs it.

    /usr/bin/python3 -I -B tools/netviewtest.py
"""
import json
import os
import shutil
import sys
import tempfile
import time

os.environ["TZ"] = "Europe/Berlin"
time.tzset()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="oomph-netviewtest-")
os.environ.update(OOMPH_DIR=os.path.join(TMP, "log"), OOMPH_LEDGER_DIR=os.path.join(TMP, "ledger"),
                  OOMPH_STATE_DIR=os.path.join(TMP, "state"), TMPDIR=os.path.join(TMP, "tmp"))
for d in ("log", "tmp"):
    os.makedirs(os.path.join(TMP, d))
sys.path.insert(0, os.path.join(ROOT, "daemon"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import oomph  # noqa: E402
import oomph_sync  # noqa: E402
import oomph_top as T  # noqa: E402
import oomph_view as V  # noqa: E402
import topfixture  # noqa: E402

failures = []


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)


KEY = "rmac:00:00:5e:00:53:01"
NB = {"if": "en0", "vpn": False, "network": KEY, "src": "flows", "flows": 87, "down_mbps": 212.4, "up_mbps": 8.14,
      "lan_mbps": 0.1}
DOWN = {"network": KEY, "cap": 250.0, "margin": 62.5, "reserved": 150.0, "busy": 212.4, "others": 8.0}
UP = {"network": KEY, "cap": 40.0, "margin": 12.0, "reserved": 0.0, "busy": 8.1, "others": 1.0}
Q = {"network": KEY, "cap": 20.0, "margin": 2.0, "used": 12.4, "from": 1.0, "to": 2.0, "period": "month", "label": "phone"}


def tile(s, recent=None, hint=False):
    return V.net_tile(s, recent, hint)


def test_tile():
    base = {"t": 1.0, "ram_gb": 36.0, "app_gb": 10, "wired_gb": 5, "compressed_gb": 1, "pressure": 1,
            "swap_used_gb": 0, "swap_total_gb": 0, "disk_free_gb": 80}
    check(V.available(base) == ["memory", "cpu", "gpu", "disk"] and V.available(dict(base, net=NB))[-1] == "net"
          and V.available(dict(base, net="x")) == V.available(base) and "net" not in V.available(None),
          "tile: a fifth tile only where the logger reports a network (a logger before 1.15: four, 12.15)")
    t = tile({"net": NB, "net_names": [{"name": "Chrome", "down": 3.0, "up": 0.2, "n": 9},
                                       {"name": "curl", "down": 205.0, "up": 0.3, "n": 1}]})
    check(t["reading"] == "↓212 ↑8.1" and t["short"] == t["reading"] and t["meter"] == 0 and t["top"] == "curl" and
          t["note"] == "line not tested" and t["flag"] is None,
          "tile: without a figure ↓/↑ now, no fill, the busiest name, and \"line not tested\" on line 4 (%s)" % t)
    t = tile({"net": NB, "pools": {"net.down": DOWN, "net.up": UP}})
    check(abs(t["meter"] - 212.4 / 250) < 1e-9 and t["note"] is None and t["flag"] is None,
          "tile: with a figure the meter is the download against it (%.3f)" % t["meter"])
    t = tile({"net": NB, "pools": {"net.down": dict(DOWN, level="busy"), "net.up": UP}})
    check(t["flag"] == "busy" and t["level"] == 0, "tile: the logger's level busy is the flag busy, never a warning")
    t = tile({"net": NB, "pools": {"net.down": DOWN, "net.up": UP, "net.quota": Q}})
    check(t["flag"] == "metered · 12/20 GB" and t["level"] == 0 and V.flag_text(t, short=True) == "12/20 GB",
          "tile: a metered network says what of its cap is used (%r), short in a narrow tile" % t["flag"])
    t = tile({"net": NB, "pools": {"net.quota": dict(Q, used=18.2)}})
    check(t["flag"] == "1.8 GB left" and t["level"] == 1 and t["note"] == "line not tested",
          "tile: under 10 %% of the cap left the flag is amber, with what is left (%r)" % t["flag"])
    t = tile({"net": NB, "pools": {"net.quota": dict(Q, used=30.0)}})
    check(t["flag"] == "0.0 GB left", "tile: past the cap nothing is left, never a negative figure")
    t = dict(tile({"net": NB, "pools": {"net.down": DOWN}}), queue=2)
    check(V.flag_text(t) == "2 waiting" and V.flag_text(t, short=True) == "◻2",
          "tile: requests waiting for the line are counted on its tile")
    check(tile({"net": {"if": None}})["reading"] == "offline" and tile({"net": {"if": 5}})["reading"] == "offline" and
          tile({})["reading"] == "–" and tile({"net": dict(NB, down_mbps=1e300, up_mbps="x")})["reading"] == "↓– ↑–",
          "tile: offline without an interface, \"–\" without a block, a figure oomph could not have written is none")
    flows = [(300.0, 7.0, True), (310.0, 8.0, True), (320.0, 9.0, True)]
    pools = {"net.down": DOWN, "net.up": UP}
    st = tile({"net": NB, "pools": pools}, flows)
    check(st["note"] == "seen 310 > 250", "tile: the last three samples above 1.1 x the figure: the stale hint (%r)"
          % st["note"])
    check(tile({"net": NB, "pools": pools}, [(300.0, 7, True), (310.0, 8, False), (320.0, 9, True)])["note"] is None and
          tile({"net": NB, "pools": pools}, flows[1:])["note"] is None and
          tile({"net": NB, "pools": pools}, [(270.0, 7, True)] * 3)["note"] is None,
          "tile: no stale hint from totals only, from fewer than three samples, or within 10 % of the figure")
    check(tile({"net": NB, "pools": pools}, [(9.0, 46.0, True)] * 3)["note"] == "seen ↑46 > 40",
          "tile: the upload's stale hint says so")
    k = V.net_key(NB)
    keyed = [(300.0, 7.0, True, k), (310.0, 8.0, True, k), (320.0, 9.0, True, k)]
    check(1 <= k <= 127 and V.net_key({"if": "en0"}) == 0 and V.net_key(None) == 0 and
          tile({"net": NB, "pools": pools}, keyed)["note"] == "seen 310 > 250" and
          tile({"net": NB, "pools": pools}, [(900.0, 7.0, True, k % 127 + 1)] + keyed[1:])["note"] is None and
          tile({"net": NB, "pools": pools}, keyed[:2] + [(320.0, 9.0, True, V.NET_MIXED)])["note"] is None,
          "tile: no stale hint from samples of the network before a move, nor from a bucket that spans one (12.8)")
    agg = V.res_agg([{"nd": 1.0, "nu": 1.0, "nf": True, "nk": 3}, {"nd": 2.0, "nu": 1.0, "nf": True, "nk": 4}])
    check(agg["nk"] == V.NET_MIXED and V.res_agg([{"nd": 1.0, "nu": 1.0, "nf": True, "nk": 3}] * 2)["nk"] == 3,
          "tile: a bucket keeps its samples' network mark, or says they were on more than one")
    check(V.net_gutter(500, "↓") == "↓500" and V.net_gutter(20000, "↓") == "↓20k" and V.net_gutter(1e6, "↓") == "↓1G",
          "plot: the gutter's scale stays within five cells up to the most a rate can be")
    check(tile({"net": NB}, None, True)["note"] == "metered?" and
          tile({"net": NB, "pools": {"net.quota": Q}}, None, True)["note"] == "line not tested" and
          tile({"net": NB, "pools": pools}, flows, True)["note"].startswith("seen"),
          "tile: the system's \"metered?\" only while the network has no cap, after the stale hint")
    for top, want in ((0, 1), (1, 1), (2.5, 5), (194, 200), (250, 500), (1000, 1000), (1000.1, 2000)):
        check(V.net_scale(top) == want, "scale: %s Mbit/s → 0 … %s (1, 2, 5 × 10ⁿ)" % (top, want))


def lease(i, req, now, part=None, granted=True, **more):
    return dict({"id": i, "key": "%s@%d" % (i, int(req)), "state": "granted" if granted else "queued", "gb": 0.01,
                 "purpose": "p " + i, "requested": req, "seen": now - 2, "v": 2, "res": {"net": part},
                 "holder": {"pid": 1, "start": 1, "kind": "session"}}, **({"granted": req} if granted else {}), **more)


def test_leases():
    now = 1795180000.0
    g = V._norm(lease("r1", now - 600, now, {"ask": 200, "min": 100, "got": 150, "used": 143.2, "gb": 40, "moved": 12.3,
                                             "eta": now + 1440, "network": KEY}))
    q = V._norm(lease("r2", now - 60, now, {"ask": 94, "min": 47, "gb": 8}, granted=False, waiting_on=["net.down"]))
    u = V._norm(lease("r3", now - 30, now, {"gb": 40, "unmanaged": True, "network": "gw:192.0.2.1/24"}))
    up = V._norm(dict(lease("r4", now - 30, now, None), res={"net_up": {"ask": 20, "got": 20, "gb": 5, "moved": 0.4}}))
    rec = V._norm({"event": "end", "key": "r5@1", "id": "r5", "purpose": "pull", "gb": 0.01, "requested": now - 9000,
                   "granted": now - 9000, "ended": now - 3000, "v": 2,
                   "res": {"net": 150, "net_gb": 40, "net_network": KEY}})
    check([V.holds(r, "net") for r in (g, q, u, up, rec)] == [True] * 5 and not any(V.holds(r, "memory") for r in (g, q, u)),
          "lease: a rate, a volume, an upload part or a record holds the network; a lease of the network alone no memory")
    check([V.amounts_text(r) for r in (g, q, u, up, rec)] ==
          ["150 Mbit/s · 40 GB", "94 Mbit/s · 8 GB", "↓40 GB", "↑20 Mbit/s · ↑5 GB", "150 Mbit/s · 40 GB"],
          "lease: its amounts as the row says them (12.15): %s" % [V.amounts_text(r) for r in (g, q, u, up, rec)])
    check(V.status_text(g, ["net"], "net", now) == "12.3 of 40 GB · ≈ 24 min left" and
          V.status_text(q, ["net"], "net", now) == "waiting 60 s · for the network" and q["waiting"] == ["net"],
          "lease: what it moved and when it should be done; a request waiting for the line says so (%r, %r)"
          % (V.status_text(g, ["net"], "net", now), V.status_text(q, ["net"], "net", now)))
    over = V._norm(lease("r6", now - 600, now, {"ask": 100, "got": 100, "used": 140, "flag": "over", "over_t": now - 60}))
    check(V.status_text(over, ["memory", "net"], "memory", now).startswith("over on the network"),
          "lease: a grant over its rate is flagged on the network")
    check(V.caption_text([g, q, u, up], ["net"], 3) == "150 Mbit/s · ↑20 Mbit/s · 3 in the last 24 h" and
          "waiting for the network" in V.other_text([q], short=False),
          "lease: the caption sums the rates granted each way; the line for the rest names a request waiting for the network")
    um = V._norm(lease("r7", now - 30, now, {"ask": 200, "min": 100, "gb": 40, "unmanaged": True}))
    check(V.res_vector({"granted": 2, "res": {"net": {"ask": 200, "min": 100, "unmanaged": True, "gb": 40}}}) ==
          {"mem": False, "net_gb": 40, "net_unmanaged": True} and V.amounts_text(um) == "↓40 GB" and
          V.caption_text([um], ["net"], 1) == "1 in the last 24 h" and
          all(st[3] == 0 for b in V.stack_reservations([um], now, "net") for st in b["steps"]),
          "lease: an unmanaged part holds no rate, whatever it asked: no Mbit/s in its row, the caption or the band")
    # another machine's lease as its mirror carries it: no `res`, no `waiting_on`, no memory (its network's parts
    # do not travel): "waiting", never "0G … for memory" (N4-4); one with memory still waits for memory
    rq = V._norm({"id": "r9", "state": "queued", "gb": 0, "purpose": "docker pull", "requested": now - 120})
    rm = V._norm({"id": "r10", "state": "queued", "gb": 8, "purpose": "build", "requested": now - 60})
    check(V.res_vector({"state": "queued", "gb": 0}) == {"mem": False} and
          V.status_text(rq, ["memory", "net"], "net", now) == "waiting 2 min" and V.amounts_text(rq) == "–" and
          V.status_text(rm, ["memory", "net"], "net", now) == "waiting 60 s · for memory",
          "lease: another machine's queued lease without memory reads just waiting (%r, %r)" % (
              V.status_text(rq, ["memory", "net"], "net", now), V.amounts_text(rq)))
    # ... but a granted one stays as 1.14.2 had it (a 0.0G memory row): a remote CPU-, disk- or GPU-only grant
    # carries gb 0.01 and no `res` too, and must not fall into "On other resources: " with nothing after it
    rg = V._norm({"id": "r11", "state": "granted", "gb": 0.01, "purpose": "render", "requested": now - 300,
                  "granted": now - 290})
    check(V.res_vector({"state": "granted", "gb": 0.01, "granted": now - 290}) == {} and V.holds(rg, "memory") and
          V.rv_split([rg], ["memory", "net"]) == ([rg], []),
          "lease: another machine's granted lease of gb 0.01 keeps its row, not an empty 'other' line (%r)"
          % V.res_vector({"state": "granted", "gb": 0.01, "granted": now - 290}))
    upq = V._norm(dict(lease("r8", now - 30, now, None, granted=False), res={"net_up": {"ask": 20, "min": 10}}))
    check(V.holds(up, "net") and not V.holds(up, "net", band=True) and V.bands([up], ["net"], "net") == [] and
          upq["waiting"] == ["net"],
          "lease: an upload part alone has a row but no block in the line's band (the download's)")
    check(V.bands([g, q], ["memory", "net"], "net") == ["net"] and V.bands([g], ["memory"], "memory") == [] and
          V.bands([g, rec], ["memory", "cpu", "net"], "memory") == ["net"],
          "band: the network has one where something held it in the 14 days and it is shown")
    blocks = V.stack_reservations([g, q], now, "net")
    check(blocks and blocks[0]["steps"][0][3] == 150 and blocks[1]["steps"][-1][3] == 150 + 94,
          "band: the line's blocks stack the rates, the waiting request on top")
    check(V.band_top(150, "net", 187.5) == 187.5 and V.band_top(244, "net", 187.5) == 500 and V.band_top(3, "net") == 5
          and V.band_scale(187.5, "net") == "187M",
          "band: its scale is what the line can share (cap less the margin), else 1, 2, 5 × 10ⁿ")


def test_mirror():
    cur = {"t": 1795180000.0, "ram_gb": 36.0, "app_gb": 10, "net": dict(NB),
           "net_names": [{"name": "curl", "down": 200.0, "up": 0.3, "n": 1}],
           "pools": {"t": 1795180000.0, "cpu": {"cap": 14}, "net.down": DOWN, "net.up": dict(UP, level="busy"),
                     "net.quota": Q}}
    full = oomph.full_sample(cur)
    p = full.get("pools") or {}
    text = json.dumps(full)
    check(set(p) == {"t", "net.down", "net.up", "net.quota"} and p["net.down"]["cap"] == 250.0 and
          p["net.up"]["level"] == "busy" and p["net.quota"]["used"] == 12.4 and KEY not in text and "phone" not in text
          and "network" not in full["net"] and full["net_names"][0]["name"] == "curl",
          "mirror: another machine's tile gets the line's figures, what agents hold, its cap: never the key or label")
    check("pools" not in oomph.slim_sample(cur) and oomph_sync.gb_ok(full, 36.0),
          "mirror: the history's slim samples carry no pools; the current sample passes the mirror's checks")
    t = V.net_tile(full)
    check(t["reading"] == "↓212 ↑8.1" and t["flag"] == "metered · 12/20 GB" and t["top"] == "curl" and t["note"] is None,
          "mirror: a remote tab's Network tile reads the same from it (%s)" % [t["reading"], t["flag"], t["note"]])


def test_real_mirror():
    """The network machine mirrored through the real `oomph serve --stdio` and `oomph remote sync --once`
    (tools/mirrorfixture.py's "network" scene): the tile and the chart of a remote tab have what they read."""
    import contextlib
    import io
    import mirrorfixture
    d = os.path.join(TMP, "mirror")
    keep = dict(os.environ)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            rc = mirrorfixture.main([d, "network"])
    finally:
        os.environ.clear()
        os.environ.update(keep)
    log = os.path.join(d, "mirror", "log")
    cur = json.load(open(os.path.join(log, "current.json")))
    t = V.net_tile(cur)
    last = None
    for n in sorted(os.listdir(log)):
        if n.startswith("samples-") and n.endswith(".jsonl"):
            last = json.loads(open(os.path.join(log, n)).read().splitlines()[-1])
    raw = open(os.path.join(log, "current.json")).read()
    check(rc == 0 and t["reading"] == "↓174 ↑1.2" and t["top"] == "curl" and t["note"] is None and t["meter"] > 0.6 and
          last and last["net"].get("down_mbps") == 174.4 and "network" not in last["net"] and KEY not in raw,
          "mirror: through the real protocol a remote tab gets the line's rates in every sample and its figures and "
          "busiest names now; the router's MAC stays home (%s)" % [rc, t["reading"], t["top"], t["note"]])


def frames():
    base = os.path.join(TMP, "frames")
    log, led = topfixture.write_fixture(os.path.join(base, "net"), "network")
    oomph.LEDGER_DIR = led
    out = {}
    for name, glyphs, color, keys in (("plot", "unicode", "256", "w"), ("ascii", "ascii", "256", "w"),
                                      ("cp437", "cp437", "16", "w"), ("mono", "unicode", "none", "w"),
                                      ("cells", "cells", "truecolor", "w M C"), ("panel", "unicode", "256", "w a"),
                                      ("help", "unicode", "256", "?"), ("memory", "unicode", "256", ""),
                                      ("wide", "unicode", "256", "w M"), ("light", "unicode", "truecolor", "W")):
        model = T.load_model("6h", topfixture.NOW, log_dir=log, live=False, rv={"sel": ["memory"], "focus": "memory"})
        model.update(host="studio", os="macOS 15")
        w, h = (160, 48) if name == "wide" else (80, 32)
        ui = topfixture.press_keys(model, w, h, "6h", keys)
        caps = V.Caps(color, glyphs, "light" if name == "light" else "dark")
        out[name] = (V.render(model, w, h, caps, ui), model)
    return out


def test_frames():
    fr = frames()
    text = {k: f.text() for k, (f, _) in fr.items()}
    check("Network" in text["memory"] and "↓174 ↑1.2" in text["memory"] and "Down" not in text["memory"],
          "top: the fifth tile with ↓/↑ now; Memory keeps the plot until w")
    check("Down 174" in text["plot"] and "↓500" in text["plot"] and "↑500" in text["plot"] and
          any(c in text["plot"] for c in "▁▂▃▄▅▆▇█"),
          "top: w gives the network the plot, download above, upload below, the scale both ways in the gutter")
    check(all(ord(c) < 128 for c in text["ascii"]) and "v174 ^1.2" in text["ascii"] and "v500" in text["ascii"],
          "top: the ASCII glyphs say v and ^ for the arrows, nothing else outside ASCII")
    ok437 = True
    glyphs = "☺☻♥♦♣♠•◘○◙♂♀♪♫☼►◄↕‼¶§▬↨↑↓→←∟↔▲▼⌂"     # the font's pictures of 0x01-0x1F (Python's codec has controls)
    for c in text["cp437"]:
        try:
            c.encode("cp437")
        except UnicodeEncodeError:
            ok437 = ok437 and c in glyphs
    check(ok437 and "↓174" in text["cp437"], "top: on the Linux console every character of the network's frame is in code "
                                               "page 437 (the arrows are)")
    check(not V.lint_pairing(fr["cells"][0]) and not V.lint_pairing(fr["plot"][0]) and " Mem" in text["cells"] and
          " CPU" in text["cells"], "top: the colour rule holds; M and C add their rows under the network's plot")
    check("Top network" in text["panel"] and "curl" in text["panel"] and "Mbit/s ↓ ↑" in text["panel"],
          "top: a on the network's plot lists the busiest names on the line, down and up")
    check("m c g d w" in text["help"] and "M C G D W" in text["help"],
          "top: the help names w and W where the network has a tile")
    check("Net" in text["wide"] and "for the network" in text["wide"],
          "top: the line's band and a request waiting for the network in the list")
    check("Down" not in text["light"] and "Network" in text["light"],
          "top: W adds the network without giving it the plot")
    m = dict(fr["memory"][1], avail=["memory", "cpu", "gpu", "disk"])
    hl = "\n".join(V.render(m, 80, 32, V.Caps("256", "unicode", "dark"), {"span": "6h",
                                                                         "overlay": {"kind": "help", "page": 1,
                                                                                     "off": 0}}).text().split("\n"))
    check("m c g d w" not in hl and "m c g d" in hl, "top: without a network tile the help keeps m c g d")
    # a hostile mirror's process count is clamped as the app clamps it (N4-3): 1 … 9999, never a 300-digit number
    rd = T.readings({"pressure": 1, "net_names": [{"name": "a", "down": 1.0, "up": 0.0, "n": 1e300},
                                                  {"name": "b", "down": 2.0, "up": 0.0, "n": -5},
                                                  {"name": "c", "down": 0.5, "up": 0.0, "n": "x"}]})
    check(sorted(k for _, _, k, _, _ in rd["net_names"]) == [1, 1, 9999],
          "top: net_names' process counts 1 … 9999 whatever the sample says (%s)" % [k for _, _, k, _, _ in rd["net_names"]])


def main():
    t0 = time.time()
    try:
        test_tile()
        test_leases()
        test_mirror()
        test_real_mirror()
        test_frames()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("netviewtest: %s in %.1f s" % ("all passed" if not failures else "%d FAILED" % len(failures), time.time() - t0))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
