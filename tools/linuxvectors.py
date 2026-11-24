#!/usr/bin/python3 -I
"""Holds the app's Linux tab (app/oomph.swift, LinuxTab; roadmap 03 §3.9, the Linux-tab gate, 1.13.3) to what the
Linux logger writes and to the gate's rules.

tools/vectors/linux.json holds inputs and the expected answers: the eight tiles for samples the real Linux
backend (daemon/oomph_linux.py) measured on recorded machines (tools/linuxfixture.py), with a few states made
from them (a desktop, stall time in its long form, a logger that sees only its own processes, a container with
zswap); the texts of oom_kill and limit_stall events; quiet incidents folded; "who" on reservation rows; the
texts of a machine that is reached but has little to show; the chart legend; group names; which systems get a
tab. The expected answers are the app's: `oomph --linux-vectors FILE` runs its own functions over the inputs.

Without the app the answers in the file are held to the gate (03 §13's "done when": no "Idle 0 s", "Wired",
"Compressed 0.0 GB", "63 GB" or "biggest app" on a Linux tab) and to the logger and the CLI: the tile matrix
follows the machine's facts (its `measures`, kind and scope), Available is RAM less app, kernel and compressed
memory, the stall figure is the sample's, an oom_kill alarms unless oomph.calm_event calls it no news; two
recorded machines are measured afresh and must give the file's memory figures; the machine's static fields are
invented (never those of the machine that measured them).

    tools/linuxvectors.py                  the rules and the CLI against the file (the self-test runs this)
    tools/linuxvectors.py --app BINARY     the app against the file (CI runs this after the build)
    tools/linuxvectors.py --app BINARY --write
                                           new inputs (cases below, measured afresh) answered by the app,
                                           written to the file; then run without --app to check them
Exit 0 when everything agrees, 1 when something differs, 2 when it could not run.
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILE = os.path.join(ROOT, "tools", "vectors", "linux.json")
DAEMON = os.path.join(ROOT, "daemon")
sys.path.insert(0, DAEMON)
sys.path.insert(0, os.path.join(ROOT, "tools"))

GROUPS = ("tiles", "event", "rows", "who", "remedy", "legend", "group_name", "labeled",
          "legend_help", "capsule", "hover", "words")   # (the last four: L3, 1.13.4)

# the backend on a recorded machine, in a child: its sample's memory part and its machine block
MEASURE = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
import oomph_linux as L
s = L.system_memory()
print(json.dumps({"s": s, "m": L.machine(all_procs=True)}))
"""

GROUPS_FX = [{"name": "docker:3f9c1a7e (nginx)", "mb": 2150, "n": 6}, {"name": "postgresql@16-main", "mb": 1200, "n": 9},
             {"name": "sshd", "mb": 12, "n": 2}]
SCENARIOS = ("ubuntu-server-idle", "pain-critical", "zram-desktop", "rhel9-nopsi", "container-2g",
             "container-thrash-roomy-host", "epyc-nvidia", "server-noswap-93pct")


def measure(scenario, tmp):
    import linuxfixture
    root = os.path.join(tmp, scenario)
    linuxfixture.build(root, scenario)
    env = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY")}
    env["OOMPH_SYSROOT"] = root
    r = subprocess.run([sys.executable, "-I", "-B", "-c", MEASURE, DAEMON], capture_output=True, text=True, timeout=60, env=env)
    if r.returncode != 0:
        raise SystemExit("could not measure %s: %s" % (scenario, r.stderr.strip()[-400:]))
    return json.loads(r.stdout)


# what the recorded machines do not cover: the backend reads its host name, kernel, architecture and cores from
# the machine it runs on, which must not land in a file that is published (it would be the build machine's)
INVENTED = {"id": "m-3f9c1a7e5b2d4c10", "name": "build-01", "kernel": "6.8.0-48-generic", "arch": "x86_64", "cpus": 48}
# a sample's memory figures, which a measurement afresh must reproduce
MEMORY = ("ram_gb", "app_gb", "wired_gb", "compressed_gb", "swap_used_gb", "swap_total_gb", "free_pct", "pressure", "psi",
          "linux", "scope")


def tile_case(name, s, m, **over):
    """A sample as the logger writes it into current.json (os, away, groups, its machine in `daemon`), the
    machine's static fields invented (INVENTED)."""
    s = dict(s, t=1795180000.0, os="linux", away={"idle_s": None, "display_on": None, "locked": False},
             groups=GROUPS_FX, disk_free_gb=s.get("disk_free_gb") or 120.0)
    m = dict(m, **INVENTED)
    for k, v in over.items():
        if k == "kind":
            m["kind"] = v
        elif k == "measures":
            m["measures"] = dict(m.get("measures") or {}, **v)
        elif k == "all_procs":
            pass
        else:
            s[k] = v
    s["daemon"] = {"interval": 30, "version": "1.13.3", "machine": m, "all_procs": over.get("all_procs", True)}
    return {"case": name, "name": "build-01", "sample": s, "machine": {"os": "linux", "kind": m.get("kind"),
                                                                       "measures": m.get("measures")}}


def cases():
    tmp = tempfile.mkdtemp(prefix="oomph-lv-")
    try:
        got = {sc: measure(sc, tmp) for sc in SCENARIOS}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    tiles = [tile_case(sc, got[sc]["s"], got[sc]["m"], kind="server") for sc in SCENARIOS]
    idle = got["ubuntu-server-idle"]
    zr = got["zram-desktop"]
    tiles += [
        tile_case("desktop, no idle time", zr["s"], zr["m"], kind="desktop"),
        tile_case("desktop, idle 7 min", zr["s"], zr["m"], kind="laptop",
                  away={"idle_s": 420, "display_on": True, "locked": False}),
        tile_case("stall, long form", idle["s"], idle["m"], kind="server",
                  psi={"mem_some": 100.0, "mem_full": 100.0, "mem_some60": 88.0, "mem_full60": 70.0}),
        tile_case("stall, fully a little", idle["s"], idle["m"], kind="server",
                  psi={"mem_some": 28.4, "mem_full": 10.2, "mem_some60": 20.0, "mem_full60": 8.0}),
        tile_case("hidepid", idle["s"], idle["m"], kind="server", all_procs=False),
        tile_case("container with zswap", got["container-2g"]["s"], got["container-2g"]["m"], kind="container",
                  measures={"zswap": True}, compressed_gb=0.3),
        tile_case("no groups yet", idle["s"], idle["m"], kind="server", groups=[]),
    ]
    ev = [
        {"t": 1795180000.0, "kind": "oom_kill", "kills": 3, "cgroup": 0, "ooms": 3, "by": {"kernel": 3},
         "top": {"java": 2, "node": 1}, "victims": []},
        {"t": 1795180000.0, "kind": "oom_kill", "kills": 1, "cgroup": 0, "ooms": 0, "by": {"systemd-oomd": 1},
         "top": {"chrome": 1}, "victims": []},
        {"t": 1795180000.0, "kind": "oom_kill", "kills": 0, "cgroup": 6, "ooms": 6, "by": {"cgroup": 6},
         "top": {"node": 6}, "victims": []},
        {"t": 1795180000.0, "kind": "oom_kill", "kills": 3, "cgroup": 0, "ooms": 0, "by": {"unknown": 3}, "top": {},
         "victims": []},
        {"t": 1795180000.0, "kind": "oom_kill", "kills": 5, "cgroup": 1, "ooms": 6, "by": {"kernel": 4, "earlyoom": 1, "cgroup": 1},
         "top": {"a": 2, "b": 1, "c": 1, "d": 1, "e": 1}, "victims": []},
        {"t": 1795180000.0, "kind": "oom_kill", "kills": 1, "cgroup": 2, "ooms": 3, "by": {"systemd-oomd": 1, "cgroup": 2},
         "top": {"node": 3}, "victims": []},
        {"t": 1795180000.0, "kind": "limit_stall", "cgroup": "docker:9d02c41b (node)"},
        {"t": 1795180000.0, "kind": "jetsam", "kills": 2, "top": {"Safari": 2}},
    ]
    inc = lambda i, t, **k: dict({"id": i, "start": t, "reasons": [{"kind": "x", "desc": "d"}]}, **k)  # noqa: E731
    rows = [
        {"incidents": [inc("20261120-031000", 1795140000.0)], "quiet": []},
        {"incidents": [inc("20261120-031000", 1795140000.0), inc("20261118-120000", 1794980000.0)],
         "quiet": [inc("20261119-080000", 1795050000.0, quiet=True), inc("20261121-080000", 1795180000.0, quiet=True),
                   inc("20261117-080000", 1794880000.0, quiet=True)]},
        {"incidents": [], "quiet": [inc("20261121-080000", 1795180000.0, quiet=True)]},
    ]
    lease = lambda u: dict({"id": "r1", "requested": 1795179000.0, "gb": 4.0, "purpose": "build"}, **({"user": u} if u else {}))  # noqa
    who = [{"leases": [lease("ada"), lease("ada")]}, {"leases": [lease("ada"), lease("kim")]}, {"leases": [lease(None), lease("kim")]},
           {"leases": []}]
    remedy = [{"state": st, "os": o, "name": "build-01", "user": u, "at": "13:02"}
              for st in ("stopped", "denied", "absent") for o, u in (("linux", "kim"), ("macos", None))]
    legend = [{"linux": a, "away": b, "missing": c} for a, b, c in
              ((False, True, False), (True, False, False), (True, True, True), (False, True, True))]
    legend += [{"linux": True, "away": False, "missing": False, "compressed": False, "swap": True},
               {"linux": True, "away": True, "missing": False, "compressed": True, "swap": False},
               {"linux": True, "away": False, "missing": True, "compressed": False, "swap": False}]
    # the series from a sample, as the app's chart and oomph top take them: a swap file without a swap total or swap
    # in use (container-2g), no swap at all, zram as the only swap
    legend += [{"linux": True, "away": False, "missing": False, "sample": t["sample"]} for t in tiles
               if t["case"] in ("container-2g", "server-noswap-93pct", "zram-desktop")]
    pt = lambda t, w, a, c, sw, some=None, full=None, limit=None: dict(  # noqa: E731
        {"t": t, "wired": w, "app": a, "comp": c, "swap": sw},
        **{k: v for k, v in (("some", some), ("full", full), ("limit", limit)) if v is not None})
    hover = [
        {"ram": 62.7, "zram": False, "swap": True, "points": [pt(1, 3.4, 14.8, 0, 0.5, 28.4, 10.2), pt(2, 3.4, 15.1, 0, 0.6, 35.0, 12.0)]},
        {"ram": 62.7, "zram": False, "swap": False, "points": [pt(1, 3.4, 14.8, 0, 0, 0.0, 0.0, 97.0)]},
        {"ram": 31.0, "zram": True, "swap": True, "points": [pt(1, 2.0, 20.0, 3.0, 1.0, 4.2, 0.0), pt(2, 2.1, 20.0, 3.1, 1.0, 4.2)]},
        {"ram": 16.0, "zram": False, "swap": True, "points": [pt(1, 1.0, 8.0, 0, 0)]},   # PSI off: no Stalled line
    ]
    names = ["docker:3f9c1a7e (nginx)", "podman:web", "pod:5d9c7e2a (runner)", "postgresql@16-main",
             "user@1000.service/app-gnome-firefox-12345.scope-long", "node"]
    return {"tiles": tiles, "event": [{"e": e} for e in ev], "rows": rows, "who": who, "remedy": remedy, "legend": legend,
            "group_name": [{"name": n} for n in names], "labeled": [{"os": o} for o in ("macos", "linux", "freebsd")],
            "hover": hover}


# ---------------------------------------------------------------------------------------------- the rules
def check_rules(v):
    """The expected answers against the gate and against the logger's own figures. A list of failures."""
    import oomph
    bad = []
    inp, exp = v["inputs"], v["expected"]
    for c, cells in zip(inp["tiles"], exp["tiles"]):
        who = "tiles %s" % c["case"]
        if not cells or len(cells) != 8:
            bad.append("%s: not eight tiles: %r" % (who, cells))
            continue
        s, m = c["sample"], c["sample"]["daemon"]["machine"]
        ms = m.get("measures") or {}
        text = " ".join("%s %s" % (x[1], x[0]) for x in cells)
        labels = [x[0] for x in cells]
        for word in ("Wired", "biggest app"):
            if word in text:
                bad.append("%s: says %r" % (who, word))
        if re.search(r"\bIdle\b", text) and "0 s Idle" in text and (s.get("away") or {}).get("idle_s") is None:
            bad.append("%s: Idle 0 s for a machine without idle time" % who)
        comp = ms.get("zram") is True or ms.get("zswap") is True
        if "0.0 GB Compressed" in text and not comp:
            bad.append("%s: Compressed 0.0 GB on a machine that compresses nothing" % who)
        if not re.fullmatch(r"\d+\.\d GB", cells[3][1]):
            bad.append("%s: RAM without its decimal: %r" % (who, cells[3][1]))
        cg = (s.get("scope") or {}).get("kind") == "cgroup"
        desk = m.get("kind") in ("desktop", "laptop")
        zram_only = ms.get("zram") is True and ms.get("zswap") is not True and not s.get("swapfiles") and s["swap_total_gb"] < 0.05
        want = ["App memory", "Compressed" if comp else "Available", "Kernel",
                ("Memory limit" if cg else "RAM total") + (" · host %.1f GB" % s["scope"]["host_ram_gb"] if cg and comp else ""),
                "zram used / size" if zram_only else "Swap used / size", "Free disk",
                "Idle" if desk else "of RAM available" if ms.get("psi") is False or not s.get("psi") else "Stalled on memory",
                "biggest group"]
        if labels != want:
            bad.append("%s: tiles %r, the matrix says %r" % (who, labels, want))
        avail = max(0.0, s["ram_gb"] - s["app_gb"] - s["wired_gb"] - s["compressed_gb"])
        if not comp and cells[1][1] != "%.1f GB" % avail:
            bad.append("%s: Available %r, the sample says %.1f GB" % (who, cells[1][1], avail))
        if cells[2][1] != "%.1f GB" % s["wired_gb"]:
            bad.append("%s: Kernel %r, the sample's wired_gb is %.1f" % (who, cells[2][1], s["wired_gb"]))
        if want[6] == "Stalled on memory":
            some = s["psi"]["mem_some"]
            if cells[6][1] != ("%.1f %%" % some if some < 9.95 else "%.0f %%" % some):
                bad.append("%s: stall %r, the sample's mem_some is %s" % (who, cells[6][1], some))
            if cells[6][5] != (some >= 10 or s["psi"].get("mem_full", 0) >= 5):
                bad.append("%s: stall red %r at %s %%" % (who, cells[6][5], some))
            if (s["psi"].get("limit") or {}).get("some", 0) >= 0.05 and not (cells[6][2] or "").endswith("▣"):
                bad.append("%s: the stall taken out at a limit is not shown: %r" % (who, cells[6][2]))
        if s["daemon"].get("all_procs") is False and (cells[7][1], cells[7][3]) != ("—", "not visible"):
            bad.append("%s: a logger that sees only itself, yet the group tile says %r" % (who, cells[7]))
        bad += top_agrees(who, s, cells)
    for c, a in zip(inp["event"], exp["event"]):
        e = c["e"]
        if e["kind"] == "oom_kill":
            if a[1] != (not oomph.calm_event(e)):
                bad.append("event %r: alarming %r, oomph.calm_event says %r" % (e, a[1], oomph.calm_event(e)))
            if "jetsam" in a[0] or not re.match(r"\d+ killed ", a[0]):
                bad.append("event %r: %r" % (e, a[0]))
            if not e["top"] and "(names not known)" not in a[0]:
                bad.append("event %r: counted kills must say the names are not known: %r" % (e, a[0]))
            # kills at a container's limit are the container's: never in the machine's count (03 §5.6)
            if e.get("kills") and e.get("cgroup") and not (a[0].startswith("%d killed by " % e["kills"])
                                                           and "(+%d at their limit)" % e["cgroup"] in a[0]):
                bad.append("event %r: the machine's kills and those at a limit apart: %r" % (e, a[0]))
        elif e["kind"] == "limit_stall" and (a[1] or e["cgroup"] not in a[0]):
            bad.append("event %r: %r" % (e, a))
    for c, a in zip(inp["rows"], exp["rows"]):
        q = [r for r in a if r[0] == "quiet"]
        if len(q) != (1 if c["quiet"] else 0) or (q and q[0][2] != len(c["quiet"]) - 1):
            bad.append("rows %r: the quiet ones are not one folded row: %r" % (c, a))
        if len([r for r in a if r[0] == "incident"]) != len(c["incidents"]):
            bad.append("rows %r: an incident is missing: %r" % (c, a))
    for c, a in zip(inp["who"], exp["who"]):
        if a != (len({x["user"] for x in c["leases"] if x.get("user")}) > 1):
            bad.append("who %r: %r" % (c, a))
    for c, a in zip(inp["legend"], exp["legend"]):
        names = a[0] + a[1]
        if c["linux"] and ("Wired" in names or "Kernel" not in names) or not c["linux"] and "Wired" not in names:
            bad.append("legend %r: %r" % (c, a))
        if ("away" in names) != c["away"]:
            bad.append("legend %r: away %r" % (c, a))
    bad += l3_rules(inp, exp)
    for c, a in zip(inp["labeled"], exp["labeled"]):
        if a != (c["os"] in ("macos", "linux")):
            bad.append("labeled %r: %r" % (c, a))
    for c, a in zip(inp["remedy"], exp["remedy"]):
        if c["os"] == "linux" and c["state"] == "stopped" and a[4] != "sudo systemctl restart oomphd":
            bad.append("remedy %r: %r" % (c, a))
        if c["os"] == "linux" and c["state"] in ("absent", "denied") and a[4] != "sudo linux/install.sh --system":
            bad.append("remedy %r: %r" % (c, a))
        if len(a[4]) > 31:  # it fits the 300 pt callout with its Copy button (03 §3.9: 31 characters at most)
            bad.append("remedy %r: a command too long for the callout: %r" % (c, a[4]))
    host = socket.gethostname().split(".")[0].lower()

    def strings(x):
        if isinstance(x, dict):
            for y in x.values():
                yield from strings(y)
        elif isinstance(x, list):
            for y in x:
                yield from strings(y)
        elif isinstance(x, str):
            yield x.lower()
    if host and host != "build-01" and host in set(strings(v)):
        bad.append("the vectors carry the name of the machine running this (%r): measured static fields leaked" % host)
    for c in inp["tiles"]:
        mm = c["sample"]["daemon"]["machine"]
        if any(mm.get(k) != x for k, x in INVENTED.items()):
            bad.append("tiles %s: the machine's static fields are not the invented ones: %r"
                       % (c["case"], {k: mm.get(k) for k in INVENTED}))
    return bad


MAC_TEXT = re.compile(r"\b(macOS|(?<!this )Mac|jetsam|Activity Monitor|Wired|asleep)\b")   # ("this Mac": the viewer)


def l3_rules(inp, exp):
    """L3 (1.13.4): the legend shows only the series a Linux machine has, each with a Linux text; the capsule's
    tooltip gives the level in Linux terms (stall time where it is measured, what is available); the hover
    card's series, its Available line (RAM less app, kernel and compressed) and its one Stalled line follow the
    points; the callout and the tour speak Linux. No Mac word anywhere in them."""
    bad = []
    import oomph_top
    import oomph_view as view
    for c, names, helps in zip(inp["legend"], exp.get("legend", []), exp.get("legend_help") or [[]] * len(inp["legend"])):
        if not c["linux"]:
            continue
        flat = names[0]
        if "sample" in c:       # the app's series from the machine's facts, and oomph top's from the same sample
            term = [n for n, _ in view.series_words(oomph_top.readings(c["sample"]))]
            if flat != term:
                bad.append("legend from the sample %s: the app shows %r, oomph top %r" % (c["sample"].get("swapfiles"), flat, term))
            import oomph
            v = oomph._View("24h", 0, 1)           # oomph html's chart: the same rule for its Swap series
            v.count(dict(c["sample"], t=1))
            if v.swap != ("Swap" in flat):
                bad.append("legend from the sample %s: the app shows %r, oomph html %s Swap"
                           % (c["sample"].get("swapfiles"), flat, "shows" if v.swap else "leaves out"))
        elif ("Compressed" in flat) != c.get("compressed", True) or ("Swap" in flat) != c.get("swap", True):
            bad.append("legend %r: the series %r are not the machine's" % (c, flat))
        if any(MAC_TEXT.search(h) for h in helps):
            bad.append("legend %r: a Mac's text on a Linux tab: %r" % (c, [h for h in helps if MAC_TEXT.search(h)]))
    for c, t in zip(inp["tiles"], exp.get("capsule") or []):
        s, ms = c["sample"], c["sample"]["daemon"]["machine"].get("measures") or {}
        avail = max(0.0, s["ram_gb"] - s["app_gb"] - s["wired_gb"] - s["compressed_gb"])
        if not isinstance(t, str) or MAC_TEXT.search(t) or "%.1f GB available" % avail not in t:
            bad.append("capsule %s: %r (available %.1f GB)" % (c["case"], t, avail))
        elif ms.get("psi") is not False and s.get("psi") and "Stalled on memory" not in t:
            bad.append("capsule %s: no stall time where it is measured: %r" % (c["case"], t))
    for c, a in zip(inp.get("hover") or [], exp.get("hover") or []):
        series, av, st = a
        want = ["App"] + (["Compressed"] if c["zram"] else []) + ["Kernel"] + (["Swap"] if c["swap"] else [])
        avs = ["%.1f" % max(0.0, c["ram"] - p["wired"] - p["app"] - p["comp"]) for p in c["points"]]
        lo, hi = min(avs, key=float), max(avs, key=float)
        if series != want or av != ("%s GB" % hi if lo == hi else "%s–%s GB" % (lo, hi)):
            bad.append("hover %r: %r" % (c, a))
        some = [p["some"] for p in c["points"] if "some" in p]
        if (st is None) != (not some) or some and not st.startswith(LinuxTabPct(min(some)).split(" ")[0]):
            bad.append("hover %r: the Stalled line %r" % (c, st))
        if some and any(p.get("limit", 0) >= 0.05 for p in c["points"]) and "at a limit" not in st:
            bad.append("hover %r: stall time at a limit not said: %r" % (c, st))
    words = exp.get("words") or []
    if not words or any(MAC_TEXT.search(w) for w in words) or "group" not in words[0] or "OOM killer" not in words[-1]:
        bad.append("the callout and the tour on a Linux tab: %r" % words)
    return bad


def LinuxTabPct(x):
    return "%.1f %%" % x if x < 9.95 else "%.0f %%" % x


def top_agrees(who, s, cells):
    """`oomph top` on the same sample (T3, 1.13.4): its tiles (oomph_view.linux_tiles) say what the app's say, in
    the terminal's shorter labels: the same figures, App memory, Available or Compressed, Kernel, the RAM with its
    decimal or the limit, swap or zram, stall time, Idle or what is available, the biggest group by its Linux name."""
    import oomph_top
    import oomph_view as view
    g = view.GLYPHS["unicode"]
    c = oomph_top.readings(s)
    if c.get("linux") is None:
        return ["%s: oomph top does not read this sample as a Linux machine's" % who]
    top = view.linux_tiles(c, g)
    bad = []
    for i in range(7):
        val, lab = top[i][0], top[i][1]
        want_v, want_l = cells[i][1].replace("—", g["dash"]), cells[i][0]
        same_l = lab == want_l or want_l.startswith(lab.split(" / ")[0].split()[0]) or (i == 4 and lab == "zram / size")
        if not val.startswith(want_v) or not same_l:
            bad.append("%s: oomph top's tile %d is %r %r, the app's %r %r" % (who, i, val, lab, want_v, want_l))
    want_g = (cells[7][3] or "").replace("#1 ", "")
    got_g = top[7][1].replace("#1 ", "") if len(top) > 7 else "–"     # no group yet: the terminal drops the tile
    if got_g != want_g:
        bad.append("%s: oomph top's group tile %r, the app's %r" % (who, got_g, want_g))
    if any(w in " ".join(t[1] for t in top) for w in ("Wired", "biggest app")):
        bad.append("%s: oomph top says a Mac's word: %r" % (who, [t[1] for t in top]))
    return bad


def remeasured(v):
    """Two recorded machines measured afresh by the backend: their memory figures must be the file's (the tiles
    are held to what the logger measures, not to what it once did). A list of failures."""
    bad = []
    stored = {c["case"]: c["sample"] for c in v["inputs"]["tiles"]}
    tmp = tempfile.mkdtemp(prefix="oomph-lv-")
    try:
        for sc in ("ubuntu-server-idle", "container-2g"):
            s = measure(sc, tmp)["s"]
            for k in MEMORY:
                if s.get(k) != stored[sc].get(k):
                    bad.append("%s measured afresh: %s is %r, the file says %r" % (sc, k, s.get(k), stored[sc].get(k)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return bad


def app_answers(binary, inputs):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(inputs, f)
    try:
        r = subprocess.run([binary, "--linux-vectors", f.name], capture_output=True, text=True, timeout=60)
    finally:
        os.unlink(f.name)
    if r.returncode != 0:
        print("the app could not answer: %s" % r.stderr.strip())
        return None
    return json.loads(r.stdout)


def compare(got, want):
    bad = 0
    for g in GROUPS:
        if got.get(g) != want.get(g):
            bad += 1
            print("FAIL  the app, %s:" % g)
            for i, (a, b) in enumerate(zip(got.get(g) or [], want.get(g) or [])):
                if a != b:
                    print("        case %d: %r, expected %r" % (i, a, b))
        else:
            print("ok    the app agrees on %s (%d cases)" % (g, len(want.get(g) or [])))
    return bad


def main(argv):
    if "--app" in argv:
        binary = argv[argv.index("--app") + 1]
        if "--write" in argv:
            inputs = cases()
            got = app_answers(binary, inputs)
            if got is None:
                return 2
            with open(FILE, "w") as f:
                json.dump({"inputs": inputs, "expected": got}, f, indent=1, ensure_ascii=False, sort_keys=True)
                f.write("\n")
            print("wrote %s" % FILE)
            bad = check_rules({"inputs": inputs, "expected": got})
            for b in bad:
                print("FAIL  " + b)
            return 1 if bad else 0
        v = json.load(open(FILE))
        got = app_answers(binary, v["inputs"])
        if got is None:
            return 2
        bad = check_rules({"inputs": v["inputs"], "expected": got})
        for b in bad:
            print("FAIL  " + b)
        return 1 if compare(got, v["expected"]) or bad else 0
    v = json.load(open(FILE))
    bad = check_rules(v) + remeasured(v)
    for b in bad:
        print("FAIL  " + b)
    if not bad:
        print("ok    the Linux tab's words hold to the gate and the logger (%d tile cases, %d events)"
              % (len(v["inputs"]["tiles"]), len(v["inputs"]["event"])))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
