#!/usr/bin/python3 -I
"""The app's renders, made to repeat themselves (roadmap 02 §8; 1.10.6): a fixture directory, and the
check that two renders of it are byte-identical. A render reads this Mac's clock and asks the process
table whether a lease's holder lives; `--now T` and `--no-liveness` take both from the fixture, and
`--fixture DIR` reads DIR/log, DIR/ledger and DIR/machines instead of this Mac's folders.

    tools/renderfixture.py DIR          write the fixture into DIR and print the command that draws it
    tools/renderfixture.py --app EXE    check EXE (oomph.app/Contents/MacOS/oomph): every state below is
                                        drawn twice and must come out byte for byte the same; a render an hour
                                        later must differ (the clock is honoured), and so must one without
                                        --no-liveness (the fixture's holders are not alive)
    tools/renderfixture.py --app EXE --resources DIR
                                        the four-resource popup (1.11.0, and its bands of 1.12.3, behind
                                        resourcesUI) forced on, in every
                                        state of RESOURCES below, light and dark, into DIR as NAME-light.png and
                                        NAME-dark.png, and the menu-bar chip (--render-chip) as chip-light.png and
                                        chip-dark.png: what the owner looks at before switching it on
    tools/renderfixture.py --app EXE --against OLD [--same-version] [--keep DIR]
                                        a change with no visual change (the TimeAxis refactor, 1.10.7): every
                                        render state of the popup (ALL below: the --ai states, the switched-off
                                        + and its popover, the tabs, a mirror, the plain and ∞ popup at 8 and
                                        16 GB of RAM), light and dark, drawn by EXE and by OLD (the build before
                                        the change) must be byte-identical; --keep saves the pairs that differ
                                        into DIR. A line per pair that differs as it is found, progress every 20.
                                        The popup shows its version, and a changed tree builds "X-dirty":
                                        --same-version draws EXE from a copy of its bundle restamped with OLD's
                                        version and commit (Info.plist's CFBundleShortVersionString and
                                        CFBundleVersion, Resources/oomph.py's VERSION and COMMIT) and signed
                                        again ad hoc (codesign --force --sign -), as build-app.sh signs

The data is tools/topfixture.py's invented week ("default"), its live leases held by a process that cannot
exist. CI runs the check after building the app; the TimeAxis refactor (M5) is held to it before and after.
The tabs and the mirror of --against are tools/mirrorfixture.py's, with this Mac's week moved to end with them;
they are dated by the clock when written, and both builds draw the one written fixture at the same --now.
The fixture's machine has 36 GB of RAM (topfixture); "fx8" and "fx16" are the same week on 8 and 16 GB, whose
y domain is another (roadmap 02 §8). Takes about ten minutes; run it under `oomph run --reserve`.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import topfixture  # noqa: E402

NOW = int(topfixture.NOW)
DEAD_PID = 99999999  # above every system's pid limit: kill(pid, 0) says ESRCH
# (--ai state, extra arguments): the plain popup, the ∞ range, the morph halfway, both tooltips, dark, and the
# machines switch on
STATES = [("", []), ("log", []), ("blend:0.5", []), ("hover:300", []), ("hoverlog:300", ["--dark"]),
          ("rhover:420:30", []), ("", ["--dark"]), ("", ["-machinesUI", "YES"])]
DEFAULTS = ["-aiOn", "NO", "-machinesUI", "NO", "-resourcesUI", "NO", "-openedAgo", "0"]  # never this Mac's own settings
ON = ["-machinesUI", "YES"]
SEEN = ON + ["-lastSeenIncident", "99999999-999999"]  # This Mac has nothing new to say: the remembered tab opens
STUDIO, AIR = "m-7f3a9c1e5b2d4a68", "m-4e5f607182930415"
# Every render state of the popup, for --against: (fixture, --ai state, extra arguments), each drawn light and
# dark. "fx" is the fixture of `write`, "remote" that of `write_remote` (its tabs), "mirror" draws its offline
# mirror. `--ai changelog` is left out: it runs this Mac's installed CLI, which is not part of the fixture.
ALL = ([("fx", ai, []) for ai in (
    "", "loading", "callout", "top", "resmore", "on", "running", "connected:claude", "connected:openai",
    "connected:ollama", "connecting", "dialog-connected", "dialog-error", "upgrade", "check", "checking", "uptodate",
    "build", "log", "6h", "1h", "blend:0.25", "blend:0.5", "blend:0.75", "hover:40", "hover:300", "hover:548",
    "hoverlog:120", "hoverlog:300", "hoverlog:440", "rhover:420:30", "rhover:200:20:6h", "rhover:100:40:1h",
    "tour:1", "tour:2", "tour:3", "tour:4")]
    + [("fx", ai, ON) for ai in (
        "", "tour:4", "add", "addhover", "addtype", "addssh", "pair", "pair:link", "addconnecting", "adderr:refused",
        "adderr:local_network_denied", "ask", "paired", "paired:other", "share", "share:off", "share:update",
        "share:activate", "sharecode")]
    + [("remote", "", SEEN), ("remote", "log", SEEN), ("remote", "", ON + ["-selectedMachine", STUDIO])]
    + [("remote", ai, SEEN + ["-selectedMachine", STUDIO]) for ai in ("", "log", "1h", "hover:300", "hoverlog:200",
                                                                       "rhover:420:30", "blend:0.5")]
    + [("remote", "", SEEN + ["-selectedMachine", m]) for m in (
        "m-1b2c3d4e5f607182", "m-90a1b2c3d4e5f607", "m-2c3d4e5f60718293", AIR)]
    + [("remote", "", SEEN + ["-selectedMachine", AIR, "-openedAgo", "2"])]
    + [("mirror", ai, []) for ai in ("", "log", "1h", "6h", "hover:300", "hoverlog:200", "rhover:420:30")]
    + [(fx, ai, []) for fx in ("fx8", "fx16") for ai in ("", "log")]
    # the four resources' fixture with their switch off (1.11.0): the samples' cpu, gpu and disks blocks and the
    # agents of the reservations change nothing in the popup until the switch is on
    + [("fxr", ai, []) for ai in ("", "log", "hover:300", "rhover:420:30", "top", "tour:1", "tour:2")]
    # the network's fixture with the switch off (NET N4, 1.15): the samples' net blocks, the pools of the line and the
    # network's leases change nothing in the popup until the switch is on
    + [("fxn", ai, []) for ai in ("", "log", "hover:300", "rhover:420:30", "top", "6h")])
# The four resources forced on (--resources, and two in the check): (name, fixture, --ai state, extra arguments).
RON = ["-resourcesUI", "YES"]


def sel(focus, *shown):
    return RON + ["-selectedResources", "(%s)" % ",".join(shown or (focus,)), "-focusResource", focus]


ALL4 = ("memory", "cpu", "gpu", "disk")
ALL5 = ALL4 + ("net",)
RESOURCES = ([("memory-alone", "fxr", "", sel("memory")), ("memory-cpu", "fxr", "", sel("memory", "memory", "cpu")),
              ("memory-gpu-disk", "fxr", "", sel("memory", "memory", "gpu", "disk")),
              ("all-memory", "fxr", "", sel("memory", *ALL4)), ("all-gpu", "fxr", "", sel("gpu", *ALL4)),
              ("all-cpu-6h", "fxr", "6h", sel("cpu", *ALL4)), ("cpu-alone", "fxr", "", sel("cpu")),
              ("gpu-alone", "fxr", "", sel("gpu")), ("disk-alone", "fxr", "", sel("disk")),
              ("disk-cpu-1h", "fxr", "1h", sel("disk", "cpu", "disk")),
              ("all-memory-inf", "fxr", "log", sel("memory", *ALL4)),
              ("all-memory-hover", "fxr", "hover:300", sel("memory", *ALL4)),
              ("all-cpu-hover", "fxr", "hover:300", sel("cpu", *ALL4)),
              ("memory-strip-card", "fxr", "rhover:420:30", sel("memory")),
              ("memory-callout", "fxr", "top", sel("memory")), ("cpu-callout", "fxr", "top", sel("cpu")),
              ("gpu-callout", "fxr", "top", sel("gpu")), ("disk-callout", "fxr", "top", sel("disk")),
              ("cpu-only-list", "fxr", "", sel("cpu", "cpu", "gpu")),
              # B3 (1.12.3): a band per reserved resource; the pointer on a row, on a block of the CPU band; every row
              ("bands-row-hover", "fxr", "rowhover:0", sel("memory", *ALL4)),
              ("bands-cpu-card", "fxr", "rhover:428:56", sel("memory", *ALL4)),
              ("bands-all-rows", "fxr", "resmore", sel("memory", *ALL4)),
              ("tour-1", "fxr", "tour:1", sel("memory", "memory", "cpu")), ("tour-2", "fxr", "tour:2", sel("memory", "memory", "cpu"))]
             + [("all-memory-level-%d" % n, "fxr", "lvl:%d" % n, sel("memory", *ALL4)) for n in range(1, 6)]
             + [("memory-tight", "fxr-tight", "", sel("cpu")), ("memory-critical", "fxr-crit", "", sel("cpu", "cpu", "gpu")),
                ("disk-low", "fxr-disklow", "", sel("memory")), ("disk-critical", "fxr-diskcrit", "", sel("memory", *ALL4)),
                ("cpu-busy-throttled", "fxr-hot", "", sel("cpu", *ALL4)), ("no-gpu", "fxr-nogpu", "", sel("memory", *ALL4)),
                ("old-logger", "fx", "", sel("memory", *ALL4)), ("machines-and-resources", "fxr", "", sel("memory", "memory", "cpu")
                                                                + ["-machinesUI", "YES"]),
                # NET N3 (1.15): a metered network with less than 10 % of its cap left, the capsule amber
                ("network-metered-low", "fxr-metered", "", sel("memory", *ALL4))]
             # NET N4 (1.15): the fifth tile and the network's chart, band, list and hover (topfixture's "network": a
             # 250/40 line, a model pulled at 150 Mbit/s granted, an image pull waiting for the line)
             + [("net-five-tiles-idle", "fxn-idle", "", sel("memory")),
                ("net-saturated-grant", "fxn", "", sel("net", "memory", "net")),
                ("net-alone", "fxn", "", sel("net")), ("net-alone-6h", "fxn", "6h", sel("net")),
                ("net-all-five", "fxn", "", sel("net", *ALL5)), ("net-memory-focus-all-five", "fxn", "", sel("memory", *ALL5)),
                ("net-hover", "fxn", "hover:400:6h", sel("net", "memory", "net")),
                ("net-callout", "fxn", "top", sel("net")), ("net-all-rows", "fxn", "resmore", sel("net", *ALL5)),
                ("net-unknown", "fxn-unknown", "", sel("net")),
                ("net-metered", "fxn-metered", "", sel("net", "memory", "net")),
                ("net-metered-low", "fxn-metlow", "", sel("net", "memory", "net")),
                ("net-metered-hint", "fxn-unknown", "", sel("net") + ["-netMetered", "YES"]),
                ("net-stale", "fxn-stale", "", sel("net")),
                ("net-offline", "fxn-offline", "", sel("memory", "memory", "net")),
                ("net-old-logger", "fxr", "", sel("memory", *ALL5)),
                # another machine's tab: its mirror carries the line's rates, figures and busiest names (no key)
                ("net-remote-tab", "mirnet", "", sel("net", "memory", "net")),
                ("net-level-3", "fxn", "lvl:3", sel("net", *ALL5))])
# what each variant of the resources fixture changes in its current.json (the samples stay the week's)
VARIANTS = {"fxr-tight": {"pressure": 2}, "fxr-crit": {"pressure": 4, "jetsam_kills": 3},
            "fxr-disklow": {"disk_free_gb": 12.0, "disks!": [12.0, "low"]},
            "fxr-diskcrit": {"disk_free_gb": 3.5, "disks!": [3.5, "critical"]},
            "fxr-hot": {"cpu!": {"busy": 13.4, "user": 11.0, "sys": 2.4, "therm": 2}}, "fxr-nogpu": {"gpu": []},
            "fxr-metered": {"pools": {"t": NOW, "net.quota": {"network": "rmac:00:00:5e:00:53:01", "cap": 20.0, "margin": 2.0,
                                                              "used": 18.2, "from": NOW - 12 * 86400,
                                                              "to": NOW + 18 * 86400, "period": "month",
                                                              "label": "phone"}}}}
# ... and of the network fixture (NET N4): the line quiet, without a figure, metered, near its cap, its figure stale (the
# pull runs at 176 Mbit/s against 150 stored), offline
_NK = topfixture.NET_KEY
_NDOWN = {"network": _NK, "cap": 250.0, "margin": 62.5, "reserved": 150.0, "busy": 176.0, "others": 14.2}
_NUP = {"network": _NK, "cap": 40.0, "margin": 12.0, "reserved": 0.0, "busy": 1.2, "others": 1.1}
_NQ = {"network": _NK, "cap": 20.0, "margin": 2.0, "from": NOW - 12 * 86400, "to": NOW + 18 * 86400, "period": "month"}
NET_VARIANTS = {
    "fxn-idle": {"net": {"if": "en0", "vpn": False, "network": _NK, "src": "flows", "flows": 31, "down_mbps": 2.1,
                         "up_mbps": 0.4, "lan_mbps": 0.0},
                 "net_names": [{"name": "Google Chrome", "down": 1.4, "up": 0.2, "n": 9}]},
    "fxn-unknown": {"pools": None},
    "fxn-metered": {"pools": {"t": NOW, "net.down": _NDOWN, "net.up": _NUP, "net.quota": dict(_NQ, used=12.4)}},
    "fxn-metlow": {"pools": {"t": NOW, "net.down": _NDOWN, "net.up": _NUP, "net.quota": dict(_NQ, used=18.2, label="phone")}},
    "fxn-stale": {"pools": {"t": NOW, "net.down": dict(_NDOWN, cap=150.0, margin=37.5), "net.up": _NUP}},
    "fxn-offline": {"net": {"if": None}, "net_names": None, "pools": None}}


def write(d, ram=None, scenario="default", change=None):
    """The fixture: topfixture's default machine (or another scenario, "resources" for 1.11.0's four
    resources); its live leases' holder is DEAD_PID. With `ram`, the machine has that many GB (current.json's
    ram_gb) instead of 36; `change` (VARIANTS) sets other fields of current.json ("disks!": the first pool's
    free GB and level, "cpu!": fields of the cpu block)."""
    log, led = topfixture.write_fixture(d, scenario)
    os.makedirs(os.path.join(d, "machines"))
    dead_holders(os.path.join(led, "ledger.json"))
    if ram is not None or change:
        p = os.path.join(log, "current.json")
        with open(p, encoding="utf-8") as f:
            cur = json.load(f)
        if ram is not None:
            cur["ram_gb"] = float(ram)
        for k, v in (change or {}).items():
            if v is None:
                cur.pop(k, None)
            elif k == "disks!":
                cur["disks"][0].update(free_gb=v[0], level=v[1])
            elif k == "cpu!":
                cur["cpu"].update(v)
            else:
                cur[k] = v
        with open(p, "w", encoding="utf-8") as f:
            json.dump(cur, f)
    return d


def dead_holders(p):
    """The live leases of the ledger at p, held by DEAD_PID."""
    with open(p, encoding="utf-8") as f:
        ledger = json.load(f)
    for lease in ledger["leases"]:
        lease["holder"]["pid"] = DEAD_PID
    with open(p, "w", encoding="utf-8") as f:
        json.dump(ledger, f)


def write_remote(d):
    """The tabs and a mirror: tools/mirrorfixture.py's machines (studio live, mini-ci not connected, gpu-box
    needs attention, lab-mini blocked by macOS, air reconnecting, and two Recents) and its offline mirror,
    with this Mac's own week moved to end with them. Returns (fixture, mirror, the --now that draws them)."""
    import mirrorfixture
    with contextlib.redirect_stdout(io.StringIO()):
        mirrorfixture.machines(os.path.join(d, "m"), tabs=True)
    now = int(time.time())
    fx = os.path.join(d, "fx")
    mirrorfixture.moved(fx, now - 60)
    os.rename(os.path.join(d, "m", "machines"), os.path.join(fx, "machines"))
    dead_holders(os.path.join(fx, "ledger", "ledger.json"))
    return fx, os.path.join(d, "m", "offline", "mirror"), now


def net_mirror(d):
    """A live mirror of topfixture's network machine, through the real `oomph remote sync --once` (mirrorfixture's
    "network" scene); its directory. Drawn right after (a live link goes stale)."""
    import mirrorfixture
    with contextlib.redirect_stdout(io.StringIO()):
        mirrorfixture.main([d, "network"])
    return os.path.join(d, "mirror")


def stamp(exe):
    """The version a build carries, as build-app.sh stamps it: Info.plist's CFBundleShortVersionString and
    CFBundleVersion, and the VERSION and COMMIT lines of its CLI (Contents/Resources/oomph.py)."""
    import plistlib
    contents, v = os.path.dirname(os.path.dirname(os.path.abspath(exe))), {}
    try:
        with open(os.path.join(contents, "Info.plist"), "rb") as f:
            info = plistlib.load(f)
        v.update((k, info.get(k)) for k in ("CFBundleShortVersionString", "CFBundleVersion"))
        with open(os.path.join(contents, "Resources", "oomph.py"), encoding="utf-8") as f:
            v.update((ln.split(" ", 1)[0], ln.rstrip("\n")) for ln in f if ln.startswith(("VERSION = ", "COMMIT = ")))
    except (OSError, ValueError):
        pass
    return v


def restamp(exe, old, base):
    """A copy of the bundle of `exe` under `base` carrying `old`'s stamp, signed again ad hoc; its executable."""
    import plistlib
    app = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(exe))))
    copy = os.path.join(base, "restamped", os.path.basename(app))
    shutil.copytree(app, copy, symlinks=True)
    want = stamp(old)
    p = os.path.join(copy, "Contents", "Info.plist")
    with open(p, "rb") as f:
        info = plistlib.load(f)
    info.update((k, want[k]) for k in ("CFBundleShortVersionString", "CFBundleVersion") if want.get(k) is not None)
    with open(p, "wb") as f:
        plistlib.dump(info, f)
    p = os.path.join(copy, "Contents", "Resources", "oomph.py")
    with open(p, encoding="utf-8") as f:
        lines = f.read().split("\n")
    lines = [want.get(ln.split(" ", 1)[0], ln) if ln.startswith(("VERSION = ", "COMMIT = ")) else ln for ln in lines]
    with open(p, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    subprocess.run(["codesign", "--force", "--sign", "-", copy], check=True, capture_output=True, timeout=120)
    return os.path.join(copy, "Contents", "MacOS", os.path.basename(exe))


def against(exe, old, keep=None, same_version=False):
    """Every state of ALL, light and dark, drawn by `exe` and by `old`: byte-identical, or reported. A pair
    that differs is drawn by `old` once more, to tell a change from a state that does not repeat itself.
    Prints as it goes (flushed): a run cut short still says what it found."""
    base = tempfile.mkdtemp(prefix="oomph-renderfixture-")
    same, differ, unsteady = 0, [], []
    try:
        if same_version:
            exe = restamp(exe, old, base)
        shown = [" / ".join(str(stamp(x).get(k)) for k in ("CFBundleShortVersionString", "VERSION")) for x in (exe, old)]
        if shown[0] != shown[1]:
            print("warning: the builds carry different versions (%s; %s), which the popup shows: renders with it "
                  "differ (--same-version restamps a copy)" % tuple(shown), flush=True)
        fx = write(os.path.join(base, "fx"))
        rfx, mirror, rnow = write_remote(os.path.join(base, "remote"))
        where = {"fx": (fx, NOW, []), "remote": (rfx, rnow, []), "mirror": (rfx, rnow, ["--mirror", mirror]),
                 "fx8": (write(os.path.join(base, "fx8"), 8), NOW, []),
                 "fx16": (write(os.path.join(base, "fx16"), 16), NOW, []),
                 "fxr": (write(os.path.join(base, "fxr"), scenario="resources"), NOW, []),
                 "fxn": (write(os.path.join(base, "fxn"), scenario="network"), NOW, [])}
        for i, (kind, ai, extra) in enumerate(ALL):
            if i and i % 20 == 0:
                print("  %d of %d states drawn, %d pairs byte-identical" % (i, len(ALL), same), flush=True)
            for dark in (False, True):
                d, now, more = where[kind]
                args = list(more) + list(extra) + (["--dark"] if dark else [])
                name = "%s %s%s" % (kind, ai or "plain", "".join(" " + x for x in extra + (["--dark"] if dark else [])))
                a = render(old, d, os.path.join(base, "%d%s-old.png" % (i, "d" * dark)), ai, args, now)
                b = render(exe, d, os.path.join(base, "%d%s-new.png" % (i, "d" * dark)), ai, args, now)
                if a[1] is not None and a[1] == b[1]:
                    same += 1
                    continue
                c = render(old, d, os.path.join(base, "%d%s-again.png" % (i, "d" * dark)), ai, args, now)
                (unsteady if c[1] != a[1] else differ).append(name)
                said = ["%d bytes" % len(r[1]) if r[1] else r[2] or "nothing" for r in (a, b)]
                print("%s  %s (old %s, new %s)" % ("UNSTEADY" if c[1] != a[1] else "DIFFER  ", name, said[0], said[1]),
                      flush=True)
                if keep:
                    os.makedirs(keep, exist_ok=True)
                    stem = name.replace(" ", "_").replace(":", "-").replace("/", "-")
                    for tag, r in (("old", a), ("new", b)):
                        if r[1]:
                            with open(os.path.join(keep, "%s.%s.png" % (stem, tag)), "wb") as f:
                                f.write(r[1])
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print("renderfixture: %d of %d renders byte-identical to the build before%s%s" % (
        same, 2 * len(ALL), "; %d differ" % len(differ) if differ else "",
        "; %d do not repeat themselves in the old build" % len(unsteady) if unsteady else ""), flush=True)
    return 1 if differ or unsteady or not same else 0


def render(exe, fx, out, ai="", extra=(), now=NOW, live=False):
    """One render into `out`: (exit code, the PNG's bytes or None, stderr)."""
    cmd = [exe, "--render-popup", out, "--fixture", fx, "--now", str(now)] + ([] if live else ["--no-liveness"])
    cmd += (["--ai", ai] if ai else []) + DEFAULTS + list(extra)  # after DEFAULTS: the last value of a key wins
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return -1, None, "timed out"
    data = open(out, "rb").read() if os.path.exists(out) and os.path.getsize(out) > 0 else None
    return r.returncode, data, r.stderr.strip()


def resources(exe, out):
    """Every state of RESOURCES, light and dark, into `out` (the owner's renders of the four resources)."""
    base = tempfile.mkdtemp(prefix="oomph-renderfixture-")
    os.makedirs(out, exist_ok=True)
    bad = 0
    try:
        where = {"fx": write(os.path.join(base, "fx")), "fxr": write(os.path.join(base, "fxr"), scenario="resources"),
                 "fxn": write(os.path.join(base, "fxn"), scenario="network")}
        for k, ch in VARIANTS.items():
            where[k] = write(os.path.join(base, k), scenario="resources", change=ch)
        for k, ch in NET_VARIANTS.items():
            where[k] = write(os.path.join(base, k), scenario="network", change=ch)
        where["mirnet"] = where["fx"]
        mirror = net_mirror(os.path.join(base, "mirnet"))
        for name, fx, ai, extra in RESOURCES:
            for dark in (False, True):
                path = os.path.join(out, "%s-%s.png" % (name, "dark" if dark else "light"))
                more = ["--mirror", mirror] if fx == "mirnet" else []
                rc, data, err = render(exe, where[fx], path, ai, list(extra) + more + (["--dark"] if dark else []),
                                       int(time.time()) if fx == "mirnet" else NOW)   # a mirror is dated now
                bad += data is None
                print("%s  %s%s" % ("ok   " if data else "FAIL ", os.path.basename(path), "" if data else ": " + err),
                      flush=True)
        for dark in (False, True):          # the menu-bar chip: each body, with and without the disk's disc
            path = os.path.join(out, "chip-%s.png" % ("dark" if dark else "light"))
            try:
                r = subprocess.run([exe, "--render-chip", path] + (["--dark"] if dark else []), capture_output=True,
                                   text=True, timeout=60)
                err = r.stderr.strip()
            except subprocess.TimeoutExpired:
                err = "timed out"
            data = os.path.exists(path) and os.path.getsize(path) > 0
            bad += not data
            print("%s  %s%s" % ("ok   " if data else "FAIL ", os.path.basename(path), "" if data else ": " + err), flush=True)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print("renderfixture: %d renders of the four resources in %s%s" % (2 * len(RESOURCES) + 2, out,
                                                                       "; %d failed" % bad if bad else ""))
    return 1 if bad else 0


def check(exe):
    bad = []

    def ok(cond, what):
        print(("ok    " if cond else "FAIL  ") + what, flush=True)
        if not cond:
            bad.append(what)

    base = tempfile.mkdtemp(prefix="oomph-renderfixture-")
    try:
        fx = write(os.path.join(base, "fx"))
        first = {}
        for i, (ai, extra) in enumerate(STATES):
            name = (ai or "plain") + "".join(" " + x for x in extra)
            a = render(exe, fx, os.path.join(base, "%d-a.png" % i), ai, extra)
            b = render(exe, fx, os.path.join(base, "%d-b.png" % i), ai, extra)
            first[i] = a[1]
            ok(a[0] == 0 and a[1] is not None and a[1] == b[1],
               "render %s: drawn twice, byte-identical (%s)" % (
                   name, "%d bytes" % len(a[1]) if a[1] and a[1] == b[1] else a[2] or b[2] or "they differ"))
        ok(first[0] is not None and first[len(STATES) - 1] not in (None, first[0]),
           "render with the machines switch on: a different picture from the plain one (the switch took)")
        # the four resources (1.11.0): drawn twice the same, the switch takes, and off it changes nothing
        fxr = write(os.path.join(base, "fxr"), scenario="resources")
        pics = {}
        for i, (ai, extra) in enumerate([("", []), ("", sel("memory")), ("", sel("gpu", *ALL4)), ("lvl:4", sel("cpu", *ALL4))]):
            a = render(exe, fxr, os.path.join(base, "r%d-a.png" % i), ai, extra)
            b = render(exe, fxr, os.path.join(base, "r%d-b.png" % i), ai, extra)
            pics[i] = a[1]
            ok(a[0] == 0 and a[1] is not None and a[1] == b[1], "render of the four resources %s: drawn twice, byte-identical (%s)"
               % (" ".join(extra[1:]) or "switched off", "%d bytes" % len(a[1]) if a[1] and a[1] == b[1] else a[2] or b[2] or "differ"))
        ok(len({pics[i] for i in pics if pics[i]}) == 4,
           "the four resources: the switch takes, and Memory alone, all four on the GPU and a compact level differ")
        # the network (NET N4, 1.15): its states drawn twice the same; the tile, its chart and "metered?" each show
        fxn = write(os.path.join(base, "fxn"), scenario="network")
        npics = {}
        for i, (ai, extra) in enumerate([("", []), ("", sel("memory")), ("", sel("net")),
                                         ("", sel("net") + ["-netMetered", "YES"])]):
            a = render(exe, fxn, os.path.join(base, "n%d-a.png" % i), ai, extra)
            b = render(exe, fxn, os.path.join(base, "n%d-b.png" % i), ai, extra)
            npics[i] = a[1]
            ok(a[0] == 0 and a[1] is not None and a[1] == b[1], "render of the network %s: drawn twice, byte-identical (%s)"
               % (" ".join(extra[1:]) or "switched off", "%d bytes" % len(a[1]) if a[1] and a[1] == b[1] else a[2] or b[2] or "differ"))
        ok(len({npics[i] for i in npics if npics[i]}) == 4 and npics[1] not in (None, pics[1]),
           "the network: its tile, its chart and the system's \"metered?\" each change the picture")
        later = render(exe, fx, os.path.join(base, "later.png"), now=NOW + 3600)
        ok(later[1] is not None and first[0] is not None and later[1] != first[0],
           "render an hour later by --now: a different picture (the clock comes from --now)")
        live = render(exe, fx, os.path.join(base, "live.png"), live=True)
        ok(live[1] is not None and first[0] is not None and live[1] != first[0],
           "render without --no-liveness: a different picture (the fixture's holders are not alive)")
        nolog = render(exe, os.path.join(base, "nothing"), os.path.join(base, "nolog.png"))
        ok(nolog[0] == 2 and nolog[1] is None, "--fixture without a log folder: refused (exit %s)" % nolog[0])
        badnow = render(exe, fx, os.path.join(base, "badnow.png"), now="soon")
        ok(badnow[0] == 2 and badnow[1] is None, "--now that is not a time: refused (exit %s)" % badnow[0])
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print("renderfixture: %s" % ("renders repeat themselves" if not bad else "%d problem(s)" % len(bad)))
    return 1 if bad else 0


def main(argv):
    def arg(k):
        return argv[argv.index(k) + 1] if k in argv and argv.index(k) + 1 < len(argv) else None
    if arg("--app") and arg("--against"):
        return against(arg("--app"), arg("--against"), arg("--keep"), "--same-version" in argv)
    if arg("--app") and arg("--resources"):
        return resources(arg("--app"), arg("--resources"))
    if arg("--app"):
        return check(arg("--app"))
    if len(argv) == 1 and not argv[0].startswith("-"):
        d = write(argv[0])
        print("renderfixture: %s (now = %d)\n  oomph.app/Contents/MacOS/oomph --render-popup out.png --fixture %s "
              "--now %d --no-liveness %s" % (d, NOW, d, NOW, " ".join(DEFAULTS)))
        return 0
    print(__doc__.strip())
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
