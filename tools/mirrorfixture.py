#!/usr/bin/python3 -I
"""Mirror fixtures for the popup (roadmap 01 §3.4, §3.5, §12): another machine's mirror, made the
way the app will get one, so `--render-popup … --mirror DIR` can draw each state of a link.

    tools/mirrorfixture.py DIR [live|offline|fetching|machines|recents]
    tools/mirrorfixture.py DIR linux [VARIANT]

writes a made-up machine ("studio": the week of tools/topfixture.py, moved so that it ends now)
into DIR/source, mirrors it through a pipe with the real `oomph remote sync --once` into
DIR/mirror, and then sets the scene:

    live      the link is up (status.json: live, written just now by a process that exists)
    offline   the link dropped 40 minutes ago; an earlier drop left 2 hours not received
    fetching  just paired: the last 6 hours are in, the lists are still being fetched

    machines  six tabs (roadmap 01 R1a): DIR/machines is an OOMPH_MACHINES_DIR whose machines.json
              pins studio (live), mini-ci (not connected), gpu-box (its key changed), lab-mini
              (Blocked by macOS: Local Network) and air (live when the popup last closed, 40 minutes
              ago: an opening draws its grace, then Connecting…, never Not connected; -openedAgo 2
              renders the second step), and atlas, a Linux machine (not connected; a tab since 1.13.3);
              render-01 and build-box (over ssh) are Recents (not tabs), for the + and its popover (1.10.2)
    recents   the + on the line (R1b): DIR/machines knows render-01 and build-box as Recents only
    linux     a Linux machine, build-01, over ssh as kim (03 §3.9, the Linux-tab gate; 1.13.3): the week
              turned into a Linux server's (Kernel, Available, stall time, OOM kills, a limit stall, an
              incident and three quiet ones, reservations of two accounts), mirrored live into DIR/mirror;
              DIR is also a --fixture directory: DIR/log and DIR/ledger are This Mac's week, DIR/machines
              pins build-01. VARIANT: server (the default), desktop (zram only, no idle time), nopsi,
              container (a 2 GB cgroup limit on the 62.7 GB host, with zswap), limit (stall time at a container's limit), longstall,
              hidden (the logger sees only its own processes), killsnone, stopped (its logger stopped 15
              minutes ago), denied (kim may not read the logs), absent (nothing is logged there)

Then: <app>/Contents/MacOS/oomph --render-popup out.png --mirror DIR/mirror [--dark] [--ai log], or
for the tabs OOMPH_MACHINES_DIR=DIR/machines <app> --render-popup out.png -machinesUI YES
[-selectedMachine m-7f3a9c1e5b2d4a68]; for linux, <app> --render-popup out.png --fixture DIR -machinesUI YES
-selectedMachine m-3f9c1a7e5b2d4c10 -lastSeenIncident 99999999-999999 [--ai remedy] (or --mirror DIR/mirror).
Render right after writing the fixture: a live link goes stale 10 s after status.json was written
(this tool dates it two minutes ahead). All data is invented.
"""
import gzip
import json
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "daemon"))
import topfixture  # noqa: E402  (its clock is Europe/Berlin; the moved week keeps its local hours roughly)
import oomph_sync as sync  # noqa: E402



def moved(fx, until):
    """topfixture's default machine, every time moved by the same amount so that it ends at
    `until`, with the fields a real logger writes and the machine block."""
    src = os.path.join(fx, "tf")
    log, led = topfixture.write_fixture(src, "default")
    dt = round(until - topfixture.NOW)
    out_log, out_led = os.path.join(fx, "log"), os.path.join(fx, "ledger")
    os.makedirs(os.path.join(out_log, "incidents"))
    os.makedirs(out_led)

    def read(p):
        with open(p, "rb") as f:
            d = f.read()
        return gzip.decompress(d) if p.endswith(".gz") else d
    rows = []
    for n in sorted(os.listdir(log)):
        if n.startswith("samples-"):
            rows += [json.loads(x) for x in read(os.path.join(log, n)).splitlines()]
    by_day = {}
    for r in rows:
        r["t"] += dt
        lt = time.localtime(r["t"])
        off = lt.tm_gmtoff
        r = dict({"t": r["t"], "iso": time.strftime("%Y-%m-%dT%H:%M:%S", lt) + "%s%02d:%02d" % (
            "-" if off < 0 else "+", abs(off) // 3600, abs(off) % 3600 // 60), "hot": False, "os": "macos",
            "pressure": 1, "ram_gb": 64.0}, **{k: v for k, v in r.items() if k != "t"})
        by_day.setdefault(r["iso"][:10], []).append(r)
    today = max(by_day)
    for day, rs in by_day.items():
        text = b"".join(json.dumps(r).encode() + b"\n" for r in rs)
        if day == today:
            open(os.path.join(out_log, "samples-%s.jsonl" % day), "wb").write(text)
        else:
            with gzip.GzipFile(os.path.join(out_log, "samples-%s.jsonl.gz" % day), "wb", mtime=0) as f:
                f.write(text)
    cur = json.load(open(os.path.join(log, "current.json")))
    cur.update(t=cur["t"] + dt, ram_gb=64.0, os="macos", free_pct=58, swapfiles=0, cached_gb=4.0, free_gb=1.0)
    cur["daemon"].update(started=cur["t"] - 86400 * 3, machine={
        "id": "m-7f3a9c1e5b2d4a68", "name": "studio", "os": "macos", "arch": "arm64", "os_version": "macOS 27.2",
        "kernel": "27.2.0", "kind": "desktop", "cpus": 16, "virt": "none", "measures": {"memory": True}})
    json.dump(cur, open(os.path.join(out_log, "current.json"), "w"))
    with open(os.path.join(out_log, "events.jsonl"), "w") as f:
        for x in read(os.path.join(log, "events.jsonl")).splitlines():
            e = json.loads(x)
            e["t"] += dt
            f.write(json.dumps(e) + "\n")
    for iid in os.listdir(os.path.join(log, "incidents")):
        inc = json.load(open(os.path.join(log, "incidents", iid, "incident.json")))
        inc["start"] += dt
        inc["end"] = inc["end"] + dt if inc.get("end") else None
        for r in inc["reasons"]:
            r["t"] += dt
        inc["id"] = time.strftime("%Y%m%d-%H%M%S", time.localtime(inc["start"]))
        os.makedirs(os.path.join(out_log, "incidents", inc["id"]))
        json.dump(inc, open(os.path.join(out_log, "incidents", inc["id"], "incident.json"), "w"))

    def shift(r):
        for k in ("t", "requested", "granted", "ended", "expires", "seen"):
            if isinstance(r.get(k), (int, float)):
                r[k] += dt
        for s in r.get("segments") or []:
            s["t"] += dt
        return r
    with open(os.path.join(out_led, "reservations.jsonl"), "w") as f:
        for x in read(os.path.join(led, "reservations.jsonl")).splitlines():
            f.write(json.dumps(shift(json.loads(x))) + "\n")
    L = json.load(open(os.path.join(led, "ledger.json")))
    L["leases"] = [shift(x) for x in L["leases"]]
    json.dump(L, open(os.path.join(out_led, "ledger.json"), "w"))
    shutil.rmtree(src)


def main(argv):
    if not argv or argv[0].startswith("-"):
        print(__doc__.strip())
        return 2
    out, scene = argv[0], (argv[1] if len(argv) > 1 else "offline")
    if scene not in ("live", "offline", "fetching", "machines", "recents", "linux") or \
            scene == "linux" and argv[2:] and argv[2] not in LINUX_VARIANTS:
        print(__doc__.strip())
        return 2
    if scene in ("machines", "recents"):
        return machines(out, tabs=scene == "machines")
    if scene == "linux":
        return linux(out, argv[2] if argv[2:] else "server")
    now = time.time()
    drop = now - 40 * 60 if scene == "offline" else now
    src, mir = os.path.join(out, "source"), os.path.join(out, "mirror")
    shutil.rmtree(out, ignore_errors=True)
    moved(src, drop - 20)
    env = dict(os.environ, OOMPH_DIR=os.path.join(src, "log"), OOMPH_LEDGER_DIR=os.path.join(src, "ledger"))
    os.environ.update(OOMPH_DIR=env["OOMPH_DIR"], OOMPH_LEDGER_DIR=env["OOMPH_LEDGER_DIR"])
    serve = [sys.executable, "-I", "-B", os.path.join(ROOT, "daemon", "oomph.py"), "serve", "--stdio", "--now", repr(drop)]
    r = sync.sync_once(serve, into=mir)
    st = json.load(open(os.path.join(mir, "sync.json")))
    status = json.load(open(os.path.join(mir, "status.json")))
    cov = sync.Coverage(st["have"])
    if scene == "offline":
        # an earlier drop that was never backfilled: 2 hours, 7 to 5 hours before the link went down
        a, b = drop - 7 * 3600, drop - 5 * 3600
        m = sync.Mirror(mir)
        for day in m.days():
            rows = m.day_rows(day)
            if any(a <= t <= b for t in rows):
                name = m.day_name(day)
                keep = b"".join(rows[t] + b"\n" for t in sorted(rows) if not a <= t <= b)
                m.write("log", name, keep, gz=name.endswith(".gz"))
        cov.remove(a, b)
        status.update(state="offline", was=None, since=drop, last_contact=drop, error="timeout",
                      detail="no answer", attempt=7, next_try=now + 40, updated=now, pid=None)
    elif scene == "live":
        status.update(state="live", was=None, since=now - 3600, last_contact=now, error=None, updated=now + 120, pid=1)
    else:
        keep = now - 6 * 3600
        for n in os.listdir(os.path.join(mir, "log")):
            if n.startswith("samples-"):
                p = os.path.join(mir, "log", n)
                if n.endswith(".gz"):
                    os.remove(p)
                    continue
                lines = [x for x in open(p, "rb").read().splitlines() if json.loads(x)["t"] >= keep]
                open(p, "wb").write(b"".join(x + b"\n" for x in lines))
        for n in ("ledger.json", "reservations.jsonl"):
            os.remove(os.path.join(mir, "ledger", n))
        shutil.rmtree(os.path.join(mir, "log", "incidents"))
        cov = sync.Coverage([[keep, now]])
        st["synced"] = {"ledger": False, "reservations": False, "incidents": False}
        status.update(state="catching_up", was=None, since=now, last_contact=now, error=None, updated=now + 120, pid=1)
    st["have"] = cov.spans
    st["offset_s"] = 0.0  # the server's clock was set (--now), not off
    json.dump(st, open(os.path.join(mir, "sync.json"), "w"))
    json.dump(status, open(os.path.join(mir, "status.json"), "w"))
    print("%s: %s (%d samples mirrored)" % (scene, mir, r["counts"]["samples"]))
    return 0


def recent_entries(now):
    """Two machines this Mac was paired with that are not tabs now: Recents in the connect popover."""
    return [{"mid": "m-5a6b7c8d9e0f1a2b", "id": "m-5a6b7c8d9e0f1a2b", "name": "render-01", "label": None, "transport": "tcp",
             "host": "render-01.local", "port": 6674, "user": None, "addrs": ["10.0.4.23"], "fp": "sha256:" + "%064x" % 77,
             "client": "c-00000077", "os": "macos", "os_version": "macOS 26.4", "ram_gb": 192, "version": "1.10.0", "caps": [],
             "added": now - 20 * 86400, "last_connected": now - 2 * 86400, "pinned": False, "order": 20},
            {"mid": "m-6b7c8d9e0f1a2b3c", "id": "m-6b7c8d9e0f1a2b3c", "name": "build-box", "label": None, "transport": "ssh",
             "host": "build-box", "port": None, "user": "sam", "addrs": [], "fp": None, "client": None, "os": "macos",
             "os_version": "macOS 27.1", "ram_gb": 32, "version": "1.10.0", "caps": [], "added": now - 9 * 86400,
             "last_connected": now - 5 * 86400, "pinned": False, "order": 21}]


def machines(out, tabs=True):
    """Five pinned machines (and a Linux one) in an OOMPH_MACHINES_DIR, as `oomph remote add` leaves them,
    and two Recents; with tabs False only the Recents (the + on the line)."""
    shutil.rmtree(out, ignore_errors=True)
    if not tabs:
        base = os.path.join(out, "machines")
        os.makedirs(base, mode=0o700)
        json.dump({"v": 1, "machines": recent_entries(time.time())}, open(os.path.join(base, "machines.json"), "w"), indent=1)
        print("recents: %s (render-01 and build-box, no tab)" % base)
        return 0
    main([os.path.join(out, "live"), "live"])
    main([os.path.join(out, "offline"), "offline"])
    base = os.path.join(out, "machines")
    os.makedirs(base, mode=0o700)
    now = time.time()
    tabs = [("m-7f3a9c1e5b2d4a68", "studio", "live", None, "macos"), ("m-1b2c3d4e5f607182", "mini-ci", "offline", None, "macos"),
            ("m-90a1b2c3d4e5f607", "gpu-box", "offline", "identity_changed", "macos"),
            ("m-2c3d4e5f60718293", "lab-mini", "offline", "local_network_denied", "macos"),
            ("m-4e5f607182930415", "air", "offline", "was_live", "macos"),
            ("m-3d4e5f6071829304", "atlas", "offline", None, "linux")]
    entries = []
    for i, (mid, name, src, problem, osname) in enumerate(tabs):
        shutil.copytree(os.path.join(out, src, "mirror"), os.path.join(base, mid))
        mj = os.path.join(base, mid, "machine.json")
        json.dump(dict(json.load(open(mj)), id=mid, name=name, **(LINUX_INFO if osname == "linux" else {})), open(mj, "w"))
        if osname == "linux":  # its samples say so too (a Linux tab since 1.13.3)
            cp = os.path.join(base, mid, "log", "current.json")
            json.dump(dict(json.load(open(cp)), os="linux"), open(cp, "w"))
        p = os.path.join(base, mid, "status.json")
        st = json.load(open(p))
        if problem == "was_live":  # the engine left it so when the popup closed (D8)
            st.update(state="idle", was="live", error=None, detail=None, fast=None, attempt=0, next_try=None, pid=None,
                      connect_ms=110, transport="tcp", last_contact=now - 40 * 60)
        elif problem == "identity_changed":
            st.update(state="needs_attention", error=problem, detail="its key changed", attempt=0, next_try=None)
        elif problem:
            st.update(state="offline", error=problem, fast=True, detail="192.168.1.31: No route to host, after 2 ms")
        json.dump(st, open(p, "w"))
        entries.append({"mid": mid, "id": mid, "name": name, "label": None, "transport": "tcp", "host": name + ".local",
                        "port": 6674, "user": None, "addrs": [], "fp": "sha256:" + "%064x" % (i + 1),
                        "client": "c-0000000%d" % i, "os": osname, "version": "1.10.0", "caps": [],
                        "added": now - 86400 * (3 - i), "pinned": True, "order": i + 1})
    entries += recent_entries(now)
    json.dump({"v": 1, "machines": entries}, open(os.path.join(base, "machines.json"), "w"), indent=1)
    print("machines: %s (studio live, mini-ci not connected, gpu-box needs attention, lab-mini blocked by macOS, "
          "air reconnecting, atlas Linux, not connected)" % base)
    return 0


LINUX_MID = "m-3f9c1a7e5b2d4c10"
LINUX_INFO = {"os": "linux", "os_version": "Ubuntu 24.04.3 LTS", "kind": "server"}
LINUX_VARIANTS = ("server", "desktop", "nopsi", "container", "limit", "longstall", "hidden", "killsnone", "stopped", "denied",
                  "absent")
MEASURES = {"memory": True, "psi": True, "kills": "journal", "cgroup": "v2", "zram": False, "zswap": False, "presence": "none",
            "footprint": "anon+swap", "names": "argv", "containers": "main-program", "unowned": False, "scope": "host",
            "cpu": "proc-stat", "io": "diskstats", "disks": "mountinfo", "gpu": "none", "all_procs": True}
CONTAINER_GB = 2.0  # docker -m 2g on build-01
CONTAINER_SCOPE = {"kind": "cgroup", "id": "/system.slice/docker-9d02c41b.scope", "limit_gb": CONTAINER_GB, "by": "max",
                   "host_ram_gb": 62.7, "host_pressure": 1, "host_margin_gb": 8.0}
LINUX_GROUPS = [("docker:9d02c41b (node)", 4.1, 23), ("postgresql@16-main", 3.2, 11), ("java", 2.2, 1),
                ("docker:3f9c1a7e (nginx)", 0.9, 5), ("sshd", 0.1, 3)]


def linuxize(src, variant):
    """The moved week in src turned into a Linux server's, as its logger writes it (03 §3.9, §5): no away, no
    compressed memory, stall time, OOM kills instead of jetsam, an incident and three quiet ones."""
    log, led = os.path.join(src, "log"), os.path.join(src, "ledger")
    desk = variant == "desktop"
    for n in os.listdir(log):
        if not n.startswith("samples-"):
            continue
        p = os.path.join(log, n)
        raw = open(p, "rb").read()
        rows = [json.loads(x) for x in (gzip.decompress(raw) if n.endswith(".gz") else raw).splitlines()]
        for r in rows:
            if variant == "container":  # the logger inside a 2 GB container on the 62.7 GB host: the container's figures
                f = CONTAINER_GB / (r.get("ram_gb") or 64.0)
                for k in ("app_gb", "wired_gb", "compressed_gb", "cached_gb", "free_gb", "swap_used_gb"):
                    if isinstance(r.get(k), (int, float)):
                        r[k] = round(r[k] * f, 2)
                r["scope"] = dict(CONTAINER_SCOPE, host_avail_gb=44.5)
            r.update(os="linux", ram_gb=CONTAINER_GB if variant == "container" else 62.7,
                     away={"idle_s": None, "display_on": None, "locked": False}, psi={"mem_some": 0.4, "mem_full": 0.0})
            if not desk:
                r["wired_gb"] = round(r["wired_gb"] * 0.4, 2)
                r["compressed_gb"] = 0.0
            r.pop("unowned_gb", None)
        text = b"".join(json.dumps(r).encode() + b"\n" for r in rows)
        if n.endswith(".gz"):
            with gzip.GzipFile(p, "wb", mtime=0) as f:
                f.write(text)
        else:
            open(p, "wb").write(text)
    cp = os.path.join(log, "current.json")
    cur = json.load(open(cp))
    t = cur["t"]
    ms = dict(MEASURES)
    cur.update(os="linux", ram_gb=62.7, app_gb=14.8, wired_gb=3.4, compressed_gb=0.0, swap_used_gb=0.2, swap_total_gb=8.0,
               swapfiles=1, free_pct=71, cached_gb=31.9, free_gb=12.6, disk_free_gb=412.0, jetsam_kills=0, pressure=1,
               away={"idle_s": None, "display_on": None, "locked": False}, psi={"mem_some": 2.4, "mem_full": 0.3},
               linux={"avail_gb": 44.5, "kswap_total_gb": 8.0, "kswap_free_gb": 7.8, "zram_disk_gb": 0.0, "overcommit": 0,
                      "commit_pct": 41, "margin_gb": 8.0},
               groups=[{"name": a, "mb": int(gb * 1024), "n": k} for a, gb, k in LINUX_GROUPS])
    cur.pop("unowned_gb", None)
    if desk:
        ms.update(zram=True)
        cur.update(compressed_gb=2.9, swap_used_gb=0.0, swap_total_gb=0.0, swapfiles=0,
                   linux=dict(cur["linux"], kswap_total_gb=8.0, kswap_free_gb=1.9, zram_disk_gb=8.0))
    elif variant == "nopsi":
        ms["psi"] = False
        cur.pop("psi")
    elif variant == "container":  # less than a sixteenth of the host's RAM: the host's figures must still pass a mirror
        ms.update(zswap=True, scope="cgroup")
        cur.update(ram_gb=CONTAINER_GB, app_gb=1.1, wired_gb=0.2, compressed_gb=0.1, cached_gb=0.4, free_gb=0.2, free_pct=30,
                   swap_used_gb=0.1, scope=dict(CONTAINER_SCOPE, host_avail_gb=44.5),
                   linux=dict(cur["linux"], avail_gb=0.6, margin_gb=0.3),
                   groups=[{"name": a, "mb": mb, "n": k} for a, mb, k in (("node", 820, 7), ("npm", 260, 2), ("sh", 4, 1))])
    elif variant == "limit":
        cur["psi"] = {"mem_some": 0.0, "mem_full": 0.0,
                      "limit": {"some": 97.0, "full": 41.0, "cgroups": ["docker:9d02c41b (node)"]}}
    elif variant == "longstall":
        cur.update(pressure=4, psi={"mem_some": 100.0, "mem_full": 100.0})
    elif variant == "hidden":
        ms["all_procs"] = False
    elif variant == "killsnone":
        ms["kills"] = "none"
    kind = "desktop" if desk else "container" if variant == "container" else "server"
    cur["daemon"].update(machine={"id": LINUX_MID, "name": "build-01", "os": "linux", "arch": "x86_64",
                                  "os_version": "Ubuntu 24.04.3 LTS", "kernel": "6.8.0-48-generic", "kind": kind, "cpus": 48,
                                  "virt": "none", "measures": ms}, all_procs=ms["all_procs"], user="oomphd")
    json.dump(cur, open(cp, "w"))
    # the Mac's jetsam reports become the OOM killer's kills; a kill at a container's limit, a limit stall
    ep = os.path.join(log, "events.jsonl")
    evs = [json.loads(x) for x in open(ep, "rb").read().splitlines()]
    out = []
    for e in evs:
        if e.get("kind") == "jetsam":
            k = max(1, int(e.get("kills") or 1))
            e = {"t": e["t"], "kind": "oom_kill", "kills": k, "cgroup": 0, "ooms": k, "by": {"kernel": k},
                 "top": {"java": k - 1, "node": 1} if k > 1 else {"node": 1}, "victims": []}
        out.append(e)
    out += [{"t": t - 5 * 3600, "kind": "oom_kill", "kills": 0, "cgroup": 6, "ooms": 6, "by": {"cgroup": 6}, "top": {"node": 6},
             "victims": []},
            {"t": t - 5 * 3600 + 60, "kind": "limit_stall", "cgroup": "docker:9d02c41b (node)"}]
    with open(ep, "w") as f:
        for e in sorted(out, key=lambda e: e["t"]):
            f.write(json.dumps(e) + "\n")
    idir = os.path.join(log, "incidents")
    for iid in os.listdir(idir):
        inc = json.load(open(os.path.join(idir, iid, "incident.json")))
        inc["reasons"] = [{"kind": "oom_kill", "t": inc["start"], "desc": "OOM killer killed node (pid 48211, 2.1 GB)"}] + \
            inc["reasons"][1:]
        json.dump(inc, open(os.path.join(idir, iid, "incident.json"), "w"))
    for days in (0.4, 1.4, 3.4):  # containers at their own limit: one quiet incident per day
        st = t - days * 86400
        iid = time.strftime("%Y%m%d-%H%M%S", time.localtime(st))
        os.makedirs(os.path.join(idir, iid))
        json.dump({"id": iid, "start": st, "end": st + 1800, "start_iso": iid, "quiet": True, "open": False,
                   "opened_by": "cgroup_oom_storm", "cgroups": [{"name": "docker:9d02c41b (node)", "ooms": 6, "first": st}],
                   "reasons": [{"kind": "cgroup_oom_storm", "t": st, "desc": "docker:9d02c41b (node): 6 OOMs at its limit"}]},
                  open(os.path.join(idir, iid, "incident.json"), "w"))
    # the ledger open to every account (D16): two hold reservations
    lp = os.path.join(led, "ledger.json")
    L = json.load(open(lp))
    for i, lease in enumerate(L["leases"]):
        lease["user"] = ("ada", "kim")[i % 2]
    json.dump(L, open(lp, "w"))


def linux(out, variant="server"):
    """build-01 (see the docstring): the week moved to end now, turned into a Linux machine's, mirrored live
    through `oomph serve --stdio`, then the variant's state; DIR/log and DIR/ledger are This Mac's week."""
    shutil.rmtree(out, ignore_errors=True)
    now = time.time()
    src, mir = os.path.join(out, "source"), os.path.join(out, "mirror")
    moved(src, now - 20)
    linuxize(src, variant)
    os.environ.update(OOMPH_DIR=os.path.join(src, "log"), OOMPH_LEDGER_DIR=os.path.join(src, "ledger"))
    serve = [sys.executable, "-I", "-B", os.path.join(ROOT, "daemon", "oomph.py"), "serve", "--stdio", "--now", repr(now)]
    r = sync.sync_once(serve, into=mir)
    st = json.load(open(os.path.join(mir, "sync.json")))
    st["offset_s"] = 0.0
    json.dump(st, open(os.path.join(mir, "sync.json"), "w"))
    status = json.load(open(os.path.join(mir, "status.json")))
    status.update(state="live", was=None, since=now - 3600, last_contact=now, error=None, updated=now + 120, pid=1,
                  transport="ssh", connect_ms=420)
    json.dump(status, open(os.path.join(mir, "status.json"), "w"))
    mj, cj = os.path.join(mir, "machine.json"), os.path.join(mir, "log", "current.json")
    if variant == "stopped":  # the logger there stopped 15 minutes ago; the link is up
        cur = json.load(open(cj))
        cur["t"] = now - 900
        json.dump(cur, open(cj, "w"))
    elif variant in ("denied", "absent"):
        json.dump(dict(json.load(open(mj)), logs=variant), open(mj, "w"))
        os.remove(cj)
        if variant == "absent":  # nothing is logged there: no history, no incidents; the ledger is read
            for n in os.listdir(os.path.join(mir, "log")):
                p = os.path.join(mir, "log", n)
                shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    # This Mac's week beside it, also ending now (its logger reports: the remembered tab opens), and the tab
    moved(os.path.join(out, "mac"), now - 20)
    shutil.move(os.path.join(out, "mac", "log"), os.path.join(out, "log"))
    shutil.move(os.path.join(out, "mac", "ledger"), os.path.join(out, "ledger"))
    shutil.rmtree(os.path.join(out, "mac"))
    base = os.path.join(out, "machines")
    os.makedirs(base, mode=0o700)
    shutil.copytree(mir, os.path.join(base, LINUX_MID))
    entry = {"mid": LINUX_MID, "id": LINUX_MID, "name": "build-01", "label": None, "transport": "ssh", "host": "build-01.lan",
             "port": None, "user": "kim", "addrs": [], "fp": None, "client": None, "version": "1.13.3", "caps": [],
             "added": now - 86400, "last_connected": now, "pinned": True, "order": 1, **LINUX_INFO}
    json.dump({"v": 1, "machines": [entry]}, open(os.path.join(base, "machines.json"), "w"), indent=1)
    shutil.rmtree(src)
    print("linux %s: %s (%d samples mirrored; --fixture %s, -selectedMachine %s)" % (variant, mir, r["counts"]["samples"],
                                                                                     out, LINUX_MID))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
