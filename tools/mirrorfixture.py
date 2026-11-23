#!/usr/bin/python3 -I
"""Mirror fixtures for the popup (roadmap 01 §3.4, §3.5, §12): another machine's mirror, made the
way the app will get one, so `--render-popup … --mirror DIR` can draw each state of a link.

    tools/mirrorfixture.py DIR [live|offline|fetching|machines|recents]

writes a made-up machine ("studio": the week of tools/topfixture.py, moved so that it ends now)
into DIR/source, mirrors it through a pipe with the real `oomph remote sync --once` into
DIR/mirror, and then sets the scene:

    live      the link is up (status.json: live, written just now by a process that exists)
    offline   the link dropped 40 minutes ago; an earlier drop left 2 hours not received
    fetching  just paired: the last 6 hours are in, the lists are still being fetched

    machines  five tabs (roadmap 01 R1a): DIR/machines is an OOMPH_MACHINES_DIR whose machines.json
              pins studio (live), mini-ci (not connected), gpu-box (its key changed), lab-mini
              (Blocked by macOS: Local Network) and air (live when the popup last closed, 40 minutes
              ago: an opening draws its grace, then Connecting…, never Not connected; -openedAgo 2
              renders the second step), and atlas, a Linux machine, which gets no tab; render-01 and
              build-box (over ssh) are Recents (not tabs), for the + and its popover (1.10.2)
    recents   the + on the line (R1b): DIR/machines knows render-01 and build-box as Recents only

Then: <app>/Contents/MacOS/oomph --render-popup out.png --mirror DIR/mirror [--dark] [--ai log], or
for the tabs OOMPH_MACHINES_DIR=DIR/machines <app> --render-popup out.png -machinesUI YES
[-selectedMachine m-7f3a9c1e5b2d4a68].
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
    if scene not in ("live", "offline", "fetching", "machines", "recents"):
        print(__doc__.strip())
        return 2
    if scene in ("machines", "recents"):
        return machines(out, tabs=scene == "machines")
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
        json.dump(dict(json.load(open(mj)), id=mid, name=name), open(mj, "w"))
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
          "air reconnecting, atlas Linux: no tab)" % base)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
