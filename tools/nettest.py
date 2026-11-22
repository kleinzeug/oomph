#!/usr/bin/python3 -I
"""Tests of the protocol core (roadmap 01 §12): `oomph serve --stdio` against fixture machines,
`oomph remote sync --once` through a pipe, coverage, the mirror writer and what crosses the wire.
Unprivileged and portable (no Mac needed); tools/selftest.py runs it. All data is invented.

    /usr/bin/python3 -I -B tools/nettest.py
"""
import base64
import gzip
import hashlib
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "daemon"))
import topfixture  # noqa: E402  (sets TZ to Europe/Berlin: fixture days are that zone's dates)
import oomph  # noqa: E402
import oomph_net as net  # noqa: E402
import oomph_sync as sync  # noqa: E402

PY = sys.executable
OOMPH = os.path.join(ROOT, "daemon", "oomph.py")
NOW = topfixture.NOW + 30  # the fixture machine's clock: half a minute after its last sample
TMP = tempfile.mkdtemp(prefix="oomph-nettest-")
failures = []


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)


def serve_argv(now=NOW):
    return [PY, "-I", "-B", OOMPH, "serve", "--stdio", "--now", repr(now)]


def use(fx):
    """Point this process's environment (and so every server it starts) at a fixture machine."""
    os.environ["OOMPH_DIR"], os.environ["OOMPH_LEDGER_DIR"] = os.path.join(fx, "log"), os.path.join(fx, "ledger")


def read(path):
    with open(path, "rb") as f:
        data = f.read()
    return gzip.decompress(data) if path.endswith(".gz") else data


def tree(d):
    """{relative path: sha1 of contents} of a directory, links and modes included."""
    out = {}
    for root, dirs, files in os.walk(d):
        for f in sorted(files + [x for x in dirs if os.path.islink(os.path.join(root, x))]):
            p = os.path.join(root, f)
            st = os.lstat(p)
            body = os.readlink(p).encode() if os.path.islink(p) else read(p) if os.path.isfile(p) else b""
            out[os.path.relpath(p, d)] = (oct(st.st_mode), hashlib.sha1(body).hexdigest())
    return out


# the blocks of a 1.9.1 logger, with disks far bigger than 16 times the RAM (a mirror before 1.9.1
# refuses any such *_gb: so `disks` must stay home)
BLOCKS_191 = {"cpu": {"n": 16, "p": 12, "e": 4, "busy": 3.2, "user": 2.5, "sys": 0.7, "p_busy": 2.9, "e_busy": 0.3,
                      "load": [3.1, 2.8, 2.2], "therm": 0},
              "gpu": [{"id": "gpu0", "name": "Apple M3 Max", "unified": True, "util": 12.0, "active": 12.0, "now": 10,
                       "src": "clients", "mem_gb": 1.5, "mem_alloc_gb": 4.2, "mem_limit_gb": 27.0}],
              "io": {"r_mb_s": 1.2, "w_mb_s": 3.4},
              "disks": [{"id": "data", "name": "Data", "mount": "/System/Volumes/Data", "total_gb": 926.4, "free_gb": 600.2,
                         "watch": True, "low_gb": 20, "crit_gb": 5, "level": "ok", "roles": ["home"]},
                        {"id": "vol:5E0C61B2-0F4A-4D1B-9C57-3A1D2B7E9F10", "name": "Scratch", "mount": "/Volumes/Scratch",
                         "total_gb": 1862.8, "free_gb": 1500.0, "watch": False, "kind": "external"}],
              "top_cpu": [{"pid": 7, "name": "cargo", "g": "iTerm2", "cpu": 2.0}]}


def make_machine(name="default"):
    """topfixture's machine with the samples a real logger writes: iso, pressure, the per-process
    lists and leases (which must stay home), a scalar no reader knows yet and a nested object no
    reader knows (which must not travel), the blocks of 1.9.1 on the newest day's samples;
    current.json with its daemon and machine blocks (and the 1.9.1 blocks)."""
    fx = os.path.join(TMP, name)
    log, led = topfixture.write_fixture(fx, "default")
    for n in sorted(os.listdir(log)):
        if not n.startswith("samples-"):
            continue
        p = os.path.join(log, n)
        rows = [json.loads(x) for x in read(p).splitlines()]
        for r in rows:
            r.update(iso=time.strftime("%Y-%m-%dT%H:%M:%S+01:00", time.localtime(r["t"])), hot=False, pressure=1,
                     ram_gb=36.0, os="macos", future_scalar=1.5, future_block={"x": 1},
                     top=[{"pid": 1, "name": "launchd", "mb": 20}], groups=[{"name": "Finder", "mb": 300, "n": 1}],
                     claude=[{"pid": 7, "cwd": "/srv/proj/atlas", "mb": 900, "n": 3}],
                     leases=[{"id": "r1", "state": "granted", "gb": 2.0, "purpose": "build"}])
            if n == "samples-%s.jsonl" % time.strftime("%Y-%m-%d", time.localtime(NOW)):
                r.update(BLOCKS_191)
        text = b"".join(json.dumps(r).encode() + b"\n" for r in rows)
        if n.endswith(".gz"):
            with gzip.GzipFile(p, "wb", mtime=0) as f:
                f.write(text)
        else:
            open(p, "wb").write(text)
    cur = json.load(open(os.path.join(log, "current.json")))
    cur["daemon"]["machine"] = {"id": "m-0123456789abcdef", "name": "studio", "os": "macos", "arch": "arm64",
                                "os_version": "macOS 27.2", "kernel": "27.2.0", "kind": "desktop", "cpus": 16,
                                "virt": "none", "measures": {"memory": True, "pressure": "kernel"}}
    cur["top"] = [{"pid": 1, "name": "launchd", "mb": 20, "secret": "x" * 500, "nested": {"a": 1}}] * 40
    cur.update(BLOCKS_191)
    json.dump(cur, open(os.path.join(log, "current.json"), "w"))
    return fx


def page_rows(page):
    return [json.loads(x) for x in net.unpack(page["data"])]


def rpc(srv, method, **params):
    r = srv.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    if "error" in r:
        raise net.RPCError(r["error"]["code"], r["error"]["message"], r["error"].get("data"))
    return r["result"]


def stdio(lines, now=NOW, timeout=20):
    """Raw lines through `oomph serve --stdio`; its answers, parsed."""
    p = subprocess.run(serve_argv(now), input=b"".join(x + b"\n" for x in lines), capture_output=True, timeout=timeout)
    return [json.loads(x) for x in p.stdout.splitlines() if x.strip()]


def hello():
    return net.dumps({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"proto": [1, 1]}})


# ------------------------------------------------------------------ a fixture machine, mirrored
fx = make_machine()
use(fx)
before = tree(fx)
mir = os.path.join(TMP, "mirror")
t0 = time.time()
r = subprocess.run([PY, "-I", "-B", OOMPH, "remote", "sync", "--once", "--into", mir, "--json", "--"] + serve_argv(),
                   capture_output=True, text=True, timeout=180)
res = json.loads(r.stdout or "{}")
check(r.returncode == 0 and res.get("ok") and res["counts"]["samples"] > 10000,
      "remote sync --once through a pipe: %s samples, %s days, %.1f s"
      % (res.get("counts", {}).get("samples"), res.get("days"), time.time() - t0) + (r.stderr[-300:] if r.returncode else ""))
check(tree(fx) == before, "the server wrote nothing into the machine's directories")

slog = os.path.join(fx, "log")
mlog = os.path.join(mir, "log")
same, days = True, 0
for n in sorted(os.listdir(slog)):
    if not n.startswith("samples-"):
        continue
    day = n[8:18]
    want = b"".join(net.dumps(oomph.slim_sample(json.loads(x))) + b"\n" for x in read(os.path.join(slog, n)).splitlines())
    got = [x for x in os.listdir(mlog) if x.startswith("samples-" + day)]
    same = same and len(got) == 1 and read(os.path.join(mlog, got[0])) == want
    days += 1
check(same and days == 8, "every day of samples in the mirror is the slimmed source, byte for byte (%d days)" % days)
gz = sorted(x for x in os.listdir(mlog) if x.endswith(".gz"))
check(len(gz) == 7 and os.path.exists(os.path.join(mlog, "samples-2026-11-20.jsonl")),
      "past days fully covered are gzipped (%d); the remote's today stays plain" % len(gz))
one = json.loads(read(os.path.join(mlog, "samples-2026-11-20.jsonl")).splitlines()[0])
check(not {"top", "groups", "claude", "leases", "future_block"} & set(one) and one.get("future_scalar") == 1.5
      and set(one["away"]) <= set(oomph.AWAY_KEYS), "slim samples: scalars and away only; a new scalar travels")
today = [json.loads(x) for x in read(os.path.join(mlog, "samples-2026-11-20.jsonl")).splitlines()]
check(all(x.get("cpu", {}).get("busy") == 3.2 and x["gpu"][0]["util"] == 12.0 and x["io"]["w_mb_s"] == 3.4 and
          "disks" not in x and "top_cpu" not in x for x in today),
      "1.9.1 samples (disks of 926 and 1,863 GB on a 36 GB machine) all reach the mirror with CPU, GPU and I/O; "
      "the disks stay home (%d samples)" % len(today))

srv = net.Server(slog, os.path.join(fx, "ledger"), now=NOW)
rpc(srv, "hello", proto=[1, 1])
ev_src = [net.dumps(net.scrub(json.loads(x))) for x in read(os.path.join(slog, "events.jsonl")).splitlines()]
check(read(os.path.join(mlog, "events.jsonl")).splitlines() == ev_src, "events mirrored in file order, byte for byte")
recs = [oomph._valid_finished(json.loads(x), log=True) for x in read(os.path.join(fx, "ledger", "reservations.jsonl")).splitlines()]
check(read(os.path.join(mir, "ledger", "reservations.jsonl")).splitlines() == [net.dumps(net.record_out(x)) for x in recs],
      "reservation records mirrored byte for byte (%d)" % len(recs))
snap = json.loads(net.unpack(rpc(srv, "ledger")["data"])[0])
mled = json.load(open(os.path.join(mir, "ledger", "ledger.json")))
check(mled["leases"] == snap["leases"] and len(mled["leases"]) == 4 and all("holder" in x for x in mled["leases"]),
      "the ledger snapshot: live leases from named fields (%d)" % len(mled["leases"]))
incs = sorted(os.listdir(os.path.join(mlog, "incidents")))
check(incs == sorted(i[0] for i in topfixture.INCIDENTS) and all(
    json.load(open(os.path.join(mlog, "incidents", i, "incident.json"))) ==
    net.incident_out(json.load(open(os.path.join(slog, "incidents", i, "incident.json")))) for i in incs),
    "incidents mirrored from their named fields (%d)" % len(incs))
cur = json.load(open(os.path.join(mlog, "current.json")))
check(len(cur["top"]) == 25 and set(cur["top"][0]) == {"pid", "name", "mb"} and cur["daemon"]["machine"]["id"] ==
      "m-0123456789abcdef" and "virt" in cur["daemon"]["machine"] and cur["gpu"][0]["name"] == "Apple M3 Max" and
      cur["cpu"]["busy"] == 3.2 and "disks" not in cur,
      "current.json: rebuilt from the whitelist (top capped at 25, unknown fields gone; CPU and GPU, no disks)")
# what a mirror lets in: a disk's size is bounded apart from the RAM (an 8 GB Mac with a 1 TB disk)
small = dict(BLOCKS_191, t=topfixture.NOW - 60, ram_gb=8.0, app_gb=3.0, free_gb=1.0, disk_free_gb=900.0,
             disks=[dict(BLOCKS_191["disks"][0], total_gb=1000.0, free_gb=900.0)])
ing = sync.Ingest({"now": topfixture.NOW, "ram_gb": 8.0})
check(ing.row(net.dumps(oomph.slim_sample(small)), "samples") and ing.row(net.dumps(oomph.full_sample(small)), "samples")
      and ing.row(net.dumps(small), "samples") and ing.dropped["samples"] == 0,
      "ingest: an 8 GB machine with 900 GB free on a 1 TB disk is let in, slim, full and with its disks block")
check(not ing.row(net.dumps(dict(small, app_gb=200.0)), "samples") and
      not ing.row(net.dumps(dict(small, disks=[{"id": "data", "total_gb": 1e7}])), "samples") and
      not ing.row(net.dumps(dict(small, gpu=[{"mem_gb": 1000.0}])), "samples"),
      "ingest: memory above 16 times the RAM, a 10 PB disk and a GPU's 1 TB on an 8 GB machine are still refused")
st = json.load(open(os.path.join(mir, "sync.json")))
mj = json.load(open(os.path.join(mir, "machine.json")))
check(st["have"] and st["have"][0][0] <= mj["oldest"] and st["have"][-1][1] >= NOW - 120 and len(st["have"]) == 1
      and all(st["synced"].values()) and mj["name"] == "studio" and mj["id"] == "m-0123456789abcdef",
      "sync.json: one covered stretch from the oldest sample to now, every list synced; machine.json names it")
stj = json.load(open(os.path.join(mir, "status.json")))
check(stj["state"] == "idle" and stj["was"] == "live" and stj["error"] is None, "status.json: idle, was live")
env = dict(os.environ, OOMPH_DIR=mlog, OOMPH_LEDGER_DIR=os.path.join(mir, "ledger"))
cli = subprocess.run([PY, "-I", "-B", OOMPH, "incidents"], capture_output=True, text=True, timeout=60, env=env)
cli2 = subprocess.run([PY, "-I", "-B", OOMPH, "reservations", "--history", "--last", "60d", "--json"], capture_output=True,
                      text=True, timeout=60, env=env)
check(cli.returncode == 0 and cli.stdout.count("\n") == 4 and json.loads(cli2.stdout or "{}").get("finished") == 171,
      "the CLI reads a mirror like any log and ledger directory (incidents, reservation history)")

# again: nothing new, nothing rewritten but the bookkeeping
snap1 = {k: v for k, v in tree(mir).items() if not k.endswith(("status.json", "sync.json", "machine.json"))}
r2 = sync.sync_once(serve_argv(), into=mir)
snap2 = {k: v for k, v in tree(mir).items() if not k.endswith(("status.json", "sync.json", "machine.json"))}
check(snap1 == snap2 and r2["counts"]["samples"] < 100 and r2["counts"]["events"] == 0 and r2["counts"]["records"] == 0,
      "a second sync changes nothing: it asks only the overlap (%d samples) and gets no new rows" % r2["counts"]["samples"])

# small pages: the same mirror, page by page
mir_s = os.path.join(TMP, "mirror-small")
r3 = sync.sync_once(serve_argv(), into=mir_s, max_bytes=4096)
same = all(read(os.path.join(mlog, n)) == read(os.path.join(mir_s, "log", n)) for n in os.listdir(mlog) if n.startswith("samples-"))
check(same and read(os.path.join(mir_s, "ledger", "reservations.jsonl")) == read(os.path.join(mir, "ledger", "reservations.jsonl"))
      and read(os.path.join(mir_s, "log", "events.jsonl")) == read(os.path.join(mlog, "events.jsonl")),
      "4 KB pages give the same mirror")

# a hole, refilled newest first
day = os.path.join(mir_s, "log", "samples-2026-11-20.jsonl")
lines = read(day).splitlines()
keep = [x for x in lines if not (topfixture.T(20, 9) <= json.loads(x)["t"] <= topfixture.T(20, 11))]
open(day, "wb").write(b"".join(x + b"\n" for x in keep))
sj = json.load(open(os.path.join(mir_s, "sync.json")))
cov = sync.Coverage(sj["have"])
cov.remove(topfixture.T(20, 9), topfixture.T(20, 11))
sj["have"] = cov.spans
json.dump(sj, open(os.path.join(mir_s, "sync.json"), "w"))
seen = []
orig = sync.Sync.samples
sync.Sync.samples = lambda self, a, b: (seen.append((a, b)), orig(self, a, b))[1]
sync.sync_once(serve_argv(), into=mir_s)
sync.Sync.samples = orig
check(read(day) == read(os.path.join(mlog, "samples-2026-11-20.jsonl")) and seen and seen[0][1] >= NOW - 60
      and any(a <= topfixture.T(20, 9) and b >= topfixture.T(20, 11) for a, b in seen),
      "a hole in the coverage is asked for and filled; the newest window first (%d windows)" % len(seen))

# ------------------------------------------------------------------ coverage, against a brute-force model
rng = random.Random(7)
ok = True
for _ in range(300):  # cells: [a, b] covers the unit cells a … b-1
    c, model = sync.Coverage(), set()
    for _ in range(rng.randint(1, 12)):
        a = rng.randint(0, 60)
        b = a + rng.randint(0, 15)
        if rng.random() < 0.7:
            c.add(a, b)
            model |= set(range(a, b))
        else:
            c.remove(a, b)
            model -= set(range(a, b))
    cells = {i for x, y in c.spans for i in range(x, y)}
    lo, hi = rng.randint(0, 40), rng.randint(40, 80)
    hole_cells = {i for x, y in c.holes(lo, hi) for i in range(x, y)}
    ok = ok and cells == model and all(c.spans[i][1] < c.spans[i + 1][0] for i in range(len(c.spans) - 1)) \
        and all(x < y for x, y in c.spans) and hole_cells == set(range(lo, hi)) - model \
        and all(c.covers(i, i + 1) == (i in model) for i in range(0, 80))
check(ok, "coverage arithmetic: 300 random histories of add and remove agree with a model")
ws = sync.windows([[0, 30 * 3600], [40 * 3600, 50 * 3600]], 50 * 3600 - 24 * 3600)
check(ws[0] == [44 * 3600, 50 * 3600] and all(b - a <= sync.WINDOW_S for a, b in ws) and ws[-1][0] == 0
      and [w for w in ws if w[1] > 26 * 3600] == ws[:len([w for w in ws if w[1] > 26 * 3600])],
      "windows: the last day first, newest first, at most 6 h each")

# ------------------------------------------------------------------ cursors are positions
cx = os.path.join(TMP, "cursors")
os.makedirs(os.path.join(cx, "log"))
os.makedirs(os.path.join(cx, "ledger"))
evs = [{"t": 1000.0, "kind": "jetsam", "n": i} for i in range(40)]                 # forty of one time
evs += [{"t": 1001.0 + (0.1 if i % 3 == 0 else 0), "kind": "log", "n": 40 + i} for i in range(30)]  # out of order
evs += [{"t": 900.0 + i, "kind": "log", "n": 70 + i} for i in range(10)]           # the clock stepped back
evs += [{"t": 1100.0, "kind": "log", "n": 80}]
with open(os.path.join(cx, "log", "events.jsonl"), "w") as f:
    f.write("".join(json.dumps(dict(e, pad=os.urandom(150).hex())) + "\n" for e in evs))
cs = net.Server(os.path.join(cx, "log"), os.path.join(cx, "ledger"), now=2000.0)
rpc(cs, "hello", proto=[1, 1])
got, after, pages = [], [0, 0], 0
while pages < 200:
    p = rpc(cs, "events", after=after, max_bytes=4096)
    got += [e["n"] for e in page_rows(p)]
    pages += 1
    if not p["more"]:
        break
    after = p["next"]
check(got == list(range(81)) and pages >= 3, "events: %d pages, every row once in file order (a group of one time split "
      "across pages, rows out of order, a clock step back)" % pages)
p = rpc(cs, "events", after=[1000.0, 7], max_bytes=4096)
check(page_rows(p)[0]["n"] == 7 and p["anchored"], "a cursor names the k-th row of its time")
p = rpc(cs, "events", after=[1000.5, 3], max_bytes=4096)
check(not p["anchored"] and page_rows(p)[0]["n"] == 40, "a cursor whose row is gone: anchored false, from the first later row")
p = rpc(cs, "events", after=[1100.0, 1])
check(p["n"] == 0 and not p["more"] and p["next"] == [1100.0, 1], "past the last row: an empty page, more false")

# ------------------------------------------------------------------ too big, too strange, too many
hx = os.path.join(TMP, "hostile")
os.makedirs(os.path.join(hx, "log", "incidents", "20261120-101010"))
os.makedirs(os.path.join(hx, "log", "incidents", "20261120-111111"))
os.makedirs(os.path.join(hx, "ledger"))
t = topfixture.NOW
big = {"t": t - 60, "app_gb": 1.0, "blob": "x" * (1 << 20)}
rows = [{"t": t - 120, "app_gb": 1.0, "wired_gb": 1.0, "compressed_gb": 1.0, "swap_used_gb": 0.0}, big,
        {"t": t - 30, "app_gb": 2.0, "wired_gb": 1.0, "compressed_gb": 1.0, "swap_used_gb": 0.0,
         "long": "y" * 5000, "nested": [{"deep": {"er": 1}}]}]
with open(os.path.join(hx, "log", "samples-%s.jsonl" % time.strftime("%Y-%m-%d", time.localtime(t))), "w") as f:
    f.write("".join(json.dumps(x) + "\n" for x in rows))
with open(os.path.join(hx, "log", "events.jsonl"), "w") as f:
    f.write(json.dumps({"t": t - 50, "kind": "log", "msg": "z" * (100 << 10)}) + "\n" +
            json.dumps({"t": t - 40, "kind": "log", "msg": "fine", "deep": {"a": {"b": {"c": {"d": {"e": 1}}}}}}) + "\n")
json.dump({"t": t, "pad": "p" * (2 << 20)}, open(os.path.join(hx, "log", "current.json"), "w"))
json.dump({"id": "20261120-101010", "start": t - 9000, "reasons": [], "pad": "q" * (300 << 10)},
          open(os.path.join(hx, "log", "incidents", "20261120-101010", "incident.json"), "w"))
json.dump({"id": "20261120-111111", "start": t - 5000, "reasons": [{"kind": "pressure", "desc": "d", "t": t - 5000,
                                                                    "evil": "e"}], "open": False, "rogue": [1] * 99},
          open(os.path.join(hx, "log", "incidents", "20261120-111111", "incident.json"), "w"))
hs = net.Server(os.path.join(hx, "log"), os.path.join(hx, "ledger"), now=t)
rpc(hs, "hello", proto=[1, 1])
p = rpc(hs, "samples", after=[0, 0], to=t)
rs = page_rows(p)
check([x["t"] for x in rs] == [t - 120, t - 30] and p["skipped"] == 1 and len(rs[1]["long"]) == oomph.SLIM_STR
      and "nested" not in rs[1], "a 1 MB sample line is skipped and counted; strings are cut, nested values stay home")
p = rpc(hs, "events", after=[0, 0])
rs = page_rows(p)
check(len(rs) == 1 and p["skipped"] == 1 and p["next"][0] == t - 40, "a 100 KB event is skipped, the cursor moves past it")
s = rpc(hs, "subscribe", streams=[])
check(s["current"] is None and s["current_skipped"] is True, "a 2 MB current.json: current null, current_skipped true")
p = rpc(hs, "incidents", after="")
rs = page_rows(p)
check([x["id"] for x in rs] == ["20261120-111111"] and p["skipped"] == 1 and "rogue" not in rs[0]
      and "evil" not in rs[0]["reasons"][0], "a 300 KB incident.json is skipped; incidents travel as named fields")
try:
    rpc(hs, "samples", after=[0, 0], to=t - 86400 * 30)
    check(False, "a window older than retention is refused")
except net.RPCError as e:
    check(e.code == net.ERR["retention"] and e.data.get("oldest") == t - 120, "a window older than retention: -32040 "
          "with the oldest sample")

# the shared ledger directory: whatever is planted there is absent, and nothing waits on it
led = os.path.join(hx, "ledger")
os.mkfifo(os.path.join(led, "ledger.json"))
os.symlink(os.path.join(hx, "log", "current.json"), os.path.join(led, "reservations.jsonl"))
t1 = time.time()
snap = json.loads(net.unpack(rpc(hs, "ledger")["data"])[0])
p = rpc(hs, "reservations", after=[0, 0])
check(snap == {"leases": [], "state": {}, "history": []} and p["n"] == 0 and time.time() - t1 < 2,
      "a FIFO at ledger.json and a link at reservations.jsonl: read as absent, nothing waits (%.2f s)" % (time.time() - t1))
os.unlink(os.path.join(led, "ledger.json"))
with open(os.path.join(led, "ledger.json"), "w") as f:
    json.dump({"seq": 5, "leases": [{"id": "r5", "state": "granted", "gb": 2.0, "purpose": "p" * 5000, "requested": t - 60,
                                     "granted": t - 60, "holder": {"pid": 5, "start": 1, "kind": "session", "x": "y"},
                                     "extra": {"deep": 1}}, {"id": "r6", "gb": "lots"}], "history": []}, f)
snap = json.loads(net.unpack(rpc(hs, "ledger")["data"])[0])
check(len(snap["leases"]) == 1 and len(snap["leases"][0]["purpose"]) == 200 and "extra" not in snap["leases"][0]
      and set(snap["leases"][0]["holder"]) == {"pid", "start", "kind"}, "ledger: malformed leases dropped, fields named and cut")

# ------------------------------------------------------------------ the stdio front end
use(fx)
out = stdio([net.dumps({"jsonrpc": "2.0", "id": 1, "method": "ledger"}), hello(),
             net.dumps({"jsonrpc": "2.0", "id": 2, "method": "nosuch"}),
             net.dumps({"jsonrpc": "2.0", "id": 3, "method": "samples", "params": {"after": "x"}}),
             b"{not json", net.dumps({"jsonrpc": "2.0", "id": 4, "method": "ping"})])
codes = [m.get("error", {}).get("code") for m in out]
check(codes == [-32001, None, -32601, -32602, -32700, None] and out[1]["result"]["auth"] == ["transport"]
      and out[5]["result"]["now"] == NOW, "serve --stdio: nothing before hello, then errors by the book, ping")
out = stdio([net.dumps({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"proto": [2, 3]}})])
check(out and out[0]["error"]["code"] == -32020 and out[0]["error"]["data"] == {"min": 1, "max": 1},
      "a client speaking only newer protocols: -32020 with the server's range")
out = stdio([b"[" * 5000])
check(out == [{"jsonrpc": "2.0", "method": "bye", "params": {"reason": "too_large"}}],
      "a line over 4 KB before hello ends the session")
out = stdio([hello(), net.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {"pad": "x" * 30000}})])
check(len(out) == 2 and "result" in out[1], "after hello, lines up to 64 KB")

# a noisy pipe: a login banner before oomph answers
noisy = os.path.join(TMP, "noisy.sh")
with open(noisy, "w") as f:
    f.write('#!/bin/sh\nprintf "Welcome to studio\\nLast login: today\\n"\nexec "$@"\n')
os.chmod(noisy, 0o755)
r = sync.sync_once(["/bin/sh", noisy] + serve_argv(), into=os.path.join(TMP, "mirror-noisy"))
check(r["counts"]["samples"] > 10000, "a banner before the first frame is skipped")
loud = os.path.join(TMP, "loud.sh")
with open(loud, "w") as f:
    f.write('#!/bin/sh\necho "Welcome to studio"\nhead -c 100000 /dev/zero | tr "\\0" "x" | fold -w 500\necho\nexec "$@"\n')
os.chmod(loud, 0o755)
try:
    sync.sync_once(["/bin/sh", loud] + serve_argv(), into=os.path.join(TMP, "mirror-loud"))
    check(False, "100 KB of noise: not_oomph")
except sync.SyncError as e:
    check(e.code == "not_oomph" and "Welcome to studio" in e.detail,
          "100 KB of noise: not_oomph, quoting the first line (%s)" % e.detail)
    st = json.load(open(os.path.join(TMP, "mirror-loud", "status.json")))
    check(st["was"] == "offline" and st["error"] == "not_oomph", "status.json says why")
try:
    sync.sync_once(["/bin/sh", "-c", "echo 'sam@studio: Permission denied (publickey).' >&2; exit 255"],
                   into=os.path.join(TMP, "mirror-denied"))
    check(False, "a server that never answers")
except sync.SyncError as e:
    check(e.code == "not_oomph" and "Permission denied" in e.detail, "a command that fails: its last line of stderr "
          "is quoted (%s)" % e.detail)

# ------------------------------------------------------------------ the live stream
live = os.path.join(TMP, "live")
shutil.copytree(fx, live)
use(live)
dayf = os.path.join(live, "log", "samples-2026-11-20.jsonl")
p = subprocess.Popen(serve_argv(NOW + 60), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
rd = net.Lines(p.stdout.fileno(), net.LINE_OUT)


def say(i, method, **params):
    p.stdin.write(net.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params}) + b"\n")
    p.stdin.flush()


def wait_for(pred, secs):
    end = time.time() + secs
    while time.time() < end:
        line = rd.read(max(0.05, end - time.time()))
        if line is None:
            break
        m = json.loads(line)
        if pred(m):
            return m
    return None


say(1, "hello", proto=[1, 1])
wait_for(lambda m: m.get("id") == 1, 10)
say(2, "subscribe", streams=["samples", "events", "ledger", "incidents"])
sub = wait_for(lambda m: m.get("id") == 2, 10)
last_t = json.loads(read(dayf).splitlines()[-1])["t"]
row = dict(json.loads(read(dayf).splitlines()[-1]), t=last_t + 30, top=[{"pid": 9}])
with open(dayf, "ab") as f:
    half = json.dumps(row).encode()
    f.write(half[:40])
    f.flush()
    time.sleep(1.3)
    f.write(half[40:] + b"\n")
tick = wait_for(lambda m: m.get("method") == "tick", 4)
check(sub and sub["result"]["current"] and tick and [x["t"] for x in tick["params"]["samples"]] == [last_t + 30]
      and tick["params"]["prev"] == last_t and "top" not in tick["params"]["samples"][0],
      "subscribe: a sample written in two parts arrives once, whole and slim, with prev from the file")
with open(os.path.join(live, "log", "events.jsonl"), "a") as f:
    f.write(json.dumps({"t": last_t + 31, "kind": "log", "msg": "hi"}) + "\n")
note = wait_for(lambda m: m.get("method") == "events", 4)
check(note and note["params"]["events"][0]["msg"] == "hi", "subscribe: an appended event arrives")
lj = os.path.join(live, "ledger", "ledger.json")
L = json.load(open(lj))
L["leases"] = L["leases"][:1]
tmpf = lj + ".tmp"
json.dump(L, open(tmpf, "w"))
os.replace(tmpf, lj)
note = wait_for(lambda m: m.get("method") == "ledger", 4)
check(note and len(note["params"]["leases"]) == 1, "subscribe: a changed ledger arrives")
os.makedirs(os.path.join(live, "log", "incidents", "20261120-132700"))
json.dump({"id": "20261120-132700", "start": last_t, "open": True, "reasons": [{"kind": "pressure", "desc": "x", "t": last_t}]},
          open(os.path.join(live, "log", "incidents", "20261120-132700", "incident.json"), "w"))
note = wait_for(lambda m: m.get("method") == "incident", 4)
check(note and note["params"]["incident"]["id"] == "20261120-132700", "subscribe: a new incident arrives")
p.stdin.close()
p.wait(10)
p.stdout.close()

# ------------------------------------------------------------------ a hostile server
evil = os.path.join(TMP, "evil.py")
with open(evil, "w") as f:
    f.write(r'''import base64, json, sys, zlib
T = %r
def page(rows, **kw):
    d = dict(enc="zlib+b64", data=base64.b64encode(zlib.compress("\n".join(rows).encode())).decode(), **kw)
    return d
def raw(o):
    return json.dumps(o, allow_nan=True)
for line in sys.stdin:
    q = json.loads(line); m, i = q["method"], q["id"]
    if m == "hello":
        r = {"proto": 1, "auth": ["transport"], "machine": {"id": "../../etc", "name": "e\x1b[31mvil‮", "now": T,
             "oldest": T - 3600, "ram_gb": 16.0, "tz": "+01:00"}}
    elif m == "subscribe":
        r = {"current": {"t": T, "app_gb": 1e308, "name": "x"}, "current_skipped": False}
    elif m == "ledger":
        r = page([raw({"leases": [{"id": "r1", "gb": 1e308, "requested": T}, {"id": "r2", "gb": 1.0,
                  "requested": T, "purpose": "\x07bell "}], "state": {}, "history": []})])
    elif m == "incidents":
        r = page([raw({"id": "../../x", "start": T}), raw({"id": "20261120-101010", "start": T, "reasons": []})],
                 next="20261120-101010", more=False, open=[])
    elif m == "samples":
        rows = [raw({"t": T - 10, "app_gb": 1e308}), raw({"t": T - 20, "app_gb": -3}), raw({"t": 1.0, "app_gb": 1}),
                raw({"t": 4102444800.0, "app_gb": 1}), raw({"t": T - 30, "app_gb": 2.0, "iso": "../../../x",
                "s": "ok\x1b]52;c;x\x07"}), "[" * 100000 + "]" * 100000, raw({"t": float("inf")})]
        r = page(rows, next=q["params"]["after"], more=True, to=T)
    elif m in ("events", "reservations"):
        r = page([], next=[0, 0], more=False)
    else:
        r = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": i, "result": r}) + "\n"); sys.stdout.flush()
''' % (topfixture.NOW,))
em = os.path.join(TMP, "mirror-evil")
outside = tree(TMP)
try:
    r = sync.sync_once([PY, "-I", "-B", evil], into=em)
    err = None
except sync.SyncError as e:
    r, err = None, e
after_t = {k: v for k, v in tree(TMP).items() if not k.startswith("mirror-evil")}
check(after_t == {k: v for k, v in outside.items() if not k.startswith("mirror-evil")},
      "a hostile server: nothing written outside the mirror")
files = tree(em)
rows = [json.loads(x) for n in files if "samples-" in n for x in read(os.path.join(em, n)).splitlines()]
check(err is None and [x["t"] for x in rows] == [topfixture.NOW - 30] and rows[0]["s"] == "ok]52;c;x"
      and sorted(n for n in files if "incidents" in n) == ["log/incidents/20261120-101010/incident.json"]
      and "log/current.json" not in files and r["dropped"]["samples"] == 7,
      "a hostile server: 1e308, negative GB, 1970 and 2100 dropped and counted, ../ ids refused, controls stripped "
      "(%s)" % (err or r["dropped"]))
bad = json.load(open(os.path.join(em, "sync.json")))["bad"]
check(bad and bad[0]["why"] == "stuck", "a reply that does not move the cursor ends that window (marked bad)")
lj = json.load(open(os.path.join(em, "ledger", "ledger.json")))
check([x["id"] for x in lj["leases"]] == ["r2"] and lj["leases"][0]["purpose"] == "bell",
      "the ledger from a hostile server: 1e308 GB refused, controls stripped")

# a page that inflates past its limit
bomb = base64.b64encode(zlib.compress(b"\0" * (net.INFLATE + 10))).decode()
try:
    net.unpack(bomb)
    check(False, "an inflate bomb is refused")
except ValueError:
    check(True, "a page that inflates past 16 MB is refused")

# the mirror's own directory: a link planted there is never followed
lm = os.path.join(TMP, "mirror-link")
os.makedirs(lm)
victim = os.path.join(TMP, "victim")
os.makedirs(victim)
os.symlink(victim, os.path.join(lm, "log"))
use(fx)
try:
    sync.sync_once(serve_argv(), into=lm)
    check(False, "a link planted in the mirror")
except (sync.SyncError, OSError):
    check(os.listdir(victim) == [], "a link planted in the mirror is not followed (the sync fails, the target is untouched)")

# broken answers: a reason and exit 1, never a traceback, and the next run is not stuck
odd = os.path.join(TMP, "odd.py")
with open(odd, "w") as f:
    f.write(r"""import base64, json, sys, zlib
T, MODE = %r, sys.argv[1]
def page(rows, **kw):
    return dict(enc="zlib+b64", data=base64.b64encode(zlib.compress("\n".join(rows).encode())).decode(), **kw)
for line in sys.stdin:
    q = json.loads(line); m, i = q["method"], q["id"]
    if m == "hello":
        r = {"proto": 1, "auth": ["transport"], "machine": {"id": "m-00000000000000aa", "name": "odd", "now": T,
             "oldest": T - 3600, "ram_gb": 16.0, "tz": "+01:00"}}
    elif m == "subscribe":
        r = {"current": None, "current_skipped": False}
    elif m == "ledger":
        r = page([json.dumps({"leases": [], "state": {}, "history": []})])
    elif m == "incidents" and MODE == "baddate":
        r = page([json.dumps({"id": "20251399-999999", "start": T})], next="20251399-999999", more=False,
                 open=["20251399-999999"])
    elif m == "incidents":
        r = page([], next="", more=False, open=5)
    elif m == "samples" and MODE == "notdict":
        r = 5
    elif m == "samples":
        r = page([], next=q["params"]["after"], more=False, to=q["params"]["to"])
    else:
        r = page([], next=[0, 0], more=False)
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": i, "result": r}) + "\n"); sys.stdout.flush()
""" % (topfixture.NOW,))
om = os.path.join(TMP, "mirror-odd")
os.makedirs(os.path.join(om, "log", "incidents", "20251399-999999"), mode=0o700)  # left by an older client
open(os.path.join(om, "log", "incidents", "20251399-999999", "incident.json"), "w").write("{}\n")
runs = []
for mode in ("baddate", "baddate", "openint"):
    try:
        sync.sync_once([PY, "-I", "-B", odd, mode], into=om)
        runs.append(None)
    except sync.SyncError as e:
        runs.append(e.code)
check(runs == [None] * 3 and os.listdir(os.path.join(om, "log", "incidents")) == []
      and json.load(open(os.path.join(om, "sync.json")))["incidents_open"] == [],
      "an incident id that is no date (20251399-999999) and `open: 5`: skipped, an old folder of such a name "
      "pruned, every run fine (%s)" % runs)
r = subprocess.run([PY, "-I", "-B", OOMPH, "remote", "sync", "--once", "--into", om, "--", PY, "-I", "-B", odd,
                    "notdict"], capture_output=True, text=True, timeout=60)
stj = json.load(open(os.path.join(om, "status.json")))
check(r.returncode == 1 and "Traceback" not in r.stderr and stj["error"] == "not_oomph",
      "a samples answer that is not an object: exit 1 with a reason, status.json says why (%r)" % r.stderr[-200:])
orig = sync.Sync.events
sync.Sync.events = lambda self: {}["boom"]
try:
    sync.sync_once([PY, "-I", "-B", odd, "openint"], into=om)
    err = None
except sync.SyncError as e:
    err = e.code
sync.Sync.events = orig
stj = json.load(open(os.path.join(om, "status.json")))
check(err == "bad" and stj["error"] == "bad" and stj["was"] == "offline",
      "anything else that breaks a run: SyncError bad, status.json written (%s)" % err)


class Recorder:
    def __init__(self):
        self.calls = []

    def call(self, method, params=None):
        self.calls.append((method, params))
        return {"enc": "zlib+b64", "data": net.pack([]), "next": "", "more": False, "open": []}


rm = sync.Mirror(os.path.join(TMP, "mirror-midnight"))
rm.put_json("", "sync.json", {"incidents_to": "20261120-000000", "incidents_open": ["20261120-000000"]})
rec = Recorder()
sync.Sync(rec, rm, {"now": NOW, "tz": "+01:00"}).incidents()
check([p["after"] for m, p in rec.calls] == ["20261120-000000", "20261119-235959"],
      "an open incident from midnight is asked for again from the second before it")
T0 = topfixture.T(20, 12)
day = time.strftime("%Y-%m-%d", time.localtime(T0))
check(sync._day_of({"t": T0, "iso": "9999-01-01T00:00:00+01:00"}, 3600) == day
      and sync._day_of({"t": T0, "iso": "2026-13-45T00:00:00+01:00"}, 3600) == day
      and sync._day_of({"t": topfixture.T(20, 0) + 600, "iso": "2026-11-19T23:10:00+00:00"}, 3600) == "2026-11-19",
      "a sample's day: its iso date only when it is the day of its time or one next to it")
check(hs.machine()["name"] == net.clean(socket.gethostname(), 64).split(".")[0],
      "a logger that names no machine: the server names it by its host name")

# a server started by a large process: its own growth counts, not the parent's peak
big = ("import subprocess, sys\nb = b'\\x01' * (130 << 20)\n"
       "p = subprocess.run(sys.argv[1:], input=sys.stdin.buffer.read(), capture_output=True)\n"
       "sys.stdout.buffer.write(p.stdout)\n")
reqs = [hello()] + [net.dumps({"jsonrpc": "2.0", "id": i + 2, "method": m, "params": {}})
                    for i, m in enumerate(("ledger", "events", "incidents"))]
p = subprocess.run([PY, "-I", "-B", "-c", big] + serve_argv(), input=b"".join(x + b"\n" for x in reqs),
                   capture_output=True, timeout=60)
ans = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
check(len([a for a in ans if "result" in a]) == 4 and not any(a.get("method") == "bye" for a in ans[:4]),
      "a server started by a 130 MB process answers hello and 3 requests (%s)"
      % [a.get("method") or ("result" if "result" in a else "error") for a in ans])

# the CLI's edges
r = subprocess.run([PY, "-I", "-B", OOMPH, "remote", "sync"], capture_output=True, text=True, timeout=30)
r2 = subprocess.run([PY, "-I", "-B", OOMPH, "remote", "sync", "--once", "--bogus"], capture_output=True, text=True, timeout=30)
r3 = subprocess.run([PY, "-I", "-B", OOMPH, "serve"], capture_output=True, text=True, timeout=30)
check(r.returncode == r2.returncode == r3.returncode == 2 and "only --once" in r.stderr and "--bogus" in r2.stderr,
      "remote sync without --once, an unknown option, serve without --stdio: exit 2 with the usage")

shutil.rmtree(TMP, ignore_errors=True) if not os.environ.get("NETTEST_KEEP") else print("kept", TMP)
print("\n%s" % ("FAILED (%d)" % len(failures) if failures else "all protocol checks passed"))
sys.exit(1 if failures else 0)
