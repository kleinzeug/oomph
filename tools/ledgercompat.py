#!/usr/bin/python3 -I
"""Ledger version 2 for readers, and the frozen-1.8.1 test (roadmap §4.4; 02 §9.2, §9.3, §13).

The ledger code of oomph 1.8.1 (unchanged since 1.7.0, and what MCP servers started before an
update still run for hours) is taken from git, `git show v1.8.1:daemon/oomph.py`, and run in this
process next to this checkout's, on one ledger directory, in both directions:

  A  1.8.1 on a ledger of version 2 as newer writers will write it (vector leases, a lease without
     memory, agent keys, users, scopes, sessions, "grant" records, the outcomes "refused" and
     "volume_gone"): it does not fail, keeps every field it does not know, and what it writes
     there (an end without the newer fields) still reads as a vector through the merging reader.
  B  this code on the same ledger: it keeps every v2 field and the lease without memory, grants
     no vector request and lets no request pass one, writes the vector into the end of a vector
     lease, and 1.8.1 reads all it wrote and tells the same outcomes.
  A2 1.9.1 (1.8.4 to 1.9.1 validate leases) on the same v2 ledger, when the tag is in this clone: it
     keeps the v2 fields but drops a lease without memory (gb 0) and the `res` of each segment when
     it writes; pinned, for B1. (CI clones have tags up to v1.8.4 only: A2 runs locally.)
  C  1.8.1's own files: this code reads them, makes a memory vector of an old lease without
     writing one, and writes back what 1.8.1 writes plus `agent` (D11) and, from 1.9.4 (L1), `user`
     and the holder's uid (03 §6.5); 1.8.1 reads that back.

Both programs measure nothing here: a fixed sample and process table stand in, so this runs on
any system. Run: /usr/bin/python3 -I -B tools/ledgercompat.py
Exit 0 when every check passes, 1 when one fails, 2 when it could not run (no tag v1.8.1 in this
clone: a skip, except under CI, where it fails).
"""
import atexit
import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="oomph-ledgercompat-")
atexit.register(shutil.rmtree, TMP, True)  # also when a check raises
os.environ["OOMPH_DIR"] = os.path.join(TMP, "logs")
os.environ["OOMPH_STATE_DIR"] = os.path.join(TMP, "state")
os.environ["OOMPH_LEDGER_DIR"] = os.path.join(TMP, "unused")
sys.path.insert(0, os.path.join(ROOT, "daemon"))

import oomph as new  # noqa: E402

failures = []


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)


def old_module(tag="v1.8.1"):
    """A tagged release's oomph.py from git, imported under a name of its own; None without the tag."""
    try:
        src = subprocess.run(["git", "-C", ROOT, "show", tag + ":daemon/oomph.py"], capture_output=True,
                             timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        src = b""
    if b"def _evaluate" not in src:
        return None
    d = os.path.join(TMP, tag)
    os.mkdir(d)
    path = os.path.join(d, "oomph.py")
    open(path, "wb").write(src)
    spec = importlib.util.spec_from_file_location("oomph_" + tag[1:].replace(".", "_"), path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


old = old_module()
if old is None:
    print("skip  the frozen-1.8.1 test: tag v1.8.1 is not in this clone (git fetch --tags)")
    sys.exit(1 if os.environ.get("CI") else 2)
mid = old_module("v1.9.1")  # the last release before B0: it validates leases (1.8.4+); optional, tags may lag

# --- the stand-ins: one live process (this one), one that has ended, a fixed sample (38 GB free)
ME, START = os.getpid(), 1795000000
p = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
p.wait()
DEAD = p.pid
PROCS = {ME: {"pid": ME, "ppid": 1, "uid": os.getuid(), "name": "python3", "start": START, "fp": 0, "rss": 0,
              "path": sys.executable}}
SAMPLE = {"t": time.time(), "ram_gb": 64.0, "app_gb": 20.0, "wired_gb": 4.0, "compressed_gb": 2.0, "pressure": 1,
          "disk_free_gb": 200.0, "swap_used_gb": 0.0, "swap_total_gb": 0.0, "os": "macos"}
HOLDER = {"pid": ME, "start": START, "kind": "session", "project": "/work/atlas"}


class Procs:
    OS = "macos"

    @staticmethod
    def collect_procs():
        return copy.deepcopy(PROCS)

    @staticmethod
    def is_agent(p):
        return p.get("name") == "claude"


old._oomphd = Procs          # 1.8.1 asks oomphd for the process table
old._sample_override = lambda: dict(SAMPLE)
if mid:
    mid._plat = Procs        # 1.8.8+ ask the backend
    mid._sample_override = lambda: dict(SAMPLE)
new._plat = Procs            # this code asks the backend
new._sample_override = lambda: dict(SAMPLE)


def use(name):
    """A fresh ledger directory for both programs."""
    d = os.path.join(TMP, name)
    os.makedirs(d)
    os.chmod(d, 0o777)
    old.LEDGER_DIR = new.LEDGER_DIR = d
    if mid:
        mid.LEDGER_DIR = d
    return d


def put(d, name, data):
    path = os.path.join(d, name)
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, 0o666)


def raw(d):
    return json.load(open(os.path.join(d, "ledger.json")))


def log(d):
    return [json.loads(x) for x in open(os.path.join(d, "reservations.jsonl"))]


def lease(L, rid):
    return next((x for x in L["leases"] if x["id"] == rid), None)


def quietly(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception as e:  # noqa: B902
        return e


# --- a ledger of version 2, as a vector-aware writer (1.12) and a Linux one (1.9.4) will write it
NOW = time.time()
AGENT = {"key": new.agent_key(ME, START), "slot": 0}
OTHER_NS = 4026531836 if new._own_ns() != 4026531836 else 4026531837  # never this process's (Linux: the host's)
V2_FIELDS = ("v", "res", "res_granted", "waiting_on", "hold", "base", "last", "watch_also", "watch_names", "user",
             "scope", "agent")


def v2_ledger():
    t = round(NOW - 600, 1)
    vec = {"id": "r1", "key": "r1@%d" % t, "v": 2, "state": "granted", "purpose": "cargo test -j8",
           "project": "/work/atlas", "holder": {"pid": ME, "start": START, "kind": "session", "uid": 501},
           "agent": AGENT, "user": "x", "scope": "host", "watch": ME, "watch_also": [{"pid": ME, "start": START}],
           "watch_names": ["ollama"], "ttl": 1800.0, "requested": t, "seen": t, "granted": t, "expires": t + 1800,
           "res": {"ram": {"ask": 2.0, "got": 2.0}, "cpu": {"ask": 8, "min": 4, "got": 6, "used": 5.2, "peak": 6.0},
                   "disk": {"ask": 20, "got": 20, "used": 1.5, "peak": 1.5, "pool": "data", "w": 1.5},
                   "mem": {"got": 2.0, "used": 0.0, "peak": 0.0, "tree": 0.0, "dev": 0.0}},
           "res_granted": t, "waiting_on": [], "hold": ["cpu"],
           "base": {"t": 81234.5, "cpu_s": 1820.4, "gpu_s": 0.0, "w_gb": 12.5, "free_gb": 63.2},
           "last": {"t": 81290.1, "cpu_s": 2110.9, "gpu_s": 0.0, "w_gb": 12.9},
           "gb": 2.0, "baseline_gb": 0.0, "used_gb": 0.0, "peak_gb": 0.0, "future_field": {"kept": True},
           "segments": [{"t": t, "gb": 2.0, "res": {"ram": 2.0, "cpu": 6, "disk": 20}}]}
    cpu_only = {"id": "r2", "key": "r2@%d" % (t + 60), "v": 2, "state": "queued", "purpose": "rustc -j12",
                "project": "/work/atlas", "holder": {"pid": ME, "start": START, "kind": "run", "uid": 501},
                "agent": AGENT, "user": "x", "watch": ME, "ttl": 1800.0, "requested": t + 60, "seen": round(NOW, 1),
                "res": {"cpu": {"ask": 12, "min": 6}, "mem": {"got": 0.0}}, "waiting_on": ["cpu"], "hold": ["cpu"],
                "gb": 0.0, "segments": [{"t": t + 60, "gb": 0.0}]}
    behind = {"id": "r3", "key": "r3@%d" % (t + 120), "state": "queued", "gb": 1.0, "purpose": "an old client",
              "project": "/work/b", "holder": {"pid": ME, "start": START, "kind": "process"}, "watch": ME,
              "ttl": 1800, "requested": t + 120, "seen": round(NOW, 1), "segments": [{"t": t + 120, "gb": 1.0}]}
    dead = {"id": "r4", "key": "r4@%d" % (t + 30), "v": 2, "state": "granted", "purpose": "llama.cpp eval",
            "project": "/work/c", "holder": {"pid": DEAD, "start": START + 1, "kind": "session", "uid": 501},
            "agent": {"key": "3f9a0c21", "slot": 1},
            "user": "x", "watch": DEAD, "ttl": 1800.0, "requested": t + 30, "seen": round(NOW, 1),
            "granted": t + 31, "expires": t + 1831,
            "res": {"ram": {"ask": 3.0, "got": 3.0}, "gpu": {"ask": 60, "got": 60, "peak": 71, "dev": "gpu0"},
                    "vram": {"ask": 4.0, "got": 4.0, "dev": "gpu0", "unified": True},
                    "mem": {"got": 7.0, "used": 5.0, "peak": 6.5}},
            "res_granted": t + 31, "gb": 7.0, "baseline_gb": 0.0, "used_gb": 5.0, "peak_gb": 6.5}
    # two holders in a container (another pid namespace, 03 §7.3), whose pids mean nothing here: a grant
    # with a time limit stays until it, an `oomph run` (none) until it stops stamping `seen`
    held = dict(behind, id="r6", key="r6@%d" % (t + 150), state="granted", gb=1.0, requested=t + 150, granted=t + 150,
                expires=t + 1950, holder={"pid": DEAD, "start": START + 2, "kind": "process", "ns": OTHER_NS})
    run = dict(held, id="r7", key="r7@%d" % (t + 160), requested=t + 160, granted=t + 160, expires=None, ttl=None,
               seen=round(NOW - 400, 1), holder=dict(held["holder"], kind="run"))
    # and one planted with a time limit no writer sets: it must not live until then
    far = dict(held, id="r5", key="r5@%d" % (t + 170), requested=t + 170, granted=t + 170, expires=NOW + 30 * 86400)
    L = {"v": 2, "seq": 7, "boot": "6f1c2e7a-91b0-4d55-a1d2-2f0e5c3b9a10",
         "sessions": {"%d@%d" % (ME, START): {"cwd": "/work/atlas", "uid": 501, "seen": round(NOW, 1)}},
         "leases": [vec, cpu_only, behind, dead, held, run, far], "history": [],
         "state": {"t": round(NOW, 1), "level": "ok", "free_gb": 38.0}}
    recs = [{"event": "grant", "t": t + 31, "key": dead["key"], "id": "r4", "purpose": dead["purpose"],
             "project": "/work/c", "holder": "session", "gb": 7.0, "requested": t + 30, "granted": t + 31,
             "peak_gb": 0.0, "v": 2, "agent": dead["agent"], "user": "x",
             "res": {"ram": 3.0, "gpu": 60, "vram": 4.0}},
            {"event": "grant", "t": t, "key": vec["key"], "id": "r1", "purpose": vec["purpose"],
             "project": "/work/atlas", "holder": "session", "gb": 2.0, "requested": t, "granted": t, "peak_gb": 0.0,
             "v": 2, "agent": AGENT, "user": "x", "res": {"ram": 2.0, "cpu": 6, "disk": 20, "disk_pool": "data"}},
            {"event": "end", "t": t - 300, "key": "r0@%d" % (t - 900), "id": "r0", "purpose": "a 40-core job",
             "project": "/work/d", "holder": "session", "gb": 0.0, "requested": t - 900, "granted": None,
             "peak_gb": 0.0, "ended": t - 300, "outcome": "refused", "note": "40 cores asked, 14 here", "v": 2,
             "user": "x", "res": {"cpu": 40}},
            {"event": "end", "t": t - 200, "key": "r9@%d" % (t - 800), "id": "r9", "purpose": "a dataset copy",
             "project": "/work/d", "holder": "process", "gb": 0.0, "requested": t - 800, "granted": t - 800,
             "peak_gb": 0.0, "ended": t - 200, "outcome": "volume_gone", "v": 2,
             "res": {"disk": 30.0, "disk_pool": "vol:0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9"}, "peak": {"disk": 12.0}}]
    return L, recs


def plant_v2(d):
    L, recs = v2_ledger()
    put(d, "ledger.json", json.dumps(L, indent=1))
    put(d, "reservations.jsonl", "".join(json.dumps(r) + "\n" for r in recs))
    return L


def kept(got, want, rid):
    """The v2 fields of lease `rid` as the fixture had them (mirrors may move: they are recomputed)."""
    g, w = lease(got, rid), lease(want, rid)
    bad = [k for k in V2_FIELDS + ("future_field",) if k in w and (g or {}).get(k) != w[k]]
    bad += [k for k in ("uid", "ns") if k in w["holder"] and (g or {}).get("holder", {}).get(k) != w["holder"][k]]
    return g is not None and not bad, bad


def seg_res(L, rid):
    return [x.get("res") for x in (lease(L, rid) or {}).get("segments") or []]


def by_key(recs):
    return {r["key"]: r for r in recs}


# ======================================= A: 1.8.1 on a ledger of version 2
d = use("a")
want = plant_v2(d)
L0 = quietly(old.read_ledger)
check(isinstance(L0, dict) and [x["id"] for x in L0["leases"]] == ["r1", "r2", "r3", "r4", "r6", "r7", "r5"],
      "A 1.8.1 reads a v2 ledger")
co = quietly(old.coordination, ME)
check(isinstance(co, dict) and {b["id"] for b in co["mine"]} == {"r1", "r2", "r3"},
      "A 1.8.1 coordination on a v2 ledger (%s)" % (type(co).__name__ if not isinstance(co, dict) else "ok"))
st = quietly(old.reserve, 0.5, "1.8.1 client", HOLDER)
check(isinstance(st, dict) and st.get("status") == "granted", "A 1.8.1 reserves on a v2 ledger (%s)"
      % (st.get("status") if isinstance(st, dict) else repr(st)))
L1 = raw(d)
for rid in ("r1", "r2"):
    ok, bad = kept(L1, want, rid)
    check(ok, "A 1.8.1 writes back %s with every v2 field it does not know (%s)" % (rid, bad or "all kept"))
check(all(L1.get(k) == want[k] for k in ("v", "boot", "sessions")), "A 1.8.1 keeps the ledger's v, boot and sessions")
check(seg_res(L1, "r1") == seg_res(want, "r1"), "A 1.8.1 keeps the res of a vector lease's segments")
check(lease(L1, "r4") is None and lease(L1, "r2")["state"] == "granted",
      "A 1.8.1 retires the dead vector lease and, as designed, grants the queued one by gb (02 §9.3: res_granted)")
check(lease(L1, "r6") is None and lease(L1, "r7") is None and lease(L1, "r5") is None,
      "A 1.8.1 retires a container's leases by their pids (it knows no namespaces) (%s)" % [x["id"] for x in L1["leases"]])
nl = quietly(new.read_ledger)
check(isinstance(nl, dict) and [x["id"] for x in nl["leases"]] == [x["id"] for x in L1["leases"]]
      and all(kept(nl, want, rid)[0] for rid in ("r1", "r2")),
      "A this code reads what 1.8.1 wrote: every lease, the one without memory too, v2 fields intact")
end4 = [r for r in log(d) if r["id"] == "r4" and r["event"] == "end"]
check(len(end4) == 1 and "res" not in end4[0] and "agent" not in end4[0], "A 1.8.1's end record has no res and no agent")
m = by_key(new.merge_history(new.read_history())).get(want["leases"][3]["key"], {})
check(m.get("event") == "end" and m.get("outcome") == "holder_gone" and m.get("res") == {"ram": 3.0, "gpu": 60, "vram": 4.0}
      and m.get("agent") == {"key": "3f9a0c21", "slot": 1} and m.get("v") == 2 and m.get("user") == "x",
      "A the merging reader keeps res, agent, v and user of a vector lease 1.8.1 ended")
oh = quietly(old.reservation_history, 3600, 500)
got = {x["id"]: x["outcome"] for x in oh.get("reservations", [])} if isinstance(oh, dict) else {}
check(got.get("r0") == "refused" and got.get("r9") == "volume_gone" and got.get("r4") == "holder_gone",
      "A 1.8.1's history tells the outcomes it does not know as they are (%s)" % sorted(got.items()))
am = quietly(old.amend, "r1", gb=3.0)
L2 = raw(d)
r1 = new._valid_lease(lease(L2, "r1"))
vec = new.lease_res(r1) if r1 else {}
check(isinstance(am, dict) and r1 and r1["gb"] == 3.0 and vec.get("ram", {}).get("got") == 3.0
      and vec.get("mem", {}).get("got") == 3.0 and vec.get("cpu", {}).get("got") == 6,
      "A 1.8.1 amends a vector lease's gb only; the reader's ram follows it, the cores stay")
new.release("r1")
end1 = [r for r in log(d) if r["id"] == "r1" and r["event"] == "end"]
check(len(end1) == 1 and end1[0]["gb"] == 3.0 and end1[0].get("res") == {"ram": 3.0, "cpu": 6, "disk": 20,
                                                                         "disk_pool": "data"},
      "A this code ends the lease 1.8.1 amended: the end record's ram follows gb (%s)" % (end1[-1:] or [{}])[0].get("res"))
snap = quietly(old.ledger_snapshot, Procs.collect_procs())
rel = quietly(old.release, "all", ME)
check(isinstance(snap, list) and isinstance(rel, dict) and not raw(d)["leases"],
      "A 1.8.1's snapshot and release all on a v2 ledger")

# ======================================= B: this code on a ledger of version 2, 1.8.1 reading it
d = use("b")
want = plant_v2(d)
st = quietly(new.reserve, 0.5, "new client", HOLDER)
L1 = raw(d)
check(isinstance(st, dict) and st.get("status") == "queued" and st.get("position") == 3,
      "B a request queues behind the vector request it cannot weigh (%s)" % (st.get("status") if isinstance(st, dict)
                                                                             else repr(st)))
check(lease(L1, "r2")["state"] == "queued" and lease(L1, "r3")["state"] == "queued",
      "B no vector request is granted here, and nobody passes one")
for rid in ("r1", "r2"):
    ok, bad = kept(L1, want, rid)
    check(ok, "B this code writes back %s with every v2 field (%s)" % (rid, bad or "all kept"))
check(all(L1.get(k) == want[k] for k in ("v", "boot", "sessions")), "B the ledger's v, boot and sessions are kept")
check(seg_res(L1, "r1") == seg_res(want, "r1") == [{"ram": 2.0, "cpu": 6, "disk": 20}],
      "B this code writes back the res of a vector lease's segments (%s)" % seg_res(L1, "r1"))
check(lease(L1, "r4") is None, "B the vector lease whose holder ended is retired")
check(lease(L1, "r6") is not None and lease(L1, "r7") is None and lease(L1, "r5") is None,
      "B a holder in another pid namespace is not looked up by its pid: a grant stays until its time (unless "
      "that is further off than any writer sets), a run ends when it stops stamping seen")
mine = lease(L1, st.get("id"))
check(mine and mine.get("agent") == {"key": new.agent_key(ME, START)} and "v" not in mine and "res" not in mine,
      "B a new lease is what 1.8.1 writes plus agent {key} (%s)" % (mine or {}).get("agent"))
end4 = [r for r in log(d) if r["id"] == "r4" and r["event"] == "end"]
check(len(end4) == 1 and end4[0].get("res") == {"ram": 3.0, "gpu": 60, "vram": 4.0} and end4[0].get("peak") == {"gpu": 71}
      and end4[0].get("agent") == {"key": "3f9a0c21", "slot": 1} and end4[0].get("v") == 2
      and end4[0].get("user") == "x" and end4[0]["gb"] == 7.0,
      "B this code's end record of a vector lease carries its res, peak, agent, v and user")
for rid in ("r2", "r3"):  # the vector request goes, and the line moves on
    new.release(rid)
st2 = quietly(new.reserve, 0.5, "new client", HOLDER, ticket=st.get("id"))
check(isinstance(st2, dict) and st2.get("status") == "granted", "B with the vector request gone, the line moves on")
am = quietly(new.amend, st.get("id"), gb=0.75)
ed = [r for r in log(d) if r["id"] == st.get("id") and r["event"] == "edit"]
check(isinstance(am, dict) and ed and ed[-1].get("agent") == {"key": new.agent_key(ME, START)},
      "B an edit record carries the agent")
co = quietly(old.coordination, ME)
check(isinstance(co, dict) and {b["id"] for b in co["mine"]} == {"r1", st.get("id")},
      "B 1.8.1 reads the ledger this code wrote")
oh = quietly(old.reservation_history, 3600, 500)
nh = new.reservation_history(3600, 500)
og = {x["id"]: (x["outcome"], x["gb"]) for x in oh.get("reservations", [])} if isinstance(oh, dict) else {}
ng = {x["id"]: (x["outcome"], x["gb"]) for x in nh["reservations"]}
check(og and og == ng, "B 1.8.1 and this code tell the same history (%s)" % sorted(og.items()))
L = raw(d)
L["history"].append({"id": "r20", "key": "r20@1", "purpose": "too big", "gb": 0.0, "holder": "session",
                     "outcome": "refused", "note": "40 cores asked, 14 here", "requested": NOW - 9, "granted": None,
                     "ended": NOW - 8, "waited_s": 1, "held_s": 0, "v": 2, "res": {"cpu": 40}})
put(d, "ledger.json", json.dumps(L))
ns, os_ = new.reserve(1, "x", HOLDER, ticket="r20"), quietly(old.reserve, 1, "x", HOLDER, ticket="r20")
check(ns.get("status") == "refused" and "40 cores" in ns.get("advice", "") and isinstance(os_, dict)
      and os_.get("status") == "gone" and os_.get("outcome") == "refused",
      "B a ticket turned down reads refused here, gone (refused) in 1.8.1")
new.release("all", ME)
check(quietly(old.read_ledger)["leases"] == [], "B 1.8.1 reads the emptied ledger (its coordination call retired "
      "the container's grant by its pid, as before)")

# ======================================= A2: 1.9.1 (1.8.4 to 1.9.1 validate leases) on a ledger of version 2
if mid is None:
    print("skip  A2 1.9.1 on a v2 ledger: tag v1.9.1 is not in this clone")
else:
    d = use("a2")
    want = plant_v2(d)
    L0 = quietly(mid.read_ledger)
    check(isinstance(L0, dict) and [x["id"] for x in L0["leases"]] == ["r1", "r3", "r4", "r6", "r7", "r5"],
          "A2 1.9.1 reads a v2 ledger, all but the lease without memory (gb 0: B1 must give such a lease a "
          "memory mirror above 0, or accept that these releases drop it on their next write)")
    st = quietly(mid.reserve, 0.5, "1.9.1 client", HOLDER)
    L1 = raw(d)
    check(isinstance(st, dict) and st.get("status") in ("granted", "queued") and kept(L1, want, "r1")[0]
          and all(L1.get(k) == want[k] for k in ("v", "boot", "sessions")),
          "A2 1.9.1 reserves on a v2 ledger and writes back r1, v, boot and sessions unchanged (%s)"
          % (kept(L1, want, "r1")[1] or "all kept"))
    check(lease(L1, "r2") is None, "A2 1.9.1 drops the lease without memory when it writes (known; see above)")
    check(seg_res(L1, "r1") == [None], "A2 1.9.1 drops the res of a lease's segments when it writes (known: B1 must "
          "read a segment without res, as this code's amend also writes one)")
    nl = quietly(new.read_ledger)
    check(isinstance(nl, dict) and [x["id"] for x in nl["leases"]] == [x["id"] for x in L1["leases"]],
          "A2 this code reads what 1.9.1 wrote")

# ======================================= C: 1.8.1's own files, both ways
d = use("c")
a = old.reserve(1.0, "old A", HOLDER)
b = old.reserve(2.0, "old B", HOLDER)
old.amend(b["id"], gb=1.5)
old.release(a["id"])
L0 = raw(d)
r = new._valid_lease(lease(L0, b["id"]))
check(r and new.lease_res(r) == {"ram": {"ask": 1.5, "got": 1.5}, "mem": {"got": 1.5, "used": 0.0, "peak": 0.0}},
      "C a 1.8.1 lease reads as a vector of memory only (made, not written)")
c = new.reserve(0.5, "new C", HOLDER)
L1 = raw(d)
ob = lease(L1, b["id"])
check("res" not in ob and "v" not in ob and ob.get("agent") == {"key": new.agent_key(ME, START)}
      and "v" not in L1, "C this code writes no version 2 into a 1.8.1 ledger, only agent (D11)")
old_keys = set(lease(L0, b["id"])) | {"agent", "user"}  # user: from 1.9.4 (roadmap §4.4: L1 writes it)
nc = lease(L1, c["id"])
check(set(nc) <= old_keys and nc.get("user") and set(nc["holder"]) <= set(lease(L0, b["id"])["holder"]) | {"uid", "ns"},
      "C a lease this code makes has 1.8.1's fields, agent and user (%s)" % sorted(set(nc) - old_keys))
new.amend(c["id"], gb=0.25)
new.release(c["id"])
recs = log(d)
old_rec = set(next(x for x in recs if x["id"] == a["id"] and x["event"] == "end")) | {"agent", "user"}
new_recs = [x for x in recs if x["id"] == c["id"]]
check(new_recs and all(set(x) <= old_rec | {"change", "expires"} for x in new_recs),
      "C its records have 1.8.1's fields, agent and user")
oh = old.reservation_history(3600, 500)
nh = new.reservation_history(3600, 500)
og = {x["id"]: (x["outcome"], x["gb"], x.get("gb_changes")) for x in oh["reservations"]}
ng = {x["id"]: (x["outcome"], x["gb"], x.get("gb_changes")) for x in nh["reservations"]}
check(og == ng and len(og) == 3, "C 1.8.1 and this code tell the same history of each other's records (%s)"
      % sorted((k, v[:2]) for k, v in og.items()))
old.release("all", ME)
check(new.read_ledger()["leases"] == [], "C this code reads 1.8.1's release")

# ======================================= D: the normaliser, on v2 fields anyone could have planted
base = {"id": "r30", "state": "granted", "gb": 1.0, "purpose": "p", "holder": {"pid": ME, "start": START},
        "requested": NOW, "granted": NOW}
V = new._valid_lease
check(V(dict(base, gb=0)) is None and V(dict(base, gb=0, v=2))["gb"] == 0 and V(dict(base, gb=0, v="2")) is None,
      "D a lease without memory is kept only as version 2")
x = V(dict(base, v=2, res={"cpu": {"ask": -1, "got": 6, "peak": float("inf"), "dev": {"x": 1}, "later": "kept"},
                           "net": {"got": 1}, "disk": {"got": 20, "pool": "../../etc"}, "gpu": "lots",
                           "vram": {"got": 2, "unified": "yes"}, "mem": {"got": 3, "dev": 1.0}}))
check(x["res"] == {"cpu": {"got": 6, "later": "kept"}, "disk": {"got": 20, "pool": "../../etc"}, "vram": {"got": 2},
                   "mem": {"got": 3, "dev": 1.0}, "net": {"got": 1}},
      "D res: mistyped amounts dropped, a later resource carried through, an id is a string compared, never opened "
      "(%s)" % json.dumps(x["res"]))
x = V(dict(base, v=2, res=dict({"cpu": {"got": 1}, "Bad Name": {"got": 1}, "disk_pool": {"got": 1}},
                               **{"r%02d" % i: {"got": i, "ask": "x"} for i in range(30)})))
check(list(x["res"]) == ["cpu"] + ["r%02d" % i for i in range(new.RES_MAX - 1)] and x["res"]["r03"] == {"got": 3},
      "D res: at most %d resources, a later one only by a lowercase name, typed like the known" % new.RES_MAX)
x = V(dict(base, v=2, res="x", agent={"key": "3F9A0C21"}, waiting_on=["cpu", 5], hold=list("abcdefghijklmnopq"),
           watch_also=[{"pid": -1}], watch_names=["x" * 33], user="u" * 65, scope=7, res_granted=1e300,
           base={"t": "x"}, holder={"pid": ME, "uid": -1, "ns": "x"}))
check(set(new.V2_LEASE) & set(x) == {"v"} and set(x["holder"]) == {"pid", "start", "kind"},
      "D mistyped v2 fields of a lease are absent, the lease stays (%s)" % sorted(set(new.V2_LEASE) & set(x)))
check(new._agent({"key": "3f9a0c21", "slot": 6}) is None and new._agent({"key": "3f9a0c2"}) is None
      and new._agent({"key": "3f9a0c21", "slot": 5, "x": 1}) == {"key": "3f9a0c21", "slot": 5},
      "D agent: an 8-digit hex key and a slot 0-5, anything else is 'agent not known'")
x = new._valid_ledger({"leases": [], "v": 2.5, "boot": "a b", "sessions": {"1@2": {"cwd": "/w", "uid": "x"},
                                                                          "bad": {}, "3@4": "x"}})
check("v" not in x and "boot" not in x and x["sessions"] == {"1@2": {"cwd": "/w"}},
      "D the ledger root: a bad v and boot are absent, bad sessions dropped")
rec = {"id": "r31", "gb": 0, "requested": NOW, "event": "grant", "key": "k", "res": {"cpu": 6, "disk_pool": 5, "x": 1,
                                                                                    "X": 1, "y": "1"},
       "peak": {"cpu": "x"}, "agent": {"key": "zz"}, "note": 4,
       "segments": [{"t": NOW, "gb": 1.0, "res": {"cpu": 2, "z": -1}}, {"t": NOW, "gb": 1.0, "res": "x"}]}
x = new._valid_finished(rec, log=True)
check(x and x["res"] == {"cpu": 6, "x": 1} and not {"peak", "agent", "note"} & set(x)
      and x["segments"] == [{"t": NOW, "gb": 1.0, "res": {"cpu": 2}}, {"t": NOW, "gb": 1.0}],
      "D a history record's v2 fields are typed the same way")
m = new.merge_history([dict(rec, res={"cpu": 6}, agent={"key": "3f9a0c21"}, v=2),
                       dict(rec, event="edit", res={"cpu": 4}, agent=None, v=None, peak=None),
                       dict(rec, event="end", outcome="released", res=None, agent=None),
                       dict(rec, event="edit", res={"cpu": 99}, outcome=None)])
check(len(m) == 1 and m[0]["event"] == "end" and m[0]["outcome"] == "released" and m[0]["res"] == {"cpu": 4}
      and m[0]["agent"] == {"key": "3f9a0c21"} and m[0]["v"] == 2,
      "D merge: later records override, a null does not undo res/agent/v, nothing undoes an end")
x = new.lease_res(V(dict(base, v=2, gb=1.0, res={"ram": {"ask": 3.0, "got": 3.0}, "mem": {"got": 6.0},
                                                  "vram": {"ask": 4.0, "got": 4.0, "unified": True}})))
check(x["ram"] == {"ask": 0.0, "got": 0.0} and x["vram"]["got"] == 1.0 and x["mem"]["got"] == 1.0,
      "D an old writer's amend below a lease's unified VRAM: no negative ram, VRAM within gb (%s)" % json.dumps(x))
q = dict(base, state="queued", granted=None, seen=NOW, gb=0.5)
L = {"leases": [V(dict(q, id="r40", v=2, scope="cgroup:/a", res={"cpu": {"ask": 4}})), V(dict(q, id="r41"))],
     "history": []}
new._evaluate(L, dict(SAMPLE), Procs.collect_procs(), NOW)
check([x["state"] for x in L["leases"]] == ["queued", "granted"],
      "D a queued v2 request of another scope does not hold the host's line")
L = {"leases": [V(dict(q, id="r42", v=2, res={"cpu": {"ask": 4}})), V(dict(q, id="r43"))], "history": []}
new._evaluate(L, dict(SAMPLE), Procs.collect_procs(), NOW)
check([x["state"] for x in L["leases"]] == ["queued", "queued"], "D a queued v2 request of the host holds the line")
import oomph_view as view  # noqa: E402
ns_lease = dict(base, holder={"pid": DEAD, "start": START, "ns": OTHER_NS}, key="k50", id="r50", seen=NOW)
for own, gone in ((None, False), (OTHER_NS, True)):
    rs = view.merge_reservations([], {"leases": [ns_lease], "history": []}, NOW, lambda pid: pid != DEAD, own_ns=own)
    check(len(rs) == 1 and (rs[0]["outcome"] == "holder_gone") == gone,
          "oomph top tests a holder's pid when its ns is the viewer's own, not when it is another's (own_ns %s)" % own)
rs = view.merge_reservations([], {"leases": [dict(ns_lease, holder={"pid": DEAD, "start": START})], "history": []},
                             NOW, lambda pid: pid != DEAD, own_ns=OTHER_NS)
check(len(rs) == 1 and rs[0]["outcome"] == "holder_gone", "oomph top tests a holder without ns, as oomph does")
check(new.agent_key(ME, START) == new.agent_key(ME, START) != new.agent_key(ME, START + 1)
      and new.agent_key(ME, None) is None and len(new.agent_key(1, 0)) == 8,
      "D the agent key: stable for a process, another after a restart, none without a start time")

# a holder in another pid namespace: its pid is another process's here
G = dict(base, holder={"pid": ME, "start": START, "ns": OTHER_NS}, seen=NOW, ttl=1800.0, expires=NOW + 1800)
gone = [new._holder_gone(dict(G, ttl=t, expires=NOW + e), {}, NOW)
        for t, e in ((3 * 86400, 3 * 86400), (1800, 3 * 86400), (30 * 86400, 6 * 86400), (30 * 86400, 8 * 86400),
                     (None, 3600), (None, 9 * 3600))]
check(gone == [False, True, False, True, False, True],
      "D another namespace's grant ends by its own ttl (7 days at most; without one, this version's), not this "
      "version's limit (%s)" % gone)
d = use("d")
L = new.read_ledger()
L["seq"] = 61
L["leases"] = [dict(G, id="r60", key="k60"), dict(base, id="r61", key="k61", seen=NOW, ttl=1800.0, expires=NOW + 1800)]
put(d, "ledger.json", json.dumps(L))
co = new.coordination(ME)
check([b["id"] for b in co["mine"]] == ["r61"] and [b["id"] for b in co["others"]] == ["r60"],
      "D coordination: a container's lease with this session's pid is another's")
rel = new.release("all", ME)
check([h["id"] for h in rel["released"]] == ["r61"] and [x["id"] for x in raw(d)["leases"]] == ["r60"],
      "D release all leaves a container's lease with the same pid alone")
SES, RUN = 2 ** 30 + 1, 2 ** 30 + 2
procs = {SES: {"pid": SES, "ppid": 1, "name": "claude", "start": START - 50},
         RUN: {"pid": RUN, "ppid": SES, "name": "python3", "start": START}}
run = dict(base, holder={"pid": RUN, "start": START, "kind": "run"})
check(new._agent_of(run, procs) == new.agent_key(SES, START - 50)
      and new._agent_of(dict(run, holder=dict(run["holder"], kind="process")), procs) == new.agent_key(RUN, START)
      and new._agent_of(dict(run, holder=dict(run["holder"], start=START + 1)), procs) == new.agent_key(RUN, START + 1),
      "D the agent of an old writer's `oomph run` inside a session is the session's; of anything else, the holder's")
st = new.reserve(0.25, "run", dict(HOLDER, kind="run", agent=new.agent_key(SES, START - 50)))
check(lease(raw(d), st["id"])["agent"] == {"key": new.agent_key(SES, START - 50)}
      and "agent" not in lease(raw(d), st["id"])["holder"],
      "D a reservation made by `oomph run` inside a session has the session's agent key")

print("ledger compatibility: %s" % ("all %s" % "ok" if not failures else "%d FAILED" % len(failures)))
sys.exit(1 if failures else 0)
