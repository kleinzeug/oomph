#!/usr/bin/python3 -I
"""Unprivileged smoke test for the daemon and CLI. Used by CI; safe to run locally.

Samples the real system into a temporary log directory, feeds the daemon a synthetic
jetsam storm, checks that an incident opens and closes with a report, and runs every
CLI command against the result. Run: /usr/bin/python3 -I tools/selftest.py
"""
import io
import json
import os
import sys
import tempfile
import time
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["OOMPH_DIR"] = tempfile.mkdtemp(prefix="oomph-selftest-")
os.environ["OOMPH_LEDGER_DIR"] = os.path.join(os.environ["OOMPH_DIR"], "ledger")
sys.path.insert(0, os.path.join(ROOT, "daemon"))

import oomph  # noqa: E402
import oomphd  # noqa: E402

LOG = os.environ["OOMPH_DIR"]
failures = []


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)


# --- raw collectors
s = oomphd.system_memory()
check(s["ram_gb"] > 0, "system_memory: RAM %.0f GB, pressure %s, swap %.1f/%.1f GB, disk %.0f GB free"
      % (s["ram_gb"], s["pressure"], s["swap_used_gb"], s["swap_total_gb"], s["disk_free_gb"]))
a = oomphd.away_state()
check("idle_s" in a, "away_state: idle %ss, display_on=%s" % (a["idle_s"], a["display_on"]))
procs = oomphd.collect_procs()
top, groups, sessions = oomphd.summarize_procs(procs)
check(len(procs) > 10 and top and top[0]["mb"] > 0, "collect_procs: %d processes, biggest %s (%d MB)"
      % (len(procs), top[0]["name"] if top else "?", top[0]["mb"] if top else 0))

# --- daemon: sample, synthetic storm, incident lifecycle
d = oomphd.Daemon()
d.notify = lambda title, msg: d.event("notified", title=title, msg=msg)
d.evaluate(d.sample())
for i in range(12):
    d.handle_log({"eventMessage": "[gui/501/com.apple.example [%d]:] exited with exit reason "
                  "(namespace: 1 code: 0xd) - OS_REASON_JETSAM, ran for 10ms" % (1000 + i),
                  "processImagePath": "/sbin/launchd"})
d.handle_log({"eventMessage": "(CoreDiagnostics) Process exampled [1234] killed by jetsam reason low-swap",
              "processImagePath": "/usr/libexec/ReportSystemMemory"})
s = d.sample()
d.evaluate(s)
check(s["jetsam_kills"] == 12, "jetsam kills aggregated into the sample (%d)" % s["jetsam_kills"])
check(d.incident is not None, "jetsam storm opened an incident")
iid = d.incident["id"] if d.incident else None
kinds = {r["kind"] for r in (d.incident or {}).get("reasons", [])}
check({"jetsam_storm", "jetsam_report"} <= kinds, "incident triggers: %s" % sorted(kinds))
if d.incident:
    d.incident["last_trigger"] -= oomphd.INCIDENT_CLOSE_AFTER + 60
time.sleep(1.1)
d.evaluate(d.sample())
check(d.incident is None, "incident closed after the trigger cleared")
inc_dir = os.path.join(LOG, "incidents", iid or "missing")
check(os.path.exists(os.path.join(inc_dir, "report.html")), "incident report.html written")
inc = json.load(open(os.path.join(inc_dir, "incident.json"))) if iid else {}
check(inc.get("summary", {}).get("jetsam_kills") == 12, "incident.json summary counts the kills")
check(os.path.exists(os.path.join(LOG, "current.json")), "current.json written")

# --- jetsam exits via `log show` polling: parsed, deduplicated across overlapping windows
real_run = oomphd.run
line = lambda i: json.dumps({"timestamp": "2026-11-19 03:52:57.%06d+0100" % i, "machTimestamp": 1000 + i,
                             "processImagePath": "/sbin/launchd",
                             "eventMessage": "[gui/501/com.apple.svc%d [%d]:] exited with exit reason (namespace: 1 "
                                             "code: 0xd) - OS_REASON_JETSAM, ran for 5ms" % (i % 3, 500 + i)})
fake_out = "\n".join(line(i) for i in range(15)) + '\n{"count":15,"finished":1}\n'
oomphd.run = lambda cmd, timeout=10: fake_out
d2 = oomphd.Daemon()
cur = d2.poll_jetsam(time.time() - 30)
cur = d2.poll_jetsam(cur)  # same lines again (overlapping window)
check(d2.jet["kills"] == 15, "jetsam poll: 15 launchd exits counted once despite overlap (%d)" % d2.jet["kills"])
check(any(x["kind"] == "jetsam_storm" for x in d2.pending_triggers), "jetsam poll: 15 kills in a minute is a storm")
oomphd.run = lambda cmd, timeout=10: ""
check(d2.poll_jetsam(123.0) == 123.0, "jetsam poll: a failed query keeps its window for the retry")
oomphd.run = real_run
out = oomphd.run(["/usr/bin/log", "show", "--style", "ndjson", "--last", "20s", "--predicate", oomph.JETSAM_EXIT_PREDICATE], timeout=60)
check('"finished"' in out, "jetsam poll: the real `log show` query runs")

# --- stall vs. sleep, unowned memory, pressure flapping
d2.pending_triggers = []
d2.prev_t, d2.prev_up = time.time() - 120, oomphd.uptime_s() - 118  # 2 min apart, awake throughout
st = d2.sample()
check(st.get("stall") and any(x["kind"] == "stall" for x in d2.pending_triggers), "awake 2-min gap reported as a stall")
d2.prev_t, d2.prev_up = time.time() - 600, oomphd.uptime_s() - 5   # 10 min apart, asleep almost all of it
st = d2.sample()
check(not st.get("stall"), "asleep 10-min gap reported as sleep, not a stall")
check(isinstance(st.get("unowned_gb"), float) and st["unowned_gb"] < oomph.unowned_limit_gb(st["ram_gb"]),
      "ownership: %.1f GB unowned now (procs %.1f GB), below the %.0f GB limit"
      % (st.get("unowned_gb") or -1, st.get("procs_gb") or -1, oomph.unowned_limit_gb(st["ram_gb"])))
evs = []
d2.event = lambda kind, **kw: evs.append(dict(kw, kind=kind))
d2.notify = lambda *a: None
d2.open_incident = lambda t, reasons: setattr(d2, "incident", {"id": "x", "reasons": list(reasons), "last_trigger": t})
base = dict(st, pressure=1, unowned_gb=2.0, swap_used_gb=0.0, disk_free_gb=60.0)
t0 = time.time()
for i, pr in enumerate([1, 2, 4, 2, 4, 2, 4, 2] + [2] * 14):
    d2.evaluate(dict(base, t=t0 + 5 * i, pressure=pr))
kinds = [e["kind"] for e in evs]
flap = [e for e in evs if e["kind"] == "pressure_flapping"]
check(kinds.count("pressure_change") == 1 and len(flap) == 1 and flap[0]["flips"] == 6,
      "pressure flapping batched: %s" % [(e["kind"], e.get("flips")) for e in evs])
d2.incident = None
leak = dict(base, unowned_gb=140.0, procs_gb=15.0)
for i in range(15):
    d2.evaluate(dict(leak, t=t0 + 200 + 5 * i))
check(d2.incident and any(r["kind"] == "unowned" for r in d2.incident["reasons"]) and
      any(e["kind"] == "unowned_memory" for e in evs), "140 GB unowned for a minute opens an incident")
check(oomph.verdict(leak)["level"] == "tight" and "outside any process" in " ".join(oomph.verdict(leak)["reasons"]),
      "verdict: unowned memory makes it tight")
old = [{"t": t0 + i * 10, "iso": "2026-11-19T05:11:%02d+01:00" % i, "kind": "pressure_change", "old": 2 + 2 * (i % 2),
        "new": 4 - 2 * (i % 2)} for i in range(6)]
col = oomph.collapse_pressure_events(old + [{"t": t0 + 999, "iso": "x", "kind": "sleep_gap"}])
check([e["kind"] for e in col] == ["pressure_flapping", "sleep_gap"] and col[0]["flips"] == 6,
      "report: logged flips collapse into one row")

# --- CLI against the generated data
for args in (["status"], ["report", "--last", "10m"], ["incidents"], ["incident", "latest"],
             ["html", "--last", "1h", "-o", os.path.join(LOG, "adhoc.html")]):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = oomph.main(args)
    check(rc == 0 and buf.getvalue().strip(), "oomph %s" % " ".join(args))
html = open(os.path.join(LOG, "adhoc.html")).read()
check(html.count("<svg") >= 3, "HTML report contains its charts")
check("by %s %s</p>" % (oomph.BRAND, oomph.VERSION) in html and "id=oomph-data" in html,
      "HTML report: the footer names BRAND, the data element keeps its id")
import re  # noqa: E402
blob = re.search(r'<script type="application/json" id=oomph-data>(.*?)</script>', html, re.S)
rd = json.loads(blob.group(1).replace("<\\/", "</")) if blob else {}
vw = rd.get("views") or {}
first = next(iter(vw.values()), {})
check(first.get("procs") and first.get("apps") is not None and isinstance(rd.get("events"), list),
      "HTML report embeds its table data per view (%s; %d processes, %d apps, %d events)"
      % ("/".join(vw), len(first.get("procs") or []), len(first.get("apps") or []), len(rd.get("events") or [])))
views = oomph.report_views(0, 86400)
check([v[0] for v in views] == ["24h", "6h", "1h"], "a 24h report switches between 24h / 6h / 1h")

# --- agent protocol: check / verdict / session / MCP
v = oomph.verdict(oomph.sample(with_procs=False))
check(v["level"] in oomph.LEVELS and v["exit_code"] == oomph.LEVELS.index(v["level"]),
      "oomph check: %s, %.1fG free" % (v["level"], v["free_gb"]))
# fixed numbers, not this Mac's: 36 GB RAM, 10 GB free, empty swap (live swap could be full)
fixed = {"ram_gb": 36.0, "app_gb": 20.0, "wired_gb": 4.0, "compressed_gb": 2.0, "swap_used_gb": 0.0,
         "swap_total_gb": 0.0, "jetsam_kills": 0, "unowned_gb": 2.0, "pressure": 1, "disk_free_gb": 60.0}
check(oomph.verdict(fixed)["level"] == "ok", "verdict: ok with 10 GB free, normal pressure, 60 GB disk")
fake = dict(fixed, pressure=2, disk_free_gb=9.8)
check(oomph.verdict(fake)["level"] == "tight", "verdict escalates to tight on WARN pressure / low disk")
fake.update(pressure=4)
check(oomph.verdict(fake)["level"] == "critical", "verdict escalates to critical on CRITICAL pressure")
check(oomph.verdict(dict(fixed, swap_used_gb=7.5, swap_total_gb=8.0, disk_free_gb=12.0))["level"] == "critical",
      "verdict: full swap on a disk too full to grow it is critical")
ses = oomph.find_session()
check(ses is None or ses["total_mb"] >= 0, "oomph session: %s" % ("not under Claude" if ses is None else "pid %s" % ses["pid"]))

import subprocess  # noqa: E402
reqs = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                                  "clientInfo": {"name": "selftest", "version": "0"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "memory_check", "arguments": {}}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "incidents", "arguments": {"limit": 3}}},
]
out = subprocess.run(["/usr/bin/python3", "-I", "-B", os.path.join(ROOT, "daemon", "oomph.py"), "mcp"],
                     input="\n".join(json.dumps(r) for r in reqs) + "\n", capture_output=True, text=True,
                     env=dict(os.environ), timeout=60).stdout
resp = {m["id"]: m for m in map(json.loads, out.strip().splitlines())}
check(resp.get(1, {}).get("result", {}).get("serverInfo", {}).get("name") == "oomph", "MCP initialize")
names = [t["name"] for t in resp.get(2, {}).get("result", {}).get("tools", [])]
check({"memory_check", "my_session", "wait_for_memory", "incidents", "incident", "memory_status",
       "reserve_memory", "release_memory", "reservations", "update_reservation", "reservation_history"} <= set(names),
      "MCP tools/list: %s" % ", ".join(names))
txt = resp.get(3, {}).get("result", {}).get("content", [{}])[0].get("text", "{}")
check(json.loads(txt).get("level") in oomph.LEVELS, "MCP tools/call memory_check")
inc_list = json.loads(resp.get(4, {}).get("result", {}).get("content", [{}])[0].get("text", "null"))
check(isinstance(inc_list, list) and len(inc_list) >= 1, "MCP tools/call incidents (%d)" % len(inc_list or []))
check(os.path.exists(os.path.join(ROOT, "skills", "oomph", "SKILL.md")), "skills/oomph/SKILL.md present")

# --- coordination ledger: decisions against a fixed sample (36 GB RAM, 10 GB free, normal pressure)
fake = dict(oomph.live_sample(with_procs=False), ram_gb=36.0, app_gb=20.0, wired_gb=4.0, compressed_gb=2.0,
            pressure=1, disk_free_gb=60.0, swap_used_gb=0.0, swap_total_gb=0.0)
oomph._sample_override = lambda: dict(fake)
me = {"pid": os.getpid(), "start": None, "kind": "process", "project": ROOT}
other_proc = subprocess.Popen(["/bin/sleep", "120"])
other = {"pid": other_proc.pid, "start": None, "kind": "session", "project": "/tmp/other"}
a = oomph.reserve(4, "build A", me)
check(a["status"] == "granted", "ledger: 4G granted with 10G free (%s)" % a["status"])
b = oomph.reserve(6, "build B", other)
check(b["status"] == "queued" and b["position"] == 1, "ledger: 6G queued behind it (%s)" % b["status"])
c = oomph.reserve(0.5, "small C", other)
check(c["status"] == "queued" and c["position"] == 2, "ledger: small request waits its turn (strict FIFO)")
v = oomph.checked_verdict(other["pid"])
check(v["coordination"]["reserved_by_others_gb"] == 4.0, "check: sees 4G reserved by another session")
r = oomph.release(a["id"])
check(set(r["next_granted"]) == {b["id"], c["id"]}, "ledger: release hands the room to the queue (%s)" % r["next_granted"])
huge = oomph.reserve(20, "huge", me)
check(huge["status"] == "queued", "ledger: oversize request waits while others hold grants")
other_proc.kill()
other_proc.wait()
huge = oomph.reserve(20, "huge", me, ticket=huge["id"])
check(huge["status"] == "granted" and huge.get("note"), "ledger: dead holder reaped; oversize granted when alone")
check(oomph.reserve(40, "x", me)["status"] == "refused", "ledger: request larger than RAM refused")
fake["pressure"] = 4
crit = oomph.reserve(0.1, "during critical", me)
check(crit["status"] == "queued", "ledger: nothing granted while memory is critical")
fake["pressure"] = 1
oomph.release("all", me["pid"])
check(not oomph.read_ledger()["leases"], "ledger: release all clears this holder's entries")
rc = oomph.main(["run", "--reserve", "256M", "--for", "selftest run", "--", "/bin/sh", "-c", "exit 3"])
hist = oomph.read_ledger()["history"]
check(rc == 3 and hist[-1]["purpose"] == "selftest run" and hist[-1]["outcome"] == "released",
      "oomph run: waits for a grant, passes the exit code through, releases")

# --- editing reservations, and the persistent history log
log_path = os.path.join(os.environ["OOMPH_LEDGER_DIR"], "reservations.jsonl")


def log_recs():
    return [json.loads(x) for x in open(log_path)] if os.path.exists(log_path) else []


check([r["id"] for r in log_recs()] == [h["id"] for h in oomph.read_ledger()["history"]],
      "history log: every finished reservation recorded (%d)" % len(log_recs()))
os.rename(log_path, log_path + ".bak")
oomph.release(oomph.reserve(0.1, "seed", me)["id"])
check([r.get("backfilled", False) for r in log_recs()] == [True] * (len(log_recs()) - 1) + [False],
      "history log: a new log is seeded with the ledger's own history")
os.replace(log_path + ".bak", log_path)
other_proc = subprocess.Popen(["/bin/sleep", "120"])
other = {"pid": other_proc.pid, "start": None, "kind": "session", "project": "/tmp/other"}
a = oomph.reserve(4, "amend A", me)
b = oomph.reserve(6, "amend B", other)
check(a["status"] == "granted" and b["status"] == "queued", "amend: 4G granted, 6G queued behind it")
g = oomph.amend(a["id"], gb=5)
lease = lambda rid: next((x for x in oomph.read_ledger()["leases"] if x["id"] == rid), {})  # noqa: E731
check(g["status"] == "refused" and "separately" in g["advice"] and lease(a["id"])["gb"] == 4,
      "amend: growing a grant while others are queued is refused, with advice; the grant stays")
time.sleep(0.15)  # spans are kept to 0.1 s: changes within that merge
sh = oomph.amend(a["id"], gb=1.5)
check(sh["status"] == "granted" and sh["changed"]["gb"] == [4, 1.5], "amend: shrinking applies at once")
check(oomph.reserve(6, "amend B", other, ticket=b["id"])["status"] == "granted",
      "amend: the room a shrink frees goes to the queue")
oomph.release(b["id"])
time.sleep(0.15)
gr = oomph.amend(a["id"], gb=3)
check(gr["status"] == "granted" and gr["changed"]["gb"] == [1.5, 3], "amend: growing applies when it fits and nobody waits")
t_before = time.time()
tt = oomph.amend(a["id"], ttl_s=600, purpose="amend A, second phase")
ex = lease(a["id"]).get("expires", 0)
check(abs(ex - (t_before + 600)) < 5 and lease(a["id"])["purpose"] == "amend A, second phase",
      "amend: new ttl counts from now (%.0f s left), new purpose" % (ex - time.time()))
check(oomph.amend(a["id"], gb=40)["status"] == "refused", "amend: more than the Mac's RAM refused")
check([x["gb"] for x in lease(a["id"])["segments"]] == [4, 1.5, 3], "amend: the size timeline keeps a segment per change")
edits = [x for x in log_recs() if x["event"] == "edit" and x["id"] == a["id"]]
check(len(edits) == 3 and edits[-1]["change"].get("purpose") and edits[-1]["change"].get("expires_in_min"), "history log: one edit record per applied change (%d)" % len(edits))
t_rel = time.time()
oomph.release(a["id"])
end = [x for x in log_recs() if x["event"] == "end" and x["id"] == a["id"]]
check(end and end[-1]["outcome"] == "released" and abs(end[-1]["ended"] - t_rel) < 3 and
      [x["gb"] for x in end[-1].get("segments", [])] == [4, 1.5, 3] and end[-1]["holder"] == "process",
      "history log: a release ends the span at the release time, with its size timeline")
x = oomph.reserve(0.5, "will expire", me, ttl_s=60)
with oomph.Ledger() as L:
    for r in L["leases"]:
        if r["id"] == x["id"]:
            r["granted"], r["expires"] = round(time.time() - 200, 1), round(time.time() - 100, 1)
            planned = r["expires"]
oomph.coordination()
end = [r for r in log_recs() if r["event"] == "end" and r["id"] == x["id"]]
check(end and end[-1]["outcome"] == "expired" and end[-1]["ended"] == planned,
      "history log: an expired grant ends at its expiry, not when it was noticed")
y = oomph.reserve(0.5, "holder dies", other)
other_proc.kill()
other_proc.wait()
# the root daemon's thread hands the refresh to `oomph _ledger-refresh` running as nobody; same payload here
payload = json.dumps({"s": dict(fake), "procs": list(oomphd.collect_procs().values())}, default=str)
rr = subprocess.run([sys.executable, "-I", "-B", oomph.__file__, "_ledger-refresh"], input=payload,
                    capture_output=True, text=True, env=dict(os.environ))
check(rr.returncode == 0 and isinstance(json.loads(rr.stdout).get("leases"), list),
      "daemon tick: the unprivileged ledger refresh runs, answers the snapshot (%s)" % rr.stderr.strip()[-200:])
end = [r for r in log_recs() if r["event"] == "end" and r["id"] == y["id"]]
check(end and end[-1]["outcome"] == "holder_gone" and not oomph.read_ledger()["leases"],
      "daemon tick: a dead holder's reservation is retired and logged")
hist = oomph.reservation_history(3600)
mine_a = next((h for h in hist["reservations"] if h["id"] == a["id"]), {})
check(len(mine_a.get("gb_changes", [])) == 3 and mine_a["outcome"] == "released" and hist["finished"] >= 4,
      "reservation_history: spans with their size changes (%d finished)" % hist["finished"])
seen_ids = {r["id"] for r in log_recs()}
os.remove(os.path.join(os.environ["OOMPH_LEDGER_DIR"], "ledger.json"))
z = oomph.reserve(0.5, "after a reset", me)
check(z["id"] not in seen_ids and lease(z["id"])["key"].startswith(z["id"] + "@"),
      "ids stay unique after the ledger is deleted (%s, key %s)" % (z["id"], lease(z["id"]).get("key")))
with open(log_path, "a") as f:
    f.write(json.dumps({"event": "end", "t": time.time() - 20 * 86400, "ended": time.time() - 20 * 86400,
                        "key": "r0@1", "id": "r0", "purpose": "ancient", "gb": 1, "requested": 1}) + "\n")
with oomph.Ledger() as L:
    L["history_pruned"] = 0
oomph.release(z["id"])
check(not any(r["id"] == "r0" for r in log_recs()) and any(r["id"] == z["id"] for r in log_recs()),
      "history log: records older than 14 days are pruned")
w = oomph.reserve(0.5, "cli amend", me)
for args, want in ((["amend", w["id"], "--gb", "256M", "--ttl", "5m"], 0), (["amend", "r999999", "--gb", "1G"], 75),
                   (["amend", w["id"]], 2), (["reservations", "--history", "--last", "1h"], 0)):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = oomph.main(args)
    check(rc == want and buf.getvalue().strip(), "oomph %s → exit %d" % (" ".join(args), rc))
oomph.release(w["id"])
# --- H0: the shared ledger directory is world-writable, so anything in it may be hostile
import hashlib  # noqa: E402
import secrets  # noqa: E402
import stat  # noqa: E402
import threading  # noqa: E402
LD = os.environ["OOMPH_LEDGER_DIR"]
scratch = tempfile.mkdtemp(prefix="oomph-h0-")


def timed(fn, *a, **kw):
    t = time.time()
    try:
        return fn(*a, **kw), time.time() - t
    except Exception as e:  # noqa: B902
        return e, time.time() - t


def digest(p):
    st = os.lstat(p)
    return hashlib.sha256(open(p, "rb").read()).hexdigest(), st.st_size, st.st_mtime_ns, st.st_nlink


fifo = os.path.join(scratch, "fifo")
os.mkfifo(fifo)
os.symlink("/dev/zero", os.path.join(scratch, "zero"))
reg = os.path.join(scratch, "reg")
open(reg, "w").write('{"a": 1}')
os.symlink(reg, os.path.join(scratch, "link"))
sparse = os.path.join(scratch, "sparse")
with open(sparse, "wb") as f:
    f.truncate(1 << 30)
under = os.path.join(scratch, "under")
open(under, "wb").write(b"x" * (oomph.LIMITS["ledger"] - 1))
os.link(reg, os.path.join(scratch, "hard"))
os.mkdir(os.path.join(scratch, "dir"))
lines = os.path.join(scratch, "lines")
open(lines, "wb").write(b"".join(b'{"n": %d}\n' % i for i in range(200000)))
for name, want in (("fifo", None), ("zero", None), ("link", None), ("sparse", None), ("hard", None), ("dir", None),
                   ("missing", None)):
    got, dt = timed(oomph.read_bounded, os.path.join(scratch, name), oomph.LIMITS["ledger"])
    check(got is want and dt < 1, "read_bounded: %s → refused at once (%.2f s)" % (name, dt))
got, dt = timed(oomph.read_bounded, under, oomph.LIMITS["ledger"])
check(isinstance(got, bytes) and len(got) == oomph.LIMITS["ledger"] - 1, "read_bounded: a file just under the limit is read")
open(under, "ab").write(b"xx")
check(oomph.read_bounded(under, oomph.LIMITS["ledger"]) is None, "read_bounded: just over the limit is refused")
tail = oomph.read_bounded(lines, 4096, tail=True)
check(tail and tail.endswith(b'{"n": 199999}\n') and tail.startswith(b'{"n": ') and len(tail) <= 4096,
      "read_bounded tail: the newest whole lines of a bigger file")
got, dt = timed(oomph.read_bounded, sparse, oomph.LIMITS["history"], tail=True)
check(isinstance(got, bytes) and len(got) == 0 and dt < 2, "read_bounded tail: 1 GB sparse file → nothing, %.2f s" % dt)
U = oomph.loads_untrusted
check(U(b'{"a": [1, 2.5, "x", null]}') == {"a": [1, 2.5, "x", None]} and U("9" * 30) == int("9" * 30),
      "loads_untrusted: ordinary JSON")
check(all(U(x) is None for x in ("9" * 31, "-" + "9" * 31, "NaN", "[Infinity]", "1e999", "[" * 100000 + "]" * 100000,
                                 json.dumps({str(i): i for i in range(300)}), b"\xff\xfe", "{", "")),
      "loads_untrusted: huge int, NaN/Infinity, overflow, deep nesting, too many keys, bad bytes → None")

# malformed leases and records: dropped, never raised, by every reader and writer
me_pid = os.getpid()
good = {"id": "r900", "state": "granted", "gb": 0.5, "purpose": "valid one", "project": "/tmp/" + "p" * 300,
        "holder": {"pid": me_pid, "start": None, "kind": "process"}, "watch": me_pid, "ttl": 1800,
        "requested": time.time() - 5, "seen": time.time() - 5, "granted": time.time() - 5, "expires": time.time() + 900}
bad = [{"id": "r1"}, {"id": "r2", "state": "granted", "gb": "x", "purpose": "p", "holder": {"pid": 1}, "requested": 1},
       {"id": "r3", "state": "queued", "gb": 1, "purpose": "p", "holder": {"pid": "x"}, "requested": 1},
       {"id": "r4", "state": "granted", "gb": 1, "purpose": "p", "holder": {"pid": me_pid}, "requested": 1},
       {"id": "../x", "state": "queued", "gb": 1, "purpose": "p", "holder": {"pid": me_pid}, "requested": 1},
       {"id": "r6", "state": "queued", "gb": 1e300, "purpose": "p", "holder": {"pid": me_pid}, "requested": 1},
       {"id": "r7", "state": "queued", "gb": 1, "purpose": "p", "holder": {"pid": me_pid}, "requested": 1e300}, "r8", None]
odd = dict(good, id="r901", watch=[1], segments="x", used_gb="lots", holder={"pid": me_pid, "start": "x"})
open(os.path.join(LD, "ledger.json"), "w").write(json.dumps({"seq": "zz", "leases": bad + [good, odd],
                                                              "history": [{"id": 5}, {"id": "r3"}], "state": []}))
with open(log_path, "a") as f:
    f.write('{"id": "r1"}\n{"key": "x"}\nnot json\n' + "[" * 50000 + "\n" + '{"id": "r2", "gb": 1, "requested": %s}\n'
            % ("9" * 40) + '{"event": "end", "id": "r3", "gb": "x", "requested": 1, "ended": 2}\n')
L0 = oomph.read_ledger()
check([r["id"] for r in L0["leases"]] == ["r900", "r901"] and L0["history"] == [] and L0["seq"] == 901,
      "malformed ledger: invalid leases and history dropped, seq repaired (%s)" % [r["id"] for r in L0["leases"]])
o = next(r for r in L0["leases"] if r["id"] == "r901")
check(o["watch"] is None and "segments" not in o and "used_gb" not in o and o["holder"]["start"] is None,
      "malformed ledger: mistyped optional fields reset")
check(next(r for r in L0["leases"] if r["id"] == "r900")["project"] == good["project"],
      "malformed ledger: a long project path is carried through uncut (no view limit on the write path)")
ok, snap = True, []
try:
    oomph.coordination(me_pid)
    oomph.reservation_history(30 * 86400, 500)
    snap = oomph.ledger_snapshot(oomphd.collect_procs())
    oomph.release("r901")
    oomph.release("r900")
except Exception as e:  # noqa: B902
    ok = repr(e)
check(ok is True and [b["id"] for b in snap] == ["r900", "r901"], "malformed ledger: coordination, history, snapshot, "
      "release all work (%s)" % ok)
tick, dt = timed(oomph.ledger_tick, dict(fake), oomphd.collect_procs())
check(isinstance(tick, tuple) and tick[1] is None and dt < 5, "daemon tick on the repaired ledger (%.2f s)" % dt)

# what root republishes: typed fields, capped
blk = oomph.sample_leases([{"id": "r%d" % i, "state": "granted", "gb": 1.0, "purpose": "p" * 5000, "project": i,
                            "used_gb": 0.5, "for_min": "x", "evil": {"deep": [1]}} for i in range(500)] + ["x", None])
check(0 < len(blk) <= 64 and len(json.dumps(blk)) <= 16 << 10 and all(len(b["purpose"]) == 200 and b["project"] is None
      and set(b) == {"id", "state", "gb", "purpose", "project", "used_gb"} for b in blk),
      "sample leases block: %d entries, %d bytes, typed fields only" % (len(blk), len(json.dumps(blk))))

# a held lock: a clean "busy" within the deadline, never a hang
holder = subprocess.Popen([sys.executable, "-I", "-c", "import fcntl, os, sys, time\n"
                           "fd = os.open(sys.argv[1], os.O_RDONLY)\nfcntl.flock(fd, fcntl.LOCK_EX)\n"
                           "print('held', flush=True)\ntime.sleep(60)", os.path.join(LD, "ledger.lock")],
                          stdout=subprocess.PIPE, text=True)
holder.stdout.readline()
got, dt = timed(oomph.reserve, 0.1, "while locked", me)
check(isinstance(got, oomph.LedgerBusy) and oomph.LOCK_WAIT_S <= dt < oomph.LOCK_WAIT_S + 2,
      "held lock: reserve gives up with LedgerBusy after %.1f s" % dt)
oomph._lock_wait = 0.5
err = io.StringIO()
from contextlib import redirect_stderr  # noqa: E402
with redirect_stdout(io.StringIO()), redirect_stderr(err):
    rc = oomph.main(["reserve", "100M", "--for", "while locked"])
check(rc == 75 and "busy" in err.getvalue(), "held lock: `oomph reserve` exits 75 with %r" % err.getvalue().strip()[:60])
oomph._lock_wait = oomph.LOCK_WAIT_S
open(os.path.join(LD, "ledger.json"), "w").write(json.dumps({"seq": 1, "leases": [good], "history": []}))
tick, dt = timed(oomph.ledger_tick, dict(fake), oomphd.collect_procs())
check(isinstance(tick, tuple) and "busy" in (tick[1] or "") and [b["id"] for b in tick[0]] == ["r900"] and dt < 3,
      "held lock: the daemon's child gives up after 1 s, still answers the snapshot (%.2f s)" % dt)
holder.kill()
holder.wait()
oomph.release("r900")

# planted links: zero writes through them, by construction
victim = os.path.join(scratch, "victim")  # someone's ~/.zshrc
open(victim, "w").write("export PATH=/usr/bin\n")
before = digest(victim)
for name in ("ledger.json", "reservations.jsonl"):
    p = os.path.join(LD, name)
    keep = open(p, "rb").read() if os.path.exists(p) else None
    for how in ("symlink", "hardlink"):
        if os.path.lexists(p):
            os.remove(p)
        (os.symlink if how == "symlink" else os.link)(victim, p)
        x = oomph.reserve(0.1, "planted " + how, me)
        oomph.release(x["id"])
        st = os.lstat(p)
        check(digest(victim) == before and stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
              "planted %s at %s: the victim is unchanged, a fresh file took the name" % (how, name))
    if keep is not None and name == "reservations.jsonl":
        open(p, "ab").write(keep)
pid = os.getpid()
for name in ("ledger.json", "reservations.jsonl"):  # 1.8.3's predictable temporary names
    os.symlink(victim, os.path.join(LD, "%s.%d.tmp" % (name, pid)))
real_hex = secrets.token_hex
secrets.token_hex = lambda n=None: "c0ffee"  # make the random name predictable, and plant a link there
os.symlink(victim, os.path.join(LD, "ledger.json.c0ffee.tmp"))
got = timed(oomph.reserve, 0.1, "planted temp", me)[0]
secrets.token_hex = real_hex
check(isinstance(got, (oomph.LedgerError, OSError)) and digest(victim) == before,
      "planted link at the temporary name: the write fails (O_EXCL), nothing through it (%s)" % type(got).__name__)
x = oomph.reserve(0.1, "temp names", me)
oomph.release(x["id"])
check(digest(victim) == before, "planted links at 1.8.3's temporary names: unused, the victim is unchanged")
for f in os.listdir(LD):
    if f.endswith(".tmp"):
        os.remove(os.path.join(LD, f))

# the directory itself replaced by a link
real_ld = oomph.LEDGER_DIR
other_dir = os.path.join(scratch, "elsewhere")
os.mkdir(other_dir)
open(os.path.join(other_dir, "ledger.json"), "w").write(json.dumps({"seq": 1, "leases": [good], "history": []}))
os.symlink(other_dir, os.path.join(scratch, "linked"))
oomph.LEDGER_DIR = os.path.join(scratch, "linked")
listing = sorted(os.listdir(other_dir))
err = io.StringIO()
with redirect_stdout(io.StringIO()), redirect_stderr(err):
    rc = oomph.main(["reserve", "100M", "--for", "linked dir"])
r1 = oomph.read_ledger()
check(rc == 1 and "not a plain directory" in err.getvalue() and r1["leases"] == [] and sorted(os.listdir(other_dir))
      == listing, "directory replaced by a link: refused (exit %d), nothing read or written there" % rc)
tick = timed(oomph.ledger_tick, dict(fake), oomphd.collect_procs())[0]
check(isinstance(tick, tuple) and tick[0] == [] and "not a plain directory" in (tick[1] or ""),
      "directory replaced by a link: the daemon's child reports it, no snapshot")
oomph.LEDGER_DIR = real_ld

# the sampler never waits for the ledger child
x = timed(oomph.run_bounded, ["/bin/sleep", "30"], b"", 100, 0.5)
check(isinstance(x[0], oomph.LedgerError) and "timed out" in str(x[0]) and x[1] < 2,
      "run_bounded: a hanging child is killed after its timeout (%.2f s)" % x[1])
x = timed(oomph.run_bounded, ["/usr/bin/yes"], b"", 1000, 5)
check(isinstance(x[0], oomph.LedgerError) and "more than" in str(x[0]) and x[1] < 2,
      "run_bounded: a child that says too much is killed")
x = timed(oomph.run_bounded, ["/bin/cat"], b"z" * (1 << 20), 2 << 20, 5)[0]
check(isinstance(x, tuple) and x[0] == 0 and len(x[1]) == 1 << 20, "run_bounded: input bigger than a pipe buffer")
hang = threading.Event()
calls = []


def slow_tick(s, procs):
    calls.append(s["t"])
    hang.wait(20)
    return [], None


dd = oomphd.Daemon()
dd.ledger = oomphd.LedgerWorker(dd.event, tick=slow_tick)
dd.ledger.FORCE_EVERY = 0  # no skipping here
dd.ledger.start()
times = [timed(dd.sample)[1] for _ in range(4)]
time.sleep(0.2)
check(max(times) < 1 and len(calls) == 1, "daemon: the sampler doesn't wait for a hanging ledger child "
      "(samples took %s s)" % ", ".join("%.2f" % t for t in times))
latest_t = dd.ledger.slot[0]["t"] if dd.ledger.slot else None
hang.set()
time.sleep(0.3)
check(len(calls) == 2 and calls[1] == latest_t, "daemon: the mailbox keeps only the latest sample")
dd2 = oomphd.Daemon()
dd2.ledger.start()
x = oomph.reserve(0.5, "in the sample", me)
dd2.sample()
for _ in range(100):
    if dd2.ledger.runs:
        break
    time.sleep(0.05)
s2 = dd2.sample()
check([b["id"] for b in s2.get("leases", [])] == [x["id"]] and set(s2["leases"][0]) <= {"id", "state", "gb", "purpose", "project"}
      | set(oomph.SAMPLE_LEASE_NUMS), "daemon: the next sample carries the live reservation from the child")
dd2.ledger.at -= 3 * oomphd.INTERVAL
check(not dd2.ledger.latest(2 * oomphd.INTERVAL), "daemon: a snapshot older than two intervals is dropped")
oomph.release(x["id"])
dd2.sample()
for _ in range(100):
    if dd2.ledger.runs >= 2 and not dd2.ledger.slot:
        break
    time.sleep(0.05)
time.sleep(0.5)
n = dd2.ledger.runs
for _ in range(3):
    dd2.sample()
    time.sleep(0.2)
check(dd2.ledger.runs == n, "daemon: no child while nothing is reserved and ledger.json is unchanged")

# old and new on one ledger: 1.8.3 (still running as MCP servers) and this code read each other's files
old = os.path.join(scratch, "v183")
os.mkdir(old)
for f in ("oomph.py", "oomphd.py"):
    src = subprocess.run(["git", "-C", ROOT, "show", "v1.8.3:daemon/" + f], capture_output=True, text=True).stdout
    open(os.path.join(old, f), "w").write(src)
if os.path.getsize(os.path.join(old, "oomph.py")) > 1000:
    def old_cli(*a):
        r = subprocess.run([sys.executable, "-I", "-B", os.path.join(old, "oomph.py")] + list(a), capture_output=True,
                           text=True, env=dict(os.environ), timeout=60)
        return json.loads(r.stdout) if r.stdout.strip().startswith("{") else {"rc": r.returncode, "err": r.stderr[-300:]}
    n_new = oomph.reserve(0.1, "new A", me)
    seen = old_cli("reservations", "--json")
    o_b = old_cli("reserve", "100M", "--for", "old B", "--json")
    ids = [r["id"] for r in oomph.read_ledger()["leases"]]
    check(any(b["id"] == n_new["id"] for b in seen.get("others", []) + seen.get("mine", [])) and o_b.get("id") in ids,
          "1.8.3 reads the new ledger, the new code keeps 1.8.3's lease (%s)" % ids)
    rel = old_cli("release", o_b.get("id", "r0"), "--json")
    oomph.release(n_new["id"])
    hist = old_cli("reservations", "--history", "--last", "1h", "--limit", "500", "--json")
    got = {x["id"]: x["outcome"] for x in hist.get("reservations", [])}
    mine_h = {x["id"]: x["outcome"] for x in oomph.reservation_history(3600, 500)["reservations"]}
    check(rel.get("released") and got.get(o_b.get("id")) == mine_h.get(o_b.get("id")) in ("released", "cancelled"),
          "history log: 1.8.3 appends, the new code rewrites, each reads the other's records")
    check(got.get(n_new["id"]) == "released", "1.8.3 reads the history log the new code rewrote")
else:
    print("skip  1.8.3 compatibility: tag v1.8.3 not in this clone")
buf = io.StringIO()
with redirect_stdout(buf):
    oomph.main(["version", "--json"])
check(json.loads(buf.getvalue()).get("hardening") == 1, "oomph version --json says hardening 1")
oomph._sample_override = None

reqs = [reqs[0], reqs[1],
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "reserve_memory",
                                                                       "arguments": {"gb": 0.1, "purpose": "mcp", "wait_s": 5}}},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "reservations", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "release_memory", "arguments": {"id": "all"}}},
        {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "update_reservation",
                                                                       "arguments": {"id": "r999999", "gb": 1}}},
        {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "reservation_history",
                                                                       "arguments": {"hours": 1, "purpose": "amend"}}}]
out = subprocess.run(["/usr/bin/python3", "-I", "-B", os.path.join(ROOT, "daemon", "oomph.py"), "mcp"],
                     input="\n".join(json.dumps(r) for r in reqs) + "\n", capture_output=True, text=True,
                     env=dict(os.environ), timeout=60).stdout
resp = {m["id"]: m for m in map(json.loads, out.strip().splitlines())}
res5 = json.loads(resp.get(5, {}).get("result", {}).get("content", [{}])[0].get("text", "{}"))
check(res5.get("status") in ("granted", "queued"), "MCP reserve_memory (%s)" % res5.get("status"))
res6 = json.loads(resp.get(6, {}).get("result", {}).get("content", [{}])[0].get("text", "{}"))
check("available_gb" in res6, "MCP reservations")
res7 = json.loads(resp.get(7, {}).get("result", {}).get("content", [{}])[0].get("text", "{}"))
check(len(res7.get("released", [])) == 1, "MCP release_memory all")
res8 = json.loads(resp.get(8, {}).get("result", {}).get("content", [{}])[0].get("text", "{}"))
check(res8.get("status") == "gone", "MCP update_reservation (unknown id: %s)" % res8.get("status"))
res9 = json.loads(resp.get(9, {}).get("result", {}).get("content", [{}])[0].get("text", "{}"))
check(res9.get("reservations") and all("amend" in x["purpose"] for x in res9["reservations"]),
      "MCP reservation_history, filtered by purpose (%d)" % len(res9.get("reservations") or []))

# --- N1: one name for people (BRAND), one for machines (CMD, paths, labels), kept apart
src = {f: open(os.path.join(ROOT, "daemon", f)).read() for f in ("oomph.py", "oomph_upgrade.py", "oomphd.py")}
check(oomph.CMD == "oomph" and 'LOG_DIR = os.environ.get("OOMPH_DIR", "/Library/Logs/oomph")' in src["oomph.py"] and
      'LEDGER_DIR = os.environ.get("OOMPH_LEDGER_DIR", "/Users/Shared/oomph")' in src["oomph.py"] and
      oomph.SKILL_URL == "https://raw.githubusercontent.com/kleinzeug/oomph/main/skills/oomph/SKILL.md" and
      'os.environ.get("OOMPH_REPO", "https://github.com/kleinzeug/oomph.git")' in src["oomph_upgrade.py"] and
      'CONFIG_FILE = "/Library/Application Support/oomph/config.json"' in src["oomph.py"],
      "identifiers frozen: CMD, log and ledger directories, skill URL, upgrade repository, config file")
check('"_ledger-refresh"' in src["oomph.py"] and "_ledger-refresh refuses to run as root" in src["oomph.py"] and
      "os.path.realpath(__file__)" in src["oomphd.py"], "the hidden ledger command, its root fence, oomphd's real path")
buf = io.StringIO()
with redirect_stdout(buf):
    oomph.main([])
first = buf.getvalue().splitlines()[0]
saved_brand = oomph.BRAND
oomph.BRAND = "oompire"
other = oomph.usage(oomph.__doc__).splitlines()
oomph.BRAND = saved_brand
check(first.startswith(oomph.BRAND + " — ") and other[0].startswith("oompire — ") and
      other[1:] == oomph.__doc__.strip().splitlines()[1:], "help: the first word is BRAND, the commands stay `oomph`")
for args, want in ((["version"], oomph.VERSION + "\n"), (["version", "--json"], None)):
    buf = io.StringIO()
    with redirect_stdout(buf):
        oomph.main(args)
    if want:
        check(buf.getvalue() == want, "oomph version prints exactly the version")
    else:
        vj = json.loads(buf.getvalue())
        check(set(vj) == {"version", "commit", "brand", "command", "hardening"} and vj["command"] == "oomph" and
              vj["brand"] == oomph.BRAND, "oomph version --json: version, commit, brand, command, hardening")
init = resp.get(1, {}).get("result", {}).get("serverInfo", {})
check(init.get("name") == "oomph" and init.get("title") == oomph.BRAND, "MCP serverInfo: name oomph, title BRAND")
check(sorted(names) == sorted(["memory_check", "reserve_memory", "release_memory", "update_reservation", "reservations",
                               "reservation_history", "my_session", "memory_status", "wait_for_memory", "incidents",
                               "incident"]), "MCP tool names frozen")
skill = open(os.path.join(ROOT, "skills", "oomph", "SKILL.md")).read()
check(skill.startswith("---\nname: oomph\n") and "`oomph resources` succeeds" in skill[:1200],
      "SKILL.md: name oomph; its first lines say resource flags only if `oomph resources` succeeds")
bl = subprocess.run([sys.executable, "-I", "-B", os.path.join(ROOT, "tools", "brandlint.py")], capture_output=True,
                    text=True, timeout=60)
check(bl.returncode == 0, "brandlint: prose and identifiers kept apart (%s)" % bl.stdout.strip().splitlines()[-1:])

# --- strict options: an option this oomph doesn't know is refused, never taken for gigabytes
oomph._sample_override = lambda: dict(fixed)
n_before = len(oomph.read_ledger()["leases"])
for args in (["reserve", "--cpu", "8", "5G", "--for", "x"], ["reserve", "5G", "8", "--for", "x"],
             ["reserve", "5G", "--for"], ["reserve", "lots", "--for", "x"],
             ["amend", "r1", "--gb", "3G", "--cpu", "2"], ["release", "r1", "r2"], ["release", "--all"],
             ["run", "--reserve", "1G", "--cpu", "2", "--", "/usr/bin/touch", os.path.join(LOG, "ran")],
             ["run", "--reserve", "1G", "8", "--", "/usr/bin/touch", os.path.join(LOG, "ran")]):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = oomph.main(args)
    check(rc == 2 and "usage: oomph %s" % args[0] in err.getvalue() and
          ("unknown option" in err.getvalue() or "unexpected argument" in err.getvalue() or
           "needs a value" in err.getvalue() or "not a size" in err.getvalue()),
          "strict: `oomph %s` exits 2 (%s)" % (" ".join(args), err.getvalue().splitlines()[0] if err.getvalue() else rc))
check(len(oomph.read_ledger()["leases"]) == n_before and not os.path.exists(os.path.join(LOG, "ran")),
      "strict: nothing was reserved and nothing ran")
oomph._sample_override = None
reqs2 = [reqs[0], reqs[1]] + [
    {"jsonrpc": "2.0", "id": 20 + i, "method": "tools/call", "params": {"name": n, "arguments": a}}
    for i, (n, a) in enumerate((("reserve_memory", {"gb": 1, "purpose": "x", "cpu": 8}),
                                ("update_reservation", {"id": "r1", "gb_cpu": 2}),
                                ("release_memory", {"id": "all", "force": True}),
                                ("reserve_memory", {"purpose": "x"}),
                                ("reserve_memory", {"gb": 0.1, "wait_s": 0}),
                                ("release_memory", {"id": "all"})))]
out = subprocess.run(["/usr/bin/python3", "-I", "-B", os.path.join(ROOT, "daemon", "oomph.py"), "mcp"],
                     input="\n".join(json.dumps(r) for r in reqs2) + "\n", capture_output=True, text=True,
                     env=dict(os.environ), timeout=60).stdout
resp2 = {m["id"]: m for m in map(json.loads, out.strip().splitlines())}
errs = [resp2.get(20 + i, {}).get("result", {}) for i in range(4)]
check(all(e.get("isError") for e in errs) and "takes no argument cpu" in errs[0]["content"][0]["text"] and
      "needs gb" in errs[3]["content"][0]["text"],
      "MCP: the reservation tools refuse unknown and missing arguments (%s)" % [e.get("isError") for e in errs])
ok2 = [resp2.get(24 + i, {}).get("result", {}) for i in range(2)]
check(all(e and not e.get("isError") for e in ok2),
      "MCP: reserve_memory without purpose still works, as \"unspecified\" (%s)" % [e.get("isError") for e in ok2])
oomph._sample_override = lambda: dict(fixed)
out, err = io.StringIO(), io.StringIO()
with redirect_stdout(out), redirect_stderr(err):
    rc = oomph.main(["reserve", "-1G", "--for", "x"])
oomph._sample_override = None
check(rc == 75 and "unknown option" not in err.getvalue() and "REFUSED" in out.getvalue(),
      "strict: a negative size is the ledger's to refuse, with its advice (%s)" % (out.getvalue() or err.getvalue()).strip()[:80])
check(all(t["inputSchema"].get("additionalProperties") is False for t in oomph.MCP_TOOLS
          if t["name"] in ("reserve_memory", "update_reservation", "release_memory")),
      "MCP: the reservation tools' schemas are closed")

# --- the root-owned configuration file: anything not root's is ignored
cfgd = tempfile.mkdtemp(prefix="oomph-config-")
cfg = os.path.join(cfgd, "config.json")
open(cfg, "w").write('{"ioreport": true}')
os.chmod(cfg, 0o644)
check(oomph.read_config(cfg) == ({"ioreport": True} if os.geteuid() == 0 else {}),
      "config: a file root doesn't own is ignored")
check(oomph.read_config(os.path.join(cfgd, "missing.json")) == {} and oomph.read_config("/nonexistent/x.json") == {},
      "config: a missing file is no configuration")
os.environ["OOMPH_SELFTEST_SWITCH"] = "1"
check(oomph.setting("selftest_switch", config={"selftest_switch": False}) == "1" and
      oomph.setting("other", 5, config={"other": 7}) == 7 and oomph.setting("absent", 5, config={}) == 5,
      "config: OOMPH_<NAME> beats the file, the file beats the default")
os.environ.pop("OOMPH_SELFTEST_SWITCH")

# --- side-by-side installs, into a throwaway prefix (install.sh's test mode: no root, no launchd)
import shutil  # noqa: E402
inst = tempfile.mkdtemp(prefix="oomph-install-")
pfx = os.path.join(inst, "root")
os.mkdir(pfx)


def flat_source(name, version, skill_note):
    """An app bundle's Resources folder, stamped with `version`."""
    d = os.path.join(inst, name)
    os.makedirs(os.path.join(d, "skills", "oomph"))
    for f in ("oomphd.py", "oomph.py", "oomph_ai.py", "oomph_upgrade.py", "local.oomph.daemon.plist"):
        shutil.copy(os.path.join(ROOT, "daemon", f), d)
    for f in ("install.sh", "uninstall.sh"):
        shutil.copy(os.path.join(ROOT, f), d)
    open(os.path.join(d, "skills", "oomph", "SKILL.md"), "w").write(skill + skill_note)
    with open(os.path.join(d, "oomphd.py"), "a") as f:  # says where it was imported from, when asked to
        f.write('\nif __import__("os").environ.get("OOMPH_SELFTEST_IMPORTS"):\n'
                '    open(__import__("os").environ["OOMPH_SELFTEST_IMPORTS"], "a").write(__file__ + "\\n")\n')
    t = open(os.path.join(d, "oomph.py")).read().replace('VERSION = "dev"', 'VERSION = "%s"' % version, 1)
    open(os.path.join(d, "oomph.py"), "w").write(t)
    return d


def sh(script, *args):
    r = subprocess.run(["/bin/bash", script] + list(args), capture_output=True, text=True, timeout=120,
                       env=dict(os.environ, OOMPH_INSTALL_ROOT=pfx))
    return r.returncode, (r.stdout + r.stderr).strip()


lx = os.path.join(pfx, "usr", "local", "libexec")
lib, binp = os.path.join(lx, "oomph"), os.path.join(pfx, "usr", "local", "bin", "oomph")
os.makedirs(lib)  # the old layout: a real directory, as installed by 1.8.4 and before
os.makedirs(os.path.dirname(binp))
old = open(os.path.join(ROOT, "daemon", "oomph.py")).read().replace('VERSION = "dev"', 'VERSION = "1.8.4"', 1)
open(os.path.join(lib, "oomph.py"), "w").write(old)
os.symlink(os.path.join(lib, "oomph.py"), binp)
A, B = flat_source("A", "1.8.5", ""), flat_source("B", "1.8.6", "\n<!-- installed with 1.8.6 -->\n")
rc, msg = sh(os.path.join(A, "install.sh"))
ls = lambda: sorted(os.listdir(lx))  # noqa: E731
ver = lambda: subprocess.run([binp, "version"], capture_output=True, text=True, timeout=30).stdout.strip()  # noqa: E731
check(rc == 0 and os.readlink(lib) == "oomph-1.8.5" and ls() == ["oomph", "oomph-1.8.4", "oomph-1.8.5"] and
      ver() == "1.8.5" and os.path.realpath(binp) == os.path.join(os.path.realpath(lx), "oomph-1.8.5", "oomph.py"),
      "install over the old layout: the real directory moves aside, the link points at the new version (%s)"
      % (msg.splitlines()[-1:] if rc == 0 else msg[-300:]))
rc, msg = sh(os.path.join(A, "install.sh"))
check(rc == 0 and os.readlink(lib) == "oomph-1.8.5" and ls() == ["oomph", "oomph-1.8.4", "oomph-1.8.5"],
      "install again: the same files are reused, nothing new")
os.mkdir(os.path.join(lx, "oomph-1.8.5", "__pycache__"))  # as `sudo oomph …` may leave
os.symlink("oomph-gone", os.path.join(lx, ".oomph.link.99999"))  # an interrupted swap's
os.symlink("gone", os.path.join(os.path.dirname(binp), ".oomph.link.99999"))
rc, msg = sh(os.path.join(A, "install.sh"))
check(rc == 0 and os.readlink(lib) == "oomph-1.8.5" and ls() == ["oomph", "oomph-1.8.4", "oomph-1.8.5"] and
      os.listdir(os.path.dirname(binp)) == ["oomph"],
      "install again with a bytecode cache in the current version: still nothing new, leftover links removed (%s)" % ls())
# a process started through the link imports from the version directory it resolved, and keeps it
here_a = subprocess.run(["/usr/bin/python3", "-I", "-B", "-c", "import sys; sys.path.insert(0, sys.argv[1]); "
                         "import oomph; print(oomph.HERE)", lib], capture_output=True, text=True, timeout=30).stdout.strip()
imports = os.path.join(inst, "imports")
mcp = subprocess.Popen([binp, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                       env=dict(os.environ, OOMPH_SELFTEST_IMPORTS=imports))
mcp.stdin.write(json.dumps(reqs[0]) + "\n")
mcp.stdin.flush()
init = json.loads(mcp.stdout.readline() or "{}")  # it has answered, so it has resolved where it runs from
rc, msg = sh(os.path.join(B, "install.sh"))
st_a = os.stat(os.path.join(lx, "oomph-1.8.5"))
check(rc == 0 and os.readlink(lib) == "oomph-1.8.6" and ver() == "1.8.6" and here_a.endswith("/oomph-1.8.5") and
      os.path.exists(os.path.join(here_a, "oomphd.py")) and time.time() - st_a.st_mtime < 120,
      "install a newer version: one rename switches; the version a running process started from stays, "
      "dated when it was replaced")
out = mcp.communicate("\n".join(json.dumps(r) for r in (reqs[1], {
    "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "reservations", "arguments": {}}})) + "\n",
    timeout=60)[0]
got = {m["id"]: m for m in map(json.loads, out.strip().splitlines())}
imported = open(imports).read().split() if os.path.exists(imports) else []
check(init.get("result", {}).get("serverInfo", {}).get("version") == "1.8.5" and
      not got.get(3, {}).get("result", {}).get("isError", True) and imported and
      all(os.path.dirname(x) == os.path.join(os.path.realpath(lx), "oomph-1.8.5") for x in imported),
      "an MCP server started before the install still answers, as the version it started as, "
      "and imports later from its own directory (%s)" % [os.path.basename(os.path.dirname(x)) for x in imported])
for n in ("oomph-1.8.4", "oomph-1.8.5", "oomph-1.8.6"):
    os.utime(os.path.join(lx, n), (time.time() - 8 * 86400,) * 2)
os.utime(os.path.join(lx, "oomph-1.8.5"), (time.time() - 6 * 86400,) * 2)
rc, msg = sh(os.path.join(B, "install.sh"))
check(rc == 0 and ls() == ["oomph", "oomph-1.8.5", "oomph-1.8.6"],
      "versions replaced more than 7 days ago are removed, the current one never (%s)" % ls())
home = os.path.join(inst, "home")
os.mkdir(home)
r = subprocess.run([binp, "setup-claude"], capture_output=True, text=True, timeout=60,
                   env=dict(os.environ, HOME=home, PATH="/usr/bin:/bin"))
got = os.path.join(home, ".claude", "skills", "oomph", "SKILL.md")
check(r.returncode == 0 and os.path.exists(got) and open(got).read().endswith("<!-- installed with 1.8.6 -->\n"),
      "setup-claude installs the SKILL.md installed with this oomph, not main's")
rc, msg = sh(os.path.join(B, "uninstall.sh"), "--purge")
left = [os.path.join(dp, f) for dp, dn, fn in os.walk(pfx) for f in fn + [x for x in dn if os.path.islink(os.path.join(dp, x))]]
check(rc == 0 and not left and not os.path.lexists(lib) and ls() == [], "uninstall removes every version and both links (%s)" % left)
shutil.rmtree(inst, ignore_errors=True)
shutil.rmtree(cfgd, ignore_errors=True)

# --- AI report harness against a local mock of the Claude, OpenAI and Ollama APIs
import http.server  # noqa: E402
import threading  # noqa: E402
sys.path.insert(0, os.path.join(ROOT, "daemon"))
import oomph_ai  # noqa: E402
seen = []
REPORT_MD = "## Verdict\nAll fine.\n## Timeline\n- 10:00 **quiet**\n## Evidence\n| a | b |\n|---|---|\n| 1 | 2 |"


class Mock(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        seen.append((self.path, dict(self.headers), None))
        if self.headers.get("x-api-key") == "sk-bad" or self.headers.get("authorization") == "Bearer sk-bad":
            b = json.dumps({"error": {"type": "authentication_error", "message": "invalid x-api-key"}}).encode()
            self.send_response(401)
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        elif "/models/" in self.path:
            self.reply({"id": self.path.rsplit("/", 1)[1], "type": "model"})
        else:
            self.reply({"models": [{"name": "mock-model"}]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        seen.append((self.path, dict(self.headers), body))
        if self.path == "/v1/messages":
            first = len(body["messages"]) == 1
            self.reply({"stop_reason": "tool_use" if first else "end_turn", "content":
                        [{"type": "thinking", "thinking": "", "signature": "x"},
                         {"type": "tool_use", "id": "t1", "name": "overview", "input": {"since": "-1h"}}] if first
                        else [{"type": "text", "text": REPORT_MD}]})
        elif self.path == "/v1/responses":
            first = "previous_response_id" not in body
            self.reply({"id": "r1" if first else "r2", "output":
                        [{"type": "function_call", "call_id": "c1", "name": "timeline", "arguments": '{"step_minutes": 30}'}]
                        if first else [{"type": "message", "content": [{"type": "output_text", "text": REPORT_MD}]}]})
        else:  # /api/chat
            first = len(body["messages"]) == 2
            self.reply({"message": {"role": "assistant", "content": "" if first else REPORT_MD, "tool_calls":
                        [{"function": {"name": "events", "arguments": {"kind": "stall"}}}] if first else []}})


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mock)
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = "http://127.0.0.1:%d" % srv.server_address[1]
for pk, url in (("claude", base), ("openai", base + "/v1"), ("ollama", base)):
    seen.clear()
    out = os.path.join(LOG, "ai-%s.html" % pk)
    buf = io.StringIO()
    os.environ["OOMPH_AI_TOKEN"] = "sk-test"
    with redirect_stdout(buf):
        rc = oomph_ai.cmd_ai_report(["--provider", pk, "--base-url", url, "--last", "1h", "-o", out])
    lines = [json.loads(x) for x in buf.getvalue().splitlines() if x.startswith("{")]
    page = open(out).read() if os.path.exists(out) else ""
    check(rc == 0 and lines[-1].get("done") and "AI analysis" in page and "<table>" in page and sum(b is not None for _, _, b in seen) == 2,
          "AI report via mock %s: %d requests, %d progress lines, tool %s" % (
              pk, len(seen), sum("progress" in x for x in lines), lines[-1].get("tool_calls") if lines else "?"))
for pk, url, tok, model, want in (("claude", base, "sk-test", "claude-opus-5-5", 0), ("claude", base, "sk-bad", None, 3),
                                   ("openai", base + "/v1", "sk-test", None, 0), ("ollama", base, "", "mock-model", 0),
                                   ("ollama", base, "", "nope", 3)):
    seen.clear()
    os.environ["OOMPH_AI_TOKEN"] = tok
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = oomph_ai.cmd_ai_check(["--provider", pk, "--base-url", url] + (["--model", model] if model else []))
    last = json.loads(buf.getvalue().splitlines()[-1])
    check(rc == want and (last.get("ok") if want == 0 else last.get("error")) and len(seen) == 1,
          "ai-check %s %s: %s" % (pk, "accepts" if want == 0 else "rejects", last.get("model") or last.get("error")))
os.environ["OOMPH_AI_TOKEN"] = "sk-test"
claude_req = None
seen.clear()
with redirect_stdout(io.StringIO()):
    oomph_ai.cmd_ai_report(["--provider", "claude", "--base-url", base, "--last", "1h", "-o", os.path.join(LOG, "x.html")])
h, b2 = {k.lower(): v for k, v in seen[1][1].items()}, seen[1][2]
check(h.get("anthropic-version") == "2026-10-21" and h.get("x-api-key") == "sk-test"
      and b2["messages"][1]["content"][0]["type"] == "thinking" and b2["messages"][2]["content"][0]["type"] == "tool_result"
      and b2["output_config"]["effort"] == "high", "Claude request: headers, thinking passed back, tool_result")
os.environ.pop("OOMPH_AI_TOKEN")
srv.shutdown()

# --- upgrades: check / changelog / build against a throwaway repository with tagged releases
import oomph_upgrade  # noqa: E402
up = tempfile.mkdtemp(prefix="oomph-upgrade-")
repo = os.path.join(up, "repo")
os.makedirs(repo)
g = lambda *a: subprocess.run(["git", "-C", repo] + list(a), capture_output=True, text=True,  # noqa: E731
                              env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
                                       GIT_COMMITTER_EMAIL="t@t")).stdout.strip()
g("init", "-q", "-b", "main")
open(os.path.join(repo, "build-app.sh"), "w").write(
    '#!/bin/bash\nset -e\necho "==> Compiling"\nmkdir -p "$1/oomph.app/Contents/MacOS"\n'
    'touch "$1/oomph.app/Contents/MacOS/oomph"\necho "==> Built"\n')
g("add", "-A"); g("commit", "-q", "-m", "First release"); g("tag", "v1.0.0")
c1 = g("rev-parse", "HEAD")
for i in (1, 2):
    open(os.path.join(repo, "f%d" % i), "w").write(str(i))
    g("add", "-A"); g("commit", "-q", "-m", "Change %d" % i, "-m", "- detail **%d**\n\nCo-Authored-By: x" % i)
os.environ.update(OOMPH_REPO=repo, OOMPH_UPGRADE_DIR=os.path.join(up, "support"))
import importlib  # noqa: E402
importlib.reload(oomph_upgrade)
check(oomph_upgrade.parse_version("1.5.0-3-gabc1234-dirty") == (1, 5, 0, 3) and
      oomph_upgrade.parse_version("2.0.0") > oomph_upgrade.parse_version("1.9.9-12-gabc"), "upgrade: version ordering")
saved = (oomph.VERSION, oomph.COMMIT)
oomph.VERSION, oomph.COMMIT = "1.0.0", c1
r = oomph_upgrade.check()
check(r["newer"] and r["behind"] == 2 and r["available"].startswith("1.0.0-2-g"),
      "upgrade check: 2 commits behind, %s available" % r["available"])
lg = oomph_upgrade.log()
check([e["status"] for e in lg] == ["new", "new", "installed"] and "Co-Authored-By" not in lg[0]["body"]
      and lg[-1]["version"] == "1.0.0", "upgrade log: newest first, statuses, versions, trailers dropped")
oomph.VERSION, oomph.COMMIT = r["available"], r["commit"]
check(not oomph_upgrade.check()["newer"], "upgrade check: up to date at main's head")
oomph.VERSION, oomph.COMMIT = "0.9.0", "f" * 40  # a build whose commit main no longer has
check(oomph_upgrade.check()["newer"], "upgrade check: falls back to comparing versions after a rewrite")
buf = io.StringIO()
with redirect_stdout(buf):
    app, v = oomph_upgrade.build(os.path.join(up, "staging"))
msgs = [json.loads(x) for x in buf.getvalue().splitlines()]
check(os.path.isdir(app) and v.startswith("1.0.0-2-g") and any(m.get("progress") == "Compiling" for m in msgs),
      "upgrade build: runs build-app.sh into staging, streams its steps")
oomph.VERSION, oomph.COMMIT = saved
for k in ("OOMPH_REPO", "OOMPH_UPGRADE_DIR"):
    os.environ.pop(k)

print("\n%s — logs in %s" % ("FAILED (%d)" % len(failures) if failures else "all checks passed", LOG))
sys.exit(1 if failures else 0)
