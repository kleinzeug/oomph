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
from contextlib import redirect_stdout

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
fake = dict(oomph.live_sample(with_procs=False), pressure=2, disk_free_gb=9.8)
check(oomph.verdict(fake)["level"] == "tight", "verdict escalates to tight on WARN pressure / low disk")
fake.update(pressure=4)
check(oomph.verdict(fake)["level"] == "critical", "verdict escalates to critical on CRITICAL pressure")
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
       "reserve_memory", "release_memory", "reservations"} <= set(names),
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
oomph._sample_override = None

reqs = [reqs[0], reqs[1],
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "reserve_memory",
                                                                       "arguments": {"gb": 0.1, "purpose": "mcp", "wait_s": 5}}},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "reservations", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "release_memory", "arguments": {"id": "all"}}}]
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

print("\n%s — logs in %s" % ("FAILED (%d)" % len(failures) if failures else "all checks passed", LOG))
sys.exit(1 if failures else 0)
