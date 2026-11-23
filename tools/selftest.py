#!/usr/bin/python3 -I
"""Unprivileged smoke test for the daemon and CLI. Used by CI; safe to run locally.

Samples the real system into a temporary log directory, feeds the daemon a synthetic
jetsam storm, checks that an incident opens and closes with a report, and runs every
CLI command against the result. Run: /usr/bin/python3 -I tools/selftest.py
"""
import io
import json
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["OOMPH_DIR"] = tempfile.mkdtemp(prefix="oomph-selftest-")
os.environ["OOMPH_LEDGER_DIR"] = os.path.join(os.environ["OOMPH_DIR"], "ledger")
os.environ["OOMPH_STATE_DIR"] = os.path.join(os.environ["OOMPH_DIR"], "state")  # pins and settings: never the real ones
os.environ["OOMPH_IOREPORT"] = "0"  # the daemon samples below never start the IOReport helper, whatever this Mac's config says
os.environ.pop("OOMPH_NO_IOREPORT", None)
sys.path.insert(0, os.path.join(ROOT, "daemon"))

import oomph  # noqa: E402
import oomphd  # noqa: E402

# On a Mac everything runs. Elsewhere (CI's Linux jobs) the portable half runs on a stand-in for a
# Mac's backend (tools/fixtureplat.py), so that its checks keep their macOS meaning, and what needs a
# Mac's tools or a measuring child process is skipped; the Linux backend and the CLI on it are
# tools/linuxtest.py's, which runs at the end. OOMPH_SELFTEST_PORTABLE=1 tries that run on a Mac.
MAC = sys.platform == "darwin" and os.environ.get("OOMPH_SELFTEST_PORTABLE") != "1"
if not MAC:
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import fixtureplat  # noqa: E402
    oomph._plat = fixtureplat
P = oomph.plat()
LOG = os.environ["OOMPH_DIR"]
failures = []


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)


# --- raw collectors
s = P.system_memory()
check(s["ram_gb"] > 0, "system_memory: RAM %.0f GB, pressure %s, swap %.1f/%.1f GB, disk %.0f GB free"
      % (s["ram_gb"], s["pressure"], s["swap_used_gb"], s["swap_total_gb"], s["disk_free_gb"]))
a = P.away_state()
check("idle_s" in a, "away_state: idle %ss, display_on=%s" % (a["idle_s"], a["display_on"]))
procs = P.collect_procs()
top, groups, sessions = oomphd.summarize_procs(procs)
# a Mac runs hundreds; a container (CI's Debian and Rocky jobs, as an unprivileged user) only a handful
check(len(procs) > (10 if MAC else 2) and os.getpid() in procs and top and top[0]["mb"] > 0,
      "collect_procs: %d processes, biggest %s (%d MB)"
      % (len(procs), top[0]["name"] if top else "?", top[0]["mb"] if top else 0))

# --- daemon: sample, synthetic storm, incident lifecycle
d = oomphd.Daemon()
d.notify = lambda title, msg, **kw: d.event("notified", title=title, msg=msg, **kw)
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
if MAC:  # the real `log show` query needs macOS
    out = oomphd.run(["/usr/bin/log", "show", "--style", "ndjson", "--last", "20s", "--predicate", oomph.JETSAM_EXIT_PREDICATE], timeout=60)
    check('"finished"' in out, "jetsam poll: the real `log show` query runs")
else:
    print("skip  the real `log show` query needs macOS")

# --- stall vs. sleep, unowned memory, pressure flapping
d2.pending_triggers = []
d2.prev_t, d2.prev_up = time.time() - 120, P.uptime_s() - 118  # 2 min apart, awake throughout
st = d2.sample()
check(st.get("stall") and any(x["kind"] == "stall" for x in d2.pending_triggers), "awake 2-min gap reported as a stall")
d2.prev_t, d2.prev_up = time.time() - 600, P.uptime_s() - 5   # 10 min apart, asleep almost all of it
st = d2.sample()
check(not st.get("stall"), "asleep 10-min gap reported as sleep, not a stall")
check(isinstance(st.get("unowned_gb"), float) and st["unowned_gb"] < oomph.unowned_limit_gb(st["ram_gb"]),
      "ownership: %.1f GB unowned now (procs %.1f GB), below the %.0f GB limit"
      % (st.get("unowned_gb") or -1, st.get("procs_gb") or -1, oomph.unowned_limit_gb(st["ram_gb"])))
evs = []
d2.event = lambda kind, **kw: evs.append(dict(kw, kind=kind))
d2.notify = lambda *a, **kw: None
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

# --- incidents: headlined by the most severe reason, a kill announced once, the 2-hour limit
d3 = oomphd.Daemon()
notes = []
d3.notify = lambda title, msg, **kw: notes.append(dict(kw, msg=msg))
t3 = time.time() + 7 * 86400  # ids of their own, after every other incident of this test
d3.evaluate(dict(base, t=t3, pressure=4))
id3 = (d3.incident or {}).get("id")
kill = {"kind": "jetsam_report", "t": t3 + 5, "msg": "Processes killed by jetsam, reason low-swap"}
d3.pending_triggers.append(kill)
d3.evaluate(dict(base, t=t3 + 5, pressure=4))
d3.pending_triggers += [dict(kill, t=t3 + 10), {"kind": "dialog", "t": t3 + 10, "msg": "Your system has run out of "
                        "application memory"}, {"kind": "jetsam_storm", "t": t3 + 10, "msg": "storm"}]
d3.evaluate(dict(base, t=t3 + 10, pressure=4))
inc3 = d3.incident or {}
disk3 = json.load(open(os.path.join(LOG, "incidents", str(id3), "incident.json")))
check(inc3.get("id") == id3 and [r["kind"] for r in disk3["reasons"]] == ["jetsam_report", "dialog", "jetsam_storm", "pressure"]
      and disk3.get("opened_by") == "pressure", "a kill after pressure headlines the incident; id and opened_by stay (%s)"
      % [r["kind"] for r in disk3.get("reasons", [])])
check(len(notes) == 2 and notes[1].get("event") == "kill" and kill["msg"] in notes[1]["msg"],
      "a kill after pressure is notified once, past the cool-down (%s)" % [n.get("event") for n in notes])
inc3["start"] -= oomphd.INCIDENT_MAX_S
d3.evaluate(dict(base, t=t3 + 15, pressure=4))
old3 = json.load(open(os.path.join(LOG, "incidents", str(id3), "incident.json")))
new3 = d3.incident or {}
check(old3.get("rolled") and not old3.get("open") and os.path.exists(os.path.join(LOG, "incidents", str(id3), "report.html"))
      and new3.get("continues") == id3 and new3.get("id") != id3 and len(notes) == 2,
      "an incident is closed at 2 hours and continued in a new one without a notification")
new3["last_trigger"] -= oomphd.INCIDENT_CLOSE_AFTER + 60
d3.evaluate(dict(base, t=t3 + 20, pressure=1))
check(d3.incident is None, "the continued incident closes when its triggers clear")
buf = io.StringIO()
with redirect_stdout(buf):
    oomph.main(["incidents"])
check(any(str(id3) in ln and kill["msg"] in ln for ln in buf.getvalue().splitlines()),
      "oomph incidents shows the kill as the headline")


def incident_at(dm, t, **kw):
    """An open incident as run() resumes it, its folder made."""
    dm.incident = dict({"id": "%s-%d" % (dm.__class__.__name__, t), "start": t, "start_iso": "", "last_trigger": t,
                        "open": True, "reasons": [{"kind": "pressure", "t": t, "desc": "x"}]}, **kw)
    os.makedirs(os.path.join(LOG, "incidents", dm.incident["id"]), exist_ok=True)
    return dm.incident["id"]


d4, notes = oomphd.Daemon(), []
d4.notify = lambda title, msg, **kw: notes.append(dict(kw, msg=msg))
t4 = t3 + 86400
id4 = incident_at(d4, t4 - 5 * 3600, last_trigger=t4 - 4.9 * 3600)
d4.pending_triggers.append(dict(kill, t=t4))
d4.evaluate(dict(base, t=t4, pressure=1))
old4 = json.load(open(os.path.join(LOG, "incidents", id4, "incident.json")))
new4 = d4.incident or {}
check(not old4.get("open") and not old4.get("rolled") and new4.get("opened_by") == "jetsam_report"
      and "continues" not in new4 and d4.rolled is None and len(notes) == 1,
      "a kill after a sleep or restart opens a new incident and is notified (%d notes)" % len(notes))

d5, notes = oomphd.Daemon(), []
d5.notify = lambda title, msg, **kw: notes.append(dict(kw, msg=msg))
t5 = t4 + 86400
d5.evaluate(dict(base, t=t5, pressure=4))
d5.incident["start"] -= oomphd.INCIDENT_MAX_S
d5.evaluate(dict(base, t=t5 + 5, pressure=1))
rolled5 = d5.incident is None and d5.rolled is not None
d5.pending_triggers.append(dict(kill, t=t5 + 10))
d5.evaluate(dict(base, t=t5 + 10, pressure=1))
new5 = d5.incident or {}
check(rolled5 and new5.get("continues") and len(notes) == 2 and notes[1].get("event") == "kill",
      "a kill just after a roll-over opens the continuation and is notified once (%s)" % [n.get("event") for n in notes])
new5["start"] -= oomphd.INCIDENT_MAX_S
d5.evaluate(dict(base, t=t5 + 15, pressure=4))
d5.pending_triggers.append(dict(kill, t=t5 + 20))
d5.evaluate(dict(base, t=t5 + 20, pressure=4))
check((d5.incident or {}).get("continues") == new5.get("id") and (d5.incident or {}).get("escalated")
      and len(notes) == 2, "a kill joining the continuation of an announced kill stays silent (%d notes)" % len(notes))

# --- summaries and reports stream: a day of samples, then a 2-hour incident closed by the logger
day_dir = tempfile.mkdtemp(prefix="oomph-selftest-day-")
t_end = (int(time.time()) // 86400 - 3) * 86400 + 0.5  # three days ago, its own files
tmpl = dict(base, top=[{"pid": 100 + i, "name": "proc%d" % i, "mb": 500 + 40 * i, "ppid": 1, "uid": 501, "g": "app%d" % (i % 15)}
                       for i in range(25)], groups=[{"name": "app%d" % i, "mb": 900 + 70 * i, "n": 3} for i in range(15)])
files = {}
times = [t_end - 86400 + 30 * i for i in range(2880 - 240)] + [t_end - 7200 + 5 * i for i in range(1441)]
for i, t in enumerate(times):
    smp = dict(tmpl, t=t, iso=oomphd.now_iso(t), pressure=4 if t >= t_end - 7200 else 1, jetsam_kills=int(i % 97 == 0),
               swap_used_gb=(i % 300) / 100.0, top=[dict(p, pid=p["pid"] + 1000 * (i // 400), mb=p["mb"] + i % 211)
                                                    for p in tmpl["top"]])
    day = oomphd.datetime.date.fromtimestamp(t).isoformat()
    files.setdefault(day, []).append(json.dumps(smp))
for day, lines in files.items():
    open(os.path.join(day_dir, "samples-%s.jsonl" % day), "w").write("\n".join(lines) + "\n")
probe = r"""
import json, os, resource, sys
sys.path.insert(0, sys.argv[1])
import oomphd
t = float(sys.argv[2])
d = oomphd.Daemon()
d.incident = {"id": "day", "start": t - 7200, "start_iso": "", "last_trigger": t - 180, "open": True,
              "reasons": [{"kind": "pressure", "t": t - 7200, "desc": "x"}]}
os.makedirs(os.path.join(oomphd.LOG_DIR, "incidents", "day"), exist_ok=True)
d.close_incident(t)
inc = json.load(open(os.path.join(oomphd.LOG_DIR, "incidents", "day", "incident.json")))
print(json.dumps({"rss_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1048576.0,
                  "samples": inc.get("summary", {}).get("samples"),
                  "report": os.path.getsize(os.path.join(oomphd.LOG_DIR, "incidents", "day", "report.html"))}))
"""
r = subprocess.run([sys.executable, "-I", "-B", "-c", probe, os.path.join(ROOT, "daemon"), str(t_end)],
                   env=dict(os.environ, OOMPH_DIR=day_dir), capture_output=True, text=True, timeout=300)
pr = json.loads(r.stdout.strip().splitlines()[-1]) if r.returncode == 0 and r.stdout.strip() else {}
check(pr.get("samples") == 1441 + 30 and pr.get("report", 0) > 100000 and pr.get("rss_mb", 999) < 96,
      "closing a 2-hour incident on a full day's log stays under 96 MB (%.0f MB, %s samples)%s"
      % (pr.get("rss_mb", -1), pr.get("samples"), "" if pr else ": " + r.stderr.strip()[-300:]))
saved_dir = oomph.LOG_DIR
oomph.LOG_DIR = day_dir
w = (t_end - 7200, t_end)
check(oomph.summarize(oomph.iter_samples(*w), []) == oomph.summarize(oomph.load_samples(*w), []),
      "a summary streamed from the files equals the one from the loaded list")
sub = oomph.load_samples(t_end - 4 * 3600, t_end)
views = oomph.report_views(t_end - 4 * 3600, t_end)
strip = lambda h: re.sub(r"generated [^<]* by|\bnd\d+", "", h)  # noqa: E731
check(strip(oomph.render_html(sub, [], "r", None, views)) ==
      strip(oomph.render_html(oomph.SampleWindow(t_end - 4 * 3600, t_end), [], "r", None, views)),
      "a report from the files read twice equals the one from the loaded list (%d samples)" % len(sub))
oomph.LOG_DIR = saved_dir
shutil.rmtree(day_dir, ignore_errors=True)

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

reqs = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                                  "clientInfo": {"name": "selftest", "version": "0"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "memory_check", "arguments": {}}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "incidents", "arguments": {"limit": 3}}},
]
if MAC:  # MCP server in a child process: it measures this machine
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
else:
    print("skip  MCP server in a child process: it measures this machine")
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
payload = json.dumps({"s": dict(fake), "procs": list(P.collect_procs().values())}, default=str)
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
odd = os.path.join(scratch, "odd")       # the tail as the cut of a copy gave it, at every boundary


def cut_tail(whole, cap):
    if len(whole) <= cap:
        return whole
    d = whole[-cap:]
    return d[d.find(b"\n") + 1:] if b"\n" in d else b""


bad_tail = []
for whole in (b"".join(b'{"n": %d}\n' % i for i in range(300)), b"a\n" + b"b" * 5000, b"x" * 9000 + b"\n",
              b"\n" * 50, b"ab\ncd\nef", b"", b"q" * 70000 + b"\n" + b"r" * 100 + b"\n"):
    open(odd, "wb").write(whole)
    for cap in (1, 2, 3, 9, 10, 11, 100, 2999, 3000, 5001, 5002, 9001, 65536, 70102, 1 << 20):
        if oomph.read_bounded(odd, cap, tail=True) != cut_tail(whole, cap):
            bad_tail.append((len(whole), cap))
check(not bad_tail, "read_bounded tail: the fragment skipped before the read gives what cutting a copy gave, at "
      "every boundary (%s)" % (bad_tail[:3] or "none differ"))
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
    snap = oomph.ledger_snapshot(P.collect_procs())
    oomph.release("r901")
    oomph.release("r900")
except Exception as e:  # noqa: B902
    ok = repr(e)
check(ok is True and [b["id"] for b in snap] == ["r900", "r901"], "malformed ledger: coordination, history, snapshot, "
      "release all work (%s)" % ok)
tick, dt = timed(oomph.ledger_tick, dict(fake), P.collect_procs())
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
tick, dt = timed(oomph.ledger_tick, dict(fake), P.collect_procs())
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

# the read side's race (03-linux C.3 row 19), planted deterministically: the attacker links someone's
# private file at the log's name, and removes the link right after the writer opened it, so the open
# file has one link again by the time it is checked. A hook in os.open plays the attacker.
real_open = os.open
armed = []


def racing_open(path, flags, mode=0o777, *, dir_fd=None):
    fd = real_open(path, flags, mode, dir_fd=dir_fd)
    if armed and path == armed[0][0] and not flags & (os.O_WRONLY | os.O_RDWR):
        armed.pop(0)[1](path, dir_fd)
    return fd


def raced(fn, *a, moves=(), **kw):
    """fn(*a, **kw) with os.open hooked: each move (name, action(name, dir_fd)) runs right after
    the next read-only open of that name, once."""
    armed[:] = list(moves)
    os.open = racing_open
    try:
        return fn(*a, **kw), not armed
    finally:
        os.open = real_open
        armed[:] = []


def unlink_it(name, dfd):
    os.unlink(name, dir_fd=dfd)


log_p = os.path.join(LD, "reservations.jsonl")
keep_log = open(log_p, "rb").read()
secret = os.path.join(scratch, "private-log")  # someone's own oomph-shaped file, mode 0600
now_t = time.time()
open(secret, "w").write("".join(json.dumps({"event": "end", "t": now_t, "key": "r%d@1" % i, "id": "r%d" % i,
                                            "gb": 1, "requested": now_t - 60, "ended": now_t, "outcome": "released",
                                            "purpose": "SECRET-%d" % i}) + "\n" for i in range(3)))
os.chmod(secret, 0o600)
before_s = digest(secret)
os.remove(log_p)
os.link(secret, log_p)
dfd = os.open(LD, os.O_RDONLY | os.O_DIRECTORY)
got, fired = raced(oomph.read_bounded, "reservations.jsonl", 1 << 20, dfd, moves=[("reservations.jsonl", unlink_it)])
check(fired and got and b"SECRET-0" in got and not os.path.lexists(log_p),
      "read race planted: without `shared`, the private file is read through the vanished link (the old check)")
os.link(secret, log_p)
x = oomph.reserve(0.1, "read race", me)
real_lstat = oomph._lstat
oomph._lstat = lambda name, dfd: os.stat(secret) if name == "reservations.jsonl" else real_lstat(name, dfd)
# ^ and the attacker wins the race of the check by name, too (C.3 row 19): it reports the victim, one link
real_read_once, reads = oomph._read_once, []


def watched_read_once(name, cap, dfd, tail, shared):  # which read met the attacker, and what it returned
    n = len(armed)
    got = real_read_once(name, cap, dfd, tail, shared)
    reads.append((name, shared, len(armed) < n, got))
    return got


oomph._read_once = watched_read_once
try:
    _, fired = raced(oomph.release, x["id"], moves=[("reservations.jsonl", unlink_it)])
finally:
    oomph._lstat, oomph._read_once = real_lstat, real_read_once
log_now = open(log_p, "rb").read()
check(("reservations.jsonl", True, True, None) in reads, "read race: the raced open was the writer's shared read "
      "of the log, and it was refused (%s)" % [r[:3] + (r[3] if r[3] is None else len(r[3]),) for r in reads])
check(fired and b"SECRET" not in log_now and b"read race" in log_now and digest(secret) == before_s,
      "read race: a writer refuses a private file it opened through a vanished link, even when the check by name "
      "is raced too; nothing of it reaches the shared log, the file is unchanged")
public = os.path.join(scratch, "public-log")  # readable by everyone: only the link checks after the read can tell
open(public, "wb").write(open(secret, "rb").read())
os.chmod(public, 0o644)
os.remove(log_p)
os.link(public, log_p)
got, fired = raced(oomph.read_bounded, "reservations.jsonl", 1 << 20, dfd, shared=True,
                   moves=[("reservations.jsonl", unlink_it)])
check(fired and got is None, "read race: the name gone after the read: refused (%r)" % (got and got[:20]))


os.link(public, log_p)
real_fstat, calls = os.fstat, []


def fstat_relinking(fd):  # the attacker links the name again between the read and the check after it
    calls.append(fd)
    if len(calls) == 2:
        os.link(public, log_p)
    return real_fstat(fd)


os.fstat = fstat_relinking
try:
    got, fired = raced(oomph.read_bounded, "reservations.jsonl", 1 << 20, dfd, shared=True,
                       moves=[("reservations.jsonl", unlink_it)])
finally:
    os.fstat = real_fstat
check(fired and got is None, "read race: the link planted again after the read: still two links by name, refused")
os.remove(log_p)
sdfd = os.open(scratch, os.O_RDONLY | os.O_DIRECTORY)
modes = {}
for m in (0o644, 0o604, 0o640, 0o600):  # a user in the file's group gets the group's bits, not the others'
    os.chmod(public, m)
    modes[oct(m)] = oomph.read_bounded("public-log", 1 << 20, sdfd, shared=True) is not None
os.chmod(public, 0o644)
os.close(sdfd)
check(modes == {"0o644": True, "0o604": False, "0o640": False, "0o600": False},
      "shared read: only a file with all three read bits is read (%s)" % modes)


def renamed_over(name, dfd):  # an honest writer replaces the file while it is read
    oomph._replace(dfd, name, b'{"seq": 7, "leases": [], "history": []}')


keep_ledger = open(os.path.join(LD, "ledger.json"), "rb").read()
open(os.path.join(LD, "ledger.json"), "w").write('{"seq": 6, "leases": [], "history": []}')
got, fired = raced(oomph.read_bounded, "ledger.json", 1 << 20, dfd, shared=True, moves=[("ledger.json", renamed_over)])
check(fired and got and b'"seq": 7' in got, "shared read: a file renamed over the name meanwhile → read again, the new one")
oomph._replace(dfd, "ledger.json", keep_ledger)
odd_line = json.dumps({"t": now_t, "note": "SECRET-dated-but-not-oomph"}).encode()
oomph._replace(dfd, "reservations.jsonl", keep_log + odd_line + b"\n")
os.close(dfd)
n0 = len(oomph.read_history())
x = oomph.reserve(0.1, "shape", me)
oomph.release(x["id"])
log_now = open(log_p, "rb").read()
check(b"SECRET" not in log_now and len(oomph.read_history()) > n0 > 0 and b'"shape"' in log_now,
      "history rewrite: a dated line not shaped like oomph's records is not carried over; oomph's are (%d)" % n0)

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
tick = timed(oomph.ledger_tick, dict(fake), P.collect_procs())[0]
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
if MAC and os.path.getsize(os.path.join(old, "oomph.py")) > 1000:  # 1.8.3 measures with macOS's libraries
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
    print("skip  1.8.3 compatibility: %s" % ("tag v1.8.3 not in this clone" if MAC else "1.8.3 needs macOS"))

# ledger version 2 for readers (B0, 1.9.2) and the frozen-1.8.1 test: 1.8.1's ledger code from git and this
# code on each other's files and on a v2 ledger, both directions; runs anywhere (it measures nothing)
try:
    r = subprocess.run([sys.executable, "-I", "-B", os.path.join(ROOT, "tools", "ledgercompat.py")],
                       capture_output=True, text=True, timeout=120)
except subprocess.TimeoutExpired:
    r = subprocess.CompletedProcess([], 1, "", "timed out after 120 s")
bad = [x for x in r.stdout.splitlines() if x.startswith("FAIL")]
if r.returncode == 2:
    print((r.stdout.strip().splitlines() or ["skip  the frozen-1.8.1 test"])[-1])
else:
    check(r.returncode == 0, "ledger v2 and the frozen-1.8.1 test: %d checks (%s)" % (
        sum(1 for x in r.stdout.splitlines() if x.startswith(("ok", "FAIL"))),
        "; ".join(bad) or (r.stdout.strip().splitlines() or [r.stderr[-300:]])[-1]))

# an install swaps a real /usr/local/libexec/oomph (1.6.0 to 1.8.0 installed one) for a link to
# this version under a 1.8.4 MCP server that has taken no tool call yet: its first one imports this
# oomphd, which must still answer the measuring names 1.8.4 calls on it (they moved to the backend)
lib = os.path.join(scratch, "libexec", "oomph")
new_lib = os.path.join(scratch, "libexec", "oomph-new")
os.makedirs(lib)
for f in ("oomph.py", "oomphd.py"):
    src = subprocess.run(["git", "-C", ROOT, "show", "v1.8.4:daemon/" + f], capture_output=True, text=True).stdout
    open(os.path.join(lib, f), "w").write(src)
if MAC and os.path.getsize(os.path.join(lib, "oomph.py")) > 1000:
    shutil.copytree(os.path.join(ROOT, "daemon"), new_lib, ignore=shutil.ignore_patterns("__pycache__"))
    mcp = subprocess.Popen([sys.executable, "-I", "-B", os.path.join(lib, "oomph.py"), "mcp"], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=dict(os.environ))
    mcp.stdin.write(json.dumps(reqs[0]) + "\n" + json.dumps(reqs[1]) + "\n")
    mcp.stdin.flush()
    up = mcp.stdout.readline()
    os.rename(lib, lib + ".old")  # what install.sh does, as one rename each
    os.symlink(new_lib, lib)
    try:
        out = mcp.communicate("".join(json.dumps(r) + "\n" for r in (
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "memory_check", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "reserve_memory",
                                                                           "arguments": {"gb": 0.1, "purpose": "swap"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "release_memory",
                                                                           "arguments": {"id": "all"}}})), timeout=90)[0]
    except subprocess.TimeoutExpired:
        mcp.kill()
        out = ""
    res = {r.get("id"): r for r in (json.loads(x) for x in out.splitlines() if x.startswith("{"))}
    bad = [i for i in (3, 4, 5) if "result" not in res.get(i, {}) or res[i]["result"].get("isError")]
    check(up.startswith("{") and not bad, "a 1.8.4 MCP server answers after an install swapped in this oomphd (%s)"
          % (", ".join("%d: %s" % (i, json.dumps(res.get(i))[:160]) for i in bad) or "check, reserve, release"))
else:
    print("skip  1.8.4 MCP server across an install: %s" % ("tag v1.8.4 not in this clone" if MAC else "needs macOS"))
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
if MAC:  # MCP reservations in a child process: it measures this machine
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
else:
    print("skip  MCP reservations in a child process: it measures this machine")

# --- N1: one name for people (BRAND), one for machines (CMD, paths, labels), kept apart
src = {f: open(os.path.join(ROOT, "daemon", f)).read() for f in ("oomph.py", "oomph_upgrade.py", "oomphd.py")}
mac_paths = oomph.PATHS["darwin"]
check(oomph.CMD == "oomph" and mac_paths["log"] == "/Library/Logs/oomph" and mac_paths["ledger"] == "/Users/Shared/oomph"
      and mac_paths["state"] == "~/Library/Application Support/oomph" and
      'LOG_DIR = os.environ.get("OOMPH_DIR", PATHS_HERE["log"])' in src["oomph.py"] and
      'LEDGER_DIR = os.environ.get("OOMPH_LEDGER_DIR") or _path("ledger")' in src["oomph.py"] and
      oomph.SKILL_URL == "https://raw.githubusercontent.com/kleinzeug/oomph/main/skills/oomph/SKILL.md" and
      'os.environ.get("OOMPH_REPO", "https://github.com/kleinzeug/oomph.git")' in src["oomph_upgrade.py"] and
      mac_paths["config"] == "/Library/Application Support/oomph/config.json" and
      (not MAC or oomph.CONFIG_FILE == mac_paths["config"]),
      "identifiers frozen: CMD, log, ledger and state directories, skill URL, upgrade repository, config file")
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
if MAC:  # MCP serverInfo and tool names, from the child process
    init = resp.get(1, {}).get("result", {}).get("serverInfo", {})
    check(init.get("name") == "oomph" and init.get("title") == oomph.BRAND, "MCP serverInfo: name oomph, title BRAND")
    check(sorted(names) == sorted(["memory_check", "reserve_memory", "release_memory", "update_reservation", "reservations",
                                   "reservation_history", "my_session", "memory_status", "wait_for_memory", "incidents",
                                   "incident"]), "MCP tool names frozen")
else:
    print("skip  MCP serverInfo and tool names, from the child process")
skill = open(os.path.join(ROOT, "skills", "oomph", "SKILL.md")).read()
check(skill.startswith("---\nname: oomph\n") and "`oomph resources --json` lists under `reservable`" in skill[:1300],
      "SKILL.md: name oomph; its first lines say resource flags only for what `oomph resources` lists as reservable")
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
if MAC:  # MCP argument checks in a child process
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
else:
    print("skip  MCP argument checks in a child process")
oomph._sample_override = lambda: dict(fixed)
out, err = io.StringIO(), io.StringIO()
with redirect_stdout(out), redirect_stderr(err):
    rc = oomph.main(["reserve", "-1G", "--for", "x"])
oomph._sample_override = None
check(rc == 75 and "unknown option" not in err.getvalue() and "REFUSED" in out.getvalue(),
      "strict: a negative size is the ledger's to refuse, with its advice (%s)"
      % " ".join((out.getvalue() or err.getvalue()).split())[:80])
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

# --- oomph top: the chart maths held to the app's, golden frames, one frame of this run's data (T0); the
# full-screen program in a pseudo-terminal, its decoder and writer, tmux as an oracle, --ssh (T1)
import oomph_view as view  # noqa: E402
for tool, what in (("chartvectors.py", "chart maths agree with the app's (tools/vectors/chart.json)"),
                   ("topfixture.py", "golden frames match (tools/golden/top)"),
                   ("toptest.py", "the dashboard in a terminal: keys, resizes, signals, suspend, --ssh, tmux "
                                  "(tools/toptest.py)")):
    r = subprocess.run([sys.executable, "-I", "-B", os.path.join(ROOT, "tools", tool)], capture_output=True, text=True,
                       timeout=300)
    bad = [x for x in r.stdout.splitlines() if "FAIL" in x or "DIFFER" in x]
    check(r.returncode == 0, "top: %s (%s)" % (what, (bad or r.stdout.strip().splitlines()[-1:] or [r.stderr[-300:]])[0]))
check([view.nice_top(r * 1.1) for r in (8, 16, 36, 64)] == [10, 20, 40, 72] and
      view.y_top(36, [("data", dict(t=1, wired=8, app=22, comp=10, swap=0, away=False, kills=0))])[0] == 48,
      "top: the y axis tops out at a round value over 1.1 x RAM and the peak (8 → 10, 16 → 20, 36 → 40, 64 → 72)")
g8 = view.GLYPHS["unicode"]["eighths"]
cells = view.stack_cells([(0, 12, "wired"), (12, 16, "swap")], 2, g8)
check(cells[0] == (g8[8], "wired", None) and cells[1] == (g8[4], "wired", "swap") and
      view.stack_cells([(0, 3, "app"), (3, 8, "comp")], 1, g8)[0] == (g8[3], "app", "comp"),
      "top: a cell holds the lower series as glyph and the upper as background, to the eighth (%s)" % cells)
hostile = "\x1b]52;c;aGk=\x07\x1b[2J‮evil⁦ שלום \U0001F680 構築 é́́ \x9b31m\x7f﻿"
fr = view.Frame(40, 1)
fr.put(0, 0, hostile)
import unicodedata  # noqa: E402
check(not any(unicodedata.category(ch)[0] == "C" for c in fr.c[0] for ch in c[0]) and "ש" not in fr.text() and
      view.tw(fr.text().rstrip("\n")) == 40 and view.tw("構築") == 4 and view.fit("構築構築", 4) == "構 …",
      "top: text is cleaned (no control, format or right-to-left character reaches a cell; wide characters are two)")
import oomph_top  # noqa: E402
tlog = tempfile.mkdtemp(prefix="oomph-top-")
t_now = 1795180000.0
with open(os.path.join(tlog, "events.jsonl"), "w") as f:      # past EVENTS_CAP, the newest line last
    pad = json.dumps({"t": t_now - 86400, "kind": "daemon_start", "pad": "x" * 200}) + "\n"
    f.write(pad * (oomph_top.EVENTS_CAP // len(pad) + 50))
    f.write(json.dumps({"t": t_now - 60, "kind": "jetsam", "kills": 2}) + "\n")
ev = oomph_top.load_events(tlog)
check(os.path.getsize(os.path.join(tlog, "events.jsonl")) > oomph_top.EVENTS_CAP and ev and
      ev[0][1] == "2 killed by jetsam" and ev[0][2],
      "top: an events file bigger than the cap still shows its newest event (%r)" % (ev[:1],))
for i in range(oomph_top.INCIDENTS_SHOWN + 5):                 # every 2 days, all named by local start time
    st0 = t_now - 86400 * (2 * i + 1)
    iid = time.strftime("%Y%m%d-%H%M%S", time.localtime(st0))
    os.makedirs(os.path.join(tlog, "incidents", iid))
    with open(os.path.join(tlog, "incidents", iid, "incident.json"), "w") as f:
        json.dump({"id": iid, "start": st0, "end": st0 + 60}, f)
shown, n90 = oomph_top.load_incidents(tlog, t_now)
check(len(shown) == oomph_top.INCIDENTS_SHOWN and n90 == oomph_top.INCIDENTS_SHOWN + 5,
      "top: the incidents of 90 days are counted past the %d shown (%d shown, %d counted)"
      % (oomph_top.INCIDENTS_SHOWN, len(shown), n90))
odd = []
for cur in ({"t": -1e300}, {"t": t_now, "groups": 5, "claude": "x", "pressure": [1]},
            {"t": t_now, "ram_gb": 16, "app_gb": -40, "compressed_gb": 4, "wired_gb": 3, "pressure": {"a": 1}}):
    with open(os.path.join(tlog, "current.json"), "w") as f:
        json.dump(cur, f)
    try:
        m = oomph_top.load_model("24h", t_now, log_dir=tlog, live=False)
        fr = view.render(dict(m, host="h", os="o"), 130, 40, view.Caps("256", "unicode", "dark"), {"span": "24h"})
        lines = fr.text().rstrip("\n").split("\n")
        if len(lines) != 40 or any(view.tw(x) != 130 for x in lines):
            odd.append("%s: frame is not 130x40" % sorted(cur))
    except Exception as e:
        odd.append("%s: %r" % (sorted(cur), e))
check(not odd, "top: odd types in current.json draw a frame, not a traceback (%s)" % "; ".join(odd))
fr = view.Frame(20, 1)
view.meter(fr, 5, 0, 10, [(-40.0, "app"), (4.0, "comp")], 16.0, view.GLYPHS["unicode"], view.Caps("256", "unicode", "dark"))
check(all(c[0] == " " and c[1] is None for c in fr.c[0][:5] + fr.c[0][15:]),
      "top: a meter stays in its cells when a reading is negative")
shutil.rmtree(tlog, ignore_errors=True)
top_cmd = [sys.executable, "-I", "-B", os.path.join(ROOT, "daemon", "oomph.py"), "top"]
r = subprocess.run(top_cmd + ["--once"], capture_output=True, text=True, timeout=120, env=dict(os.environ))
lines = r.stdout.split("\n")[:-1]
check(r.returncode == 0 and len(lines) == 24 and all(view.tw(x) == 80 for x in lines) and "\x1b" not in r.stdout,
      "top: `oomph top --once` into a pipe prints 24 lines of 80 cells without escapes (exit %s %s)"
      % (r.returncode, r.stderr.strip()[-200:]))
check(lines and lines[0].lstrip().startswith(oomph.BRAND) and re.search(r"Logging every|Incident open|Logger", lines[-1]),
      "top: the frame has the name, this machine and the logger's status (%r)" % (lines[-1:] or [""])[0].strip())
m = oomph_top.load_model("24h", t_now, log_dir=tlog, live=False)
row0 = view.render(dict(m, host="ci-runner-" + "x" * 70, os="o"), 80, 24, view.Caps("256", "unicode", "dark"),
                   {"span": "24h"}).text().split("\n")[0]
check(row0.lstrip().startswith(oomph.BRAND) and "ci-runner-" in row0 and view.tw(row0) == 80,
      "top: a long host name is cut, the name stays in row 0 (%r)" % row0.strip()[:60])
host_w = {}
for w_ in range(30, 161):     # no width at which one column less gives the host name more of the row (the cliff)
    r0 = view.render(dict(m, host="ci-runner-" + "x" * 140, os="o"), w_, 24, view.Caps("256", "unicode", "dark"),
                     {"span": "24h"}).text().split("\n")[0]
    hm = re.search(r"ci-r[^ ]*", r0)
    host_w[w_] = len(hm.group(0)) if hm else 0
cliff = [w_ for w_ in range(31, 161) if host_w[w_ - 1] > host_w[w_]]
check(not cliff and host_w[80] >= 12, "top: a long host name gets no more of row 0 as the terminal narrows; no cliff "
      "(at %s)" % ["%d: %d > %d" % (w_, host_w[w_ - 1], host_w[w_]) for w_ in cliff[:3]])


class _Term99:
    entered = False

    def enter(self, extra=""):
        _Term99.entered = True
        raise oomph_top.Gone()        # (if reached, end the run rather than wait for keys)

    def restore(self):
        pass

    def size(self):
        return 80, 24

    def present(self, *a):
        pass

    def forget(self):
        pass


app99 = oomph_top.App(_Term99(), view.Caps("256", "unicode", "dark"), {}, "24h", tempfile.mkdtemp(prefix="oomph-top99-"),
                      readonly="test", probe=False)
app99.src.step = lambda: (_ for _ in ()).throw(oomph_top.Leave(15))
rc99 = app99.run()
app99.model = m
real_render, real_at = view.render, oomph_top.at
view.render = lambda *a, **k: (_ for _ in ()).throw(oomph_top.Leave(1))
oomph_top.at = lambda model, now: model
try:
    app99.paint()
    painted = "swallowed"
except oomph_top.Leave:
    painted = "raised"
finally:
    view.render, oomph_top.at = real_render, real_at
check(rc99 == 0 and not _Term99.entered and painted == "raised", "top: a SIGTERM (Leave) during the first step or a "
      "render leaves at once, never swallowed as a crash (entered %s, paint %s)" % (_Term99.entered, painted))
r = subprocess.run(top_cmd + ["--once", "--size", "100x30", "--span", "1h", "--glyphs", "ascii", "--color", "256",
                              "--some-later-option"], capture_output=True, text=True, timeout=120, env=dict(os.environ))
lines = r.stdout.split("\n")[:-1]
check(r.returncode == 0 and len(lines) == 30 and "\x1b[" in r.stdout and "ignored: --some-later-option" in lines[-1] and
      all(ord(ch) < 128 for ch in re.sub(r"\x1b\[[0-9;]*m", "", r.stdout)),
      "top: --size, --span, --glyphs ascii, --color 256; an unknown option is ignored and named")
r = subprocess.run(top_cmd + ["--once", "--span", "2d"], capture_output=True, text=True, timeout=60, env=dict(os.environ))
check(r.returncode == 2 and "--span" in r.stderr, "top: a span it does not know is a usage error (exit 2)")

# --- L0b: the portable core: one backend contract, the path table, `os` and `machine`, 80 columns, doctor
CONTRACT = ("OS", "machine", "system_memory", "away_state", "collect_procs", "proc_cwd", "group_key", "is_agent",
            "ownership", "uptime_s", "notify", "dump_syslog")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import fixtureplat  # noqa: E402
backends = [fixtureplat] + ([P] if MAC else [])
check(all(hasattr(b, n) for b in backends for n in CONTRACT) and (not MAC or P.__name__ == "oomph_darwin"),
      "backend contract: %s %s every member" % (" and ".join(b.__name__ for b in backends), "have" if MAC else "has"))
probe = r"""
import json, sys
sys.platform = "linux"   # what imports on a Linux box, here
sys.path.insert(0, sys.argv[1])
import oomph, oomphd
try:
    backend = oomph.plat().__name__
    unsupported = None
except oomph.Unsupported as e:
    backend, unsupported = None, str(e)
rc = oomph.main(["check"])
print(json.dumps({"native": [m for m in ("ctypes", "oomph_darwin") if m in sys.modules], "unsupported": unsupported,
                  "backend": backend,
                  "rc": rc, "log": oomph.LOG_DIR, "ledger": oomph.LEDGER_DIR, "state": oomph.STATE_DIR,
                  "config": oomph.CONFIG_FILE, "mode": oomph.PATHS_HERE["ledger_mode"]}))
"""
xdg = tempfile.mkdtemp(prefix="oomph-xdg-")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import linuxfixture  # noqa: E402
linuxfixture.build(os.path.join(xdg, "root"), "ubuntu-server-idle")
clean = {k: v for k, v in os.environ.items() if not k.startswith("OOMPH_")}
r = subprocess.run([sys.executable, "-I", "-B", "-c", probe, os.path.join(ROOT, "daemon")], capture_output=True, text=True,
                   env=dict(clean, XDG_STATE_HOME=xdg, OOMPH_SYSROOT=os.path.join(xdg, "root")), timeout=60)
lx_ = json.loads(r.stdout.strip().splitlines()[-1]) if r.returncode == 0 and r.stdout.strip() else {}
check(lx_.get("native") == [] and lx_.get("backend") == "oomph_linux" and lx_.get("rc") == 0 and
      "14.4G available of 16G" in r.stdout,
      "on Linux: oomph and oomphd import without native code; oomph_linux measures (a recorded Ubuntu here): %s"
      % ((r.stdout.strip().splitlines() or [""])[0][:80] or r.stderr.strip()[-200:]))
check(lx_.get("log") == "/var/log/oomph" and lx_.get("state") == os.path.join(xdg, "oomph") and
      re.fullmatch(re.escape(os.path.join(xdg, "oomph", "ledger")) + r"/(m-[0-9a-f]{16}|local)", lx_.get("ledger", "")) and
      lx_.get("config") == "/etc/oomph/config.json" and lx_.get("mode") == 0o700,
      "path table on Linux: logs, a per-user ledger per machine (0700), XDG state, /etc config (%s)" % lx_.get("ledger"))
probe2 = "import sys; sys.path.insert(0, sys.argv[1]); import oomph, oomphd; oomph.main(['incidents']); " \
         "oomph.main(['report', '--last', '10m']); print('NATIVE', [m for m in ('ctypes', 'oomph_darwin') if m in sys.modules])"
r = subprocess.run([sys.executable, "-I", "-B", "-c", probe2, os.path.join(ROOT, "daemon")], capture_output=True, text=True,
                   env=dict(os.environ), timeout=60)
check(r.stdout.strip().endswith("NATIVE []"), "reading logs loads no backend (incidents, report): %s"
      % (r.stdout.strip().splitlines()[-1:] or [r.stderr[-200:]])[0])
shutil.rmtree(xdg, ignore_errors=True)

# samples say which system wrote them; current.json says which machine
cur = json.load(open(os.path.join(LOG, "current.json")))
day_files = sorted(f for f in os.listdir(LOG) if f.startswith("samples-") and f.endswith(".jsonl"))
last = json.loads(open(os.path.join(LOG, day_files[-1])).read().splitlines()[-1]) if day_files else {}
mach = cur.get("daemon", {}).get("machine") or {}
check(cur.get("os") == last.get("os") == P.OS and "machine" not in last and "daemon" not in last,
      "samples carry os %r; the machine block is in current.json only" % last.get("os"))
check({"id", "name", "os", "arch", "os_version", "kernel", "kind", "cpus", "measures"} <= set(mach) and
      mach["os"] == P.OS and isinstance(mach["measures"], dict) and "all_procs" in mach["measures"] and
      (not MAC or (re.fullmatch(r"m-[0-9a-f]{16}", mach["id"] or "") and mach["kind"] in ("laptop", "desktop"))),
      "current.json: daemon.machine %s, %s, %s, measures %s" % (mach.get("id"), mach.get("os_version"), mach.get("kind"),
                                                               sorted(mach.get("measures") or {})))
check(oomph.live_sample(with_procs=False).get("os") == P.OS, "a live reading carries os too")
unclassified = sorted((set(last) | set(cur)) - set(oomph.SAMPLE_KEYS))
check(not unclassified and oomph.SAMPLE_KEYS["daemon"] == "full" and "top" not in oomph.slim_sample(cur),
      "every key the logger writes is classified for the wire (keep, drop, full)%s"
      % (": not " + ", ".join(unclassified) if unclassified else ""))
check(oomph.verdict(dict(fixed, disk_free_gb=3.0))["level"] == "critical" and
      oomph.verdict(dict(fixed, os="macos", disk_free_gb=3.0))["level"] == "critical" and
      oomph.verdict(dict(fixed, os="linux", disk_free_gb=3.0))["level"] == "ok",
      "verdict: a full disk counts on a Mac (os absent or macos), not on Linux")

# every reader takes old samples (no os, no machine) and newer ones (keys it does not know)
vdir = tempfile.mkdtemp(prefix="oomph-variants-")
t_v = time.time()
# the blocks of 1.9.1 as 02 §5.1 writes them, so that every reader meets them on every system (not only this Mac's)
RES_EXAMPLE = {
    "cpu": {"n": 14, "p": 10, "e": 4, "busy": 9.12, "user": 7.61, "sys": 1.51, "p_busy": 7.9, "e_busy": 1.22,
            "load": [10.2, 13.9, 13.1], "therm": 2},
    "gpu": [{"id": "gpu0", "name": "Apple M3 Max", "unified": True, "util": 47.0, "active": 47.0, "now": 52, "src": "clients",
             "mem_gb": 3.99, "mem_alloc_gb": 11.68, "mem_limit_gb": 27.0, "mem_limit_est": True}],
    "disks": [{"id": "data", "name": "Data", "mount": "/System/Volumes/Data", "dev": "disk3", "fs": "apfs", "total_gb": 994.7,
               "free_gb": 63.2, "roles": ["home", "swap", "tmp"], "watch": True, "low_gb": 20, "crit_gb": 5, "level": "ok"},
              {"id": "vol:5E0C61B2-0F4A-4D1B-9C57-3A1D2B7E9F10", "name": "Scratch", "mount": "/Volumes/Scratch",
               "dev": "disk7", "fs": "apfs", "total_gb": 1863.0, "free_gb": 912.4, "roles": [], "kind": "external",
               "watch": False}],
    "io": {"w_mb_s": 12.4, "r_mb_s": 3.1},
    "top_cpu": [{"pid": 4711, "name": "cargo", "g": "iTerm2", "cpu": 5.2, "s": 640}],
    "top_gpu": [{"pid": 413, "name": "WindowServer", "g": "WindowServer", "gpu": 9.1}],
    "top_io": [{"pid": 902, "name": "com.docker.virtualization", "g": "Docker", "w": 18.3}]}
RES_KEYS = tuple(RES_EXAMPLE)
newer = dict(cur, os="linux", psi={"mem_some": 0.1}, linux={"avail_gb": 4.0}, killed=[{"name": "x", "mb": 1, "by": "k"}],
             daemon=dict(cur.get("daemon", {}), machine=dict(mach, measures=dict(mach.get("measures") or {}, psi=True),
                                                             kind="container")), future_block={"x": [1]}, **RES_EXAMPLE)
newer["groups"] = [dict(g, cpu=1.5, gpu=2.0) for g in cur.get("groups") or []]
older = {k: v for k, v in cur.items() if k != "os" and k not in RES_KEYS}
older["daemon"] = {k: v for k, v in cur.get("daemon", {}).items() if k != "machine"}
saved_log = oomph.LOG_DIR
bad_reads = []
for label, cv in (("old", older), ("new", newer)):
    os.makedirs(os.path.join(vdir, label), exist_ok=True)
    rows = [dict(cv, t=t_v - 60 * i, iso=oomphd.now_iso(t_v - 60 * i)) for i in range(30, -1, -1)]
    for row in rows:
        row.pop("daemon", None)
    with open(os.path.join(vdir, label, "samples-%s.jsonl" % oomphd.datetime.date.fromtimestamp(t_v).isoformat()), "w") as f:
        f.write("".join(json.dumps(x) + "\n" for x in rows))
    json.dump(dict(cv, t=t_v), open(os.path.join(vdir, label, "current.json"), "w"))
    # the events and an incident of each version: the new resources' kinds and summary fields (1.9.5, 02 §5.3)
    evl = [{"t": t_v - 900, "kind": "disk_low", "disk_free_gb": 12.0}, {"t": t_v - 800, "kind": "pressure_change", "old": 1,
                                                                         "new": 2}]
    if label == "new":
        evl += [{"t": t_v - 700, "kind": "thermal", "old": 0, "new": 2, "busy": 9.1},
                {"t": t_v - 650, "kind": "cpu_saturated", "busy": 13.1, "n": 14, "minutes": 10, "top": {"cargo": 9.0}},
                {"t": t_v - 600, "kind": "cpu_saturated_cleared", "busy": 2.0, "n": 14, "minutes": 14},
                {"t": t_v - 550, "kind": "disk_low", "disk_free_gb": 12.0, "pool": "data", "name": "Data", "mount": "/",
                 "free_gb": 12.0, "level": "low"},
                {"t": t_v - 500, "kind": "disk_filling", "pool": "data", "name": "Data", "free_gb": 30.0, "rate_gb_min": 2.5,
                 "eta_min": 10.0, "top": {"dd": 900.0}},
                {"t": t_v - 450, "kind": "volume", "pool": "vol:X", "name": "Scratch", "mount": "/Volumes/Scratch",
                 "what": "mounted"},
                {"t": t_v - 400, "kind": "unowned_memory", "gb": 20.0, "gpu_alloc_gb": 11.7},
                {"t": t_v - 350, "kind": "a_kind_of_1_10", "x": [1]}]
    for e in evl:
        e["iso"] = oomphd.now_iso(e["t"])
    with open(os.path.join(vdir, label, "events.jsonl"), "w") as f:
        f.write("".join(json.dumps(e) + "\n" for e in evl))
    iid = time.strftime("%Y%m%d-%H%M%S", time.localtime(t_v - 1200))
    os.makedirs(os.path.join(vdir, label, "incidents", iid))
    with open(os.path.join(vdir, label, "incidents", iid, "incident.json"), "w") as f:
        json.dump({"id": iid, "start": t_v - 1200, "end": t_v - 300, "open": False,
                   "reasons": [{"kind": "pressure", "desc": "Memory pressure CRITICAL", "t": t_v - 1200}],
                   "summary": oomph.summarize(rows, evl)}, f)
    oomph.LOG_DIR = os.path.join(vdir, label)
    try:
        with redirect_stdout(io.StringIO()):
            for args in (["status"], ["report", "--last", "1h"], ["html", "--last", "1h", "-o", os.path.join(vdir, "r.html")],
                         ["incidents"], ["incident", "latest"]):
                if oomph.main(args) != 0:
                    bad_reads.append("%s: oomph %s" % (label, args[0]))
        html_v = oomph.incident_html(oomph.list_incidents()[-1])
        if ("Cores busy" in html_v) != (label == "new"):
            bad_reads.append("%s: the incident report's CPU panel" % label)
        m = oomph_top.load_model("1h", t_v, log_dir=oomph.LOG_DIR, live=False)
        texts = [e[1] for e in m["events"]]
        if label == "new" and not ("disk low: Data 12.0 GB free" in texts and "disk mounted: Scratch" in texts and
                                   "cores saturated: 13.1 of 14 busy for 10 min" in texts and "thermal nominal → heavy" in texts
                                   and "a kind of 1 10" in texts):
            bad_reads.append("new: event words in oomph top %s" % texts)
        for ui in ({"span": "1h"}, {"span": "1h", "panel": "e"}, {"span": "1h", "overlay": {"kind": "inc", "id": iid}}):
            view.render(m, 80, 24, view.Caps("none", "unicode", "dark"), ui)
        lay = view.layout(m, 100, 30)
        for c in range(0, lay["plot_w"], 7):
            ui = {"span": "1h"}
            view.inspect_at(ui, m, lay, c)
            view.render(m, 100, 30, view.Caps("256", "unicode", "dark"), ui)
        import oomph_ai  # noqa: E402
        lg = oomph_ai.Logs(t_v - 3600, t_v)
        oomph_ai.briefing(lg)
        tl = lg.timeline({"step_minutes": 10})
        if ("cores_busy" in tl["rows"][-1]) != (label == "new"):
            bad_reads.append("%s: AI timeline rows %s" % (label, sorted(tl["rows"][-1])))
        for by in ("memory", "cpu", "gpu", "writes"):
            lg.top_at({"by": by})
        lg.events({"kind": "disk_filling"})
    except Exception as e:  # noqa: B902
        bad_reads.append("%s: %r" % (label, e))
oomph.LOG_DIR = saved_log
shutil.rmtree(vdir, ignore_errors=True)
check(not bad_reads, "old and newer samples, events and incidents through status, report, html, incidents, the incident "
      "report, oomph top (events, the incident card, inspect at every 7th column) and the AI tools (%s)"
      % ("; ".join(bad_reads) or "all read"))

# 80 columns: long names are cut by rule, prose is wrapped, headlines continue under their column
wide = []


def fits(what, text, w=80):
    """Lines longer than w, except where one word (a temporary folder's path) is longer than half a line."""
    long = [x for x in text.splitlines() if len(x) > w and max(len(y) for y in x.split()) <= w // 2]
    if long:
        wide.append("%s: %r" % (what, long[0]))


oomph._sample_override = lambda: dict(fixed)
lp = oomph.reserve(0.2, "a purpose far longer than any column could hold, by design", dict(me, project="/x/" + "p" * 80))
lq = oomph.reserve(0.2, "another long purpose that waits behind the first one, too", dict(me, project="/y/q"))
for args in (["status"], ["reservations"], ["incidents"], ["report", "--last", "1h"], ["check"],
             ["reserve", "100G", "--for", "a purpose far longer than any column could hold"]):
    buf = io.StringIO()
    with redirect_stdout(buf):
        oomph.main(args)
    fits("oomph " + " ".join(args[:1]), buf.getvalue())
v = oomph.checked_verdict()
v["reasons"] = ["a reason far longer than one line of a narrow terminal could ever hold without wrapping it"] * 2
fits("verdict line", oomph.verdict_line(v, 80))
fits("verdict line at 60", oomph.verdict_line(v, 60), 60)
oomph.release(lp["id"])
oomph.release(lq["id"])
oomph._sample_override = None
iid_l = "20990101-000000"
os.makedirs(os.path.join(LOG, "incidents", iid_l))
json.dump({"id": iid_l, "start": time.time() - 60, "open": True, "reasons": [
    {"kind": "pressure", "t": time.time(), "desc": "Memory pressure CRITICAL (swap 12.5 GB, disk 3 GB free) and then some more"}]},
    open(os.path.join(LOG, "incidents", iid_l, "incident.json"), "w"))
buf = io.StringIO()
with redirect_stdout(buf):
    oomph.main(["incidents"])
rows = buf.getvalue().splitlines()
k = next((i for i, x in enumerate(rows) if x.startswith(iid_l)), None)
check(rows[0].split() == ["incident", "took", "state", "kills", "headline"] and k is not None and
      rows[k][36:].startswith("Memory pressure") and "OPEN" in rows[k] and rows[k + 1].startswith(" " * 36),
      "incidents: a table with a header; a long headline continues under its column")
shutil.rmtree(os.path.join(LOG, "incidents", iid_l))
check(oomph.fit_group("docker:b81d07c2 (redis-server)", 24) == "docker:b81d07c2 (redis…)" and
      oomph.cut_middle("prometheus-config-reloader", 20) == "prometheus…-reloader" and
      oomph.cut_left("/Users/x/proj/api", 10) == "…/proj/api" and oomph.cut_end("gradle build", 6) == "gradl…",
      "cuts: a container's id stays whole, names keep head and tail, folders their end, purposes their start")
check(not wide, "every line fits 80 columns (%s)" % ("; ".join(wide) or "status, reservations, incidents, report, check"))

# MCP, in-process: the same tools on whatever measures here
names_ip = [t["name"] for t in oomph.MCP_TOOLS]
check(sorted(names_ip) == sorted(["memory_check", "reserve_memory", "release_memory", "update_reservation", "reservations",
                                  "reservation_history", "my_session", "memory_status", "wait_for_memory", "incidents",
                                  "incident"]), "MCP tool names frozen (in-process)")
oomph._sample_override = lambda: dict(fixed)
mr = oomph._mcp_call("reserve_memory", {"gb": 0.1, "purpose": "in-process", "wait_s": 0})
ml = oomph._mcp_call("reservations", {})
mf = oomph._mcp_call("release_memory", {"id": mr.get("id", "r0")})
oomph._sample_override = None
check(mr.get("status") == "granted" and any(b["id"] == mr["id"] for b in ml.get("mine", []) + ml.get("others", []))
      and mf.get("released"), "MCP in-process: reserve, list, release (%s)" % mr.get("status"))

# oomph doctor: one line per check, a fix where there is one, exit 0 / 1 / 2
buf = io.StringIO()
with redirect_stdout(buf):
    rc = oomph.main(["doctor", "--json"])
dj = json.loads(buf.getvalue())
ids = [x["id"] for x in dj["checks"]]
check(set(dj) == {"version", "machine", "ledger", "checks", "exit"} and rc == dj["exit"] and rc in (0, 1) and
      {"python", "memory", "processes", "logger", "versions", "ledger", "claude"} <= set(ids) and
      all(x["level"] in oomph.DOCTOR_LEVELS for x in dj["checks"]) and dj["ledger"]["path"] == oomph.LEDGER_DIR and
      (dj["exit"] == 1) == any(x["level"] == "warn" for x in dj["checks"]),
      "doctor --json: %s → exit %d" % (", ".join("%s %s" % (x["id"], x["level"]) for x in dj["checks"]), rc))
buf = io.StringIO()
with redirect_stdout(buf):
    rc2 = oomph.main(["doctor"])
fits("doctor", buf.getvalue())
check(rc2 == rc and buf.getvalue().splitlines()[0].startswith(oomph.BRAND + " ") and not wide,
      "doctor: the same verdict as text, in 80 columns")
planted = tempfile.mkdtemp(prefix="oomph-doctor-")
os.symlink(LD, os.path.join(planted, "linked"))
os.mkdir(os.path.join(planted, "fifo"))
os.mkfifo(os.path.join(planted, "fifo", "ledger.json"))
os.mkdir(os.path.join(planted, "private"))
os.close(os.open(os.path.join(planted, "private", "reservations.jsonl"), os.O_CREAT | os.O_WRONLY, 0o600))
os.mkdir(os.path.join(planted, "group"))
os.close(os.open(os.path.join(planted, "group", "ledger.json"), os.O_CREAT | os.O_WRONLY, 0o604))
os.chmod(os.path.join(planted, "group", "ledger.json"), 0o604)
os.mkdir(os.path.join(planted, "lock"))
os.close(os.open(os.path.join(planted, "lock", "ledger.lock"), os.O_CREAT | os.O_WRONLY, 0o600))
saved_ld = oomph.LEDGER_DIR
found = []
for name in ("linked", "fifo", "private", "group", "lock"):
    oomph.LEDGER_DIR = os.path.join(planted, name)
    r = oomph.doctor()
    found.append(next(x for x in r["checks"] if x["id"] == "ledger"))
oomph.LEDGER_DIR = saved_ld
check([x["level"] for x in found] == ["warn"] * 5 and "symbolic link" in found[0]["text"] and
      "not a regular file" in found[1]["text"] and "not readable by everyone" in found[2]["text"] and
      "not readable by everyone, so it is refused" in found[3]["text"] and "can't take the lock" in found[4]["text"]
      and all(x.get("fix") for x in found) and all(x["fix"].startswith("chmod 666 ") for x in found[2:]),
      "doctor: a ledger folder replaced by a link, a FIFO planted as ledger.json, a private reservations.jsonl, a "
      "ledger.json its group can't read, a private lock: warn, with the fix (chmod for a mode; nothing opened)")
shutil.rmtree(planted, ignore_errors=True)

# --- side-by-side installs, into a throwaway prefix (install.sh's test mode: no root, no launchd)
if MAC:  # install.sh needs macOS (BSD tools, launchd)
    inst = tempfile.mkdtemp(prefix="oomph-install-")
    pfx = os.path.join(inst, "root")
    os.mkdir(pfx)


    def flat_source(name, version, skill_note):
        """An app bundle's Resources folder, stamped with `version`."""
        d = os.path.join(inst, name)
        os.makedirs(os.path.join(d, "skills", "oomph"))
        for f in ("oomphd.py", "oomph.py", "oomph_darwin.py", "oomph_linux.py", "oomph_ioreport.py", "oomph_ai.py",
                  "oomph_upgrade.py", "oomph_top.py", "oomph_view.py", "oomph_net.py", "oomph_sync.py",
                  "local.oomph.daemon.plist"):
            shutil.copy(os.path.join(ROOT, "daemon", f), d)
        for f in ("install.sh", "uninstall.sh"):
            shutil.copy(os.path.join(ROOT, f), d)
        open(os.path.join(d, "skills", "oomph", "SKILL.md"), "w").write(skill + skill_note)
        for f in ("oomphd.py", "oomph_darwin.py"):  # say where they were imported from, when asked to
            with open(os.path.join(d, f), "a") as h:
                h.write('\nif __import__("os").environ.get("OOMPH_SELFTEST_IMPORTS"):\n'
                        '    open(__import__("os").environ["OOMPH_SELFTEST_IMPORTS"], "a").write(__file__ + "\\n")\n')
        t = open(os.path.join(d, "oomph.py")).read().replace('VERSION = "dev"', 'VERSION = "%s"' % version, 1)
        open(os.path.join(d, "oomph.py"), "w").write(t)
        return d


    def sh(script, *args, umask=None):
        r = subprocess.run(["/bin/bash", script] + list(args), capture_output=True, text=True, timeout=120,
                           env=dict(os.environ, OOMPH_INSTALL_ROOT=pfx),
                           preexec_fn=None if umask is None else (lambda: os.umask(umask)))
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
    cache = os.path.join(lx, "oomph-1.8.5", "__pycache__")
    check(any(n.startswith("oomph_top.") and n.endswith(".pyc") for n in os.listdir(cache))
          if os.path.isdir(cache) else False,
          "install compiles the modules once (oomph top and every command import instead of compiling)")
    os.makedirs(cache, exist_ok=True)  # as `sudo oomph …` may leave
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
    rc, msg = sh(os.path.join(B, "install.sh"), umask=0)     # as from a sudo that passed on a umask of 000
    loose = [os.path.relpath(os.path.join(dp, x), lx) for dp, dn, fn in os.walk(os.path.join(lx, "oomph-1.8.6"))
             for x in dn + fn if os.lstat(os.path.join(dp, x)).st_mode & 0o022]
    pyc = [x for x in os.listdir(os.path.join(lx, "oomph-1.8.6", "__pycache__"))] \
        if os.path.isdir(os.path.join(lx, "oomph-1.8.6", "__pycache__")) else []
    check(rc == 0 and pyc and not loose, "install under a umask of 000: the bytecode (%d files) and everything else in "
          "the version directory is writable by its owner alone (%s)" % (len(pyc), loose[:3]))
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
else:
    print("skip  install.sh needs macOS (BSD tools, launchd)")

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
if MAC:  # upgrades need macOS (xcrun git, the app build)
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
else:
    print("skip  upgrades need macOS (xcrun git, the app build)")

# --- M1 (1.9.1): CPU, GPU, I/O and disks in the samples; status, check, resources, ps, volumes (roadmap 02 §4, §5, §7)
FIX = os.path.join(ROOT, "tools", "fixtures")


class StubPlat:
    """A backend whose readings the test sets: uptime, ticks, the pid list."""
    OS = "macos"

    def __init__(self):
        self.up, self.ticks, self.pids = 1000.0, None, None

    def uptime_s(self):
        return self.up

    def cpu_ticks(self):
        return self.ticks

    def cpu_topology(self):
        return {"n": 4, "p": 2, "e": 2, "e_ids": [0, 1]}

    def thermal_level(self):
        return 0

    def list_pids(self):
        return self.pids


def ptab(*rows):
    """A process table: (pid, ppid, start, cpu_s, child_s[, wr])."""
    return {r[0]: {"pid": r[0], "ppid": r[1], "uid": 501, "name": "p%d" % r[0], "start": r[2], "fp": 0, "rss": 0, "path": "",
                   "cpu_s": float(r[3]), "child_s": float(r[4]), "rd": 0, "wr": r[5] if len(r) > 5 else 0} for r in rows}


def meter_run(steps):
    """Readings one second apart: each step (process table, raw pids or None). Returns the per-pid CPU of each."""
    sp, m, out = StubPlat(), None, []
    m = oomphd.Meter(sp)
    for procs, raw in steps:
        sp.up += 1.0
        sp.pids = raw
        out.append({pid: round(x["cpu"], 3) for pid, x in m.read(procs)[1].items()})
    return out


old_t = int(time.time()) - 3600
# a child busy for 2 s, seen alive twice, then reaped at once with 0.5 s more: the parent reads 0.5, not 2.5
r = meter_run([(ptab((10, 1, old_t, 0, 0), (11, 10, old_t, 0, 0)), None),
               (ptab((10, 1, old_t, 0, 0), (11, 10, old_t, 1.0, 0)), None),
               (ptab((10, 1, old_t, 0, 0), (11, 10, old_t, 2.0, 0)), None),
               (ptab((10, 1, old_t, 0, 2.5)), None)])
check(r[3].get(10) == 0.5 and r[1].get(11) == 1.0 and max(x.get(10, 0) for x in r) <= 1.3,
      "cpu: a reaped child's time is counted once: the parent reads 0.5 cores after it, not 2.5 (%s)" % r[3])
# the zombie case (A.25): the child exits after 3 s, stays unreaped for three readings, then is reaped
zt = [(ptab((10, 1, old_t, 0, 0), (11, 10, old_t, 0, 0)), [10, 11]),
      (ptab((10, 1, old_t, 0, 0), (11, 10, old_t, 1.0, 0)), [10, 11]),
      (ptab((10, 1, old_t, 0, 0), (11, 10, old_t, 2.0, 0)), [10, 11]),
      (ptab((10, 1, old_t, 0, 0)), [10, 11]), (ptab((10, 1, old_t, 0, 0)), [10, 11]), (ptab((10, 1, old_t, 0, 0)), [10, 11]),
      (ptab((10, 1, old_t, 0, 3.0)), [10])]
r = meter_run(zt)
total = sum(x.get(10, 0) + x.get(11, 0) for x in r)
check(max(x.get(10, 0) for x in r) <= 1.3 and abs(total - 3.0) < 0.01,
      "cpu: a child reaped three readings after it exited: no spike in the parent, its 3 s counted once (%.2f)" % total)
# six short children no reading saw: their time is found in the parent
r = meter_run([(ptab((10, 1, old_t, 0, 0)), None), (ptab((10, 1, old_t, 0.1, 3.0)), None)])
check(r[1].get(10) == 3.1, "cpu: six short children nobody saw leave their 3 s in the parent (%s)" % r[1])
# launchd reaps every orphan: its child time is ignored; nothing reads above the core count
r = meter_run([(ptab((1, 0, old_t, 0, 0), (12, 1, old_t, 0, 0)), None), (ptab((1, 0, old_t, 0.2, 50.0), (12, 1, old_t, 9.0, 0)), None)])
check(r[1].get(1) == 0.2 and r[1].get(12) == 4.0, "cpu: launchd's reaped time is ignored; 9 s in a second reads as the "
      "4 cores there are (%s)" % r[1])
# the clamp: the per-process sum never exceeds what the machine was busy, plus half a core
sp = StubPlat()
m = oomphd.Meter(sp)
sp.ticks = [[0, 0, 100, 0]] * 4
m.read(ptab((20, 1, old_t, 0, 0), (21, 1, old_t, 0, 0)))
sp.up += 1.0
sp.ticks = [[25, 0, 175, 0]] * 4  # each core a quarter busy: one core in all
blocks, use = m.read(ptab((20, 1, old_t, 2.0, 0), (21, 1, old_t, 2.0, 0)))
check(abs(blocks["cpu"]["busy"] - 1.0) < 1e-6 and abs(sum(x["cpu"] for x in use.values()) - 1.5) < 1e-6 and m.scaled > 1,
      "cpu: 4 cores of processes on a machine 1 core busy are scaled to 1.5, and that is reported (%.2f)"
      % sum(x["cpu"] for x in use.values()))
check(blocks["cpu"]["user"] + blocks["cpu"]["sys"] == blocks["cpu"]["busy"] and blocks["cpu"]["e_busy"] == 0.5 and
      blocks["cpu"]["p_busy"] == 0.5, "cpu: busy = user + sys, split by cluster (%s)" % blocks["cpu"])
sp.up += 1.0
sp.ticks = [[25 + (1 << 32) - 10, 0, 175 + 10, 0]] * 4  # a 32-bit counter wrapped
blocks, _ = m.read(ptab((20, 1, old_t, 2.0, 0)))
check(blocks["cpu"]["busy"] <= 4 and blocks["cpu"]["busy"] >= 0, "cpu: a wrapped 32-bit tick counter (%s)" % blocks["cpu"]["busy"])
blocks, _ = m.read(ptab((20, 1, old_t, 2.0, 0)), gap=True)
check("busy" not in blocks["cpu"] and "io" not in blocks and blocks["cpu"]["n"] == 4,
      "cpu: no rates in the first reading after a gap, the core count stays")
# the GPU from the registry: rung 2 (clients) after a first reading of rung 3, hostile creator strings, no clients
greg = {n: P.parse_gpu_registry(open(os.path.join(FIX, "ioreg", n + ".plist"), "rb").read()) if MAC else None
        for n in ("accelerator", "hostile", "noclients")}
if MAC:
    acc = greg["accelerator"][0]
    check(acc["name"] == "Apple M3 Max" and acc["now"] == 38 and acc["clients"][4294971540] == (413, 125000000000) and
          acc["usage"], "gpu: the registry's property list: model, utilization, memory, GPU time per client")
    hos = greg["hostile"][0]["clients"]
    check(hos == {4294972000: (4242, 5000000), 4294972002: (77, 2500)},
          "gpu: a hostile creator string gives its pid and the real time, nothing else (%s)" % hos)
    check(greg["noclients"][0]["clients"] == {} and not greg["noclients"][0]["usage"], "gpu: a device without clients")
    sp = StubPlat()
    seq = [greg["accelerator"]]
    nxt = json.loads(json.dumps(greg["accelerator"], default=list))
    nxt[0]["clients"] = {int(k): tuple(v) for k, v in nxt[0]["clients"].items()}
    nxt[0]["clients"][4294971540] = (413, 125000000000 + 300000000)    # 0.3 s of GPU time in one second
    nxt[0]["clients"][4294971800] = (900, 100000000)                    # a new client, 0.1 s
    del nxt[0]["clients"][4294971700]                                   # a client that closed
    seq.append(nxt)
    sp.gpu_registry = lambda: seq.pop(0)
    sp.gpu_mem_limit_gb = lambda ram: (27.0, True)
    m = oomphd.Meter(sp)
    b0, _ = m.read({}, ram_gb=36)
    sp.up += 1.0
    b1, u1 = m.read({}, ram_gb=36)
    g0, g1 = b0["gpu"][0], b1["gpu"][0]
    check(g0["src"] == "ioreg" and g0["util"] == 38.0 and "active" not in g0 and g1["src"] == "clients" and
          g1["util"] == 40.0 and abs(u1[413]["gpu"] - 30.0) < 1e-6 and abs(u1[900]["gpu"] - 10.0) < 1e-6 and
          g1["mem_limit_gb"] == 27.0 and g1["mem_limit_est"] and g1["mem_gb"] == 0.92,
          "gpu: first the driver's instantaneous figure (ioreg), then busy time from the clients' GPU time (%s, %s)"
          % (g0.get("util"), g1.get("util")))
    sp.gpu_registry = lambda: None
    check("gpu" not in m.read({})[0], "gpu: a registry that cannot be read costs the block, nothing else")
    # the safety net: the clients' figure 30 points from the driver's for five minutes, and the device reads rung 3
    sp, n_calls = StubPlat(), [0]

    def drift():
        n_calls[0] += 1
        d = json.loads(json.dumps(greg["noclients"], default=list))
        d[0].update(now=0, usage=True, clients={1: (413, n_calls[0] * 3 * 10 ** 9)})  # 30 % of each 10 s
        return d
    sp.gpu_registry = drift
    m = oomphd.Meter(sp)
    srcs = []
    for _ in range(40):
        g = m.read({})[0]["gpu"][0]
        srcs.append(g.get("src"))
        sp.up += 10.0
    errs = [e for w, e in m.errors if w == "gpu"]
    check(srcs[1] == "clients" and srcs[30] == "clients" and srcs[32:] == ["ioreg"] * 8 and len(errs) == 1,
          "gpu: the clients' figure 30 points from the driver's for five minutes: that device reads the driver's "
          "figure from then on, said once (%s)" % "".join(x[0] for x in srcs))
    # what the system hands the root logger is read with a cap and a deadline
    t0 = time.time()
    big = P.run_capped([sys.executable, "-I", "-c", "import sys; sys.stdout.write('x' * 20000000)"], 8 << 20, 5)
    slow = P.run_capped(["/bin/sleep", "30"], 1 << 20, 1)
    check(big is None and slow is None and time.time() - t0 < 8,
          "a command that prints 20 MB or never ends costs its reading within the deadline (%.1f s)" % (time.time() - t0))
else:
    print("skip  the registry parser and the bounded reads are the Mac backend's")

# --- M2 (1.9.3): the GPU at full speed, from the IOReport helper as nobody; opt-in (roadmap 02 §4.2, §10.6)
A4 = [0.0, 338.0, 618.0, 796.0, 832.0, 924.0, 952.0, 1056.0, 1064.0, 1182.0, 1182.0, 1312.0, 1242.0, 1380.0]  # 02 A.4
U = 72000  # residency units of one part in a thousand of 3 s at 24 MHz


def gpuph(**res):
    """GPUPH's 16 states (OFF, P1 … P15) with residencies in thousandths of the interval."""
    return [[n, res.get(n, 0) * U] for n in ["OFF"] + ["P%d" % i for i in range(1, 16)]]


A15 = gpuph(OFF=501, P1=427, P2=30, P3=26, P5=16)  # the desktop of 02 A.3
DT = 1000 * U
util, active = oomphd.full_speed(A15, A4, DT)
check(abs(util - 14.37) < 0.01 and abs(active - 49.9) < 1e-9,
      "full speed: the residencies of A.3 weighed with the table of A.4 give the hand-computed 14.4 %% (busy %.1f %%; %.2f)"
      % (active, util))
lower_last = A4[:12] + [1380.0, 1242.0]
check(abs(oomphd.full_speed(gpuph(P1=1000), lower_last, DT)[0] - 338 / 1380 * 100) < 1e-9 and
      oomphd.full_speed(gpuph(OFF=1000), A4, DT) == (0.0, 0.0),
      "full speed: the table's maximum is full speed, not its last entry (it is not monotonic); an idle GPU reads 0")
for what, args in (("residency in P14, which has no frequency", (gpuph(OFF=900, P14=100), A4, DT)),
                   ("a renamed state", ([["OFF", 500 * U]] + [["GPU%d" % i, 0] for i in range(1, 15)] + [["P15", 500 * U]], A4, DT)),
                   ("a table of one frequency", (A15, [0.0, 338.0], DT)),
                   ("residencies that add up to half the interval", (A15, A4, 2 * DT)),
                   ("a negative residency", (gpuph(OFF=1001, P1=-1), A4, DT)),
                   ("a state with residency at 0 MHz", (gpuph(OFF=500, P2=500), [0.0, 338.0, 0.0, 796.0], DT)),
                   ("states that are not a list of pairs", ([["OFF", 1.5]], A4, DT)),
                   ("a table that is not one", (A15, ["338"] * 14, DT)),
                   ("a residency of 2^64", (gpuph(OFF=1000)[:1] + [["P1", 2 ** 64]], A4, DT)),
                   ("an interval of 2^64", (A15, A4, 2 ** 64))):
    r = oomphd.full_speed(*args)
    check(r[0] is None and isinstance(r[1], str), "full speed: %s falls back to busy time (%s)" % (what, r[1]))

# opt-in: off unless the root-owned config or OOMPH_IOREPORT says so; OOMPH_NO_IOREPORT wins
os.environ.pop("OOMPH_IOREPORT")
wanted = [oomph.ioreport_wanted(config=c) for c in ({}, {"ioreport": True}, {"ioreport": "yes"}, {"ioreport": 0},
                                                       {"ioreport": True, "no_ioreport": True})]
os.environ["OOMPH_IOREPORT"] = "1"
wanted.append(oomph.ioreport_wanted(config={}))
os.environ["OOMPH_NO_IOREPORT"] = "1"
wanted.append(oomph.ioreport_wanted(config={"ioreport": True}))
os.environ.pop("OOMPH_NO_IOREPORT")
os.environ["OOMPH_IOREPORT"] = "0"
wanted.append(oomph.ioreport_wanted(config={"ioreport": True}))
check(wanted == [False, True, True, False, False, True, False, False] and oomphd.full_speed_rung(P) is None and
      oomphd.full_speed_rung(StubPlat()) is None,
      "full speed is opt-in: only \"ioreport\": true in the config or OOMPH_IOREPORT=1 starts it; no_ioreport wins (%s)" % wanted)

# doctor: a designed state is a note, a broken one a warning; no "switch it on" where the figure cannot work
nfs = oomph._no_full_speed
dg = [oomph._doctor_gpu({"daemon": {"ioreport": st}}, "kick") for st in ("table", "unavailable", "missing", "shape")]
oomph._no_full_speed = lambda: True
no_table = oomph._doctor_gpu(None, "kick")
oomph._no_full_speed = lambda: False
table = oomph._doctor_gpu(None, "kick")
oomph._no_full_speed = nfs
check([d[1] for d in dg] == ["note", "note", "warn", "warn"] and "reinstall" in dg[2][2] and "60" in dg[3][2] and
      len(no_table) == 3 and "not available here" in no_table[2] and len(table) == 4 and "sudo" in table[3],
      "doctor: no table or channel is a note, a missing helper or bad readings a warning; the opt-in is offered only "
      "where the figure can work")

# the helper's protocol, with stand-ins for it: a good one, one that crashes four ways, one whose readings never fit
ird = tempfile.mkdtemp(prefix="oomph-ioreport-")
st_path = os.path.join(ird, "ioreport.json")
GOOD = json.dumps({"dt": DT, "hz": 24e6, "states": A15})


def stand_in(body):
    """A helper that answers each line of input with `body`, a Python expression for the line."""
    return [sys.executable, "-I", "-c", "import sys, time\nfor _ in sys.stdin:\n    sys.stdout.write(%s)\n"
            "    sys.stdout.flush()" % body]


fs = oomphd.FullSpeed(stand_in(repr(GOOD + "\n")), A4, st_path, (1000, "27.2 26B1"))
r = [fs.figure(None), fs.figure(None), fs.figure(3.0), fs.figure(9.0)]
check(r[0] is None and r[1] is None and r[2] is not None and abs(r[2][0] - util) < 1e-9 and r[3] is None and
      fs.bad == 0 and not fs.errors and fs.status() == "on",
      "helper: started at the first sample, asked every sample; a reading over another interval is dropped, not held "
      "against it (%s)" % r)
fs.close()
ident, crashes, t0 = (1000, "27.2 26B1"), [], time.time()
for what, cmd in (("exits", [sys.executable, "-I", "-c", "import sys; sys.exit(1)"]),
                  ("hangs", stand_in("time.sleep(30) or ''")),
                  ("prints garbage", stand_in(repr("{not json\n"))),
                  ("prints a 10 MB line", stand_in("'x' * 10000000 + '\\n'"))):
    fs = oomphd.FullSpeed(cmd, A4, st_path, ident)
    on = fs.status()
    fs.figure(None)
    time.sleep(0.2)
    got = fs.figure(3.0)
    saved = json.load(open(st_path))
    crashes.append((what, on, got, saved["crashes"], saved["off"], fs.status()))
    fs.close()
check([c[3] for c in crashes] == [1, 2, 3, 4] and all(c[1] == "on" and c[2] is None for c in crashes) and
      [c[5] for c in crashes] == ["on", "on", "on", "crashes"] and crashes[-1][4] == "crashes" and time.time() - t0 < 10,
      "helper: one that exits, hangs, prints garbage or a 10 MB line costs that sample; the count is kept in "
      "ioreport.json and the fourth crash switches it off (%s; %.1f s)" % ([c[:1] + c[3:] for c in crashes], time.time() - t0))
again = oomphd.FullSpeed(stand_in(repr(GOOD + "\n")), A4, st_path, ident)
reboot = oomphd.FullSpeed(stand_in(repr(GOOD + "\n")), A4, st_path, (2000, "27.2 26B1"))
update = oomphd.FullSpeed(stand_in(repr(GOOD + "\n")), A4, st_path, (1000, "27.3 26C1"))
check(again.status() == "crashes" and again.figure(None) is None and again.proc is None and reboot.status() == "on" and
      update.status() == "on", "helper: off for the rest of the boot across restarts of the logger; a new boot or macOS "
      "update starts the count afresh")
os.remove(st_path)
fs = oomphd.FullSpeed(stand_in(repr(json.dumps({"dt": DT, "hz": 24e6, "states": gpuph(OFF=900, P14=100)}) + "\n")),
                      A4, st_path, ident)
fs.figure(None)
r = [fs.figure(3.0) for _ in range(oomphd.IOREPORT_BAD_OFF)]
check(not any(r) and fs.status() == "shape" and json.load(open(st_path))["off"] == "shape" and fs.proc is None and
      len(fs.errors) == 1 and "P14" in fs.errors[0],
      "helper: %d readings in a row that do not fit the table switch it off until the next boot, said once"
      % oomphd.IOREPORT_BAD_OFF)
os.remove(st_path)
fs = oomphd.FullSpeed(stand_in(repr('{"error": "no channel"}\n')), A4, st_path, ident)
fs.figure(None)
r = fs.figure(3.0)
check(r is None and fs.status() == "unavailable" and fs.proc is None and not fs.errors and len(fs.notes) == 1 and
      not os.path.exists(st_path), "helper: a Mac without the GPU's performance states reads busy time for the run, "
      "a note and no error (no alarm at every start of the logger)")
fs = oomphd.FullSpeed(stand_in(repr(GOOD + "\n")), [0.0, 338.0], st_path, ident)
check(fs.status() == "table" and fs.figure(None) is None and fs.proc is None and not fs.errors and len(fs.notes) == 1,
      "helper: not started without a usable table, a note and no error")
huge = oomphd.FullSpeed(stand_in(repr(json.dumps({"dt": 2 ** 64, "hz": 24e6, "states": A15}) + "\n")), A4, st_path, ident)
huge.figure(None)
r = [huge.figure(3.0), huge.figure(3.0)]
huge.close()
check(r == [None, None] and huge.bad == 2 and huge.status() == "on" and not os.path.exists(st_path),
      "helper: an interval of 2^64 is a bad reading, not an exception that escapes the sample (%s)" % huge.why)
fs = oomphd.FullSpeed(stand_in("time.sleep(30) or ''"), A4, st_path, ident)
fs.figure(None)
fs.close(final=True)  # the logger's stop, while a reading would be pending
fs._crash("ended (exit status -9)")  # what a reading the stop interrupted would make of it
check(fs.figure(3.0) is None and fs.proc is None and not os.path.exists(st_path) and not fs.errors,
      "helper: after the logger's stop nothing is asked, and nothing counts as a crash")

# the sample: util at full speed, active busy time, src ioreport; a process's GPU is its share of busy time × util
if MAC:
    class Fig:
        def __init__(self):
            self.asked = []

        def figure(self, dt_s):
            self.asked.append(dt_s)
            return (14.4, 50.0) if dt_s else None
    sp, fig = StubPlat(), Fig()
    seq = [greg["accelerator"], nxt]
    sp.gpu_registry = lambda: seq.pop(0)
    sp.gpu_mem_limit_gb = lambda ram: (27.0, True)
    m = oomphd.Meter(sp, fig)
    b0, _ = m.read({}, ram_gb=36)
    sp.up += 1.0
    b1, u1 = m.read({}, ram_gb=36)
    g0, g1 = b0["gpu"][0], b1["gpu"][0]
    check(fig.asked == [None, 1.0] and g0["src"] == "ioreg" and g1["src"] == "ioreport" and g1["util"] == 14.4 and
          g1["active"] == 50.0 and abs(u1[413]["gpu"] - 10.8) < 1e-6 and abs(u1[900]["gpu"] - 3.6) < 1e-6,
          "sample: with the helper the GPU reads %.1f %% at full speed and %.0f %% busy; WindowServer's 0.3 s of 0.4 s "
          "is 10.8 %% of the GPU (%s)" % (g1["util"], g1.get("active", -1), {p: round(x["gpu"], 2) for p, x in u1.items()}))

    # the real helper, where this Mac has the channel: its readings fit, it does not grow, and this process never
    # loads the private library (CI's runners are VMs: the channel is usually missing there)
    def images():
        dyld = __import__("ctypes").CDLL("/usr/lib/libSystem.B.dylib")
        dyld._dyld_get_image_name.restype = __import__("ctypes").c_char_p
        return [dyld._dyld_get_image_name(i) or b"" for i in range(dyld._dyld_image_count())]
    if os.path.exists(st_path):
        os.remove(st_path)
    fs = oomphd.FullSpeed(P.ioreport_helper(), P.gpu_dvfs_mhz(), st_path, P.boot_id())
    fs.figure(None)
    time.sleep(0.6)
    t1 = P.uptime_s()
    fs.figure(None)
    time.sleep(0.6)
    real = fs.figure(P.uptime_s() - t1)
    if fs.status() in ("unavailable", "table"):
        print("skip  the real IOReport helper: this Mac has no %s" % (
            "GPU performance-state channel" if fs.status() == "unavailable" else "usable GPU frequency table"))
    else:
        check(real is not None and 0 <= real[0] <= real[1] <= 100 and fs.bad == 0 and not fs.errors,
              "the real helper: a reading fits this Mac's table (%s %% at full speed, %s %% busy; table %s MHz)"
              % (real and round(real[0], 1), real and round(real[1], 1), P.gpu_dvfs_mhz()))
    fs.close()
    hp = subprocess.Popen(P.ioreport_helper(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def rss_kb():
        return int(subprocess.run(["/bin/ps", "-o", "rss=", "-p", str(hp.pid)], capture_output=True, text=True,
                                  timeout=10).stdout.strip() or 0)
    def answer(deadline=2.0):
        """One line of the helper's within `deadline` seconds, or b"" (a helper that hangs costs the test, not CI)."""
        buf, fd, end = b"", hp.stdout.fileno(), time.monotonic() + deadline
        while not buf.endswith(b"\n") and len(buf) < 1 << 16:
            left = end - time.monotonic()
            if left <= 0 or not select.select([fd], [], [], left)[0]:
                return b""
            b = os.read(fd, 1 << 16)  # one question, one line: nothing of the next answer can follow it
            if not b:
                return b""
            buf += b
        return buf
    try:
        lines, rss = [], [0, 0]
        for i in range(1200):
            hp.stdin.write(b"\n")
            hp.stdin.flush()
            lines.append(answer())
            if not lines[-1] or b"no channel" in lines[0]:
                break
            if i in (199, 1199):
                rss[i > 199] = rss_kb()
    finally:
        try:
            hp.stdin.close()
            hp.wait(10)
        except (OSError, subprocess.TimeoutExpired):
            hp.kill()
            hp.wait(10)
        hp.stdout.close()
    if b"no channel" not in lines[0]:
        check(len(lines) == 1200 and all(x.endswith(b"\n") and b'"states"' in x for x in lines) and
              rss[1] - rss[0] < 2048 and rss[1] < 40 << 10,
              "the real helper: 1,000 readings leave its memory unchanged (%d -> %d KB; without CFRelease it would grow "
              "by 6 MB)" % tuple(rss))
    check(not any(b"IOReport" in x for x in images()), "this process, the logger's, never loads libIOReport")
shutil.rmtree(ird, ignore_errors=True)

# disks: the class table on captured and made-up mount records; diskutil only for /dev/disk names
vfix = json.load(open(os.path.join(FIX, "volumes.json")))["mounts"]
SSD = next(i for i, c in enumerate(vfix) if "A.30" in c["case"])
WORK = next(i for i, c in enumerate(vfix) if "second internal" in c["case"])
if MAC:
    wrong = []
    for c in vfix:
        if c["want"][0] == "watched":
            continue
        got = P.classify_volume(c["rec"], c.get("facts"))
        if list(got[:2]) != c["want"]:
            wrong.append("%s: %s" % (c["case"], got))
    check(not wrong and len(vfix) >= 12, "volumes: %d mount records classified as 02 §4.4 says, the external SSD of A.30 "
          "listed%s" % (len(vfix), ": " + "; ".join(wrong) if wrong else ""))
    recs = [c["rec"] for c in vfix]
    facts = {P.mount_key(c["rec"]): c["facts"] for c in vfix if "facts" in c}
    pools, rows = P.disk_pools(recs, facts)
    ids = [p["id"] for p in pools]
    check(ids == ["data", "vol:5E0C61B2-0F4A-4D1B-9C57-3A1D2B7E9F10", "vol:55555555-6666-4777-8888-999999999999"] and
          pools[0]["watch"] and pools[0]["level"] == "ok" and not pools[1]["watch"] and pools[1]["kind"] == "external" and
          "low_gb" not in pools[1], "volumes: the system's pool (VM volume and all) is watched, the SSD and a second "
          "internal disk are listed, by UUID; nothing else is sampled (%s)" % ids)
    same = dict(vfix[SSD]["rec"], mount="/Volumes/Scratch 1", dev=16777999)
    twin = dict(vfix[SSD]["rec"], mount="/Volumes/Scratch 2", dev=16777998)
    twin["from"] = "/dev/disk40s1"
    f2 = {P.mount_key(same): vfix[SSD]["facts"], P.mount_key(twin): dict(vfix[SSD]["facts"], pool_uuid="77777777-0000-4000-8000-000000000000")}
    p2 = P.disk_pools([vfix[0]["rec"], same, twin], f2)[0]
    check([p["id"] for p in p2[1:]] == ["vol:5E0C61B2-0F4A-4D1B-9C57-3A1D2B7E9F10", "vol:77777777-0000-4000-8000-000000000000"],
          "volumes: the same volume at a new mount point is the same pool; another of the same name is another")
    weak = P.disk_pools([vfix[0]["rec"], vfix[WORK]["rec"]], {P.mount_key(vfix[WORK]["rec"]): dict(vfix[WORK]["facts"], pool_uuid=None)})[0]
    check(weak[1]["id"] == "mnt:/Volumes/Work" and weak[1].get("weak"), "volumes: a volume without a UUID is listed by "
          "its mount point, weakly")
    low = P.disk_pools([dict(vfix[0]["rec"], free_gb=4.0)], {})[0][0]
    check(low["level"] == "critical" and P.disk_pools([dict(vfix[0]["rec"], free_gb=19.0)], {})[0][0]["level"] == "low",
          "volumes: the system's pool is low under 20 GB, critical under 5")
    sraw = json.load(open(os.path.join(FIX, "volumes.json")))["statfs"]["records"]
    kept = P.mount_records(sraw)
    bad_root = [dict(r, free=r["size"] + 1) if r["mount"] == "/" else r for r in sraw]
    bad_data = [dict(r, size=1 << 61) if r["mount"] == "/System/Volumes/Data" else r for r in sraw]
    check(kept is not None and [m["mount"] for m in kept] == ["/", "/System/Volumes/Data", "/Volumes/Scratch"] and
          P.mount_records(bad_root) is None and P.mount_records(bad_data) is None and
          P.mount_records([r for r in sraw if r["mount"] != "/"]) is None,
          "volumes: a FUSE mount answering absurd sizes is left out, not the whole table; an absurd or missing "
          "/ or Data volume refuses it")

    class VolPlat:
        asked = []
        mounts = staticmethod(lambda: [c["rec"] for c in vfix])
        mount_key, disk_pools = staticmethod(P.mount_key), staticmethod(P.disk_pools)

        @staticmethod
        def volume_facts(dev):
            VolPlat.asked.append(dev)
            return next((c.get("facts") for c in vfix if c["rec"]["from"] == dev), None)
    vp, vr = oomphd.Volumes(VolPlat, wait=True).read()
    check(all(re.fullmatch(r"/dev/disk\d+(s\d+)*", d) for d in VolPlat.asked) and "-rf" not in VolPlat.asked and
          "/dev/disk3s5" not in VolPlat.asked and "/dev/disk9s3" not in VolPlat.asked and
          [p["id"] for p in vp] == ids, "volumes: diskutil is asked about disks only, never about the system's pool, a "
          "hidden volume or a FUSE mount's 'device' (%s)" % VolPlat.asked)
    n_ask, VolPlat.asked = len(VolPlat.asked), []
    bg = oomphd.Volumes(VolPlat)
    first = [p["id"] for p in bg.read()[0]]
    deadline = time.time() + 10
    while len(VolPlat.asked) < n_ask and time.time() < deadline:
        time.sleep(0.05)
    time.sleep(0.2)
    later = [p["id"] for p in bg.read()[0]]
    check(first == ["data"] and later == ids, "volumes: the logger's first sample lists the system's pool only; the "
          "others follow once diskutil has answered, off the sampling path")
else:
    print("skip  the volume class table is the Mac backend's")

# the real thing, on this Mac: two samples of the logger
if MAC:
    dm = oomphd.Daemon()
    s1 = dm.sample()
    time.sleep(1.0)
    s2 = dm.sample()
    c2, n_ = s2.get("cpu") or {}, os.cpu_count()
    check(s1.get("cpu", {}).get("n") == n_ and "busy" not in s1.get("cpu", {}) and 0 <= c2.get("busy", -1) <= n_ and
          abs(c2.get("user", 0) + c2.get("sys", 0) - c2.get("busy", 0)) < 0.02 and c2.get("therm") in (0, 1, 2, 3, 4),
          "sample: cpu %s of %s cores busy, thermal %s; the first sample has no rates" % (c2.get("busy"), n_, c2.get("therm")))
    dk = {d["id"]: d for d in s2.get("disks") or []}
    data = dk.get("data") or {}
    check(0 < data.get("free_gb", 0) <= data.get("total_gb", 0) and {"home", "tmp"} <= set(data.get("roles") or []) and
          data.get("watch"), "sample: disks has the system's pool, %.0f of %.0f GB free, roles %s"
          % (data.get("free_gb", 0), data.get("total_gb", 0), data.get("roles")))
    gl = s2.get("gpu")
    check(isinstance(gl, list) and all(0 <= g.get("util", 0) <= 100 and g.get("src") in ("ioreport", "clients", "ioreg")
                                       for g in gl), "sample: gpu %s" % ([(g.get("name"), g.get("util"), g.get("src"))
                                                                          for g in gl] if gl else gl))
    check(isinstance(s2.get("io"), dict) and s2["io"]["w_mb_s"] >= 0 and
          all(isinstance(x.get("cpu"), float) for x in s2.get("top_cpu") or []) and len(s2.get("top_cpu") or []) <= 8,
          "sample: io %s, top_cpu %d entries" % (s2.get("io"), len(s2.get("top_cpu") or [])))
    sz = len(json.dumps(s2, separators=(",", ":")))
    print("      a sample of this run: %d bytes (%s)" % (sz, ", ".join("%s %d" % (k, len(json.dumps(s2[k], separators=(",", ":"))))
                                                                    for k in RES_KEYS if k in s2)))
    # the time base: a busy child's CPU as rusage reads it equals what the child counted itself
    bc = subprocess.Popen([sys.executable, "-I", "-c", "import time, sys\nt = time.process_time()\n"
                           "while time.process_time() - t < 0.8: pass\nprint(time.process_time(), flush=True)\n"
                           "time.sleep(5)"], stdout=subprocess.PIPE, text=True)
    own = float(bc.stdout.readline())
    seen = P.collect_procs().get(bc.pid, {}).get("cpu_s", 0)
    bc.kill()
    bc.wait()
    check(abs(seen - own) <= 0.1 * own, "cpu: rusage's CPU time in seconds (the Mach time base applied): %.2f s, the child "
          "counted %.2f s" % (seen, own))
    # native memory given back: 2,000 rounds of every native reading in a child, its peak size grows < 1 MB
    soak = r"""
import os, resource, sys
sys.path.insert(0, sys.argv[1])
import oomph_darwin as P
def once():
    P.cpu_ticks(); P.thermal_level(); P.mounts(); P._rusage(os.getpid()); P.list_pids()
for _ in range(300): once()
a = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
for _ in range(2000): once()
print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - a)
"""
    r = subprocess.run([sys.executable, "-I", "-B", "-c", soak, os.path.join(ROOT, "daemon")], capture_output=True,
                       text=True, timeout=60)
    grew = int(r.stdout.strip() or -1) if r.returncode == 0 else -1
    check(0 <= grew < 1 << 20, "soak: 2,000 rounds of ticks, thermal level, mounts, rusage and the pid list grow the "
          "process by %d KB" % (grew // 1024))
    # the ledger's child is told what it needs of a process, not the new counters
    check(set(oomph.PROC_KEYS) >= {"pid", "ppid", "start", "fp", "name"} and "cpu_s" not in oomph.PROC_KEYS,
          "the ledger child's process table: %s" % ", ".join(oomph.PROC_KEYS))
else:
    print("skip  sampling CPU, GPU and disks needs macOS")

# the wire: the chart's numbers travel slim, names stay home; the full current sample carries the GPU's name. The
# disks stay home in 1.9.1: every mirror up to 1.9.0 refuses a row whose *_gb is above 16 x RAM, as a disk's size is
sl = oomph.slim_sample(dict(cur, **RES_EXAMPLE))
fu = oomph.full_sample(dict(cur, **RES_EXAMPLE))
check(sl["cpu"].get("busy") == 9.12 and "load" not in sl["cpu"] and sl["gpu"][0] == {
      "id": "gpu0", "util": 47.0, "active": 47.0, "now": 52, "src": "clients", "mem_gb": 3.99, "mem_alloc_gb": 11.68} and
      not {"top_cpu", "top_gpu", "top_io", "disks"} & set(sl), "slim samples: the chart's CPU, GPU and I/O numbers; no "
      "names, no disks, no per-process lists (%d bytes more)" % (len(json.dumps(sl)) - len(json.dumps(oomph.slim_sample(cur)))))
check("disks" not in fu and fu["top_cpu"][0]["cpu"] == 5.2 and fu["gpu"][0]["name"] == "Apple M3 Max",
      "full sample: the GPU's name and the top lists; no disks")
import oomph_sync  # noqa: E402
eight = dict(cur, ram_gb=8.0, disk_free_gb=900.0, **dict(RES_EXAMPLE, disks=[dict(RES_EXAMPLE["disks"][0], total_gb=1000.0,
                                                                                  free_gb=900.0)]))
ing = oomph_sync.Ingest({"now": time.time(), "ram_gb": 8.0})
ok_rows = [ing.row(json.dumps(x), "samples") for x in (oomph.slim_sample(eight), oomph.full_sample(eight), eight)]
check(all(ok_rows) and ing.dropped["samples"] == 0 and not ing.row(json.dumps(dict(eight, app_gb=300.0)), "samples"),
      "a mirror lets in an 8 GB machine with 900 GB free on a 1 TB disk (slim, full, whole), and still refuses 300 GB "
      "of app memory there")
def _walk_gb(x, top):
    """gb_ok as a mirror up to 1.9.0 has it: every *_gb, nested ones too, at most 16 x RAM."""
    if isinstance(x, dict):
        return all((not (isinstance(k, str) and k.endswith("_gb")) or v is None or 0 <= v <= top) and _walk_gb(v, top)
                   for k, v in x.items())
    return all(_walk_gb(v, top) for v in x) if isinstance(x, list) else True


check(_walk_gb(oomph.slim_sample(dict(eight, disk_free_gb=60.0)), 128.0) and
      _walk_gb(oomph.full_sample(dict(eight, disk_free_gb=60.0)), 128.0) and not _walk_gb(eight, 128.0), "what a 1.9.1 logger sends passes a 1.9.0 mirror's check; the disks block would not")

# the CLI on a fixed sample: check, status, resources, ps, volumes
res_s = dict(fixed, t=time.time(), iso="2026-11-22T10:00:00+01:00", source="daemon", **RES_EXAMPLE)
oomph._sample_override = lambda: dict(res_s)
real_measure = oomphd.measure
oomphd.measure = lambda *a, **k: (_ for _ in ()).throw(AssertionError("a plain check measured"))
buf = io.StringIO()
with redirect_stdout(buf):
    rc = oomph.main(["check"])
out = " ".join(buf.getvalue().split())
check(rc == 0 and "9.1 of 14 cores busy (P 7.9 · E 1.2) · thermal heavy" in out and
      "busy 47 % of the time (speed not reported) · 4.0 of 27 GB GPU memory" in out and "Data 63 GB free of 995" in out and
      "Scratch 912 GB free of 1,863 · not watched" in out and out.index("cpu") < out.index("advice:"),
      "oomph check: a line for CPU, GPU and each disk before the advice; the exit code as before")
oomph._sample_override = lambda: dict(fixed, source="daemon")
buf = io.StringIO()
with redirect_stdout(buf):
    oomph.main(["check"])
check("not recorded by the logger" in buf.getvalue(), "oomph check: a logger older than 1.9.1 is named as the reason")
oomph._sample_override = lambda: dict(fixed, source="live")
buf = io.StringIO()
with redirect_stdout(buf):
    oomph.main(["check"])
check("not measured (logging is off; `oomph check --measure`" in buf.getvalue(), "oomph check without the logger: CPU and "
      "GPU not measured, and it does not wait")
oomphd.measure = real_measure
# pins: a listed volume this user pinned counts in check and hook; one nobody pinned never does
low_s = dict(res_s, disks=[RES_EXAMPLE["disks"][0], dict(RES_EXAMPLE["disks"][1], free_gb=10.0)])
oomph._sample_override = lambda: dict(low_s)
v_unpinned = oomph.checked_verdict()
oomph.save_user_settings({"volumes": {"pinned": ["vol:5E0C61B2-0F4A-4D1B-9C57-3A1D2B7E9F10"]}, "other": 1})
v_pinned = oomph.checked_verdict()
mode = os.stat(oomph.settings_path()).st_mode & 0o777
check(v_unpinned["level"] == "ok" and v_pinned["level"] == "tight" and "on Scratch (pinned)" in " ".join(v_pinned["reasons"])
      and mode == 0o600 and "disks" in v_pinned["resources"], "pins: 10 GB free on a pinned 1.8 TB disk is low for this "
      "user (floors 20 and 5 GB there), and nothing when not pinned (%s / %s)" % (v_unpinned["level"], v_pinned["level"]))
check(v_pinned["advice"].startswith("Disk space is short on Scratch") and "parallelism" not in v_pinned["advice"] and
      not v_pinned.get("notes"), "pins: a pinned low disk gets disk advice, not memory advice")
dk_p = {d["id"]: d for d in v_pinned["resources"]["disks"]}
dk_mcp = {d["id"]: d for d in oomph._mcp_call("memory_check", {})["resources"]["disks"]}
pin_id = "vol:5E0C61B2-0F4A-4D1B-9C57-3A1D2B7E9F10"
check(all(d[pin_id].get("pinned") is True and d[pin_id].get("low_gb") == 20.0 and d[pin_id].get("crit_gb") == 5.0 and
          d[pin_id].get("level") == "low" and d["data"].get("pinned") is False for d in (dk_p, dk_mcp)) and
      all(x.get("pinned") is False and "low_gb" not in x for x in v_unpinned["resources"]["disks"] if x["id"] == pin_id),
      "check --json and MCP memory_check: each disk says whether it is pinned, a pinned pool carries its floors and "
      "level, as `resources --json` (%s)" % {k: (v.get("pinned"), v.get("low_gb")) for k, v in dk_p.items()})
oomph._sample_override = lambda: dict(low_s, pressure=2)
v_both = oomph.checked_verdict()
oomph._sample_override = lambda: dict(res_s, disks=RES_EXAMPLE["disks"][:1])
v_gone = oomph.checked_verdict()
line_gone = oomph.verdict_line(v_gone, width=200)
oomph._sample_override = lambda: dict(low_s)
check("parallelism" in v_both["advice"] and "Disk space is short on Scratch" in v_both["advice"] and
      v_gone["level"] == "ok" and "not checked" in " ".join(v_gone.get("notes") or []) and "note: pinned vol:5E0C" in
      line_gone, "pins: memory and disk advice when both are short; a pin the sample has no pool for is said to be "
      "unchecked")
open(oomph.settings_path(), "w").write('{"volumes": {"pinned": "vol:x", "hidden": [1, null, "../x"]}}')
check(oomph.volume_prefs() == (set(), set()) and oomph.checked_verdict()["level"] == "ok",
      "pins: a damaged settings file reads as none")
os.unlink(oomph.settings_path())
# status on a sample with the new blocks
os.makedirs(os.path.join(LOG, "m1"), exist_ok=True)
saved_log = oomph.LOG_DIR
oomph.LOG_DIR = os.path.join(LOG, "m1")
json.dump(dict(res_s, daemon={"pid": 1, "version": "1.9.1", "interval": 30, "root": True}, away={}, groups=[], claude=[],
               free_pct=60, cached_gb=3.0, free_gb=4.0, swapfiles=0),
          open(os.path.join(oomph.LOG_DIR, "current.json"), "w"))
buf = io.StringIO()
with redirect_stdout(buf):
    rc = oomph.main(["status"])
out = " ".join(buf.getvalue().split())
check(rc == 0 and "cpu 9.1 of 14 cores busy" in out and "io read 3.1 MB/s · write 12.4 MB/s" in out and
      "busiest (cores):" in out and "cargo (iTerm2)" in out and "writing to disk (MB/s):" in out,
      "oomph status: CPU, GPU, disk and I/O lines and the busiest processes per resource")
for argv, want in ((["ps", "--json"], ("cpu", 5.2)), (["ps", "--gpu", "--json"], ("gpu", 9.1)),
                   (["ps", "--io", "--json", "-n", "1"], ("w", 18.3))):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = oomph.main(argv)
    d = json.loads(buf.getvalue())
    check(rc == 0 and d["resource"] == want[0] and d["rows"][0][want[0]] == want[1], "oomph %s: from the logger's sample"
          % " ".join(argv))
json.dump(dict({k: v for k, v in res_s.items() if k not in ("top_gpu", "top_io")}, away={}, groups=[], claude=[],
               daemon={"pid": 1, "version": "1.9.1", "interval": 30, "root": True}, free_pct=60, cached_gb=3.0, free_gb=4.0,
               swapfiles=0),
          open(os.path.join(oomph.LOG_DIR, "current.json"), "w"))
oomphd.measure = lambda *a, **k: (_ for _ in ()).throw(AssertionError("ps measured against a current logger"))
buf = io.StringIO()
with redirect_stdout(buf):
    rc = oomph.main(["ps", "--gpu"])
oomphd.measure = real_measure
check(rc == 0 and "nothing measurable right now" in buf.getvalue() and "older" not in buf.getvalue(),
      "oomph ps --gpu: a 1.9.1 logger with no GPU clients means nothing measurable, not an old logger")
nocpu = {k: v for k, v in res_s.items() if k not in ("cpu", "disks")}
lines_new = dict(oomph.resource_lines(dict(nocpu, daemon={"version": "1.9.1"})))
lines_old = dict(oomph.resource_lines(dict(nocpu, gpu=None, daemon={"version": "1.9.0"})))
check(lines_new["cpu"] == oomph.NOT_READ and lines_old["cpu"] == oomph.NOT_LOGGED and
      oomph.logger_measures({"cpu": {}}) and not oomph.logger_measures({"daemon": {"version": "1.10"}}) and
      oomph.logger_measures({"daemon": {"version": "1.10.0"}}), "a 1.9.1 sample without its cpu block is not "
      "blamed on an old logger; the version decides when no block is there")
with redirect_stderr(io.StringIO()):
    check(oomph.main(["ps", "--cpu", "--gpu"]) == 2 and oomph.main(["ps", "-n", "0"]) == 2 and oomph.main(["ps", "--x"]) == 2,
          "oomph ps: one resource, 1 to 100 rows, no unknown option")
buf = io.StringIO()
with redirect_stdout(buf):
    rc = oomph.main(["resources", "--json"])
d = json.loads(buf.getvalue())
check(rc == 0 and d["reservable"] == ["memory"] and d["memory"]["reservable"] and d["cpu"]["n"] == 14 and
      not d["cpu"]["reservable"] and d["gpu"][0]["name"] == "Apple M3 Max" and not d["gpu"][0]["reservable"] and
      [x["id"] for x in d["disks"]] == ["data", "vol:5E0C61B2-0F4A-4D1B-9C57-3A1D2B7E9F10"] and d["disks"][0]["watched"],
      "oomph resources --json: memory reservable; cores, GPU and disks listed, not yet reservable")
buf = io.StringIO()
with redirect_stdout(buf):
    rc = oomph.main(["resources"])
check(rc == 0 and "not reservable yet" in buf.getvalue() and "Only memory can be reserved" in buf.getvalue(),
      "oomph resources: says what can be reserved")
oomph.LOG_DIR = saved_log
oomph._sample_override = None
if MAC:
    here = os.stat(LOG).st_dev & 0xFFFFFFFF

    class PinPlat:
        @staticmethod
        def mounts():
            return [dict(vfix[0]["rec"], dev=1), dict(vfix[SSD]["rec"], dev=here)]
        mount_key, disk_pools = staticmethod(P.mount_key), staticmethod(P.disk_pools)
        volume_facts = staticmethod(lambda dev: vfix[SSD]["facts"])
    real_plat = oomph._plat
    import types
    oomph._plat = types.SimpleNamespace(**dict({k: getattr(real_plat, k) for k in dir(real_plat) if not k.startswith("__")},
                                               **{k: getattr(PinPlat, k) for k in ("mounts", "mount_key", "disk_pools",
                                                                                   "volume_facts")}))
    try:
        outs = []
        for argv in (["volumes", "watch", LOG], ["volumes", "--json"], ["volumes", "hide", LOG], ["volumes"],
                     ["volumes", "--all", "--json"], ["volumes", "unwatch", LOG], ["volumes", "unhide", LOG]):
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                outs.append((oomph.main(argv), buf.getvalue()))
        pinned_after = oomph.volume_prefs()
        lst = json.loads(outs[1][1])
        allv = json.loads(outs[4][1])
        check(outs[0][0] == 0 and "pinned" in outs[0][1] and any(e.get("pinned") for e in lst) and outs[2][0] == 0 and
              "Scratch" not in outs[3][1] and any(e.get("hidden") for e in allv) and outs[5][0] == outs[6][0] == 0 and
              pinned_after == (set(), set()), "oomph volumes watch / hide / unwatch / unhide: per user, by pool id")
        with redirect_stderr(io.StringIO()):
            check(oomph.main(["volumes", "watch", "/nonexistent/x"]) == 1 and oomph.main(["volumes", "watch"]) == 2,
                  "oomph volumes watch: a path on no recorded volume is refused")
    finally:
        oomph._plat = real_plat
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = oomph.main(["volumes", "--all", "--json"])
    vl = json.loads(buf.getvalue())
    check(rc == 0 and any(e.get("id") == "data" and e["class"] == "watched" for e in vl) and
          all(e["class"] in ("watched", "listed", "ignored") and e["why"] for e in vl),
          "oomph volumes --all on this Mac: %s" % ", ".join("%s %s" % (e["name"], e["class"]) for e in vl
                                                            if e["class"] != "ignored"))
else:
    print("skip  oomph volumes reads the Mac's mount table")

# --- M3 (1.9.5): events, incident fields and report panels for the other resources (roadmap 02 §5.3)
dm = oomphd.Daemon()
ev3, notes3 = [], []
dm.event = lambda kind, **kw: ev3.append(dict(kw, kind=kind))
dm.notify = lambda title, msg, **kw: notes3.append((title, msg))
dm.started -= 1000
t3 = time.time()
DATA = {"id": "data", "name": "Data", "mount": "/System/Volumes/Data", "free_gb": 60.0, "watch": True, "low_gb": 20,
        "crit_gb": 5, "level": "ok"}
EXT = {"id": "vol:5E0C61B2-0F4A-4D1B-9C57-3A1D2B7E9F10", "name": "Scratch", "mount": "/Volumes/Scratch", "free_gb": 900.0,
       "watch": False}


def s3(t, busy=2.0, therm=0, pools=(DATA,), **kw):
    x = dict(t=t, iso=oomphd.now_iso(t), pressure=1, swap_used_gb=0.0, disk_free_gb=pools[0]["free_gb"] if pools else 60.0,
             ram_gb=36.0, unowned_gb=1.0, compressor_logical_gb=1.0, away={"idle_s": 0}, os="macos",
             cpu={"n": 14, "busy": busy, "therm": therm},
             top_cpu=[{"pid": 1, "name": "cargo", "cpu": 6.0}, {"pid": 2, "name": "cargo", "cpu": 3.0}],
             top_io=[{"pid": 3, "name": "dd", "w": 900.0}], disks=[dict(p) for p in pools])
    x.update(kw)
    return x


def kinds3(*k):
    return [e for e in ev3 if e["kind"] in k]


for i, th in enumerate([0, 2, 3, 2, 2, 2, 2, 2]):      # a change, then two more within the minute: batched
    dm.evaluate(s3(t3 + 30 * i, therm=th))
th_ev = kinds3("thermal")
check(len(th_ev) == 2 and (th_ev[0]["old"], th_ev[0]["new"]) == (0, 2) and th_ev[1].get("flips") == 2 and
      th_ev[1]["new"] == 2, "events: the thermal level, a change at once and the flips after it in one event (%s)"
      % [(e["old"], e["new"], e.get("flips")) for e in th_ev])
for i in range(25):                                   # 12.5 minutes at 13 of 14 cores, a pause, then again within the hour
    dm.evaluate(s3(t3 + 600 + 30 * i, busy=13.0))
dm.evaluate(s3(t3 + 600 + 30 * 25, busy=2.0))
for i in range(25):
    dm.evaluate(s3(t3 + 1500 + 30 * i, busy=13.5))
sat = kinds3("cpu_saturated", "cpu_saturated_cleared")
check([e["kind"] for e in sat] == ["cpu_saturated", "cpu_saturated_cleared"] and sat[0]["minutes"] == 10 and
      sat[0]["top"] == {"cargo": 9.0} and sat[0]["n"] == 14, "events: cores saturated after ten minutes at 90 %%, cleared "
      "below 75 %%, and not again within the hour (%s)" % [(e["kind"], e.get("minutes"), e.get("top")) for e in sat])
dz = oomphd.Daemon()
ev_z = []
dz.event = lambda kind, **kw: ev_z.append(dict(kw, kind=kind))
dz.notify = lambda *a, **kw: None
for i in range(9):                                    # 4.5 minutes busy, a sleep of eight hours, busy again
    dz.evaluate(s3(t3 + 30 * i, busy=13.3))
dz.evaluate(dict(s3(t3 + 8 * 3600, busy=13.3), cpu={"n": 14, "therm": 0}))     # (no rates after the gap)
for i in range(1, 12):
    dz.evaluate(s3(t3 + 8 * 3600 + 30 * i, busy=13.3))
sat_z = [(e["kind"], e.get("minutes")) for e in ev_z if e["kind"].startswith("cpu_sat")]
for i in range(22):                                   # saturated for real, then the lid closes: over where last seen
    dz.evaluate(s3(t3 + 9 * 3600 + 30 * i, busy=13.3))
dz.evaluate(s3(t3 + 12 * 3600, busy=13.3))
sat_z2 = [(e["kind"], e.get("minutes"), e.get("gap")) for e in ev_z if e["kind"].startswith("cpu_sat")]
check(sat_z == [] and sat_z2[0] == ("cpu_saturated", 10, None) and sat_z2[1:] == [("cpu_saturated_cleared", 10, 10170)],
      "events: a sleep starts the saturation clock again and ends an episode where it was last seen (%s, %s)"
      % (sat_z, sat_z2))
del ev3[:]
dm.prev_pools = None
for i in range(8):                                    # 2.5 GB less every 30 s: full in minutes
    dm.evaluate(s3(t3 + 3000 + 30 * i, pools=(dict(DATA, free_gb=40.0 - 2.5 * i),)))
fill = kinds3("disk_filling")
hot_filling = dm.hot
dm.evaluate(s3(t3 + 3300, pools=(dict(DATA, free_gb=22.0),)))
dm.evaluate(s3(t3 + 3600, pools=(dict(DATA, free_gb=22.0),)))
check(len(fill) == 1 and fill[0]["pool"] == "data" and fill[0]["rate_gb_min"] == 5.0 and fill[0]["top"] == {"dd": 900.0}
      and hot_filling and not dm.hot and sum(1 for n in notes3 if n[0] == "Disk filling up") == 1,
      "events: a watched disk filling (5 GB a minute, full in minutes): one event with the writers, one notification, "
      "hot sampling while it fills (%s)" % [(e["rate_gb_min"], e["eta_min"]) for e in fill])
del ev3[:], notes3[:]
low_ext = dict(EXT, watch=True, low_gb=20, crit_gb=5, level="low", free_gb=12.0)
for i in range(3):
    dm.evaluate(s3(t3 + 4000 + 30 * i, pools=(dict(DATA, free_gb=15.0, level="low"), low_ext)))
low = kinds3("disk_low")
check(len(low) == 2 and {e["pool"] for e in low} == {"data", EXT["id"]} and
      next(e for e in low if e["pool"] == "data").get("disk_free_gb") == 15.0 and
      [n[0] for n in notes3] == ["Disk space low", "Disk space low"] and "on Scratch" in notes3[1][1],
      "events: disk_low per watched disk, the startup disk's as before (disk_free_gb, the swap warning), each once in "
      "six hours (%s)" % [(e["pool"], e.get("free_gb")) for e in low])
del ev3[:]
dm.prev_pools, dm.started = None, t3 + 4500
dm.evaluate(s3(t3 + 4600, pools=(DATA, EXT)))        # within the first two minutes after a start: what is there
dm.evaluate(s3(t3 + 4610, pools=(DATA,)))
dm.started = t3
dm.evaluate(s3(t3 + 4700, pools=(DATA, EXT)))
dm.evaluate(s3(t3 + 5100, pools=(DATA, dict(EXT, watch=True))))
dm.evaluate(s3(t3 + 5500, pools=(DATA,)))
dm.evaluate(s3(t3 + 5530))                           # a sample without its disks block: no news
for i, there in enumerate([1, 0, 1, 0, 0, 0]):       # a mount that flaps: told at once, then once after a quiet time
    dm.evaluate(s3(t3 + 5900 + 30 * i if i < 5 else t3 + 6250, pools=(DATA, EXT) if there else (DATA,)))
del dm.prev_pools["data"]
vol = [(e["what"], e["name"], e.get("changes")) for e in kinds3("volume")]
check(vol == [("mounted", "Scratch", None), ("watched", "Scratch", None), ("unmounted", "Scratch", None),
              ("mounted", "Scratch", None), ("unmounted", "Scratch", 3)],
      "events: a disk mounted, watched and gone; none in the first minutes after a start; a flapping mount in one "
      "event after five quiet minutes (%s)" % vol)
del ev3[:]
dm2 = oomphd.Daemon()
dm2.event = lambda kind, **kw: ev3.append(dict(kw, kind=kind))
dm2.notify = lambda *a, **kw: None
for i in range(15):                                   # a 1.9.0 sample: no cpu, gpu or disks block
    old3 = {k: v for k, v in s3(t3 + 5000 + 30 * i, disk_free_gb=12.0, unowned_gb=140.0, procs_gb=10.0).items()
            if k not in ("cpu", "disks", "top_cpu", "top_io")}
    dm2.evaluate(old3)
dm2.evaluate(dict(s3(t3 + 5500, unowned_gb=140.0, procs_gb=10.0),
                  gpu=[{"id": "gpu0", "util": 4.0, "src": "clients", "mem_gb": 3.0, "mem_alloc_gb": 11.68}]))
old_low = kinds3("disk_low")
un = kinds3("unowned_memory")
dm2.evaluate(s3(t3 + 5530, pools=(dict(DATA, free_gb=12.0, level="low"),)))    # the disks block back: no second warning
check(len(kinds3("disk_low")) == 1 and len(old_low) == 1 and set(old_low[0]) == {"disk_free_gb", "kind"} and
      not kinds3("thermal", "cpu_saturated", "disk_filling", "volume") and un and "gpu_alloc_gb" not in un[0],
      "events: samples without the new blocks keep the events of 1.9.4, the startup disk's disk_low too (%s)"
      % [e["kind"] for e in ev3])
dm3 = oomphd.Daemon()
dm3.event = lambda kind, **kw: ev3.append(dict(kw, kind=kind))
dm3.notify = lambda *a, **kw: None
del ev3[:]
for i in range(15):
    dm3.evaluate(dict(s3(t3 + 6000 + 30 * i, unowned_gb=140.0, procs_gb=10.0),
                      gpu=[{"id": "gpu0", "util": 4.0, "src": "clients", "mem_gb": 3.0, "mem_alloc_gb": 11.68}]))
un = kinds3("unowned_memory")
check(un and un[0].get("gpu_alloc_gb") == 11.68, "events: unowned memory says how much the GPU has allocated (%s)"
      % (un[0].get("gpu_alloc_gb") if un else None))
check(oomph.notify_text('Vol"ume\\\\ \x1b[2J‮evil\nname', 30) == "Vol ume    [2J evil name" and
      len(oomph.notify_text("x" * 500)) == 200, "notifications: names their owners chose lose quotes, backslashes, control "
      "and direction characters, and are cut (%r)" % oomph.notify_text('Vol"ume\\\\ \x1b[2J‮evil\nname', 30))
# the summary and the report: the GPU's two kinds of figure apart, nothing for samples before 1.9.1
seq3 = []
for i in range(60):
    t = t3 - 3600 + 60 * i
    x = s3(t, busy=2.0 + (i % 10), pools=(dict(DATA, free_gb=60.0 - i / 10.0), EXT))
    x.update(app_gb=10.0, wired_gb=5.0, compressed_gb=3.0, swap_total_gb=0.0, jetsam_kills=0,
             top=[{"pid": 1, "name": "cargo", "mb": 500 + i, "cpu": 6.0, "gpu": 0.5}],
             groups=[{"name": "iTerm2", "mb": 900, "n": 3, "cpu": 6.5}],
             gpu=[{"id": "gpu0", "util": 30.0 + i % 7 if i >= 30 else 80.0 + i % 5, "active": 70.0,
                   "src": "ioreport" if i >= 30 else "clients", "mem_gb": 4.0 + i / 100.0, "mem_alloc_gb": 11.0,
                   "mem_limit_gb": 27.0}],
             top_gpu=[{"pid": 2, "name": "WindowServer", "gpu": 5.0}])
    seq3.append(x)
sm = oomph.summarize(seq3, [])
olds = [{k: v for k, v in x.items() if k not in ("cpu", "gpu", "disks", "top_cpu", "top_gpu", "top_io")} for x in seq3]
so = oomph.summarize(olds, [])
check(sm["max_cpu_busy"] == 11.0 and sm["cpu_n"] == 14 and sm["max_gpu_busy"] == 84.0 and sm["max_gpu_util"] == 36.0 and
      sm["max_gpu_mem_gb"] == 4.59 and sm["min_free_gb"] == {"data": 54.1, EXT["id"]: 900.0} and
      sm["writers"][0]["name"] == "dd" and sm["top_cpu_at_peak"][0]["name"] == "cargo" and
      sm["top_gpu_at_peak"][0]["name"] == "WindowServer" and sm["process_risers"][0].get("cpu_peak") == 6.0 and
      not {"max_cpu_busy", "max_gpu_util", "max_gpu_busy", "max_gpu_mem_gb", "min_free_gb", "writers"} & set(so) and
      "cpu_peak" not in so["process_risers"][0],
      "summary: the CPU's, the GPU's (busy time and full speed apart, across the change), GPU memory's peaks, the least "
      "free space per disk and the writers; absent, not zero, for older samples")
h_mixed = oomph.render_html(seq3, [], "r")
h_busy = oomph.render_html(seq3[:30], [], "r")
h_old = oomph.render_html(olds, [], "r")
check("<h2>GPU at full speed and busy time (%)" in h_mixed and "<h2>GPU busy time (%)" in h_busy and
      "full speed" not in h_busy.split("Biggest risers")[0] and "Cores busy (of 14)" in h_mixed and
      "GPU memory (GB)" in h_mixed and "working-set limit 27" in h_mixed and "Free space on Data (GB)" in h_mixed and
      "Busiest on the CPU at its peak" in h_mixed and "Writing to disk, peak" in h_mixed and '"cpu":6.0' in h_mixed and
      not any(w in h_old for w in ("Cores busy", "GPU busy", "GPU at full", "Free space on", "Busiest on", '"cpu":')),
      "report: panels for the cores, the GPU in its two wordings, GPU memory against its limit, each watched disk with "
      "its floors; the busiest per resource; CPU and GPU columns in the risers; none of it for older samples")
lines3 = oomph.resource_summary_lines(sm, {"data": "Data"})
check(any(x.startswith("cores: at most 11.0 of 14 busy") for x in lines3) and
      any("% of full speed" in x for x in lines3) and any("speed not reported" in x for x in lines3) and
      any("Data 54.1 GB" in x for x in lines3) and not oomph.resource_summary_lines(so),
      "oomph report: the other resources in words, the GPU's two figures named apart (%s)" % lines3[:2])
ing3 = oomph_sync.Ingest({"now": time.time(), "ram_gb": 8.0})
check(ing3.row(json.dumps({"t": time.time() - 60, "kind": "disk_low", "pool": "vol:x", "free_gb": 900.0}), "events") and
      ing3.row(json.dumps({"t": time.time() - 60, "ram_gb": 8.0, "free_gb": 4.0}), "samples") and
      not ing3.row(json.dumps({"t": time.time() - 60, "ram_gb": 8.0, "free_gb": 900.0}), "samples"),
      "a mirror lets in a disk's event with 900 GB free on an 8 GB machine; a sample's free memory stays bounded")
import oomph_top as _ot  # noqa: E402
words = {k: _ot.event_text(dict(e, kind=k)) for k, e in (
    ("thermal", {"old": 2, "new": 0}), ("cpu_saturated", {"busy": 13.25, "n": 14, "minutes": 12}),
    ("cpu_saturated_cleared", {"minutes": 30}), ("disk_filling", {"mount": "/Volumes/X", "eta_min": 7.4, "rate_gb_min": 3}),
    ("volume", {"pool": "vol:Y", "what": "unwatched"}), ("disk_low", {"disk_free_gb": 3.0}))}
check(words == {"thermal": "thermal heavy → nominal", "cpu_saturated": "cores saturated: 13.2 of 14 busy for 12 min",
                "cpu_saturated_cleared": "cores no longer saturated, after 30 min",
                "disk_filling": "disk filling: /Volumes/X, full in 7 min at 3.0 GB/min", "volume": "disk no longer watched: vol:Y",
                "disk_low": "disk low: 3.0 GB free"} and "disk_filling" in _ot.ALARMING,
      "event words (the app's ChartEvent says the same; the chart vectors hold them together): %s" % words)
odd = os.path.join(tempfile.mkdtemp(prefix="oomph-odd-"), "events.jsonl")
with open(odd, "w") as f:       # odd values in a line cost that line at most, never the list
    for e in ({"kind": "volume", "what": ["x"]}, {"kind": "pressure_change", "old": [1], "new": {}},
              {"kind": "thermal", "old": 1e308, "new": 2}, {"kind": "jetsam", "kills": 2}):
        f.write(json.dumps(dict(e, t=time.time() - 60)) + "\n")
odd_ev, odd_c = _ot.load_events(os.path.dirname(odd), chart=True)
check(len(odd_c) >= 1 and any(t == "2 killed by jetsam" for _, t, _ in odd_ev) and
      _ot.event_text({"kind": "volume", "what": ["x"]}) == "disk changed: ?",
      "event words: a line with odd values (a list for a word) does not take the other events with it (%s)"
      % [x[1] for x in odd_ev])

# --- 1.9.9: the busiest by name with a count, the report's words and clean names, smaller fixes
procs99 = {i: {"pid": i, "name": "yes"} for i in range(100, 114)}
procs99.update({200: {"pid": 200, "name": "cc1plus"}, 201: {"pid": 201, "name": "cc1plus"},
                300: {"pid": 300, "name": "WindowServer"}})
use99 = {i: {"cpu": 0.9} for i in range(100, 114)}
use99.update({200: {"cpu": 1.0}, 201: {"cpu": 0.5}, 300: {"cpu": 0.2}, 999: {"cpu": 5.0}})
cn99 = oomphd.cpu_names(procs99, use99)
check(cn99 == [{"name": "yes", "cpu": 12.6, "n": 14}, {"name": "cc1plus", "cpu": 1.5, "n": 2},
               {"name": "WindowServer", "cpu": 0.2, "n": 1}],
      "sample: cpu_names adds up each name's cores over the whole process table, with a count (%s)" % cn99[:2])
dn99, ev99 = oomphd.Daemon(), []
dn99.event = lambda kind, **kw: ev99.append(dict(kw, kind=kind))
dn99.notify = lambda *a, **kw: None
for i in range(22):
    dn99.evaluate(s3(t3 + 30 * i, busy=13.3, cpu_names=cn99))
sat99 = [e for e in ev99 if e["kind"] == "cpu_saturated"]
check(sat99 and sat99[0]["top"] == {"yes": 12.6, "cc1plus": 1.5, "WindowServer": 0.2} and
      sat99[0]["top_n"] == {"yes": 14, "cc1plus": 2, "WindowServer": 1},
      "events: cpu_saturated names the busiest from the whole process list, by name with a count, not from the "
      "eight rows of top_cpu (%s)" % (sat99[0] if sat99 else None))
sm99 = oomph.summarize([dict(x, cpu_names=cn99) for x in seq3], [])
l99 = oomph.resource_summary_lines(sm99, {"data": "Data"})
check(sm99.get("names_cpu_at_peak", [None])[0] == {"name": "yes", "cpu": 12.6, "n": 14} and
      any("(yes ×14 12.6, cc1plus ×2 1.5, WindowServer 0.2)" in x for x in l99) and
      any("(cargo ×2 9.0)" in x for x in lines3) and any("(WindowServer 5 %)" in x for x in lines3),
      "oomph report, other resources: the busiest grouped by name with a count; an older sample's top_cpu grouped "
      "too (%s | %s)" % ([x for x in l99 if x.startswith("cores")], [x for x in lines3 if x.startswith("cores")]))
vol99 = {"t": t3, "iso": oomphd.now_iso(t3), "kind": "volume", "pool": "vol:5E0C61B2-0F4A-4D1B-9C57-3A1D2B7E9F10",
         "mount": "/Volumes/Datasets", "name": "Datasets", "what": "unmounted"}
check(oomph._event_detail(vol99) == "Datasets unmounted" and
      oomph._event_detail(dict(vol99, name=None, what="watched", changes=3)) == "/Volumes/Datasets watched (3 changes)",
      "oomph report, events: a volume event in words (%r)" % oomph._event_detail(vol99))
rdir = tempfile.mkdtemp(prefix="oomph-report99-")
evil = "ev\x1b]0;owned\x07il\x1b[2J\u202e"
for x in seq3[-20:]:
    y = dict(x, cpu_names=[dict(cn99[0], name="yes" + evil)] + cn99[1:], groups=[{"name": "app" + evil, "mb": 900, "n": 1}])
    with open(os.path.join(rdir, "samples-%s.jsonl" % oomphd.datetime.date.fromtimestamp(y["t"]).isoformat()), "a") as f:
        f.write(json.dumps(y) + "\n")
with open(os.path.join(rdir, "events.jsonl"), "w") as f:
    f.write(json.dumps(dict(vol99, t=seq3[-5]["t"], iso=oomphd.now_iso(seq3[-5]["t"]), name="Data" + evil)) + "\n")
saved_log99, oomph.LOG_DIR = oomph.LOG_DIR, rdir
buf = io.StringIO()
try:
    with redirect_stdout(buf):
        rc = oomph.main(["report", "--last", "2h"])
finally:
    oomph.LOG_DIR = saved_log99
rep99 = buf.getvalue()
check(rc == 0 and not re.search("[\x00-\x09\x0b-\x1f\x7f-\x9f\u202a-\u202e]", rep99) and "yesev?]0;owned?il?[2J? ×14" in rep99
      and "Dataev?]0;owned?il?[2J? unmounted" in rep99,
      "oomph report: names with escape and direction characters reach the terminal cleaned (%r)"
      % [x for x in rep99.splitlines() if "owned" in x][-2:])
check(oomph.term_text("a\u200fb\u061cc\u200ed\ufeff\x1b") == "a?b?c?d??",
      "oomph report: the bidi marks (LRM, RLM, ALM) and a BOM are cleaned too (%r)" % oomph.term_text("a\u200fb\u061c"))
_saved99 = (os.environ.get("OOMPH_LEDGER_PRIVATE"), oomph.LEDGER_DIR)
try:
    oomph.LEDGER_DIR = os.path.join(os.environ["OOMPH_DIR"], "named-ledger")  # a folder named on purpose
    os.environ.pop("OOMPH_LEDGER_PRIVATE", None)
    named = oomph._per_user_ledger()
    os.environ["OOMPH_LEDGER_PRIVATE"] = "1"
    told = oomph._per_user_ledger()
    os.environ["OOMPH_LEDGER_PRIVATE"] = "0"
    off = oomph._per_user_ledger()
finally:
    oomph.LEDGER_DIR = _saved99[1]
    if _saved99[0] is None:
        os.environ.pop("OOMPH_LEDGER_PRIVATE", None)
    else:
        os.environ["OOMPH_LEDGER_PRIVATE"] = _saved99[0]
check(not named and told and not off, "ledger: a sudo caller's child is told that its folder is the per-user default "
      "(OOMPH_LEDGER_PRIVATE=1) and checks it; the variable switches the check on, never off (%s %s %s)" % (named, told, off))
check(oomph._on_ram({"os": "linux", "ram_gb": 0.5, "scope": {"kind": "cgroup", "id": "/x"}}) == "in a cgroup limited to 0.5 GB"
      and oomph._on_ram({"os": "linux", "ram_gb": 2.0, "scope": {"kind": "cgroup", "id": "/x"}}) == "in a cgroup limited to 2 GB"
      and oomph._on_ram({"ram_gb": 36.0}) == "on a Mac with 36 GB RAM",
      "a refusal says 0.5 GB for a 512 MB cgroup, not 0 GB")
now99 = time.time()
fut99 = {"holder": {"pid": 1, "start": 1, "ns": "pid:[4026531999]"}, "state": "granted", "requested": now99 - 60,
         "granted": now99 + 30 * 86400, "seen": now99 + 30 * 86400, "ttl": 1800.0, "expires": now99 + 30 * 86400 + 1800}
check(oomph._holder_gone(fut99, {}, now99) and oomph._holder_gone(dict(fut99, state="queued", granted=None), {}, now99) and
      not oomph._holder_gone(dict(fut99, granted=now99 - 60, seen=now99 - 30, expires=now99 + 1740), {}, now99),
      "a lease of another pid namespace stamped in the future is gone (it would hold its place until then); a "
      "current one is not")


class _VolP:
    mounts = staticmethod(lambda: [])
    mount_key = staticmethod(lambda r: r["mount"])
    disk_pools = staticmethod(lambda recs, facts: ([], []))


vq = oomphd.Volumes(_VolP)
vq.todo = [("/Volumes/Gone", "/dev/disk9s1")]
vq.read()
check(vq.todo == [], "volumes: a mount gone before diskutil was asked about it leaves the queue")
saved_ds, saved_me = oomph._daemon_sample, oomphd.measure
oomph._daemon_sample, oomphd.measure = (lambda: None), (lambda *a, **k: ({}, {}, {}))
buf = io.StringIO()
try:
    with redirect_stdout(buf):
        oomph.main(["ps", "--gpu"])
finally:
    oomph._daemon_sample, oomphd.measure = saved_ds, saved_me
check("every user's processes" in buf.getvalue() and "your own" not in buf.getvalue(),
      "oomph ps --gpu without the logger: the note says the GPU covers every user (%r)" % buf.getvalue().strip()[-90:])
check("`OOMPH top` is a full-screen dashboard for people" in skill and "OOMPH status --json" in skill and
      "OOMPH top --once" in skill, "SKILL.md: oomph top is for people; agents use status --json or top --once")
swift99 = open(os.path.join(ROOT, "app", "oomph.swift")).read()
gets99 = [m_.start() for m_ in re.finditer(r"Keychain\.get\(", swift99)]
fn99 = swift99.find("func reportToken(")
check(len(gets99) == 1 and fn99 != -1 and fn99 < gets99[0] < swift99.find("\n    }\n", fn99) and
      re.search(r"var aiConnected: Bool \{ aiOn \}", swift99) and "Keychain.get" not in swift99[swift99.find("func loadDraft"):
                                                                                              swift99.find("func fetchOllamaModels")],
      "the app reads the keychain only for a report (reportToken): not to know it is connected, not to fill the dialog")

# the protocol core: serve --stdio, remote sync --once, coverage, the mirror (tools/nettest.py, a file of its own)
r = subprocess.run([sys.executable, "-I", "-B", os.path.join(ROOT, "tools", "nettest.py")], capture_output=True, text=True,
                   timeout=600, env={k: v for k, v in os.environ.items() if k not in ("OOMPH_DIR", "OOMPH_LEDGER_DIR")})
for line in r.stdout.splitlines():
    if line.startswith(("ok    ", "FAIL  ")):
        print("      net: " + line)
check(r.returncode == 0, "the protocol core (tools/nettest.py): %s" % ((r.stdout.strip().splitlines() or [""])[-1]
                                                                      + r.stderr[-400:]))

# Linux for agents (1.9.4): the Linux backend on recorded machines, here too; the exit codes of the CLI on this
# system (the same table on a Mac and on Linux); on Linux the live backend and linux/install.sh (tools/linuxtest.py)
r = subprocess.run([sys.executable, "-I", "-B", os.path.join(ROOT, "tools", "linuxtest.py")], capture_output=True, text=True,
                   timeout=900, env={k: v for k, v in os.environ.items()
                                     if not k.startswith("OOMPH_") or k == "OOMPH_LINUXTEST_STRICT"})
for line in r.stdout.splitlines():
    if line.startswith(("ok    ", "FAIL  ", "skip  ", "info  ")):
        print("    linux: " + line)
check(r.returncode == 0, "Linux for agents (tools/linuxtest.py): %s" % ((r.stdout.strip().splitlines() or [""])[-1]
                                                                       + r.stderr[-400:]))

print("\n%s — logs in %s" % ("FAILED (%d)" % len(failures) if failures else "all checks passed", LOG))
sys.exit(1 if failures else 0)
