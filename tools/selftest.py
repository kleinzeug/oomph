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

# --- CLI against the generated data
for args in (["status"], ["report", "--last", "10m"], ["incidents"], ["incident", "latest"],
             ["html", "--last", "1h", "-o", os.path.join(LOG, "adhoc.html")]):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = oomph.main(args)
    check(rc == 0 and buf.getvalue().strip(), "oomph %s" % " ".join(args))
html = open(os.path.join(LOG, "adhoc.html")).read()
check(html.count("<svg") >= 3, "HTML report contains its charts")

print("\n%s — logs in %s" % ("FAILED (%d)" % len(failures) if failures else "all checks passed", LOG))
sys.exit(1 if failures else 0)
