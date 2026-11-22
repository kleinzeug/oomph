#!/usr/bin/env python3
"""Apply Appendix B's patterns to journal lines. Input: journalctl -o json (one object per line) or plain text."""
import json, re, sys, collections
INVOKED = re.compile(r"^(?P<who>.+) invoked oom-killer: gfp_mask=(?P<gfp>0x[0-9a-f]+)\(.*?\), "
                     r"(?:nodemask=\S+, )?order=(?P<order>-?\d+), oom_score_adj=(?P<adj>-?\d+)")
SUMMARY = re.compile(r"^oom-kill:constraint=(?P<constraint>CONSTRAINT_\w+),nodemask=[^,]*(?:,[^,=]+=[^,]*)*?"
                     r",(?:oom_memcg=(?P<memcg>.+?)|global_oom),task_memcg=(?P<task_cg>.+?)"
                     r",task=(?P<name>.+),pid=(?P<pid>\d+),uid=(?P<uid>\d+)$")
KILLED  = re.compile(r"^(?:(?P<what>Memory cgroup out of memory|Out of memory(?: \(oom_kill_allocating_task\))?): )?"
                     r"Killed process (?P<pid>\d+) \((?P<name>.+)\),? total-vm:(?P<vm>\d+)kB, anon-rss:(?P<anon>\d+)kB, "
                     r"file-rss:(?P<file>\d+)kB(?:, shmem-rss:(?P<shmem>\d+)kB)?(?:, UID:(?P<uid>\d+))?")
KILL_OLD = re.compile(r"^(?P<what>Memory cgroup out of memory|Out of memory(?: \(oom_kill_allocating_task\))?): "
                      r"Kill process (?P<pid>\d+) \((?P<name>.+)\) score \d+ or sacrifice child")
OOMD_P  = re.compile(r"^Killed (?P<cg>\S+) due to memory pressure for (?P<mon>\S+) being (?P<pct>[\d.]+)% > (?P<lim>[\d.]+)%")
OOMD_S  = re.compile(r"^Killed (?P<cg>\S+) due to memory used \((?P<used>\d+)\) / total \((?P<total>\d+)\) and swap used ")
EARLY   = re.compile(r'^sending (?P<sig>SIGTERM|SIGKILL) to process (?P<pid>\d+) uid (?P<uid>\d+) "(?P<name>.*?)": ')
PATS = [("INVOKED", INVOKED), ("SUMMARY", SUMMARY), ("KILLED", KILLED), ("KILL_OLD", KILL_OLD),
        ("OOMD_P", OOMD_P), ("OOMD_S", OOMD_S), ("EARLY", EARLY)]
SUSPECT = re.compile(r"oom|Killed|kill|SIGTERM|SIGKILL|out of memory", re.I)
quiet = "-q" in sys.argv
counts = collections.Counter(); shown = collections.Counter(); unmatched = []
prefixed = unprefixed = 0
pids = set()
for raw in sys.stdin:
    raw = raw.rstrip("\n")
    if not raw: continue
    msg, src = raw, "text"
    if raw.startswith("{"):
        try:
            o = json.loads(raw)
            msg = o.get("MESSAGE", "")
            if isinstance(msg, list): msg = bytes(msg).decode("utf-8", "replace")
            src = o.get("_TRANSPORT", "?") + "/" + str(o.get("SYSLOG_IDENTIFIER", ""))
        except ValueError:
            pass
    for name, rx in PATS:
        m = rx.search(msg) if name == "EARLY" else rx.match(msg)
        if m:
            counts[name] += 1
            if name == "KILLED":
                pids.add(m.group("pid"))
                if m.group("what"): prefixed += 1
                else: unprefixed += 1
            if not quiet or shown[name] < 3:
                shown[name] += 1
                print("%-8s %s | %s" % (name, {k: v for k, v in m.groupdict().items() if v is not None}, msg[:300]))
            break
    else:
        if re.match(r"^\s|^\[\s*pid\s*\]|^\[\s*\d+\]|.*\+0x[0-9a-f]+/0x", msg):
            continue  # stack frames and the task table of the report, not records
        if SUSPECT.search(msg) and ("oom" in msg.lower() or "earlyoom" in src or "Killed process" in msg):
            unmatched.append((src, msg))
print("COUNTS " + " ".join("%s=%d" % (n, counts[n]) for n, _ in PATS)
      + " KILLED_prefixed=%d KILLED_unprefixed=%d KILLED_distinct_pids=%d" % (prefixed, unprefixed, len(pids)))
print("UNMATCHED oom-related lines: %d" % len(unmatched))
for s, m in unmatched[:40]:
    print("  UNMATCHED [%s] %s" % (s, m[:300]))
