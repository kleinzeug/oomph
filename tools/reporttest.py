#!/usr/bin/python3 -I
"""Tests of another machine read here (roadmap 01 §4.8, §9, §12; R2): the server's full samples and
incident files, `oomph --machine NAME check|status|reservations|incidents|incident|report|html`, the
reports drawn here from its data, and the gate of R2: `render_html` and `incident_html` over data
whose every string is hostile produce no element or attribute the template does not have.
Unprivileged and portable; tools/selftest.py runs it. All data is invented.

    /usr/bin/python3 -I -B tools/reporttest.py
"""
import base64
import gzip
import html.parser
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "daemon"))
import topfixture  # noqa: E402  (TZ Europe/Berlin: fixture days are that zone's dates)
import oomph  # noqa: E402
import oomph_net as net  # noqa: E402
import oomph_sync as sync  # noqa: E402

PY = sys.executable
OOMPH = os.path.join(ROOT, "daemon", "oomph.py")
NOW = topfixture.NOW + 30
failures = []
# Every kind of string that must not become markup, script or a terminal control (01 §12).
EVIL = ["a\"b'c`d</script><script>alert(1)</script>", "<img src=x onerror=alert(2)>", "x\u2028y\u2029z",
        "\x1b[2J\x1b]0;t\x07esc", "\u202eevil\u202c", "</style><svg onload=alert(3)>", "${alert(4)}",
        "<!--<script>"]  # a browser's double-escaped script state: the data block would run on past the page's script


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)


def evil(i):
    return EVIL[i % len(EVIL)] + " %d" % i


def machine(d, hostile=True, mid="m-0123456789abcdef", name="studio"):
    """A Mac's log and ledger directories: six hours of full samples (every process), events, an
    incident with its system log, reservations; with `hostile`, every string a hostile one."""
    s = (lambda i, plain: evil(i)) if hostile else (lambda i, plain: plain)
    log, led = os.path.join(d, "log"), os.path.join(d, "ledger")
    os.makedirs(os.path.join(log, "incidents", "20261120-120000"))
    os.makedirs(led)
    by_day, t = {}, topfixture.NOW - 6 * 3600
    while t <= topfixture.NOW:
        k = int(t // 60) % 50
        x = {"t": t, "iso": time.strftime("%Y-%m-%dT%H:%M:%S+01:00", time.localtime(t)), "os": "macos", "pressure": 1,
             "free_pct": 40, "ram_gb": 36.0, "app_gb": 12.0 + k / 10.0, "wired_gb": 6.0, "compressed_gb": 3.0,
             "cached_gb": 6.0, "free_gb": 9.0, "swap_total_gb": 2.0, "swap_used_gb": 0.5, "swapfiles": 1,
             "disk_free_gb": 300.0, "jetsam_kills": 0, "away": {"idle_s": 0, "display_on": True, "locked": False,
                                                              "sleep_preventers": [s(1, "caffeinate")]},
             "cpu": {"n": 16, "busy": 3.5 + k / 10.0}, "io": {"r_mb_s": 1.0, "w_mb_s": 2.0},
             "top": [{"pid": 400 + j, "ppid": 1, "name": s(j, "proc%d" % j), "uid": 501, "mb": 900 - 100 * j + k,
                      "g": s(j + 3, "App %d" % j), "s": 640 if j == 0 else None, "cpu": 1.0} for j in range(5)],
             "groups": [{"name": s(j + 3, "App %d" % j), "mb": 1800 - 200 * j, "n": 3} for j in range(5)],
             "claude": [{"pid": 640, "cwd": s(9, "/srv/proj/atlas"), "mb": 3000, "n": 9}],
             "top_cpu": [{"pid": 400, "name": s(0, "proc0"), "g": s(3, "App 0"), "cpu": 2.0}],
             "disks": [{"id": "vol:00000000-1111-2222-3333-444444444444", "name": s(5, "Datasets"), "kind": "external",
                        "total_gb": 1800.0, "free_gb": 400.0 - k, "watch": True, "low_gb": 50.0, "crit_gb": 20.0,
                        "mount": "/Volumes/" + s(5, "Datasets")}]}
        by_day.setdefault(time.strftime("%Y-%m-%d", time.localtime(t)), []).append(x)
        t += 60
    for day, rows in by_day.items():
        with open(os.path.join(log, "samples-%s.jsonl" % day), "w") as f:
            f.writelines(json.dumps(r) + "\n" for r in rows)
    cur = dict(rows[-1], daemon={"pid": 99, "version": "1.10.6", "interval": 60, "incident": None, "root": True,
                                 "machine": {"id": mid, "name": name, "os": "macos", "arch": "arm64",
                                             "os_version": "macOS 27.2", "kind": "desktop", "cpus": 16}})
    with open(os.path.join(log, "current.json"), "w") as f:
        json.dump(cur, f)
    with open(os.path.join(log, "events.jsonl"), "w") as f:
        for i, kind in enumerate(("pressure_change", "volume", "cpu_saturated", "incident_open")):
            f.write(json.dumps({"t": topfixture.NOW - 3600 + 60 * i, "kind": kind, "name": s(i + 10, "Datasets"),
                                "what": "mounted", "old": [1] if hostile and i == 0 else 1, "new": 2,
                                "desc": s(i + 11, "busy")}) + "\n")
    inc = os.path.join(log, "incidents", "20261120-120000")
    with open(os.path.join(inc, "incident.json"), "w") as f:
        json.dump({"id": "20261120-120000", "start": topfixture.NOW - 2 * 3600, "end": topfixture.NOW - 3600,
                   "open": False, "last_trigger": topfixture.NOW - 2 * 3600 + 300,
                   "reasons": [{"kind": "pressure", "desc": s(20, "memory pressure critical"), "t": topfixture.NOW - 7200}],
                   "summary": incident_summary(by_day, topfixture.NOW - 2 * 3600, topfixture.NOW - 3600)}, f)
    with open(os.path.join(inc, "syslog.txt"), "w") as f:
        f.write("12:00:01 kernel: \x1b[31mred\x1b[0m jetsam %s\n" % s(21, "x") * 3)
    lease = {"id": "r7", "state": "granted", "gb": 6.0, "purpose": s(30, "gradle assembleDebug"),
             "project": s(31, "/srv/proj/atlas"), "holder": {"pid": 640, "start": 1, "kind": "session"},
             "requested": topfixture.NOW - 600, "granted": topfixture.NOW - 590, "seen": topfixture.NOW - 10,
             "used_gb": 2.0, "key": "r7@1"}
    queued = dict(lease, id="r8", state="queued", gb=4.0, purpose=s(32, "pytest -n 8"), key="r8@1")
    queued.pop("granted")
    with open(os.path.join(led, "ledger.json"), "w") as f:
        json.dump({"seq": 8, "leases": [lease, queued], "state": {"free_gb": 9.0, "margin_gb": 1.8, "reserved_gb": 6.0,
                                                                   "available_gb": 1.2}, "history": []}, f)
    with open(os.path.join(led, "reservations.jsonl"), "w") as f:
        f.write(json.dumps({"event": "end", "t": topfixture.NOW - 900, "key": "r5@1", "id": "r5", "purpose": s(33, "x"),
                            "project": s(34, "p"), "holder": "session", "gb": 2.0, "requested": topfixture.NOW - 2000,
                            "granted": topfixture.NOW - 1990, "ended": topfixture.NOW - 900, "peak_gb": 1.5,
                            "outcome": "released"}) + "\n")
    return log, led


def incident_summary(by_day, start, end):
    """What the logger writes as an incident's summary (summarize()), over the samples of its span, one
    of them at WARN: an onset with a level's name, the least free GB per disk, 2 kills."""
    rows = [dict(r) for day in sorted(by_day) for r in by_day[day] if start <= r["t"] <= end]
    rows[len(rows) // 2].update(pressure=2, jetsam_kills=2)
    return json.loads(json.dumps(oomph.summarize(rows, [])))


def linux_machine(d, mid="m-fedcba9876543210", name="box"):
    """machine() as a Linux logger writes it (01 §4.8: the renderer here takes a Linux machine's samples):
    PSI with a cgroup's share, the kernel's figures (a commit_pct it could not read), a cgroup scope,
    two NVIDIA cards, no presence; every string a hostile one."""
    log, led = machine(d, hostile=True, mid=mid, name=name)

    def linux(r):
        r = dict(r, os="linux", compressed_gb=0.0, swapfiles=1,
                 away={"idle_s": None, "display_on": None, "locked": False, "sleep_preventers": []},
                 psi={"mem_some": 3.5, "mem_full": 0.4, "mem_some60": 2.0, "mem_full60": 0.2, "cpu_some": 9.0,
                      "io_some": 1.0, "io_full": 0.5, "limit": {"some": 1.0, "full": 0.1, "by": evil(40)}},
                 linux={"avail_gb": 15.0, "anon_gb": 10.0, "shmem_gb": 0.5, "commit_pct": None, "overcommit": 0,
                        "margin_gb": 2.5, "swap_room_gb": 4.0, "oversize_gb": 12.0, "floor_gb": 3.0},
                 scope={"kind": "cgroup", "id": evil(41), "limit_gb": 32.0, "by": "max", "host_ram_gb": 251.0,
                        "host_avail_gb": 200.0, "host_pressure": 1, "host_margin_gb": 8.0},
                 gpu=[{"id": "nvidia:%d" % i, "name": evil(42 + i), "util": 30.0 * i, "mem_gb": 2.0 + i,
                       "mem_limit_gb": 24.0, "src": "nvidia"} for i in range(2)])
        r.pop("jetsam_kills", None)
        return r
    _edit_days(log, linux)
    curp = os.path.join(log, "current.json")
    cur = linux(json.load(open(curp)))
    cur["daemon"]["machine"].update(os="linux", arch="x86_64", os_version="Ubuntu 24.04", cpus=48,
                                    measures={"memory": True, "psi": True, "kills": "count", "scope": "cgroup"})
    with open(curp, "w") as f:
        json.dump(cur, f)
    return log, led


class Shape(html.parser.HTMLParser):
    """The elements and attributes of a page, and its scripts' text (01 §12: the gate of R2)."""

    def __init__(self):
        html.parser.HTMLParser.__init__(self, convert_charrefs=True)
        self.shape, self.scripts, self._in = set(), [], None

    def handle_starttag(self, tag, attrs):
        self.shape.add((tag, tuple(sorted(a for a, _ in attrs))))
        self._in = [] if tag == "script" else None

    def handle_data(self, data):
        if self._in is not None:
            self._in.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in is not None:
            self.scripts.append("".join(self._in))
            self._in = None


def shape(page):
    p = Shape()
    p.feed(page)
    p.close()
    return p


def page_ok(page, template, what):
    """No element or attribute beyond the template's; the data blob still one JSON document and the
    script text the template's own; no control or direction character anywhere."""
    p = shape(page)
    extra = p.shape - template.shape
    blobs = [x for x in p.scripts if x.lstrip().startswith("{")]
    ok_blob = len(blobs) == 1 and isinstance(json.loads(blobs[0]), dict) and "<" not in blobs[0]
    code_same = [x for x in p.scripts if not x.lstrip().startswith("{")] == \
        [x for x in template.scripts if not x.lstrip().startswith("{")]
    clean = not any(c in page for c in ("\x1b", "\x07", "\u202e", "\u2028"))
    check(not extra and ok_blob and code_same and len(p.scripts) == len(template.scripts),
          "%s: only the template's elements and attributes (extra: %s), one JSON data block (no `<` in it, so no "
          "`</script>` or `<!--`), the template's script"
          % (what, sorted(extra)[:3]))
    return clean


def cli(*args, env=None, timeout=90):
    return subprocess.run([PY, "-I", "-B", OOMPH] + list(args), capture_output=True, text=True, timeout=timeout,
                          env=dict(os.environ, **(env or {})))


def server_checks(log, led):
    srv = net.Server(log_dir=log, ledger_dir=led, now=NOW)
    srv.open = True
    hello = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"proto": [1, 1]}})
    caps = hello["result"]["machine"]["caps"]
    check("full" in caps and "files" in caps, "the server offers full samples and incident files (caps: %s)" % caps)

    def call(method, **p):
        return srv.handle({"jsonrpc": "2.0", "id": 2, "method": method, "params": p})
    a = topfixture.NOW - 3600
    r = call("samples", after=[a, 0], to=NOW, full=True)
    rows = [json.loads(x) for x in net.unpack(r["result"]["data"])]
    slim = [json.loads(x) for x in net.unpack(call("samples", after=[a, 0], to=NOW)["result"]["data"])]
    check(rows and all("top" in x and "groups" in x and "disks" in x for x in rows) and
          not any("mount" in d for x in rows for d in x["disks"]) and not any("top" in x for x in slim),
          "samples with full: every process and the disks (no mount paths); without: slim")
    for bad, why in (({"after": [a - 86400, 0], "to": NOW, "full": True}, "a window over a day"),
                     ({"after": [0, 0], "to": NOW, "full": True}, "no start"),
                     ({"after": [a, 0], "to": NOW, "full": "yes"}, "full not a bool"),
                     ({"after": [a, 0], "to": NOW, "full": 1}, "full as a number")):
        check(call("samples", **bad).get("error", {}).get("code") == net.ERR["params"], "samples refuses %s" % why)
    iid = "20261120-120000"
    r = call("incident_file", id=iid, name="syslog.txt")["result"]
    got = zlib.decompress(base64.b64decode(r["data"]))
    check(got == open(os.path.join(log, "incidents", iid, "syslog.txt"), "rb").read() and r["more"] is False and
          r["next"] == len(got), "incident_file: syslog.txt whole, in one chunk")
    for bad in ({"id": iid, "name": "incident.json"}, {"id": iid, "name": "../current.json"}, {"id": "../x", "name": "syslog.txt"},
                {"id": "20261120-130000", "name": "syslog.txt"}, {"id": iid, "name": "syslog.txt", "after": -1},
                {"id": iid, "name": "syslog.txt", "after": True}):
        check(call("incident_file", **bad).get("error", {}).get("code") == net.ERR["params"],
              "incident_file refuses %s" % json.dumps(bad)[:60])
    secret = os.path.join(os.path.dirname(log), "secret.txt")
    with open(secret, "w") as f:
        f.write("PRIVATE")
    os.rename(os.path.join(log, "incidents", iid, "syslog.txt"), secret + ".bak")
    os.symlink(secret, os.path.join(log, "incidents", iid, "syslog.txt"))
    r = call("incident_file", id=iid, name="syslog.txt")["result"]
    check(zlib.decompress(base64.b64decode(r["data"])) == b"", "incident_file never follows a link")
    os.unlink(os.path.join(log, "incidents", iid, "syslog.txt"))
    os.rename(secret + ".bak", os.path.join(log, "incidents", iid, "syslog.txt"))


def render_checks(tmp):
    """The gate (01 §12): the reports over hostile strings, straight from the files (no sanitising
    at ingest), have the shape of the same reports over plain ones."""
    plain, bad = os.path.join(tmp, "plain"), os.path.join(tmp, "bad")
    machine(plain, hostile=False)
    machine(bad, hostile=True)
    pages = {}
    for d in (plain, bad):
        oomph.LOG_DIR = os.path.join(d, "log")
        since, until = topfixture.NOW - 6 * 3600, topfixture.NOW
        e = oomph.load_events(since, until)
        pages[d] = (oomph.render_html(oomph.SampleWindow(since, until), e, "Memory report: %s" % (
                        "studio" if d == plain else EVIL[0]),
                        intro_html="<p class=sub>Data from <b>%s</b></p>" % oomph._e("studio" if d == plain else EVIL[1])),
                    oomph.incident_html(oomph.list_incidents()[0]))
    tpl = shape(pages[plain][0])
    outside = pages[bad][0].split('<script type="application/json"')[0]
    check("<img" not in outside and "&lt;img" in outside, "a hostile name is text in the page, escaped")
    page_ok(pages[bad][0], tpl, "render_html over hostile samples, events and title")
    page_ok(pages[bad][1], shape(pages[plain][1]), "incident_html over a hostile incident")


def _edit_days(log, fn):
    """Every row of a machine's own day files through fn (row -> row)."""
    for n in os.listdir(log):
        if n.startswith("samples-") and n.endswith(".jsonl"):
            p = os.path.join(log, n)
            rows = [json.loads(x) for x in open(p) if x.strip()]
            with open(p, "w") as f:
                f.writelines(json.dumps(fn(r)) + "\n" for r in rows)


def hostile_shapes(mdir, log):
    """Its data with the wrong shape, not only hostile text (01 §4.8: an older, newer or hostile machine):
    every command reads it or says it can't, and never exits 1 or 2, which `check` means as a verdict."""
    saved = {n: open(os.path.join(log, n), "rb").read() for n in os.listdir(log) if n.startswith("samples-")}
    curp = os.path.join(mdir, "log", "current.json")
    incp = os.path.join(mdir, "log", "incidents", "20261120-120000", "incident.json")
    cur0, inc0 = open(curp).read(), open(incp).read()
    for what, fn in (("a process without its size", lambda r: dict(r, top=[{"name": "x", "pid": 1}] + r["top"])),
                     ("a size that is text", lambda r: dict(r, top=[dict(r["top"][0], mb="big")] + r["top"][1:],
                                                            groups=[{"name": "g", "mb": "big", "n": 1}])),
                     ("processes that are numbers", lambda r: dict(r, top=[1, 2], groups=[None], claude="x")),
                     ("blocks of the wrong kind", lambda r: dict(r, cpu=[1], disks={"x": 1}, gpu="x", pressure="x",
                                                                 away=[1], ram_gb=None))):
        _edit_days(log, fn)  # it serves them so: fetched as full samples, and the summary samples kept
        for argv in (["report", "--last", "6h"], ["html", "--last", "6h", "-o", os.path.join(mdir, "x.html")],
                     ["incident", "20261120-120000", "--html", "--no-open", "-o", os.path.join(mdir, "i.html")]):
            r = cli("--machine", "studio", *argv)
            check(r.returncode == 0 and "Traceback" not in r.stderr, "its samples with %s: %s reads them (%s)" % (
                what, argv[0], r.stderr.strip()[-160:]))
        for n, b in saved.items():
            with open(os.path.join(log, n), "wb") as f:
                f.write(b)
    cur = json.loads(cur0)
    for what, change in (("pressure as text", {"pressure": "x"}), ("daemon as text", {"daemon": "x"}),
                         ("no ram_gb", {"ram_gb": None}), ("swap_used_gb null", {"swap_used_gb": None}),
                         ("no pressure", {"pressure": None}), ("no free_gb", {"free_gb": None}),
                         ("no disk_free_gb", {"disk_free_gb": None}), ("away a list", {"away": [1]}),
                         ("groups without counts", {"groups": [{"name": "g", "mb": 1}, 7]}),
                         ("a lease of the wrong kind", {"leases": [{"id": 1}], "top_cpu": [{"cpu": "x"}]})):
        c = {k: v for k, v in dict(cur, **change).items() if not (v is None and change.get(k, 0) is None)}
        with open(curp, "w") as f:
            json.dump(c, f)
        for argv in (["check"], ["check", "--json"], ["status"], ["status", "--json"]):
            r = cli("--machine", "studio", *argv, "--no-connect")
            check(r.returncode in (0, 3, 4) and "Traceback" not in r.stderr and
                  ("--json" not in argv or isinstance(json.loads(r.stdout or "null"), dict)),
                  "current sample with %s: %s exits %d, neither tight nor critical" % (what, " ".join(argv), r.returncode))
    with open(curp, "w") as f:
        f.write(cur0)
    inc = json.loads(inc0)
    for what, change in (("end as text", {"end": "x"}), ("reasons numbers", {"reasons": [1]}),
                         ("summary as text", {"summary": "x"}), ("a reason without a time", {"reasons": [{"desc": 3}]})):
        with open(incp, "w") as f:
            json.dump(dict(inc, **change), f)
        for argv in (["incidents"], ["incident", "20261120-120000", "--html", "--no-open", "-o",
                                     os.path.join(mdir, "i.html")]):
            r = cli("--machine", "studio", *argv, "--no-connect")
            check(r.returncode == 0 and "Traceback" not in r.stderr, "an incident with %s: %s reads it (%s)" % (
                what, argv[0], r.stderr.strip()[-160:]))
    with open(incp, "w") as f:
        f.write(inc0)

    # what still fails is said in one line, exit 4: never 1 or 2
    real = sync.remote_check
    sync.remote_check = lambda r, args: 1 // 0
    saved_g = (oomph.LOG_DIR, oomph.LEDGER_DIR, oomph.REMOTE, oomph.CLOCK_S, oomph.DAY_PAD, oomph.FULL_DIR, oomph.FULL_SPANS)
    err, out = sys.stderr, sys.stdout
    try:
        sys.stderr = sys.stdout = open(os.devnull, "w")
        rc = sync.cmd_machine("studio", ["check", "--no-connect"])
    finally:
        sys.stderr.close()
        sys.stderr, sys.stdout = err, out
        sync.remote_check = real
        (oomph.LOG_DIR, oomph.LEDGER_DIR, oomph.REMOTE, oomph.CLOCK_S, oomph.DAY_PAD, oomph.FULL_DIR,
         oomph.FULL_SPANS) = saved_g
    check(rc == sync.UNREADABLE == 4, "a failure reading its data: exit 4, not a verdict")


class FakeLink:
    """One page of rows to fetch_full."""

    def __init__(self, rows, to):
        self.rows, self.to = rows, to

    def call(self, method, params):
        return {"data": net.pack([json.dumps(r).encode() for r in self.rows]), "more": False, "to": self.to}


def fetch_checks(tmp):
    """fetch_full: rows rebuilt with their types at ingest; coverage ends at the last row that fit."""
    a = topfixture.NOW - 3600
    base = {"iso": "x", "os": "macos", "pressure": 1, "ram_gb": 36.0, "app_gb": 1.0, "wired_gb": 1.0,
            "compressed_gb": 1.0, "cached_gb": 1.0, "free_gb": 9.0}
    small = [dict(base, t=a + 60 * i, top=[{"pid": 1, "name": "p", "mb": "big"}, {"pid": "2", "name": "q", "mb": 5},
                                           {"pid": 3, "name": "r", "mb": 7}], groups=[1, {"name": "g", "mb": 3, "n": 1}])
             for i in range(3)]
    big = dict(base, t=a + 180, top=[{"pid": j, "name": "p" * 200, "mb": j} for j in range(25)])
    rows = small + [big] + [dict(r, t=r["t"] + 240) for r in small]
    m = sync.Mirror(os.path.join(tmp, "fetchmirror"))
    machine = {"caps": ["full"], "now": a + 3600, "oldest": a - 86400, "ram_gb": 36.0, "version": "1.10.6"}
    line = lambda r: len(net.dumps(oomph.typed_sample(oomph.report_sample(r))))
    cap = sync.FULL_RAW_CAP
    try:
        sync.FULL_RAW_CAP = sum(line(r) + 1 for r in small) + line(big) // 2
        got = sync.fetch_full(FakeLink(rows, a + 3600), m, machine, a, a + 3600)
    finally:
        sync.FULL_RAW_CAP = cap
    have = m.json("full", "cover.json")["have"]
    kept = [json.loads(x) for d in m.days("full") for x in m.day_rows(d, "full").values()]
    check(got["n"] == 3 and have == [[a, a + 120]], "fetch_full: a row that does not fit ends the coverage there "
          "(%s, %s)" % (got, have))
    check(all(isinstance(p["mb"], (int, float)) and isinstance(p["pid"], int) for r in kept for p in r["top"]) and
          all(len(r["top"]) == 1 and r["groups"] == [{"name": "g", "mb": 3, "n": 1}] for r in kept),
          "fetch_full: list items without a numeric size or pid dropped at ingest")


class SyslogLink:
    """incident_file as a server answers it: one log whole, one that goes away between its chunks."""

    def call(self, method, params):
        body = b"kernel: jetsam\n" * 10
        if params["id"] == "20261120-110000" and params["after"]:
            return {"data": base64.b64encode(zlib.compress(b"")).decode(), "next": 0, "more": False}
        return {"data": base64.b64encode(zlib.compress(body)).decode(), "next": params["after"] + len(body),
                "more": params["id"] == "20261120-110000"}

    def close(self):
        pass


def catch_up_checks(tmp):
    """catch_up: one incident's system log that fails is that log's failure, not the contact's."""
    m = sync.Mirror(os.path.join(tmp, "catchmirror"))
    machine = {"caps": ["files"], "now": NOW, "version": "1.10.6"}

    class Quiet:
        def __init__(self, *a):
            pass
        current = ledger = incidents = lambda self: None

    saved = sync.open_link, sync.remember, sync.Sync
    try:
        sync.open_link = lambda e, secret: (SyslogLink(), machine, None)
        sync.remember, sync.Sync = (lambda *a: None), Quiet
        book = type("B", (), {"secrets": {}})()
        got = sync.catch_up(book, {"mid": "m-0123456789abcdef", "transport": "ssh"}, m,
                            lambda mc: {"syslog": ["20261120-110000", "20261120-120000"]})
    except sync.SyncError as err:
        got = {"raised": err.detail}
    finally:
        sync.open_link, sync.remember, sync.Sync = saved
    sl = got.get("syslog") or {}
    check(sl.get("20261120-110000", {}).get("ok") is False and sl.get("20261120-120000", {}).get("ok") is True and
          m.json("", "contact.json"), "catch_up: a system log gone between its chunks fails alone; the rest is fetched "
          "and the contact counts (%s)" % got)


def linux_checks(tmp, fake):
    """A Linux machine read here (01 §4.8): check, status and a report over its samples, hostile strings
    and all, through the same gate as a Mac's."""
    lx = os.path.join(tmp, "box")
    linux_machine(lx)
    env = {"FAKEDIR": lx}
    r = cli("remote", "add", "sam@box", "--name", "box", "--json", env=env)
    check(r.returncode == 0, "remote add of a Linux machine over a fake ssh (%s)" % r.stderr.strip()[-200:])
    r = cli("--machine", "box", "check", "--json", env=env)
    j = json.loads(r.stdout or "{}")
    check(r.returncode == j.get("exit_code") and j.get("origin") == "remote:box" and j.get("level") in ("ok", "tight")
          and len(j.get("resources", {}).get("gpu") or []) == 2 and "Traceback" not in r.stderr,
          "Linux machine: check --json, its verdict and its two GPUs (%s)" % (r.stderr.strip()[-160:] or j.get("level")))
    r = cli("--machine", "box", "check", env=env)
    check(r.returncode in (0, 1) and "--measure" not in r.stdout and "\x1b" not in r.stdout, "Linux machine: check")
    r = cli("--machine", "box", "status", env=env)
    check(r.returncode == 0 and "Nones" not in r.stdout and "None" not in r.stdout.split("you")[-1].split("\n")[0] and
          "--measure" not in r.stdout and "\x1b" not in r.stdout and "\u202e" not in r.stdout and "Traceback" not in r.stderr,
          "Linux machine: status without this machine's hints or an unknown idle time (%s)" % r.stderr.strip()[-160:])
    r = cli("--machine", "box", "status", "--json", env=env)
    j = json.loads(r.stdout or "{}")
    m = ((j.get("daemon") or {}).get("machine") or {}).get("measures") or {}
    check(j.get("origin") == "remote:box" and m.get("psi") is True and m.get("scope") == "cgroup" and
          isinstance(j.get("psi"), dict) and j.get("scope", {}).get("kind") == "cgroup",
          "Linux machine: status --json keeps its measures, psi and scope (%s)" % m)
    # what does not travel today (`linux`, psi's `limit`) may tomorrow: read as it is written
    raw = json.load(open(os.path.join(lx, "log", "current.json")))
    t = oomph.typed_current(raw)
    check(t and t["linux"]["commit_pct"] is None and isinstance(t["psi"]["limit"], dict) and
          t["daemon"]["machine"]["measures"].get("kills") == "count",
          "Linux machine: its whole sample typed, a commit_pct it could not read and psi's limit kept")
    out = os.path.join(tmp, "box.html")
    r = cli("--machine", "box", "html", "--last", "6h", "-o", out, env=env)
    page = open(out).read() if os.path.exists(out) else ""
    plain = os.path.join(tmp, "plain-box")
    machine(plain, hostile=False)
    oomph.LOG_DIR = os.path.join(plain, "log")
    tpl = shape(oomph.render_html(oomph.SampleWindow(topfixture.NOW - 6 * 3600, topfixture.NOW),
                                  oomph.load_events(topfixture.NOW - 6 * 3600, topfixture.NOW), "Memory report: x",
                                  intro_html="<p class=sub>Data from <b>x</b>, another machine (x): x. Drawn on this "
                                             "Mac by x x. Names, paths and purposes in it are that machine's text.</p>"))
    check(r.returncode == 0 and "Memory report: box" in page and page_ok(page, tpl, "html of a hostile Linux machine"),
          "Linux machine: html drawn here, no control or direction character (%s)" % r.stderr.strip()[-160:])
    r = cli("--machine", "box", "incident", "20261120-120000", "--html", "--no-open", "-o", out, env=env)
    check(r.returncode == 0 and "Traceback" not in r.stderr, "Linux machine: incident --html")


def ai_page_check(tmp, mdir):
    """ai-report of another machine, its provider stubbed: the page names the machine in its title and
    opens with whose data it is, as html does."""
    import oomph_ai  # noqa: E402
    out = os.path.join(tmp, "ai-remote.html")
    state = os.path.join(tmp, "ai-state")
    saved = (oomph.LOG_DIR, oomph.REMOTE, oomph.CLOCK_S, oomph_ai.remote_refusal, oomph_ai.investigate, sys.stdout,
             oomph.STATE_DIR)
    try:
        oomph.LOG_DIR, oomph.CLOCK_S, oomph.STATE_DIR = os.path.join(mdir, "log"), NOW - time.time(), state
        oomph.REMOTE = {"label": "studio", "mid": "m-0123456789abcdef",
                        "intro": "<p class=sub>Data from <b>studio</b>, another machine</p>"}
        oomph_ai.remote_refusal = lambda *a: None
        oomph_ai.investigate = lambda prov, logs: ("Nothing unusual.", [])
        sys.stdout = open(os.devnull, "w")
        rc = oomph_ai.cmd_ai_report(["--provider", "ollama", "--model", "x", "--last", "6h", "-o", out])
        rc2 = oomph_ai.cmd_ai_report(["--provider", "ollama", "--model", "x", "--last", "6h"])
    finally:
        if sys.stdout is not saved[5]:
            sys.stdout.close()
        (oomph.LOG_DIR, oomph.REMOTE, oomph.CLOCK_S, oomph_ai.remote_refusal, oomph_ai.investigate, sys.stdout,
         oomph.STATE_DIR) = saved
    own = os.path.join(state, "reports", "ai-report-m-0123456789abcdef.html")
    check(rc2 == 0 and os.path.exists(own) and os.stat(own).st_mode & 0o077 == 0 and
          os.stat(os.path.dirname(own)).st_mode & 0o077 == 0 and
          not os.path.lexists(os.path.join(tmp, "oomph-ai-report.html")),
          "ai-report of another machine without -o: in this user's own reports folder (0700, 0600), not in TMPDIR")
    page = open(out).read() if os.path.exists(out) else ""
    check(rc == 0 and "<title>Memory report: studio</title>" in page and
          page.find("Data from <b>studio</b>") < page.find("Nothing unusual.") and "Data from" in page,
          "ai-report of another machine: its name in the title, whose data it is above the analysis")


def main():
    tmp = tempfile.mkdtemp(prefix="oomph-reporttest-")
    try:
        return run(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run(tmp):
    fx = os.path.join(tmp, "fx")
    log, led = machine(fx)
    server_checks(log, led)
    render_checks(tmp)
    fetch_checks(tmp)
    catch_up_checks(tmp)

    # pure parts
    saved_env, saved_plat = dict(os.environ), sys.platform
    try:
        os.environ["SSH_CONNECTION"] = "10.0.0.1 1 10.0.0.2 22"
        over_ssh = sync.desktop()
        os.environ.pop("SSH_CONNECTION")
        sys.platform = "linux"
        for k in ("DISPLAY", "WAYLAND_DISPLAY"):
            os.environ.pop(k, None)
        headless = sync.desktop()
        os.environ["WAYLAND_DISPLAY"] = "wayland-0"
        wayland = sync.desktop()
    finally:
        sys.platform = saved_plat
        os.environ.clear()
        os.environ.update(saved_env)
    check(not over_ssh and not headless and wayland, "incident --html opens a page only where there is a desktop "
          "(not over ssh, not on a headless Linux box)")
    plain_fx = os.path.join(tmp, "plain-summary")
    plain_log = machine(plain_fx, hostile=False)[0]
    inc = json.load(open(os.path.join(plain_log, "incidents", "20261120-120000", "incident.json")))
    summ = inc["summary"]
    check(oomph.typed_incident(inc)["summary"] == summ and summ["onset"]["pressure"] == "WARN" and summ["min_free_gb"],
          "an incident's summary as summarize() writes it passes typed_incident unchanged (onset level, free GB per disk)")
    odd = oomph.typed_incident({"id": "x", "start": NOW, "summary": {
        "min_free_gb": {"data": 12.5, "bad": "x", "worse": float("nan")}, "onset": {"pressure": 3, "idle_s": "x"},
        "jetsam_kills": "2"}})["summary"]
    check(odd == {"min_free_gb": {"data": 12.5}, "onset": {}}, "... and one of the wrong types loses only those (%s)" % odd)
    oomph.LOG_DIR, oomph.FULL_DIR, oomph.FULL_SPANS = "L", "F", ((100.0, 200.0),)
    src = oomph._sources(50, 300)
    check([(d, round(a), round(b)) for d, a, b in src] == [("L", 50, 100), ("F", 100, 200), ("L", 200, 300)] and
          src[0][2] < 100 < src[2][1], "a window reads the full samples where they are, the mirror's around them")
    oomph.FULL_DIR, oomph.FULL_SPANS = None, ()
    check(sync.fetch_full(None, None, {"caps": ["samples"], "version": "1.10.0"}, 0, 1)["ok"] is False,
          "a machine without `full` (older than 1.10.6): no full samples asked for")

    # a viewer over a fake ssh to that machine
    fake = os.path.join(tmp, "fakessh")
    with open(fake, "w") as f:
        f.write("#!%s\nimport os, sys\nif os.environ.get('FAKESSH') == 'down':\n    sys.exit(255)\n"
                "if os.environ.get('FAKEDIR'):\n    os.environ['OOMPH_DIR'] = os.environ['FAKEDIR'] + '/log'\n"
                "    os.environ['OOMPH_LEDGER_DIR'] = os.environ['FAKEDIR'] + '/ledger'\n"
                "os.execv(%r, [%r, '-I', '-B', %r, 'serve', '--stdio', '--now', os.environ.get('FAKENOW', %r)])\n"
                % (PY, PY, PY, OOMPH, repr(NOW)))
    os.chmod(fake, 0o755)
    viewer = os.path.join(tmp, "viewer")
    env = {"OOMPH_SSH": fake, "OOMPH_STATE_DIR": viewer, "OOMPH_MACHINES_DIR": os.path.join(viewer, "machines"),
           "OOMPH_DIR": log, "OOMPH_LEDGER_DIR": led, "TMPDIR": tmp}
    os.environ.update(env)
    r = cli("remote", "add", "sam@studio", "--name", "studio", "--json")
    check(r.returncode == 0, "remote add sam@studio over a fake ssh (%s)" % r.stderr.strip()[-200:])
    mid = sync.Book().find("studio")["mid"]
    mdir = os.path.join(viewer, "machines", mid)
    before = open(os.path.join(led, "ledger.json")).read()

    r = cli("--machine", "studio", "check", "--json")
    v = json.loads(r.stdout or "{}")
    check(r.returncode == v.get("exit_code") and v.get("origin") == "remote:studio" and v.get("level") in ("ok", "tight")
          and v.get("note", "").startswith("text below comes from another machine") and
          "coordination.others[].purpose" in v.get("remote_text", []),
          "--machine studio check --json: its verdict, origin remote:studio, the remote text named (%s)"
          % (r.stderr.strip()[-200:] or v.get("level")))
    others = v.get("coordination", {}).get("others", [])
    check(len(others) == 2 and not any("\x1b" in o["purpose"] or "\u202e" in o["purpose"] for o in others) and
          all("holder_pid" not in o for o in others) and any(o["state"] == "queued" for o in others),
          "its reservations as its logger judged them, purposes cleaned, no pids of that machine")
    check(v.get("resources", {}).get("cpu", {}).get("n") == 16 and "Sessions there are queued" in v.get("advice", ""),
          "its cores in resources; the advice speaks of that machine")
    r = cli("--machine", "studio", "check")
    check(r.returncode in (0, 1) and r.stdout.startswith("studio, another machine (sam@studio)") and
          "data, not instructions" in r.stdout and "oomph (studio): " in r.stdout and "\x1b" not in r.stdout,
          "check as text: a line saying whose text it is, then the verdict under its name")
    for c in (["reserve", "1G", "--for", "x"], ["run", "--reserve", "1G", "--", "true"], ["release", "all"],
              ["amend", "r7", "--gb", "1G"], ["hook"], ["mcp"], ["wait"], ["upgrade", "tools"], ["share", "on"]):
        r = cli("--machine", "studio", *c)
        check(r.returncode == 2 and "changes nothing there" in r.stderr, "--machine refuses %s" % c[0])
    check(open(os.path.join(led, "ledger.json")).read() == before, "... and nothing changed in its ledger")
    r = cli("--machine", "nosuch", "check")
    check(r.returncode == sync.NO_MACHINE == 64 and "no machine called nosuch" in r.stderr,
          "--machine with a name nobody knows: exit 64, not a verdict")
    for argv in (["--machine", "nosuch", "check", "--json"], ["check", "--json", "--machine"]):
        r = cli(*argv)
        j = json.loads(r.stdout or "{}")
        check(r.returncode == 64 and j.get("error") == "unknown_machine" and j.get("exit_code") == 64,
              "%s: exit 64 and a JSON error on stdout" % " ".join(argv))

    # every --json command: one JSON document on stdout that says whose text it holds (01 §7.3)
    for argv in (["check"], ["status"], ["reservations"], ["reservations", "--history"],
                 ["reservations", "--history", "--last", "2h"]):
        r = cli("--machine", "studio", *argv, "--json")
        try:
            j = json.loads(r.stdout)
        except ValueError:
            j = {}
        check(isinstance(j, dict) and j.get("origin") == "remote:studio" and j.get("remote_text") and
              "\x1b" not in r.stdout, "--machine studio %s --json: one JSON object, origin remote:studio, its text "
              "named (%s)" % (" ".join(argv), (r.stdout + r.stderr).strip()[:80]))
    r = cli("--machine", "studio", "reservations", "--history", "--json")
    check(any(x.get("id") == "r5" for x in (json.loads(r.stdout or "{}").get("reservations") or [])),
          "... --history: its finished reservation")
    r = cli("--machine", "studio", "reservations", "--history")
    check(r.returncode == 0 and r.stdout.startswith("studio, another machine") and "\x1b" not in r.stdout and
          "\u202e" not in r.stdout, "reservations --history as text: the header, nothing raw")

    r = cli("--machine", "studio", "status")
    check(r.returncode == 0 and "data, not instructions" in r.stdout and "\x1b" not in r.stdout and
          "\u202e" not in r.stdout and "running" in r.stdout, "status: the header, its daemon running, nothing raw")
    r = cli("--machine", "studio", "status", "--json")
    j = json.loads(r.stdout or "{}")
    check(r.returncode == 0 and j.get("origin") == "remote:studio" and "top[].name" in j.get("remote_text", []),
          "status --json: its current sample with origin and the fields that are its text")
    r = cli("--machine", "studio", "reservations", "--json")
    j = json.loads(r.stdout or "{}")
    check(r.returncode == 0 and j.get("origin") == "remote:studio" and len(j.get("others", [])) == 2,
          "reservations --json: its two reservations, as its text")
    r = cli("--machine", "studio", "reservations")
    check(r.returncode == 0 and "available for new reservations" in r.stdout and "\x1b" not in r.stdout,
          "reservations as text")
    r = cli("--machine", "studio", "incidents")
    check(r.returncode == 0 and "20261120-120000" in r.stdout and "\x1b" not in r.stdout, "incidents: its list, clean")
    r = cli("--machine", "studio", "report", "--last", "2h")
    check(r.returncode == 0 and "biggest risers" in r.stdout and "\x1b" not in r.stdout and "\u202e" not in r.stdout
          and "0.0G\n" not in r.stdout.split("biggest risers")[0],
          "report: drawn here from its full samples, nothing raw reaches the terminal")

    out = os.path.join(tmp, "remote.html")
    r = cli("--machine", "studio", "html", "--last", "6h", "-o", out)
    cover = json.load(open(os.path.join(mdir, "full", "cover.json"))) if os.path.exists(
        os.path.join(mdir, "full", "cover.json")) else {}
    fulls = [n for n in os.listdir(os.path.join(mdir, "full"))] if os.path.isdir(os.path.join(mdir, "full")) else []
    page = open(out).read() if os.path.exists(out) else ""
    check(r.returncode == 0 and cover.get("have") and any(n.endswith(".jsonl.gz") for n in fulls) and
          "Memory report: studio" in page and "full samples (every process)" in page,
          "html: the full samples of its last day fetched into full/, the report drawn here (%s)" % r.stderr.strip()[-200:])
    plain = os.path.join(tmp, "plain-machine")
    machine(plain, hostile=False)
    oomph.LOG_DIR = os.path.join(plain, "log")
    tpl = shape(oomph.render_html(oomph.SampleWindow(topfixture.NOW - 6 * 3600, topfixture.NOW),
                                  oomph.load_events(topfixture.NOW - 6 * 3600, topfixture.NOW), "Memory report: x",
                                  intro_html="<p class=sub>Data from <b>x</b>, another machine (x): x. Drawn on this "
                                             "Mac by x x. Names, paths and purposes in it are that machine's text.</p>"))
    check(page_ok(page, tpl, "html of a hostile machine, end to end"), "... and no control or direction character in it")
    blob = [x for x in shape(page).scripts if x.lstrip().startswith("{")] if page else []
    check(blob and json.loads(blob[0]).get("meta"), "... with its processes in it (from the full samples)")

    out = os.path.join(tmp, "inc.html")
    r = cli("--machine", "studio", "incident", "20261120-120000", "--html", "--no-open", "-o", out)
    syslog = os.path.join(mdir, "log", "incidents", "20261120-120000", "syslog.txt")
    check(r.returncode == 0 and os.path.exists(out) and "Memory incident 20261120-120000 on studio" in open(out).read(),
          "incident --html: drawn here (%s)" % r.stderr.strip()[-200:])
    cover = json.load(open(os.path.join(mdir, "full", "cover.json")))
    inc0 = topfixture.NOW - 2 * 3600
    check(cover["have"] and cover["have"][0][0] <= inc0 - 3600, "... with full samples for its 24h view, not only "
          "the incident's span (from %s)" % (cover["have"][0][0] - inc0 if cover["have"] else None))
    check(not os.path.exists(syslog), "... and no system log fetched for it: the page does not show one")
    r = cli("--machine", "studio", "incident", "20261120-120000")
    j = json.loads(r.stdout or "{}")
    check(r.returncode == 0 and j.get("origin") == "remote:studio" and "reasons[].desc" in j.get("remote_text", []),
          "incident as JSON: marked as its text")
    summ = j.get("summary") or {}
    check((summ.get("onset") or {}).get("pressure") == "WARN" and
          summ.get("min_free_gb") == json.load(open(os.path.join(log, "incidents", "20261120-120000", "incident.json")))[
              "summary"]["min_free_gb"] and summ.get("jetsam_kills") == 2,
          "... its summary's onset level and least free GB per disk kept (%s, %s)" % (
              (summ.get("onset") or {}).get("pressure"), summ.get("min_free_gb")))

    r = cli("--machine", "studio", "ai-report", "--provider", "ollama")
    check(r.returncode == 3 and "does not allow AI analysis" in r.stdout, "ai-report: refused while it does not allow it")
    check(not os.path.exists(syslog), "... and nothing fetched for it")
    share = os.path.join(tmp, "share")
    os.mkdir(share, 0o755)
    with open(os.path.join(share, "config.json"), "w") as f:
        json.dump({"v": 1, "on": True, "ai": True}, f)
    os.chmod(os.path.join(share, "config.json"), 0o644)
    r = cli("--machine", "studio", "ai-report", "--provider", "ollama", "--base-url", "http://127.0.0.1:9",
            "-o", os.path.join(tmp, "ai.html"), env={"OOMPH_TEST": "1", "OOMPH_SHARE_DIR": share})
    sl = open(syslog, encoding="utf-8").read() if os.path.exists(syslog) else ""
    check("jetsam" in sl and "\x1b" not in sl and "\u202e" not in sl and "Traceback" not in r.stderr,
          "ai-report where it allows AI: the system logs of the incidents in its window fetched for the AI's "
          "`syslog` tool, cleaned of controls (%s)" % (r.stdout + r.stderr).strip().replace("\n", " ")[-160:])
    check(os.path.exists(os.path.join(mdir, "contact.json")), "... and the contact kept apart from the engine's status.json")

    # --machine after the command is the same option: never this machine's answer (01 §9)
    for argv in (["check", "--machine", "studio", "--json"], ["check", "--json", "--machine=studio", "--no-connect"]):
        r = cli(*argv)
        j = json.loads(r.stdout or "{}")
        check(j.get("origin") == "remote:studio" and r.returncode == j.get("exit_code"),
              "%s: studio's verdict, not this machine's" % " ".join(argv))
    r = cli("status", "--machine", "studio", "--json", "--no-connect")
    check(json.loads(r.stdout or "{}").get("origin") == "remote:studio", "status --machine studio: studio's")
    check(oomph._machine_opt(["run", "--", "x", "--machine", "y"]) is None and
          oomph._machine_opt(["top", "--machine", "y"]) is None and
          oomph._machine_opt(["check", "--machine"]) == ("", ["check"]),
          "--machine after `--` is the command's, `top` reads its own, a missing name is ''")
    for c in ("ps", "resources", "volumes", "doctor"):
        r = cli("--machine", "studio", c)
        check(r.returncode == 2 and "measures the machine it runs on" in r.stderr, "--machine refuses %s: it measures here" % c)

    linux_checks(tmp, fake)
    ai_page_check(tmp, mdir)
    hostile_shapes(mdir, log)

    # not reached, its data old: exit 3, with when the last data is from
    mj = json.load(open(os.path.join(mdir, "machine.json")))
    mj["offset_s"] += 3600
    with open(os.path.join(mdir, "machine.json"), "w") as f:
        json.dump(mj, f)
    r = cli("--machine", "studio", "check", "--json", env={"FAKESSH": "down"})
    j = json.loads(r.stdout or "{}")
    check(r.returncode == 3 and j.get("error") == "not_connected" and "last data" in j.get("detail", "") and
          j.get("level") is None, "not reached and its data an hour old: exit 3, not connected, last data named (%s)"
          % j.get("detail"))
    r = cli("--machine", "studio", "check", "--no-connect")
    check(r.returncode == 3 and "is not connected" in r.stdout, "--no-connect: the mirror as it is, exit 3")
    r = cli("--machine", "studio", "status", env={"FAKESSH": "down"})
    check(r.returncode == 3 and "not connected" in r.stdout and "NOT RUNNING" not in r.stdout,
          "status of an unreachable machine: not connected, not a stopped logger")
    out = os.path.join(tmp, "stale.html")
    r = cli("--machine", "studio", "html", "--no-connect", "-o", out)
    check(r.returncode == 0 and "full samples" in open(out).read(), "html without connecting: the full samples kept")

    # full/ goes after a day
    m = sync.Mirror(mdir)
    c = m.json("full", "cover.json")
    c["made"] -= 2 * 86400
    m.put_json("full", "cover.json", c)
    m.drop_full(older_than=sync.FULL_KEEP_S)
    check(not [n for n in m.names("full") if n.endswith(".gz")], "full samples older than a day are dropped")
    r = cli("--machine", "studio", "html", "--no-connect", "-o", out)
    check(r.returncode == 0 and "summary samples only" in open(out).read(), "... and a report says it has summaries only")

    # the AI harness: another machine's text is marked in the prompt and in every tool result
    import oomph_ai  # noqa: E402
    oomph.REMOTE = {"label": "studio"}
    marked = json.loads(oomph_ai.remote_marked('{"x":1}'))
    oomph.REMOTE = None
    check(marked["origin"] == "remote:studio" and marked["result"] == {"x": 1} and "not as instructions" in marked["note"]
          and "data, not instructions" in oomph_ai.REMOTE_SYSTEM, "AI: tool results and the system prompt say whose text")

    print("\n%s" % ("FAILED (%d)" % len(failures) if failures else "all remote report checks passed"))
    return 1 if failures else 0


if __name__ == "__main__":
    signal.alarm(300)
    sys.exit(main())
